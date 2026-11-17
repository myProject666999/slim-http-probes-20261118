package http

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/slimtoolkit/slim/pkg/app/master/config"
)

// probeAPISpecAtBase builds and executes the probe requests for one resolved
// API spec against an explicit base URL. It is deliberately decoupled from
// host/port plumbing so in-process test servers (httptest.Server.URL) can drive
// it directly.
//
// Execution semantics:
//   - requests are already ordered by the builder (sorted paths, CRUD method
//     order within each path-template group);
//   - each request is retried per opts.RetryCount/RetryWait, mirroring the
//     basic probe command behavior;
//   - a request that keeps failing is recorded in the report and execution
//     continues — failures never abort a round, and completed calls are never
//     rolled back, so partial results from a crashed target are retained.
func (p *CustomProbe) probeAPISpecAtBase(
	baseURL, prefix string,
	spec *openapi3.T,
) APISpecProbeReport {
	report := APISpecProbeReport{}

	creds := parseAPISpecAuth(p.opts.APISpecAuth)
	requests := buildSpecRequests(spec, p.opts, creds)

	httpClient, err := getHTTPClient(protoFromBaseURL(baseURL))
	if err != nil {
		p.xc.Out.Error("HTTP probe - construct client error - %v", err.Error())
		return report
	}

	if p.printState {
		p.xc.Out.State("http.probe.api-spec.probe.endpoint.starting",
			ovars{
				"base":      baseURL,
				"prefix":    prefix,
				"endpoints": spec.Paths.Len(),
				"requests":  len(requests),
			})
	}

	for _, reqSpec := range requests {
		if reqSpec.Skipped {
			report.add(specRequestResult{
				Method:     reqSpec.Method,
				URL:        reqSpec.PathTemplate,
				Skipped:    true,
				SkipReason: reqSpec.SkipReason,
			})

			if p.printState {
				p.xc.Out.Info("http.probe.api-spec.probe.endpoint.skip",
					ovars{
						"method": reqSpec.Method,
						"path":   reqSpec.PathTemplate,
						"reason": reqSpec.SkipReason,
					})
			}
			continue
		}

		result := p.executeSpecRequest(httpClient, baseURL, prefix, reqSpec)
		report.add(result)
	}

	return report
}

func (p *CustomProbe) executeSpecRequest(
	client *http.Client,
	baseURL, prefix string,
	reqSpec specRequest,
) specRequestResult {
	maxRetryCount := probeRetryCount
	if p.opts.RetryCount > 0 {
		maxRetryCount = p.opts.RetryCount
	}

	notReadyErrorWait := time.Duration(16)
	webErrorWait := time.Duration(8)
	otherErrorWait := time.Duration(4)
	if p.opts.RetryWait > 0 {
		webErrorWait = time.Duration(p.opts.RetryWait)
		notReadyErrorWait = time.Duration(p.opts.RetryWait * 2)
		otherErrorWait = time.Duration(p.opts.RetryWait / 2)
	}

	endpoint, err := joinEndpoint(baseURL, prefix, reqSpec.Path, reqSpec.Query)
	if err != nil {
		return specRequestResult{
			Method:   reqSpec.Method,
			URL:      reqSpec.Path,
			Attempts: 0,
			Error:    err.Error(),
		}
	}

	result := specRequestResult{Method: reqSpec.Method, URL: endpoint}

	for attempt := 0; attempt < maxRetryCount; attempt++ {
		var bodyReader io.Reader
		if len(reqSpec.Body) > 0 {
			bodyReader = bytes.NewReader(reqSpec.Body)
		}

		req, err := http.NewRequest(reqSpec.Method, endpoint, bodyReader)
		if err != nil {
			// Same arguments every loop, so retrying cannot help.
			result.Error = err.Error()
			break
		}

		for name, values := range reqSpec.Header {
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}
		if reqSpec.MediaType != "" {
			req.Header.Set("Content-Type", reqSpec.MediaType)
		}

		res, callErr := client.Do(req)
		p.CallCount++
		result.Attempts = attempt + 1

		if res != nil {
			if res.Body != nil {
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
		}

		if callErr == nil {
			p.OkCount++
			result.OK = true
			result.Status = res.StatusCode
			break
		}

		p.ErrCount++
		result.Error = callErr.Error()

		if p.printState {
			p.xc.Out.Info("http.probe.api-spec.probe.endpoint.call",
				ovars{
					"status":   "error",
					"method":   reqSpec.Method,
					"endpoint": endpoint,
					"attempt":  attempt + 1,
					"error":    result.Error,
					"time":     time.Now().UTC().Format(time.RFC3339),
				})
		}

		urlErr := &url.Error{}
		if errors.As(callErr, &urlErr) {
			if errors.Is(urlErr.Err, io.EOF) {
				time.Sleep(notReadyErrorWait * time.Second)
			} else {
				time.Sleep(webErrorWait * time.Second)
			}
		} else {
			time.Sleep(otherErrorWait * time.Second)
		}
	}

	if p.printState && result.OK {
		p.xc.Out.Info("http.probe.api-spec.probe.endpoint.call",
			ovars{
				"status":   fmt.Sprintf("%v", result.Status),
				"method":   result.Method,
				"endpoint": result.URL,
				"attempts": result.Attempts,
				"error":    "none",
				"time":     time.Now().UTC().Format(time.RFC3339),
			})
	}

	return result
}

func joinEndpoint(baseURL, prefix, path string, query url.Values) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	base.Path = stringsJoinPath(base.Path, prefix, path)
	if len(query) > 0 {
		base.RawQuery = query.Encode()
	}

	return base.String(), nil
}

// stringsJoinPath joins URL path segments without cleaning ".." or collapsing
// duplicated slashes, since path parameters may legitimately contain them.
func stringsJoinPath(segments ...string) string {
	parts := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" || segment == "/" {
			continue
		}
		parts = append(parts, strings.Trim(segment, "/"))
	}

	if len(parts) == 0 {
		return "/"
	}

	return "/" + strings.Join(parts, "/")
}

// protoFromBaseURL selects the HTTP client protocol from the base URL scheme,
// preserving HTTPS probing through the same getHTTPClient selector the basic
// probe commands use.
func protoFromBaseURL(baseURL string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" {
		return config.ProtoHTTP
	}

	switch parsed.Scheme {
	case config.ProtoHTTPS:
		return config.ProtoHTTPS
	default:
		return config.ProtoHTTP
	}
}

// probeAPISpecEndpoints keeps the original call signature used by the probe
// orchestration while delegating to the base-URL executor.
func (p *CustomProbe) probeAPISpecEndpoints(
	proto, targetHost, port, prefix string,
	spec *openapi3.T,
) APISpecProbeReport {
	baseURL := getHTTPAddr(proto, targetHost, port)
	return p.probeAPISpecAtBase(baseURL, prefix, spec)
}
