package http

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"
)

type apiSpecInfo struct {
	spec           *openapi3.T
	prefixOverride string
}

func (p *CustomProbe) loadAPISpecFiles() {
	for _, info := range p.opts.APISpecFiles {
		fileName := info
		prefixOverride := ""
		if strings.Contains(info, ":") {
			parts := strings.SplitN(info, ":", 2)
			fileName = parts[0]
			prefixOverride = parts[1]
		}

		spec, err := loadAPISpecFromFile(fileName)
		if err != nil {
			p.xc.Out.Info("http.probe.apispec.error",
				ovars{
					"message": "error loading api spec file",
					"error":   err,
				})
			continue
		}

		if spec == nil {
			p.xc.Out.Info("http.probe.apispec",
				ovars{
					"message": "unsupported spec type",
				})
			continue
		}

		info := apiSpecInfo{
			spec:           spec,
			prefixOverride: prefixOverride,
		}

		p.APISpecProbes = append(p.APISpecProbes, info)
	}
}

func parseAPISpec(rdata []byte) (*openapi3.T, error) {
	if isOpenAPI(rdata) {
		log.Debug("http.CustomProbe.parseAPISpec - is openapi")
		loader := openapi3.NewLoader()
		loader.IsExternalRefsAllowed = true
		spec, err := loader.LoadFromData(rdata)
		if err != nil {
			log.Debugf("http.CustomProbe.parseAPISpec.LoadFromData - error=%v", err)
			return nil, err
		}

		return spec, nil
	}

	if isSwagger(rdata) {
		log.Debug("http.CustomProbe.parseAPISpec - is swagger")
		spec2 := &openapi2.T{}
		if err := yaml.Unmarshal(rdata, spec2); err != nil {
			log.Debugf("http.CustomProbe.parseAPISpec.yaml.Unmarshal - error=%v", err)
			return nil, err
		}

		spec, err := openapi2conv.ToV3(spec2)
		if err != nil {
			log.Debugf("http.CustomProbe.parseAPISpec.ToV3 - error=%v", err)
			return nil, err
		}

		return spec, nil
	}

	log.Debugf("http.CustomProbe.parseAPISpec - unsupported api spec type (%d): %s", len(rdata), string(rdata))
	return nil, nil
}

func loadAPISpecFromEndpoint(client *http.Client, endpoint string) (*openapi3.T, error) {
	log.Debugf("http.CustomProbe.loadAPISpecFromEndpoint(%s)", endpoint)
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Debugf("http.CustomProbe.loadAPISpecFromEndpoint.http.NewRequest - error=%v", err)
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		log.Debugf("http.CustomProbe.loadAPISpecFromEndpoint.httpClient.Do - error=%v", err)
		return nil, err
	}

	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}

	if res.Body != nil {
		rdata, err := io.ReadAll(res.Body)
		if err != nil {
			log.Debugf("http.CustomProbe.loadAPISpecFromEndpoint.response.read - error=%v", err)
			return nil, err
		}

		return parseAPISpec(rdata)
	}

	log.Debug("http.CustomProbe.loadAPISpecFromEndpoint.response - no body")
	return nil, nil
}

func loadAPISpecFromFile(name string) (*openapi3.T, error) {
	rdata, err := os.ReadFile(name)
	if err != nil {
		log.Debugf("http.CustomProbe.loadAPISpecFromFile.ReadFile - error=%v", err)
		return nil, err
	}

	return parseAPISpec(rdata)
}

func isSwagger(data []byte) bool {
	if (bytes.Contains(data, []byte(`"swagger":`)) ||
		bytes.Contains(data, []byte(`swagger:`))) &&
		bytes.Contains(data, []byte(`paths`)) {
		return true
	}

	return false
}

func isOpenAPI(data []byte) bool {
	if (bytes.Contains(data, []byte(`"openapi":`)) ||
		bytes.Contains(data, []byte(`openapi:`))) &&
		bytes.Contains(data, []byte(`paths`)) {
		return true
	}

	return false
}

func apiSpecPrefix(spec *openapi3.T) (string, error) {
	//for now get the api prefix from the first server struc
	//later, support multiple prefixes if there's more than one server struct
	var prefix string
	for _, sinfo := range spec.Servers {
		xurl := sinfo.URL
		if strings.Contains(xurl, "{") {
			for k, vinfo := range sinfo.Variables {
				varStr := fmt.Sprintf("{%s}", k)
				if strings.Contains(xurl, varStr) {
					valStr := "var"
					if vinfo.Default != "" {
						valStr = fmt.Sprintf("%v", vinfo.Default)
					} else if len(vinfo.Enum) > 0 {
						valStr = fmt.Sprintf("%v", vinfo.Enum[0])
					}

					xurl = strings.ReplaceAll(xurl, varStr, valStr)
				}
			}
		}

		if strings.Contains(xurl, "{") {
			xurl = strings.ReplaceAll(xurl, "{", "")

			if strings.Contains(xurl, "}") {
				xurl = strings.ReplaceAll(xurl, "}", "")
			}
		}

		parsed, err := url.Parse(xurl)
		if err != nil {
			return "", err
		}

		if parsed.Path != "" && parsed.Path != "/" {
			prefix = parsed.Path
		}
	}

	return prefix, nil
}

func (p *CustomProbe) loadAPISpecs(proto, targetHost, port string) {

	baseAddr := getHTTPAddr(proto, targetHost, port)
	client, err := getHTTPClient(proto)
	if err != nil {
		p.xc.Out.Error("HTTP probe - construct client error - %v", err.Error())
		return
	}

	//TODO:
	//Need to support user provided target port for the spec,
	//but these need to be mapped to the actual port at runtime
	//Need to support user provided target proto for the spec
	for _, info := range p.opts.APISpecs {
		specPath := info
		prefixOverride := ""
		if strings.Contains(info, ":") {
			parts := strings.SplitN(info, ":", 2)
			specPath = parts[0]
			prefixOverride = parts[1]
		}

		addr := fmt.Sprintf("%s%s", baseAddr, specPath)
		spec, err := loadAPISpecFromEndpoint(client, addr)
		if err != nil {
			p.xc.Out.Info("http.probe.apispec.error",
				ovars{
					"message": "error loading api spec from endpoint",
					"error":   err,
				})

			continue
		}

		if spec == nil {
			p.xc.Out.Info("http.probe.apispec",
				ovars{
					"message": "unsupported spec type",
				})

			continue
		}

		info := apiSpecInfo{
			spec:           spec,
			prefixOverride: prefixOverride,
		}

		p.APISpecProbes = append(p.APISpecProbes, info)
	}
}
