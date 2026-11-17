package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/slimtoolkit/slim/pkg/app/master/config"
)

func parsePathOnly(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return parsed.Path, nil
}

// recordedRequest captures what the in-process server actually received.
type recordedRequest struct {
	Method     string
	Path       string
	AuthHeader string
	APIKey     string
	Body       string
}

// newRecordingServer returns an in-process HTTP double whose handler maps each
// request path to a distinct simulated file. Every request reads that file
// (represented by recording its name), so the set of touched files models the
// file-access collection a real container slim run would observe.
func newRecordingServer(t *testing.T) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{files: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := ""
		if r.Body != nil {
			data, _ := io.ReadAll(r.Body)
			body = string(data)
		}

		rec.add(r, body)

		// Distinct simulated file per path, mirroring distinct code paths.
		fileName := "files" + strings.ReplaceAll(r.URL.Path, "/", "_") + ".dat"
		w.Header().Set("X-Touched-File", fileName)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fileName))
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

type recorder struct {
	mu       sync.Mutex
	files    map[string]bool
	requests []recordedRequest
}

func (r *recorder) add(req *http.Request, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fileName := "files" + strings.ReplaceAll(req.URL.Path, "/", "_") + ".dat"
	r.files[fileName] = true
	r.requests = append(r.requests, recordedRequest{
		Method:     req.Method,
		Path:       req.URL.Path,
		AuthHeader: req.Header.Get("Authorization"),
		APIKey:     req.Header.Get("X-API-Key"),
		Body:       body,
	})
}

func (r *recorder) fileSet() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.files))
	for name := range r.files {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (r *recorder) requestList() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedRequest, len(r.requests))
	copy(out, r.requests)
	return out
}

func fastProbeOpts(extra config.HTTPProbeOptions) config.HTTPProbeOptions {
	// One attempt with minimal waiting so connection failures don't stall tests.
	extra.RetryCount = 1
	extra.RetryWait = 1
	return extra
}

func TestExecutorSendsOnlySafeMethodsByDefault(t *testing.T) {
	srv, rec := newRecordingServer(t)
	spec := mustParseSpec(t, specFixtureA)
	probe := newTestProbe(t, fastProbeOpts(config.HTTPProbeOptions{}))

	report := probe.probeAPISpecAtBase(srv.URL, "", spec)

	for _, result := range report.Requests {
		if result.Skipped {
			t.Errorf("public request skipped: %s %s", result.Method, result.URL)
		}
		if !result.OK {
			t.Errorf("request failed: %+v", result)
		}
		if !safeMethods[result.Method] {
			t.Errorf("destructive method %s executed by default", result.Method)
		}
	}

	for _, req := range rec.requestList() {
		if !safeMethods[req.Method] {
			t.Errorf("server observed destructive method %s", req.Method)
		}
	}
}

func TestExecutorDestructiveOrderingOverHTTP(t *testing.T) {
	srv, _ := newRecordingServer(t)
	spec := mustParseSpec(t, specFixtureA)
	probe := newTestProbe(t, fastProbeOpts(config.HTTPProbeOptions{APISpecDestructive: true}))

	report := probe.probeAPISpecAtBase(srv.URL, "", spec)

	// The report preserves builder ordering (sorted paths, CRUD method order
	// per group), so derive the observed call order directly from it.
	var order []string
	for _, result := range report.Requests {
		order = append(order, result.Method)
	}

	lastPost, firstDelete := -1, -1
	for i, method := range order {
		switch method {
		case http.MethodPost:
			lastPost = i
		case http.MethodDelete:
			if firstDelete == -1 {
				firstDelete = i
			}
		}
	}
	if lastPost == -1 || firstDelete == -1 || lastPost > firstDelete {
		t.Fatalf("create-before-delete ordering violated over HTTP: %v", order)
	}
}

func TestExecutorAuthHeadersReachServer(t *testing.T) {
	srv, rec := newRecordingServer(t)
	spec := mustParseSpec(t, specFixtureB)
	opts := fastProbeOpts(config.HTTPProbeOptions{
		APISpecAuth: []string{
			"apiKeyAuth:secret-key",
			"bearerAuth:tok-123",
			"basicAuth:alice:s3cret",
		},
	})
	probe := newTestProbe(t, opts)

	report := probe.probeAPISpecAtBase(srv.URL, "", spec)

	saw := map[string]recordedRequest{}
	for _, req := range rec.requestList() {
		saw[req.Path] = req
	}

	if got := saw["/secure-key"].APIKey; got != "secret-key" {
		t.Errorf("apiKey not propagated: %q", got)
	}
	if got := saw["/secure-bearer"].AuthHeader; got != "Bearer tok-123" {
		t.Errorf("bearer not propagated: %q", got)
	}
	if !strings.HasPrefix(saw["/secure-basic"].AuthHeader, "Basic ") {
		t.Errorf("basic auth not propagated: %q", saw["/secure-basic"].AuthHeader)
	}

	// Every report entry for the secured endpoints must be successful.
	for _, result := range report.Requests {
		if strings.Contains(result.URL, "/secure") && !result.OK {
			t.Errorf("secured call failed: %+v", result)
		}
	}
}

func TestMultiRoundMergeWithMidRoundCrash(t *testing.T) {
	srv, rec := newRecordingServer(t)
	spec := mustParseSpec(t, specFixtureA)
	probe := newTestProbe(t, fastProbeOpts(config.HTTPProbeOptions{}))

	// Round 1: healthy server.
	report1 := probe.probeAPISpecAtBase(srv.URL, "", spec)
	if len(report1.Requests) == 0 {
		t.Fatal("round 1 produced no requests")
	}
	for _, result := range report1.Requests {
		if !result.OK {
			t.Fatalf("round 1 should fully succeed, got failure: %+v", result)
		}
	}
	round1Files := rec.fileSet()
	if len(round1Files) == 0 {
		t.Fatal("round 1 recorded no file access")
	}

	// Round 2: crash the target halfway through. The builder emits three safe
	// requests (sorted: /health, /items, /items/{id}/...); close after the first.
	var round2Calls int
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		round2Calls++
		if round2Calls == 2 {
			// Close from a goroutine: Close waits for in-flight requests, and
			// the current request must finish first.
			go srv.Close()
		}
		rec.add(r, "")
		w.WriteHeader(http.StatusOK)
	})

	report2 := probe.probeAPISpecAtBase(srv.URL, "", spec)

	// The executor must return normally with failures recorded, not panic/abort.
	failures := 0
	for _, result := range report2.Requests {
		if !result.OK && !result.Skipped {
			failures++
			if result.Attempts == 0 {
				t.Errorf("failed result recorded without attempts: %+v", result)
			}
			if result.Error == "" {
				t.Errorf("failed result missing error text: %+v", result)
			}
		}
	}
	if failures == 0 {
		t.Fatal("expected at least one failure after mid-round server close")
	}

	// Round-1 partial data is fully retained: the union of touched files is
	// exactly the union of the two rounds' successful file sets.
	merged := rec.fileSet()

	// Recompute expected union: round-1 files plus whatever round 2 recorded
	// before the crash (already accumulated in the same recorder).
	if len(merged) < len(round1Files) {
		t.Fatalf("round-1 files lost after crash: before=%v after=%v", round1Files, merged)
	}

	// Every round-1 file must still be present.
	mergedSet := map[string]bool{}
	for _, name := range merged {
		mergedSet[name] = true
	}
	for _, name := range round1Files {
		if !mergedSet[name] {
			t.Errorf("round-1 file %q missing from merged set %v", name, merged)
		}
	}

	// The merged set equals precisely what the successful requests touched:
	// no file exists without a corresponding successful report entry.
	successfulPaths := map[string]bool{}
	for _, result := range append(report1.Requests, report2.Requests...) {
		if result.OK {
			if u, err := parsePathOnly(result.URL); err == nil {
				successfulPaths["files"+strings.ReplaceAll(u, "/", "_")+".dat"] = true
			}
		}
	}
	for _, name := range merged {
		if !successfulPaths[name] {
			t.Errorf("merged file %q has no matching successful request (union mismatch)", name)
		}
	}
}
