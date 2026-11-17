package http

import (
	"encoding/base64"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/slimtoolkit/slim/pkg/app/master/config"
)

// specFixtureB declares apiKey, bearer and basic security schemes plus public
// endpoints, including an explicit anonymous override ("security: [{}]").
const specFixtureB = `
openapi: 3.0.0
info:
  title: fixture-b
  version: "1.0"
security:
  - apiKeyAuth: []
paths:
  /open:
    get:
      security: []
      responses:
        "200":
          description: ok
  /anon:
    get:
      security:
        - {}
      responses:
        "200":
          description: ok
  /secure-key:
    get:
      security:
        - apiKeyAuth: []
      responses:
        "200":
          description: ok
  /secure-bearer:
    get:
      security:
        - bearerAuth: []
      responses:
        "200":
          description: ok
  /secure-basic:
    get:
      security:
        - basicAuth: []
      responses:
        "200":
          description: ok
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
    bearerAuth:
      type: http
      scheme: bearer
    basicAuth:
      type: http
      scheme: basic
`

// swaggerFixtureBTwin is the Swagger 2.x equivalent, exercising the
// openapi2conv path: securityDefinitions, global security and an in:body param.
const swaggerFixtureBTwin = `
swagger: "2.0"
info:
  title: fixture-b-swagger
  version: "1.0"
basePath: /v2
securityDefinitions:
  apiKeyAuth:
    type: apiKey
    in: header
    name: X-API-Key
  basicAuth:
    type: basic
security:
  - apiKeyAuth: []
paths:
  /open:
    get:
      security: []
      responses:
        "200":
          description: ok
  /widgets:
    post:
      parameters:
        - name: widget
          in: body
          required: true
          schema:
            $ref: "#/definitions/Widget"
      responses:
        "201":
          description: created
definitions:
  Widget:
    type: object
    required: [name]
    properties:
      name:
        type: string
`

func skippedPaths(requests []specRequest) map[string]string {
	out := map[string]string{}
	for _, req := range requests {
		if req.Skipped {
			out[req.Method+" "+req.PathTemplate] = req.SkipReason
		}
	}
	return out
}

func calledPaths(requests []specRequest) []string {
	var out []string
	for _, req := range requests {
		if !req.Skipped {
			out = append(out, req.Method+" "+req.PathTemplate)
		}
	}
	sort.Strings(out)
	return out
}

func TestSecuredOperationsSkippedWithoutCredentials(t *testing.T) {
	spec := mustParseSpec(t, specFixtureB)
	probe := newTestProbe(t, config.HTTPProbeOptions{})
	requests := buildSpecRequests(spec, probe.opts, map[string]apiSpecCredential{})

	skipped := skippedPaths(requests)
	for _, endpoint := range []string{"/secure-key", "/secure-bearer", "/secure-basic"} {
		reason, ok := skipped["GET "+endpoint]
		if !ok {
			t.Errorf("expected %s to be skipped without credentials", endpoint)
			continue
		}
		if !strings.HasPrefix(reason, "missing-credential:") {
			t.Errorf("%s skip reason = %q, want missing-credential prefix", endpoint, reason)
		}
	}

	called := calledPaths(requests)
	want := []string{"GET /anon", "GET /open"}
	if strings.Join(called, "|") != strings.Join(want, "|") {
		t.Fatalf("public calls = %v, want %v", called, want)
	}
}

func TestCredentialsAppliedByScheme(t *testing.T) {
	spec := mustParseSpec(t, specFixtureB)
	opts := config.HTTPProbeOptions{
		APISpecAuth: []string{
			"apiKeyAuth:secret-key",
			"bearerAuth:tok-123",
			"basicAuth:alice:s3cret",
		},
	}
	probe := newTestProbe(t, opts)
	creds := parseAPISpecAuth(opts.APISpecAuth)
	requests := buildSpecRequests(spec, probe.opts, creds)

	byPath := map[string]specRequest{}
	for _, req := range requests {
		byPath[req.PathTemplate] = req
	}

	for name, req := range map[string]specRequest{
		"/secure-key":    byPath["/secure-key"],
		"/secure-bearer": byPath["/secure-bearer"],
		"/secure-basic":  byPath["/secure-basic"],
	} {
		if req.Skipped {
			t.Errorf("%s unexpectedly skipped: %s", name, req.SkipReason)
		}
	}

	if got := byPath["/secure-key"].Header.Get("X-API-Key"); got != "secret-key" {
		t.Errorf("apiKey header = %q", got)
	}
	if got := byPath["/secure-bearer"].Header.Get("Authorization"); got != "Bearer tok-123" {
		t.Errorf("bearer header = %q", got)
	}
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	if got := byPath["/secure-basic"].Header.Get("Authorization"); got != wantBasic {
		t.Errorf("basic header = %q, want %q", got, wantBasic)
	}
}

func TestExplicitHeaderOverrideAndColonInValue(t *testing.T) {
	creds := parseAPISpecAuth([]string{"apiKeyAuth:X-Custom-Key:part1:part2"})
	cred, ok := creds["apiKeyAuth"]
	if !ok {
		t.Fatal("credential not parsed")
	}
	override, hasOverride := cred.headerOverride()
	if !hasOverride || override != "X-Custom-Key" || cred.credential() != "part1:part2" {
		t.Fatalf("override parse = %+v", cred)
	}

	// A basic credential with a colon is rejoined as "user:pass". The
	// header-override vs. basic-auth ambiguity is deliberately resolved later,
	// against the authoritative security scheme type (see TestCredentialsAppliedByScheme).
	basic := parseAPISpecAuth([]string{"basicAuth:alice:s3cret"})["basicAuth"]
	if basic.value() != "alice:s3cret" {
		t.Fatalf("basic value = %q", basic.value())
	}
}

func TestSwaggerTwoTwinConvertsAndGeneratesBody(t *testing.T) {
	spec := mustParseSpec(t, swaggerFixtureBTwin)

	if spec.Components == nil || len(spec.Components.SecuritySchemes) != 2 {
		t.Fatalf("securityDefinitions not converted: %+v", spec.Components)
	}
	for _, name := range []string{"apiKeyAuth", "basicAuth"} {
		if _, ok := spec.Components.SecuritySchemes[name]; !ok {
			t.Errorf("converted scheme %q missing", name)
		}
	}

	// Without credentials, the secured POST is skipped; the public GET is called.
	probe := newTestProbe(t, config.HTTPProbeOptions{APISpecDestructive: true})
	requests := buildSpecRequests(spec, probe.opts, map[string]apiSpecCredential{})

	var post *specRequest
	for i := range requests {
		if requests[i].Method == http.MethodPost {
			post = &requests[i]
		}
	}
	if post == nil {
		t.Fatal("POST /widgets not enumerated from Swagger 2 spec")
	}
	if !post.Skipped || !strings.HasPrefix(post.SkipReason, "missing-credential:") {
		t.Fatalf("secured POST should be skipped, got skipped=%v reason=%q", post.Skipped, post.SkipReason)
	}

	// With a credential, the in:body request body must be generated from the
	// converted definition and contain the required field.
	creds := parseAPISpecAuth([]string{"apiKeyAuth:key"})
	requests = buildSpecRequests(spec, probe.opts, creds)
	for i := range requests {
		if requests[i].Method == http.MethodPost {
			post = &requests[i]
		}
	}
	if post.Skipped {
		t.Fatalf("POST skipped with credential: %s", post.SkipReason)
	}
	if !strings.Contains(string(post.Body), `"name"`) {
		t.Errorf("Swagger 2 in:body not generated: %s", string(post.Body))
	}
}
