package http

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/slimtoolkit/slim/pkg/app"
	"github.com/slimtoolkit/slim/pkg/app/master/config"
)

// specFixtureA exercises path params, query params, a required request body
// built from mutually recursive schemas, and a destructive endpoint.
const specFixtureA = `
openapi: 3.0.0
info:
  title: fixture-a
  version: "1.0"
paths:
  /health:
    get:
      responses:
        "200":
          description: ok
  /items:
    get:
      parameters:
        - name: q
          in: query
          required: true
          schema:
            type: string
            example: needle
        - name: limit
          in: query
          required: true
          schema:
            type: integer
            enum: [10, 20, 50]
        - name: tag
          in: query
          schema:
            type: string
      responses:
        "200":
          description: ok
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/Node"
      responses:
        "201":
          description: created
  /items/{id}/parts/{code}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
            example: 42
        - name: code
          in: path
          required: true
          schema:
            type: string
            minLength: 5
      responses:
        "200":
          description: ok
    delete:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
            example: 42
        - name: code
          in: path
          required: true
          schema:
            type: string
            minLength: 5
      responses:
        "204":
          description: deleted
components:
  schemas:
    Node:
      type: object
      required: [id, kind, child]
      properties:
        id:
          type: string
        kind:
          type: string
          enum: [root, leaf]
        child:
          $ref: "#/components/schemas/LeafNode"
    LeafNode:
      type: object
      required: [label, parent, nodes]
      properties:
        label:
          type: string
        parent:
          $ref: "#/components/schemas/Node"
        nodes:
          type: array
          minItems: 2
          items:
            $ref: "#/components/schemas/Node"
`

func mustParseSpec(t *testing.T, raw string) *openapi3.T {
	t.Helper()
	spec, err := parseAPISpec([]byte(raw))
	if err != nil {
		t.Fatalf("parseAPISpec failed: %v", err)
	}
	if spec == nil {
		t.Fatalf("parseAPISpec returned nil spec")
	}
	return spec
}

func newTestProbe(t *testing.T, opts config.HTTPProbeOptions) *CustomProbe {
	t.Helper()
	xc := app.NewExecutionContext("test", true, "")
	return newCustomProbe(xc, "127.0.0.1", opts, false)
}

func requestKeys(requests []specRequest) []string {
	keys := make([]string, 0, len(requests))
	for _, req := range requests {
		keys = append(keys, req.Method+" "+req.PathTemplate)
	}
	sort.Strings(keys)
	return keys
}

func TestBuildSpecRequestsSafeByDefault(t *testing.T) {
	spec := mustParseSpec(t, specFixtureA)
	probe := newTestProbe(t, config.HTTPProbeOptions{})

	requests := buildSpecRequests(spec, probe.opts, map[string]apiSpecCredential{})
	keys := requestKeys(requests)

	want := []string{
		"GET /health",
		"GET /items",
		"GET /items/{id}/parts/{code}",
	}
	if strings.Join(keys, "|") != strings.Join(want, "|") {
		t.Fatalf("default request set = %v, want %v", keys, want)
	}

	for _, req := range requests {
		if safeMethods[req.Method] == false {
			t.Errorf("destructive method %s present with destructive probing disabled", req.Method)
		}
		if req.Skipped {
			t.Errorf("public request %s %s unexpectedly skipped: %s", req.Method, req.PathTemplate, req.SkipReason)
		}
	}
}

func TestBuildSpecRequestsDestructiveSetAndOrder(t *testing.T) {
	spec := mustParseSpec(t, specFixtureA)
	probe := newTestProbe(t, config.HTTPProbeOptions{APISpecDestructive: true})

	requests := buildSpecRequests(spec, probe.opts, map[string]apiSpecCredential{})

	// Locate each path-template group and assert create -> read -> delete
	// ordering within it.
	groupMethods := map[string][]string{}
	for _, req := range requests {
		if strings.HasPrefix(req.PathTemplate, "/items") {
			groupMethods[req.PathTemplate] = append(groupMethods[req.PathTemplate], req.Method)
		}
	}

	if got := strings.Join(groupMethods["/items"], ","); got != "POST,GET" {
		t.Fatalf("/items group order = %v, want POST,GET", got)
	}
	if got := strings.Join(groupMethods["/items/{id}/parts/{code}"], ","); got != "GET,DELETE" {
		t.Fatalf("/items/{id}/parts/{code} group order = %v, want GET,DELETE", got)
	}

	// Globally, every POST must precede every DELETE.
	lastPost, firstDelete := -1, -1
	for i, req := range requests {
		switch req.Method {
		case "POST":
			lastPost = i
		case "DELETE":
			if firstDelete == -1 {
				firstDelete = i
			}
		}
	}
	if lastPost == -1 || firstDelete == -1 || lastPost > firstDelete {
		t.Fatalf("create-before-delete ordering violated (post=%d delete=%d)", lastPost, firstDelete)
	}
}

func TestParameterPlaceholderLegality(t *testing.T) {
	spec := mustParseSpec(t, specFixtureA)
	probe := newTestProbe(t, config.HTTPProbeOptions{})
	requests := buildSpecRequests(spec, probe.opts, map[string]apiSpecCredential{})

	var itemPath *specRequest
	var itemList *specRequest
	for i := range requests {
		switch requests[i].PathTemplate {
		case "/items/{id}/parts/{code}":
			itemPath = &requests[i]
		case "/items":
			itemList = &requests[i]
		}
	}

	if itemPath == nil || itemList == nil {
		t.Fatalf("expected requests not found: %+v", requests)
	}

	numericID := regexp.MustCompile(`^/items/[0-9]+/parts/`)
	if !numericID.MatchString(itemPath.Path) {
		t.Errorf("path id placeholder not numeric: %s", itemPath.Path)
	}
	if strings.Contains(itemPath.Path, "{") || strings.Contains(itemPath.Path, "}") {
		t.Errorf("unsubstituted brace remains in path: %s", itemPath.Path)
	}
	if !regexp.MustCompile(`parts/[a-z]{5,}$`).MatchString(itemPath.Path) {
		t.Errorf("minLength placeholder not honored: %s", itemPath.Path)
	}

	if got := itemList.Query.Get("q"); got != "needle" {
		t.Errorf("query example not used: q=%q", got)
	}
	if got := itemList.Query.Get("limit"); got != "10" {
		t.Errorf("query enum[0] not used: limit=%q", got)
	}
	if got := itemList.Query.Get("tag"); got == "" {
		t.Errorf("type-generated query placeholder missing for tag")
	}
}

func TestRequestBodyRecursionTerminatesAndIsLegal(t *testing.T) {
	spec := mustParseSpec(t, specFixtureA)
	probe := newTestProbe(t, config.HTTPProbeOptions{APISpecDestructive: true})
	requests := buildSpecRequests(spec, probe.opts, map[string]apiSpecCredential{})

	var post *specRequest
	for i := range requests {
		if requests[i].Method == "POST" && requests[i].PathTemplate == "/items" {
			post = &requests[i]
			break
		}
	}
	if post == nil {
		t.Fatal("POST /items request not built")
	}
	if post.MediaType != mediaTypeJSON {
		t.Fatalf("media type = %q, want %q", post.MediaType, mediaTypeJSON)
	}

	var body map[string]any
	if err := json.Unmarshal(post.Body, &body); err != nil {
		t.Fatalf("generated body is not legal JSON: %v\nbody=%s", err, string(post.Body))
	}

	for _, required := range []string{"id", "kind", "child"} {
		if _, ok := body[required]; !ok {
			t.Errorf("Node missing required field %q in %s", required, string(post.Body))
		}
	}
	if got := body["kind"]; got != "root" {
		t.Errorf("enum value not used: kind=%v", got)
	}

	child, ok := body["child"].(map[string]any)
	if !ok {
		t.Fatalf("child not an object: %v", body["child"])
	}
	for _, required := range []string{"label", "parent", "nodes"} {
		if _, ok := child[required]; !ok {
			t.Errorf("LeafNode missing required field %q in %s", required, string(post.Body))
		}
	}

	nodes, ok := child["nodes"].([]any)
	if !ok || len(nodes) < 2 {
		t.Fatalf("minItems not honored for nodes: %v", child["nodes"])
	}

	// Recursion must have truncated rather than expanding forever: the body
	// stays well under a depth proportional to maxSchemaDepth.
	depth := jsonDepth(body)
	if depth > maxSchemaDepth+2 {
		t.Errorf("recursion not bounded, depth=%d body=%s", depth, string(post.Body))
	}

	// Determinism: two builds produce byte-identical bodies.
	again := buildSpecRequests(spec, probe.opts, map[string]apiSpecCredential{})
	var postAgain *specRequest
	for i := range again {
		if again[i].Method == "POST" && again[i].PathTemplate == "/items" {
			postAgain = &again[i]
		}
	}
	if string(postAgain.Body) != string(post.Body) {
		t.Errorf("non-deterministic body generation:\nfirst=%s\nagain=%s", post.Body, postAgain.Body)
	}
}

func jsonDepth(value any) int {
	switch typed := value.(type) {
	case map[string]any:
		max := 0
		for _, child := range typed {
			if d := jsonDepth(child); d > max {
				max = d
			}
		}
		return max + 1
	case []any:
		max := 0
		for _, child := range typed {
			if d := jsonDepth(child); d > max {
				max = d
			}
		}
		return max + 1
	default:
		return 1
	}
}

func TestGenSchemaValueTruncatesDirectSelfCycle(t *testing.T) {
	// Build a schema graph with a direct self-reference (an object whose
	// "next" property points back to the same *Schema). genSchemaValue must
	// terminate via the ancestry set rather than overflowing the stack.
	self := &openapi3.Schema{
		Type:     &openapi3.Types{"object"},
		Required: []string{"id"},
		Properties: openapi3.Schemas{
			"id": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
		},
	}
	self.Properties["next"] = &openapi3.SchemaRef{Value: self}

	ref := &openapi3.SchemaRef{Value: self}
	value := genSchemaValue(ref, 0, map[*openapi3.Schema]struct{}{})

	obj, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("self-cycle value not an object: %T", value)
	}
	if _, ok := obj["id"]; !ok {
		t.Fatalf("required field missing after cycle truncation: %v", obj)
	}
	// The cyclic "next" reference must be truncated rather than expanded:
	// it is either absent or a type-correct empty terminal, never a nested
	// copy of the whole object (which would indicate unbounded recursion).
	if next, present := obj["next"]; present {
		if terminal, ok := next.(map[string]any); !ok || len(terminal) != 0 {
			t.Fatalf("cyclic reference not truncated to empty object terminal: %v", next)
		}
	}
}

func TestJoinEndpointEncodesQuery(t *testing.T) {
	query := url.Values{}
	query.Set("q", "a b")
	got, err := joinEndpoint("http://127.0.0.1:8080", "/api", "/items", query)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "http://127.0.0.1:8080/api/items?") {
		t.Errorf("unexpected endpoint: %s", got)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("q") != "a b" {
		t.Errorf("query value round-trip failed: %s", parsed.RawQuery)
	}
}
