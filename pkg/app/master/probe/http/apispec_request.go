package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/slimtoolkit/slim/pkg/app/master/config"
)

const (
	// maxSchemaDepth bounds recursive schema/example generation so that deeply
	// nested or cyclic $ref structures truncate instead of overflowing the stack.
	maxSchemaDepth = 8

	placeholderString  = "str"
	placeholderInteger = 0
	placeholderNumber  = 0.0

	mediaTypeJSON = "application/json"
	mediaTypeForm = "application/x-www-form-urlencoded"
	mediaTypeAny  = "*/*"
)

// specRequest is one fully resolved HTTP request derived from an API spec
// operation, or a record describing an operation that was skipped.
type specRequest struct {
	Method       string
	PathTemplate string
	Path         string
	Query        url.Values
	Header       http.Header
	Body         []byte
	MediaType    string

	Secured    bool
	Skipped    bool
	SkipReason string
}

// specRequestResult records what happened when a specRequest was executed.
type specRequestResult struct {
	Method     string
	URL        string
	Status     int
	Attempts   int
	OK         bool
	Skipped    bool
	SkipReason string
	Error      string
}

// APISpecProbeReport is the additive outcome of probing one API spec.
// Rounds never roll back, so merging reports across rounds is a simple union
// of the requests and their recorded outcomes.
type APISpecProbeReport struct {
	Requests []specRequestResult
}

func (r *APISpecProbeReport) add(result specRequestResult) {
	r.Requests = append(r.Requests, result)
}

// safeMethods are the only methods sent unless destructive probing is enabled.
var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
}

// destructiveMethods order within a single path-template group implements the
// create -> modify -> read -> delete chain for the same resource.
var destructiveMethodOrder = map[string]int{
	http.MethodPost:    0,
	http.MethodPut:     1,
	http.MethodPatch:   2,
	http.MethodGet:     3,
	http.MethodHead:    4,
	http.MethodOptions: 5,
	http.MethodDelete:  6,
}

// buildSpecRequests converts every operation in a resolved spec into a
// specRequest. Output ordering is deterministic: path templates are sorted and
// methods follow destructiveMethodOrder (safe methods naturally cluster in the
// middle; with destructive probing disabled only they survive the filter).
func buildSpecRequests(
	spec *openapi3.T,
	opts config.HTTPProbeOptions,
	creds map[string]apiSpecCredential,
) []specRequest {
	var requests []specRequest
	if spec == nil || spec.Paths == nil || spec.Paths.Len() == 0 {
		return requests
	}

	for _, pathTemplate := range spec.Paths.InMatchingOrder() {
		pathItem := spec.Paths.Value(pathTemplate)
		if pathItem == nil {
			continue
		}

		ops := pathItem.Operations()
		methods := make([]string, 0, len(ops))
		for method := range ops {
			methods = append(methods, method)
		}
		sort.Slice(methods, func(i, j int) bool {
			return destructiveMethodOrder[methods[i]] < destructiveMethodOrder[methods[j]]
		})

		for _, method := range methods {
			op := ops[method]
			if op == nil {
				continue
			}

			if !opts.APISpecDestructive && !safeMethods[method] {
				continue
			}

			req := buildOperationRequest(spec, pathTemplate, pathItem, method, op, opts, creds)
			requests = append(requests, req)
		}
	}

	return requests
}

func buildOperationRequest(
	spec *openapi3.T,
	pathTemplate string,
	pathItem *openapi3.PathItem,
	method string,
	op *openapi3.Operation,
	opts config.HTTPProbeOptions,
	creds map[string]apiSpecCredential,
) specRequest {
	req := specRequest{
		Method:       method,
		PathTemplate: pathTemplate,
		Path:         pathTemplate,
		Query:        url.Values{},
		Header:       http.Header{},
	}

	// Security: determine the effective requirements before building anything
	// else so a skipped operation carries a useful reason and no partial state.
	requirements := effectiveSecurity(spec, op)
	if len(requirements) > 0 && !isAnonymousSecurity(requirements) {
		req.Secured = true
		if missing := missingCredentialScheme(requirements, creds); missing != "" {
			req.Skipped = true
			req.SkipReason = "missing-credential:" + missing
			return req
		}
	}

	params := mergeParameters(pathItem.Parameters, op.Parameters)
	pathValues := map[string]string{}
	var cookies []string

	for _, paramRef := range params {
		if paramRef == nil || paramRef.Value == nil {
			continue
		}
		param := paramRef.Value

		// Schema-based parameters are the supported path; Content-only
		// parameters (rare) are best-effort skipped.
		if param.Schema == nil || param.Schema.Value == nil {
			continue
		}

		value := parameterValue(param)
		valueStr := fmt.Sprintf("%v", value)

		switch param.In {
		case openapi3.ParameterInPath:
			pathValues[param.Name] = valueStr
		case openapi3.ParameterInQuery:
			req.Query.Set(param.Name, valueStr)
		case openapi3.ParameterInHeader:
			req.Header.Set(param.Name, valueStr)
		case openapi3.ParameterInCookie:
			cookies = append(cookies, param.Name+"="+valueStr)
		}
	}

	if len(cookies) > 0 {
		// A request carries a single Cookie header; concatenate the pairs
		// deterministically (parameters retain their spec order).
		req.Header.Set("Cookie", strings.Join(cookies, "; "))
	}

	for name, value := range pathValues {
		req.Path = strings.ReplaceAll(req.Path, "{"+name+"}", url.PathEscape(value))
	}

	// Bodies are never attached to HEAD/OPTIONS requests.
	if method != http.MethodHead && method != http.MethodOptions &&
		op.RequestBody != nil && op.RequestBody.Value != nil {
		if body, mediaType, ok := buildRequestBody(op.RequestBody.Value); ok {
			req.Body = body
			req.MediaType = mediaType
		}
	}

	// Apply credentials last so an explicit auth header wins over any
	// same-named parameter-derived header.
	if req.Secured {
		placeholder := &http.Request{Header: req.Header, URL: &url.URL{}}
		if !applyAPISpecAuth(placeholder, spec, requirements, creds) {
			req.Skipped = true
			req.SkipReason = "missing-credential:unknown"
			return req
		}
		req.Header = placeholder.Header
		if placeholder.URL != nil && placeholder.URL.RawQuery != "" {
			authQuery, _ := url.ParseQuery(placeholder.URL.RawQuery)
			for name, values := range authQuery {
				for _, v := range values {
					req.Query.Set(name, v)
				}
			}
		}
	}

	return req
}

// mergeParameters combines path-level parameters with operation-level ones,
// letting the operation override on the "in:name" key.
func mergeParameters(pathParams, opParams openapi3.Parameters) openapi3.Parameters {
	merged := openapi3.Parameters{}
	index := map[string]int{}

	add := func(ref *openapi3.ParameterRef) {
		if ref == nil || ref.Value == nil {
			return
		}
		key := ref.Value.In + ":" + ref.Value.Name
		if pos, ok := index[key]; ok {
			merged[pos] = ref
			return
		}
		index[key] = len(merged)
		merged = append(merged, ref)
	}

	for _, ref := range pathParams {
		add(ref)
	}
	for _, ref := range opParams {
		add(ref)
	}

	return merged
}

// parameterValue resolves a parameter placeholder with the documented priority:
// parameter example -> first named example -> schema example -> enum -> default
// -> type-generated placeholder.
func parameterValue(param *openapi3.Parameter) any {
	if param.Example != nil {
		return param.Example
	}

	if len(param.Examples) > 0 {
		keys := make([]string, 0, len(param.Examples))
		for name := range param.Examples {
			keys = append(keys, name)
		}
		sort.Strings(keys)

		if ref := param.Examples[keys[0]]; ref != nil && ref.Value != nil {
			return ref.Value.Value
		}
	}

	if param.Schema != nil {
		return genSchemaValue(param.Schema, 0, map[*openapi3.Schema]struct{}{})
	}

	return placeholderString
}

// buildRequestBody generates a minimal legal body for the best-supported media
// type. JSON is preferred; urlencoded forms are supported; multipart is not
// generated (documented limitation).
func buildRequestBody(body *openapi3.RequestBody) ([]byte, string, bool) {
	if len(body.Content) == 0 {
		return nil, "", false
	}

	mediaType := selectMediaType(body.Content)
	mt := body.Content[mediaType]
	if mt == nil || mt.Schema == nil || mt.Schema.Value == nil {
		return nil, "", false
	}

	value := mediaTypeValue(mt)

	switch {
	case isJSONMediaType(mediaType):
		data, err := json.Marshal(value)
		if err != nil {
			return nil, "", false
		}
		return data, mediaTypeJSON, true
	case mediaType == mediaTypeForm:
		values := url.Values{}
		if obj, ok := value.(map[string]any); ok {
			keys := make([]string, 0, len(obj))
			for name := range obj {
				keys = append(keys, name)
			}
			sort.Strings(keys)
			for _, name := range keys {
				values.Set(name, fmt.Sprintf("%v", obj[name]))
			}
		}
		return []byte(values.Encode()), mediaTypeForm, true
	default:
		// Unknown media type: best-effort JSON encoding so the request still
		// carries a legal, schema-shaped payload.
		data, err := json.Marshal(value)
		if err != nil {
			return nil, "", false
		}
		return data, mediaTypeJSON, true
	}
}

func mediaTypeValue(mt *openapi3.MediaType) any {
	if mt.Example != nil {
		return mt.Example
	}

	if len(mt.Examples) > 0 {
		keys := make([]string, 0, len(mt.Examples))
		for name := range mt.Examples {
			keys = append(keys, name)
		}
		sort.Strings(keys)

		if ref := mt.Examples[keys[0]]; ref != nil && ref.Value != nil {
			return ref.Value.Value
		}
	}

	return genSchemaValue(mt.Schema, 0, map[*openapi3.Schema]struct{}{})
}

// selectMediaType picks deterministically: exact application/json, then sorted
// JSON-ish/application types, then the wildcard (Swagger 2 without consumes),
// then the lexicographically smallest available type.
func selectMediaType(content openapi3.Content) string {
	names := make([]string, 0, len(content))
	for name := range content {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if name == mediaTypeJSON {
			return name
		}
	}

	for _, name := range names {
		if isJSONMediaType(name) {
			return name
		}
	}

	for _, name := range names {
		if name == mediaTypeAny {
			return name
		}
	}

	return names[0]
}

func isJSONMediaType(mediaType string) bool {
	mediaType = strings.ToLower(mediaType)
	return mediaType == mediaTypeJSON ||
		strings.HasSuffix(mediaType, "+json") ||
		strings.HasPrefix(mediaType, "application/")
}

// genSchemaValue produces a minimal legal value for a (resolved) schema.
//
// Value priority at every node: example -> enum[0] -> default -> generated.
// The ancestry set tracks *Schema pointers on the current recursion path to
// truncate cycles (including cycles through anonymous inline schemas, which
// carry no $ref string), and maxSchemaDepth bounds deep but acyclic nesting.
func genSchemaValue(
	ref *openapi3.SchemaRef,
	depth int,
	ancestry map[*openapi3.Schema]struct{},
) any {
	if ref == nil || ref.Value == nil {
		return placeholderString
	}
	schema := ref.Value

	if value, ok := hintedValue(schema); ok {
		return value
	}

	if depth >= maxSchemaDepth {
		return emptyTerminal(schema)
	}

	if _, onPath := ancestry[schema]; onPath {
		return emptyTerminal(schema)
	}

	// Composition: allOf merges its members; oneOf/anyOf take the first
	// author-listed alternative.
	if len(schema.AllOf) > 0 {
		return genAllOfValue(schema, depth, ancestry)
	}
	if len(schema.OneOf) > 0 {
		return genSchemaValue(schema.OneOf[0], depth+1, ancestry)
	}
	if len(schema.AnyOf) > 0 {
		return genSchemaValue(schema.AnyOf[0], depth+1, ancestry)
	}

	types := schema.Type.Slice()
	if len(types) == 0 {
		// Unspecified type means "any": a permissive empty string is legal
		// everywhere a primitive placeholder is accepted.
		return placeholderString
	}

	switch types[0] {
	case "string":
		return genStringValue(schema)
	case "integer":
		return genIntegerValue(schema)
	case "number":
		return genNumberValue(schema)
	case "boolean":
		return false
	case "array":
		return genArrayValue(schema, depth, ancestry)
	case "object":
		return genObjectValue(schema, depth, ancestry)
	default:
		return placeholderString
	}
}

// hintedValue implements the example -> enum -> default priority.
func hintedValue(schema *openapi3.Schema) (any, bool) {
	if schema.Example != nil {
		return schema.Example, true
	}

	if len(schema.Enum) > 0 {
		return schema.Enum[0], true
	}

	if schema.Default != nil {
		return schema.Default, true
	}

	return nil, false
}

func genStringValue(schema *openapi3.Schema) string {
	value := placeholderString
	if uint64(len(value)) < schema.MinLength {
		value = strings.Repeat("a", int(schema.MinLength))
	}
	return value
}

func genIntegerValue(schema *openapi3.Schema) int {
	if schema.Min != nil {
		min := int(*schema.Min)
		if schema.ExclusiveMin {
			min++
		}
		return min
	}
	return placeholderInteger
}

func genNumberValue(schema *openapi3.Schema) float64 {
	if schema.Min != nil {
		min := *schema.Min
		if schema.ExclusiveMin {
			min++
		}
		return min
	}
	return placeholderNumber
}

func genArrayValue(
	schema *openapi3.Schema,
	depth int,
	ancestry map[*openapi3.Schema]struct{},
) []any {
	if schema.Items == nil {
		return []any{}
	}

	count := int(schema.MinItems)
	if count == 0 {
		count = 1
	}

	items := make([]any, 0, count)
	for i := 0; i < count; i++ {
		items = append(items, genSchemaValue(schema.Items, depth+1, ancestry))
	}
	return items
}

func genObjectValue(
	schema *openapi3.Schema,
	depth int,
	ancestry map[*openapi3.Schema]struct{},
) map[string]any {
	ancestry[schema] = struct{}{}
	defer delete(ancestry, schema)

	result := map[string]any{}

	required := append([]string{}, schema.Required...)
	for _, name := range required {
		if prop, ok := schema.Properties[name]; ok {
			result[name] = genSchemaValue(prop, depth+1, ancestry)
		} else if schema.AdditionalProperties.Schema != nil {
			result[name] = genSchemaValue(schema.AdditionalProperties.Schema, depth+1, ancestry)
		} else {
			result[name] = placeholderString
		}
	}

	// Add optional properties only to satisfy minProperties, choosing the
	// lexicographically smallest names for deterministic output.
	if uint64(len(result)) < schema.MinProps {
		optional := make([]string, 0, len(schema.Properties))
		for name := range schema.Properties {
			if _, included := result[name]; !included {
				optional = append(optional, name)
			}
		}
		sort.Strings(optional)

		for _, name := range optional {
			if uint64(len(result)) >= schema.MinProps {
				break
			}
			result[name] = genSchemaValue(schema.Properties[name], depth+1, ancestry)
		}
	}

	return result
}

// genAllOfValue unions the required fields and properties of all subschemas,
// the common OpenAPI inheritance pattern.
func genAllOfValue(
	schema *openapi3.Schema,
	depth int,
	ancestry map[*openapi3.Schema]struct{},
) map[string]any {
	ancestry[schema] = struct{}{}
	defer delete(ancestry, schema)

	result := map[string]any{}
	for _, sub := range schema.AllOf {
		if sub == nil || sub.Value == nil {
			continue
		}
		subValue := genSchemaValue(sub, depth+1, ancestry)
		if obj, ok := subValue.(map[string]any); ok {
			for name, value := range obj {
				result[name] = value
			}
		}
	}

	// The schema may declare its own properties alongside allOf.
	for name, prop := range schema.Properties {
		if _, exists := result[name]; !exists {
			result[name] = genSchemaValue(prop, depth+1, ancestry)
		}
	}

	return result
}

// emptyTerminal returns a type-correct empty value used when generation must
// truncate due to the depth cap or a cyclic reference, keeping the payload
// valid JSON instead of emitting a dangling reference.
func emptyTerminal(schema *openapi3.Schema) any {
	types := schema.Type.Slice()
	if len(types) == 0 {
		return placeholderString
	}

	switch types[0] {
	case "string":
		return ""
	case "integer":
		return 0
	case "number":
		return 0.0
	case "boolean":
		return false
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	default:
		return placeholderString
	}
}

func sortStrings(values []string) {
	sort.Strings(values)
}
