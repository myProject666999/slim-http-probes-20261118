package http

import (
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	log "github.com/sirupsen/logrus"
)

// apiSpecCredential is a user-provided credential for a named security scheme.
//
// Segments holds everything after the scheme name, split with SplitN(3):
//
//	"<scheme>:<value>"          -> [value]
//	"<scheme>:<a>:<b:c>"        -> [a, "b:c"]
//
// The segments are interpreted against the authoritative security scheme
// definition at apply time, where the scheme type disambiguates: an http/basic
// scheme rejoins the segments as "user:pass", while an apiKey scheme treats the
// first segment as an explicit header override when two segments are present.
type apiSpecCredential struct {
	Segments []string
}

func (c apiSpecCredential) value() string {
	return strings.Join(c.Segments, ":")
}

// credential returns the secret portion, dropping the header name in the
// explicit-override form.
func (c apiSpecCredential) credential() string {
	if len(c.Segments) == 2 {
		return c.Segments[1]
	}
	return c.value()
}

// headerOverride returns the explicit header name only for the two-segment
// "<scheme>:<header>:<value>" form.
func (c apiSpecCredential) headerOverride() (string, bool) {
	if len(c.Segments) == 2 {
		return c.Segments[0], true
	}
	return "", false
}

// parseAPISpecAuth turns --http-probe-apispec-auth values into credentials
// keyed by security scheme name. Supported input forms:
//
//	"<scheme>:<value>"          - header location derived from the scheme
//	                              (for basic auth the value is "user:pass")
//	"<scheme>:<header>:<value>" - explicit header name override (apiKey schemes)
//
// Splitting with SplitN keeps colons inside credential values intact
// (e.g. basic auth's "user:pass" or bearer tokens containing colons).
func parseAPISpecAuth(values []string) map[string]apiSpecCredential {
	creds := map[string]apiSpecCredential{}
	for _, raw := range values {
		parts := strings.SplitN(raw, ":", 3)
		if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" {
			log.Debugf("http.probe.apispec.auth - ignoring malformed credential (%v)", raw)
			continue
		}

		scheme := strings.TrimSpace(parts[0])
		creds[scheme] = apiSpecCredential{Segments: parts[1:]}
	}

	return creds
}

// effectiveSecurity returns the security requirements that apply to an operation.
// Operation-level security overrides the top-level document security, including
// an empty slice, which explicitly marks the operation as anonymous.
// A nil result means no security is declared (public operation).
func effectiveSecurity(spec *openapi3.T, op *openapi3.Operation) openapi3.SecurityRequirements {
	if op.Security != nil {
		return *op.Security
	}

	return spec.Security
}

// isAnonymousSecurity reports whether the requirements contain an empty
// requirement object. OpenAPI defines "security: [{}]" as an explicit
// anonymous alternative, so such an operation is public even when other
// requirements name secured schemes.
func isAnonymousSecurity(requirements openapi3.SecurityRequirements) bool {
	for _, req := range requirements {
		if len(req) == 0 {
			return true
		}
	}

	return false
}

// missingCredentialScheme returns the name of the first required security
// scheme for which the user provided no credential, or "" when at least one
// requirement can be satisfied with the available credentials (or the
// operation needs no credentials at all).
func missingCredentialScheme(
	requirements openapi3.SecurityRequirements,
	creds map[string]apiSpecCredential,
) string {
	if len(requirements) == 0 || isAnonymousSecurity(requirements) {
		return ""
	}

	for _, req := range requirements {
		schemes := make([]string, 0, len(req))
		for name := range req {
			schemes = append(schemes, name)
		}
		sortStrings(schemes)

		allAvailable := true
		for _, name := range schemes {
			if _, ok := creds[name]; !ok {
				allAvailable = false
				break
			}
		}

		if allAvailable {
			return ""
		}
	}

	// No requirement could be satisfied as a whole. Report the first missing
	// scheme of the first (deterministically ordered) requirement.
	for _, req := range requirements {
		schemes := make([]string, 0, len(req))
		for name := range req {
			schemes = append(schemes, name)
		}
		sortStrings(schemes)

		for _, name := range schemes {
			if _, ok := creds[name]; !ok {
				return name
			}
		}
	}

	return ""
}

// applyAPISpecAuth attaches credentials to a request for every scheme named in
// the first security requirement the available credentials can satisfy fully.
// It returns false (without touching the request) when no requirement can be
// satisfied; the caller is expected to skip such an operation.
func applyAPISpecAuth(
	req *http.Request,
	spec *openapi3.T,
	requirements openapi3.SecurityRequirements,
	creds map[string]apiSpecCredential,
) bool {
	if len(requirements) == 0 || isAnonymousSecurity(requirements) {
		return true
	}

	var chosen openapi3.SecurityRequirement
	for _, req := range requirements {
		schemes := make([]string, 0, len(req))
		for name := range req {
			schemes = append(schemes, name)
		}
		sortStrings(schemes)

		allAvailable := true
		for _, name := range schemes {
			if _, ok := creds[name]; !ok {
				allAvailable = false
				break
			}
		}

		if allAvailable {
			chosen = req
			break
		}
	}

	if chosen == nil {
		return false
	}

	schemes := make([]string, 0, len(chosen))
	for name := range chosen {
		schemes = append(schemes, name)
	}
	sortStrings(schemes)

	for _, name := range schemes {
		cred := creds[name]
		schemeRef := securityScheme(spec, name)
		if schemeRef == nil || schemeRef.Value == nil {
			// Unknown scheme: fall back to a plain header so an explicitly
			// provided credential is still sent.
			header := "Authorization"
			if override, ok := cred.headerOverride(); ok {
				header = override
			}
			req.Header.Set(header, cred.credential())
			continue
		}

		applySecurityScheme(req, schemeRef.Value, cred)
	}

	return true
}

func securityScheme(spec *openapi3.T, name string) *openapi3.SecuritySchemeRef {
	if spec.Components == nil {
		return nil
	}

	return spec.Components.SecuritySchemes[name]
}

func applySecurityScheme(req *http.Request, scheme *openapi3.SecurityScheme, cred apiSpecCredential) {
	switch scheme.Type {
	case "apiKey":
		if override, ok := cred.headerOverride(); ok {
			req.Header.Set(override, cred.credential())
			return
		}

		switch scheme.In {
		case "cookie":
			req.AddCookie(&http.Cookie{Name: scheme.Name, Value: cred.credential()})
		case "query":
			q := req.URL.Query()
			q.Set(scheme.Name, cred.credential())
			req.URL.RawQuery = q.Encode()
		default: // "header" and any unrecognized location
			header := scheme.Name
			if header == "" {
				header = "X-API-Key"
			}
			req.Header.Set(header, cred.credential())
		}
	case "http":
		switch strings.ToLower(scheme.Scheme) {
		case "basic":
			// Basic auth rejoins all segments after the scheme name as
			// "user:pass"; the header-override interpretation never applies to
			// http schemes, so value() is correct here.
			username, password, _ := strings.Cut(cred.value(), ":")
			req.SetBasicAuth(username, password)
		default: // bearer (and any other http scheme): static token
			req.Header.Set("Authorization", "Bearer "+cred.credential())
		}
	default:
		// oauth2 and openIdConnect: no token-exchange flow is implemented, so
		// the user-provided value is sent as a static bearer token. An
		// explicit override still allows a custom header name.
		if override, ok := cred.headerOverride(); ok {
			req.Header.Set(override, cred.credential())
			return
		}
		req.Header.Set("Authorization", "Bearer "+cred.credential())
	}
}
