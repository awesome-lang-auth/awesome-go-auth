package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The JWKS route: the path it is served at, the two headers the reference sets
// on it, and the two ways an Auth and a bare ServeMux reach it. The document
// itself is TestIDPJWKSDocumentShape in idp_test.go; everything here is the
// wire around it.

// TestIDPJWKSPathDefaultsAndValidation: the path is the reference's constant
// unless configured (auth.router.ts:475), and a relative one is refused at
// construction — it is concatenated onto the mount prefix, so it would mount
// <prefix>jwks.json and be served from nowhere anybody looks.
func TestIDPJWKSPathDefaultsAndValidation(t *testing.T) {
	key := idpTestRSAKey(t)
	if DefaultJWKSPath != "/.well-known/jwks.json" {
		t.Fatalf("DefaultJWKSPath = %q, want the reference's", DefaultJWKSPath)
	}
	for _, tc := range []struct{ name, configured, want string }{
		{"default", "", DefaultJWKSPath},
		{"override", "/keys.json", "/keys.json"},
		{"nested override", "/oidc/keys", "/oidc/keys"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp, err := NewIDP(IDPConfig{Issuer: idpTestIssuer, Signer: key, JWKSPath: tc.configured}, nil)
			if err != nil {
				t.Fatalf("NewIDP: %v", err)
			}
			if got := idp.JWKSPath(); got != tc.want {
				t.Fatalf("JWKSPath() = %q, want %q", got, tc.want)
			}
		})
	}
	// Everything the four adapters and RegisterHandlers cannot all route as the
	// same literal path: a relative path, a trailing slash (a subtree pattern in
	// net/http, a literal segment in chi), a router wildcard or URL delimiter,
	// an empty segment, and the four OIDC endpoints the adapters and
	// RegisterHandlers both mount — which would panic in ServeMux at mount time
	// rather than fail here. Those four are spelled as the constants
	// jwksReservedPaths is built from, so renaming one cannot leave this
	// asserting the old string.
	for _, bad := range []string{
		"jwks.json", ".well-known/jwks.json", "keys/",
		"/keys/", "/.well-known/",
		"/keys/{id}", "/keys}", "/keys?raw", "/keys#frag", "//keys.json", "/a//b",
		OIDCAuthorizePath, OIDCTokenPath, OIDCUserInfoPath, OIDCDiscoveryPath,
	} {
		t.Run("refuses "+bad, func(t *testing.T) {
			idp, err := NewIDP(IDPConfig{Issuer: idpTestIssuer, Signer: key, JWKSPath: bad}, nil)
			if err == nil {
				t.Fatalf("NewIDP accepted JWKSPath %q", bad)
			}
			if idp != nil {
				t.Fatal("NewIDP returned an IDP alongside the error")
			}
			if !strings.Contains(err.Error(), "JWKSPath") || !strings.Contains(err.Error(), bad) {
				t.Fatalf("error = %v, want it to name JWKSPath and the value", err)
			}
		})
	}
}

// TestIDPJWKSHandlerHeaders is the reference's handler, header by header:
// Cache-Control on every answer (auth.router.ts:502) and the
// Access-Control-Allow-Origin resolution of :492-500 — the wildcard by default,
// a listed Origin echoed back, an unlisted one left without the header while
// the document is served regardless.
func TestIDPJWKSHandlerHeaders(t *testing.T) {
	key := idpTestRSAKey(t)
	const listed, unlisted = "https://app.example.com", "https://evil.example.com"
	for _, tc := range []struct {
		name    string
		origins []string
		request string
		want    string
		present bool
	}{
		{"nil is the wildcard", nil, listed, "*", true},
		{"nil is the wildcard with no Origin", nil, "", "*", true},
		{"the one-element slice is the reference's wildcard string", []string{"*"}, unlisted, "*", true},
		{"the one-element slice is the wildcard with no Origin", []string{"*"}, "", "*", true},
		// auth.router.ts:493 compares the whole value, so a wildcard inside a
		// longer slice is an ordinary allowlist entry there and here: it opens
		// nothing, and the entries beside it still work.
		{"a wildcard inside a longer list opens nothing", []string{listed, "*"}, unlisted, "", false},
		{"a wildcard inside a longer list leaves its neighbours listed", []string{listed, "*"}, listed, listed, true},
		{"listed origin is echoed", []string{listed, "https://admin.example.com"}, listed, listed, true},
		{"second listed origin is echoed", []string{listed, "https://admin.example.com"}, "https://admin.example.com", "https://admin.example.com", true},
		{"unlisted origin gets no header", []string{listed}, unlisted, "", false},
		{"absent origin gets no header", []string{listed}, "", "", false},
		{"an empty allowlist allows nothing", []string{}, listed, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp, err := NewIDP(IDPConfig{Issuer: idpTestIssuer, Signer: key, JWKSCORSOrigins: tc.origins}, nil)
			if err != nil {
				t.Fatalf("NewIDP: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "/auth"+DefaultJWKSPath, nil)
			if tc.request != "" {
				req.Header.Set("Origin", tc.request)
			}
			rec := httptest.NewRecorder()
			idp.JWKSHandler().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Cache-Control"); got != jwksCacheControl {
				t.Errorf("Cache-Control = %q, want %q", got, jwksCacheControl)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			got, present := rec.Header()["Access-Control-Allow-Origin"]
			if present != tc.present {
				t.Fatalf("Access-Control-Allow-Origin present = %v (%v), want %v", present, got, tc.present)
			}
			if tc.present && got[0] != tc.want {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got[0], tc.want)
			}
			// The document is served whatever the Origin said: CORS bounds what
			// a browser script may read, not what the server answers.
			var doc JWKS
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				t.Fatalf("decode body %q: %v", rec.Body.String(), err)
			}
			if len(doc.Keys) != 1 || doc.Keys[0].Kid != DefaultIDPKeyID {
				t.Fatalf("body = %+v, want the signer's key", doc)
			}
		})
	}
}

// TestIDPRegisterHandlersJWKSPathsAndDiscovery: RegisterHandlers mounts the
// canonical path the adapters mount, GET-only as the reference registers it
// (auth.router.ts:490), points the discovery document's jwks_uri at it, and
// no longer serves <base>/jwks — the pre-0.6.0 path that was the deprecated
// alias through the 0.x line (upstream plan D-13) and went with v1.0.0.
//
// The Issuer here carries the mount prefix, because that is what makes jwks_uri
// resolve to the mounted route — the coupling README_DETAILED documents. The
// test holds the two to each other rather than to a constant: it fetches the
// path component of the advertised jwks_uri from the very mux that advertised
// it, so a discovery URL nothing serves fails.
func TestIDPRegisterHandlersJWKSPathsAndDiscovery(t *testing.T) {
	key := idpTestRSAKey(t)
	const basePath = "/oidc"
	const issuer = "https://idp.example.com" + basePath
	idp, err := NewIDP(IDPConfig{Issuer: issuer, Signer: key}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	mux := http.NewServeMux()
	idp.RegisterHandlers(mux, basePath)

	path := basePath + DefaultJWKSPath
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != jwksCacheControl {
		t.Errorf("GET %s Cache-Control = %q, want %q", path, got, jwksCacheControl)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("GET %s Access-Control-Allow-Origin = %q, want *", path, got)
	}
	// GET only, as the reference registers it with router.get
	// (auth.router.ts:490) and as all four adapters mount it: a method-less
	// ServeMux pattern would answer the document to POST too, and cache it.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		bad := httptest.NewRecorder()
		mux.ServeHTTP(bad, httptest.NewRequest(method, path, nil))
		if bad.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405 — the route is GET-only", method, path, bad.Code)
		}
		if got := bad.Header().Get("Cache-Control"); got != "" {
			t.Errorf("%s %s Cache-Control = %q, want none", method, path, got)
		}
		if strings.Contains(bad.Body.String(), `"keys"`) {
			t.Errorf("%s %s was served the JWKS document: %s", method, path, bad.Body.String())
		}
	}

	// The removed alias is a miss, and a plain one: 404 from the mux itself,
	// not a redirect and not the document under another name.
	gone := httptest.NewRecorder()
	mux.ServeHTTP(gone, httptest.NewRequest(http.MethodGet, basePath+"/jwks", nil))
	if gone.Code != http.StatusNotFound {
		t.Errorf("GET %s/jwks = %d, want 404 — the alias was removed in v1.0.0", basePath, gone.Code)
	}

	doc := decodeDiscovery(t, mux, basePath)
	advertised, _ := doc["jwks_uri"].(string)
	if want := issuer + DefaultJWKSPath; advertised != want {
		t.Fatalf("jwks_uri = %v, want %q — the canonical path, not the alias", doc["jwks_uri"], want)
	}
	// And the advertised URL has to be the mounted one, not merely the expected
	// string: a relying party follows discovery and fetches exactly this path.
	parsed, err := url.Parse(advertised)
	if err != nil {
		t.Fatalf("parse jwks_uri %q: %v", advertised, err)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, parsed.Path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s (the path of the advertised jwks_uri %q) = %d, want 200",
			parsed.Path, advertised, rec.Code)
	}

	// JWKSURL is the override for a gateway whose external URL is not
	// Issuer + the mounted path.
	override, err := NewIDP(IDPConfig{Issuer: issuer, Signer: key, JWKSURL: "https://keys.example.com/jwks.json"}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	overrideMux := http.NewServeMux()
	override.RegisterHandlers(overrideMux, basePath)
	if doc := decodeDiscovery(t, overrideMux, basePath); doc["jwks_uri"] != "https://keys.example.com/jwks.json" {
		t.Fatalf("jwks_uri = %v, want the JWKSURL override", doc["jwks_uri"])
	}

	// "/jwks" is an ordinary JWKSPath now, with nothing special about it: a
	// deployment that wants the old URL back configures it and gets exactly
	// one registration there.
	configured, err := NewIDP(IDPConfig{Issuer: issuer, Signer: key, JWKSPath: "/jwks"}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	configuredMux := http.NewServeMux()
	configured.RegisterHandlers(configuredMux, basePath)
	rec = httptest.NewRecorder()
	configuredMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, basePath+"/jwks", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s/jwks with JWKSPath=/jwks = %d, want 200", basePath, rec.Code)
	}
}

func decodeDiscovery(t *testing.T, mux *http.ServeMux, basePath string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, basePath+"/.well-known/openid-configuration", nil))
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode discovery %q: %v", rec.Body.String(), err)
	}
	return doc
}

// TestWithIDPAdoptsTheService: an IDP built with a nil Service — the only order
// a host can write, since NewIDP wants a *Service and New is what produces one
// — is bound to the Service the Auth was built around, and one already bound to
// a different Service is refused rather than adopted or silently left pointing
// elsewhere.
func TestWithIDPAdoptsTheService(t *testing.T) {
	key := idpTestRSAKey(t)

	if _, err := New(WithIDP(nil)); err == nil {
		t.Fatal("New(WithIDP(nil)) succeeded, want an error")
	}

	bare, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if bare.IDP() != nil {
		t.Fatal("IDP() is not nil without WithIDP")
	}
	if bare.JWKSHandler() != nil {
		t.Fatal("JWKSHandler() is not nil without WithIDP")
	}

	idp, err := NewIDP(IDPConfig{Issuer: idpTestIssuer, Signer: key}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	a, err := New(WithIDP(idp))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.IDP() != idp {
		t.Fatal("IDP() is not the IDP WithIDP was given")
	}
	if idp.authSvc != a.Service() {
		t.Fatal("the IDP did not adopt the Auth's Service")
	}
	if a.JWKSHandler() == nil {
		t.Fatal("JWKSHandler() is nil with WithIDP")
	}

	// An IDP already built around some other Service is refused: adopting it
	// would point this Auth's /token and /userinfo at that Service's user store,
	// and rebinding an IDP that may already be serving is a data race besides.
	svc, err := NewService(testConfig("01234567890123456789012345678901"), NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	bound, err := NewIDP(IDPConfig{Issuer: idpTestIssuer, Signer: key}, svc)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	second, err := New(WithIDP(bound))
	if err == nil {
		t.Fatal("New accepted an IDP already bound to another Service")
	}
	if second != nil {
		t.Fatal("New returned an Auth alongside the error")
	}
	if !strings.Contains(err.Error(), "WithIDP") {
		t.Fatalf("error = %v, want it to name WithIDP", err)
	}
	if bound.authSvc != svc {
		t.Fatal("the refused New rebound the IDP anyway")
	}

	// The same thing one step later: the first New binds the IDP, so handing it
	// to a second New is the double-bind, not an assembly order a host can mean.
	shared, err := NewIDP(IDPConfig{Issuer: idpTestIssuer, Signer: key}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	first, err := New(WithIDP(shared))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := New(WithIDP(shared)); err == nil {
		t.Fatal("a second New adopted an IDP the first had already bound")
	}
	if shared.authSvc != first.Service() {
		t.Fatal("the second New rebound the IDP away from the first Auth's Service")
	}
}

// TestGenerateOpenAPISpecIDProvider: the JWKS path is in the generated document
// only when OpenAPIInfo.IDProvider says the adapter was mounted WithIDP, it
// follows OpenAPIInfo.JWKSPath, and it sits under the mount prefix like every
// other path. The wiretest harness's "jwks" conditional set holds this to what
// the four adapters actually mount; this is the generator on its own.
func TestGenerateOpenAPISpecIDProvider(t *testing.T) {
	paths := func(info OpenAPIInfo) map[string]any {
		spec := GenerateOpenAPISpec(info)
		out, ok := spec["paths"].(map[string]any)
		if !ok {
			t.Fatalf("paths is %T", spec["paths"])
		}
		return out
	}

	schemas := func(info OpenAPIInfo) map[string]any {
		spec := GenerateOpenAPISpec(info)
		components, ok := spec["components"].(map[string]any)
		if !ok {
			t.Fatalf("components is %T", spec["components"])
		}
		out, ok := components["schemas"].(map[string]any)
		if !ok {
			t.Fatalf("schemas is %T", components["schemas"])
		}
		return out
	}

	if _, ok := paths(OpenAPIInfo{})["/auth"+DefaultJWKSPath]; ok {
		t.Fatal("the JWKS path is documented without OpenAPIInfo.IDProvider")
	}
	// The two schemas nothing but that path item references go with it: a
	// deployment with no IdP must not ship definitions nothing points at.
	for _, name := range []string{"JWK", "JWKS"} {
		if _, ok := schemas(OpenAPIInfo{})[name]; ok {
			t.Errorf("schema %q is defined without OpenAPIInfo.IDProvider", name)
		}
		if _, ok := schemas(OpenAPIInfo{IDProvider: true})[name]; !ok {
			t.Errorf("schema %q is missing with OpenAPIInfo.IDProvider", name)
		}
	}

	for _, tc := range []struct{ name, prefix, configured, want string }{
		{"default", "", "", "/auth" + DefaultJWKSPath},
		{"custom prefix", "/api/auth", "", "/api/auth" + DefaultJWKSPath},
		{"custom path", "", "/keys.json", "/auth/keys.json"},
		// A caller that dropped the leading "/" meant the same path below the
		// prefix; the alternative is the nonsense path "/authkeys.json".
		{"a missing leading slash is normalised", "", "keys.json", "/auth/keys.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item, ok := paths(OpenAPIInfo{APIPrefix: tc.prefix, IDProvider: true, JWKSPath: tc.configured})[tc.want]
			if !ok {
				t.Fatalf("%q is not documented", tc.want)
			}
			operations, ok := item.(map[string]any)
			if !ok {
				t.Fatalf("path item is %T", item)
			}
			if len(operations) != 1 {
				t.Fatalf("path item has %d operations, want get alone", len(operations))
			}
			if _, ok := operations["get"]; !ok {
				t.Fatalf("path item has no get operation: %v", operations)
			}
		})
	}

	// A JWKSPath that collides with a documented route leaves that route alone.
	// Replacing it would drop a real endpoint from the spec with no error, which
	// is strictly worse than omitting the conditional one; NewIDP refuses such a
	// path outright, so a collision here means this field disagrees with the IdP.
	t.Run("a collision leaves the documented route alone", func(t *testing.T) {
		const collides = "/me"
		item, ok := paths(OpenAPIInfo{IDProvider: true, JWKSPath: collides})["/auth"+collides]
		if !ok {
			t.Fatal("/auth/me disappeared from the document")
		}
		operations, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("path item is %T", item)
		}
		get, ok := operations["get"].(map[string]any)
		if !ok {
			t.Fatalf("get is %T", operations["get"])
		}
		if get["operationId"] != "me" {
			t.Fatalf("operationId = %v, want %q — the JWKS item replaced the documented route",
				get["operationId"], "me")
		}
	})
}
