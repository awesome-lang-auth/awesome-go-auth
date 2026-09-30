package wiretest

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// The OIDC group: the four endpoints the adapters mount beside the JWKS route
// on an Auth built with auth.WithIDP — the discovery document, authorize, token
// and userinfo.
//
// They are the endpoints (*auth.IDP).RegisterHandlers has always mounted, at
// the same paths, served by the same handlers; what is new is that they sit
// inside the adapters' own mount and therefore inside this suite. Nothing here
// is cited: the reference ships no OIDC authorization server, so these four
// have no counterpart to be faithful to, and every assertion below states what
// idp.go's handlers do rather than what some reference line says they should.
// That also means this file is where their shapes are pinned for all four
// adapters — a change in any of them fails here four times.
//
// The unhappy paths of authorize and userinfo are the standard library's
// http.Error: a plain-text line, not the family's JSON error envelope. That is
// a genuine difference from every other route in this suite and it is asserted
// as such, so that "fixing" it into an envelope is a visible decision rather
// than a silent one. The token endpoint's are the OAuth error body of RFC 6749
// §5.2 instead — {"error": ..., "error_description": ...} with Cache-Control:
// no-store — because that is the one a relying party's OAuth library parses;
// assertTokenRefusal holds that shape, and oidc_token.go holds the flows
// behind it: PKCE, the two client authentication methods, and the
// refresh_token grant.
//
// The other half of the contract — that the four are absent without WithIDP,
// and that the generated OpenAPI document tracks them in both directions — is
// the "oidc" conditional set at the bottom of this file, replayed by
// testOpenAPI.
//
// Resource-server mode cuts across both halves and has a case of its own here:
// HTTPConfig.ResourceServer unmounts authorize and token, the two of the four
// that create or exchange a credential, and leaves discovery and userinfo
// where they are. That combination is not a conditional set because the
// harness's removes field only takes routes the base configuration mounts.

// The clients the suite's IdP registers. authorize and token both refuse every
// request whose client_id is not registered, so without one the refusals below
// could not tell an unknown client from an empty registry; the second is what
// a token issued to the first is presented by in the wrong-client cases.
const (
	testOIDCClientID          = "wiretest-client"
	testOIDCClientSecret      = "wiretest-client-secret"
	testOIDCRedirectURI       = "https://rp.example.com/callback"
	testOIDCOtherClientID     = "wiretest-other-client"
	testOIDCOtherClientSecret = "wiretest-other-client-secret"
)

// newTestOIDCIDP builds the IdP the OIDC cases mount: the JWKS group's key,
// issuer and kid — the key is generated once for the whole binary, see
// testIDPKey — plus the two registered clients, which newTestIDP has no
// reason to carry.
func newTestOIDCIDP() *auth.IDP {
	// The Service is nil: auth.WithIDP binds the one the Auth is built around,
	// which is the Service /token and /userinfo then read their user from.
	idp, err := auth.NewIDP(
		auth.IDPConfig{Issuer: testIDPIssuer, Signer: testIDPKey(), KeyID: testIDPKeyID},
		nil,
		auth.IDPClient{
			ClientID:     testOIDCClientID,
			ClientSecret: testOIDCClientSecret,
			RedirectURIs: []string{testOIDCRedirectURI},
			Name:         "wiretest relying party",
		},
		auth.IDPClient{
			ClientID:     testOIDCOtherClientID,
			ClientSecret: testOIDCOtherClientSecret,
			RedirectURIs: []string{testOIDCRedirectURI},
			Name:         "wiretest other relying party",
		},
	)
	if err != nil {
		// Unreachable with a valid config, and conditionalRouteSet hooks have no
		// *testing.T to fail through.
		panic("wiretest: auth.NewIDP: " + err.Error())
	}
	return idp
}

// newOIDCEnv mounts an adapter on an Auth carrying that IdP.
func newOIDCEnv(t *testing.T, mount Mounter) *Env {
	t.Helper()
	return NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIDP(newTestOIDCIDP()))
}

// oidcAuthorizeQuery is the query an authorization request carries, with the
// client_id left to the caller so that the registered and the unregistered case
// differ in exactly that one parameter.
func oidcAuthorizeQuery(clientID string) string {
	return "?" + url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {testOIDCRedirectURI},
		"response_type": {"code"},
		"state":         {"opaque-state"},
	}.Encode()
}

// oidcForm builds an application/x-www-form-urlencoded request, the encoding
// the token endpoint reads its parameters from.
func oidcForm(env *Env, path string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// assertOIDCRefusal holds one http.Error answer: the status, the single
// plain-text line, and the two things every refusal on these routes has to
// keep — no cookie, since the endpoints are mounted ahead of the CSRF
// middleware, and nothing of the token or the profile it declined to issue.
func assertOIDCRefusal(t *testing.T, rec *httptest.ResponseRecorder, status int, want string) {
	t.Helper()
	AssertStatus(t, rec, status)
	if got := strings.TrimSpace(rec.Body.String()); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain — these endpoints refuse with http.Error, "+
			"not the family's JSON error envelope", got)
	}
	AssertNoCookies(t, rec)
	for _, leaked := range []string{"access_token", "refresh_token", "id_token", `"sub"`, `"email"`} {
		if strings.Contains(rec.Body.String(), leaked) {
			t.Errorf("a refusal body carries %s: %s", leaked, rec.Body.String())
		}
	}
}

// assertOIDCUnrouted fails unless the request missed the route entirely. The Go
// routers disagree on 404 versus 405 among themselves, so both are accepted;
// what matters is that no handler of this group answered.
func assertOIDCUnrouted(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	switch rec.Code {
	case http.StatusNotFound, http.StatusMethodNotAllowed:
	default:
		t.Fatalf("status = %d, want 404 or 405 (body %q)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "issuer") {
		t.Errorf("an unrouted request was served the discovery document: %s", rec.Body.String())
	}
}

// assertOIDCStringList compares one list-of-strings member of the discovery
// document, order included: a relying party reads these as preference order.
func assertOIDCStringList(t *testing.T, doc map[string]any, member string, want ...string) {
	t.Helper()
	raw, ok := doc[member].([]any)
	if !ok {
		t.Errorf("%s = %#v, want a list of strings", member, doc[member])
		return
	}
	got := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Errorf("%s contains %#v, want a string", member, v)
			return
		}
		got = append(got, s)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s = [%s], want [%s]", member, strings.Join(got, ","), strings.Join(want, ","))
	}
}

// assertOIDCDiscoveryDocument holds one answer from the discovery endpoint to
// the frame every one of them has: 200, application/json, no cookie — it is
// mounted ahead of the CSRF middleware like the JWKS route and a relying party
// fetches it with no credential at all — and exactly the thirteen members. It
// returns the parsed document so a caller can go on to the values.
func assertOIDCDiscoveryDocument(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	AssertStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
	AssertNoCookies(t, rec)

	doc := Body(t, rec)
	AssertKeys(t, doc,
		"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
		"response_types_supported", "subject_types_supported",
		"id_token_signing_alg_values_supported", "scopes_supported", "grant_types_supported",
		"token_endpoint_auth_methods_supported", "code_challenge_methods_supported", "claims_supported",
	)
	return doc
}

func testOIDC(t *testing.T, mount Mounter) {
	t.Run("the discovery document", func(t *testing.T) {
		env := newOIDCEnv(t, mount)
		doc := assertOIDCDiscoveryDocument(t,
			env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.OIDCDiscoveryPath, nil)))

		// Every URL is derived from IDPConfig.Issuer, not from the mount prefix:
		// the document says where the IdP is reached from outside, which is why
		// Issuer has to carry the prefix for the advertised paths to resolve.
		for member, want := range map[string]string{
			"issuer":                 testIDPIssuer,
			"authorization_endpoint": testIDPIssuer + auth.OIDCAuthorizePath,
			"token_endpoint":         testIDPIssuer + auth.OIDCTokenPath,
			"userinfo_endpoint":      testIDPIssuer + auth.OIDCUserInfoPath,
			"jwks_uri":               testIDPIssuer + auth.DefaultJWKSPath,
		} {
			if doc[member] != want {
				t.Errorf("%s = %v, want %q", member, doc[member], want)
			}
		}
		assertOIDCStringList(t, doc, "response_types_supported", "code")
		assertOIDCStringList(t, doc, "subject_types_supported", "public")
		assertOIDCStringList(t, doc, "id_token_signing_alg_values_supported", "RS256")
		assertOIDCStringList(t, doc, "scopes_supported", "openid", "email", "profile", "offline_access")
		assertOIDCStringList(t, doc, "grant_types_supported", "authorization_code", "refresh_token")
		assertOIDCStringList(t, doc, "token_endpoint_auth_methods_supported", "client_secret_basic", "client_secret_post")
		assertOIDCStringList(t, doc, "code_challenge_methods_supported", "S256")
		assertOIDCStringList(t, doc, "claims_supported",
			"sub", "email", "name", "iat", "exp", "iss", "aud", "nonce")

		// And the advertised jwks_uri is a URL this very mount serves. The
		// suite's Issuer ends in the default prefix, so the two halves of the
		// IdP surface are checked against each other rather than against a
		// constant: a discovery document pointing at a path nobody mounts is
		// the failure a relying party hits first.
		advertised, _ := doc["jwks_uri"].(string)
		parsed, err := url.Parse(advertised)
		if err != nil {
			t.Fatalf("parse jwks_uri %q: %v", advertised, err)
		}
		keys := env.Do(httptest.NewRequest(http.MethodGet, parsed.Path, nil))
		AssertStatus(t, keys, http.StatusOK)
	})

	t.Run("authorize refuses an unknown client", func(t *testing.T) {
		env := newOIDCEnv(t, mount)
		rec := env.Do(httptest.NewRequest(http.MethodGet,
			env.Config.Prefix()+auth.OIDCAuthorizePath+oidcAuthorizeQuery("nobody-registered-this"), nil))
		assertOIDCRefusal(t, rec, http.StatusBadRequest, "unknown client")

		// The same request for the registered client reaches the sign-in form,
		// so the refusal above is about the client and not about the route
		// being mounted wrong.
		ok := env.Do(httptest.NewRequest(http.MethodGet,
			env.Config.Prefix()+auth.OIDCAuthorizePath+oidcAuthorizeQuery(testOIDCClientID), nil))
		AssertStatus(t, ok, http.StatusOK)
		if got := ok.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
			t.Errorf("Content-Type = %q, want text/html — the GET answer is the sign-in form", got)
		}
		if !strings.Contains(ok.Body.String(), "<form") {
			t.Errorf("the authorize form is missing from %s", ok.Body.String())
		}

		// A registered client with an unregistered redirect_uri is refused too,
		// and differently: the allowlist is what keeps the redirect target
		// server-controlled.
		bad := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.OIDCAuthorizePath+"?"+url.Values{
			"client_id":    {testOIDCClientID},
			"redirect_uri": {"https://attacker.example.com/callback"},
		}.Encode(), nil))
		assertOIDCRefusal(t, bad, http.StatusBadRequest, "redirect_uri not allowed")
	})

	t.Run("token refuses a code nobody issued", func(t *testing.T) {
		env := newOIDCEnv(t, mount)
		rec := env.Do(oidcForm(env, auth.OIDCTokenPath, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"a-code-this-idp-never-minted"},
			"client_id":     {testOIDCClientID},
			"client_secret": {testOIDCClientSecret},
		}))
		assertTokenRefusal(t, rec, http.StatusBadRequest, "invalid_grant")

		// The client credentials are checked before the code, so an unknown
		// client is a different refusal with a different status — which is what
		// makes the 400 above a statement about the code.
		unknown := env.Do(oidcForm(env, auth.OIDCTokenPath, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"a-code-this-idp-never-minted"},
			"client_id":     {"nobody-registered-this"},
			"client_secret": {testOIDCClientSecret},
		}))
		assertTokenRefusal(t, unknown, http.StatusUnauthorized, "invalid_client")

		// And the registered client with the wrong secret is the same refusal:
		// the endpoint never distinguishes the two for a caller.
		wrongSecret := env.Do(oidcForm(env, auth.OIDCTokenPath, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"a-code-this-idp-never-minted"},
			"client_id":     {testOIDCClientID},
			"client_secret": {"not-the-secret"},
		}))
		assertTokenRefusal(t, wrongSecret, http.StatusUnauthorized, "invalid_client")

		// Two grants are implemented, and they are the two the discovery
		// document advertises; any other is refused before the client is
		// looked at.
		other := env.Do(oidcForm(env, auth.OIDCTokenPath, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {testOIDCClientID},
			"client_secret": {testOIDCClientSecret},
		}))
		assertTokenRefusal(t, other, http.StatusBadRequest, "unsupported_grant_type")
	})

	t.Run("userinfo refuses a token nobody signed", func(t *testing.T) {
		env := newOIDCEnv(t, mount)
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.OIDCUserInfoPath, nil)
		req.Header.Set("Authorization", "Bearer not-a-token-this-deployment-can-verify")
		assertOIDCRefusal(t, env.Do(req), http.StatusUnauthorized, "unauthorized")

		// The Authorization header is the only credential read: no header at
		// all is the same refusal, and a session cookie is not a substitute.
		bare := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.OIDCUserInfoPath, nil)
		assertOIDCRefusal(t, env.Do(bare), http.StatusUnauthorized, "unauthorized")

		env.Seed("userinfo@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("userinfo@example.com")))
		cookied := Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.OIDCUserInfoPath, nil), login)
		assertOIDCRefusal(t, env.Do(cookied), http.StatusUnauthorized, "unauthorized")
	})

	t.Run("the endpoints answer on any method", func(t *testing.T) {
		// RegisterHandlers mounts them with a method-less ServeMux pattern, so
		// the adapters register every method rather than a list of their own
		// (auth.OIDCMounts). The handlers do the discrimination themselves —
		// authorize reads r.Method, token reads the form, userinfo reads the
		// Authorization header — so each method below is answered by the
		// handler, not by the router.
		env := newOIDCEnv(t, mount)
		// All four, so that an adapter narrowing any one of them to its
		// canonical method fails here rather than passing everything else.
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(method+" discovery", func(t *testing.T) {
				req := httptest.NewRequest(method, env.Config.Prefix()+auth.OIDCDiscoveryPath, nil)
				assertOIDCDiscoveryDocument(t, env.Do(req))
			})
		}
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			t.Run(method+" token", func(t *testing.T) {
				req := httptest.NewRequest(method, env.Config.Prefix()+auth.OIDCTokenPath, nil)
				assertTokenRefusal(t, env.Do(req), http.StatusBadRequest, "unsupported_grant_type")
			})
		}
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(method+" userinfo", func(t *testing.T) {
				req := httptest.NewRequest(method, env.Config.Prefix()+auth.OIDCUserInfoPath, nil)
				assertOIDCRefusal(t, env.Do(req), http.StatusUnauthorized, "unauthorized")
			})
		}
		// authorize is the one that reads r.Method, so its three non-canonical
		// methods split: POST is the credential post, which with no form at all
		// is the handler's own refusal of an empty email and password, and
		// anything else falls through to the branch that renders the form. Both
		// are answers from the handler; a router that had narrowed the route to
		// GET would give a 404 or a 405 instead.
		authorize := env.Config.Prefix() + auth.OIDCAuthorizePath + oidcAuthorizeQuery(testOIDCClientID)
		t.Run("POST authorize", func(t *testing.T) {
			assertOIDCRefusal(t, env.Do(httptest.NewRequest(http.MethodPost, authorize, nil)),
				http.StatusUnauthorized, "invalid credentials")
		})
		for _, method := range []string{http.MethodPut, http.MethodDelete} {
			t.Run(method+" authorize", func(t *testing.T) {
				rec := env.Do(httptest.NewRequest(method, authorize, nil))
				AssertStatus(t, rec, http.StatusOK)
				if !strings.Contains(rec.Body.String(), "<form") {
					t.Errorf("the authorize form is missing from %s", rec.Body.String())
				}
			})
		}
	})

	t.Run("resource-server mode unmounts authorize and token", func(t *testing.T) {
		// HTTPConfig.ResourceServer leaves unmounted every route that creates or
		// changes a credential, and two of these four are such routes: POST
		// authorize takes an email and a password and calls Service.Login, and
		// POST token spends the resulting code for this instance's own session
		// pair. A deployment that set the flag to unmount /login and /refresh
		// and then also built WithIDP would otherwise regain both in two hops.
		// See auth.OIDCMount.ResourceServerGated.
		cfg := auth.DefaultHTTPConfig()
		cfg.ResourceServer = true
		env := NewEnv(t, mount, cfg, auth.WithIDP(newTestOIDCIDP()))

		t.Run("authorize is gone", func(t *testing.T) {
			assertOIDCUnrouted(t, env.Do(httptest.NewRequest(http.MethodGet,
				env.Config.Prefix()+auth.OIDCAuthorizePath+oidcAuthorizeQuery(testOIDCClientID), nil)))
			assertOIDCUnrouted(t, env.Do(httptest.NewRequest(http.MethodPost,
				env.Config.Prefix()+auth.OIDCAuthorizePath+oidcAuthorizeQuery(testOIDCClientID), nil)))
		})
		t.Run("token is gone", func(t *testing.T) {
			assertOIDCUnrouted(t, env.Do(oidcForm(env, auth.OIDCTokenPath, url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {"a-code-this-idp-never-minted"},
				"client_id":     {testOIDCClientID},
				"client_secret": {testOIDCClientSecret},
			})))
		})
		// The other two stay, on the terms resource_server.go gives: discovery
		// is metadata like the JWKS document beside it, and userinfo reads a
		// bearer token and returns a profile, which is GET /me's shape and
		// stays for GET /me's reason.
		t.Run("discovery and userinfo stay", func(t *testing.T) {
			assertOIDCDiscoveryDocument(t,
				env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.OIDCDiscoveryPath, nil)))
			req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.OIDCUserInfoPath, nil)
			req.Header.Set("Authorization", "Bearer not-a-token-this-deployment-can-verify")
			assertOIDCRefusal(t, env.Do(req), http.StatusUnauthorized, "unauthorized")
			AssertStatus(t, env.Do(httptest.NewRequest(http.MethodGet,
				env.Config.Prefix()+auth.DefaultJWKSPath, nil)), http.StatusOK)
		})
		// And the generated document says the same thing, so a spec built with
		// both flags cannot advertise the two paths the adapter stopped
		// mounting. The conditional-set harness cannot state this — its removes
		// field only takes routes the base configuration mounts, and these two
		// are routes only under WithIDP — so it is asserted here.
		t.Run("the spec drops the same two", func(t *testing.T) {
			spec := auth.GenerateOpenAPISpec(auth.OpenAPIInfo{
				APIPrefix:      env.Config.APIPrefix,
				IDProvider:     true,
				OIDC:           true,
				ResourceServer: true,
			})
			paths, ok := spec["paths"].(map[string]any)
			if !ok {
				t.Fatalf("spec has no paths object: %T", spec["paths"])
			}
			for route, want := range map[string]bool{
				auth.OIDCDiscoveryPath: true,
				auth.OIDCUserInfoPath:  true,
				auth.OIDCAuthorizePath: false,
				auth.OIDCTokenPath:     false,
			} {
				if _, got := paths[env.Config.Prefix()+route]; got != want {
					t.Errorf("spec documents %s = %v, want %v", route, got, want)
				}
			}
		})
	})

	t.Run("without WithIDP there are no routes", func(t *testing.T) {
		// The same condition the JWKS route is mounted under, and the same
		// answer without it. testOpenAPI asserts this through the conditional
		// set; this is the group saying it in its own terms.
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		for route, method := range oidcRouteSet().routes {
			t.Run(method+" "+route, func(t *testing.T) {
				assertOIDCUnrouted(t, env.Do(httptest.NewRequest(method, env.Config.Prefix()+route, nil)))
			})
		}
	})
}

// oidcRouteSet is the conditional set testOpenAPI replays: configured, the
// adapter serves the four OIDC endpoints and the document generated with
// OpenAPIInfo.OIDC describes them; unconfigured, neither does.
//
// One method per path, because the harness compares a documented path to one
// method. It is the method that drives the flow — a relying party GETs the
// discovery document and the sign-in form, POSTs to the token endpoint, and
// GETs userinfo — and the handlers answer the others too, which "the endpoints
// answer on any method" above pins instead.
func oidcRouteSet() conditionalRouteSet {
	return conditionalRouteSet{
		name: "oidc",
		configure: func(pc *probeConfig) {
			pc.Opts = append(pc.Opts, auth.WithIDP(newTestOIDCIDP()))
		},
		routes: map[string]string{
			auth.OIDCDiscoveryPath: http.MethodGet,
			auth.OIDCAuthorizePath: http.MethodGet,
			auth.OIDCTokenPath:     http.MethodPost,
			auth.OIDCUserInfoPath:  http.MethodGet,
		},
		spec: func() auth.OpenAPIInfo { return auth.OpenAPIInfo{OIDC: true} },
	}
}
