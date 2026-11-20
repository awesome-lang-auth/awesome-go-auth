package wiretest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Resource-server mode has two halves and this file pins both for every
// adapter.
//
// The first is subtractive: HTTPConfig.ResourceServer leaves the twenty
// credential routes unregistered, so each answers 404 while the rest of the
// surface is untouched. That is testResourceServerGating, plus the
// resourceServerRouteSet registered in conditionalRoutes, which additionally
// holds the generated spec to the same list.
//
// The second is the middleware: a bearer token verified against a remote JWKS
// and a cookie verified locally, on a host route the adapter mounts itself.
// The suite cannot reach that through a plain Mounter — there is no host route
// in it — so RunResourceServer takes a ResourceServerMounter, which each
// adapter test supplies, and the assertions stay here.

// resourceServerRouteSet is the conditional set for HTTPConfig.ResourceServer.
// It declares no added routes and removes the credential ones: the inverse
// direction the harness grew a removes field for.
func resourceServerRouteSet() conditionalRouteSet {
	return conditionalRouteSet{
		name:      "ResourceServer",
		configure: func(pc *probeConfig) { pc.HTTP.ResourceServer = true },
		removes:   auth.ResourceServerGatedRoutes(),
		spec:      func() auth.OpenAPIInfo { return auth.OpenAPIInfo{ResourceServer: true} },
	}
}

// resourceServerKeptRoutes are the routes that must survive the gating, with a
// request that reaches them without a credential. They are asserted by status
// alone: the point is that the route is mounted, not what it answers.
// The OAuth group is left out here and covered by the conditional set in
// testOpenAPI instead, which mounts under an env that configures a provider:
// unconfigured, those routes answer 404 for a reason that has nothing to do
// with the gating.
var resourceServerKeptRoutes = map[string]string{
	"/me":               http.MethodGet,
	"/sessions":         http.MethodGet,
	"/sessions/cleanup": http.MethodPost,
	"/profile":          http.MethodPatch,
	"/add-phone":        http.MethodPost,
	"/account":          http.MethodDelete,
}

// testResourceServerGating pins the unmounting itself: with
// HTTPConfig.ResourceServer set every credential route answers 404, and the
// routes a resource server can still serve are still there.
//
// Only the status is asserted for the gated routes. An unregistered path is
// answered by the router, not by this library, and the four routers write four
// different bodies — which is exactly the reference behaviour too, where an
// unregistered Express route falls through to the application 404 handler
// (auth.router.ts:541 and the five siblings guard the registration, not the
// handler).
func testResourceServerGating(t *testing.T, mount Mounter) {
	cfg := auth.DefaultHTTPConfig()
	cfg.ResourceServer = true
	env := NewEnv(t, mount, cfg)

	for route, method := range auth.ResourceServerGatedRoutes() {
		rec := env.Do(env.Request(method, route, map[string]string{}))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 404 — resource-server mode must not mount it (body %q)",
				method, route, rec.Code, rec.Body.String())
		}
	}

	for route, method := range resourceServerKeptRoutes {
		rec := env.Do(env.Request(method, route, map[string]string{}))
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d in resource-server mode, want it still mounted",
				method, route, rec.Code)
		}
	}

	// The gating is the configuration, not the build: the same adapter without
	// the flag still serves the credential routes.
	open := NewEnv(t, mount, auth.DefaultHTTPConfig())
	rec := open.Do(open.Request(http.MethodPost, "/login", credentials("gate@example.com")))
	if rec.Code == http.StatusNotFound {
		t.Errorf("POST /login = 404 without ResourceServer set; the flag must be what unmounts it")
	}
}

// ResourceServerProbePath is where a ResourceServerMounter must mount its
// probe route, relative to nothing: it is an absolute path outside the auth
// mount prefix, because a host route is what the middleware is for.
const ResourceServerProbePath = "/rs-probe"

// ResourceServerMounter builds a handler that mounts the auth routes under cfg
// *and* one GET route at ResourceServerProbePath behind the adapter own
// resource-server middleware built from rs. The probe handler must answer with
// WriteResourceServerProbe, reading the user through the adapter own
// UserFromContext — which is the part that differs per framework and the
// reason this is a second Mounter rather than a flag on the first.
type ResourceServerMounter func(t *testing.T, a *auth.Auth, cfg auth.HTTPConfig, rs auth.ResourceServerConfig) http.Handler

// WriteResourceServerProbe writes the principal the middleware put in context,
// so the assertions below can be made once for all four adapters.
func WriteResourceServerProbe(w http.ResponseWriter, user auth.User, ok bool) {
	if !ok {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "no user in context"})
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{
		"id":              user.ID,
		"email":           user.Email,
		"tenantId":        user.TenantID,
		"role":            user.Role,
		"loginProvider":   user.LoginProvider,
		"isEmailVerified": user.IsEmailVerified,
		"isTotpEnabled":   user.IsTOTPEnabled,
	})
}

const (
	rsIssuer = "https://issuer.example.test"
	rsKeyID  = "rs-key-1"
)

// rsIssuerServer is a fake identity provider: an RSA key, a JWKS endpoint that
// publishes it, and a minter for tokens signed with it.
type rsIssuerServer struct {
	key    *rsa.PrivateKey
	server *httptest.Server
}

func newRSIssuer(t *testing.T) *rsIssuerServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	jwk, err := auth.NewRSAJWK(&key.PublicKey, rsKeyID)
	if err != nil {
		t.Fatalf("build jwk: %v", err)
	}
	document := auth.JWKS{Keys: []auth.JWK{jwk}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(document)
	}))
	t.Cleanup(srv.Close)
	return &rsIssuerServer{key: key, server: srv}
}

func (s *rsIssuerServer) config() auth.ResourceServerConfig {
	return auth.ResourceServerConfig{JWKSURL: s.server.URL, Issuer: rsIssuer}
}

// mint signs an access token the way the issuer instance would: the six base
// claims of the reference payload plus iss and exp.
func (s *rsIssuerServer) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload := map[string]any{
		"sub":             "usr_rs",
		"email":           "rs@example.com",
		"role":            "member",
		"loginProvider":   "local",
		"isEmailVerified": true,
		"isTotpEnabled":   false,
		"tid":             "t1",
		"iss":             rsIssuer,
		"iat":             time.Now().Add(-time.Minute).Unix(),
		"exp":             time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range claims {
		payload[k] = v
	}
	token, err := auth.BuildRS256JWT(s.key, rsKeyID, payload)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return token
}

// RunResourceServer is the resource-server middleware matrix, run by each
// adapter against its own middleware and its own UserFromContext.
func RunResourceServer(t *testing.T, mount ResourceServerMounter) {
	issuer := newRSIssuer(t)
	rs := issuer.config()
	inner := func(t *testing.T, a *auth.Auth, cfg auth.HTTPConfig) http.Handler {
		return mount(t, a, cfg, rs)
	}

	probe := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, ResourceServerProbePath, nil)
	}

	t.Run("bearer RS256 reaches the handler with a principal built from the claims", func(t *testing.T) {
		env := NewEnv(t, inner, auth.DefaultHTTPConfig())
		req := probe()
		req.Header.Set("Authorization", "Bearer "+issuer.mint(t, nil))
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "id", "email", "tenantId", "role", "loginProvider", "isEmailVerified", "isTotpEnabled")
		for key, want := range map[string]any{
			"id":              "usr_rs",
			"email":           "rs@example.com",
			"tenantId":        "t1",
			"role":            "member",
			"loginProvider":   "local",
			"isEmailVerified": true,
			"isTotpEnabled":   false,
		} {
			if body[key] != want {
				t.Errorf("%s = %v, want %v", key, body[key], want)
			}
		}
	})

	t.Run("no store read: the principal is the token, not a user record", func(t *testing.T) {
		// The subject exists in no store here — an empty memory user store is
		// all the env has — and the request still succeeds. That is what
		// resource-server mode is.
		env := NewEnv(t, inner, auth.DefaultHTTPConfig())
		req := probe()
		req.Header.Set("Authorization", "Bearer "+issuer.mint(t, map[string]any{"sub": "usr_absent", "email": "absent@example.com"}))
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		if got := Body(t, rec)["id"]; got != "usr_absent" {
			t.Errorf("id = %v, want usr_absent", got)
		}
	})

	t.Run("cookie session is still verified locally", func(t *testing.T) {
		env := NewEnv(t, inner, auth.DefaultHTTPConfig())
		seeded, tokens := env.Seed("cookie-rs@example.com")
		req := probe()
		req.AddCookie(&http.Cookie{Name: hostAccess, Value: tokens.AccessToken})
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		if body["email"] != seeded.Email {
			t.Errorf("email = %v, want %q", body["email"], seeded.Email)
		}
	})

	t.Run("the cookie is verified without a user store", func(t *testing.T) {
		// The case above cannot fail on a store read, because every Env wires a
		// populated memory user store. This one takes the subject back out, so
		// the request reaches the middleware with a perfectly good token for a
		// user this instance has no record of — which is the permanent state of
		// a resource server, and what the reference's cookie path verifies
		// happily (a bare jwt.verify, token.service.ts:143-150).
		users := auth.NewMemoryUserStore()
		env := NewEnv(t, inner, auth.DefaultHTTPConfig(), auth.WithUserStore(users))
		seeded, tokens := env.Seed("storeless-rs@example.com")
		if err := users.DeleteUser(context.Background(), seeded.ID, seeded.TenantID); err != nil {
			t.Fatalf("drop the user record: %v", err)
		}
		if _, err := env.Auth.Authenticate(context.Background(), tokens.AccessToken); err == nil {
			t.Fatal("the store-reading path is supposed to fail here; if it no longer does, " +
				"this case cannot tell the two paths apart")
		}

		req := probe()
		req.AddCookie(&http.Cookie{Name: hostAccess, Value: tokens.AccessToken})
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		if body := Body(t, rec); body["email"] != seeded.Email {
			t.Errorf("email = %v, want %q — the principal must come from the token", body["email"], seeded.Email)
		}
	})

	t.Run("an empty bearer is the code-less 403 even with a valid cookie", func(t *testing.T) {
		// The reference selects the path on the `Bearer ` prefix, not on what
		// follows it: token === '' is no token at all, and the cookie is never
		// consulted (jwks-auth.middleware.ts:49-59).
		env := NewEnv(t, inner, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("empty-bearer@example.com")
		req := probe()
		req.Header.Set("Authorization", "Bearer ")
		req.AddCookie(&http.Cookie{Name: hostAccess, Value: tokens.AccessToken})
		AssertError(t, env.Do(req), http.StatusForbidden, "No access token provided", "")
	})

	t.Run("the bearer scheme is case-sensitive", func(t *testing.T) {
		// startsWith('Bearer ') does not match a lowercase scheme, so the
		// request falls back to the cookie and the RS256 token is never read.
		env := NewEnv(t, inner, auth.DefaultHTTPConfig())
		seeded, tokens := env.Seed("lower-bearer@example.com")
		req := probe()
		req.Header.Set("Authorization", "bearer "+issuer.mint(t, nil))
		req.AddCookie(&http.Cookie{Name: hostAccess, Value: tokens.AccessToken})
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		if body := Body(t, rec); body["email"] != seeded.Email {
			t.Errorf("email = %v, want the cookie principal %q", body["email"], seeded.Email)
		}
	})

	t.Run("no token at all is the code-less 403", func(t *testing.T) {
		env := NewEnv(t, inner, auth.DefaultHTTPConfig())
		AssertError(t, env.Do(probe()), http.StatusForbidden, "No access token provided", "")
	})

	t.Run("an unusable bearer token is 401 INVALID_TOKEN", func(t *testing.T) {
		env := NewEnv(t, inner, auth.DefaultHTTPConfig())
		for name, token := range map[string]string{
			"garbage":       "not-a-jwt",
			"wrong issuer":  issuer.mint(t, map[string]any{"iss": "https://elsewhere.example.test"}),
			"expired":       issuer.mint(t, map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}),
			"local HS256":   localHS256Token(t, env),
			"tampered body": tamper(issuer.mint(t, nil), issuer.mint(t, map[string]any{"sub": "someone-else"})),
		} {
			t.Run(name, func(t *testing.T) {
				req := probe()
				req.Header.Set("Authorization", "Bearer "+token)
				AssertError(t, env.Do(req), http.StatusUnauthorized, "Invalid or expired access token", auth.CodeInvalidToken)
			})
		}
	})

	t.Run("an unusable cookie is the same 401", func(t *testing.T) {
		env := NewEnv(t, inner, auth.DefaultHTTPConfig())
		req := probe()
		req.AddCookie(&http.Cookie{Name: hostAccess, Value: "not-a-jwt"})
		AssertError(t, env.Do(req), http.StatusUnauthorized, "Invalid or expired access token", auth.CodeInvalidToken)
	})
}

// localHS256Token is a valid session token of this instance. Presented as a
// bearer token to a resource server it must fail: the bearer path is RS256
// against the remote JWKS and nothing else.
func localHS256Token(t *testing.T, env *Env) string {
	t.Helper()
	_, tokens := env.Seed("hs256-as-bearer@example.com")
	return tokens.AccessToken
}

// tamper splices the header and payload of one token onto the signature of
// another: three well-formed segments, signed by the right key, whose signature
// does not cover these claims. Flipping a character would be flakier — the last
// base64url character of a signature carries spare bits, so some flips decode
// back to the same bytes.
func tamper(signed, other string) string {
	a, b := strings.Split(signed, "."), strings.Split(other, ".")
	if len(a) != 3 || len(b) != 3 {
		return signed
	}
	return a[0] + "." + a[1] + "." + b[2]
}
