package wiretest

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Cookie names under the default (Secure) configuration.
const (
	hostAccess  = "__Host-accessToken"
	hostRefresh = "__Host-refreshToken"
	hostCSRF    = "__Host-csrf-token"
)

// csrfPairValue is an arbitrary 32-hex token. The middleware only compares the
// header against the cookie, so the value's shape is irrelevant — only that the
// two match.
const csrfPairValue = "0123456789abcdef0123456789abcdef"

// csrfPair gives a request a valid double-submit pair so that it clears the CSRF
// middleware and reaches whatever sits behind it.
//
// It is needed only for POST /link-request. That route has no auth middleware in
// the reference, which checks the double-submit by hand inside the handler
// instead (auth.router.ts:1489-1495), so the port keeps enforcing it whether or
// not the request is cookie-authenticated. Every other mutating route defers an
// unauthenticated request to the auth gate, so a credential-less case there needs
// no pair at all and must not be given one — the pair would hide the very
// ordering those cases exist to pin.
//
// A garbage bearer token is not a substitute for either: the auth gate would
// answer "Invalid or expired access token" instead of "No access token provided".
func csrfPair(req *http.Request) *http.Request {
	req.AddCookie(&http.Cookie{Name: hostCSRF, Value: csrfPairValue})
	req.Header.Set(auth.CSRFHeaderName, csrfPairValue)
	return req
}

const (
	defaultAccessMaxAge  = int(15 * time.Minute / time.Second)
	defaultRefreshMaxAge = int(30 * 24 * time.Hour / time.Second)
	defaultCSRFMaxAge    = int(15 * time.Minute / time.Second)
)

// Run executes the wire-contract conformance suite against one adapter.
func Run(t *testing.T, mount Mounter) {
	t.Run("Register", func(t *testing.T) { testRegister(t, mount) })
	t.Run("Login", func(t *testing.T) { testLogin(t, mount) })
	t.Run("Refresh", func(t *testing.T) { testRefresh(t, mount) })
	t.Run("Logout", func(t *testing.T) { testLogout(t, mount) })
	t.Run("Me", func(t *testing.T) { testMe(t, mount) })
	t.Run("Claims", func(t *testing.T) { testClaims(t, mount) })
	t.Run("SessionRevoked", func(t *testing.T) { testSessionRevoked(t, mount) })
	t.Run("DeletedUser", func(t *testing.T) { testDeletedUser(t, mount) })
	t.Run("Sessions", func(t *testing.T) { testSessions(t, mount) })
	t.Run("Account", func(t *testing.T) { testAccount(t, mount) })
	t.Run("CookieNames", func(t *testing.T) { testCookieNames(t, mount) })
	t.Run("CookieReadPriority", func(t *testing.T) { testCookieReadPriority(t, mount) })
	t.Run("CSRF", func(t *testing.T) { testCSRF(t, mount) })
	t.Run("Redaction", func(t *testing.T) { testRedaction(t, mount) })
	t.Run("OAuthLinking", func(t *testing.T) { RunOAuthLinking(t, mount) })
	t.Run("MagicLink", func(t *testing.T) { testMagicLink(t, mount) })
	t.Run("SMSOTP", func(t *testing.T) { testSMSOTP(t, mount) })
	t.Run("TwoFactor", func(t *testing.T) { testTwoFactor(t, mount) })
	t.Run("LoginTwoFactor", func(t *testing.T) { testLoginTwoFactor(t, mount) })
	t.Run("StepUpModeDefault", func(t *testing.T) { testStepUpModeDefault(t, mount) })
	t.Run("StepUpEmptyBody", func(t *testing.T) { testStepUpEmptyBody(t, mount) })
	t.Run("CredentialEmptyBody", func(t *testing.T) { testCredentialEmptyBody(t, mount) })
	t.Run("PasswordAndEmail", func(t *testing.T) { testPasswordAndEmail(t, mount) })
	t.Run("PasswordEmailDelivery", func(t *testing.T) { testPasswordEmailDelivery(t, mount) })
	t.Run("JWKS", func(t *testing.T) { testJWKS(t, mount) })
	t.Run("OIDC", func(t *testing.T) { testOIDC(t, mount) })
	t.Run("UIConfig", func(t *testing.T) { testUIConfig(t, mount) })
	t.Run("UIPages", func(t *testing.T) { testUIPages(t, mount) })
	t.Run("ResourceServerGating", func(t *testing.T) { testResourceServerGating(t, mount) })
	t.Run("OpenAPI", func(t *testing.T) { testOpenAPI(t, mount) })
	t.Run("RateLimit", func(t *testing.T) { testRateLimit(t, mount) })
	t.Run("EventContext", func(t *testing.T) { testEventContext(t, mount) })
	t.Run("Docs", func(t *testing.T) { testDocs(t, mount) })
	t.Run("Admin", func(t *testing.T) { testAdmin(t, mount) })
	t.Run("Tools", func(t *testing.T) { testTools(t, mount) })
}

// documentedRoutes is the operation set GenerateOpenAPISpec must describe,
// relative to the mount prefix.
//
// It is spelled out rather than derived so the list has to be edited by hand
// when a route is added or dropped — deriving it from the spec would make the
// test agree with whatever the spec happens to say, which is how openapi.go
// drifted a whole major version behind the routes in the first place.
var documentedRoutes = map[string]string{
	"/register": http.MethodPost,
	"/login":    http.MethodPost,
	"/refresh":  http.MethodPost,
	"/logout":   http.MethodPost,
	"/me":       http.MethodGet,

	"/sessions":          http.MethodGet,
	"/sessions/{handle}": http.MethodDelete,
	"/sessions/cleanup":  http.MethodPost,
	"/profile":           http.MethodPatch,
	"/add-phone":         http.MethodPost,
	"/account":           http.MethodDelete,

	"/oauth/{provider}":                               http.MethodGet,
	"/oauth/{provider}/callback":                      http.MethodGet,
	"/linked-accounts":                                http.MethodGet,
	"/linked-accounts/{provider}/{providerAccountId}": http.MethodDelete,
	"/link-request":                                   http.MethodPost,
	"/link-verify":                                    http.MethodPost,

	"/magic-link/send":   http.MethodPost,
	"/magic-link/verify": http.MethodPost,
	"/sms/send":          http.MethodPost,
	"/sms/verify":        http.MethodPost,
	"/2fa/setup":         http.MethodPost,
	"/2fa/verify-setup":  http.MethodPost,
	"/2fa/verify":        http.MethodPost,
	"/2fa/disable":       http.MethodPost,

	"/forgot-password":         http.MethodPost,
	"/reset-password":          http.MethodPost,
	"/change-password":         http.MethodPost,
	"/send-verification-email": http.MethodPost,
	"/verify-email":            http.MethodGet,
	"/change-email/request":    http.MethodPost,
	"/change-email/confirm":    http.MethodPost,
}

// openAPIPathParam fills a documented path template with a value a router will
// actually route. A literal "{handle}" segment matches net/http's wildcard but
// not every framework's, so the probe substitutes a plain segment.
var openAPIPathParam = regexp.MustCompile(`\{[^/]+\}`)

// openAPIProbeSegment is what a path parameter is replaced with. It doubles as
// the name of the OAuth provider the probe env configures, so /oauth/{provider}
// resolves to something real.
const openAPIProbeSegment = "probe"

// openAPIPrefixes are the mount prefixes every spec-versus-mount comparison
// runs under: the default, and a non-default one so the spec's paths track the
// mount instead of hardcoding /auth.
var openAPIPrefixes = []string{"", "/api/auth"}

func openAPIPrefixName(prefix string) string {
	if prefix == "" {
		return "default prefix"
	}
	return prefix
}

// probeConfig is everything an OpenAPI probe env is built from. The harness
// fills it with the base configuration; a conditional route set's configure
// hook edits it before the env is mounted.
type probeConfig struct {
	// Mount is the adapter under test. A set leaves it alone: the routes a set
	// declares have to come from the adapter's own MountWithConfig, driven by
	// HTTP and Opts, or the suite ends up checking wiretest instead of the
	// adapter. It is a field only so the suite's own test can stand in a fake
	// route (see suite_test.go).
	Mount Mounter
	// HTTP is the wire configuration the adapter is mounted with. APIPrefix
	// belongs to the harness: a set that changes it is reported, not honoured.
	HTTP auth.HTTPConfig
	// Opts are handed to auth.New after the suite's defaults, which is how a set
	// wires a service the way a host application would (an IdP for JWKS, say).
	Opts []auth.Option
}

// conditionalRouteSet is a group of routes an adapter mounts only under some
// configuration, paired with the OpenAPIInfo flags that make
// GenerateOpenAPISpec describe them. documentedRoutes is the unconditional
// base; a set is what one configuration adds on top of it.
type conditionalRouteSet struct {
	// name labels the subtest and every failure message.
	name string
	// configure turns the set on by editing the probe config the env is built
	// from — a flag on HTTP, an Option appended to Opts.
	configure func(*probeConfig)
	// routes is the operation set the configuration adds, relative to the mount
	// prefix and in the shape of documentedRoutes. A route already in the base
	// set cannot be listed here: it would be conditional in name only.
	routes map[string]string
	// removes is the inverse: the operations the configuration *unmounts*, so
	// the comparison for this set is documentedRoutes ∪ routes − removes. Each
	// entry must be in documentedRoutes with the same method — a configuration
	// can only take away a route the base set has — and no route may be in both
	// routes and removes.
	//
	// It exists because resource-server mode is a route set that subtracts:
	// HTTPConfig.ResourceServer leaves the credential routes unregistered. A
	// set may declare routes, removes, or both, and must declare at least one.
	removes map[string]string
	// spec returns the OpenAPIInfo whose flags make GenerateOpenAPISpec include
	// routes and omit removes. APIPrefix is filled in by the harness.
	spec func() auth.OpenAPIInfo
}

// conditionalRoutes is the registry of route sets that exist only under a
// configuration. testOpenAPI holds each registered set to four things: with
// the set configured, the spec generated from set.spec() and the mounted
// routes agree in both directions on documentedRoutes ∪ set.routes −
// set.removes, and every route in set.removes answers 404 or 405; without it,
// the base spec and mount still agree on documentedRoutes alone, and every
// route of set.routes answers 404 or 405 there, so a route cannot quietly
// become unconditional without moving to documentedRoutes.
//
// Sets are registered in both directions. JWKS adds: it is switched on by
// auth.WithIDP and documented by OpenAPIInfo.IDProvider; see jwks.go. OIDC adds
// the IdP's other four endpoints from the same switch, documented by
// OpenAPIInfo.OIDC; see oidc.go. UI adds the config route
// HTTPConfig.UI.Enabled mounts, documented by OpenAPIInfo.UI; see ui.go. Docs
// adds the two documentation routes HTTPConfig.Docs.Enabled mounts, documented
// by OpenAPIInfo.Docs; see docs.go. Resource-server mode subtracts:
// HTTPConfig.ResourceServer leaves the credential routes unregistered and
// OpenAPIInfo.ResourceServer takes them out of the spec; see resource_server.go.
// The admin and tools sets join the additive half as those routers land.
// suite_test.go drives the mechanism itself with fake sets it passes in, so it
// stays independent of what is registered here.
var conditionalRoutes = []conditionalRouteSet{jwksRouteSet(), oidcRouteSet(), uiRouteSet(), docsRouteSet(), resourceServerRouteSet()}

// failureReporter is the slice of testing.T the OpenAPI checks report through.
// It is an interface so suite_test.go can record failures instead of raising
// them and assert on their text.
type failureReporter interface {
	Errorf(format string, args ...any)
}

// openAPIHarness is what testOpenAPI runs. Its parts are fields so the suite's
// own test can substitute a fake set, a generator that knows the fake's paths
// and a recording reporter; the adapter suites reach it only through
// testOpenAPI.
type openAPIHarness struct {
	mount    Mounter
	sets     []conditionalRouteSet
	generate func(auth.OpenAPIInfo) map[string]any
	// report receives every assertion failure; nil means the subtest's own T.
	report failureReporter
}

func (h openAPIHarness) reporter(t *testing.T) failureReporter {
	if h.report != nil {
		return h.report
	}
	return t
}

// baseConfig is the probe configuration with no conditional set applied.
func (h openAPIHarness) baseConfig(prefix string) probeConfig {
	cfg := auth.DefaultHTTPConfig()
	cfg.APIPrefix = prefix
	return probeConfig{
		Mount: h.mount,
		HTTP:  cfg,
		// The OAuth routes answer 404 for a provider nobody configured, which is
		// indistinguishable from "not mounted" at this level. Configuring a
		// provider named after the path-parameter substitution tells the two apart.
		Opts: []auth.Option{auth.WithOAuth(auth.OAuthWiring{
			Service: auth.NewOAuthService(auth.OAuthProvider{
				Name:         openAPIProbeSegment,
				ClientID:     "probe-client",
				ClientSecret: "probe-secret",
				RedirectURL:  "https://api.example.com/auth/oauth/" + openAPIProbeSegment + "/callback",
				AuthURL:      "https://provider.example.com/authorize",
				TokenURL:     "https://provider.example.com/token",
				UserInfoURL:  "https://provider.example.com/userinfo",
			}),
			LinkedAccounts: auth.NewMemoryLinkedAccounts(),
			PendingLinks:   auth.NewMemoryPendingLinks(),
			SiteURL:        "https://app.example.com",
			TenantID:       testTenant,
		})},
	}
}

// testOpenAPI holds the generated spec to the routes that exist.
//
// Every documented operation is replayed against the mounted adapter and must
// not answer 404 or 405. A spec is documentation nobody executes, so without
// this it rots silently: before this test existed openapi.go advertised
// /auth/totp/setup, /auth/sessions, /auth/forgot-password and
// /auth/reset-password, none of which any adapter has ever mounted.
//
// The base configuration is compared against documentedRoutes; each set in
// conditionalRoutes is then compared, configured, against the base plus its
// own routes. See runOpenAPI.
func testOpenAPI(t *testing.T, mount Mounter) {
	runOpenAPI(t, openAPIHarness{mount: mount, sets: conditionalRoutes, generate: auth.GenerateOpenAPISpec})
}

// runOpenAPI is testOpenAPI with its inputs exposed.
//
// With no sets the walk is the base comparison alone, once per prefix. Each
// set adds two things: in the base env, a check that none of its routes is
// reachable; in its own env, built with configure applied, the two-direction
// comparison of the spec set.spec() selects against documentedRoutes ∪
// set.routes.
func runOpenAPI(t *testing.T, h openAPIHarness) {
	sets := wellFormedSets(h.reporter(t), h.sets)

	for _, prefix := range openAPIPrefixes {
		t.Run(openAPIPrefixName(prefix), func(t *testing.T) {
			report := h.reporter(t)
			pc := h.baseConfig(prefix)
			env := NewEnv(t, pc.Mount, pc.HTTP, pc.Opts...)
			checkOpenAPI(report, env, h.generate(auth.OpenAPIInfo{APIPrefix: prefix}), documentedRoutes, nil)
			for _, set := range sets {
				checkUnconfigured(report, env, set)
			}
		})
	}

	for _, set := range sets {
		t.Run(set.name, func(t *testing.T) {
			want := minusRoutes(unionRoutes(documentedRoutes, set.routes), set.removes)
			for _, prefix := range openAPIPrefixes {
				t.Run(openAPIPrefixName(prefix), func(t *testing.T) {
					report := h.reporter(t)
					pc := h.baseConfig(prefix)
					base := pc.HTTP.Prefix()
					set.configure(&pc)
					if got := pc.HTTP.Prefix(); got != base {
						report.Errorf("conditional set %q changed the mount prefix to %q, want %q — the prefix belongs to the harness; a set adds routes under it", set.name, got, base)
						return
					}
					env := NewEnv(t, pc.Mount, pc.HTTP, pc.Opts...)
					info := set.spec()
					info.APIPrefix = prefix
					checkOpenAPI(report, env, h.generate(info), want, &set)
					checkRemoved(report, env, set)
				})
			}
		})
	}
}

// wellFormedSets reports every malformed set and returns the rest, so a
// registry mistake is one failure naming the set rather than a cascade of
// misleading route failures under it.
func wellFormedSets(report failureReporter, sets []conditionalRouteSet) []conditionalRouteSet {
	kept := make([]conditionalRouteSet, 0, len(sets))
	names := make(map[string]bool, len(sets))
	for _, set := range sets {
		ok := true
		fail := func(format string, args ...any) {
			ok = false
			report.Errorf(format, args...)
		}
		switch {
		case set.name == "":
			fail("a conditional set has no name")
		case names[set.name]:
			fail("conditional set %q is registered twice", set.name)
		}
		names[set.name] = true
		if set.configure == nil {
			fail("conditional set %q has no configure hook", set.name)
		}
		if set.spec == nil {
			fail("conditional set %q has no spec hook", set.name)
		}
		if len(set.routes) == 0 && len(set.removes) == 0 {
			fail("conditional set %q declares no routes", set.name)
		}
		for route := range set.routes {
			if _, base := documentedRoutes[route]; base {
				fail("conditional set %q redeclares %q, which is already in documentedRoutes", set.name, route)
			}
		}
		for route, method := range set.removes {
			base, inBase := documentedRoutes[route]
			switch {
			case !inBase:
				fail("conditional set %q removes %q, which is not in documentedRoutes — a set can only unmount a route the base configuration mounts", set.name, route)
			case base != method:
				fail("conditional set %q removes %q as %s, but documentedRoutes has it as %s", set.name, route, method, base)
			}
			if _, added := set.routes[route]; added {
				fail("conditional set %q both adds and removes %q", set.name, route)
			}
		}
		if ok {
			kept = append(kept, set)
		}
	}
	return kept
}

func unionRoutes(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	maps.Copy(out, base)
	maps.Copy(out, extra)
	return out
}

func minusRoutes(base, gone map[string]string) map[string]string {
	out := make(map[string]string, len(base))
	maps.Copy(out, base)
	for route := range gone {
		delete(out, route)
	}
	return out
}

// openAPIProbe builds the request that replays one documented operation. path
// is the documented template, mount prefix included; its parameters are
// substituted with openAPIProbeSegment so every router routes it.
func openAPIProbe(method, path string) (probe string, req *http.Request) {
	probe = openAPIPathParam.ReplaceAllString(path, openAPIProbeSegment)
	req = httptest.NewRequest(method, probe, stringReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	return probe, req
}

// checkOpenAPI holds one generated spec to one mounted env in both directions:
// every documented operation must be routed, and every route in want must be
// documented with its method, with nothing else documented. set is nil for the
// base configuration; otherwise every failure names it.
func checkOpenAPI(report failureReporter, env *Env, spec map[string]any, want map[string]string, set *conditionalRouteSet) {
	suffix, wantName := "", "documentedRoutes"
	if set != nil {
		suffix = fmt.Sprintf(" (conditional set %q)", set.name)
		wantName = fmt.Sprintf("documentedRoutes or conditional set %q", set.name)
	}

	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		report.Errorf("spec has no paths object: %T%s", spec["paths"], suffix)
		return
	}

	mountPrefix := env.Config.Prefix()
	seen := make(map[string]string, len(paths))
	for path, item := range paths {
		operations, ok := item.(map[string]any)
		if !ok {
			report.Errorf("path %q is not an object: %T%s", path, item, suffix)
			continue
		}
		route, found := strings.CutPrefix(path, mountPrefix)
		if !found {
			report.Errorf("documented path %q is not under the mount prefix %q%s", path, mountPrefix, suffix)
			continue
		}
		for method := range operations {
			method = strings.ToUpper(method)
			seen[route] = method

			probe, req := openAPIProbe(method, path)
			rec := env.Do(req)
			switch rec.Code {
			case http.StatusNotFound, http.StatusMethodNotAllowed:
				report.Errorf("%s %s is documented but not mounted (%d)%s", method, probe, rec.Code, suffix)
			}
		}
	}

	for route, method := range want {
		got, ok := seen[route]
		if !ok {
			report.Errorf("route %q is mounted but missing from the spec%s", route, suffix)
			continue
		}
		if got != method {
			report.Errorf("route %q is documented as %s, want %s%s", route, got, method, suffix)
		}
	}
	for route := range seen {
		if _, ok := want[route]; !ok {
			report.Errorf("spec documents %q, which is not in %s — add the route there or drop it from the spec", route, wantName)
		}
	}
}

// checkUnconfigured proves a conditional set is conditional: in an env built
// without its configure hook, each of its routes must answer 404 or 405. A
// route reachable here has either become unconditional, in which case it
// belongs in documentedRoutes, or is switched on by something other than the
// set's configure.
func checkUnconfigured(report failureReporter, env *Env, set conditionalRouteSet) {
	for route, method := range set.routes {
		probe, req := openAPIProbe(method, env.Config.Prefix()+route)
		rec := env.Do(req)
		switch rec.Code {
		case http.StatusNotFound, http.StatusMethodNotAllowed:
		default:
			report.Errorf("%s %s of conditional set %q is reachable (%d) without the set configured — a conditional route must answer 404 or 405 in the base configuration; if it is unconditional now, move it to documentedRoutes", method, probe, set.name, rec.Code)
		}
	}
}

// checkRemoved is the mirror of checkUnconfigured for a set that subtracts: in
// an env built *with* the configure hook, each route in set.removes must answer
// 404 or 405. Without it a set could declare a route unmounted, drop it from
// the spec, and leave the adapter serving it — which is the whole failure
// resource-server gating exists to prevent.
//
// Only the status is asserted, not the body: an unregistered route is answered
// by the router, and net/http, chi, gin and echo each write their own 404.
func checkRemoved(report failureReporter, env *Env, set conditionalRouteSet) {
	for route, method := range set.removes {
		probe, req := openAPIProbe(method, env.Config.Prefix()+route)
		rec := env.Do(req)
		switch rec.Code {
		case http.StatusNotFound, http.StatusMethodNotAllowed:
		default:
			report.Errorf("%s %s is still reachable (%d) with conditional set %q configured — the set declares it unmounted, so the adapter must not register it", method, probe, rec.Code, set.name)
		}
	}
}

// sensitiveFields must never appear in an adapter response body.
var sensitiveFields = []string{
	"PasswordHash",
	"TOTPSecret",
	"ResetTokenHash",
	"MagicLinkTokenHash",
	"SMSCodeHash",
	"EmailVerificationTokenHash",
	"EmailChangeTokenHash",
	"PendingEmail",
}

// testRedaction re-pins the v0.1.0 fix: no route may serialise credential
// material, and the envelope change must not have reopened that hole.
func testRedaction(t *testing.T, mount Mounter) {
	env := NewEnv(t, mount, auth.DefaultHTTPConfig())
	seeded, _ := env.Seed("redact@example.com")
	if seeded.PasswordHash == "" {
		t.Fatal("expected the stored user to carry a password hash")
	}

	register := env.Do(env.Request(http.MethodPost, "/register", credentials("redactnew@example.com")))
	login := env.Do(env.Request(http.MethodPost, "/login", credentials("redact@example.com")))
	meReq := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
	me := env.Do(Replay(meReq, login))

	for label, rec := range map[string]*httptest.ResponseRecorder{"register": register, "login": login, "me": me} {
		body := rec.Body.String()
		lowered := strings.ToLower(body)
		for _, field := range sensitiveFields {
			if strings.Contains(lowered, strings.ToLower(field)) {
				t.Errorf("%s response exposes %q: %s", label, field, body)
			}
		}
		if strings.Contains(body, seeded.PasswordHash) {
			t.Errorf("%s response leaked the stored password hash: %s", label, body)
		}
	}
}

func credentials(email string) map[string]string {
	return map[string]string{"email": email, "password": "password1", "tenantId": "t1"}
}

func accessCookieSpec() CookieSpec {
	return CookieSpec{Path: "/", MaxAge: defaultAccessMaxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

func refreshCookieSpec() CookieSpec {
	// __Host- forces Path=/, so the /auth/refresh scoping is deliberately lost.
	return CookieSpec{Path: "/", MaxAge: defaultRefreshMaxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

func csrfCookieSpec() CookieSpec {
	// Not HttpOnly: double-submit needs the page to read and mirror it.
	return CookieSpec{Path: "/", MaxAge: defaultCSRFMaxAge, Secure: true, HttpOnly: false, SameSite: http.SameSiteLaxMode}
}

func testRegister(t *testing.T, mount Mounter) {
	t.Run("cookie mode sets cookies and returns no tokens", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/register", credentials("reg@example.com")))

		AssertStatus(t, rec, http.StatusCreated)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "userId")
		if body["success"] != true {
			t.Fatalf("success = %v", body["success"])
		}
		if id, _ := body["userId"].(string); id == "" {
			t.Fatalf("userId = %v, want a non-empty id", body["userId"])
		}
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostCSRF), csrfCookieSpec())
	})

	t.Run("bearer mode returns tokens and sets no cookies", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		req := env.Request(http.MethodPost, "/register", credentials("regbearer@example.com"))
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusCreated)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "userId", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	t.Run("duplicate address", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("dup@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/register", credentials("dup@example.com")))
		AssertError(t, rec, http.StatusConflict, "User already exists", auth.CodeUserExists)
	})

	// A body missing either credential is refused before any store work, with
	// the message and code of the private dev line node-auth — not as a weak
	// password, which is what an absent password used to be reported as. The
	// same refusal has to come back in both delivery modes: the check precedes
	// the branch that decides between cookies and body tokens, and a bearer
	// client that got a different answer here would have a second failure shape
	// to handle.
	//
	// The two ways a caller asks for its tokens, kept local: only this loop uses
	// them. noCookiesAtAll is the stronger claim bearer mode can carry — cookie
	// mode still gets the CSRF cookie from the middleware on every response,
	// refusals included, so there the claim has to be made per credential name.
	registerDeliveryModes := []struct {
		name           string
		apply          func(*http.Request)
		noCookiesAtAll bool
	}{
		{"cookie mode", func(*http.Request) {}, false},
		{"bearer mode", func(r *http.Request) { r.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer) }, true},
	}
	for _, mode := range registerDeliveryModes {
		t.Run("missing credentials "+mode.name, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				body map[string]string
			}{
				{"no email", map[string]string{"password": "password1", "tenantId": "t1"}},
				{"no password", map[string]string{"email": "missingpw@example.com", "tenantId": "t1"}},
				{"neither, keys absent", map[string]string{"tenantId": "t1"}},
				{"neither, keys empty", map[string]string{"email": "", "password": "", "tenantId": "t1"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					env := NewEnv(t, mount, auth.DefaultHTTPConfig())
					req := env.Request(http.MethodPost, "/register", tc.body)
					mode.apply(req)
					rec := env.Do(req)
					AssertError(t, rec, http.StatusBadRequest, "Email and password are required", auth.CodeInvalidInput)
					// The refusal has to grant nothing, which the envelope
					// alone does not say. AssertError pins the body to exactly
					// {error, code}, so an accessToken or refreshToken leaked
					// into it already fails there in either mode; the cookie
					// jar is the half it does not cover, and a refusal that
					// still set an access or refresh cookie would otherwise
					// pass every assertion above.
					AssertNoCookie(t, rec, hostAccess)
					AssertNoCookie(t, rec, hostRefresh)
					if mode.noCookiesAtAll {
						AssertNoCookies(t, rec)
					}
				})
			}
		})
	}

	t.Run("weak password", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/register", map[string]string{"email": "weak@example.com", "password": "x"}))
		AssertError(t, rec, http.StatusBadRequest, "Password is too weak", auth.CodeWeakPassword)
	})

	t.Run("malformed body", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/register", stringReader("{not json"))
		req.Header.Set("Content-Type", "application/json")
		rec := env.Do(req)
		AssertError(t, rec, http.StatusBadRequest, "Invalid request body", auth.CodeInvalidBody)
	})
}

func testLogin(t *testing.T, mount Mounter) {
	t.Run("cookie mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("login@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/login", credentials("login@example.com")))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostCSRF), csrfCookieSpec())
	})

	t.Run("bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("loginbearer@example.com")
		req := env.Request(http.MethodPost, "/login", credentials("loginbearer@example.com"))
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	t.Run("the strategy header is matched exactly", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("loginexact@example.com")
		req := env.Request(http.MethodPost, "/login", credentials("loginexact@example.com"))
		req.Header.Set(auth.AuthStrategyHeader, "Bearer")
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		Cookie(t, rec, hostAccess)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("loginbad@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/login", map[string]string{"email": "loginbad@example.com", "password": "wrong", "tenantId": "t1"}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid credentials", auth.CodeInvalidCredentials)
	})

	// A body missing either credential is the reference's router-level 400,
	// with no code (awesome-node-auth v1.10.8 auth.router.ts:996-1000), not the
	// strategy's 401 INVALID_CREDENTIALS: the route never reaches the lookup.
	// The test is on the values as sent, so an address that is only whitespace
	// passes it and is then an unknown address.
	t.Run("missing credentials", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			body map[string]string
		}{
			{"no email", map[string]string{"password": "password1", "tenantId": "t1"}},
			{"no password", map[string]string{"email": "loginmissing@example.com", "tenantId": "t1"}},
			{"neither, keys absent", map[string]string{"tenantId": "t1"}},
			{"neither, keys empty", map[string]string{"email": "", "password": "", "tenantId": "t1"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				env := NewEnv(t, mount, auth.DefaultHTTPConfig())
				env.Seed("loginmissing@example.com")
				rec := env.Do(env.Request(http.MethodPost, "/login", tc.body))
				AssertError(t, rec, http.StatusBadRequest, "Email and password are required", "")
				AssertNoCookie(t, rec, hostAccess)
				AssertNoCookie(t, rec, hostRefresh)
			})
		}
		t.Run("a whitespace address is an unknown one", func(t *testing.T) {
			env := NewEnv(t, mount, auth.DefaultHTTPConfig())
			rec := env.Do(env.Request(http.MethodPost, "/login", map[string]string{"email": "   ", "password": "password1", "tenantId": "t1"}))
			AssertError(t, rec, http.StatusUnauthorized, "Invalid credentials", auth.CodeInvalidCredentials)
		})
	})

	t.Run("malformed body", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/login", stringReader("{not json"))
		req.Header.Set("Content-Type", "application/json")
		AssertError(t, env.Do(req), http.StatusBadRequest, "Invalid request body", auth.CodeInvalidBody)
	})
}

// testCredentialEmptyBody pins #34: a /register or /login request with no body
// at all is answered as a request whose fields are simply absent — the
// per-field answer each route gives an empty JSON object — and not as a
// malformed body.
//
// The reference runs express.json(), which leaves req.body as {} when there is
// nothing to parse, and every router reads `req.body ?? {}` since v1.10.5
// (awesome-node-auth CHANGELOG 1.10.5, issue #21), so each route reaches its
// own check: /register throws INVALID_INPUT from the default handler
// (auth.router.ts:889-891 at v1.10.8), /login answers its codeless 400
// (:996-1000). The four adapters used to disagree here as well: echo's binder
// returned nil for a zero-length body, net/http, chi and gin answered 400
// INVALID_BODY. Both shapes a client sends are covered: an empty body with the
// JSON Content-Type, and no body and no Content-Type at all. Malformed JSON is
// still 400 INVALID_BODY, pinned by testRegister and testLogin.
func testCredentialEmptyBody(t *testing.T, mount Mounter) {
	cases := []struct {
		route   string
		status  int
		message string
		code    string
	}{
		{route: "/register", status: http.StatusBadRequest, message: "Email and password are required", code: auth.CodeInvalidInput},
		{route: "/login", status: http.StatusBadRequest, message: "Email and password are required"},
	}
	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			t.Run("empty body, JSON content type", func(t *testing.T) {
				env := NewEnv(t, mount, auth.DefaultHTTPConfig())
				rec := env.Do(env.Request(http.MethodPost, tc.route, nil))
				AssertError(t, rec, tc.status, tc.message, tc.code)
				AssertNoCookie(t, rec, hostAccess)
				AssertNoCookie(t, rec, hostRefresh)
			})
			t.Run("no body, no content type", func(t *testing.T) {
				env := NewEnv(t, mount, auth.DefaultHTTPConfig())
				rec := env.Do(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+tc.route, nil))
				AssertError(t, rec, tc.status, tc.message, tc.code)
			})
		})
	}
}

func testRefresh(t *testing.T, mount Mounter) {
	t.Run("cookie mode succeeds with an empty body", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("refresh@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("refresh@example.com")))

		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/refresh", nil)
		rec := env.Do(Replay(req, login))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
	})

	t.Run("bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("refreshbearer@example.com")
		req := env.Request(http.MethodPost, "/refresh", map[string]string{"refreshToken": tokens.RefreshToken})
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	t.Run("no token anywhere", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/refresh", nil))
		AssertError(t, rec, http.StatusUnauthorized, "No refresh token provided", "")
	})

	t.Run("unusable token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/refresh", map[string]string{"refreshToken": "bogus"}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired refresh token", auth.CodeInvalidRefreshToken)
	})
}

func testLogout(t *testing.T, mount Mounter) {
	env := NewEnv(t, mount, auth.DefaultHTTPConfig())
	env.Seed("logout@example.com")
	login := env.Do(env.Request(http.MethodPost, "/login", credentials("logout@example.com")))

	req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/logout", nil)
	rec := env.Do(Replay(req, login))

	AssertStatus(t, rec, http.StatusOK)
	AssertKeys(t, Body(t, rec), "success")

	// Every name variant is expired, not just the one this configuration writes:
	// a cookie left over from a differently configured release must not survive.
	for _, name := range []string{
		hostAccess, "__Secure-accessToken", "accessToken",
		hostRefresh, "__Secure-refreshToken", "refreshToken",
		hostCSRF, "__Secure-csrf-token", "csrf-token",
	} {
		AssertCleared(t, rec, name)
	}

	t.Run("succeeds without a token", func(t *testing.T) {
		fresh := NewEnv(t, mount, auth.DefaultHTTPConfig())
		bare := fresh.Do(httptest.NewRequest(http.MethodPost, fresh.Config.Prefix()+"/logout", nil))
		AssertStatus(t, bare, http.StatusOK)
		AssertKeys(t, Body(t, bare), "success")
	})

	// Answering 200 {"success":true} is only half of logout. The session has to
	// be dead afterwards, and it has to be dead in the configurations where the
	// refresh cookie is path-scoped away from <prefix>/logout — otherwise the
	// browser looks logged out while the refresh token stays usable forever.
	for _, tc := range []struct {
		name   string
		mutate func(*auth.HTTPConfig)
	}{
		{name: "__Host- configuration", mutate: func(*auth.HTTPConfig) {}},
		// Both of these keep the access cookie at "/" but scope the refresh cookie
		// to <prefix>/refresh, so logout only ever sees the access cookie — which
		// is exactly the credential the reference logout reads.
		{name: "__Secure- via domain", mutate: func(c *auth.HTTPConfig) { c.Cookies.Domain = "example.com" }},
		{name: "bare via insecure", mutate: func(c *auth.HTTPConfig) { c.Cookies.Secure = false }},
		// Cookies.Path = "/app" is deliberately not covered: it scopes every auth
		// cookie away from the auth mount itself, so no credential reaches logout
		// in any implementation, the reference included.
	} {
		t.Run("revokes the session, "+tc.name, func(t *testing.T) {
			cfg := auth.DefaultHTTPConfig()
			tc.mutate(&cfg)
			env := NewEnv(t, mount, cfg)
			env.Seed("logoutrevoke@example.com")
			login := env.Do(env.Request(http.MethodPost, "/login", credentials("logoutrevoke@example.com")))

			logoutReq := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/logout", nil)
			AssertStatus(t, env.Do(Replay(logoutReq, login)), http.StatusOK)

			// The refresh credential the login handed out must be dead. Replay it
			// against /refresh the way the client would, path scoping and all.
			refreshReq := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/refresh", nil)
			rec := env.Do(Replay(refreshReq, login))
			AssertError(t, rec, http.StatusUnauthorized, "Session has been revoked", auth.CodeSessionRevoked)
		})
	}
}

func testMe(t *testing.T, mount Mounter) {
	t.Run("returns the user unwrapped", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("me@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("me@example.com")))

		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		rec := env.Do(Replay(req, login))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		if _, wrapped := body["user"]; wrapped {
			t.Fatalf("GET /me is wrapped in a user envelope: %s", rec.Body.String())
		}
		if body["email"] != "me@example.com" {
			t.Fatalf("email = %v, want me@example.com (body %s)", body["email"], rec.Body.String())
		}
		for _, key := range []string{"id", "isEmailVerified", "isTotpEnabled", "loginProvider", "createdAt"} {
			if _, ok := body[key]; !ok {
				t.Errorf("missing key %q in %s", key, rec.Body.String())
			}
		}
		// The reference's /me is its token payload, which carries loginProvider
		// unconditionally: `user.loginProvider ?? 'local'` (auth.router.ts:379),
		// so a password account says "local" rather than omitting the key.
		if body["loginProvider"] != "local" {
			t.Errorf("loginProvider = %v, want %q (body %s)", body["loginProvider"], "local", rec.Body.String())
		}
	})

	t.Run("bearer credential", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("mebearer@example.com")
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		if Body(t, rec)["email"] != "mebearer@example.com" {
			t.Fatalf("unexpected body %s", rec.Body.String())
		}
		AssertNoCookies(t, rec)
	})

	// 403 with no code is the reference's own behaviour for a missing or
	// unusable access token, odd as it looks beside the 401s.
	t.Run("no token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil))
		AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
	})

	t.Run("unusable token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.Header.Set("Authorization", "Bearer not-a-token")
		rec := env.Do(req)
		AssertError(t, rec, http.StatusForbidden, "Invalid or expired access token", "")
	})
}

func testSessionRevoked(t *testing.T, mount Mounter) {
	// Both browser clients log out on exactly this code and refresh-loop on
	// anything else, so both emission points are pinned.
	t.Run("refresh", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("revoked@example.com")
		if err := env.Auth.Logout(context.Background(), tokens.RefreshToken); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		rec := env.Do(env.Request(http.MethodPost, "/refresh", map[string]string{"refreshToken": tokens.RefreshToken}))
		AssertError(t, rec, http.StatusUnauthorized, "Session has been revoked", auth.CodeSessionRevoked)
	})

	t.Run("protected route under allcalls", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionCheckOn(auth.SessionCheckOnAllCalls))
		_, tokens := env.Seed("revokedme@example.com")
		if err := env.Auth.Logout(context.Background(), tokens.RefreshToken); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := env.Do(req)
		AssertError(t, rec, http.StatusUnauthorized, "Session has been revoked", auth.CodeSessionRevoked)
	})
}

func testCookieNames(t *testing.T, mount Mounter) {
	cases := []struct {
		name        string
		mutate      func(*auth.HTTPConfig)
		access      string
		refresh     string
		csrf        string
		refreshPath string
		domain      string
		secure      bool
	}{
		{
			name:        "bare when insecure",
			mutate:      func(c *auth.HTTPConfig) { c.Cookies.Secure = false },
			access:      "accessToken",
			refresh:     "refreshToken",
			csrf:        "csrf-token",
			refreshPath: "/auth/refresh",
		},
		{
			name:        "__Host- when secure, root-scoped and domainless",
			mutate:      func(c *auth.HTTPConfig) {},
			access:      hostAccess,
			refresh:     hostRefresh,
			csrf:        hostCSRF,
			refreshPath: "/",
			secure:      true,
		},
		{
			name:        "__Secure- when a domain is set",
			mutate:      func(c *auth.HTTPConfig) { c.Cookies.Domain = "example.com" },
			access:      "__Secure-accessToken",
			refresh:     "__Secure-refreshToken",
			csrf:        "__Secure-csrf-token",
			refreshPath: "/auth/refresh",
			domain:      "example.com",
			secure:      true,
		},
		{
			name:        "__Secure- when the path is not root",
			mutate:      func(c *auth.HTTPConfig) { c.Cookies.Path = "/app" },
			access:      "__Secure-accessToken",
			refresh:     "__Secure-refreshToken",
			csrf:        "__Secure-csrf-token",
			refreshPath: "/auth/refresh",
			secure:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := auth.DefaultHTTPConfig()
			tc.mutate(&cfg)
			env := NewEnv(t, mount, cfg)
			rec := env.Do(env.Request(http.MethodPost, "/register", credentials("names@example.com")))
			AssertStatus(t, rec, http.StatusCreated)

			access := Cookie(t, rec, tc.access)
			if access.Secure != tc.secure {
				t.Errorf("%s Secure = %v, want %v", access.Name, access.Secure, tc.secure)
			}
			if access.Domain != tc.domain {
				t.Errorf("%s Domain = %q, want %q", access.Name, access.Domain, tc.domain)
			}
			if refresh := Cookie(t, rec, tc.refresh); refresh.Path != tc.refreshPath {
				t.Errorf("%s Path = %q, want %q", refresh.Name, refresh.Path, tc.refreshPath)
			}
			if csrf := Cookie(t, rec, tc.csrf); csrf.HttpOnly {
				t.Errorf("%s must stay readable by JS", csrf.Name)
			}
		})
	}
}

func testCookieReadPriority(t *testing.T, mount Mounter) {
	env := NewEnv(t, mount, auth.DefaultHTTPConfig())
	_, tokens := env.Seed("priority@example.com")

	// The read side is configuration-independent: a bare cookie is honoured by a
	// server that writes __Host- names, and __Host- outranks the others.
	for _, name := range []string{"accessToken", "__Secure-accessToken", hostAccess} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
			req.AddCookie(&http.Cookie{Name: name, Value: tokens.AccessToken})
			rec := env.Do(req)
			AssertStatus(t, rec, http.StatusOK)
		})
	}

	t.Run("__Host- outranks __Secure- and bare", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.AddCookie(&http.Cookie{Name: hostAccess, Value: tokens.AccessToken})
		req.AddCookie(&http.Cookie{Name: "__Secure-accessToken", Value: "wrong"})
		req.AddCookie(&http.Cookie{Name: "accessToken", Value: "wrong"})
		AssertStatus(t, env.Do(req), http.StatusOK)
	})

	t.Run("__Secure- outranks bare", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.AddCookie(&http.Cookie{Name: "__Secure-accessToken", Value: tokens.AccessToken})
		req.AddCookie(&http.Cookie{Name: "accessToken", Value: "wrong"})
		AssertStatus(t, env.Do(req), http.StatusOK)
	})
}

func testCSRF(t *testing.T, mount Mounter) {
	t.Run("the cookie is distributed to cookie clients", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil))
		csrf := Cookie(t, rec, hostCSRF)
		if len(csrf.Value) != 32 {
			t.Errorf("csrf token = %q, want 32 hex characters", csrf.Value)
		}
		AssertCookieAttrs(t, csrf, csrfCookieSpec())
	})

	t.Run("an existing cookie is not rotated", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "existing"})
		AssertNoCookie(t, env.Do(req), hostCSRF)
	})

	// The reference mounts logout without its auth middleware, so CSRF is never
	// checked there — a client whose CSRF cookie has expired can still log out.
	t.Run("logout is exempt", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/logout", nil)
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertStatus(t, env.Do(req), http.StatusOK)
	})

	t.Run("login is exempt", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("csrflogin@example.com")
		req := env.Request(http.MethodPost, "/login", credentials("csrflogin@example.com"))
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertStatus(t, env.Do(req), http.StatusOK)
	})

	// ── Ordering: the auth gate answers before CSRF ──────────────────────────
	//
	// The reference extracts the access token first and only then reaches its CSRF
	// branch (auth.middleware.ts:29-32 then :33-42), so a request with no token at
	// all is answered 403 {"error":"No access token provided"} with **no code** and
	// never sees CSRF_INVALID. The port runs CSRF as a middleware in front of the
	// auth middleware, so it recovers that ordering by scoping enforcement to
	// requests that carry an access-token cookie.
	//
	// These cases are the wire-level statement of that. The absent `code` is the
	// load-bearing half: CSRF_INVALID would carry one, so a regression that put
	// the CSRF middleware back in front of the auth gate fails here rather than
	// only in the unit tests.
	t.Run("an unauthenticated mutating request is answered by the auth gate", func(t *testing.T) {
		routes := []struct {
			method string
			route  string
			body   any
		}{
			{http.MethodPatch, "/profile", map[string]string{"firstName": "Nobody"}},
			{http.MethodPost, "/add-phone", map[string]string{"phoneNumber": "+390000000000"}},
			{http.MethodDelete, "/account", nil},
			{http.MethodPost, "/2fa/setup", nil},
			{http.MethodPost, "/change-password", map[string]string{"currentPassword": "password1", "newPassword": "newpassword1"}},
			{http.MethodPost, "/send-verification-email", nil},
			{http.MethodPost, "/change-email/request", map[string]string{"newEmail": "changed@example.com"}},
			{http.MethodDelete, "/sessions/some-handle", nil},
		}
		for _, rt := range routes {
			t.Run(rt.method+" "+rt.route, func(t *testing.T) {
				env := NewEnv(t, mount, auth.DefaultHTTPConfig())
				// No cookies, no Authorization, no CSRF header: the shape a native
				// client has on its first call, and the shape of a forgery.
				req := env.Request(rt.method, rt.route, rt.body)
				AssertError(t, env.Do(req), http.StatusForbidden, "No access token provided", "")
			})
		}
	})

	// The same request once a session cookie is present is CSRF-checked again, so
	// the scoping above cannot be read as "CSRF is off for cookie clients".
	t.Run("a cookie-authenticated request is still CSRF-checked", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("csrfscope@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("csrfscope@example.com")))

		req := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Forged"}), login)
		AssertError(t, env.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
	})
}

func assertNonEmptyString(t *testing.T, body map[string]any, key string) {
	t.Helper()
	if v, _ := body[key].(string); v == "" {
		t.Fatalf("%s = %v, want a non-empty string", key, body[key])
	}
}
