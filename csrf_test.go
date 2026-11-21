package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func csrfHandler(cfg HTTPConfig) http.Handler {
	return CSRFMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func insecureHTTPConfig() HTTPConfig {
	cfg := DefaultHTTPConfig()
	cfg.Cookies.Secure = false
	return cfg
}

func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestCSRFMiddlewareAutoInitialisesTheCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/me", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	c := findCookie(rec, "csrf-token")
	if c == nil {
		t.Fatal("expected the csrf-token cookie to be initialised")
	}
	if len(c.Value) != 32 {
		t.Errorf("token = %q, want 32 hex characters", c.Value)
	}
	if c.HttpOnly {
		t.Error("the csrf cookie must stay readable by JS for double-submit to work")
	}
}

func TestCSRFMiddlewareDoesNotRotateAnExistingCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "csrf-token", Value: "existing"})
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)

	if c := findCookie(rec, "csrf-token"); c != nil {
		t.Fatalf("unexpected rotation: %s", c.String())
	}
}

func TestCSRFMiddlewareReadsThePrefixedCookie(t *testing.T) {
	// The write side may have emitted __Host-csrf-token; the read side has to
	// find it whatever the current configuration would write.
	//
	// The access-token cookie is what makes this request enforced at all. Without
	// it the 200 below would prove nothing: an unauthenticated request passes
	// whether or not the prefixed CSRF cookie was ever read. The access cookie is
	// prefixed too, for the same reason — CookieValue has to resolve both names.
	req := httptest.NewRequest(http.MethodPatch, "/auth/profile", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-csrf-token", Value: "match"})
	req.AddCookie(&http.Cookie{Name: hostCookiePrefix + AccessTokenCookieName, Value: "session-value"})
	req.Header.Set(CSRFHeaderName, "match")
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// TestCSRFMiddlewareEnforcementMatrix drives the enforcement predicate row by row.
//
// Almost every row sets cookieAuth. Enforcement is scoped to requests that carry
// an access-token cookie (csrfEnforced), so a row without one is not enforced
// whatever else it says: it would report 200 for reasons that have nothing to do
// with the property it names, and the row would pass no matter how the predicate
// were broken. cookieAuth is what keeps these rows load-bearing. The rows that
// deliberately omit it are the ones testing the scoping itself, and they say so.
func TestCSRFMiddlewareEnforcementMatrix(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		path       string
		cookie     string
		header     string
		authHeader string
		strategy   string
		cookieAuth bool
		want       int
	}{
		{name: "matching header passes", method: http.MethodPatch, path: "/auth/profile", cookie: "tok", header: "tok", cookieAuth: true, want: http.StatusOK},
		{name: "missing header is rejected", method: http.MethodPatch, path: "/auth/profile", cookie: "tok", cookieAuth: true, want: http.StatusForbidden},
		{name: "mismatched header is rejected", method: http.MethodPatch, path: "/auth/profile", cookie: "tok", header: "other", cookieAuth: true, want: http.StatusForbidden},
		{name: "missing cookie is rejected", method: http.MethodDelete, path: "/auth/account", header: "tok", cookieAuth: true, want: http.StatusForbidden},
		{name: "safe methods are exempt", method: http.MethodGet, path: "/auth/profile", cookie: "tok", cookieAuth: true, want: http.StatusOK},
		{name: "bearer credentials are exempt", method: http.MethodDelete, path: "/auth/account", authHeader: "Bearer abc", cookieAuth: true, want: http.StatusOK},
		// The reference exempts a request because its token *came from* the
		// Authorization header (usingBearer, auth.middleware.ts:22-26), not because
		// the client said so. X-Auth-Strategy is set by the caller on any request
		// the caller can make at all, so honouring it here would let an attacker
		// switch the control off with one header.
		{name: "the bearer strategy header alone is not exempt", method: http.MethodDelete, path: "/auth/account", strategy: AuthStrategyBearer, cookieAuth: true, want: http.StatusForbidden},
		{name: "the bearer strategy header does not exempt a cookie-authenticated request", method: http.MethodPatch, path: "/auth/profile", cookie: "tok", strategy: AuthStrategyBearer, cookieAuth: true, want: http.StatusForbidden},
		// It stays exempt when the credential is really there, whatever it declares.
		{name: "the bearer strategy header with real bearer credentials is exempt", method: http.MethodPatch, path: "/auth/profile", authHeader: "Bearer abc", strategy: AuthStrategyBearer, cookieAuth: true, want: http.StatusOK},
		// A double-submit that matches still passes with the strategy header set:
		// narrowing the exemption must not break a bearer-declaring cookie client.
		{name: "the bearer strategy header with a matching double-submit passes", method: http.MethodPatch, path: "/auth/profile", cookie: "tok", header: "tok", strategy: AuthStrategyBearer, cookieAuth: true, want: http.StatusOK},
		// Keyed on method as well as path: DELETE <prefix>/sessions/cleanup is
		// DELETE /sessions/{handle} with the handle "cleanup", which the reference
		// puts behind authMiddleware. Only POST /sessions/cleanup is unauthenticated.
		{name: "cleanup is exempt only for POST", method: http.MethodDelete, path: "/auth/sessions/cleanup", cookie: "tok", cookieAuth: true, want: http.StatusForbidden},
		{name: "login is exempt", method: http.MethodPost, path: "/auth/login", cookie: "tok", cookieAuth: true, want: http.StatusOK},
		{name: "refresh is exempt", method: http.MethodPost, path: "/auth/refresh", cookie: "tok", cookieAuth: true, want: http.StatusOK},
		// The reference deliberately mounts logout without its auth middleware,
		// so a stale CSRF cookie must not trap a client in a logged-in state.
		{name: "logout is exempt", method: http.MethodPost, path: "/auth/logout", cookie: "tok", cookieAuth: true, want: http.StatusOK},
		{name: "routes outside the prefix are untouched", method: http.MethodPost, path: "/api/orders", cookie: "tok", cookieAuth: true, want: http.StatusOK},
		// A path that merely starts with the prefix's characters is not the mount.
		{name: "a longer segment is not the prefix", method: http.MethodPost, path: "/authenticate/login", cookie: "tok", cookieAuth: true, want: http.StatusOK},
		{name: "an unrelated segment containing the prefix is untouched", method: http.MethodPost, path: "/api/authors/create", cookie: "tok", cookieAuth: true, want: http.StatusOK},
		// gin/echo groups and chi Route serve <base><prefix>/<route>: enforcement
		// must not switch itself off just because the mount sits below a base path.
		{name: "a group-mounted protected route is enforced", method: http.MethodPatch, path: "/api/auth/profile", cookie: "tok", cookieAuth: true, want: http.StatusForbidden},
		{name: "a group-mounted protected route passes with the header", method: http.MethodPatch, path: "/api/auth/profile", cookie: "tok", header: "tok", cookieAuth: true, want: http.StatusOK},
		{name: "a group-mounted exempt route stays exempt", method: http.MethodPost, path: "/api/auth/login", cookie: "tok", cookieAuth: true, want: http.StatusOK},

		// ── The scoping itself ────────────────────────────────────────────────
		//
		// No access-token cookie, so nothing here is cookie-authenticated. The
		// reference reaches its CSRF branch only after extracting a cookie token
		// (auth.middleware.ts:29-35), so these are passed through to the auth gate,
		// which answers with "No access token provided". The full-stack consequence
		// is pinned in the wiretest suite; here it is just the 200 from the stub.
		{name: "an unauthenticated cookie client is deferred to the auth gate", method: http.MethodPatch, path: "/auth/profile", cookie: "tok", want: http.StatusOK},
		{name: "an unauthenticated request with no cookies at all is deferred", method: http.MethodDelete, path: "/auth/account", want: http.StatusOK},
		{name: "a group-mounted route is deferred too", method: http.MethodPatch, path: "/api/auth/profile", cookie: "tok", want: http.StatusOK},
		// The exception. /link-request has no auth gate behind it to defer to, so
		// the manual-check table keeps it enforced with no credential of any kind.
		{name: "link-request is enforced with no credential at all", method: http.MethodPost, path: "/auth/link-request", cookie: "tok", want: http.StatusForbidden},
		{name: "link-request is enforced with no cookies at all", method: http.MethodPost, path: "/auth/link-request", want: http.StatusForbidden},
		{name: "link-request passes on a matching pair with no credential", method: http.MethodPost, path: "/auth/link-request", cookie: "tok", header: "tok", want: http.StatusOK},
		{name: "group-mounted link-request is enforced too", method: http.MethodPost, path: "/api/auth/link-request", cookie: "tok", want: http.StatusForbidden},
		// GET is still safe, even on the manual-check route.
		{name: "link-request is exempt for a safe method", method: http.MethodGet, path: "/auth/link-request", cookie: "tok", want: http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "csrf-token", Value: tc.cookie})
			}
			if tc.cookieAuth {
				req.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "session-value"})
			}
			if tc.header != "" {
				req.Header.Set(CSRFHeaderName, tc.header)
			}
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			if tc.strategy != "" {
				req.Header.Set(AuthStrategyHeader, tc.strategy)
			}
			rec := httptest.NewRecorder()
			csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestCSRFExemptionsMatchTheReference pins the exemption table route by route
// against wire-contract.md. Every route in the reference auth router that this
// port will eventually mount is listed, so a route added later cannot inherit a
// wrong default: the table itself is the thing under test, not the routes that
// happen to be mounted today.
//
// Each row carries the reference's method, because the exemptions are Express
// routes and not paths: an exempt path reached with a method the reference did
// not mount unauthenticated must still be checked.
func TestCSRFExemptionsMatchTheReference(t *testing.T) {
	// Enforced: the reference puts these behind authMiddleware, where the
	// double-submit check lives — plus POST /link-request, which has no auth
	// middleware but does its own manual check (auth.router.ts:1489-1495).
	enforced := []struct{ method, route string }{
		{http.MethodPatch, "/profile"},
		{http.MethodPost, "/add-phone"},
		{http.MethodPost, "/change-password"},
		{http.MethodPost, "/send-verification-email"},
		{http.MethodPost, "/change-email/request"},
		{http.MethodPost, "/2fa/setup"},
		{http.MethodPost, "/2fa/verify-setup"},
		{http.MethodPost, "/2fa/disable"},
		{http.MethodDelete, "/sessions/some-handle"},
		{http.MethodDelete, "/account"},
		{http.MethodDelete, "/linked-accounts/google/123"},
		{http.MethodPost, "/link-request"},
		// The method-qualified rows: the exempt path reached with the method the
		// reference mounts behind authMiddleware. DELETE /sessions/cleanup is
		// DELETE /sessions/{handle} with the handle "cleanup".
		{http.MethodDelete, "/sessions/cleanup"},
		// GET /verify-email is the table's only non-POST exemption, so a POST to it
		// proves the key really carries the method.
		{http.MethodPost, "/verify-email"},
	}
	// Exempt: mounted without authMiddleware, so never checked. Methods from
	// src/router/auth.router.ts:541, 590, 622, 715, 736, 777, 802, 859, 969, 1040,
	// 1078, 1126, 1176, 1244, 1544.
	exempt := []struct{ method, route string }{
		{http.MethodPost, "/login"},
		{http.MethodPost, "/register"},
		{http.MethodPost, "/refresh"},
		{http.MethodPost, "/logout"},
		{http.MethodPost, "/forgot-password"},
		{http.MethodPost, "/reset-password"},
		// A GET, so exempt as a safe method whatever the table says.
		{http.MethodGet, "/verify-email"},
		{http.MethodPost, "/change-email/confirm"},
		{http.MethodPost, "/magic-link/send"},
		{http.MethodPost, "/magic-link/verify"},
		{http.MethodPost, "/sms/send"},
		{http.MethodPost, "/sms/verify"},
		{http.MethodPost, "/2fa/verify"},
		{http.MethodPost, "/link-verify"},
		{http.MethodPost, "/sessions/cleanup"},
		// This port's invitation accept route, which the reference does not
		// have: unauthenticated, its credential the token in the body, exempt
		// as /reset-password is.
		{http.MethodPost, "/invitations/accept"},
	}

	for _, tc := range enforced {
		t.Run("enforced "+tc.method+tc.route, func(t *testing.T) {
			if got := statusFor(t, tc.method, "/auth"+tc.route); got != http.StatusForbidden {
				t.Errorf("%s %s = %d, want 403: CSRF is not enforced on a protected route", tc.method, tc.route, got)
			}
		})
	}
	for _, tc := range exempt {
		t.Run("exempt "+tc.method+tc.route, func(t *testing.T) {
			if got := statusFor(t, tc.method, "/auth"+tc.route); got != http.StatusOK {
				t.Errorf("%s %s = %d, want 200: an unauthenticated route must not be CSRF-checked", tc.method, tc.route, got)
			}
			// An exempt route is exempt whether or not a session rides along: the
			// reference never reaches its CSRF branch on these at all.
			if got := statusForWithoutCookieAuth(t, tc.method, "/auth"+tc.route); got != http.StatusOK {
				t.Errorf("%s %s = %d without cookie auth, want 200", tc.method, tc.route, got)
			}
		})
	}

	// The same rows again with no access-token cookie. Every enforced route defers
	// to the auth gate — except the manual-check route, which has no auth gate to
	// defer to. This is the split the two tables encode, so it is asserted rather
	// than left implied by the rows above.
	for _, tc := range enforced {
		t.Run("without cookie auth "+tc.method+tc.route, func(t *testing.T) {
			manual := csrfManualCheckRoutes[csrfExemption{method: tc.method, path: tc.route}]
			got := statusForWithoutCookieAuth(t, tc.method, "/auth"+tc.route)
			if manual {
				if got != http.StatusForbidden {
					t.Errorf("%s %s = %d, want 403: a manual-check route must be enforced with no credential", tc.method, tc.route, got)
				}
				return
			}
			if got != http.StatusOK {
				t.Errorf("%s %s = %d, want 200: an unauthenticated request belongs to the auth gate", tc.method, tc.route, got)
			}
		})
	}
}

// TestCSRFManualCheckRoutesMatchTheReference pins the second table entry by
// entry. It is the whole reason enforcement can be scoped to cookie-authenticated
// requests without opening a hole, so a route dropped from it must fail loudly.
//
// POST /link-request is the only route in the reference that is CSRF-checked
// while carrying no auth middleware: the check is hand-written at the top of the
// handler (auth.router.ts:1489-1495) and the handler goes on to accept the
// pending-link stash in place of authentication (:1513-1524).
func TestCSRFManualCheckRoutesMatchTheReference(t *testing.T) {
	want := map[csrfExemption]bool{
		{http.MethodPost, "/link-request"}: true,
	}
	if len(csrfManualCheckRoutes) != len(want) {
		t.Fatalf("csrfManualCheckRoutes = %v, want %v", csrfManualCheckRoutes, want)
	}
	for route := range want {
		if !csrfManualCheckRoutes[route] {
			t.Errorf("%s %s is missing from csrfManualCheckRoutes", route.method, route.path)
		}
	}
	// The two tables must stay disjoint: an entry in both would be exempt, because
	// csrfEnforced tests the exempt table first, and the manual check would be
	// silently dead.
	for route := range csrfManualCheckRoutes {
		if csrfExemptRoutes[route] {
			t.Errorf("%s %s is in both tables, so the manual check never runs", route.method, route.path)
		}
	}
	// And the entry is keyed on the method, like the exempt table.
	if got := statusForWithoutCookieAuth(t, http.MethodGet, "/auth/link-request"); got != http.StatusOK {
		t.Errorf("GET /link-request = %d, want 200: a safe method is never checked", got)
	}
}

// TestCSRFCookieDistributionStillHonoursTheStrategyHeader guards the other half
// of the narrowed exemption: X-Auth-Strategy no longer switches enforcement off,
// but it must still keep cookies off a bearer client's response — "bearer
// requests set no cookies" is asserted of whole responses across the adapter
// suites.
func TestCSRFCookieDistributionStillHonoursTheStrategyHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set(AuthStrategyHeader, AuthStrategyBearer)
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a safe method", rec.Code)
	}
	if c := findCookie(rec, "csrf-token"); c != nil {
		t.Fatalf("a bearer-strategy caller must not be sent a csrf cookie: %s", c.String())
	}
}

// statusFor drives the middleware with a CSRF cookie and no header — the shape
// every cookie client has before it mirrors the token.
//
// It also sends an access-token cookie, which is not incidental: enforcement is
// scoped to cookie-authenticated requests, so without it every caller of this
// helper would read 200 for the wrong reason and could no longer tell an enforced
// route from an exempt one. Callers that need the unauthenticated shape ask for it
// explicitly (statusForWithoutCookieAuth).
func statusFor(t *testing.T, method, path string) int {
	t.Helper()
	return csrfStatus(t, method, path, true)
}

// statusForWithoutCookieAuth is the same drive with no access-token cookie: the
// shape of a caller the auth gate will refuse anyway.
func statusForWithoutCookieAuth(t *testing.T, method, path string) int {
	t.Helper()
	return csrfStatus(t, method, path, false)
}

func csrfStatus(t *testing.T, method, path string, cookieAuth bool) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: "csrf-token", Value: "tok"})
	if cookieAuth {
		req.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "session-value"})
	}
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)
	return rec.Code
}

func TestCSRFRejectionBody(t *testing.T) {
	// Cookie-authenticated, so the request is actually enforced and there is a
	// rejection body to inspect.
	req := httptest.NewRequest(http.MethodPatch, "/auth/profile", nil)
	req.AddCookie(&http.Cookie{Name: "csrf-token", Value: "tok"})
	req.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "session-value"})
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if body["error"] != "CSRF token validation failed" || body["code"] != CodeCSRFInvalid {
		t.Fatalf("body = %v", body)
	}
	if len(body) != 2 {
		t.Fatalf("unexpected extra fields: %v", body)
	}
}

func TestCSRFMiddlewareDisabled(t *testing.T) {
	// The request is shaped so that it *would* be rejected with CSRF enabled:
	// cookie-authenticated, unsafe method, protected route, no mirrored header.
	// A request without the access cookie would pass either way and the 200 below
	// would not distinguish "disabled" from "not enforced".
	newRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodPatch, "/auth/profile", nil)
		req.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "session-value"})
		return req
	}

	enabled := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(enabled, newRequest())
	if enabled.Code != http.StatusForbidden {
		t.Fatalf("control: status = %d with CSRF enabled, want 403 — the case below proves nothing", enabled.Code)
	}

	cfg := insecureHTTPConfig()
	cfg.CSRF.Enabled = false

	rec := httptest.NewRecorder()
	csrfHandler(cfg).ServeHTTP(rec, newRequest())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if c := findCookie(rec, "csrf-token"); c != nil {
		t.Fatalf("no cookie should be distributed when csrf is disabled: %s", c.String())
	}

	// Disabled means disabled for the manual-check route too: the reference gates
	// its hand-written check on config.csrf.enabled (auth.router.ts:1489).
	link := httptest.NewRecorder()
	csrfHandler(cfg).ServeHTTP(link, httptest.NewRequest(http.MethodPost, "/auth/link-request", nil))
	if link.Code != http.StatusOK {
		t.Fatalf("link-request status = %d with CSRF disabled, want 200", link.Code)
	}
}
