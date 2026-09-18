package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCookieNameResolution(t *testing.T) {
	cases := []struct {
		name    string
		options CookieOptions
		want    string
	}{
		{name: "insecure stays bare", options: CookieOptions{Secure: false, Path: "/"}, want: "accessToken"},
		{name: "secure and root-scoped earns __Host-", options: CookieOptions{Secure: true, Path: "/"}, want: "__Host-accessToken"},
		{name: "an unset path is treated as root", options: CookieOptions{Secure: true}, want: "__Host-accessToken"},
		{name: "a domain downgrades to __Secure-", options: CookieOptions{Secure: true, Path: "/", Domain: "example.com"}, want: "__Secure-accessToken"},
		{name: "a non-root path downgrades to __Secure-", options: CookieOptions{Secure: true, Path: "/app"}, want: "__Secure-accessToken"},
		{name: "an insecure domain cookie stays bare", options: CookieOptions{Domain: "example.com"}, want: "accessToken"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.options.CookieName(AccessTokenCookieName); got != tc.want {
				t.Fatalf("CookieName = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHostPrefixedCookiesAreForcedHostScoped(t *testing.T) {
	// A browser silently drops a __Host- cookie that carries a Domain or is not
	// scoped to "/", so the refresh cookie's own path has to give way.
	options := CookieOptions{Secure: true, Path: "/", Domain: "", RefreshTokenPath: "/auth/refresh", RefreshTokenMaxAge: time.Hour}
	rec := httptest.NewRecorder()
	options.SetRefreshTokenCookie(rec, "token")

	c := rec.Result().Cookies()[0]
	if c.Name != "__Host-refreshToken" {
		t.Fatalf("name = %q", c.Name)
	}
	if c.Path != "/" || c.Domain != "" || !c.Secure {
		t.Fatalf("__Host- attributes not enforced: %s", c.String())
	}
}

func TestCookieValueReadPriority(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "accessToken", Value: "bare"})
	if got := CookieValue(req, AccessTokenCookieName); got != "bare" {
		t.Fatalf("bare = %q", got)
	}

	req.AddCookie(&http.Cookie{Name: "__Secure-accessToken", Value: "secure"})
	if got := CookieValue(req, AccessTokenCookieName); got != "secure" {
		t.Fatalf("__Secure- must outrank bare, got %q", got)
	}

	req.AddCookie(&http.Cookie{Name: "__Host-accessToken", Value: "host"})
	if got := CookieValue(req, AccessTokenCookieName); got != "host" {
		t.Fatalf("__Host- must outrank the rest, got %q", got)
	}
}

func TestClearAuthCookiesExpiresEveryVariant(t *testing.T) {
	options := DefaultCookieOptions()
	options.RefreshTokenPath = "/auth/refresh"
	rec := httptest.NewRecorder()
	options.ClearAuthCookies(rec, true)

	cleared := map[string]bool{}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge >= 0 || c.Value != "" {
			t.Errorf("%s is not expired: %s", c.Name, c.String())
		}
		cleared[c.Name] = true
	}
	for _, name := range []string{
		"accessToken", "__Secure-accessToken", "__Host-accessToken",
		"refreshToken", "__Secure-refreshToken", "__Host-refreshToken",
		"csrf-token", "__Secure-csrf-token", "__Host-csrf-token",
	} {
		if !cleared[name] {
			t.Errorf("variant %q was not cleared", name)
		}
	}
}

func TestClearAuthCookiesSkipsCSRFWhenDisabled(t *testing.T) {
	rec := httptest.NewRecorder()
	DefaultCookieOptions().ClearAuthCookies(rec, false)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-csrf-token" {
			t.Fatal("the csrf cookie must only be cleared when csrf is enabled")
		}
	}
}

func TestIsBearerRequestMatchesExactly(t *testing.T) {
	cases := map[string]bool{"bearer": true, "Bearer": false, "BEARER": false, "bearer ": false, "": false}
	for value, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if value != "" {
			req.Header.Set(AuthStrategyHeader, value)
		}
		if got := IsBearerRequest(req); got != want {
			t.Errorf("IsBearerRequest(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestErrorEnvelopeOmitsAnAbsentCode(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTPError(rec, HTTPErrNoAccessToken)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body) != 1 || body["error"] != "No access token provided" {
		t.Fatalf("body = %v, want the message alone", body)
	}
}

// TestErrorCatalogLiterals pins the wire strings themselves. Every other test
// compares against the constants, so without this a rename of a constant's
// value would change the wire and still pass.
func TestErrorCatalogLiterals(t *testing.T) {
	codes := map[string]string{
		CodeInvalidCredentials:  "INVALID_CREDENTIALS",
		CodeEmailNotVerified:    "EMAIL_NOT_VERIFIED",
		CodeSessionRevoked:      "SESSION_REVOKED",
		CodeInvalidToken:        "INVALID_TOKEN",
		CodeInvalidRefreshToken: "INVALID_REFRESH_TOKEN",
		CodeCSRFInvalid:         "CSRF_INVALID",
		CodeTwoFactorRequired:   "2FA_REQUIRED",
		CodeUserNotFound:        "USER_NOT_FOUND",
		CodeNotImplemented:      "NOT_IMPLEMENTED",
	}
	for got, want := range codes {
		if got != want {
			t.Errorf("code %q must be %q", got, want)
		}
	}

	if AuthStrategyHeader != "X-Auth-Strategy" || AuthStrategyBearer != "bearer" {
		t.Errorf("bearer opt-in = %q: %q", AuthStrategyHeader, AuthStrategyBearer)
	}
	if CSRFHeaderName != "X-CSRF-Token" {
		t.Errorf("csrf header = %q", CSRFHeaderName)
	}
	if AccessTokenCookieName != "accessToken" || RefreshTokenCookieName != "refreshToken" || CSRFTokenCookieName != "csrf-token" {
		t.Errorf("cookie base names drifted: %q %q %q", AccessTokenCookieName, RefreshTokenCookieName, CSRFTokenCookieName)
	}

	messages := map[HTTPError]struct {
		status  int
		message string
		code    string
	}{
		HTTPErrSessionRevoked:      {401, "Session has been revoked", "SESSION_REVOKED"},
		HTTPErrCSRFInvalid:         {403, "CSRF token validation failed", "CSRF_INVALID"},
		HTTPErrInvalidCredentials:  {401, "Invalid credentials", "INVALID_CREDENTIALS"},
		HTTPErrEmailNotVerified:    {403, "Email address is not verified", "EMAIL_NOT_VERIFIED"},
		HTTPErrNoAccessToken:       {403, "No access token provided", ""},
		HTTPErrInvalidAccessToken:  {403, "Invalid or expired access token", ""},
		HTTPErrNoRefreshToken:      {401, "No refresh token provided", ""},
		HTTPErrInvalidRefreshToken: {401, "Invalid refresh token", ""},
		HTTPErrExpiredRefreshToken: {401, "Invalid or expired refresh token", "INVALID_REFRESH_TOKEN"},
		HTTPErrInternal:            {500, "Internal server error", ""},
		HTTPErrTwoFactorRequired:   {403, "Two-factor authentication required", "2FA_REQUIRED"},
		HTTPErrInvalidToken:        {401, "Invalid or expired token", "INVALID_TOKEN"},
		// Code-less on purpose: every reference site emitting this literal emits
		// it without a code, and the one coded USER_NOT_FOUND says "Target user
		// not found" instead.
		HTTPErrUserNotFound: {404, "User not found", ""},
		HTTPErrUserExists:   {409, "User already exists", "USER_EXISTS"},
		HTTPErrWeakPassword: {400, "Password is too weak", "WEAK_PASSWORD"},
		HTTPErrInvalidBody:  {400, "Invalid request body", "INVALID_BODY"},
		// The dev line's literal register refusal (auth.router.ts:519). A client
		// that reads the message must see the same sentence from either
		// implementation, so both halves are pinned.
		HTTPErrInvalidInput: {400, "Email and password are required", "INVALID_INPUT"},
	}
	for got, want := range messages {
		if got.Status != want.status || got.Message != want.message || got.Code != want.code {
			t.Errorf("catalog entry %+v drifted from %d %q %q", got, want.status, want.message, want.code)
		}
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		err    error
		mapper func(error) HTTPError
		want   HTTPError
	}{
		{ErrInvalidCredentials, HTTPErrorFor, HTTPErrInvalidCredentials},
		{ErrEmailNotVerified, HTTPErrorFor, HTTPErrEmailNotVerified},
		{ErrUserExists, HTTPErrorFor, HTTPErrUserExists},
		{ErrWeakPassword, HTTPErrorFor, HTTPErrWeakPassword},
		// A missing field and a rejected one are different answers: both are
		// 400, and the codes are what tell a client which of the two happened.
		{ErrInvalidInput, HTTPErrorFor, HTTPErrInvalidInput},
		{ErrSessionRevoked, HTTPErrorFor, HTTPErrSessionRevoked},
		{ErrFeatureNotSupported, HTTPErrorFor, HTTPErrNotImplemented},
		// A revoked session must never collapse into a generic token failure:
		// the clients branch on this code to stop refreshing.
		{ErrSessionRevoked, RefreshHTTPError, HTTPErrSessionRevoked},
		{ErrInvalidToken, RefreshHTTPError, HTTPErrExpiredRefreshToken},
		{ErrSessionNotFound, RefreshHTTPError, HTTPErrInvalidRefreshToken},
		{ErrSessionRevoked, AccessHTTPError, HTTPErrSessionRevoked},
		{ErrInvalidToken, AccessHTTPError, HTTPErrInvalidAccessToken},
	}

	for _, tc := range cases {
		if got := tc.mapper(tc.err); got != tc.want {
			t.Errorf("mapping %v = %+v, want %+v", tc.err, got, tc.want)
		}
	}
}

// TestUnmappedSentinelsAreDeliberate makes the 500 fallback a decision instead
// of an accident. HTTPErrorFor is what every later route calls through
// WriteServiceError, so a sentinel nobody mapped turns a client-visible failure
// into "Internal server error". Adding a sentinel to errors.go without touching
// the switch fails here; the exceptions are the ones whose reference wire string
// is route-specific and must be written by the route itself.
func TestUnmappedSentinelsAreDeliberate(t *testing.T) {
	routeSpecific := map[error]string{
		// 401 "Invalid or expired SMS code" on /sms/verify, 401 "Invalid TOTP
		// code" on /2fa/verify — both code-less, both route literals. The OIDC
		// /token route (idp.go, off the reference surface) reuses it for an
		// unknown, consumed or expired authorization code and writes RFC 6749's
		// invalid_grant itself.
		ErrInvalidCode: "wire-contract §3 /sms/verify and /2fa/verify; OIDC /token invalid_grant",
		// Admin-router routes, which emit plain {"error": …} bodies.
		ErrTenantNotFound: "wire-contract §5 tenants",
		ErrRoleNotFound:   "wire-contract §5 roles",
		// The OAuth callback answers this one with a 302 to /account-conflict,
		// not with an error body (auth.router.ts:1346-1355), so there is no
		// envelope for HTTPErrorFor to map it to. The route recognises it before
		// any error mapping runs; reaching a mapper with it means the redirect
		// was lost, and the 500 that follows is the right complaint.
		ErrOAuthAccountConflict: "wire-contract §4 OAuth callback, a redirect rather than a body",
	}
	all := []error{
		ErrInvalidCredentials, ErrUserExists, ErrInvalidToken, ErrSessionNotFound,
		ErrSessionRevoked, ErrWeakPassword, ErrFeatureNotSupported, ErrEmailNotVerified,
		ErrInvalidCode, ErrTwoFactorRequired, ErrAlreadyExists, ErrTenantNotFound,
		ErrRoleNotFound, ErrEmailNotConfigured, ErrSMSNotConfigured,
		ErrOAuthAccountConflict, ErrInvalidInput,
	}
	for _, err := range all {
		mapped := HTTPErrorFor(err) != HTTPErrInternal
		if reason, exempt := routeSpecific[err]; exempt {
			if mapped {
				t.Errorf("%v is now mapped centrally; drop it from the route-specific list (%s)", err, reason)
			}
			continue
		}
		if !mapped {
			t.Errorf("%v falls through to 500: map it in HTTPErrorFor or list it as route-specific", err)
		}
	}
}

// TestLogoutAccessTokenRevokesTheSession pins the revocation path a cookie
// client's logout actually takes. The refresh cookie is scoped to
// <prefix>/refresh in every non-__Host- configuration, so a browser sends only
// the access cookie to <prefix>/logout; if that does not revoke, logout answers
// 200 and leaves the session live.
func TestLogoutAccessTokenRevokesTheSession(t *testing.T) {
	a, err := newTestAuth(WithUserStore(NewMemoryUserStore()), WithSessionStore(NewMemorySessionStore()))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()
	_, tokens, err := a.Register(ctx, RegisterInput{Email: "revoke@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := a.LogoutAccessToken(ctx, tokens.AccessToken); err != nil {
		t.Fatalf("LogoutAccessToken: %v", err)
	}
	if _, err := a.Refresh(ctx, tokens.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("refresh after logout = %v, want ErrSessionRevoked", err)
	}
}

// TestLogoutRequestFallsBackToTheAccessCookie is the same claim one level up,
// through the helper all four adapters call, with the cookie set a browser
// would actually send to <prefix>/logout in the __Secure- configuration.
func TestLogoutRequestFallsBackToTheAccessCookie(t *testing.T) {
	a, err := newTestAuth(WithUserStore(NewMemoryUserStore()), WithSessionStore(NewMemorySessionStore()))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()
	_, tokens, err := a.Register(ctx, RegisterInput{Email: "scoped@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "__Secure-accessToken", Value: tokens.AccessToken})
	a.LogoutRequest(ctx, req)

	if _, err := a.Refresh(ctx, tokens.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("refresh after logout = %v, want ErrSessionRevoked", err)
	}
}

// TestLogoutRequestToleratesEveryMissingCredential — logout must never fail.
func TestLogoutRequestToleratesEveryMissingCredential(t *testing.T) {
	a, err := newTestAuth(WithUserStore(NewMemoryUserStore()), WithSessionStore(NewMemorySessionStore()))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/auth/logout", nil),
		httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader("{not json")),
		withCookie(httptest.NewRequest(http.MethodPost, "/auth/logout", nil), "accessToken", "garbage"),
		withCookie(httptest.NewRequest(http.MethodPost, "/auth/logout", nil), "refreshToken", "garbage"),
	} {
		a.LogoutRequest(context.Background(), req)
	}
}

func withCookie(r *http.Request, name, value string) *http.Request {
	r.AddCookie(&http.Cookie{Name: name, Value: value})
	return r
}

func TestHTTPConfigResolvesDerivedDefaults(t *testing.T) {
	cfg := HTTPConfig{APIPrefix: "api/auth/"}.resolve(10*time.Minute, 48*time.Hour)

	if cfg.APIPrefix != "/api/auth" {
		t.Errorf("APIPrefix = %q", cfg.APIPrefix)
	}
	if cfg.Cookies.RefreshTokenPath != "/api/auth/refresh" {
		t.Errorf("RefreshTokenPath = %q", cfg.Cookies.RefreshTokenPath)
	}
	if cfg.Cookies.AccessTokenMaxAge != 10*time.Minute || cfg.Cookies.RefreshTokenMaxAge != 48*time.Hour {
		t.Errorf("cookie lifetimes do not track the token lifetimes: %+v", cfg.Cookies)
	}
	if cfg.CSRF.CookieName != CSRFTokenCookieName || cfg.CSRF.HeaderName != CSRFHeaderName {
		t.Errorf("csrf names = %q/%q", cfg.CSRF.CookieName, cfg.CSRF.HeaderName)
	}
}

func TestRefreshTokenFromRequestPrefersTheBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(`{"refreshToken":"from-body"}`))
	req.AddCookie(&http.Cookie{Name: "refreshToken", Value: "from-cookie"})
	if got := RefreshTokenFromRequest(req); got != "from-body" {
		t.Fatalf("got %q", got)
	}
}

func TestRefreshTokenFromRequestFallsBackToTheCookie(t *testing.T) {
	// Cookie-mode clients send no body at all; that must not read as an error.
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refreshToken", Value: "from-cookie"})
	if got := RefreshTokenFromRequest(req); got != "from-cookie" {
		t.Fatalf("got %q", got)
	}
}

// -----------------------------------------------------------------------------
// emailed links: UILink, LinkBase, ResolveSiteURL
// -----------------------------------------------------------------------------

// TestHTTPConfigUILink pins buildUiLink (auth.router.ts:261-271) branch by
// branch: the /ui segment under UI.Enabled, one trailing slash stripped from the
// prefix, one leading slash stripped from the path, and the site URL used as
// given.
func TestHTTPConfigUILink(t *testing.T) {
	const site = "https://app.example.com"
	cases := []struct {
		name string
		cfg  HTTPConfig
		site string
		path string
		want string
	}{
		{"default prefix, API route", HTTPConfig{}, site, "/reset-password?token=t", site + "/auth/reset-password?token=t"},
		{"default prefix, static UI", HTTPConfig{UI: UIOptions{Enabled: true}}, site, "/reset-password?token=t", site + "/auth/ui/reset-password?token=t"},
		{"trailing-slash prefix, API route", HTTPConfig{APIPrefix: "/api/auth/"}, site, "/verify-email?token=t", site + "/api/auth/verify-email?token=t"},
		{"trailing-slash prefix, static UI", HTTPConfig{APIPrefix: "/api/auth/", UI: UIOptions{Enabled: true}}, site, "/verify-email?token=t", site + "/api/auth/ui/verify-email?token=t"},
		{"root prefix", HTTPConfig{APIPrefix: "/"}, site, "/verify-email?token=t", site + "/verify-email?token=t"},
		{"path without a leading slash", HTTPConfig{}, site, "verify-email?token=t", site + "/auth/verify-email?token=t"},
		// The reference's empty-path shape keeps its trailing slash (:269); the
		// strip belongs to LinkBase, where the reference strips it too.
		{"empty path, API route", HTTPConfig{}, site, "", site + "/auth/"},
		{"empty path, static UI", HTTPConfig{UI: UIOptions{Enabled: true}}, site, "", site + "/auth/ui/"},
		// No site URL is a relative link, as in the reference with siteUrl unset.
		{"no site URL", HTTPConfig{}, "", "/reset-password?token=t", "/auth/reset-password?token=t"},
	}
	for _, tc := range cases {
		if got := tc.cfg.UILink(tc.site, tc.path); got != tc.want {
			t.Errorf("%s: UILink = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestHTTPConfigLinkBase pins the base the URL builders take: UILink with an
// empty path and the trailing slash removed (magic-link.strategy.ts:25-27), so
// that MagicLinkURL(LinkBase(site), tok) is exactly what the reference mails —
// and "" for no site URL, which is what lets a mailer's static BaseURL apply.
func TestHTTPConfigLinkBase(t *testing.T) {
	const site = "https://app.example.com"
	cases := []struct {
		name string
		cfg  HTTPConfig
		want string
	}{
		{"default prefix", HTTPConfig{}, site + "/auth"},
		{"static UI", HTTPConfig{UI: UIOptions{Enabled: true}}, site + "/auth/ui"},
		{"trailing-slash prefix", HTTPConfig{APIPrefix: "/api/auth/"}, site + "/api/auth"},
		{"root prefix", HTTPConfig{APIPrefix: "/"}, site},
	}
	for _, tc := range cases {
		if got := tc.cfg.LinkBase(site); got != tc.want {
			t.Errorf("%s: LinkBase = %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := (HTTPConfig{}).LinkBase(""); got != "" {
		t.Errorf("LinkBase(\"\") = %q, want \"\" so the mailer's BaseURL applies", got)
	}
	// The composition the adapters and the mailers rely on.
	ui := HTTPConfig{UI: UIOptions{Enabled: true}}
	if got := MagicLinkURL(ui.LinkBase(site), "tok"); got != site+"/auth/ui/magic-link/verify?token=tok" {
		t.Errorf("MagicLinkURL over LinkBase = %q", got)
	}
}

// siteURLAuth builds an Auth with the given site URLs and, when wiring is not
// nil, the given OAuth wiring — the two inputs ResolveSiteURL reads.
func siteURLAuth(t *testing.T, siteURLs []string, wiring *OAuthWiring) *Auth {
	t.Helper()
	opts := []Option{WithSiteURLs(siteURLs...)}
	if wiring != nil {
		opts = append(opts, WithOAuth(*wiring))
	}
	a, err := New(opts...)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

func requestWith(headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// TestResolveSiteURL pins resolveSiteUrl (auth.router.ts:233-246) over the
// allowlist buildAllowedOrigins builds (:213-219) and the default
// getDefaultSiteUrl returns (:202-206).
func TestResolveSiteURL(t *testing.T) {
	const (
		www = "https://www.example.com"
		app = "https://app.example.com"
		api = "https://api.example.com"
	)

	t.Run("an allowlisted Origin wins", func(t *testing.T) {
		a := siteURLAuth(t, []string{www, app}, nil)
		if got := a.ResolveSiteURL(requestWith(map[string]string{"Origin": app})); got != app {
			t.Errorf("got %q, want %q", got, app)
		}
	})

	t.Run("an allowlisted Referer origin wins when there is no Origin", func(t *testing.T) {
		a := siteURLAuth(t, []string{www, app}, nil)
		got := a.ResolveSiteURL(requestWith(map[string]string{"Referer": app + "/account/settings?tab=security"}))
		if got != app {
			t.Errorf("got %q, want %q", got, app)
		}
	})

	t.Run("Origin outranks Referer", func(t *testing.T) {
		a := siteURLAuth(t, []string{www, app}, nil)
		got := a.ResolveSiteURL(requestWith(map[string]string{"Origin": www, "Referer": app + "/login"}))
		if got != www {
			t.Errorf("got %q, want %q", got, www)
		}
	})

	t.Run("an unlisted Origin and Referer fall back to the first site URL", func(t *testing.T) {
		a := siteURLAuth(t, []string{www, app}, nil)
		got := a.ResolveSiteURL(requestWith(map[string]string{"Origin": "https://evil.example", "Referer": "https://evil.example/x"}))
		if got != www {
			t.Errorf("got %q, want the first site URL %q", got, www)
		}
	})

	t.Run("no headers fall back to the first site URL", func(t *testing.T) {
		a := siteURLAuth(t, []string{www, app}, nil)
		if got := a.ResolveSiteURL(requestWith(nil)); got != www {
			t.Errorf("got %q, want %q", got, www)
		}
		if got := a.ResolveSiteURL(nil); got != www {
			t.Errorf("nil request: got %q, want %q", got, www)
		}
	})

	// The reference matches exactly (`allowedOrigins.includes(origin)`): a
	// trailing slash or a different case is a different origin.
	t.Run("the match is exact", func(t *testing.T) {
		a := siteURLAuth(t, []string{www, app}, nil)
		for _, origin := range []string{app + "/", "https://APP.example.com", "http://app.example.com"} {
			if got := a.ResolveSiteURL(requestWith(map[string]string{"Origin": origin})); got != www {
				t.Errorf("Origin %q resolved to %q, want the default %q", origin, got, www)
			}
		}
	})

	t.Run("OAuthWiring.AllowedOrigins extend the allowlist", func(t *testing.T) {
		a := siteURLAuth(t, []string{www}, &OAuthWiring{AllowedOrigins: []string{app}})
		if got := a.ResolveSiteURL(requestWith(map[string]string{"Origin": app})); got != app {
			t.Errorf("got %q, want the CORS origin %q", got, app)
		}
	})

	t.Run("an empty allowlist ignores the headers and yields the default", func(t *testing.T) {
		a := siteURLAuth(t, nil, nil)
		if got := a.ResolveSiteURL(requestWith(map[string]string{"Origin": app, "Referer": app + "/"})); got != "" {
			t.Errorf("got %q, want \"\" with nothing configured", got)
		}
		// OAuthWiring.SiteURL alone is a default, not an allowlist entry: the
		// reference only allowlists what siteUrl and cors.origins hold.
		a = siteURLAuth(t, nil, &OAuthWiring{SiteURL: api})
		if got := a.ResolveSiteURL(requestWith(map[string]string{"Origin": app})); got != api {
			t.Errorf("got %q, want the wiring's site URL %q", got, api)
		}
	})

	t.Run("OAuthWiring.SiteURL overrides the first site URL as the default", func(t *testing.T) {
		a := siteURLAuth(t, []string{www, app}, &OAuthWiring{SiteURL: api})
		if got := a.ResolveSiteURL(requestWith(nil)); got != api {
			t.Errorf("got %q, want the override %q", got, api)
		}
		// The site URLs are still the allowlist.
		if got := a.ResolveSiteURL(requestWith(map[string]string{"Origin": app})); got != app {
			t.Errorf("got %q, want %q", got, app)
		}
	})

	t.Run("WithSiteURLs copies its arguments", func(t *testing.T) {
		urls := []string{www, app}
		a := siteURLAuth(t, urls, nil)
		urls[0] = "https://changed.example"
		if got := a.ResolveSiteURL(requestWith(nil)); got != www {
			t.Errorf("got %q: the option aliased the caller's slice", got)
		}
	})
}

// TestAllowedOriginsDedupeKeepsOrder pins `[...new Set([...siteUrl, ...cors])]`
// (auth.router.ts:218): site URLs first, then the CORS origins, each value at
// its first position.
func TestAllowedOriginsDedupeKeepsOrder(t *testing.T) {
	a := siteURLAuth(t,
		[]string{"https://a.example", "https://b.example", "https://a.example"},
		&OAuthWiring{AllowedOrigins: []string{"https://b.example", "https://c.example", "https://a.example", "https://d.example"}},
	)
	got := strings.Join(a.allowedOrigins(), " ")
	want := "https://a.example https://b.example https://c.example https://d.example"
	if got != want {
		t.Errorf("allowedOrigins = [%s], want [%s]", got, want)
	}
	if got := dedupeOrigins(nil, nil); len(got) != 0 {
		t.Errorf("dedupeOrigins(nil, nil) = %v, want empty", got)
	}
}
