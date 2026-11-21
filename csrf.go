package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// csrfTokenBytes is the reference's token size: 16 random bytes rendered as 32
// hex characters.
const csrfTokenBytes = 16

// randomHex renders byteLen random bytes as hex. The CSRF token uses it rather
// than randomToken because the family clients are pinned to a hex token.
func randomHex(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: random hex: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CSRFConfig configures the cookie+header double-submit CSRF protection. The
// cookie attributes come from HTTPConfig.Cookies so that the CSRF cookie is
// serialised by the same matrix as the token cookies.
type CSRFConfig struct {
	// Enabled gates both enforcement and cookie distribution, mirroring the
	// reference's config.csrf.enabled.
	Enabled    bool
	CookieName string
	HeaderName string
}

// DefaultCSRFConfig returns defaults compatible with browser cookie auth flows.
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		Enabled:    true,
		CookieName: CSRFTokenCookieName,
		HeaderName: CSRFHeaderName,
	}
}

// csrfExemption identifies one exempt route. The method is part of the key
// because the reference's exemptions are Express *routes*, not paths: it is
// `router.post('/sessions/cleanup', …)` that carries no auth middleware, while
// `router.delete('/sessions/:handle', …, authMiddleware, …)` does. Keying on the
// path alone let DELETE <prefix>/sessions/cleanup resolve to the exempt cleanup
// entry and skip the double-submit — so a session whose handle was literally
// "cleanup" could be revoked cross-site. Unreachable with the "ses_"+hex handles
// this package issues, but a custom store can mint anything.
type csrfExemption struct {
	method string
	path   string
}

// csrfExemptRoutes are the routes the reference mounts without its auth
// middleware. CSRF is enforced inside that middleware, so these routes are
// never checked — including POST /logout, which the reference deliberately
// leaves unprotected so that a client with a stale CSRF cookie can still log
// out.
//
// This table is the contract for every route added later: a mutating route that
// is absent from it is CSRF-checked, so leaving an unauthenticated route out
// breaks it and putting an authenticated one in silently unprotects it. It is
// pinned method-by-method by TestCSRFExemptionsMatchTheReference.
//
// Four entries are not simply "routes without the auth middleware":
//   - POST /2fa/verify is a pre-login step-up call with no auth gate, so the
//     reference never CSRF-checks it (wire-contract §3, "CSRF does not apply
//     to: … /2fa/verify").
//   - POST /change-email/confirm has no auth gate either: the emailed token is
//     the credential, so the link has to work from a browser with no session and
//     no CSRF cookie at all (auth.router.ts:1040-1067).
//   - GET /verify-email is listed for completeness only. It is a GET, so it is
//     already exempt as a safe method and the entry can never be the reason a
//     request passes; recording it keeps the table a faithful transcription of
//     the reference's unauthenticated surface.
//   - /link-request is deliberately NOT here. It has no auth middleware but the
//     reference performs its own manual double-submit check inside the handler
//     (auth.router.ts:1489-1495), so it is the one unauthenticated route that
//     is CSRF-protected. It lives in csrfManualCheckRoutes instead, which is
//     what keeps it enforced even with no cookie credential on the request.
//
// Methods are the reference's, route by route (src/router/auth.router.ts:541,
// 590, 622, 715, 736, 777, 802, 859, 969, 1040, 1078, 1126, 1176, 1244, 1544).
var csrfExemptRoutes = map[csrfExemption]bool{
	{http.MethodPost, "/login"}:                true,
	{http.MethodPost, "/register"}:             true,
	{http.MethodPost, "/refresh"}:              true,
	{http.MethodPost, "/logout"}:               true,
	{http.MethodPost, "/forgot-password"}:      true,
	{http.MethodPost, "/reset-password"}:       true,
	{http.MethodGet, "/verify-email"}:          true,
	{http.MethodPost, "/change-email/confirm"}: true,
	{http.MethodPost, "/magic-link/send"}:      true,
	{http.MethodPost, "/magic-link/verify"}:    true,
	{http.MethodPost, "/sms/send"}:             true,
	{http.MethodPost, "/sms/verify"}:           true,
	{http.MethodPost, "/2fa/verify"}:           true,
	{http.MethodPost, "/link-verify"}:          true,
	{http.MethodPost, "/sessions/cleanup"}:     true,
	// This port's own route, not the reference's (invitation.go): mounted only
	// with an InvitationStore, unauthenticated, and exempt for the reason
	// /reset-password and /change-email/confirm are — the emailed token in the
	// body is the credential, so the accept form has to work from a browser
	// that holds another account's cookies and no CSRF pair.
	{http.MethodPost, InvitationAcceptRoute}: true,
}

// csrfManualCheckRoutes are the routes the reference CSRF-checks by hand inside
// the handler instead of inheriting the check from its auth middleware. They are
// enforced whether or not the request is cookie-authenticated, which is what
// makes them different from every other enforced route.
//
// POST /link-request is the only entry, and it is deliberately not in
// csrfExemptRoutes. The reference mounts it without authMiddleware, then opens the
// handler with its own double-submit check gated only on `config.csrf.enabled`
// (auth.router.ts:1489-1495) — before it extracts any token (:1502). It has to:
// when no access token resolves, the handler falls back to the pending-link stash
// (:1513-1524), and that stash stands in for authentication for about an hour. So
// the route performs a write on behalf of an identity it did not authenticate,
// and the double-submit is the only thing standing between a cross-site form and
// that write.
//
// Do not fold this into csrfExemptRoutes. Being absent from the exempt table is
// not enough on its own: enforcement below is otherwise scoped to requests that
// carry an access-token cookie, and /link-request is precisely the route that
// needs checking when there is no such cookie. Without this table a pure forgery
// — no cookies, no Authorization, no headers — reaches linkRequest, which does no
// manual check of its own, and decodeJSON never inspects Content-Type, so an
// auto-submitting <form enctype="text/plain"> is enough. That overwrites any
// in-flight account-link token and mails the victim's address.
//
// [DEVIATION] One term of the reference's manual check is deliberately not
// reproduced: the bearer exemption. auth.router.ts:1489 gates the hand-written
// check on `config.csrf.enabled` alone, with no `usingBearer` term — unlike
// auth.middleware.ts:35 — so the reference answers 403 CSRF_INVALID to a
// bearer-authenticated POST /link-request that carries no double-submit pair.
// This port exempts a real bearer credential here as it does everywhere else, so
// that request succeeds. The divergence is:
//
//   - not a CSRF weakening. A cross-site page cannot set Authorization: the
//     header is not CORS-safelisted, so it costs a preflight the target must
//     approve, and the attacker has no token to put in it. Every request this
//     exempts is one the attacker could not have forged.
//   - the client-friendly direction, and the reference's own defect. The family
//     contract records it as a MISMATCH against the reference and notes it is
//     [UNTESTED] there: a native bearer client with no cookie jar "will fail this
//     check whenever CSRF is enabled server-side"
//     (docs/spec/wire-contract.md §4, POST /link-request, and mismatch summary
//     item 2). Reproducing it would break exactly those clients.
//   - invisible to a conforming client. A caller that sends the pair, as the
//     reference requires, is accepted by both.
//
// It predates csrfManualCheckRoutes — CSRFMiddleware has always short-circuited on
// usingBearerCredential — but this table is what makes the route's enforcement
// unconditional in every *other* respect, so the one remaining condition belongs
// here in writing. Pinned by TestCSRFManualCheckRouteExemptsARealBearerCredential;
// flipping it is a one-line change in CSRFMiddleware, not a table edit.
var csrfManualCheckRoutes = map[csrfExemption]bool{
	{http.MethodPost, "/link-request"}: true,
}

// CSRFMiddleware distributes and enforces the double-submit token.
//
// Distribution mirrors the reference's router-level auto-init: a request that
// arrives without a readable CSRF cookie gets a fresh one.
//
// Enforcement follows the reference matrix. A request is checked when it is an
// unsafe method, on a mounted route, that route is not exempt, the request
// presents no bearer credential, and either it carries an access-token cookie or
// the route does its own manual check in the reference:
//
//	enforced = mutating && mounted && !exempt && !usingBearerCredential
//	           && (accessTokenCookiePresent || manualCheckRoute)
//
// Safe methods, bearer requests, the unauthenticated routes in csrfExemptRoutes
// and — for every route but csrfManualCheckRoutes — requests with no cookie
// credential are passed through. The last of those is the reference's ordering:
// see csrfEnforced.
func CSRFMiddleware(cfg HTTPConfig) func(http.Handler) http.Handler {
	cfg = cfg.resolve(0, 0)
	prefix := cfg.Prefix()
	cookieName := cfg.CSRF.CookieName
	headerName := cfg.CSRF.HeaderName

	return func(next http.Handler) http.Handler {
		if !cfg.CSRF.Enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Cookie distribution. A bearer caller never reads the CSRF cookie and
			// asked not to be sent cookies, so it gets none — that is what makes
			// "bearer requests set no cookies" true of the whole response and not
			// just of the token delivery. Note this is the only thing the
			// client-declared X-Auth-Strategy header may decide.
			token := CookieValue(r, cookieName)
			if token == "" && !isBearerClient(r) {
				fresh, err := randomHex(csrfTokenBytes)
				if err != nil {
					WriteHTTPError(w, HTTPErrInternal)
					return
				}
				token = fresh
				cfg.Cookies.SetCSRFTokenCookie(w, token)
			}

			// Enforcement. Only a request that actually presents a bearer token is
			// exempt: the reference skips the check on `usingBearer`, which is set
			// solely by an "Authorization: Bearer …" header (§1.2,
			// auth.middleware.ts:22-35). A request that authenticates by cookie is
			// checked whatever it claims in X-Auth-Strategy — that header is
			// attacker-controllable on any request the attacker can make at all, so
			// letting it switch the control off would hand the exemption to exactly
			// the caller the control exists to stop.
			if usingBearerCredential(r) || !csrfEnforced(r, prefix) {
				next.ServeHTTP(w, r)
				return
			}
			headerToken := strings.TrimSpace(r.Header.Get(headerName))
			if headerToken == "" || !secureEqual(headerToken, token) {
				WriteHTTPError(w, HTTPErrCSRFInvalid)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isBearerClient reports whether the caller authenticates with a bearer token or
// asked for bearer delivery. It governs cookie *distribution* only: a client
// that declared the bearer strategy does not want cookies, and honouring that is
// harmless. It must not govern enforcement — see usingBearerCredential.
func isBearerClient(r *http.Request) bool {
	return IsBearerRequest(r) || usingBearerCredential(r)
}

// usingBearerCredential reports whether the request actually presents a bearer
// token, which is the reference's `usingBearer` (auth.middleware.ts:22-26) and
// the only condition that exempts a request from the double-submit check. A
// declared strategy is not a credential.
func usingBearerCredential(r *http.Request) bool {
	return r != nil && BearerToken(r.Header.Get("Authorization")) != ""
}

// csrfEnforced reports whether the double-submit check applies to this request.
//
// The reference runs the check inside authMiddleware, *after* the access token has
// been extracted, and only when the token came from a cookie
// (auth.middleware.ts:29-42): no token at all short-circuits to
// 403 {"error":"No access token provided"} with no code, and never reaches the
// CSRF branch. This port runs CSRF as a middleware wrapping the auth middleware,
// so it is asked first — which is what keeps cookie distribution router-level, as
// the reference's is. Scoping enforcement to requests that present an
// access-token cookie recovers the reference's ordering on the wire: a request
// with no cookie credential is passed straight through and answered by the auth
// gate with the reference's literal, while a cookie-authenticated one is still
// checked before anything touches the session.
//
// That scoping is safe only because the auth gate is the second line of defence
// for every route below. It is not, for the one route that has no auth gate at
// all, which is why csrfManualCheckRoutes is consulted before the cookie test —
// see the comment on that table — and why it is consulted against every reading of
// the mount prefix rather than only the leftmost. Where the mount sits is ambiguous
// when a host's base path ends in the same segment as the prefix, and the cookie
// test turns a missed resolution into an unenforced route rather than a noisy
// failure.
func csrfEnforced(r *http.Request, prefix string) bool {
	if !isMutatingMethod(r.Method) {
		return false
	}
	rels, mounted := csrfRelativePaths(r.URL.Path, prefix)
	if !mounted {
		return false
	}
	// A manual-check route is enforced under *any* reading of where the mount
	// prefix sits, because the prefix can legitimately occur more than once in a
	// served path and only the host knows which occurrence is the real mount. A
	// host that groups its API under /auth and keeps the default /auth prefix
	// serves /auth/auth/link-request; resolving that at the first occurrence gives
	// "/auth/link-request", which is in neither table, so the route would fall
	// through to the cookie test below and — carrying no cookie, as a forgery does
	// not — go unenforced. That is the demonstrated hole, reopened by a mount
	// shape this package advertises as supported.
	//
	// Widening enforcement is always safe here: the worst case is checking a
	// request the reference would not have, which costs a legitimate client a
	// retry with the header it should already be sending.
	for _, rel := range rels {
		if csrfManualCheckRoutes[csrfExemption{method: r.Method, path: rel}] {
			return true
		}
	}
	// Exemption, by contrast, is decided by the first (leftmost) resolution alone,
	// and deliberately not by any later one. A later occurrence can be attacker
	// chosen: path parameters are part of the path, so
	// DELETE <prefix>/linked-accounts/auth/login resolves at its second occurrence
	// to "/login" — an exempt entry — and honouring that would let any
	// cookie-authenticated protected route be unprotected by naming a provider
	// "auth". Exemptions may only ever be read from the mount the middleware was
	// configured with.
	if csrfExemptRoutes[csrfExemption{method: r.Method, path: rels[0]}] {
		return false
	}
	// CookieValue resolves the __Host- → __Secure- → bare precedence, so this
	// asks the same question of the same cookie as the auth gate behind it
	// (AccessTokenFromRequest). The two must not disagree about whether a request
	// is cookie-authenticated, or enforcement would switch off for a request the
	// auth gate then lets through.
	return CookieValue(r, AccessTokenCookieName) != ""
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// csrfRelativePaths locates the mount prefix inside a request path and returns the
// route below every occurrence of it, leftmost first, plus whether it occurs at all.
//
// The prefix has to land on a segment boundary — "/authenticate/login" is not
// "/auth" plus "enticate/login" — and it may sit after a base path, because a
// host app that mounts the adapter on a gin/echo group or a chi Route serves
// <base><prefix>/<route> while the middleware only ever knows <prefix>. Matching
// on the head of the path alone would leave every group-mounted deployment with
// enforcement silently switched off.
//
// Searching for the prefix is therefore unavoidable, and it is ambiguous whenever
// the base ends in the same segment as the prefix: a group based at /auth with the
// default /auth prefix serves /auth/auth/<route>, which resolves both to
// "/auth/<route>" (leftmost) and to "/<route>" (rightmost). Nothing in the request
// says which is the real mount, so every candidate is returned and the caller
// decides — asymmetrically, because the two ends carry different trust. See
// csrfEnforced: enforcement may be widened by any candidate, while an exemption may
// only ever be read from the first, since later segments can be attacker-chosen
// path parameters.
func csrfRelativePaths(path, prefix string) ([]string, bool) {
	if prefix == "" || prefix == "/" {
		return []string{strings.TrimSuffix(path, "/")}, true
	}
	var rels []string
	for i := 0; i+len(prefix) <= len(path); i++ {
		offset := strings.Index(path[i:], prefix)
		if offset < 0 {
			break
		}
		i += offset
		rest := path[i+len(prefix):]
		if rest == "" || strings.HasPrefix(rest, "/") {
			rels = append(rels, strings.TrimSuffix(rest, "/"))
		}
	}
	if len(rels) == 0 {
		return nil, false
	}
	return rels, true
}
