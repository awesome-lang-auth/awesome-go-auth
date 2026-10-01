package nethttp

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	auth "github.com/nik2208/awesome-go-auth"
)

// The OAuth and account-linking group (wire-contract.md §4). Every decision
// lives in the root package's flow methods; these handlers only read the
// request, call one of them and write the wire shape.
//
// The handlers are exported as http.Handler rather than as methods the other
// adapters re-implement, because chi, gin and echo all mount these six routes
// by delegating here. Path parameters are therefore read off the URL instead of
// the router: chi's URLParam, gin's c.Param and net/http's r.PathValue are
// three different mechanisms, and one shared handler can only rely on the path.

// OAuthAuthorizeHandler serves GET <prefix>/oauth/{provider}.
func (a *Adapter) OAuthAuthorizeHandler() http.Handler {
	return a.guard(http.HandlerFunc(a.oauthAuthorize))
}

// OAuthCallbackHandler serves GET <prefix>/oauth/{provider}/callback.
func (a *Adapter) OAuthCallbackHandler() http.Handler {
	return a.guard(http.HandlerFunc(a.oauthCallback))
}

// LinkedAccountsHandler serves GET <prefix>/linked-accounts.
func (a *Adapter) LinkedAccountsHandler() http.Handler {
	return a.guard(a.Middleware()(http.HandlerFunc(a.linkedAccounts)))
}

// UnlinkAccountHandler serves DELETE <prefix>/linked-accounts/{provider}/{providerAccountId}.
//
// The path-shape gate is outside both the CSRF and the auth middleware, and it
// answers the same bare 404 an unrouted path gets. That is what lets gin mount
// this route as a catch-all: gin routes on the unescaped path, so a
// providerAccountId containing %2F only reaches a two-parameter pattern as three
// segments. With the catch-all, path shapes that the other three routers reject
// at the router now arrive here instead, and they must not turn into a 403 or a
// CSRF failure that no other adapter emits.
func (a *Adapter) UnlinkAccountHandler() http.Handler {
	return a.unlinkPathGate(a.guard(a.Middleware()(http.HandlerFunc(a.unlinkAccount))))
}

// unlinkPathGate rejects anything that is not exactly
// <prefix>/linked-accounts/<provider>/<providerAccountId>.
func (a *Adapter) unlinkPathGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(pathSegmentsAfter(r, a.cfg.Prefix(), "linked-accounts")) != 2 {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LinkRequestHandler serves POST <prefix>/link-request. It is deliberately not
// behind the auth middleware: the conflict flow reaches it unauthenticated and
// proves identity through the pending-link stash instead.
func (a *Adapter) LinkRequestHandler() http.Handler {
	return a.guard(http.HandlerFunc(a.linkRequest))
}

// LinkVerifyHandler serves POST <prefix>/link-verify.
func (a *Adapter) LinkVerifyHandler() http.Handler {
	return a.guard(http.HandlerFunc(a.linkVerify))
}

// oauthAuthorize redirects the browser to the provider with a signed state and
// a PKCE challenge.
func (a *Adapter) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	provider := providerSegment(r, a.cfg.Prefix(), "oauth")
	if provider == "" {
		auth.WriteHTTPError(w, auth.OAuthHTTPError(auth.OAuthNotConfiguredError(provider)))
		return
	}
	// No credential is read off this request, deliberately. The reference's
	// /oauth/{provider} has no auth gate and reads no token (wire-contract.md §4:
	// "Auth gate: none"), and the callback resolves the identity purely through the
	// provider account. Treating "somebody is signed in" as "link to that account"
	// would hand the provider identity — and the resulting session — to whoever
	// happened to hold a session when the flow started. Linking to an existing
	// account is /link-request plus /link-verify, where an emailed token proves the
	// address.
	result, err := a.auth.OAuthBegin(r.Context(), auth.OAuthBeginInput{
		Provider:   provider,
		ReturnPath: r.URL.Query().Get("return_path"),
		Origin:     r.Header.Get("Origin"),
		Referer:    r.Header.Get("Referer"),
	})
	if err != nil {
		auth.WriteHTTPError(w, auth.OAuthHTTPError(err))
		return
	}
	http.Redirect(w, r, result.AuthorizationURL, http.StatusFound)
}

// oauthCallback completes the flow. Token delivery is always by cookie and the
// answer is always a 302: the reference ignores X-Auth-Strategy on redirect
// flows (wire-contract.md §4, issueTokens with redirectTo).
//
// Failures answer with JSON rather than a redirect, which is the reference's
// own choice here (§4: "handleError returns JSON, not a redirect") even though
// it strands a browser on a raw JSON page. The one exception is the reference's
// own: an account conflict is a 302 to /account-conflict carrying the provider,
// the code and the address, so the front-end can drive the link flow
// (auth.router.ts:1346-1355).
func (a *Adapter) oauthCallback(w http.ResponseWriter, r *http.Request) {
	provider := providerSegment(r, a.cfg.Prefix(), "oauth")
	if provider == "" {
		auth.WriteHTTPError(w, auth.OAuthHTTPError(auth.OAuthNotConfiguredError(provider)))
		return
	}
	query := r.URL.Query()
	result, err := a.auth.OAuthComplete(r.Context(), auth.OAuthCompleteInput{
		Provider: provider,
		Code:     query.Get("code"),
		State:    query.Get("state"),
	})
	if err != nil {
		// The conflict is the reference's redirect, not an error body: the state
		// stash was written by OAuthComplete and the browser is sent to the page
		// that drives /link-request. result.RedirectTo is the same
		// resolveOAuthRedirect value the reference passes to buildUiLink there
		// (auth.router.ts:1347), so a rejected state origin lands on the default
		// site url exactly as a successful login would.
		var conflict *auth.OAuthAccountConflictError
		if errors.As(err, &conflict) {
			http.Redirect(w, r, a.cfg.AccountConflictLink(result.RedirectTo, provider, conflict.Email), http.StatusFound)
			return
		}
		auth.WriteHTTPError(w, auth.OAuthHTTPError(err))
		return
	}
	cookies := a.cfg.Cookies
	if cookies.AccessTokenMaxAge <= 0 && result.Tokens.ExpiresIn > 0 {
		cookies.AccessTokenMaxAge = result.Tokens.ExpiresIn
	}
	cookies.SetAccessTokenCookie(w, result.Tokens.AccessToken)
	cookies.SetRefreshTokenCookie(w, result.Tokens.RefreshToken)
	redirectTo := result.RedirectTo
	if redirectTo == "" {
		// The reference's `redirectTo || '/'`.
		redirectTo = "/"
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// linkedAccounts answers the wrapped object.
//
// [MISMATCH] The Flutter client's getLinkedAccounts only accepts a bare JSON
// array and therefore always reads an empty list against this shape
// (wire-contract.md §4, mismatch 1). That is a client bug: Angular and the
// served auth.js both read res.linkedAccounts, so the wrapper stays.
func (a *Adapter) linkedAccounts(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
		return
	}
	accounts, err := a.auth.ListLinkedAccounts(r.Context(), user.ID)
	if err != nil {
		auth.WriteHTTPError(w, auth.OAuthHTTPError(err))
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"linkedAccounts": accounts})
}

// unlinkAccount answers success unconditionally, as the reference does: there
// is no existence check and unlinking an unknown pair is not an error.
func (a *Adapter) unlinkAccount(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
		return
	}
	// unlinkPathGate has already established that there are exactly two.
	segments := pathSegmentsAfter(r, a.cfg.Prefix(), "linked-accounts")
	if err := a.auth.UnlinkAccount(r.Context(), user.ID, segments[0], segments[1]); err != nil {
		auth.WriteHTTPError(w, auth.OAuthHTTPError(err))
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// linkRequestBody is the reference's { email, provider?, emailLang? }
// (auth.router.ts:1496).
type linkRequestBody struct {
	Email     string `json:"email"`
	Provider  string `json:"provider"`
	EmailLang string `json:"emailLang"`
}

func (a *Adapter) linkRequest(w http.ResponseWriter, r *http.Request) {
	var req linkRequestBody
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	if _, err := a.auth.LinkRequest(r.Context(), auth.LinkRequestInput{
		Email:       req.Email,
		Provider:    req.Provider,
		EmailLang:   req.EmailLang,
		AccessToken: auth.AccessTokenFromRequest(r),
		Origin:      r.Header.Get("Origin"),
		Referer:     r.Header.Get("Referer"),
		APIPrefix:   a.cfg.Prefix(),
	}); err != nil {
		auth.WriteHTTPError(w, auth.OAuthHTTPError(err))
		return
	}
	// The token itself is never in the response: it is a credential and the
	// emailed link is the only way to receive it.
	auth.WriteSuccess(w, http.StatusOK, nil)
}

type linkVerifyBody struct {
	Token             string `json:"token"`
	LoginAfterLinking bool   `json:"loginAfterLinking"`
}

func (a *Adapter) linkVerify(w http.ResponseWriter, r *http.Request) {
	var req linkVerifyBody
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	result, err := a.auth.LinkVerify(r.Context(), auth.LinkVerifyInput{
		Token:             req.Token,
		LoginAfterLinking: req.LoginAfterLinking,
	})
	if err != nil {
		auth.WriteHTTPError(w, auth.OAuthHTTPError(err))
		return
	}
	if !result.LoggedIn {
		auth.WriteSuccess(w, http.StatusOK, nil)
		return
	}
	// This is the one route in the group that honours X-Auth-Strategy: it
	// answers with a body rather than a redirect, so sendTokens applies.
	a.cfg.WriteTokens(w, r, http.StatusOK, result.Tokens, nil)
}

// providerSegment reads the provider name out of the path.
func providerSegment(r *http.Request, prefix, head string) string {
	segments := pathSegmentsAfter(r, prefix, head)
	if len(segments) == 0 {
		return ""
	}
	return segments[0]
}

// pathSegmentsAfter returns the decoded path segments that follow
// <prefix>/<head> in the request path. It reads the escaped path and unescapes
// per segment so that a provider account id containing %2F cannot split into
// two parameters.
func pathSegmentsAfter(r *http.Request, prefix, head string) []string {
	marker := strings.TrimSuffix(prefix, "/") + "/" + head
	path := r.URL.EscapedPath()
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		return nil
	}
	rest := strings.Trim(path[idx+len(marker):], "/")
	if rest == "" {
		return nil
	}
	segments := strings.Split(rest, "/")
	for i, segment := range segments {
		if decoded, err := url.PathUnescape(segment); err == nil {
			segments[i] = decoded
		}
	}
	return segments
}
