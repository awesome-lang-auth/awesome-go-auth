package chi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	auth "github.com/nik2208/awesome-go-auth"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

// Middleware returns a Chi-compatible auth middleware.
func Middleware(a *auth.Auth) func(http.Handler) http.Handler {
	return nethttpadapter.Middleware(a)
}

// Mount mounts auth routes onto a Chi router.
func Mount(r chi.Router, a *auth.Auth) {
	MountWithConfig(r, a, auth.DefaultHTTPConfig())
}

// MountWithConfig mounts auth routes using the supplied wire conventions.
//
// Under HTTPConfig.ResourceServer the credential routes are not registered at
// all — see mountCredentialRoutes and auth.ResourceServerGatedRoutes.
func MountWithConfig(r chi.Router, a *auth.Auth, cfg auth.HTTPConfig) {
	h := nethttpadapter.NewWithConfig(a, cfg)
	resolved := h.Config()
	prefix := resolved.Prefix()
	// guard is the outer chain every auth route below carries, in the
	// reference's order: the rate-limiter slot first, then the CSRF middleware,
	// so a refused request never reaches the double-submit comparison or the
	// auth middleware (auth.router.ts:468, :656). With no limiter configured it
	// is the CSRF middleware alone. See auth.HTTPConfig.RateLimiter.
	//
	// Ahead of both sits auth.EventContextMiddleware, which installs the
	// correlation id, client address and User-Agent on the request context so
	// that anything publishing an event downstream can reach them. It is
	// outermost because it cannot refuse a request and the two below it can;
	// see that function. Every adapter installs it, because a carrier present on
	// three routers out of four would make an event's provenance depend on which
	// router the host chose.
	evctx := auth.EventContextMiddleware(resolved)
	limit, csrf := auth.RateLimitMiddleware(resolved), auth.CSRFMiddleware(resolved)
	guard := func(next http.Handler) http.Handler { return evctx(limit(csrf(next))) }

	// IdP mode: the JWKS document, mounted first and bare — no limiter, no CSRF,
	// no auth — because the reference registers it ahead of every middleware
	// (auth.router.ts:473-474), spreads no rate limiter onto it (:490), and
	// registers it only when an idProvider block is configured
	// (:473); here that condition is auth.WithIDP. HEAD is registered next to
	// GET because chi, unlike net/http and Express, does not fall back from one
	// to the other.
	if idp := a.IDP(); idp != nil {
		jwks := a.JWKSHandler()
		r.Method(http.MethodGet, prefix+idp.JWKSPath(), jwks)
		r.Method(http.MethodHead, prefix+idp.JWKSPath(), jwks)
		// And the four OIDC endpoints beside it, from the same condition and on
		// the same terms: public, ahead of every middleware. r.Handle, not
		// r.Method, because these are mounted for every method — see
		// auth.OIDCMounts. They are the endpoints (*auth.IDP).RegisterHandlers
		// mounts, at the same paths, served by the same handlers.
		//
		// Two of them — /authorize, which takes a password, and /token, which
		// mints this instance's session pair — carry ResourceServerGated and
		// are skipped under HTTPConfig.ResourceServer, for the same reason
		// mountCredentialRoutes is. The mount stays here rather than moving into
		// that block so the two that are not gated keep their place ahead of
		// every middleware.
		for _, mount := range idp.OIDCMounts() {
			if mount.ResourceServerGated && resolved.ResourceServer {
				continue
			}
			r.Handle(prefix+mount.Path, mount.Handler)
		}
	}

	// The built-in UI, mounted only when it is enabled — the reference gates its
	// whole ui router on config.ui.enabled (auth.router.ts:1639-1648). One
	// handler for the whole subtree, as there, and it arrives already wrapped in
	// the CSRF middleware, so it mounts with r.Method rather than
	// r.With(csrf).MethodFunc.
	//
	// Two patterns because chi's wildcard does not match the bare mount path,
	// where Express serves the login page. HEAD is registered next to GET
	// because chi, unlike net/http and Express, does not fall back from one to
	// the other, and the static half of this router answers HEAD.
	if resolved.UI.Enabled {
		ui := h.UIHandler()
		r.Method(http.MethodGet, prefix+auth.UIRoute, ui)
		r.Method(http.MethodHead, prefix+auth.UIRoute, ui)
		r.Method(http.MethodGet, prefix+auth.UIRoute+"/*", ui)
		r.Method(http.MethodHead, prefix+auth.UIRoute+"/*", ui)
	}

	if !resolved.ResourceServer {
		mountCredentialRoutes(r, h, guard, prefix)
	}
	// /me authenticates itself (nethttp's Me) rather than sitting behind the
	// auth middleware, so the claims hook runs once and the token is verified once.
	r.With(guard).MethodFunc(http.MethodGet, prefix+"/me", h.Me)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodGet, prefix+"/sessions", h.Sessions)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodDelete, prefix+"/sessions/{handle}", h.RevokeSession)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/sessions/cleanup", h.CleanupSessions)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPatch, prefix+"/profile", h.UpdateProfile)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/add-phone", h.AddPhone)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodDelete, prefix+"/account", h.DeleteAccount)

	// OAuth and account linking. These handlers arrive already wrapped in the
	// same guard — the rate-limiter slot outside the CSRF middleware — and,
	// where the route needs one, the auth middleware, so they mount with
	// r.Method rather than r.With(...).MethodFunc.
	r.Method(http.MethodGet, prefix+"/oauth/{provider}", h.OAuthAuthorizeHandler())
	r.Method(http.MethodGet, prefix+"/oauth/{provider}/callback", h.OAuthCallbackHandler())
	r.Method(http.MethodGet, prefix+"/linked-accounts", h.LinkedAccountsHandler())
	r.Method(http.MethodDelete, prefix+"/linked-accounts/{provider}/{providerAccountId}", h.UnlinkAccountHandler())
	r.Method(http.MethodPost, prefix+"/link-request", h.LinkRequestHandler())
	r.Method(http.MethodPost, prefix+"/link-verify", h.LinkVerifyHandler())

	// Documentation, last: the reference registers both at the end of the
	// router (auth.router.ts:1656-1677) and only under its swagger option,
	// which is HTTPConfig.Docs.Enabled here. Neither route carries a guard of
	// its own there, but both sit after the router-level CSRF auto-init
	// (:529-538), so both go through the CSRF middleware here — the shared
	// net/http handlers wrap themselves in it, as the OAuth ones do. HEAD is
	// registered next to GET because chi, unlike net/http and Express, does not
	// fall back from one to the other.
	if resolved.Docs.Enabled {
		spec, ui := h.OpenAPIHandler(), h.SwaggerUIHandler()
		r.Method(http.MethodGet, prefix+auth.DocsSpecPath, spec)
		r.Method(http.MethodHead, prefix+auth.DocsSpecPath, spec)
		r.Method(http.MethodGet, prefix+auth.DocsUIPath, ui)
		r.Method(http.MethodHead, prefix+auth.DocsUIPath, ui)
	}

	// The admin console, mounted only when it is configured — Admin.Enabled and
	// an access decision, which is what HTTPConfig.AdminMounted reports. It
	// mounts at Admin.Path and not under prefix: the reference's admin router
	// is a sibling of the auth router, not a child (auth.AdminOptions).
	//
	// One shared net/http handler for the whole subtree, as for the UI, and two
	// patterns because chi's wildcard does not match the bare mount path.
	// r.Handle rather than r.Method: this router answers POST as well as GET,
	// and the handler itself 404s a method it does not serve. It carries none
	// of the auth router's middleware; adapter/nethttp/admin.go says why.
	if resolved.AdminMounted() {
		admin := h.AdminHandler()
		adminPath := resolved.AdminPath()
		r.Handle(adminPath, admin)
		r.Handle(adminPath+"/*", admin)
	}

	// The tools router, mounted only when it is configured — Tools.Enabled, an
	// AuthTools to serve and an access decision, which is what
	// HTTPConfig.ToolsMounted reports. It mounts at Tools.Path and not under
	// prefix: the reference's createToolsRouter is a sibling of the auth router,
	// not a child (auth.ToolsOptions).
	//
	// One shared net/http handler for the whole subtree, as for the admin
	// console, and two patterns because chi's wildcard does not match the bare
	// mount path. r.Handle rather than r.Method: from U23 on this router answers
	// POST as well as GET, and the handler itself 404s a method it does not
	// serve. It carries none of the auth router's middleware;
	// adapter/nethttp/tools.go says why.
	if resolved.ToolsMounted() {
		tools := h.ToolsHandler()
		toolsPath := resolved.ToolsPath()
		r.Handle(toolsPath, tools)
		r.Handle(toolsPath+"/*", tools)
	}
}

// mountCredentialRoutes registers the twenty routes that create, prove,
// deliver or change a credential — auth.ResourceServerGatedRoutes, which is the
// same list and carries the reasoning. HTTPConfig.ResourceServer is the switch
// that skips this call.
func mountCredentialRoutes(r chi.Router, h *nethttpadapter.Adapter, guard func(http.Handler) http.Handler, prefix string) {
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/register", h.Register)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/login", h.Login)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/refresh", h.Refresh)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/logout", h.Logout)
	// Passwordless and 2FA. Chi serves the net/http handlers unchanged, so the
	// only chi-specific part is the registration.
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/magic-link/send", h.MagicLinkSend)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/magic-link/verify", h.MagicLinkVerify)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/sms/send", h.SMSSend)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/sms/verify", h.SMSVerify)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/2fa/setup", h.TwoFactorSetup)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/2fa/verify-setup", h.TwoFactorVerifySetup)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/2fa/verify", h.TwoFactorVerify)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/2fa/disable", h.TwoFactorDisable)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+auth.StepUpRoute, h.TwoFactorStepUp)
	// Password management and email verification (wire-contract §2).
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/forgot-password", h.ForgotPassword)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/reset-password", h.ResetPassword)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/change-password", h.ChangePassword)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/send-verification-email", h.SendVerificationEmail)
	r.With(guard).MethodFunc(http.MethodGet, prefix+"/verify-email", h.VerifyEmail)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/change-email/request", h.ChangeEmailRequest)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/change-email/confirm", h.ChangeEmailConfirm)
}
