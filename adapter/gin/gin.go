package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

const userContextKey = "awesome_go_auth_user"

// UserFromContext extracts authenticated user from gin.Context.
func UserFromContext(c *gin.Context) (auth.User, bool) {
	v, ok := c.Get(userContextKey)
	if !ok {
		return auth.User{}, false
	}
	user, ok := v.(auth.User)
	return user, ok
}

// Adapter serves the auth routes on Gin. Responses are written through the
// shared wire helpers rather than gin's own JSON writer so that every adapter
// emits byte-identical bodies and cookies.
type Adapter struct {
	auth *auth.Auth
	cfg  auth.HTTPConfig
}

// New returns a Gin adapter using the default wire conventions.
func New(a *auth.Auth) *Adapter {
	return NewWithConfig(a, auth.DefaultHTTPConfig())
}

// NewWithConfig returns a Gin adapter using the supplied wire conventions.
func NewWithConfig(a *auth.Auth, cfg auth.HTTPConfig) *Adapter {
	return &Adapter{auth: a, cfg: a.ResolveHTTPConfig(cfg)}
}

// Config reports the resolved wire conventions this adapter serves.
func (ad *Adapter) Config() auth.HTTPConfig { return ad.cfg }

// Middleware returns a Gin-native middleware.
func Middleware(a *auth.Auth) gin.HandlerFunc {
	return New(a).Middleware()
}

// Mount mounts all auth routes into a Gin RouterGroup.
func Mount(group gin.IRoutes, a *auth.Auth) {
	New(a).Mount(group)
}

// MountWithConfig mounts all auth routes using the supplied wire conventions.
func MountWithConfig(group gin.IRoutes, a *auth.Auth, cfg auth.HTTPConfig) {
	NewWithConfig(a, cfg).Mount(group)
}

// Middleware validates access tokens and injects the user into the context.
//
// It authenticates through Auth.VerifyAccess, which reads no user store, as
// the reference's authMiddleware does: the context user is built from the
// verified token plus the optional stores' enrichment, so a token whose user
// has been deleted reaches the handler, which answers for the missing user
// itself (#31). Config.BuildTokenClaims is a mint-time hook that must not run
// on every protected request. GET /me is the one route that runs it; see me.
func (ad *Adapter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := auth.AccessTokenFromRequest(c.Request)
		if token == "" {
			auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
			c.Abort()
			return
		}
		user, err := ad.auth.VerifyAccess(c.Request.Context(), token)
		if err != nil {
			auth.WriteHTTPError(c.Writer, auth.AccessHTTPError(err))
			c.Abort()
			return
		}
		c.Set(userContextKey, user)
		c.Next()
	}
}

// Mount attaches the auth endpoints.
//
// Under HTTPConfig.ResourceServer the credential routes are not registered at
// all — see mountCredentialRoutes and auth.ResourceServerGatedRoutes.
func (ad *Adapter) Mount(group gin.IRoutes) {
	prefix := ad.cfg.Prefix()
	// IdP mode: the JWKS document, mounted first and bare — no limiter, no CSRF,
	// no auth — because the reference registers it ahead of every middleware
	// (auth.router.ts:473-474), spreads no rate limiter onto it (:490), and
	// registers it only when an idProvider block is configured
	// (:473); here that condition is auth.WithIDP. HEAD is registered next to
	// GET because gin, unlike net/http and Express, does not fall back from one
	// to the other.
	if idp := ad.auth.IDP(); idp != nil {
		jwks := serveHTTP(ad.auth.JWKSHandler())
		group.GET(prefix+idp.JWKSPath(), jwks)
		group.HEAD(prefix+idp.JWKSPath(), jwks)
		// And the four OIDC endpoints beside it, from the same condition and on
		// the same terms: public, ahead of every middleware. group.Any, not a
		// list of methods, because these are mounted for every method — see
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
			if mount.ResourceServerGated && ad.cfg.ResourceServer {
				continue
			}
			group.Any(prefix+mount.Path, serveHTTP(mount.Handler))
		}
	}

	// The shared net/http adapter behind the two groups gin does not implement
	// itself: the UI config route below and the OAuth group at the bottom. One
	// adapter for both, because building a second would re-run
	// ResolveHTTPConfig on the same config and leave two of them to drift.
	h := nethttpadapter.NewWithConfig(ad.auth, ad.cfg)

	// The built-in UI, mounted only when it is enabled — the reference gates its
	// whole ui router on config.ui.enabled (auth.router.ts:1639-1648). Gin
	// serves the shared net/http handler for the whole subtree, as the reference
	// mounts one router there, and it arrives already wrapped in the CSRF
	// middleware.
	//
	// This is the adapter that decided the shape. Gin's tree will not hold a
	// catch-all beside a static sibling: registering "<prefix>/ui/*uipath" while
	// "<prefix>/ui/config" exists panics at mount time with "catch-all wildcard
	// conflicts with existing path segment 'config'", and registering them the
	// other way round panics too. Narrowing the catch-all to ":uipage" would
	// make it fit, at the price of a UI that serves one path segment and 404s on
	// <prefix>/ui/assets/logo/x.png. So the config route is not registered here
	// at all: h.UIHandler() answers it from inside the catch-all, with the same
	// handler the other three adapters reach through the same call. The
	// conformance suite replays the document against all four, which is what
	// makes "the same handler" a checked claim rather than an intention.
	//
	// Two patterns because gin's catch-all does not match the bare mount path:
	// with only the catch-all registered, "<prefix>/ui" is a 301 to the
	// trailing-slash form where Express serves the login page. HEAD is
	// registered next to GET because gin, unlike net/http and Express, does not
	// fall back from one to the other, and the static half of this router
	// answers HEAD.
	if ad.cfg.UI.Enabled {
		ui := serveHTTP(h.UIHandler())
		group.GET(prefix+auth.UIRoute, ui)
		group.HEAD(prefix+auth.UIRoute, ui)
		group.GET(prefix+auth.UIRoute+"/*uipath", ui)
		group.HEAD(prefix+auth.UIRoute+"/*uipath", ui)
	}

	if !ad.cfg.ResourceServer {
		ad.mountCredentialRoutes(group, prefix)
	}
	// /me authenticates itself (see me) rather than sitting behind Middleware,
	// so the token is verified once and the claims hook runs once.
	group.GET(prefix+"/me", ad.guard(ad.me))

	// Sessions and account management (account.go).
	group.GET(prefix+"/sessions", ad.guard(ad.Middleware()), ad.sessions)
	group.DELETE(prefix+"/sessions/:handle", ad.guard(ad.Middleware()), ad.revokeSession)
	group.POST(prefix+"/sessions/cleanup", ad.guard(ad.cleanupSessions))
	group.PATCH(prefix+"/profile", ad.guard(ad.Middleware()), ad.updateProfile)
	group.POST(prefix+"/add-phone", ad.guard(ad.Middleware()), ad.addPhone)
	group.DELETE(prefix+"/account", ad.guard(ad.Middleware()), ad.deleteAccount)

	// OAuth and account linking. Gin registers the routes with its own ":param"
	// syntax but serves the shared net/http handlers: the group's behaviour is
	// entirely path- and body-driven, so re-implementing it here would only
	// create somewhere for the adapters to drift.
	group.GET(prefix+"/oauth/:provider", serveHTTP(h.OAuthAuthorizeHandler()))
	group.GET(prefix+"/oauth/:provider/callback", serveHTTP(h.OAuthCallbackHandler()))
	group.GET(prefix+"/linked-accounts", serveHTTP(h.LinkedAccountsHandler()))
	// The unlink route is registered as a catch-all, not as two path parameters.
	// Gin matches on the UNESCAPED path, so a providerAccountId containing %2F —
	// which net/http, chi and echo all deliver to the handler intact, as Express
	// does — arrives here as three segments and would miss a two-parameter
	// pattern entirely, giving gin a 404 where every other adapter answers 200.
	// The shared handler reads its parameters off r.URL.EscapedPath() and rejects
	// any shape that is not exactly <provider>/<providerAccountId> with the same
	// bare 404 the other routers emit, so the catch-all widens what reaches the
	// handler without widening what the route answers. The bare :provider entry
	// is there to keep gin from answering a one-segment path with a 307 to the
	// catch-all's trailing slash.
	group.DELETE(prefix+"/linked-accounts/:provider", serveHTTP(h.UnlinkAccountHandler()))
	group.DELETE(prefix+"/linked-accounts/:provider/*providerAccountId", serveHTTP(h.UnlinkAccountHandler()))
	group.POST(prefix+"/link-request", serveHTTP(h.LinkRequestHandler()))
	group.POST(prefix+"/link-verify", serveHTTP(h.LinkVerifyHandler()))

	// Documentation, last: the reference registers both at the end of the
	// router (auth.router.ts:1656-1677) and only under its swagger option,
	// which is HTTPConfig.Docs.Enabled here. Neither route carries a guard of
	// its own there, but both sit after the router-level CSRF auto-init
	// (:529-538), so both go through the CSRF middleware here — the shared
	// net/http handlers (adapter/nethttp/docs.go) wrap themselves in it, as the
	// OAuth ones above do — and they come off the very same adapter h, which is
	// already resolved and in scope. HEAD is registered next to GET because
	// gin, unlike net/http and Express, does not fall back from one to the
	// other.
	if ad.cfg.Docs.Enabled {
		spec, ui := serveHTTP(h.OpenAPIHandler()), serveHTTP(h.SwaggerUIHandler())
		group.GET(prefix+auth.DocsSpecPath, spec)
		group.HEAD(prefix+auth.DocsSpecPath, spec)
		group.GET(prefix+auth.DocsUIPath, ui)
		group.HEAD(prefix+auth.DocsUIPath, ui)
	}

	// The admin console, mounted only when it is configured — Admin.Enabled and
	// an access decision, which is what HTTPConfig.AdminMounted reports. It
	// mounts at Admin.Path and not under prefix: the reference's admin router
	// is a sibling of the auth router, not a child (auth.AdminOptions).
	//
	// One shared net/http handler for the whole subtree, as for the UI, and two
	// patterns because gin's catch-all does not match the bare mount path.
	// group.Any rather than a method list: this router answers POST as well as
	// GET, and the handler itself 404s a method it does not serve. It carries
	// none of the auth router's middleware; adapter/nethttp/admin.go says why.
	if ad.cfg.AdminMounted() {
		admin := serveHTTP(h.AdminHandler())
		adminPath := ad.cfg.AdminPath()
		group.Any(adminPath, admin)
		group.Any(adminPath+"/*adminpath", admin)
	}

	// The tools router, mounted only when it is configured — Tools.Enabled, an
	// AuthTools to serve and an access decision, which is what
	// HTTPConfig.ToolsMounted reports. It mounts at Tools.Path and not under
	// prefix: the reference's createToolsRouter is a sibling of the auth router,
	// not a child (auth.ToolsOptions).
	//
	// One shared net/http handler for the whole subtree, as for the admin
	// console, and two patterns because gin's catch-all does not match the bare
	// mount path. group.Any rather than a method list: from U23 on this router
	// answers POST as well as GET, and the handler itself 404s a method it does
	// not serve. It carries none of the auth router's middleware;
	// adapter/nethttp/tools.go says why.
	if ad.cfg.ToolsMounted() {
		tools := serveHTTP(h.ToolsHandler())
		toolsPath := ad.cfg.ToolsPath()
		group.Any(toolsPath, tools)
		group.Any(toolsPath+"/*toolspath", tools)
	}
}

// mountCredentialRoutes registers the nineteen routes that create, prove,
// deliver or change a credential — auth.ResourceServerGatedRoutes, which is the
// same list and carries the reasoning. HTTPConfig.ResourceServer is the switch
// that skips this call.
func (ad *Adapter) mountCredentialRoutes(group gin.IRoutes, prefix string) {
	group.POST(prefix+"/register", ad.guard(ad.register))
	group.POST(prefix+"/login", ad.guard(ad.login))
	group.POST(prefix+"/refresh", ad.guard(ad.refresh))
	group.POST(prefix+"/logout", ad.guard(ad.logout))

	// Passwordless and 2FA (passwordless.go). The four send/verify routes are
	// unauthenticated by contract; the three enrolment routes sit behind the
	// access-token middleware and are therefore the only ones CSRF-checked.
	group.POST(prefix+"/magic-link/send", ad.guard(ad.magicLinkSend))
	group.POST(prefix+"/magic-link/verify", ad.guard(ad.magicLinkVerify))
	group.POST(prefix+"/sms/send", ad.guard(ad.smsSend))
	group.POST(prefix+"/sms/verify", ad.guard(ad.smsVerify))
	group.POST(prefix+"/2fa/setup", ad.guard(ad.Middleware()), ad.twoFactorSetup)
	group.POST(prefix+"/2fa/verify-setup", ad.guard(ad.Middleware()), ad.twoFactorVerifySetup)
	group.POST(prefix+"/2fa/verify", ad.guard(ad.twoFactorVerify))
	group.POST(prefix+"/2fa/disable", ad.guard(ad.Middleware()), ad.twoFactorDisable)
	// Password management and email verification (password_email.go).
	ad.mountPasswordEmail(group, prefix)
}

// serveHTTP adapts a net/http handler to gin. The handler is terminal, so
// there is no chain left to abort.
func serveHTTP(h http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) { h.ServeHTTP(c.Writer, c.Request) }
}

// guard runs the shared outer chain in front of a Gin handler: the
// event-context carrier, then the rate-limiter slot, then the CSRF middleware.
// Reusing the net/http middleware — rather than reimplementing it here — is
// what keeps the enforcement matrix identical across adapters.
//
// auth.EventContextMiddleware is outermost. It installs the correlation id,
// client address and User-Agent on the request context, and the request gin
// carries forward is the one it produced: the inner handler assigns c.Request =
// r before calling through, so every later ad.auth call that takes
// c.Request.Context() sees the carrier. Every adapter installs it, because an
// event plane that loses the correlation id on one router out of four is worse
// than none.
//
// The order is the reference's: it spreads its rate limiter onto each route
// ahead of the auth middleware and therefore ahead of the double-submit check
// (auth.router.ts:468, :656), so a refusal costs nothing downstream. A limiter
// that answers is a middleware that never calls through, which is the same
// short-circuit a CSRF refusal takes below. See auth.HTTPConfig.RateLimiter.
func (ad *Adapter) guard(h gin.HandlerFunc) gin.HandlerFunc {
	evctx := auth.EventContextMiddleware(ad.cfg)
	limit, csrf := auth.RateLimitMiddleware(ad.cfg), auth.CSRFMiddleware(ad.cfg)
	mw := func(next http.Handler) http.Handler { return evctx(limit(csrf(next))) }
	return func(c *gin.Context) {
		reached := false
		mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			reached = true
			c.Request = r
			h(c)
		})).ServeHTTP(c.Writer, c.Request)
		if !reached {
			// The middleware rejected the request and already wrote the body;
			// gin would otherwise run the rest of the chain on top of it.
			c.Abort()
		}
	}
}

func (ad *Adapter) register(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TenantID string `json:"tenantId"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	user, tokens, err := ad.auth.Register(c.Request.Context(), auth.RegisterInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	ad.cfg.WriteRegistration(c.Writer, c.Request, user.ID, tokens)
}

func (ad *Adapter) login(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TenantID string `json:"tenantId"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	if req.Email == "" || req.Password == "" {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrLoginCredentialsRequired)
		return
	}
	result, err := ad.auth.LoginWithChallenge(c.Request.Context(), auth.LoginInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	// A second factor is not a failure: the challenge is its own body, carrying the
	// tempToken the step-up routes need. See login_2fa.go.
	if result.Challenge != nil {
		auth.WriteTwoFactorChallenge(c.Writer, *result.Challenge)
		return
	}
	ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusOK, result.Tokens, nil)
}

func (ad *Adapter) refresh(c *gin.Context) {
	refresh := auth.RefreshTokenFromRequest(c.Request)
	if refresh == "" {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoRefreshToken)
		return
	}
	tokens, err := ad.auth.Refresh(c.Request.Context(), refresh)
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.RefreshHTTPError(err))
		return
	}
	ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusOK, tokens, nil)
}

func (ad *Adapter) logout(c *gin.Context) {
	ad.auth.LogoutRequest(c.Request.Context(), c.Request)
	ad.cfg.Cookies.ClearAuthCookies(c.Writer, ad.cfg.CSRF.Enabled)
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

// me authenticates through Auth.Me — the stored user plus Config.BuildTokenClaims
// — rather than reading the context user, because Middleware skips the hook and
// this body is the one place its result (customClaims) is rendered. A token that
// verifies for a user the store no longer has is 404 "User not found" (#31).
func (ad *Adapter) me(c *gin.Context) {
	token := auth.AccessTokenFromRequest(c.Request)
	if token == "" {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
		return
	}
	user, err := ad.auth.Me(c.Request.Context(), token)
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.AccessHTTPError(err))
		return
	}
	auth.WriteJSON(c.Writer, http.StatusOK, auth.NewPublicUser(user))
}
