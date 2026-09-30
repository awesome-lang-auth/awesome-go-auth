package echo

import (
	"net/http"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

const userContextKey = "awesome_go_auth_user"

// UserFromContext extracts authenticated user from echo.Context.
func UserFromContext(c echo.Context) (auth.User, bool) {
	v := c.Get(userContextKey)
	if v == nil {
		return auth.User{}, false
	}
	user, ok := v.(auth.User)
	return user, ok
}

// Adapter serves the auth routes on Echo. Responses are written through the
// shared wire helpers rather than echo's own JSON writer so that every adapter
// emits byte-identical bodies and cookies.
type Adapter struct {
	auth *auth.Auth
	cfg  auth.HTTPConfig
}

// New returns an Echo adapter using the default wire conventions.
func New(a *auth.Auth) *Adapter {
	return NewWithConfig(a, auth.DefaultHTTPConfig())
}

// NewWithConfig returns an Echo adapter using the supplied wire conventions.
func NewWithConfig(a *auth.Auth, cfg auth.HTTPConfig) *Adapter {
	return &Adapter{auth: a, cfg: a.ResolveHTTPConfig(cfg)}
}

// Config reports the resolved wire conventions this adapter serves.
func (ad *Adapter) Config() auth.HTTPConfig { return ad.cfg }

// Middleware returns an Echo-native middleware.
func Middleware(a *auth.Auth) echo.MiddlewareFunc {
	return New(a).Middleware()
}

// Mount mounts auth routes on an Echo group.
func Mount(group *echo.Group, a *auth.Auth) {
	New(a).Mount(group)
}

// MountWithConfig mounts auth routes using the supplied wire conventions.
func MountWithConfig(group *echo.Group, a *auth.Auth, cfg auth.HTTPConfig) {
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
func (ad *Adapter) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := auth.AccessTokenFromRequest(c.Request())
			if token == "" {
				auth.WriteHTTPError(c.Response(), auth.HTTPErrNoAccessToken)
				return nil
			}
			user, err := ad.auth.VerifyAccess(c.Request().Context(), token)
			if err != nil {
				auth.WriteHTTPError(c.Response(), auth.AccessHTTPError(err))
				return nil
			}
			c.Set(userContextKey, user)
			return next(c)
		}
	}
}

// Mount attaches the auth endpoints.
//
// Under HTTPConfig.ResourceServer the credential routes are not registered at
// all — see mountCredentialRoutes and auth.ResourceServerGatedRoutes.
func (ad *Adapter) Mount(group *echo.Group) {
	prefix := ad.cfg.Prefix()
	// IdP mode: the JWKS document, mounted first and bare — no limiter, no CSRF,
	// no auth — because the reference registers it ahead of every middleware
	// (auth.router.ts:473-474), spreads no rate limiter onto it (:490), and
	// registers it only when an idProvider block is configured
	// (:473); here that condition is auth.WithIDP. HEAD is registered next to
	// GET because echo, unlike net/http and Express, does not fall back from one
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

	// The shared net/http adapter behind the two groups echo does not implement
	// itself: the UI config route below and the OAuth group at the bottom. One
	// adapter for both, because building a second would re-run
	// ResolveHTTPConfig on the same config and leave two of them to drift.
	h := nethttpadapter.NewWithConfig(ad.auth, ad.cfg)

	// The built-in UI, mounted only when it is enabled — the reference gates its
	// whole ui router on config.ui.enabled (auth.router.ts:1639-1648). Echo
	// serves the shared net/http handler for the whole subtree, as the reference
	// mounts one router there, and it arrives already wrapped in the CSRF
	// middleware.
	//
	// Two patterns because echo's wildcard does not match the bare mount path,
	// where Express serves the login page. HEAD is registered next to GET
	// because echo, unlike net/http and Express, does not fall back from one to
	// the other, and the static half of this router answers HEAD.
	if ad.cfg.UI.Enabled {
		ui := serveHTTP(h.UIHandler())
		group.GET(prefix+auth.UIRoute, ui)
		group.HEAD(prefix+auth.UIRoute, ui)
		group.GET(prefix+auth.UIRoute+"/*", ui)
		group.HEAD(prefix+auth.UIRoute+"/*", ui)
	}

	if !ad.cfg.ResourceServer {
		ad.mountCredentialRoutes(group, prefix)
	}
	// /me authenticates itself (see me) rather than sitting behind Middleware,
	// so the token is verified once and the claims hook runs once.
	group.GET(prefix+"/me", ad.guard(ad.me))

	// Sessions and account management (account.go).
	group.GET(prefix+"/sessions", ad.guard(ad.Middleware()(ad.sessions)))
	group.DELETE(prefix+"/sessions/:handle", ad.guard(ad.Middleware()(ad.revokeSession)))
	group.POST(prefix+"/sessions/cleanup", ad.guard(ad.cleanupSessions))
	group.PATCH(prefix+"/profile", ad.guard(ad.Middleware()(ad.updateProfile)))
	group.POST(prefix+"/add-phone", ad.guard(ad.Middleware()(ad.addPhone)))
	group.DELETE(prefix+"/account", ad.guard(ad.Middleware()(ad.deleteAccount)))

	// OAuth and account linking. Echo registers the routes with its own
	// ":param" syntax but serves the shared net/http handlers: the group's
	// behaviour is entirely path- and body-driven, so re-implementing it here
	// would only create somewhere for the adapters to drift.
	group.GET(prefix+"/oauth/:provider", serveHTTP(h.OAuthAuthorizeHandler()))
	group.GET(prefix+"/oauth/:provider/callback", serveHTTP(h.OAuthCallbackHandler()))
	group.GET(prefix+"/linked-accounts", serveHTTP(h.LinkedAccountsHandler()))
	group.DELETE(prefix+"/linked-accounts/:provider/:providerAccountId", serveHTTP(h.UnlinkAccountHandler()))
	group.POST(prefix+"/link-request", serveHTTP(h.LinkRequestHandler()))
	group.POST(prefix+"/link-verify", serveHTTP(h.LinkVerifyHandler()))

	// Documentation, last: the reference registers both at the end of the
	// router (auth.router.ts:1656-1677) and only under its swagger option,
	// which is HTTPConfig.Docs.Enabled here. Neither route carries a guard of
	// its own there, but both sit after the router-level CSRF auto-init
	// (:529-538), so both go through the CSRF middleware here — the shared
	// net/http handlers (adapter/nethttp/docs.go) wrap themselves in it, as the
	// OAuth ones above do, and they come off the very same adapter h, which is
	// already resolved and in scope. HEAD is registered next to GET because
	// echo, unlike net/http and Express, does not fall back from one to the
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
	// patterns because echo's wildcard does not match the bare mount path.
	// group.Any rather than a method list: this router answers POST as well as
	// GET, and the handler itself 404s a method it does not serve. It carries
	// none of the auth router's middleware; adapter/nethttp/admin.go says why.
	if ad.cfg.AdminMounted() {
		admin := serveHTTP(h.AdminHandler())
		adminPath := ad.cfg.AdminPath()
		group.Any(adminPath, admin)
		group.Any(adminPath+"/*", admin)
	}

	// The tools router, mounted only when it is configured — Tools.Enabled, an
	// AuthTools to serve and an access decision, which is what
	// HTTPConfig.ToolsMounted reports. It mounts at Tools.Path and not under
	// prefix: the reference's createToolsRouter is a sibling of the auth router,
	// not a child (auth.ToolsOptions).
	//
	// One shared net/http handler for the whole subtree, as for the admin
	// console, and two patterns because echo's wildcard does not match the bare
	// mount path. group.Any rather than a method list: from U23 on this router
	// answers POST as well as GET, and the handler itself 404s a method it does
	// not serve. It carries none of the auth router's middleware;
	// adapter/nethttp/tools.go says why.
	if ad.cfg.ToolsMounted() {
		tools := serveHTTP(h.ToolsHandler())
		toolsPath := ad.cfg.ToolsPath()
		group.Any(toolsPath, tools)
		group.Any(toolsPath+"/*", tools)
	}
}

// mountCredentialRoutes registers the nineteen routes that create, prove,
// deliver or change a credential — auth.ResourceServerGatedRoutes, which is the
// same list and carries the reasoning. HTTPConfig.ResourceServer is the switch
// that skips this call.
func (ad *Adapter) mountCredentialRoutes(group *echo.Group, prefix string) {
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
	group.POST(prefix+"/2fa/setup", ad.guard(ad.Middleware()(ad.twoFactorSetup)))
	group.POST(prefix+"/2fa/verify-setup", ad.guard(ad.Middleware()(ad.twoFactorVerifySetup)))
	group.POST(prefix+"/2fa/verify", ad.guard(ad.twoFactorVerify))
	group.POST(prefix+"/2fa/disable", ad.guard(ad.Middleware()(ad.twoFactorDisable)))
	// Password management and email verification (password_email.go).
	ad.mountPasswordEmail(group, prefix)
}

// serveHTTP adapts a net/http handler to echo. The handler writes the whole
// response, so there is nothing left for echo to render.
func serveHTTP(h http.Handler) echo.HandlerFunc {
	return func(c echo.Context) error {
		h.ServeHTTP(c.Response(), c.Request())
		return nil
	}
}

// guard runs the shared outer chain in front of an Echo handler: the
// event-context carrier, then the rate-limiter slot, then the CSRF middleware.
// Reusing the net/http middleware — rather than reimplementing it here — is
// what keeps the enforcement matrix identical across adapters.
//
// auth.EventContextMiddleware is outermost. It installs the correlation id,
// client address and User-Agent on the request context, and the request echo
// carries forward is the one it produced: the inner handler calls c.SetRequest(r)
// before calling through, so every later ad.auth call that takes
// c.Request().Context() sees the carrier. Every adapter installs it, because an
// event plane that loses the correlation id on one router out of four is worse
// than none.
//
// The order is the reference's: it spreads its rate limiter onto each route
// ahead of the auth middleware and therefore ahead of the double-submit check
// (auth.router.ts:468, :656), so a refusal costs nothing downstream. A limiter
// that answers never calls through, so h never runs and err stays nil — the
// response the limiter wrote is the whole response, exactly as for a CSRF
// refusal. See auth.HTTPConfig.RateLimiter.
func (ad *Adapter) guard(h echo.HandlerFunc) echo.HandlerFunc {
	evctx := auth.EventContextMiddleware(ad.cfg)
	limit, csrf := auth.RateLimitMiddleware(ad.cfg), auth.CSRFMiddleware(ad.cfg)
	mw := func(next http.Handler) http.Handler { return evctx(limit(csrf(next))) }
	return func(c echo.Context) error {
		var err error
		mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			c.SetRequest(r)
			err = h(c)
		})).ServeHTTP(c.Response(), c.Request())
		return err
	}
}

func (ad *Adapter) register(c echo.Context) error {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TenantID string `json:"tenantId"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	user, tokens, err := ad.auth.Register(c.Request().Context(), auth.RegisterInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	ad.cfg.WriteTokens(c.Response(), c.Request(), http.StatusCreated, tokens, map[string]any{"userId": user.ID})
	return nil
}

func (ad *Adapter) login(c echo.Context) error {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TenantID string `json:"tenantId"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	if req.Email == "" || req.Password == "" {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrLoginCredentialsRequired)
		return nil
	}
	result, err := ad.auth.LoginWithChallenge(c.Request().Context(), auth.LoginInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	// A second factor is not a failure: the challenge is its own body, carrying the
	// tempToken the step-up routes need. See login_2fa.go.
	if result.Challenge != nil {
		auth.WriteTwoFactorChallenge(c.Response(), *result.Challenge)
		return nil
	}
	ad.cfg.WriteTokens(c.Response(), c.Request(), http.StatusOK, result.Tokens, nil)
	return nil
}

func (ad *Adapter) refresh(c echo.Context) error {
	refresh := auth.RefreshTokenFromRequest(c.Request())
	if refresh == "" {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrNoRefreshToken)
		return nil
	}
	tokens, err := ad.auth.Refresh(c.Request().Context(), refresh)
	if err != nil {
		auth.WriteHTTPError(c.Response(), auth.RefreshHTTPError(err))
		return nil
	}
	ad.cfg.WriteTokens(c.Response(), c.Request(), http.StatusOK, tokens, nil)
	return nil
}

func (ad *Adapter) logout(c echo.Context) error {
	ad.auth.LogoutRequest(c.Request().Context(), c.Request())
	ad.cfg.Cookies.ClearAuthCookies(c.Response(), ad.cfg.CSRF.Enabled)
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

// me authenticates through Auth.Me — the stored user plus Config.BuildTokenClaims
// — rather than reading the context user, because Middleware skips the hook and
// this body is the one place its result (customClaims) is rendered. A token that
// verifies for a user the store no longer has is 404 "User not found" (#31).
func (ad *Adapter) me(c echo.Context) error {
	token := auth.AccessTokenFromRequest(c.Request())
	if token == "" {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrNoAccessToken)
		return nil
	}
	user, err := ad.auth.Me(c.Request().Context(), token)
	if err != nil {
		auth.WriteHTTPError(c.Response(), auth.AccessHTTPError(err))
		return nil
	}
	auth.WriteJSON(c.Response(), http.StatusOK, auth.NewPublicUser(user))
	return nil
}
