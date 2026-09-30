package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Auth is the top-level entrypoint configured with functional options.
type Auth struct {
	service *Service
	// oauth is nil unless WithOAuth was supplied; see oauth_wire.go.
	oauth *OAuthWiring
	// idp is nil unless WithIDP was supplied. It is what makes the adapters
	// mount the JWKS route and the four OIDC endpoints; see JWKSHandler and
	// (*IDP).OIDCMounts.
	idp *IDP
	// apiKeys and webhooks are nil unless WithAPIKeyStore and WithWebhookStore
	// were supplied. Nothing in the Service reads either — an API key
	// authenticates through APIKeyMiddleware, which is handed its store
	// directly, and outgoing webhooks are the AuthTools facade's — so they sit
	// here beside oauth rather than on Config: they are wiring the routers read,
	// and the routers that read them are the admin console's credential half
	// (admin_credentials.go) and the feature flags in front of it.
	apiKeys  APIKeyStore
	webhooks WebhookStore
}

// Option configures Auth initialization.
type Option func(*authBuilder) error

type authBuilder struct {
	cfg      Config
	users    UserStore
	sessions SessionStore
	svcOpts  []ServiceOption
	oauth    *OAuthWiring
	idp      *IDP
	apiKeys  APIKeyStore
	webhooks WebhookStore
}

// New creates a configured Auth instance from the package defaults.
func New(opts ...Option) (*Auth, error) {
	return NewWithConfig(DefaultConfig("01234567890123456789012345678901"), opts...)
}

// NewWithConfig creates a configured Auth instance from a pre-populated Config,
// with any Options applied in order on top of it.
//
// New builds its Config internally and the exported Option set has always been
// narrower than Config, so fields with no matching Option — the individual TTLs,
// EmailVerificationMode, and until now BcryptCost — were unreachable from
// outside the package (#25). Accepting the struct closes that whole class of gap
// at once and cannot drift as Config grows, which one-Option-per-field would.
// The Options remain as sugar and still compose with a supplied Config.
//
// cfg is validated by NewService exactly as New's is; a hand-built Config that
// omits, say, the TTLs is rejected rather than silently defaulted.
func NewWithConfig(cfg Config, opts ...Option) (*Auth, error) {
	b := &authBuilder{cfg: cfg}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(b); err != nil {
			return nil, err
		}
	}
	if b.users == nil {
		b.users = NewMemoryUserStore()
	}
	if b.sessions == nil {
		b.sessions = NewMemorySessionStore()
	}
	svc, err := NewService(b.cfg, b.users, b.sessions, b.svcOpts...)
	if err != nil {
		return nil, err
	}
	// An IdP built with a nil Service — the only order a host can write, since
	// the Service does not exist until here — adopts this one. One already bound
	// to a different Service is refused rather than silently adopted or silently
	// left alone: either way its /token and /userinfo would read a different
	// user store from this Auth's, and rebinding one that is already serving
	// requests is a data race besides. See WithIDP.
	if b.idp != nil {
		if b.idp.authSvc != nil && b.idp.authSvc != svc {
			return nil, errors.New("auth: WithIDP: the IDP is already bound to another Service")
		}
		b.idp.authSvc = svc
	}
	return &Auth{
		service:  svc,
		oauth:    b.oauth,
		idp:      b.idp,
		apiKeys:  b.apiKeys,
		webhooks: b.webhooks,
	}, nil
}

// Service exposes the configured core service.
func (a *Auth) Service() *Service { return a.service }

// IDP reports the Identity Provider WithIDP configured, or nil. The adapters
// consult it to decide whether to mount the JWKS route and where, and to walk
// OIDCMounts for the four OIDC endpoints.
func (a *Auth) IDP() *IDP { return a.idp }

// JWKSHandler returns the handler serving the IdP's JWKS document with the
// reference's headers, or nil when no WithIDP was given: the same handler the
// adapters mount at <prefix><IDPConfig.JWKSPath>. See (*IDP).JWKSHandler.
//
// A host mounting it itself must keep it public and ahead of any middleware,
// as the reference does (auth.router.ts:473-474): a relying party fetches the
// document with no credential of any kind.
func (a *Auth) JWKSHandler() http.Handler {
	if a.idp == nil {
		return nil
	}
	return a.idp.JWKSHandler()
}

// WithSecret configures the JWT signing secret.
func WithSecret(secret string) Option {
	return func(b *authBuilder) error {
		b.cfg.Secret = secret
		return nil
	}
}

// WithRefreshSecret sets the key refresh tokens are signed and verified with,
// the reference's refreshTokenSecret. See Config.RefreshSecret: omitted, refresh
// tokens stay on the WithSecret key, as they were before this Option existed.
//
// Unlike the zero value of Config.RefreshSecret, which means "unset" and falls
// back to Config.Secret, calling this Option with an empty or short secret is
// an error: an explicit setter reached with an unset value is a caller mistake,
// not a request for the fallback. Omit the Option to get the fallback.
func WithRefreshSecret(secret string) Option {
	return func(b *authBuilder) error {
		if len(secret) < 32 {
			return errors.New("auth: refresh secret must be at least 32 chars; omit WithRefreshSecret to sign refresh tokens with the secret")
		}
		b.cfg.RefreshSecret = secret
		return nil
	}
}

// WithIssuer configures token issuer.
func WithIssuer(issuer string) Option {
	return func(b *authBuilder) error {
		b.cfg.Issuer = issuer
		return nil
	}
}

// WithTokenTTLs configures access and refresh TTL.
func WithTokenTTLs(access, refresh time.Duration) Option {
	return func(b *authBuilder) error {
		if access <= 0 || refresh <= 0 {
			return errors.New("auth: ttl must be > 0")
		}
		b.cfg.AccessTokenTTL = access
		b.cfg.RefreshTokenTTL = refresh
		return nil
	}
}

// WithBcryptCost sets the bcrypt cost used for every password hash the library
// writes. See Config.BcryptCost.
//
// Unlike the zero value of Config.BcryptCost, which means "unset" and resolves
// to bcrypt.DefaultCost, calling this Option with 0 is an error: an explicit
// setter reached with an unset value is a caller mistake, not a request for the
// default. Omit the Option to get the default.
func WithBcryptCost(cost int) Option {
	return func(b *authBuilder) error {
		if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
			// The remedy has to be in the message. An operator who reaches this
			// with an unparsed or unset value sees only a rejected range, and
			// the cheapest way out of a rejected range is to pass MinCost —
			// which is the one outcome this whole change exists to prevent.
			return fmt.Errorf("auth: bcrypt cost must be between %d and %d; omit WithBcryptCost to get the default (%d)", bcrypt.MinCost, bcrypt.MaxCost, bcrypt.DefaultCost)
		}
		b.cfg.BcryptCost = cost
		return nil
	}
}

// WithUserStore sets a custom UserStore implementation.
func WithUserStore(store UserStore) Option {
	return func(b *authBuilder) error {
		if store == nil {
			return errors.New("auth: user store is required")
		}
		b.users = store
		return nil
	}
}

// WithSessionStore sets a custom SessionStore implementation.
func WithSessionStore(store SessionStore) Option {
	return func(b *authBuilder) error {
		if store == nil {
			return errors.New("auth: session store is required")
		}
		b.sessions = store
		return nil
	}
}

// WithMetadataProvider wires optional metadata support.
func WithMetadataProvider(store UserMetadataStore) Option {
	return func(b *authBuilder) error {
		b.svcOpts = append(b.svcOpts, WithMetadataStore(store))
		return nil
	}
}

// WithRBACProvider wires optional role/permission support.
func WithRBACProvider(store RolesPermissionsStore) Option {
	return func(b *authBuilder) error {
		b.svcOpts = append(b.svcOpts, WithRolesPermissionsStore(store))
		return nil
	}
}

// WithTenantProvider wires optional tenant support.
func WithTenantProvider(store TenantStore) Option {
	return func(b *authBuilder) error {
		b.svcOpts = append(b.svcOpts, WithTenantStore(store))
		return nil
	}
}

// WithRequire2FA enables mandatory second-factor login checks.
func WithRequire2FA(enabled bool) Option {
	return func(b *authBuilder) error {
		b.cfg.Require2FA = enabled
		return nil
	}
}

// WithTwoFactorAppName sets Config.TwoFactorAppName: the issuer an
// authenticator app shows for a TOTP enrolment made through POST
// <prefix>/2fa/setup. It is the reference's `twoFactor.appName`.
//
//	auth.WithTwoFactorAppName("Example App")
//
// Left unset, the URI carries Config.Issuer, as it always has — see
// Config.TwoFactorAppName. Passing "" is the same as not calling it.
func WithTwoFactorAppName(name string) Option {
	return func(b *authBuilder) error {
		b.cfg.TwoFactorAppName = name
		return nil
	}
}

// WithTokenClaimsBuilder customizes token claims creation. The hook may add
// claims and override the six base claims; the session claims (sid, tid, jti,
// typ, iss, iat, exp) are reserved and cannot be set from it — see
// Config.BuildTokenClaims.
//
// TokenClaimsBuilder is an alias of the func type this always took, so a
// literal still satisfies it; StaticClaims, UserFieldClaims, ChainClaims and
// (*ClaimsWebhook).Build are ready-made ones (claims.go, claims_webhook.go).
func WithTokenClaimsBuilder(fn TokenClaimsBuilder) Option {
	return func(b *authBuilder) error {
		b.cfg.BuildTokenClaims = fn
		return nil
	}
}

// WithPasswordVerifier sets Config.PasswordVerifier, the migration seam: the
// hook POST <prefix>/login consults for a user whose stored hash did not verify
// the supplied password, so a deployment can accept the password its previous
// identity provider held, adopt it as a local hash and drop the dependency.
//
//	auth.WithPasswordVerifier(func(ctx context.Context, u auth.User, pw string) (bool, bool, error) {
//		if u.Metadata["legacyIdP"] != "acme" {
//			return false, false, nil
//		}
//		ok, err := acme.CheckPassword(ctx, u.Email, pw)
//		return ok, ok, err
//	})
//
// The marker check on the first line of that example is a requirement, not
// decoration: the hook is reached for every account whose stored hash does not
// verify, including OAuth-only and magic-link-only accounts that never had a
// password, and it is reached from an unauthenticated route. See
// PasswordVerifier, which also explains why adopting a password overwrites
// whatever hash was stored.
//
// It is an additive port extension: the reference verifies bcrypt directly on
// its login path and has no such hook (local.strategy.ts:19-29). Omitting this
// Option is the reference's behaviour. Passing nil is refused, in the style of
// the sender Options: an explicit setter reached with nothing to set is a
// caller mistake, not a request to turn the seam off.
func WithPasswordVerifier(verify PasswordVerifier) Option {
	return func(b *authBuilder) error {
		if verify == nil {
			return errors.New("auth: password verifier is required")
		}
		b.cfg.PasswordVerifier = verify
		return nil
	}
}

// WithMagicLinkSender wires magic-link delivery. Without it POST
// <prefix>/magic-link/send answers 500 EMAIL_NOT_CONFIGURED, because the route
// cannot put the link in its response body.
//
// Pass a callback to send the mail yourself, or MagicLinkMailer.Send to use the
// built-in templates over a MailerTransport.
func WithMagicLinkSender(sender MagicLinkSender) Option {
	return func(b *authBuilder) error {
		if sender == nil {
			return errors.New("auth: magic link sender is required")
		}
		b.cfg.SendMagicLink = sender
		return nil
	}
}

// WithSMSCodeSender wires SMS delivery. Without it POST <prefix>/sms/send
// answers 500 SMS_NOT_CONFIGURED.
//
// Pass a callback to send the message yourself, or SMSTransportSender over an
// SMSTransport such as HTTPSMSTransport.
func WithSMSCodeSender(sender SMSCodeSender) Option {
	return func(b *authBuilder) error {
		if sender == nil {
			return errors.New("auth: sms code sender is required")
		}
		b.cfg.SendSMSCode = sender
		return nil
	}
}

// WithPasswordResetSender wires password-reset delivery for POST
// <prefix>/forgot-password. Without it the route still answers 200
// {"success":true} and mails nothing, which is what a reference deployment with
// no email block does — see delivery_password_email.go.
//
// Pass a callback to send the mail yourself, or PasswordResetMailer.Send to use
// the built-in password-reset template over a MailerTransport.
func WithPasswordResetSender(sender PasswordResetSender) Option {
	return func(b *authBuilder) error {
		if sender == nil {
			return errors.New("auth: password reset sender is required")
		}
		b.cfg.SendPasswordReset = sender
		return nil
	}
}

// WithEmailVerificationSender wires verification delivery for POST
// <prefix>/send-verification-email. Without it the route mails nothing and still
// answers 200.
//
// Pass a callback, or EmailVerificationMailer.Send for the built-in verify-email
// template.
func WithEmailVerificationSender(sender EmailVerificationSender) Option {
	return func(b *authBuilder) error {
		if sender == nil {
			return errors.New("auth: email verification sender is required")
		}
		b.cfg.SendEmailVerification = sender
		return nil
	}
}

// WithEmailChangeSender wires delivery for POST <prefix>/change-email/request.
// The message goes to the *new* address: it is a verification of the new mailbox.
// Without it the route mails nothing and still answers 200.
//
// Pass a callback, or EmailChangeMailer.Send for the built-in verify-email
// template, which is what the reference mails here.
func WithEmailChangeSender(sender EmailChangeSender) Option {
	return func(b *authBuilder) error {
		if sender == nil {
			return errors.New("auth: email change sender is required")
		}
		b.cfg.SendEmailChange = sender
		return nil
	}
}

// WithEmailChangedSender wires the notice POST <prefix>/change-email/confirm
// mails to the OLD address once the change is applied — the reference's
// config.email.sendEmailChanged (auth.router.ts:1060-1066). Without it the route
// mails nothing and still answers 200. A failing sender answers the generic 500
// with the change already committed, as the reference does.
//
// Pass a callback, or EmailChangedMailer.Send for the built-in email-changed
// template.
func WithEmailChangedSender(sender EmailChangedSender) Option {
	return func(b *authBuilder) error {
		if sender == nil {
			return errors.New("auth: email changed sender is required")
		}
		b.cfg.SendEmailChanged = sender
		return nil
	}
}

// WithTemplateStore sets Config.Templates: the store whose mail templates
// override the built-ins for every ready-made mailer the service calls — the
// reference's config.templateStore (mailer.service.ts:146, 156-179). See
// TemplateStore and MailTemplater.RenderMail for the rendering rule.
//
//	store := auth.NewMemoryTemplateStore()
//	auth.WithTemplateStore(store)
func WithTemplateStore(store TemplateStore) Option {
	return func(b *authBuilder) error {
		if store == nil {
			return errors.New("auth: template store is required")
		}
		b.cfg.Templates = store
		return nil
	}
}

// WithUploadStore sets Config.Uploads: the store the admin console's upload
// routes write through and the built-in UI serves uploaded assets back from —
// the seam over the reference's uploadDir (admin.router.ts:135).
//
// One store wires both halves. With it set, POST <admin>/api/upload/logo and its
// three siblings are registered, the console's upload feature flag turns on, and
// <prefix>/ui/assets/logo/ and <prefix>/ui/assets/uploads/ serve what was
// uploaded — the last of those without setting UIOptions.Uploads, which stays as
// the override for a host that wants the read side to come from somewhere else.
//
//	store := auth.NewMemoryUploadStore()
//	a, err := auth.New(auth.WithUploadStore(store))
//
// MemoryUploadStore keeps everything in process memory and is for tests and
// single-process deployments; a deployment that must not lose an uploaded logo
// supplies its own. See UploadStore for the contract, and ValidUploadKey for the
// one rule an implementation has to honour.
func WithUploadStore(store UploadStore) Option {
	return func(b *authBuilder) error {
		if store == nil {
			return errors.New("auth: upload store is required")
		}
		b.cfg.Uploads = store
		return nil
	}
}

// WithSettingsStore sets Config.Settings: the store holding the global runtime
// settings an administrator flips — the reference's routerOptions.settingsStore
// (auth.router.ts:92). Only AuthSettings.Require2FA is acted on, by
// POST <prefix>/2fa/disable; see SettingsStore for what the rest is for.
//
//	store := auth.NewMemorySettingsStore()
//	required := true
//	_, _ = store.UpdateSettings(ctx, auth.AuthSettings{Require2FA: &required})
//	auth.WithSettingsStore(store)
func WithSettingsStore(store SettingsStore) Option {
	return func(b *authBuilder) error {
		if store == nil {
			return errors.New("auth: settings store is required")
		}
		b.cfg.Settings = store
		return nil
	}
}

// WithEventBus sets Config.Events: the bus the library raises its identity.*
// events on. It is the reference's routerOptions.eventBus (node-auth
// auth.router.ts:92-96, read by publishRouterEvent at :418-420).
//
//	bus := auth.NewEventBus()
//	bus.Subscribe(auth.EventAuthLoginSuccess, func(ev auth.Event) { … })
//	bus.Subscribe(auth.EventBusWildcard, func(ev auth.Event) { … })
//	a, err := auth.New(auth.WithEventBus(bus))
//
// A nil bus is refused rather than accepted as "no bus", which is the opposite
// of leaving the option out. The distinction matters here more than it does for
// the store options: an event that is never raised fails silently and stays
// silent, so a host that wrote WithEventBus(b) with a b that turned out nil
// would get exactly the symptom this option exists to prevent. Omitting the
// option is how a deployment says it wants no events, and it is the default.
func WithEventBus(bus *EventBus) Option {
	return func(b *authBuilder) error {
		if bus == nil {
			return errors.New("auth: event bus is required")
		}
		b.cfg.Events = bus
		return nil
	}
}

// WithSiteURLs sets Config.SiteURLs: the base URLs the front ends are served
// from. The first is canonical, every one of them is allowlisted for the
// per-request origin match — see Config.SiteURLs and Auth.ResolveSiteURL.
//
//	auth.WithSiteURLs("https://www.example.com", "https://app.example.com")
//
// Calling it with no arguments leaves the list empty, which is the reference's
// "no siteUrl configured" and not an error.
func WithSiteURLs(urls ...string) Option {
	return func(b *authBuilder) error {
		b.cfg.SiteURLs = append([]string(nil), urls...)
		return nil
	}
}

// WithIDP registers an OIDC Identity Provider on the Auth, which is what makes
// every adapter mount its JWKS document at GET <prefix><IDPConfig.JWKSPath>,
// public and ahead of any middleware.
//
// The reference registers that route from the same condition — an idProvider
// block with a key, or enabled (auth.router.ts:473-475) — where here the
// condition is having built an IDP and passed it here.
//
// The same switch mounts the four OIDC endpoints beside it, at the paths
// (*IDP).RegisterHandlers uses and below the same prefix: OIDCDiscoveryPath,
// OIDCAuthorizePath, OIDCTokenPath and OIDCUserInfoPath, each for every method.
// Those four are this port's own — the reference has no OIDC authorization
// server — and see OIDCMounts for the list and RegisterHandlers for the host
// that would rather serve them on a mux of its own. Nothing about how /login,
// /refresh or the session tokens work changes either way.
//
// An IDP built with a nil Service adopts the one this Auth is being built
// around, which is the only order a host can write: NewIDP wants a *Service and
// a *Service only exists once New has returned. So
//
//	idp, err := auth.NewIDP(auth.IDPConfig{Signer: key}, nil)
//	a, err := auth.New(auth.WithUserStore(store), auth.WithIDP(idp))
//
// leaves idp fully wired.
//
// An IDP that already carries a different Service — one constructed directly, or
// one a previous auth.New already bound — is refused, and New returns an error:
// its /token and /userinfo would answer from that other Service's user store
// while this Auth's routes answered from this one. Build a second IDP for a
// second Auth. One IDP per Auth is also what keeps the binding free of a data
// race, since nothing rebinds an IDP that may already be serving requests.
func WithIDP(idp *IDP) Option {
	return func(b *authBuilder) error {
		if idp == nil {
			return errors.New("auth: WithIDP: nil IDP")
		}
		b.idp = idp
		return nil
	}
}

// WithAPIKeyStore registers the API-key store the admin console's 🔑 tab is
// served from: the reference's AdminOptions.apiKeyStore (admin.router.ts:121-124).
//
// It turns the apiKeys feature flag on — `!!options.apiKeyStore` (:653) — and it
// is what the four routes under <admin>/api/api-keys answer 404 for when it is
// absent. What the store can *do* is a second question those routes ask by type
// assertion: without APIKeyAdminStore the listing is a 501 naming listAll, and
// without APIKeyDeleteStore the hard delete revokes instead and says so.
//
// It is not read anywhere else. APIKeyMiddleware takes its store directly, which
// is how a host protects its own routes with a key, and registering one here
// does not put a key anywhere near the auth router's own credentials.
func WithAPIKeyStore(store APIKeyStore) Option {
	return func(b *authBuilder) error {
		if store == nil {
			return errors.New("auth: api key store is required")
		}
		b.apiKeys = store
		return nil
	}
}

// WithWebhookStore registers the outgoing-webhook store the admin console's 🔗
// tab is served from: the reference's AdminOptions.webhookStore
// (admin.router.ts:127-131).
//
// It turns the webhooks feature flag on — `!!options.webhookStore` (:654) — and
// the four routes under <admin>/api/webhooks answer 404 without it. A store that
// does not implement WebhookAdminStore serves events and answers 501 to each of
// the four, naming the single method the reference names.
//
// It is the same store AuthToolsOptions.Webhooks takes, and a deployment that
// has both passes it to both: this one is the console's management screen and
// that one is the delivery path. Neither writes what the other reads behind its
// back — the screen's PATCH changes a row the emitter will read next time it
// fans out, which is the point of the screen.
func WithWebhookStore(store WebhookStore) Option {
	return func(b *authBuilder) error {
		if store == nil {
			return errors.New("auth: webhook store is required")
		}
		b.webhooks = store
		return nil
	}
}

// WithLogger provides optional library logging callback.
func WithLogger(fn func(format string, args ...any)) Option {
	return func(b *authBuilder) error {
		b.cfg.Logger = fn
		return nil
	}
}

// Register delegates to Service.Register.
func (a *Auth) Register(ctx context.Context, in RegisterInput) (User, AuthTokens, error) {
	return a.service.Register(ctx, in)
}

// Login delegates to Service.Login.
func (a *Auth) Login(ctx context.Context, in LoginInput) (User, AuthTokens, error) {
	return a.service.Login(ctx, in)
}

// Refresh delegates to Service.Refresh.
func (a *Auth) Refresh(ctx context.Context, refreshToken string) (AuthTokens, error) {
	return a.service.Refresh(ctx, refreshToken)
}

// Logout delegates to Service.Logout.
func (a *Auth) Logout(ctx context.Context, refreshToken string) error {
	return a.service.Logout(ctx, refreshToken)
}

// Me delegates to Service.Me.
func (a *Auth) Me(ctx context.Context, accessToken string) (User, error) {
	return a.service.Me(ctx, accessToken)
}

// Authenticate delegates to Service.Authenticate: Me without the custom-claim
// enrichment, which is what the adapters' Middleware calls.
func (a *Auth) Authenticate(ctx context.Context, accessToken string) (User, error) {
	return a.service.Authenticate(ctx, accessToken)
}

// UpdateProfile delegates to Service.UpdateProfile.
func (a *Auth) UpdateProfile(ctx context.Context, in UpdateProfileInput) (User, error) {
	return a.service.UpdateProfile(ctx, in)
}

// DeleteAccount delegates to Service.DeleteAccount.
func (a *Auth) DeleteAccount(ctx context.Context, in DeleteAccountInput) error {
	return a.service.DeleteAccount(ctx, in)
}
