package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCheckOnAllCalls = "allcalls"
	SessionCheckOnRefresh  = "refresh"
	SessionCheckOnNone     = "none"
)

// Email verification modes accepted by Config.EmailVerificationMode.
//
//	none   : Register marks the address verified, so verification never comes up
//	         on the self-registration path. An address left unverified by some
//	         other route (admin provisioning, a data import, a custom UserStore
//	         whose column defaults to false) is still refused at login. This is
//	         the default and is exactly how the service behaved before the mode
//	         existed.
//	lazy   : Register leaves the address unverified and login is allowed anyway.
//	         This is the only mode in which an unverified address may log in.
//	strict : Register leaves the address unverified and login is refused until
//	         the address is confirmed.
const (
	EmailVerificationModeNone   = "none"
	EmailVerificationModeLazy   = "lazy"
	EmailVerificationModeStrict = "strict"
)

// Config contains security and token settings for the auth service.
type Config struct {
	Secret          string
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	SessionCheckOn  string
	ClockSkew       time.Duration
	MinPasswordLen  int
	// BcryptCost is the bcrypt cost used for every password hash the library
	// writes. It is this port's spelling of the reference's
	// AuthConfig.bcryptSaltRounds; "cost" is what x/crypto/bcrypt calls the
	// parameter, and what bcrypt.DefaultCost, MinCost and MaxCost name.
	//
	// Zero means unset, and unset means bcrypt.DefaultCost — never
	// bcrypt.MinCost. A Config that was never told a cost must not silently get
	// the weakest one. Any other value must lie in
	// [bcrypt.MinCost, bcrypt.MaxCost]; validate rejects the rest.
	BcryptCost            int
	ResetTokenTTL         time.Duration
	MagicLinkTTL          time.Duration
	SMSCodeTTL            time.Duration
	EmailVerificationTTL  time.Duration
	EmailVerificationMode string
	EmailChangeTTL        time.Duration
	TempTokenTTL          time.Duration
	// IssueSessionOnRegister decides whether POST <prefix>/register — and
	// Service.Register — also logs the new account in: when true, a successful
	// registration opens a session exactly as a successful POST <prefix>/login
	// does (the same cookies in cookie mode, the same accessToken and
	// refreshToken body fields in bearer mode, the same session row, the same
	// identity.auth.login.success event); when false, the registration answers
	// 201 {"success":true,"userId":"…"} and nothing else, and the client logs
	// in afterwards. It is the family's instance-admin option of that name
	// (awesome-go-auth #21).
	//
	// False — the zero value, and what DefaultConfig leaves — is the reference's
	// answer, so an unconfigured instance answers what the reference answers.
	// True is an addition the reference does not have, registered as
	// register-issues-a-session; WithIssueSessionOnRegister sets it.
	//
	// Even when true, no session is issued to an account POST <prefix>/login
	// would not log straight in: an unverified address under
	// EmailVerificationModeStrict (the verification gate wins; NewService logs
	// once when both are configured), or an account a second factor is
	// required of (Require2FA, for a new account). The registration then
	// answers the plain 201 and the account logs in through the login's own
	// gates.
	IssueSessionOnRegister bool
	Require2FA             bool
	// TwoFactorAppName is the issuer an authenticator app files a TOTP
	// enrolment under: the `issuer` of the otpauth:// URI POST <prefix>/2fa/setup
	// returns, and the prefix of its label. It is the reference's
	// `twoFactor.appName` (auth-config.model.ts:272-274, read at
	// auth.router.ts:830).
	//
	// Empty means unset, and unset means Config.Issuer — which is what the URI
	// carried before this field existed, so enrolments made then and enrolments
	// made now sit under the same name in users' apps. The reference falls back
	// to the literal 'awesome-node-auth' instead; that difference is registered
	// as the deviation totp-issuer-defaults-to-config-issuer. WithTwoFactorAppName
	// sets it.
	TwoFactorAppName string
	// BuildTokenClaims adds claims to every token minted — access, refresh and
	// the 2FA step-up token — and fills CustomClaims on the profile Me returns.
	// Its result is spread over the six base claims (sub, email, role,
	// loginProvider, isEmailVerified, isTotpEnabled) and may override them, as
	// the reference's buildTokenPayload may (auth.router.ts:378-384). The
	// session claims sid, tid, jti, typ, iss, iat and exp are reserved: they
	// are written after the merge, so a hook value under one of those names is
	// discarded rather than minted (see issueToken for why).
	//
	// It runs at mint time and on Me, and nowhere else: Authenticate, which the
	// adapters' Middleware calls on every protected request, never runs it. A
	// hook that cannot answer fails the mint (the route answers 500) and is
	// merely logged on Me. StaticClaims, UserFieldClaims, ChainClaims and
	// ClaimsWebhook build one from configuration rather than code.
	BuildTokenClaims TokenClaimsBuilder
	// PasswordVerifier is the migration seam: the hook POST <prefix>/login
	// consults for a user whose stored hash did not verify the supplied
	// password, so that a deployment moving off another identity provider can
	// accept that provider's password on the first login, adopt it as a local
	// bcrypt hash and stop calling the old system.
	//
	// It is an additive port extension with no counterpart in the reference,
	// whose login path verifies bcrypt directly and offers no hook
	// (local.strategy.ts:19-29). Nil, the default, is the reference's behaviour
	// exactly: the verifier is never called, and every login answers as it did
	// before this field existed. WithPasswordVerifier sets it. See
	// password_verifier.go.
	PasswordVerifier PasswordVerifier
	// SendMagicLink and SendSMSCode are the delivery seam. Both are optional to
	// construct a service with and required to use the route that needs them:
	// leaving one nil is what makes POST <prefix>/magic-link/send answer 500
	// EMAIL_NOT_CONFIGURED and POST <prefix>/sms/send answer 500
	// SMS_NOT_CONFIGURED. See delivery.go for why they live here.
	SendMagicLink MagicLinkSender
	SendSMSCode   SMSCodeSender
	// SendPasswordReset, SendEmailVerification and SendEmailChange are the other
	// half of the same seam, for POST <prefix>/forgot-password,
	// POST <prefix>/send-verification-email and POST <prefix>/change-email/request.
	//
	// Leaving one nil is silence rather than an error: the reference's routes send
	// no mail and still answer 200 when neither a callback nor a mailer is
	// configured, so these three have no NOT_CONFIGURED code. See
	// delivery_password_email.go.
	SendPasswordReset     PasswordResetSender
	SendEmailVerification EmailVerificationSender
	SendEmailChange       EmailChangeSender
	// SendEmailChanged is the reference's config.email.sendEmailChanged
	// (auth-config.model.ts:252-257): the notice POST <prefix>/change-email/confirm
	// mails to the OLD address once the change is applied (auth.router.ts:
	// 1060-1066). Optional; nil is silence, as for the three above. A failure is
	// the reference's generic 500 with the change already committed — see
	// Service.ConfirmEmailChange.
	SendEmailChanged EmailChangedSender
	// Templates is the reference's config.templateStore
	// (auth-config.model.ts:400, read by mailer.service.ts:146): a TemplateStore whose
	// templates override the built-ins for every ready-made mailer the service
	// calls, and which will hold the UI translations once the UI router reads
	// them. Optional; nil renders the built-ins. WithTemplateStore sets it.
	Templates TemplateStore
	// Uploads is where the admin console's four upload routes write, and where
	// the built-in UI's <prefix>/ui/assets/logo/ and <prefix>/ui/assets/uploads/
	// mounts read back from: the seam over the reference's uploadDir
	// (admin.router.ts:135, read at :991).
	//
	// Optional, and nil is the whole feature turned off rather than a degraded
	// one — the four routes are not registered, so they answer 404 rather than
	// 401, and the console's features.upload is false so the SPA draws no file
	// picker. There is deliberately no default: see UploadStore.
	//
	// It is on Config rather than in HTTPConfig.Admin for the reason Templates
	// and Settings are — it is a store, the reference carries it in the same
	// options bag as the other stores, and both the admin router and the UI
	// router read it. WithUploadStore sets it.
	Uploads UploadStore
	// Settings is the reference's routerOptions.settingsStore
	// (auth.router.ts:92, read at :890-896): the global switches an
	// administrator flips at run time. Optional; nil means the settings check is
	// skipped altogether, as it is in the reference without a store.
	//
	// One setting reaches this library: AuthSettings.Require2FA, which
	// Auth.TwoFactorPolicy ORs with Require2FA above and
	// POST <prefix>/2fa/disable refuses on. The email-verification settings are
	// stored and are deliberately not consulted at login, because the reference
	// does not consult them either — see settings_store.go and README_DETAILED,
	// "Runtime settings". WithSettingsStore sets it.
	Settings SettingsStore
	// Events is the bus every identity.* event is raised on: the reference's
	// routerOptions.eventBus (node-auth auth.router.ts:418-420, where
	// publishRouterEvent takes it and returns early when it is undefined).
	//
	// Optional, and nil is the common case. A deployment that subscribes to
	// nothing configures nothing, and Service.publish then does no work at all —
	// not even building the payload, which is why the publication sites pass a
	// builder rather than a value. See Service.publish.
	//
	// It sits on Config rather than being a ServiceOption for the reason
	// Settings does: the reference carries it in the same options bag as the
	// stores, a host that builds its Config by hand must be able to reach it,
	// and NewWithConfig is the constructor that takes the struct whole.
	// WithEventBus sets it.
	Events *EventBus
	// SiteURLs is the reference's config.email.siteUrl, which may be one string
	// or an array of them (auth-config.model.ts). Two things are read off it:
	//
	//   - The first entry is the canonical base URL for an emailed link
	//     (getDefaultSiteUrl, auth.router.ts:202-206): what a link points at when
	//     the request that asked for it carries no allowlisted Origin or Referer.
	//   - Every entry, together with OAuthWiring.AllowedOrigins, forms the origin
	//     allowlist Auth.ResolveSiteURL matches a request against
	//     (buildAllowedOrigins, auth.router.ts:213-219), so a deployment serving
	//     several front ends mails each one a link back to itself.
	//
	// Entries are matched exactly, as the reference's `includes` does: no trailing
	// slash normalisation, no case folding. Optional; with none configured the
	// adapters hand the ready-made mailers no per-request base and their static
	// BaseURL applies, as it did before this field existed. WithSiteURLs sets it.
	SiteURLs []string
	Logger   func(format string, args ...any)
}

// DefaultConfig returns secure defaults for development and production bootstrap.
func DefaultConfig(secret string) Config {
	return Config{
		Secret:                secret,
		Issuer:                "awesome-go-auth",
		AccessTokenTTL:        15 * time.Minute,
		RefreshTokenTTL:       30 * 24 * time.Hour,
		SessionCheckOn:        SessionCheckOnRefresh,
		ClockSkew:             30 * time.Second,
		MinPasswordLen:        8,
		BcryptCost:            bcrypt.DefaultCost,
		ResetTokenTTL:         1 * time.Hour,
		MagicLinkTTL:          15 * time.Minute,
		SMSCodeTTL:            10 * time.Minute,
		EmailVerificationTTL:  24 * time.Hour,
		EmailVerificationMode: EmailVerificationModeNone,
		EmailChangeTTL:        1 * time.Hour,
		TempTokenTTL:          5 * time.Minute,
	}
}

// totpIssuer is the issuer the TOTP provisioning URI carries: TwoFactorAppName
// when set, Issuer otherwise. See Config.TwoFactorAppName for why the fallback
// is not the reference's literal.
func (c Config) totpIssuer() string {
	if c.TwoFactorAppName != "" {
		return c.TwoFactorAppName
	}
	return c.Issuer
}

func (c Config) validate() error {
	if len(c.Secret) < 32 {
		return errors.New("auth: secret must be at least 32 chars")
	}
	if c.AccessTokenTTL <= 0 {
		return errors.New("auth: access token ttl must be > 0")
	}
	if c.RefreshTokenTTL <= 0 {
		return errors.New("auth: refresh token ttl must be > 0")
	}
	switch strings.ToLower(strings.TrimSpace(c.SessionCheckOn)) {
	case "", SessionCheckOnAllCalls, SessionCheckOnRefresh, SessionCheckOnNone:
	default:
		return errors.New("auth: session check mode must be one of allcalls|refresh|none")
	}
	switch strings.ToLower(strings.TrimSpace(c.EmailVerificationMode)) {
	case "", EmailVerificationModeNone, EmailVerificationModeLazy, EmailVerificationModeStrict:
	default:
		return errors.New("auth: email verification mode must be one of none|lazy|strict")
	}
	if c.MinPasswordLen < 8 {
		return errors.New("auth: min password len must be >= 8")
	}
	if c.BcryptCost != 0 && (c.BcryptCost < bcrypt.MinCost || c.BcryptCost > bcrypt.MaxCost) {
		return fmt.Errorf("auth: bcrypt cost must be between %d and %d, or 0 for the default (%d)", bcrypt.MinCost, bcrypt.MaxCost, bcrypt.DefaultCost)
	}
	if c.ResetTokenTTL <= 0 || c.MagicLinkTTL <= 0 || c.SMSCodeTTL <= 0 {
		return errors.New("auth: reset token, magic link, and sms code ttl must be > 0")
	}
	if c.EmailVerificationTTL <= 0 || c.EmailChangeTTL <= 0 || c.TempTokenTTL <= 0 {
		return errors.New("auth: email and temp token ttl must be > 0")
	}
	return nil
}
