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
	// Secret is the HS256 key of the access token and of the 2FA step-up
	// token: the reference's accessTokenSecret (auth-config.model.ts:147), with
	// which it signs both (token.service.ts:20-24). It is also the key of every
	// refresh token while RefreshSecret is empty. At least 32 characters.
	Secret string
	// RefreshSecret is the HS256 key of the refresh token: the reference's
	// refreshTokenSecret (auth-config.model.ts:148, token.service.ts:25-29 and
	// :154). Keeping it apart from Secret separates the two trust domains the
	// reference keeps apart: a component given Secret to verify access tokens
	// can no longer mint refresh tokens, and rotating RefreshSecret alone forces
	// every session to sign in again while access tokens already handed out run
	// to their expiry.
	//
	// Empty means unset, and unset means Secret, which is how every refresh
	// token was signed before this field existed; so a deployment that never
	// sets it sees no change. Setting it on a running deployment is that
	// rotation: every refresh token outstanding at that moment stops verifying.
	// When set it must be at least 32 characters, as Secret must.
	//
	// The reference, since 1.10.3, refuses to construct its router when the two
	// secrets are equal and a session store is configured (auth.router.ts:843-844
	// at 1.10.8). This port does not refuse it yet, because the fallback makes
	// the two equal in every deployment that predates this field; that refusal
	// is planned for v1.0.0. WithRefreshSecret sets it.
	RefreshSecret   string
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
	BcryptCost    int
	ResetTokenTTL time.Duration
	// ForgotPasswordMinResponseTime is the least time POST
	// <prefix>/forgot-password takes to answer, measured from when the request
	// reaches Auth.ForgotPassword: whichever branch it took — a known address
	// whose mail was sent, an unknown one, one an invitation reserves, a
	// delivery that failed, a store that failed — the answer is held until the
	// floor has passed. It exists because the branches cost differently: a
	// known address waits for the delivery, a synchronous webhook or mail
	// relay that can take seconds, and the others answer right after a lookup,
	// so the time alone says which addresses have accounts though the status
	// and the body do not. Sending from a goroutine once the answer is written
	// is no fix where the runtime freezes at that point, as AWS Lambda's does.
	// A sender that only hands the delivery to a durable queue is one: the
	// known branch is then short and a small floor covers it, though the token
	// is then stored once the queue has the delivery, not once the mail is out.
	//
	// It hides the difference only where the floor is above the slow branch's
	// worst case: a branch that already took longer is not held further, so
	// set it at or above the lookup, plus the sender's own timeout (a
	// DeliveryWebhook's Timeout, for one), plus the token write that follows a
	// good send. The hold ends early only at the request context's deadline,
	// forgotPasswordAnswerHeadroom (100 ms) before it — on Lambda the
	// function's, where an answer written after it is a timeout. The work
	// behind the answer, the send and the store included, is bounded by that
	// same moment, floor or no floor, so no branch answers later: a sender that
	// honours its context and is still running then is cut off, as a failed
	// delivery (200, nothing stored), and a store write cut off there answers
	// the 500 of a failed store. A cancelled context does not end the hold: on
	// a Go net/http server a client that half-closes its connection cancels
	// the request context and can still read the answer, so a cancelled
	// request is held like any other, and a client that did go away costs the
	// server the rest of the floor. Nothing here knows of a timeout the context
	// does not carry — http.Server.WriteTimeout, a proxy's, an API gateway's
	// integration timeout — so keep the floor well below each of those. A body
	// refused before the service is reached (400 INVALID_BODY,
	// 413 BODY_TOO_LARGE) is not held: it depends on no address.
	// Service.ForgotPassword, the library call, is never held, and keeps the
	// caller's deadline as it is.
	//
	// What it costs: every request on the route, an unknown address's
	// included, lasts at least the floor. Where the runtime counts concurrent
	// executions — AWS Lambda's does — each held request occupies one for that
	// long, so the route needs its request rate times the floor in concurrency
	// and in billed duration, and a burst of anonymous requests can take the
	// capacity the deployment's other routes share. A rate limiter keyed on
	// the address in the body does not bound that, since every new address
	// has a budget of its own; a limit per client, or capacity reserved for
	// the function, in front of the route does.
	//
	// What it does not hide: the status. A store write that fails after a good
	// send answers 500, and only a known address gets that far (the
	// reference's answer, kept). Nor does it reach /magic-link/send and
	// /sms/send, whose known and unknown addresses differ in time the same way.
	//
	// Zero — the default — is off, the behaviour this field predates. A
	// negative value is refused. WithForgotPasswordMinResponseTime sets it.
	ForgotPasswordMinResponseTime time.Duration
	MagicLinkTTL                  time.Duration
	SMSCodeTTL                    time.Duration
	EmailVerificationTTL          time.Duration
	EmailVerificationMode         string
	EmailChangeTTL                time.Duration
	// TempTokenTTL is the lifetime of the step-up token a 2FA challenge hands
	// the client — 5 minutes in DefaultConfig, the reference's hardcoded '5m'
	// — and, while EnrolmentTokenTTL is zero, of the enrolment token a
	// 2FA_SETUP_REQUIRED answer carries under EnrolOnLogin.
	TempTokenTTL time.Duration
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
	// RevokeSessionsOnPasswordReset decides whether a successful POST
	// <prefix>/reset-password — and Service.ResetPassword — also ends every
	// session the account holds: when true, once the new password is stored
	// and before the token is cleared, the session store revokes them — in one
	// call when it implements UserSessionRevoker, and otherwise by listing the
	// account's sessions under its tenant (SessionAdminStore.ListSessionsForUser)
	// and revoking each one that is neither revoked nor expired
	// (SessionAdminStore.RevokeSessionByID).
	//
	// What that ends, and when:
	//
	//   - A refresh token of those sessions is refused at once: POST
	//     <prefix>/refresh answers 401 SESSION_REVOKED, on which the family's
	//     browser clients log out.
	//   - An access token already issued stays valid until it expires —
	//     AccessTokenTTL, 15 minutes by default — under SessionCheckOn
	//     "refresh" or "none", because those modes do not read the session on
	//     a protected request. Under "allcalls" every protected request does,
	//     and answers 401 SESSION_REVOKED at once.
	//   - The reset itself opens no session, either way; the person signs in
	//     with the new password.
	//
	// The option also ends what the old password opens that the revocation
	// cannot find:
	//
	//   - A password login in flight: one that proved the old password before
	//     the reset and opens its session after the revocation has looked. A
	//     login that opens a session on the strength of the password —
	//     Service.Login and LoginWithChallenge (POST <prefix>/login, and the
	//     IDP's /authorize form), the IDP's /token, and the forced enrolment of
	//     EnrolOnLogin — reads the account again once its session exists, and
	//     if the stored password hash is no longer the one it proved, it gives
	//     the session up and is refused: as a wrong password at login,
	//     invalid_grant at /token, ErrInvalidToken at the enrolment.
	//   - An OIDC authorization code minted before the reset: it carries the
	//     fingerprint of the password its /authorize login proved
	//     (AuthCode.Credential), and /token refuses it with invalid_grant once
	//     the account's password is another.
	//   - The console token POST <admin>/login mints for a store account: it
	//     carries the same kind of fingerprint, and the admin guard, which
	//     reads the account on every console request, refuses it once the
	//     password is another, as it refuses an expired one.
	//   - An enrolment token (EnrolOnLogin), which is bound to the password it
	//     was minted under (its cred claim).
	//
	// What it does not end:
	//
	//   - A step-up token — the tempToken of a 2FA challenge — minted before
	//     the reset. Whoever passed the password step shortly before the reset
	//     and holds the second factor can still complete that challenge for
	//     TempTokenTTL (5 minutes by default) and get a session the reset never
	//     saw; a shorter TempTokenTTL narrows the window.
	//   - An access token on the admin console. The console accepts an
	//     ordinary access token whenever it verifies tokens with the secret
	//     access tokens are signed with — AdminOptions.JWTSecret unset, which
	//     falls back to Secret — and reads no session behind it, under every
	//     SessionCheckOn, "allcalls" included; so one issued before the reset
	//     opens the console until it expires (AccessTokenTTL).
	//   - A login whose own PasswordVerifier migration write lands after the
	//     reset's. With or without the option, that write replaces the new
	//     password with the old one; the login, which reads back the hash it
	//     wrote, keeps its session, and the person resets again.
	//
	// That much rests on what the stores keep. UserStore.GetUserByID returns
	// the account's PasswordHash and sees a password write that has returned
	// (a read from a lagging replica does not). The revocation reaches every
	// session whose creation had returned when it began — UserSessionRevoker's
	// contract, or a complete and consistent listing. An AuthCodeStore keeps
	// AuthCode.Credential; one that drops it makes every code fail at /token.
	//
	// Turning the option on refuses, once, what was minted before it with
	// nothing to check: an authorization code not yet redeemed, and a store
	// account's console token, whose holder signs in again. And a password
	// login is refused if the account's password hash changes in the moment
	// between its comparison and its session, whatever changed it: a reset, a
	// POST <prefix>/change-password, or a concurrent PasswordVerifier
	// migration of the same account.
	//
	// A revocation the store refuses fails the reset: the generic 500, with a
	// line through Config.Logger naming the user and the store's error. The
	// password has been changed by then and the sessions the store did revoke
	// stay revoked, but answering success would tell the person that a session
	// still usable is gone. The token is left as it is: a store that keeps it
	// until ClearResetToken, as MemoryUserStore does, lets the same link run the
	// reset and the revocation again; a store that consumes it at lookup needs
	// a new link, which does the same.
	//
	// The option needs a session store that implements UserSessionRevoker or
	// SessionAdminStore, and NewService refuses it on one that implements
	// neither, rather than accept a promise it could not keep.
	// MemorySessionStore implements SessionAdminStore. The listing path is
	// exactly as complete as the listing: a store whose listing refuses past a
	// cap fails every reset of an account over it with nothing revoked, and
	// one that lists from an eventually consistent index can miss a session
	// opened just before the reset, which then lives on. Such a store
	// implements UserSessionRevoker, whose contract is that every session
	// whose creation had returned when the call began is revoked.
	//
	// False — the zero value, and what DefaultConfig leaves — is the
	// reference's answer: a reset leaves every session alive (registered as
	// reset-password-can-revoke-sessions). WithRevokeSessionsOnPasswordReset
	// sets it.
	RevokeSessionsOnPasswordReset bool
	Require2FA                    bool
	// EnrolOnLogin lets an account that must present a second factor and has
	// none enrol one at login, and opens its session when it does: the
	// tempToken of the 403 2FA_SETUP_REQUIRED answer POST <prefix>/login gives
	// it is then an enrolment token, which POST <prefix>/2fa/setup and POST
	// <prefix>/2fa/verify-setup accept (see enrolment.go).
	//
	// It is trust on first use. Whoever holds the account's password — a
	// leaked invitation or initial password, or the password of an account
	// whose factor an administrator has just reset — binds a factor of their
	// choosing and gets a full session, and the owner's next login is then a
	// challenge they cannot answer. That is what enrolling at login means;
	// a deployment that delivers passwords it does not control, or resets
	// factors without resetting passwords, should enrol out of band instead.
	//
	// False — the zero value, and what DefaultConfig leaves — keeps the
	// behaviour this field predates: the 2FA_SETUP_REQUIRED tempToken is a
	// step-up token no route accepts, the two enrolment routes take an access
	// token only, and an account under a mandatory policy is enrolled out of
	// band. WithEnrolOnLogin sets it.
	EnrolOnLogin bool
	// EnrolmentTokenTTL is how long the enrolment token of a
	// 2FA_SETUP_REQUIRED answer lives under EnrolOnLogin: the window in which
	// POST <prefix>/2fa/setup and POST <prefix>/2fa/verify-setup complete the
	// enrolment with it and open the session. The token's own exp carries it,
	// so exp - iat is the window a client can show, and every use honours the
	// token until exp plus ClockSkew. Nothing else the enrolment depends on
	// lapses sooner: the secret /2fa/setup answers is derived from the token
	// rather than stored, and verify-setup checks the code against the clock
	// at the moment it is called.
	//
	// Zero — the zero value, and what DefaultConfig leaves — is TempTokenTTL,
	// the step-up token's lifetime, as before this field existed. Set, it must
	// lie between MinEnrolmentTokenTTL and MaxEnrolmentTokenTTL, one minute
	// and thirty, or NewService refuses the configuration; the bounds are this
	// field's, and an unset field leaves the token on TempTokenTTL whatever
	// that is. The step-up token keeps TempTokenTTL either way, and without
	// EnrolOnLogin there is no enrolment token for the field to change. It is
	// for a consumer whose invitees install an authenticator app during
	// enrolment, for whom five minutes from the password to the first code
	// can be too few.
	//
	// The window is a security setting, not only a convenience. For an
	// account with no factor the token alone completes the enrolment and opens
	// a session — /2fa/setup hands its holder the secret, and a code of that
	// secret is all verify-setup asks — so a copy of the token is worth a
	// session for as long as it lives, and fifteen minutes is three times the
	// default's exposure. A copy is worth the factor too, and that outlives
	// the token: /2fa/setup answers the same secret for every call with the
	// same token, and no event records the call, so a copy that calls it
	// before the owner enrols with that token learns the secret of the factor
	// the owner then enrols, and keeps it after the token has expired. With
	// the password, it answers the step-up until the factor is replaced. Treat
	// a leaked enrolment token as a leaked factor: change the password, then
	// enrol a new factor in place of that one (signed in, /2fa/setup and
	// /2fa/verify-setup with an access token replace it).
	//
	// What else bounds the token is unchanged. It is minted only by a login
	// that proved the account's password or by the acceptance of an
	// invitation, and it dies with a password change. It is refused while the
	// account has a factor, but not spent: a factor removed before exp
	// without a password change brings the token back, with the same secret,
	// so reset the password together with the factor (see EnrolOnLogin). Keep
	// the token out of URLs, storage and logs. WithEnrolmentTokenTTL sets it.
	EnrolmentTokenTTL time.Duration
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
	// Invitations is the store of the invitation flow (invitation.go), and
	// the switch for the whole of it: set, the adapters mount POST
	// <prefix>/invitations/accept — under HTTPConfig.ClosedRegistration too,
	// which is what the flow is for — and the admin router registers
	// POST and GET <admin>/api/users/invitations and DELETE
	// <admin>/api/users/invitations/{id}. Nil, the default, registers none of
	// the four, and nothing changes. The reference has no counterpart: see
	// the invitations-are-an-addition deviation. WithInvitationStore sets it.
	Invitations InvitationStore
	// InvitationTTL is how long an invitation's token is honoured. Zero means
	// DefaultInvitationTTL, 72 hours, so a Config built by hand before this
	// field existed is still valid; a negative value is refused.
	// WithInvitationTTL sets it.
	//
	// It bounds the token, not the account. The pending account an expired
	// invitation reserved stays — listed with its invitation as expired, and
	// signed in to by a magic link to its address, with the invited role —
	// until an administrator revokes the invitation, which removes the account
	// if nobody has used it. An offer meant to lapse is revoked.
	InvitationTTL time.Duration
	// InvitationReinvite decides what inviting an address that already has an
	// account does when that account is still pending — created by an
	// invitation that has not been accepted. False, the default, refuses it
	// like any other existing address (409); true makes the call idempotent:
	// the same account is invited again as it is, a fresh token is delivered,
	// and the tokens it replaces stop working. A re-invitation that names a
	// role or a tenant other than the account's is refused
	// (ErrInvitationMismatch) rather than answered as if it had been applied.
	// An active account is refused either way. WithInvitationReinvite sets it.
	InvitationReinvite bool
	// SendInvitation delivers an invitation's token — the reference's
	// mailer.sendInvitation (mailer.service.ts:210-227) as a seam, like the
	// five senders above. InvitationMailer.Send renders the reference's
	// template over a transport; DeliveryWebhook.SendInvitation posts the
	// delivery. Nil means no delivery: Service.InviteUser still returns the
	// token to a direct caller, and the admin route refuses to invite unless
	// AdminOptions.RevealInvitationToken hands the token to its caller.
	// WithInvitationSender sets it.
	SendInvitation InvitationSender
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
	// EmailLangs lists the languages a mail may be asked for through a
	// request's emailLang: the languages this deployment's senders render.
	// Set, the language every mail carries — the four link mails of
	// forgot-password, send-verification-email, change-email/request and
	// magic-link/send, the link-request mail, the invitation, and the
	// email-changed notice a direct caller asks a language for — reaches the
	// sender as one of these entries or not at all. The value is matched
	// without regard to case, first whole and then by its primary language
	// subtag ("IT", "it-IT" and "it_IT" are "it"), and anything else — an
	// unlisted language, a value that is not a language tag, one longer than
	// 35 characters — is replaced by "", which every sender reads as the
	// deployment's default, as it reads a request that sent none. No request
	// is refused for its language, so no answer depends on it.
	//
	// Empty — the zero value — keeps the behaviour this field predates: the
	// value reaches the sender as it was sent, as the reference passes
	// emailLang to its mailer (auth.router.ts:779, 788). The library's own
	// mailers honour "it" and "en" and fall back to their Locale for anything
	// else (resolveLang), so a deployment on them loses nothing with
	// []string{"it", "en"}; one with a sender of its own lists what that
	// sender renders. Each entry must be a language tag — subtags of letters
	// and digits separated by '-' or '_', the first two to eight letters, at
	// most 35 characters — or NewService refuses the configuration.
	// WithEmailLangs sets it.
	EmailLangs []string
	Logger     func(format string, args ...any)
}

// maxLanguageTagLen is the longest language tag EmailLangs accepts or lets
// through: the length RFC 5646 §4.4.1 asks every implementation to support.
const maxLanguageTagLen = 35

// isLanguageTag reports whether s has the shape of a language tag: one or more
// subtags of ASCII letters and digits, separated by '-' or '_' (the POSIX
// spelling of a locale is common in a request), the first of two to eight
// letters and each of one to eight characters, at most maxLanguageTagLen in
// all. It checks the shape and not the registry: "xx" is a tag here, and
// whether a deployment has templates for it is what EmailLangs says.
func isLanguageTag(s string) bool {
	if s == "" || len(s) > maxLanguageTagLen {
		return false
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '-' && s[i] != '_' {
			c := s[i] | 0x20 // ASCII lower case; leaves digits as they are
			letter := c >= 'a' && c <= 'z'
			digit := s[i] >= '0' && s[i] <= '9'
			if !letter && (!digit || start == 0) {
				return false
			}
			continue
		}
		n := i - start
		if n < 1 || n > 8 || (start == 0 && n < 2) {
			return false
		}
		start = i + 1
	}
	return true
}

// emailLang is the language a delivery carries for the emailLang a request
// sent: under EmailLangs, the matching entry as configured, or "" for the
// sender's default; with none configured, the value as it was sent. See
// EmailLangs.
func (c Config) emailLang(requested string) string {
	if len(c.EmailLangs) == 0 {
		return requested
	}
	tag := strings.TrimSpace(requested)
	if !isLanguageTag(tag) {
		return ""
	}
	for _, lang := range c.EmailLangs {
		if strings.EqualFold(tag, lang) {
			return lang
		}
	}
	primary := tag
	if i := strings.IndexAny(tag, "-_"); i >= 0 {
		primary = tag[:i]
	}
	for _, lang := range c.EmailLangs {
		if strings.EqualFold(primary, lang) {
			return lang
		}
	}
	return ""
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

// MinEnrolmentTokenTTL and MaxEnrolmentTokenTTL bound Config.EnrolmentTokenTTL
// when it is set. The floor keeps a value meant in minutes but written in
// seconds from minting a token nobody can use; the ceiling keeps to minutes
// the window in which a copy of the token is worth a session, or the secret
// of the factor enrolled with it. They bound the field, not the token's whole
// life: every use honours the token until exp plus Config.ClockSkew, so the
// longest window is thirty minutes plus that skew, and an unset field leaves
// the token on TempTokenTTL, which they do not bound.
const (
	MinEnrolmentTokenTTL = time.Minute
	MaxEnrolmentTokenTTL = 30 * time.Minute
)

// enrolmentTokenTTL is the lifetime of the enrolment token: EnrolmentTokenTTL
// when it is set, TempTokenTTL otherwise. See Config.EnrolmentTokenTTL.
func (c Config) enrolmentTokenTTL() time.Duration {
	if c.EnrolmentTokenTTL != 0 {
		return c.EnrolmentTokenTTL
	}
	return c.TempTokenTTL
}

// secretFor is the HS256 key a token of tokenType is signed and verified with:
// RefreshSecret for a refresh token when it is set, Secret for everything else
// and for a refresh token when it is not. The step-up token stays on Secret
// because the reference's is an access token (generateTokenPair(...).accessToken,
// signed with accessTokenSecret).
func (c Config) secretFor(tokenType string) string {
	if tokenType == "refresh" && c.RefreshSecret != "" {
		return c.RefreshSecret
	}
	return c.Secret
}

func (c Config) validate() error {
	if len(c.Secret) < 32 {
		return errors.New("auth: secret must be at least 32 chars")
	}
	if c.RefreshSecret != "" && len(c.RefreshSecret) < 32 {
		return errors.New("auth: refresh secret must be at least 32 chars, or empty to use the secret")
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
	if c.EnrolmentTokenTTL != 0 && (c.EnrolmentTokenTTL < MinEnrolmentTokenTTL || c.EnrolmentTokenTTL > MaxEnrolmentTokenTTL) {
		return fmt.Errorf("auth: enrolment token ttl must be between %s and %s, or 0 to use the temp token ttl; got %s",
			MinEnrolmentTokenTTL, MaxEnrolmentTokenTTL, c.EnrolmentTokenTTL)
	}
	if c.InvitationTTL < 0 {
		return errors.New("auth: invitation ttl must be > 0, or 0 for the default (72h)")
	}
	if c.ForgotPasswordMinResponseTime < 0 {
		return errors.New("auth: forgot-password minimum response time must be >= 0, and 0 is off")
	}
	for _, lang := range c.EmailLangs {
		if !isLanguageTag(lang) {
			return fmt.Errorf("auth: email language %q is not a language tag (subtags of letters and digits separated by '-' or '_', at most %d characters)", lang, maxLanguageTagLen)
		}
	}
	return nil
}
