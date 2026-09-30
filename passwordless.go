package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// This file holds the vocabulary the passwordless entry points (magic link,
// SMS OTP) and the TOTP second factor share: the step-up token, the mode
// switch, the error catalog entries those routes emit and the route-specific
// sentinel mappings. It sits in the root package for the same reason wire.go
// does — eight routes across four adapters is thirty-two chances for a literal
// to drift, and every one of these literals is on the wire.
//
// The shapes are wire-contract §3 (awesome-node-auth@cc01e997). Deviations are
// called out where they exist.

// StepUpMode is the only value of the `mode` field the routes special-case.
const StepUpMode = "2fa"

// TwoFactorMode reports whether a magic-link or SMS request asked for the
// second-factor branch.
//
// The comparison is literal and case-sensitive because the reference's is
// (`mode === '2fa'`, auth.router.ts:1087, :1134, :1192, :1255): "login", the
// empty string, and anything else all take the login branch. That is what makes
// the two shipped clients interchangeable — Angular sends mode:"login", Flutter
// omits the field — so loosening this comparison silently reroutes one of them.
func TwoFactorMode(mode string) bool { return mode == StepUpMode }

// Error codes for this section of the contract.
const (
	CodeTempTokenRequired = "TEMP_TOKEN_REQUIRED"
	CodeInvalidTempToken  = "INVALID_TEMP_TOKEN"
	// CodeInvalidAccessToken is what /2fa/verify answers for a bad step-up
	// token where its siblings answer INVALID_TEMP_TOKEN. See
	// HTTPErrInvalidStepUpToken.
	CodeInvalidAccessToken = "INVALID_ACCESS_TOKEN"
	CodeInvalidMagicLink   = "INVALID_MAGIC_LINK"
	CodeTokenMismatch      = "TOKEN_MISMATCH"
	CodePhoneNotSet        = "PHONE_NOT_SET"
	// CodeEmailNotConfigured and CodeSMSNotConfigured report a deployment that
	// cannot deliver what the send route just minted. See delivery.go.
	CodeEmailNotConfigured = "EMAIL_NOT_CONFIGURED"
	CodeSMSNotConfigured   = "SMS_NOT_CONFIGURED"
)

// The catalog entries these routes write. Several carry no code: the reference
// answers those inline rather than through its AuthError path, and the omission
// is exact, not an oversight (wire-contract §3, "Shared mechanics").
var (
	HTTPErrTempTokenRequired = HTTPError{Status: http.StatusBadRequest, Message: "tempToken is required for 2FA mode", Code: CodeTempTokenRequired}
	HTTPErrInvalidTempToken  = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid or expired temp token", Code: CodeInvalidTempToken}

	// HTTPErrInvalidStepUpToken is /2fa/verify's answer to the failure the
	// magic-link and SMS routes answer with HTTPErrInvalidTempToken. The
	// reference verifies the tempToken there through verifyAccessToken and lets
	// its AuthError through unchanged (auth.router.ts:862 vs :1096, :1144,
	// :1201, :1264), so the same failure has two codes depending on the 2FA
	// method. It is reproduced rather than harmonised: a client that special-
	// cases TOTP today would break if this route started agreeing with its
	// siblings.
	HTTPErrInvalidStepUpToken = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid or expired access token", Code: CodeInvalidAccessToken}

	// Uncoded on purpose. The reference emits this same message WITHOUT a code on
	// /magic-link/send (auth.router.ts:1111) but WITH code EMAIL_REQUIRED on
	// /link-request (auth.router.ts:1498), so this and HTTPErrLinkEmailRequired are
	// not interchangeable. Do not merge them into one entry.
	HTTPErrPasswordlessEmailRequired = HTTPError{Status: http.StatusBadRequest, Message: "email is required"}
	HTTPErrUserIDOrEmailRequired     = HTTPError{Status: http.StatusBadRequest, Message: "userId or email is required"}
	HTTPErrUserIDRequired            = HTTPError{Status: http.StatusBadRequest, Message: "userId is required"}
	HTTPErrPhoneNotSet               = HTTPError{Status: http.StatusBadRequest, Message: "User does not have a phone number configured", Code: CodePhoneNotSet}

	HTTPErrInvalidSMSCode = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid or expired SMS code"}

	// HTTPErrEmailNotConfigured is /magic-link/send's answer when nothing can
	// mail the link (magic-link.strategy.ts:12-14).
	HTTPErrEmailNotConfigured = HTTPError{Status: http.StatusInternalServerError, Message: "Email not configured", Code: CodeEmailNotConfigured}

	// HTTPErrSMSNotConfigured is /sms/send's answer when nothing can text the
	// code. The reference states this one twice with two different messages: the
	// router checks config.sms first and says "SMS is not configured"
	// (auth.router.ts:1179), and the strategy behind it says "SMS not
	// configured" (sms.strategy.ts:12) — no "is". Only the router's string is
	// ever on the wire, because its check runs before the strategy is reached,
	// so that is the one reproduced. The strategy's wording is not a second
	// catalog entry here; it has no route that can emit it.
	HTTPErrSMSNotConfigured = HTTPError{Status: http.StatusInternalServerError, Message: "SMS is not configured", Code: CodeSMSNotConfigured}

	// HTTPErrInvalidMagicLink covers both of the reference's magic-link
	// failures. The reference splits them — INVALID_MAGIC_LINK for a token it
	// cannot find, MAGIC_LINK_EXPIRED for one past its TTL
	// (magic-link.strategy.ts:41-49) — but Service.VerifyMagicLink collapses
	// the two into ErrInvalidToken, so the expiry code is not reachable from
	// here. Splitting the sentinel is the fix; both are 401 either way.
	HTTPErrInvalidMagicLink = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid magic link token", Code: CodeInvalidMagicLink}
	HTTPErrTokenMismatch    = HTTPError{Status: http.StatusUnauthorized, Message: "Token mismatch", Code: CodeTokenMismatch}

	// The two "Invalid TOTP code" entries differ only in status: /2fa/verify
	// answers 401 (auth.router.ts:869-872), /2fa/verify-setup answers 400
	// (:847-850).
	HTTPErrInvalidTOTPCode      = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid TOTP code"}
	HTTPErrInvalidTOTPSetupCode = HTTPError{Status: http.StatusBadRequest, Message: "Invalid TOTP code"}
	HTTPErrTOTPNotSetUp         = HTTPError{Status: http.StatusBadRequest, Message: "User not found or 2FA not set up"}

	HTTPErrTwoFactorRequiredForUser  = HTTPError{Status: http.StatusForbidden, Message: "Cannot disable 2FA: required for your account", Code: CodeTwoFactorRequired}
	HTTPErrTwoFactorRequiredByPolicy = HTTPError{Status: http.StatusForbidden, Message: "Cannot disable 2FA: required by system policy", Code: CodeTwoFactorRequired}
)

// ErrMagicLinkOwnerMismatch is a valid magic link presented as a second factor
// for somebody else: the link verified, but it does not belong to the user the
// step-up token names. It is a distinct sentinel rather than ErrInvalidToken
// because the wire answer differs (TOKEN_MISMATCH, not INVALID_MAGIC_LINK) and
// because the two failures mean different things — one is a bad link, the other
// is a good link on the wrong account.
var ErrMagicLinkOwnerMismatch = errors.New("auth: magic link belongs to another user")

// VerifyMagicLinkForUser consumes a magic link that must belong to userID, the
// step-up case: the caller has already identified the user through a step-up
// token and the link is only the second factor.
//
// It exists because the identity check has to happen before a session is
// created. Service.VerifyMagicLink issues one as part of verifying, so a caller
// that compared the ids afterwards would refuse the request on the wire and
// still leave a live session for the link's owner — a session that shows up in
// GET /sessions and that only the owner can revoke. A mismatch here returns
// ErrMagicLinkOwnerMismatch and issues nothing.
//
// The link is consumed even on a mismatch, matching the reference, which burns
// it in the strategy before the router compares ids
// (magic-link.strategy.ts:50 versus auth.router.ts:1150-1152).
//
// It never marks the address verified: a second factor is not proof of address
// ownership, and the reference's 2fa branch has no such call. It is
// ConsumeMagicLink, the owner comparison, and CompleteMagicLinkLogin — the
// general split, with the one predicate the routes need built in.
func (s *Service) VerifyMagicLinkForUser(ctx context.Context, in MagicLinkVerifyInput, userID string) (User, AuthTokens, error) {
	user, err := s.ConsumeMagicLink(ctx, in)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	if user.ID != userID {
		return User{}, AuthTokens{}, ErrMagicLinkOwnerMismatch
	}
	tokens, err := s.CompleteMagicLinkLogin(ctx, user)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	return user, tokens, nil
}

// tokenTypeTemp marks the step-up token.
//
// The reference mints its tempToken as an ordinary access token with a 5-minute
// lifetime and no claim distinguishing it (token.service.ts:20-24), which means
// a full access token also passes as a tempToken and a tempToken authenticates
// any protected route for five minutes. This port types it instead: the token
// is opaque to every client, so the type claim is not on the wire, and the
// confusion the reference's sharing allows is not worth reproducing. The
// consequence — a step-up token cannot be used as a session credential, or vice
// versa — is [UNTESTED] in the reference and no shipped client depends on it.
const tokenTypeTemp = "temp"

// TempTokenSubject is the identity a step-up token names. It is deliberately
// not a User: the routes that accept a tempToken re-read the user from the
// store, as the reference does, so a flag set since the token was minted is
// honoured.
type TempTokenSubject struct {
	UserID   string
	TenantID string
}

// IssueTempToken mints the step-up token a 2FA challenge hands the client. Its
// lifetime is Config.TempTokenTTL, 5 minutes by default, matching the
// reference's hardcoded '5m'.
func (s *Service) IssueTempToken(ctx context.Context, user User) (string, error) {
	token, _, err := s.issueToken(ctx, user, "", tokenTypeTemp, s.cfg.TempTokenTTL)
	return token, err
}

// VerifyTempToken resolves the identity a step-up token names, or
// ErrInvalidToken.
func (s *Service) VerifyTempToken(token string) (TempTokenSubject, error) {
	claims, err := s.parseToken(token, tokenTypeTemp)
	if err != nil {
		return TempTokenSubject{}, err
	}
	return TempTokenSubject{UserID: claims.Sub, TenantID: claims.Tid}, nil
}

// FindUser resolves a user by id, or by email when no id is given. The
// passwordless routes need it because they have to tell "no such user" apart
// from "that user has no phone number" — two different statuses in the contract
// — and the send calls answer both with silence.
func (s *Service) FindUser(ctx context.Context, userID, email, tenantID string) (User, error) {
	return s.resolveUser(ctx, userID, email, tenantID)
}

// TOTPSetup is the enrolment material POST /2fa/setup hands back. Enrolment is
// stateless in the reference and stateless here: nothing is persisted until the
// client returns the secret to /2fa/verify-setup together with a code that
// verifies against it.
//
// The reference also returns a `qrCode` PNG data URL. It is absent here: the
// root package is stdlib plus golang.org/x/crypto and a QR encoder is neither.
// A client renders OTPAuthURL itself, which is what the Rust port of this
// family does too.
type TOTPSetup struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauthUrl"`
}

// StartTOTPEnrolment mints an enrolment secret and its provisioning URI for a
// user it reads from the store; a user the store does not have is
// ErrInvalidCredentials.
func (s *Service) StartTOTPEnrolment(ctx context.Context, userID, tenantID string) (TOTPSetup, error) {
	user, err := s.users.GetUserByID(ctx, userID, tenantID)
	if err != nil {
		return TOTPSetup{}, ErrInvalidCredentials
	}
	return s.NewTOTPEnrolment(user.Email)
}

// NewTOTPEnrolment mints an enrolment secret and its provisioning URI for the
// account named email, reading no store. It is what POST <prefix>/2fa/setup
// calls with the address the access token carries: the reference's route labels
// the URI with req.user.email, the verified payload, and never looks the user up
// (awesome-node-auth v1.10.8 auth.router.ts:1369-1375). So a token whose user
// has been deleted is answered 200 there, and here (#31). Nothing is stored:
// the secret becomes the user's only when POST <prefix>/2fa/verify-setup
// confirms a code against it.
func (s *Service) NewTOTPEnrolment(email string) (TOTPSetup, error) {
	secret, err := generateTOTPSecret()
	if err != nil {
		return TOTPSetup{}, err
	}
	return TOTPSetup{Secret: secret, OTPAuthURL: totpProvisioningURI(secret, email, s.cfg.totpIssuer())}, nil
}

// totpProvisioningURI renders the otpauth:// URI an authenticator app scans:
//
//	otpauth://totp/<issuer>:<account>?algorithm=SHA1&digits=6&issuer=<issuer>&period=30&secret=<secret>
//
// The label takes otplib's form, which is what the reference emits: its
// `totp.toURI({label: email, issuer: appName, secret})` (totp.strategy.ts:17)
// reaches @otplib/uri's generateTOTP, which builds the label as
// `${issuer}:${label}` whenever an issuer is given and encodes each
// colon-separated piece with encodeURIComponent, so the separator itself stays a
// bare colon (@otplib/uri 13.4.1; the reference pins otplib ^13.3.0). With no
// issuer at all the label is the bare account and the `issuer` parameter is
// omitted, as there.
//
// The parameters are where this port and the reference part company, on
// purpose: otplib leaves algorithm, digits and period out of the URI when they
// are its defaults, and this port spells them out — from the same TOTP*
// constants validateTOTPCode reads — so that a client rendering the URI as a QR
// code cannot enrol against a different step or digit count than the verifier
// checks. Every authenticator app reads the two forms identically.
//
// Values are escaped with escapeURIComponent throughout rather than
// url.QueryEscape, whose "+" for a space in the issuer the reference never
// emits (encodeURIComponent gives %20) and which not every URI parser folds
// back. issuer is Config.totpIssuer(): TwoFactorAppName, else Issuer.
func totpProvisioningURI(secret, account, issuer string) string {
	label := escapeOTPAuthLabel(account)
	if issuer != "" {
		label = escapeOTPAuthLabel(issuer) + ":" + label
	}
	var b strings.Builder
	b.WriteString("otpauth://totp/")
	b.WriteString(label)
	b.WriteString("?algorithm=" + TOTPAlgorithm)
	b.WriteString("&digits=" + strconv.Itoa(TOTPDigits))
	if issuer != "" {
		b.WriteString("&issuer=" + escapeURIComponent(issuer))
	}
	b.WriteString("&period=" + strconv.Itoa(int(TOTPPeriod/time.Second)))
	b.WriteString("&secret=" + escapeURIComponent(secret))
	return b.String()
}

// escapeOTPAuthLabel escapes one half of the otpauth label the way otplib's
// generate does the whole of it: split on ":", encodeURIComponent each piece,
// join with a bare ":". Applying it to the issuer and the account separately
// and joining them with ":" gives the same bytes as applying it once to
// `${issuer}:${account}`, which is what the reference does.
func escapeOTPAuthLabel(s string) string {
	parts := strings.Split(s, ":")
	for i, p := range parts {
		parts[i] = escapeURIComponent(p)
	}
	return strings.Join(parts, ":")
}

// escapeURIComponent escapes a label the way the reference's otplib does, which
// is JavaScript's encodeURIComponent: everything but the unreserved set and
// !'()*~ is percent-encoded, so an account label of an email address carries
// %40 rather than a bare @.
//
// url.PathEscape is the near-miss it replaces: it leaves @ (and :) alone
// because both are legal in a path segment. Authenticator apps accept either
// spelling, so this only matters for a client comparing the URI byte for byte —
// but the reference's spelling is the one three clients have seen.
func escapeURIComponent(s string) string {
	const unreserved = "-_.!~*'()"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			strings.IndexByte(unreserved, c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

// MagicLinkVerifyHTTPError maps a Service.VerifyMagicLink or
// Service.VerifyMagicLinkForUser failure. See HTTPErrInvalidMagicLink for why
// the expiry code does not appear.
func MagicLinkVerifyHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrMagicLinkOwnerMismatch):
		return HTTPErrTokenMismatch
	case errors.Is(err, ErrInvalidToken):
		return HTTPErrInvalidMagicLink
	default:
		return HTTPErrorFor(err)
	}
}

// SMSVerifyHTTPError maps a Service.VerifySMSCode failure.
//
// ErrInvalidCredentials means the userId or tempToken named a user the store
// does not have, and that is 401 "Invalid or expired SMS code", not 404.
// The reference looks the user up inside the strategy, where a miss is
// indistinguishable from a bad code: sms.strategy.ts:24-25 returns false for an
// unknown id, and the router turns false into
// 401 {"error":"Invalid or expired SMS code"} (auth.router.ts:1275-1279). Its
// 404 (:1281-1284) sits *after* that check and only fires if the user vanished
// between the verify and the follow-up findById — a race this port cannot
// reproduce, because Service.VerifySMSCode does both in one call. Answering 404
// here would both change the status a client sees for a stale userId and turn an
// unauthenticated route into a user-existence oracle the reference does not
// have.
func SMSVerifyHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrInvalidCode), errors.Is(err, ErrInvalidCredentials):
		return HTTPErrInvalidSMSCode
	default:
		return HTTPErrorFor(err)
	}
}

// TOTPVerifyHTTPError maps a Service.VerifyTOTP failure (POST /2fa/verify).
func TOTPVerifyHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrInvalidCode):
		return HTTPErrInvalidTOTPCode
	case errors.Is(err, ErrInvalidCredentials):
		return HTTPErrTOTPNotSetUp
	default:
		return HTTPErrorFor(err)
	}
}

// TOTPSetupHTTPError maps a Service.VerifyTOTPSetup failure (POST
// /2fa/verify-setup), where a bad code is a 400 rather than the 401 the
// step-up route answers.
func TOTPSetupHTTPError(err error) HTTPError {
	if errors.Is(err, ErrInvalidCode) {
		return HTTPErrInvalidTOTPSetupCode
	}
	return HTTPErrorFor(err)
}

// StepUpSubject resolves the tempToken a 2FA-mode request carries, reporting
// the envelope to write when it cannot.
//
// The two error arguments are what keeps the reference's inconsistency
// reproducible without spreading it through the handlers: the magic-link and
// SMS routes pass HTTPErrTempTokenRequired and HTTPErrInvalidTempToken, while
// /2fa/verify passes HTTPErrInvalidStepUpToken for both — it has no
// missing-token branch at all, so an absent tempToken simply fails
// verification there.
func (a *Auth) StepUpSubject(tempToken string, missing, invalid HTTPError) (TempTokenSubject, HTTPError, bool) {
	if strings.TrimSpace(tempToken) == "" {
		return TempTokenSubject{}, missing, false
	}
	subject, err := a.service.VerifyTempToken(tempToken)
	if err != nil {
		return TempTokenSubject{}, invalid, false
	}
	return subject, HTTPError{}, true
}

// TwoFactorPolicy reports whether the deployment requires a second factor of
// every user, which is what POST <prefix>/2fa/disable refuses on with 403
// 2FA_REQUIRED. It is the OR of two terms:
//
//   - Config.Require2FA, the static deployment-time switch. It is also a login
//     term (Service.requiresTwoFactor), and it is this port's own: the reference
//     has no config-level require2FA anywhere. That is a wire difference, and it
//     is registered as config-require2fa-is-a-system-policy-term in
//     compatibility.go rather than stated only here.
//   - AuthSettings.Require2FA read from Config.Settings, the run-time switch an
//     administrator flips through the admin Control panel. This is the
//     reference's own term and the only setting it reads on this route
//     (auth.router.ts:890-896).
//
// The static term is checked first and short-circuits, so a deployment that has
// already decided the answer never pays for a store read.
//
// The error is the store failing. It is reported rather than swallowed so that
// the route can fail closed — a settings store that cannot be reached must not
// be read as permission to turn the factor off — and the adapters answer the
// reference generic 500, which is what its handleError does with anything its
// getSettings throws (auth.router.ts:189-195, the catch at :899-901).
//
// It is also logged through Config.Logger before being returned, because the
// 500 the adapters write carries no detail at all — the reference logs the
// error itself before answering the same body (console.error in handleError,
// :193) — and a policy-store outage that leaves nothing in the operator's log is
// indistinguishable from any other 500. A caller that handles the error itself
// gets one log line it did not ask for, which is the cheaper of the two
// mistakes.
//
// The signature grew the context and the error when the settings store landed.
// It was TwoFactorPolicy() bool while the answer came from Config alone, when
// there was nothing to read and nothing to fail; Go has no overloading, so the
// old spelling could only be kept under a different name that nothing would
// call, and it was dropped instead. The CHANGELOG records the break.
func (a *Auth) TwoFactorPolicy(ctx context.Context) (bool, error) {
	return a.service.twoFactorPolicy(ctx)
}

// twoFactorPolicy is TwoFactorPolicy's body, on the Service so that the MCP
// surface can report the same answer without holding an Auth. There is one
// implementation of the policy and this is it.
func (s *Service) twoFactorPolicy(ctx context.Context) (bool, error) {
	if s.cfg.Require2FA {
		return true, nil
	}
	store := s.cfg.Settings
	if store == nil {
		return false, nil
	}
	settings, err := store.GetSettings(ctx)
	if err != nil {
		s.logf("auth: settings store unreachable; the two-factor policy could not be "+
			"resolved and the route it was read from fails closed: %v", err)
		return false, err
	}
	return settings.Require2FA != nil && *settings.Require2FA, nil
}

// SMSConfigured reports whether the deployment can deliver an SMS code.
//
// /sms/send has to ask before it does anything else, because the reference
// checks config.sms at the very top of the route (auth.router.ts:1178-1181) and
// not in the strategy behind it. The ordering is client-visible, and not in a
// cosmetic way: the route answers 200 to an unknown address as an
// anti-enumeration measure, so a handler that only found out at the service call
// would tell an unconfigured deployment's caller "sent" for every address it
// does not have. The magic-link route needs no equivalent — the reference checks
// email configuration inside the strategy there, which Service.SendMagicLink
// reproduces, and WriteServiceError maps the sentinel.
func (a *Auth) SMSConfigured() bool { return a.service.cfg.SendSMSCode != nil }

// IssueTempToken delegates to Service.IssueTempToken.
func (a *Auth) IssueTempToken(ctx context.Context, user User) (string, error) {
	return a.service.IssueTempToken(ctx, user)
}

// FindUser delegates to Service.FindUser.
func (a *Auth) FindUser(ctx context.Context, userID, email, tenantID string) (User, error) {
	return a.service.FindUser(ctx, userID, email, tenantID)
}

// SendMagicLink delegates to Service.SendMagicLink.
func (a *Auth) SendMagicLink(ctx context.Context, in MagicLinkSendInput) (string, error) {
	return a.service.SendMagicLink(ctx, in)
}

// VerifyMagicLink delegates to Service.VerifyMagicLink.
func (a *Auth) VerifyMagicLink(ctx context.Context, in MagicLinkVerifyInput) (User, AuthTokens, error) {
	return a.service.VerifyMagicLink(ctx, in)
}

// VerifyMagicLinkForUser delegates to Service.VerifyMagicLinkForUser. The
// step-up branch of POST /magic-link/verify uses it so that a link belonging to
// another user is refused before a session exists.
func (a *Auth) VerifyMagicLinkForUser(ctx context.Context, in MagicLinkVerifyInput, userID string) (User, AuthTokens, error) {
	return a.service.VerifyMagicLinkForUser(ctx, in, userID)
}

// ConsumeMagicLink delegates to Service.ConsumeMagicLink: verify and burn the
// link, issue nothing, so the caller can refuse before a session exists.
func (a *Auth) ConsumeMagicLink(ctx context.Context, in MagicLinkVerifyInput) (User, error) {
	return a.service.ConsumeMagicLink(ctx, in)
}

// CompleteMagicLinkLogin delegates to Service.CompleteMagicLinkLogin: open the
// session for a user ConsumeMagicLink returned, once the caller has decided to.
func (a *Auth) CompleteMagicLinkLogin(ctx context.Context, user User) (AuthTokens, error) {
	return a.service.CompleteMagicLinkLogin(ctx, user)
}

// SendSMSCode delegates to Service.SendSMSCode.
func (a *Auth) SendSMSCode(ctx context.Context, in SMSCodeSendInput) (string, error) {
	return a.service.SendSMSCode(ctx, in)
}

// VerifySMSCode delegates to Service.VerifySMSCode.
func (a *Auth) VerifySMSCode(ctx context.Context, in SMSCodeVerifyInput) (User, AuthTokens, error) {
	return a.service.VerifySMSCode(ctx, in)
}

// StartTOTPEnrolment delegates to Service.StartTOTPEnrolment.
func (a *Auth) StartTOTPEnrolment(ctx context.Context, userID, tenantID string) (TOTPSetup, error) {
	return a.service.StartTOTPEnrolment(ctx, userID, tenantID)
}

// NewTOTPEnrolment delegates to Service.NewTOTPEnrolment. The adapters' POST
// <prefix>/2fa/setup calls it with the email of the principal the auth
// middleware verified.
func (a *Auth) NewTOTPEnrolment(email string) (TOTPSetup, error) {
	return a.service.NewTOTPEnrolment(email)
}

// VerifyTOTPSetup delegates to Service.VerifyTOTPSetup.
func (a *Auth) VerifyTOTPSetup(ctx context.Context, userID, tenantID, secret, code string) error {
	return a.service.VerifyTOTPSetup(ctx, userID, tenantID, secret, code)
}

// VerifyTOTP delegates to Service.VerifyTOTP.
func (a *Auth) VerifyTOTP(ctx context.Context, userID, tenantID, code string) (User, AuthTokens, error) {
	return a.service.VerifyTOTP(ctx, userID, tenantID, code)
}

// DisableTOTP delegates to Service.DisableTOTP.
func (a *Auth) DisableTOTP(ctx context.Context, userID, tenantID string) error {
	return a.service.DisableTOTP(ctx, userID, tenantID)
}
