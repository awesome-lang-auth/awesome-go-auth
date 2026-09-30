package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// This file holds the wire conventions for the password-management and
// email-verification group: forgot-password, reset-password, change-password,
// send-verification-email, GET verify-email, change-email/request and
// change-email/confirm.
//
// The shapes are wire-contract §2, extracted from awesome-node-auth@cc01e997
// (src/router/auth.router.ts:777-1071). The catalog, the mappers and the inline
// validations live in the root package for the same reason the rest of wire.go
// does: four adapters serve these routes and none of them may answer
// differently.
//
// Two properties of this group are load-bearing and easy to lose:
//
//   - /forgot-password answers 200 {"success":true} for an unknown address,
//     because leaking which addresses exist is the failure mode the route was
//     written to avoid (auth.router.ts:794-795).
//   - /change-email/request deliberately does the opposite: it answers 409 to an
//     authenticated caller naming an address in use (auth.router.ts:1005-1009).
//     The asymmetry is the reference's, and harmonising either side would change
//     behaviour a shipped client already relies on.
//
// None of these routes issues or clears a token, so bearer-vs-cookie delivery
// does not apply: the only bearer-mode difference is that the auth gate and the
// CSRF check treat a bearer caller as a non-cookie client.

// CodePasswordRequired is the one coded error in this group. Every other failure
// here is code-less in the reference, and a client is documented not to
// pattern-match on an absent code.
const CodePasswordRequired = "PASSWORD_REQUIRED"

// The §2 error catalog. Messages are the reference's own strings, down to the
// "UserStore does not implement …" wording it uses for an incapable store.
var (
	// HTTPErrResetTokenStoreMissing and the two below it are 500, not 501: the
	// reference reports a store that cannot perform the flow as an internal
	// error (auth.router.ts:805-808, 937-940, 1000-1003, 1042-1045). A client
	// that treats 501 as "feature absent" and 500 as "server broken" therefore
	// has to see 500 here, which is why these routes do not go through
	// HTTPErrorFor's ErrFeatureNotSupported → 501 mapping.
	HTTPErrResetTokenStoreMissing        = HTTPError{Status: http.StatusInternalServerError, Message: "UserStore does not implement findByResetToken"}
	HTTPErrEmailVerificationStoreMissing = HTTPError{Status: http.StatusInternalServerError, Message: "UserStore does not implement email verification"}
	HTTPErrChangeEmailStoreMissing       = HTTPError{Status: http.StatusInternalServerError, Message: "UserStore does not implement change-email"}

	HTTPErrInvalidResetToken       = HTTPError{Status: http.StatusBadRequest, Message: "Invalid reset token"}
	HTTPErrInvalidVerifyToken      = HTTPError{Status: http.StatusBadRequest, Message: "Invalid verification token"}
	HTTPErrInvalidEmailChangeToken = HTTPError{Status: http.StatusBadRequest, Message: "Invalid email-change token"}
	HTTPErrVerifyTokenRequired     = HTTPError{Status: http.StatusBadRequest, Message: "Token is required"}
	HTTPErrEmailAlreadyVerified    = HTTPError{Status: http.StatusBadRequest, Message: "Email is already verified"}

	// HTTPErrCurrentPasswordIncorrect is a 401 with no code, unlike the coded
	// INVALID_CREDENTIALS a failed login returns. Reproduced as-is even though it
	// is a known hazard: /change-password is absent from the Angular
	// interceptor's no-retry list, so a wrong current password costs a pointless
	// refresh-and-replay round trip (wire-contract §2, [MISMATCH]).
	HTTPErrCurrentPasswordIncorrect = HTTPError{Status: http.StatusUnauthorized, Message: "Current password is incorrect"}
	HTTPErrNewPasswordRequired      = HTTPError{Status: http.StatusBadRequest, Message: "New password is required"}

	// HTTPErrEmailInUse carries no code, so a client cannot branch on it — only
	// on the 409 status.
	HTTPErrEmailInUse = HTTPError{Status: http.StatusConflict, Message: "Email address is already in use"}

	HTTPErrPasswordRequired = HTTPError{
		Status:  http.StatusForbidden,
		Message: "You must set a password before you can change your email address.",
		Code:    CodePasswordRequired,
	}
)

// ForgotPasswordHTTPError maps a Service.ForgotPassword failure.
//
// Every failure is a bare 500: the reference has no error branch on this route
// at all, so a throwing store reaches handleError and becomes
// {"error":"Internal server error"} (auth.router.ts:796-798). ErrFeatureNotSupported
// is included on purpose — a store that cannot persist a reset token is a
// deployment fault, not a feature the caller can be told about, and answering
// 501 would tell an anonymous caller something the 200-always rule is there to
// hide.
//
// A failed *delivery* never reaches this mapper: Auth.ForgotPassword absorbs it
// so the route keeps answering 200. See there for why that one diverges.
func ForgotPasswordHTTPError(error) HTTPError { return HTTPErrInternal }

// ResetPasswordHTTPError maps a Service.ResetPassword failure.
func ResetPasswordHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		return HTTPErrResetTokenStoreMissing
	case errors.Is(err, ErrInvalidToken):
		return HTTPErrInvalidResetToken
	case errors.Is(err, ErrWeakPassword):
		// Port-only: the reference applies no password policy on this route.
		return HTTPErrWeakPassword
	default:
		return HTTPErrInternal
	}
}

// ChangePasswordHTTPError maps a Service.ChangePassword failure.
//
// ErrInvalidCredentials becomes 401 "Current password is incorrect" rather than
// the reference's 404 "User not found", because the service returns the same
// sentinel for both and the auth middleware resolved this user from the store
// moments earlier: a wrong password is the reachable case, a row that vanished
// in between is not.
func ChangePasswordHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return HTTPErrCurrentPasswordIncorrect
	case errors.Is(err, ErrWeakPassword):
		// Port-only: the reference applies no password policy on this route.
		return HTTPErrWeakPassword
	default:
		return HTTPErrInternal
	}
}

// SendVerificationEmailHTTPError maps a Service.SendVerificationEmailToken failure.
//
// The 404 "User not found" branch is not reachable over HTTP in this port and is
// kept only for a store race: the reference's auth gate trusts the JWT and never
// reads the store (auth.middleware.ts:60), so its handler's own lookup can miss
// and answer 404, whereas this port's gate resolves the user through Me() and
// answers 403 "Invalid or expired access token" for a row that no longer exists.
// The divergence belongs to the shared middleware, not to this route.
func SendVerificationEmailHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrDeliveryFailed):
		// A failed send is the reference's generic 500 and nothing else. This case
		// comes first because the delivery wrapper joins the transport's own error
		// rather than replacing it, so without it a host sender that returned (or
		// wrapped) a library sentinel would pick this route's wire answer for it —
		// a mail gateway is not entitled to answer 404 "User not found" for an
		// authenticated user who exists.
		return HTTPErrInternal
	case errors.Is(err, ErrFeatureNotSupported):
		return HTTPErrEmailVerificationStoreMissing
	case errors.Is(err, ErrInvalidCredentials):
		return HTTPErrUserNotFound
	default:
		return HTTPErrInternal
	}
}

// VerifyEmailHTTPError maps a Service.VerifyEmail failure.
func VerifyEmailHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		return HTTPErrEmailVerificationStoreMissing
	case errors.Is(err, ErrInvalidToken):
		return HTTPErrInvalidVerifyToken
	default:
		return HTTPErrInternal
	}
}

// ChangeEmailRequestHTTPError maps a Service.RequestEmailChange failure.
//
// As on /send-verification-email, the 404 branch is a store-race path only: this
// port's auth gate answers 403 where the reference's handler would answer 404.
func ChangeEmailRequestHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrDeliveryFailed):
		// As on /send-verification-email, and it matters more here: without this
		// case a sender that returned ErrUserExists would turn a failed send into
		// 409 "Email address is already in use" about an address that is free,
		// which is both a false answer and an oracle the caller never asked for.
		return HTTPErrInternal
	case errors.Is(err, ErrFeatureNotSupported):
		return HTTPErrChangeEmailStoreMissing
	case errors.Is(err, ErrUserExists), errors.Is(err, ErrAlreadyExists):
		// Not the catalog's 409 USER_EXISTS: this route's 409 is code-less and
		// says "Email address is already in use".
		return HTTPErrEmailInUse
	case errors.Is(err, ErrInvalidCredentials):
		return HTTPErrUserNotFound
	default:
		return HTTPErrInternal
	}
}

// ChangeEmailConfirmHTTPError maps a Service.ConfirmEmailChange failure.
func ChangeEmailConfirmHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		return HTTPErrChangeEmailStoreMissing
	case errors.Is(err, ErrInvalidToken):
		return HTTPErrInvalidEmailChangeToken
	default:
		return HTTPErrInternal
	}
}

// ChangePasswordInlineError reproduces the reference's inline validation on
// /change-password: an account with no stored password that submits neither
// field gets 400 "New password is required" (auth.router.ts:922-925). An account
// that does have a password never reaches it — a missing current password fails
// the comparison instead.
func ChangePasswordInlineError(user User, currentPassword, newPassword string) (HTTPError, bool) {
	if user.PasswordHash == "" && currentPassword == "" && newPassword == "" {
		return HTTPErrNewPasswordRequired, true
	}
	return HTTPError{}, false
}

// ChangeEmailInlineError reproduces the reference's PASSWORD_REQUIRED guard on
// /change-email/request: an account whose only credential is the address itself
// may not move that address (auth.router.ts:1015-1021).
//
// The reference runs this check after the 409 and 404 branches; here it runs
// before them, because the service persists the pending change in the same call
// that would report those two failures and there is no point at which the guard
// could still run without leaving a token behind. The status and code are
// therefore exact, and only the precedence between two simultaneous failures
// differs.
func ChangeEmailInlineError(user User) (HTTPError, bool) {
	if user.PasswordHash == "" {
		return HTTPErrPasswordRequired, true
	}
	return HTTPError{}, false
}

// VerifyEmailToken reads the token GET /verify-email carries. It is a query
// parameter, not a body field, and the route is the only GET in this group.
//
// The value is used exactly as sent: the reference tests it with `if (!token)`
// (auth.router.ts:972), so a token of one space is truthy there and fails the
// lookup with 400 "Invalid verification token" rather than 400 "Token is
// required". Trimming here would be friendlier but would move that request into
// the other error, so the reference's answer wins.
func VerifyEmailToken(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.Query().Get("token")
}

// DecodeOptionalJSON decodes a JSON request body into dst, tolerating an absent
// or empty one, and writes the error envelope when the body is present but
// malformed.
//
// It is the one decoder every body-reading auth route of the four adapters
// uses — this group, /register, /login, /link-request, /link-verify and the
// passwordless and TOTP step-up routes — so that they agree with each other and
// with the reference. The reference runs express.json(), which leaves req.body as
// {} rather than failing, and since v1.10.5 every route reads `req.body ?? {}`
// (awesome-node-auth CHANGELOG 1.10.5, issue #21): an absent body reaches each
// route's own per-field check. The Flutter client posts
// /send-verification-email with no body at all. A body that is present but is
// not JSON is refused: express.json() refuses it too, and the port answers with
// its own 400 INVALID_BODY envelope.
func DecodeOptionalJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r == nil || r.Body == nil {
		return true
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return true
		}
		WriteHTTPError(w, HTTPErrInvalidBody)
		return false
	}
	return true
}

// ForgotPassword delegates to Service.ForgotPassword and then throws away one
// class of failure: a send that failed after the token was stored. The route
// answers 200 {"success":true} for it, exactly as it does for an address that does
// not exist.
//
// This is a deliberate divergence, and the only one on this route. The
// reference's send sits inside the route's try block, so a throwing mailer reaches
// handleError and answers 500 (auth.router.ts:787-798) — which means a known
// address 500s while an unknown one 200s, and an attacker with a broken mail
// gateway has the enumeration oracle the route exists to deny. The spec records
// exactly that and marks it [UNTESTED] (wire-contract §2, "Anti-enumeration
// caveat: a throwing mailer produces a 500 only for existing users, which is an
// observable oracle"), so no client can depend on it. The port already refuses to
// ship an oracle the reference leaves open elsewhere — SMSVerifyHTTPError answers
// 401 where the reference would answer 404 for the same reason.
//
// Store failures are NOT swallowed: those still 500, and that oracle *is*
// reproduced (see ForgotPasswordHTTPError and the suite case that pins it). The
// difference is that a store that cannot persist a reset token has minted no
// credential and served no request correctly, while a stored-but-undelivered token
// is harmless — unguessable, single-use, expiring — so silence costs the caller
// nothing but a mail that never arrives.
//
// Divergence from Service.ForgotPassword is the same arrangement as
// Auth.ChangePassword's: the Auth methods are the HTTP surface, and a library
// consumer calling the service directly still learns that delivery failed.
func (a *Auth) ForgotPassword(ctx context.Context, in ForgotPasswordInput) (string, error) {
	token, err := a.service.ForgotPassword(ctx, in)
	if errors.Is(err, ErrDeliveryFailed) {
		// Logged, because the wire deliberately cannot report it: a deployment
		// whose mail gateway is down would otherwise see nothing but 200s while no
		// reset mail arrives. This is the arrangement the link-token delivery
		// already uses for the same swallow (see LinkStart). The address is left
		// out on purpose — the route's whole job is not to say who is registered,
		// and that applies to the log too.
		a.service.logf("auth: password reset delivery failed; the route still answered success: %v", err)
		// Nothing is returned to the caller either way — the route may not put a
		// reset token in a body — so this is indistinguishable from the
		// unknown-address path, which is the point.
		return "", nil
	}
	return token, err
}

// ResetPassword delegates to Service.ResetPassword.
func (a *Auth) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	return a.service.ResetPassword(ctx, in)
}

// ChangePassword performs POST /change-password.
//
// A passwordless account — OAuth-only, or magic-link-only — skips the
// current-password comparison entirely and may set an initial password by
// supplying newPassword alone: in the reference the compare sits inside
// `if (user.password)` and the `else if` only fires when *both* fields are
// falsy, so such a caller falls through to the hash-and-store (wire-contract §2
// "Passwordless-account path", auth.router.ts:916-928). It is the only way an
// account with no password ever acquires one.
//
// Service.ChangePassword compares unconditionally (service.go:276), and
// verifyPassword("", "") is a bcrypt error, so delegating the passwordless case
// to it reports a password the account does not have as incorrect. The
// passwordless half is therefore handled here rather than by widening
// Service.ChangePassword: a library consumer calling the service directly may
// deliberately not want a caller setting a password without presenting one, and
// this PR's contract is the HTTP surface. The service-level divergence is filed
// upstream.
func (a *Auth) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	s := a.service
	user, err := s.users.GetUserByID(ctx, in.UserID, in.TenantID)
	if err != nil {
		// The sentinel Service.ChangePassword returns for an unresolvable user;
		// ChangePasswordHTTPError turns it into the reference's 401. Unreachable
		// behind the auth gate, which resolves the same row a moment earlier.
		return ErrInvalidCredentials
	}
	if user.PasswordHash != "" {
		return s.ChangePassword(ctx, in)
	}
	if len(in.NewPassword) < s.cfg.MinPasswordLen {
		// Port-only policy, exactly as in Service.ChangePassword; the reference
		// applies none on this route.
		return ErrWeakPassword
	}
	ps, ok := s.users.(UserPasswordStore)
	if !ok {
		// 500 "Internal server error", which is what the reference's unguarded
		// call to a missing updatePassword produces too.
		return ErrFeatureNotSupported
	}
	pwHash, err := hashPassword(in.NewPassword, s.cfg.BcryptCost)
	if err != nil {
		return err
	}
	return ps.UpdatePassword(ctx, user.ID, user.TenantID, pwHash)
}

// SendVerificationEmailToken delegates to Service.SendVerificationEmailToken. An
// empty token with no error means the address is already verified.
func (a *Auth) SendVerificationEmailToken(ctx context.Context, in EmailVerificationInput) (string, error) {
	return a.service.SendVerificationEmailToken(ctx, in)
}

// VerifyEmail delegates to Service.VerifyEmail.
func (a *Auth) VerifyEmail(ctx context.Context, in VerifyEmailInput) error {
	return a.service.VerifyEmail(ctx, in)
}

// RequestEmailChange delegates to Service.RequestEmailChange.
func (a *Auth) RequestEmailChange(ctx context.Context, in ChangeEmailRequestInput) (string, error) {
	return a.service.RequestEmailChange(ctx, in)
}

// ConfirmEmailChange delegates to Service.ConfirmEmailChange.
func (a *Auth) ConfirmEmailChange(ctx context.Context, in ConfirmEmailChangeInput) error {
	return a.service.ConfirmEmailChange(ctx, in)
}
