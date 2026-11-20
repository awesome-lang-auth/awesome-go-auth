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
// ErrUserNotFound is the reference's 404 "User not found": the auth gate lets a
// token through whose user has been deleted, as the reference's does, and the
// handler's own lookup misses (auth.router.ts:1471-1474 at v1.10.8). It is
// tested before ErrInvalidCredentials, which it wraps and which is the wrong
// current password's 401 "Current password is incorrect".
func ChangePasswordHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrUserNotFound):
		return HTTPErrUserNotFound
	case errors.Is(err, ErrNewPasswordRequired):
		return HTTPErrNewPasswordRequired
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
// ErrUserNotFound is the reference's 404 "User not found" for a token whose user
// has been deleted (auth.router.ts:1519-1521 at v1.10.8), reachable since the
// auth gate stopped reading the user store (#31).
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
		// ErrUserNotFound, and the bare sentinel a host wrapper may still return
		// for the same case.
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

// ChangeEmailRequestHTTPError maps an Auth.RequestEmailChange failure.
//
// ErrUserNotFound is the reference's 404 for a token whose user has been
// deleted (auth.router.ts:1591-1594 at v1.10.8), and ErrPasswordRequired its
// 403 PASSWORD_REQUIRED (:1595-1601).
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
	case errors.Is(err, ErrPasswordRequired):
		return HTTPErrPasswordRequired
	case errors.Is(err, ErrInvalidCredentials):
		// ErrUserNotFound, which wraps it.
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

// ChangePasswordInlineError reproduces the inline validation /change-password
// had at awesome-node-auth@cc01e997: an account with no stored password that
// submits neither field gets 400 "New password is required".
//
// Deprecated: Service.ChangePassword now makes this check itself, in the
// reference's v1.10.8 order — after the user lookup and for every account, not
// only a passwordless one (auth.router.ts:1471-1479) — and answers it as
// ErrNewPasswordRequired, which ChangePasswordHTTPError maps to the same 400.
// The adapters no longer call this. It also reads user.PasswordHash, which the
// user the auth middleware puts in context does not carry since #31.
func ChangePasswordInlineError(user User, currentPassword, newPassword string) (HTTPError, bool) {
	if user.PasswordHash == "" && currentPassword == "" && newPassword == "" {
		return HTTPErrNewPasswordRequired, true
	}
	return HTTPError{}, false
}

// ChangeEmailInlineError reproduces the reference's PASSWORD_REQUIRED guard on
// /change-email/request: an account whose only credential is the address itself
// may not move that address (auth.router.ts:1595-1601 at v1.10.8).
//
// Deprecated: Auth.RequestEmailChange makes this check itself now, against the
// stored row and in the reference's order — after the 409 and 404 branches —
// and answers it as ErrPasswordRequired, which ChangeEmailRequestHTTPError maps
// to the same 403. The adapters no longer call this. The user the auth
// middleware puts in context is built from the token since #31 and carries no
// password hash, so calling this with it refuses every account.
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

// ChangePassword performs POST /change-password. It delegates to
// Service.ChangePassword, which since #30 lets a passwordless account —
// OAuth-only, or magic-link-only — set its first password without presenting
// one, as the reference does (auth.router.ts:1480-1489 at v1.10.8). This method
// used to carry that half itself, and it raised no
// identity.user.password.changed for it; the service raises it for both.
func (a *Auth) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	return a.service.ChangePassword(ctx, in)
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

// RequestEmailChange performs POST /change-email/request: Service.RequestEmailChange
// plus the reference's PASSWORD_REQUIRED guard, which refuses an account with
// no password with ErrPasswordRequired. The guard runs after the 409 and 404
// branches and before anything is stored, the reference's order
// (auth.router.ts:1586-1601 at v1.10.8). It reads the stored row, because the
// user the auth middleware puts in context is built from the token and carries
// no password hash (#31).
func (a *Auth) RequestEmailChange(ctx context.Context, in ChangeEmailRequestInput) (string, error) {
	return a.service.requestEmailChange(ctx, in, true)
}

// ConfirmEmailChange delegates to Service.ConfirmEmailChange.
func (a *Auth) ConfirmEmailChange(ctx context.Context, in ConfirmEmailChangeInput) error {
	return a.service.ConfirmEmailChange(ctx, in)
}
