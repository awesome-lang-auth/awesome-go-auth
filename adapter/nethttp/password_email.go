package nethttp

import (
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// Handlers for the password-management and email-verification group
// (wire-contract §2). The mappers, the catalog and the inline validations they
// call live in the root package's wire_password_email.go so that chi, gin and
// echo answer identically.
//
// None of these routes issues or clears a token, so none of them writes a
// cookie: the CSRF cookie the guard distributes is the only Set-Cookie a caller
// can see here.

type forgotPasswordRequest struct {
	Email    string `json:"email"`
	TenantID string `json:"tenantId"`
	// EmailLang selects the language of the mail, as in the reference
	// (auth.router.ts:779). It reaches the sender untouched as the delivery's
	// Lang; the ready-made mailers honour "it" and "en" and fall back to their
	// Locale for anything else.
	EmailLang string `json:"emailLang"`
}

// linkBase resolves the base an emailed link is built under for this request:
// the request's Origin or Referer matched against the site URL allowlist, then
// the mount prefix (and /ui under HTTPConfig.UIEnabled) — the reference's
// buildUiLink(resolveSiteUrl(req, …), …) pair (auth.router.ts:785-786). Empty
// when no site URL is configured, which leaves a ready-made mailer on its
// static BaseURL.
func (a *Adapter) linkBase(r *http.Request) string {
	return a.cfg.LinkBase(a.auth.ResolveSiteURL(r))
}

type resetPasswordRequest struct {
	Token string `json:"token"`
	// Password, not newPassword: the field name is what the served auth.js and
	// the Flutter client both send.
	Password string `json:"password"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

type sendVerificationEmailRequest struct {
	EmailLang string `json:"emailLang"`
}

type changeEmailRequestRequest struct {
	NewEmail  string `json:"newEmail"`
	EmailLang string `json:"emailLang"`
}

type tokenRequest struct {
	Token string `json:"token"`
}

// ForgotPassword handles POST <prefix>/forgot-password.
//
// It answers 200 {"success":true} whether or not the address exists. That is the
// whole point of the route and a reference test pins it, so an unknown-address
// branch must never become observable — not as a status, not as a body, not as a
// timing-free 404.
func (a *Adapter) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotPasswordRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	// The reset token is deliberately discarded here: it is a credential, so it
	// may not reach the response body. Delivery happens inside the service,
	// through Config.SendPasswordReset; a deployment that wired no sender behaves
	// like a reference deployment with no email block — the route succeeds and no
	// mail goes out. A sender that fails does not change the answer either, which
	// is Auth.ForgotPassword's doing.
	in := auth.ForgotPasswordInput{
		Email:    req.Email,
		TenantID: req.TenantID,
		LinkBase: a.linkBase(r),
		Lang:     req.EmailLang,
	}
	if _, err := a.auth.ForgotPassword(r.Context(), in); err != nil {
		auth.WriteHTTPError(w, auth.ForgotPasswordHTTPError(err))
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// ResetPassword handles POST <prefix>/reset-password. The token is single-use:
// the service clears it after the password is written.
func (a *Adapter) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	if err := a.auth.ResetPassword(r.Context(), auth.ResetPasswordInput{Token: req.Token, NewPassword: req.Password}); err != nil {
		auth.WriteHTTPError(w, auth.ResetPasswordHTTPError(err))
		return
	}
	// No session is revoked and no cookie is cleared, exactly as in the
	// reference: a password reset leaves existing sessions alive.
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// ChangePassword handles POST <prefix>/change-password. It is authenticated and
// CSRF-checked in cookie mode.
func (a *Adapter) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
		return
	}
	var req changePasswordRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	in := auth.ChangePasswordInput{
		UserID:          user.ID,
		TenantID:        user.TenantID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}
	if err := a.auth.ChangePassword(r.Context(), in); err != nil {
		auth.WriteHTTPError(w, auth.ChangePasswordHTTPError(err))
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// SendVerificationEmail handles POST <prefix>/send-verification-email. It is
// authenticated, and an empty body is valid — the Flutter client sends none.
func (a *Adapter) SendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
		return
	}
	var req sendVerificationEmailRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	in := auth.EmailVerificationInput{
		UserID:   user.ID,
		TenantID: user.TenantID,
		LinkBase: a.linkBase(r),
		Lang:     req.EmailLang,
	}
	token, err := a.auth.SendVerificationEmailToken(r.Context(), in)
	if err != nil {
		auth.WriteHTTPError(w, auth.SendVerificationEmailHTTPError(err))
		return
	}
	if token == "" {
		// An already-verified address is not an error to the service, which
		// reports it by issuing no token. The reference answers 400 here.
		auth.WriteHTTPError(w, auth.HTTPErrEmailAlreadyVerified)
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// VerifyEmail handles GET <prefix>/verify-email?token=…
//
// It always answers JSON. The reference performs no content negotiation and no
// redirect on this route; the HTML experience belongs to the optional static UI,
// which fetches this endpoint client-side and renders the JSON it gets back.
func (a *Adapter) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := auth.VerifyEmailToken(r)
	if token == "" {
		auth.WriteHTTPError(w, auth.HTTPErrVerifyTokenRequired)
		return
	}
	if err := a.auth.VerifyEmail(r.Context(), auth.VerifyEmailInput{Token: token}); err != nil {
		auth.WriteHTTPError(w, auth.VerifyEmailHTTPError(err))
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// ChangeEmailRequest handles POST <prefix>/change-email/request. It is
// authenticated and CSRF-checked in cookie mode.
//
// Unlike /forgot-password this route does reveal that an address is taken, with
// a 409. The asymmetry is the reference's and is reproduced deliberately.
func (a *Adapter) ChangeEmailRequest(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
		return
	}
	var req changeEmailRequestRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	if httpErr, refused := auth.ChangeEmailInlineError(user); refused {
		auth.WriteHTTPError(w, httpErr)
		return
	}
	// The change token is discarded for the same reason the reset token is: it is
	// a credential. The service mails it to the *new* address through
	// Config.SendEmailChange, and unlike /forgot-password a failed send here is
	// the reference's generic 500.
	in := auth.ChangeEmailRequestInput{
		UserID:   user.ID,
		TenantID: user.TenantID,
		NewEmail: req.NewEmail,
		LinkBase: a.linkBase(r),
		Lang:     req.EmailLang,
	}
	if _, err := a.auth.RequestEmailChange(r.Context(), in); err != nil {
		auth.WriteHTTPError(w, auth.ChangeEmailRequestHTTPError(err))
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// ChangeEmailConfirm handles POST <prefix>/change-email/confirm.
//
// It is unauthenticated and CSRF-exempt on purpose: the emailed token is the
// credential, so the link has to work from a browser that carries no session and
// no CSRF cookie at all.
func (a *Adapter) ChangeEmailConfirm(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	if err := a.auth.ConfirmEmailChange(r.Context(), auth.ConfirmEmailChangeInput{Token: req.Token}); err != nil {
		auth.WriteHTTPError(w, auth.ChangeEmailConfirmHTTPError(err))
		return
	}
	// The access token still carries the old address until it is refreshed, and
	// no session is revoked — the reference does neither.
	auth.WriteSuccess(w, http.StatusOK, nil)
}
