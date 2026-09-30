package echo

import (
	"net/http"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
)

// Handlers for the password-management and email-verification group
// (wire-contract §2), mounted by mountPasswordEmail below.
//
// Bodies are decoded with auth.DecodeOptionalJSON rather than echo's Bind, for
// the same reason gin's are: every route in this group accepts an empty body,
// and one shared decoder is what keeps that true of all four adapters.

// mountPasswordEmail attaches the §2 routes.
func (ad *Adapter) mountPasswordEmail(group *echo.Group, prefix string) {
	group.POST(prefix+"/forgot-password", ad.guard(ad.forgotPassword))
	group.POST(prefix+"/reset-password", ad.guard(ad.resetPassword))
	group.POST(prefix+"/change-password", ad.guard(ad.Middleware()(ad.changePassword)))
	group.POST(prefix+"/send-verification-email", ad.guard(ad.Middleware()(ad.sendVerificationEmail)))
	group.GET(prefix+"/verify-email", ad.guard(ad.verifyEmail))
	group.POST(prefix+"/change-email/request", ad.guard(ad.Middleware()(ad.changeEmailRequest)))
	group.POST(prefix+"/change-email/confirm", ad.guard(ad.changeEmailConfirm))
}

// linkBase resolves the base an emailed link is built under for this request —
// the request's Origin or Referer against the site URL allowlist, then the
// mount prefix — exactly as the net/http adapter does, so the four adapters mail
// the same link for the same request. Empty when no site URL is configured.
func (ad *Adapter) linkBase(r *http.Request) string {
	return ad.cfg.LinkBase(ad.auth.ResolveSiteURL(r))
}

// forgotPassword always answers 200 {"success":true}, unknown address included:
// the anti-enumeration guarantee is the reason the route exists.
func (ad *Adapter) forgotPassword(c echo.Context) error {
	var req struct {
		Email     string `json:"email"`
		TenantID  string `json:"tenantId"`
		EmailLang string `json:"emailLang"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	// The reset token is a credential: it never reaches the body. The service
	// delivers it through Config.SendPasswordReset, and neither a missing sender
	// nor a failing one changes this answer.
	in := auth.ForgotPasswordInput{
		Email:    req.Email,
		TenantID: req.TenantID,
		LinkBase: ad.linkBase(c.Request()),
		Lang:     req.EmailLang,
	}
	if _, err := ad.auth.ForgotPassword(c.Request().Context(), in); err != nil {
		auth.WriteHTTPError(c.Response(), auth.ForgotPasswordHTTPError(err))
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

func (ad *Adapter) resetPassword(c echo.Context) error {
	var req struct {
		Token string `json:"token"`
		// password, not newPassword — the field name the family clients send.
		Password string `json:"password"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	if err := ad.auth.ResetPassword(c.Request().Context(), auth.ResetPasswordInput{Token: req.Token, NewPassword: req.Password}); err != nil {
		auth.WriteHTTPError(c.Response(), auth.ResetPasswordHTTPError(err))
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

func (ad *Adapter) changePassword(c echo.Context) error {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrNoAccessToken)
		return nil
	}
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	in := auth.ChangePasswordInput{
		UserID:          user.ID,
		TenantID:        user.TenantID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}
	if err := ad.auth.ChangePassword(c.Request().Context(), in); err != nil {
		auth.WriteHTTPError(c.Response(), auth.ChangePasswordHTTPError(err))
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

func (ad *Adapter) sendVerificationEmail(c echo.Context) error {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrNoAccessToken)
		return nil
	}
	var req struct {
		EmailLang string `json:"emailLang"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	in := auth.EmailVerificationInput{
		UserID:   user.ID,
		TenantID: user.TenantID,
		LinkBase: ad.linkBase(c.Request()),
		Lang:     req.EmailLang,
	}
	token, err := ad.auth.SendVerificationEmailToken(c.Request().Context(), in)
	if err != nil {
		auth.WriteHTTPError(c.Response(), auth.SendVerificationEmailHTTPError(err))
		return nil
	}
	if token == "" {
		// The service reports an already-verified address by issuing no token.
		auth.WriteHTTPError(c.Response(), auth.HTTPErrEmailAlreadyVerified)
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

// verifyEmail always answers JSON: no content negotiation, no redirect.
func (ad *Adapter) verifyEmail(c echo.Context) error {
	token := auth.VerifyEmailToken(c.Request())
	if token == "" {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrVerifyTokenRequired)
		return nil
	}
	if err := ad.auth.VerifyEmail(c.Request().Context(), auth.VerifyEmailInput{Token: token}); err != nil {
		auth.WriteHTTPError(c.Response(), auth.VerifyEmailHTTPError(err))
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

// changeEmailRequest does reveal that an address is taken, with a 409 — the
// deliberate opposite of /forgot-password.
func (ad *Adapter) changeEmailRequest(c echo.Context) error {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrNoAccessToken)
		return nil
	}
	var req struct {
		NewEmail  string `json:"newEmail"`
		EmailLang string `json:"emailLang"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	if httpErr, refused := auth.ChangeEmailInlineError(user); refused {
		auth.WriteHTTPError(c.Response(), httpErr)
		return nil
	}
	in := auth.ChangeEmailRequestInput{
		UserID:   user.ID,
		TenantID: user.TenantID,
		NewEmail: req.NewEmail,
		LinkBase: ad.linkBase(c.Request()),
		Lang:     req.EmailLang,
	}
	if _, err := ad.auth.RequestEmailChange(c.Request().Context(), in); err != nil {
		auth.WriteHTTPError(c.Response(), auth.ChangeEmailRequestHTTPError(err))
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

// changeEmailConfirm is unauthenticated and CSRF-exempt: the emailed token is
// the credential, so the link works from any browser.
func (ad *Adapter) changeEmailConfirm(c echo.Context) error {
	var req struct {
		Token string `json:"token"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	if err := ad.auth.ConfirmEmailChange(c.Request().Context(), auth.ConfirmEmailChangeInput{Token: req.Token}); err != nil {
		auth.WriteHTTPError(c.Response(), auth.ChangeEmailConfirmHTTPError(err))
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}
