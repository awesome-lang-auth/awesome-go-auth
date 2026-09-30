package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
)

// Handlers for the password-management and email-verification group
// (wire-contract §2), mounted by mountPasswordEmail below.
//
// Bodies are decoded with auth.DecodeOptionalJSON rather than gin's
// ShouldBindJSON: every route in this group accepts an empty body — the Flutter
// client posts /send-verification-email with none — and gin's binder reports
// that as an error. Sharing the decoder is what keeps "empty body is valid"
// true of all four adapters.

// mountPasswordEmail attaches the §2 routes.
func (ad *Adapter) mountPasswordEmail(group gin.IRoutes, prefix string) {
	group.POST(prefix+"/forgot-password", ad.guard(ad.forgotPassword))
	group.POST(prefix+"/reset-password", ad.guard(ad.resetPassword))
	group.POST(prefix+"/change-password", ad.guard(ad.Middleware()), ad.changePassword)
	group.POST(prefix+"/send-verification-email", ad.guard(ad.Middleware()), ad.sendVerificationEmail)
	group.GET(prefix+"/verify-email", ad.guard(ad.verifyEmail))
	group.POST(prefix+"/change-email/request", ad.guard(ad.Middleware()), ad.changeEmailRequest)
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
func (ad *Adapter) forgotPassword(c *gin.Context) {
	var req struct {
		Email     string `json:"email"`
		TenantID  string `json:"tenantId"`
		EmailLang string `json:"emailLang"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	// The reset token is a credential: it never reaches the body. The service
	// delivers it through Config.SendPasswordReset, and neither a missing sender
	// nor a failing one changes this answer.
	in := auth.ForgotPasswordInput{
		Email:    req.Email,
		TenantID: req.TenantID,
		LinkBase: ad.linkBase(c.Request),
		Lang:     req.EmailLang,
	}
	if _, err := ad.auth.ForgotPassword(c.Request.Context(), in); err != nil {
		auth.WriteHTTPError(c.Writer, auth.ForgotPasswordHTTPError(err))
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) resetPassword(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
		// password, not newPassword — the field name the family clients send.
		Password string `json:"password"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	if err := ad.auth.ResetPassword(c.Request.Context(), auth.ResetPasswordInput{Token: req.Token, NewPassword: req.Password}); err != nil {
		auth.WriteHTTPError(c.Writer, auth.ResetPasswordHTTPError(err))
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) changePassword(c *gin.Context) {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
		return
	}
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	in := auth.ChangePasswordInput{
		UserID:          user.ID,
		TenantID:        user.TenantID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}
	if err := ad.auth.ChangePassword(c.Request.Context(), in); err != nil {
		auth.WriteHTTPError(c.Writer, auth.ChangePasswordHTTPError(err))
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) sendVerificationEmail(c *gin.Context) {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
		return
	}
	var req struct {
		EmailLang string `json:"emailLang"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	in := auth.EmailVerificationInput{
		UserID:   user.ID,
		TenantID: user.TenantID,
		LinkBase: ad.linkBase(c.Request),
		Lang:     req.EmailLang,
	}
	token, err := ad.auth.SendVerificationEmailToken(c.Request.Context(), in)
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.SendVerificationEmailHTTPError(err))
		return
	}
	if token == "" {
		// The service reports an already-verified address by issuing no token.
		auth.WriteHTTPError(c.Writer, auth.HTTPErrEmailAlreadyVerified)
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

// verifyEmail always answers JSON: no content negotiation, no redirect.
func (ad *Adapter) verifyEmail(c *gin.Context) {
	token := auth.VerifyEmailToken(c.Request)
	if token == "" {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrVerifyTokenRequired)
		return
	}
	if err := ad.auth.VerifyEmail(c.Request.Context(), auth.VerifyEmailInput{Token: token}); err != nil {
		auth.WriteHTTPError(c.Writer, auth.VerifyEmailHTTPError(err))
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

// changeEmailRequest does reveal that an address is taken, with a 409 — the
// deliberate opposite of /forgot-password.
func (ad *Adapter) changeEmailRequest(c *gin.Context) {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
		return
	}
	var req struct {
		NewEmail  string `json:"newEmail"`
		EmailLang string `json:"emailLang"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	if httpErr, refused := auth.ChangeEmailInlineError(user); refused {
		auth.WriteHTTPError(c.Writer, httpErr)
		return
	}
	in := auth.ChangeEmailRequestInput{
		UserID:   user.ID,
		TenantID: user.TenantID,
		NewEmail: req.NewEmail,
		LinkBase: ad.linkBase(c.Request),
		Lang:     req.EmailLang,
	}
	if _, err := ad.auth.RequestEmailChange(c.Request.Context(), in); err != nil {
		auth.WriteHTTPError(c.Writer, auth.ChangeEmailRequestHTTPError(err))
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

// changeEmailConfirm is unauthenticated and CSRF-exempt: the emailed token is
// the credential, so the link works from any browser.
func (ad *Adapter) changeEmailConfirm(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	if err := ad.auth.ConfirmEmailChange(c.Request.Context(), auth.ConfirmEmailChangeInput{Token: req.Token}); err != nil {
		auth.WriteHTTPError(c.Writer, auth.ChangeEmailConfirmHTTPError(err))
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}
