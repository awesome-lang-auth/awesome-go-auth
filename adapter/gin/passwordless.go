package gin

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
)

// The passwordless entry points and the TOTP second factor: wire-contract §3.
// The branching, the literals and the sentinel mappings live in the root
// package, so these closures are the Gin plumbing and nothing else.
//
// SendMagicLink and SendSMSCode return the credential they minted and these
// handlers drop it: putting it in the response body would turn a second factor
// into no factor at all. The service delivers it through the senders on Config
// (see delivery.go); the send routes owe that seam only the /sms/send precheck.
//
// Bodies are decoded with auth.DecodeOptionalJSON, the decoder every body-reading
// route of the four adapters shares: an absent body is a body with every field
// omitted, as express.json() leaves req.body as {}, and malformed JSON is 400
// INVALID_BODY.

func (ad *Adapter) magicLinkSend(c *gin.Context) {
	var req struct {
		Email     string `json:"email"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
		TenantID  string `json:"tenantId"`
		EmailLang string `json:"emailLang"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	email, tenantID := req.Email, req.TenantID
	if auth.TwoFactorMode(req.Mode) {
		subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Writer, herr)
			return
		}
		// The address comes from the step-up token; an email in the body is
		// ignored, so a caller holding a tempToken cannot redirect the link.
		user, err := ad.auth.FindUser(c.Request.Context(), subject.UserID, "", subject.TenantID)
		if err != nil {
			auth.WriteHTTPError(c.Writer, auth.HTTPErrUserNotFound)
			return
		}
		email, tenantID = user.Email, user.TenantID
	} else if strings.TrimSpace(email) == "" {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrPasswordlessEmailRequired)
		return
	}
	// The link base and language are resolved the same way in both modes
	// (auth.router.ts:1104, 1114); see the net/http handler.
	in := auth.MagicLinkSendInput{
		Email:    email,
		TenantID: tenantID,
		LinkBase: ad.linkBase(c.Request),
		Lang:     req.EmailLang,
	}
	if _, err := ad.auth.SendMagicLink(c.Request.Context(), in); err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) magicLinkVerify(c *gin.Context) {
	var req struct {
		Token     string `json:"token"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	in := auth.MagicLinkVerifyInput{Token: req.Token}
	var tokens auth.AuthTokens
	var err error
	if auth.TwoFactorMode(req.Mode) {
		subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Writer, herr)
			return
		}
		// The service compares the ids, so a link belonging to another user is
		// refused before any session exists; comparing them here would answer 401
		// and still leave the owner with a session.
		_, tokens, err = ad.auth.VerifyMagicLinkForUser(c.Request.Context(), in, subject.UserID)
	} else {
		_, tokens, err = ad.auth.VerifyMagicLink(c.Request.Context(), in)
	}
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.MagicLinkVerifyHTTPError(err))
		return
	}
	ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusOK, tokens, nil)
}

func (ad *Adapter) smsSend(c *gin.Context) {
	// First, before the body is even read: the reference checks config.sms at the
	// top of this route, so an unconfigured deployment answers 500 rather than
	// the 200 an unknown address would otherwise get. See Auth.SMSConfigured.
	if !ad.auth.SMSConfigured() {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrSMSNotConfigured)
		return
	}
	var req struct {
		UserID    string `json:"userId"`
		Email     string `json:"email"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
		TenantID  string `json:"tenantId"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	userID, tenantID := strings.TrimSpace(req.UserID), req.TenantID
	switch {
	case auth.TwoFactorMode(req.Mode):
		subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Writer, herr)
			return
		}
		userID, tenantID = subject.UserID, subject.TenantID
	case strings.TrimSpace(req.Email) != "":
		// An unknown address answers 200; an unknown userId 404s below. Only the
		// address is treated as enumerable, which is the reference's asymmetry.
		user, err := ad.auth.FindUser(c.Request.Context(), "", req.Email, tenantID)
		if err != nil {
			auth.WriteSuccess(c.Writer, http.StatusOK, nil)
			return
		}
		userID = user.ID
	case userID == "":
		auth.WriteHTTPError(c.Writer, auth.HTTPErrUserIDOrEmailRequired)
		return
	}

	user, err := ad.auth.FindUser(c.Request.Context(), userID, "", tenantID)
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrUserNotFound)
		return
	}
	if user.PhoneNumber == "" {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrPhoneNotSet)
		return
	}
	if _, err := ad.auth.SendSMSCode(c.Request.Context(), auth.SMSCodeSendInput{UserID: user.ID, TenantID: user.TenantID}); err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) smsVerify(c *gin.Context) {
	var req struct {
		UserID    string `json:"userId"`
		Code      string `json:"code"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
		TenantID  string `json:"tenantId"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	userID, tenantID := strings.TrimSpace(req.UserID), req.TenantID
	if auth.TwoFactorMode(req.Mode) {
		subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Writer, herr)
			return
		}
		userID, tenantID = subject.UserID, subject.TenantID
	} else if userID == "" {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrUserIDRequired)
		return
	}
	_, tokens, err := ad.auth.VerifySMSCode(c.Request.Context(), auth.SMSCodeVerifyInput{UserID: userID, TenantID: tenantID, Code: req.Code})
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.SMSVerifyHTTPError(err))
		return
	}
	ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusOK, tokens, nil)
}

// enrolmentCaller is who an enrolment request acts for: the user Middleware
// put in the context, when the routes sit behind it (Config.EnrolOnLogin
// off), and otherwise whoever auth.Auth.TOTPEnrolmentCaller resolves from the
// request — an access token, or under Config.EnrolOnLogin the enrolment token
// of a 2FA_SETUP_REQUIRED answer.
func (ad *Adapter) enrolmentCaller(c *gin.Context, tempToken string) (auth.TOTPEnrolmentCaller, auth.HTTPError, bool) {
	// Only Middleware puts a user there, and the routes sit behind it only
	// with Config.EnrolOnLogin off; with it on, the request's own credential
	// decides.
	if !ad.auth.EnrolOnLogin() {
		if user, ok := UserFromContext(c); ok {
			return auth.TOTPEnrolmentCaller{User: user}, auth.HTTPError{}, true
		}
	}
	return ad.auth.TOTPEnrolmentCaller(c.Request.Context(), c.Request, tempToken)
}

// twoFactorSetup serves a voluntary enrolment, and under Config.EnrolOnLogin
// a forced one, whose secret is the one the server minted for the enrolment
// token (enrolmentCaller says which).
func (ad *Adapter) twoFactorSetup(c *gin.Context) {
	// The reference reads no body here, so one that is not JSON simply carries
	// no enrolment token.
	var req auth.TOTPEnrolmentRequest
	_ = auth.DecodeOptionalJSONBody(c.Request, &req)
	caller, herr, ok := ad.enrolmentCaller(c, req.TempToken)
	if !ok {
		auth.WriteHTTPError(c.Writer, herr)
		return
	}
	if caller.Forced {
		setup, err := ad.auth.NewForcedTOTPEnrolment(c.Request.Context(), caller.EnrolmentToken)
		if err != nil {
			auth.WriteHTTPError(c.Writer, auth.TOTPEnrolmentHTTPError(err))
			return
		}
		auth.WriteJSON(c.Writer, http.StatusOK, setup)
		return
	}
	setup, err := ad.auth.NewTOTPEnrolment(caller.User.Email)
	if err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	// The enrolment material is the whole body: no success envelope.
	auth.WriteJSON(c.Writer, http.StatusOK, setup)
}

// twoFactorVerifySetup resolves its caller as twoFactorSetup does. A forced
// enrolment, with the secret /2fa/setup minted for its token, opens the
// session the login could not; a voluntary one answers {"success":true} as it
// always has. The code field is "token" on this route and "totpCode" on
// /2fa/verify.
func (ad *Adapter) twoFactorVerifySetup(c *gin.Context) {
	var req auth.TOTPEnrolmentRequest
	bodyErr := auth.DecodeOptionalJSONBody(c.Request, &req)
	// The caller first, then the body: the order the middleware and the decoder
	// behind it answered in.
	caller, herr, ok := ad.enrolmentCaller(c, req.TempToken)
	if !ok {
		auth.WriteHTTPError(c.Writer, herr)
		return
	}
	if bodyErr != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInvalidBody)
		return
	}
	if caller.Forced {
		_, tokens, err := ad.auth.CompleteTOTPEnrolment(c.Request.Context(), caller.EnrolmentToken, req.Secret, req.Token)
		if err != nil {
			auth.WriteHTTPError(c.Writer, auth.TOTPEnrolmentHTTPError(err))
			return
		}
		ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusOK, tokens, nil)
		return
	}
	if err := ad.auth.VerifyTOTPSetup(c.Request.Context(), caller.User.ID, caller.User.TenantID, req.Secret, req.Token); err != nil {
		auth.WriteHTTPError(c.Writer, auth.TOTPSetupHTTPError(err))
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) twoFactorVerify(c *gin.Context) {
	var req struct {
		TempToken string `json:"tempToken"`
		TOTPCode  string `json:"totpCode"`
	}
	if !auth.DecodeOptionalJSON(c.Writer, c.Request, &req) {
		return
	}
	// Both arguments are the same envelope: this route has no missing-tempToken
	// branch, and it answers INVALID_ACCESS_TOKEN where its siblings answer
	// INVALID_TEMP_TOKEN.
	subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrInvalidStepUpToken, auth.HTTPErrInvalidStepUpToken)
	if !ok {
		auth.WriteHTTPError(c.Writer, herr)
		return
	}
	_, tokens, err := ad.auth.VerifyTOTP(c.Request.Context(), subject.UserID, subject.TenantID, req.TOTPCode)
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.TOTPVerifyHTTPError(err))
		return
	}
	ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusOK, tokens, nil)
}

func (ad *Adapter) twoFactorDisable(c *gin.Context) {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
		return
	}
	// Re-read the user rather than trust the access token: a require2FA flag set
	// after the token was issued still has to be honoured. Fails closed; see
	// auth.Auth.TwoFactorDisableUserRefusal.
	if herr, refused := ad.auth.TwoFactorDisableUserRefusal(c.Request.Context(), user.ID, user.TenantID); refused {
		auth.WriteHTTPError(c.Writer, herr)
		return
	}
	// The system-wide term is second, as in the reference (per-user at :884-888,
	// settings at :890-896). A settings store that cannot answer fails closed
	// with the reference generic 500 (handleError, :899-901 and :189-195);
	// TwoFactorPolicy logs the error through Config.Logger, because this body
	// carries none of it.
	required, err := ad.auth.TwoFactorPolicy(c.Request.Context())
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInternal)
		return
	}
	if required {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrTwoFactorRequiredByPolicy)
		return
	}
	if err := ad.auth.DisableTOTP(c.Request.Context(), user.ID, user.TenantID); err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}
