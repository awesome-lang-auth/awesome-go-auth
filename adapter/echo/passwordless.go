package echo

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
)

// The passwordless entry points and the TOTP second factor: wire-contract §3.
// The branching, the literals and the sentinel mappings live in the root
// package, so these closures are the Echo plumbing and nothing else.
//
// SendMagicLink and SendSMSCode return the credential they minted and these
// handlers drop it: putting it in the response body would turn a second factor
// into no factor at all. The service delivers it through the senders on Config
// (see delivery.go); the send routes owe that seam only the /sms/send precheck.
//
// Bodies are decoded with auth.DecodeOptionalJSON, the decoder every body-reading
// route of the four adapters shares, rather than echo's Bind: an absent body is
// a body with every field omitted, as express.json() leaves req.body as {}, and
// malformed JSON is 400 INVALID_BODY whatever the Content-Type says.

func (ad *Adapter) magicLinkSend(c echo.Context) error {
	var req struct {
		Email     string `json:"email"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
		TenantID  string `json:"tenantId"`
		EmailLang string `json:"emailLang"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	email, tenantID := req.Email, req.TenantID
	if auth.TwoFactorMode(req.Mode) {
		subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Response(), herr)
			return nil
		}
		// The address comes from the step-up token; an email in the body is
		// ignored, so a caller holding a tempToken cannot redirect the link.
		user, err := ad.auth.FindUser(c.Request().Context(), subject.UserID, "", subject.TenantID)
		if err != nil {
			auth.WriteHTTPError(c.Response(), auth.HTTPErrUserNotFound)
			return nil
		}
		email, tenantID = user.Email, user.TenantID
	} else if strings.TrimSpace(email) == "" {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrPasswordlessEmailRequired)
		return nil
	}
	// The link base and language are resolved the same way in both modes
	// (auth.router.ts:1104, 1114); see the net/http handler.
	in := auth.MagicLinkSendInput{
		Email:    email,
		TenantID: tenantID,
		LinkBase: ad.linkBase(c.Request()),
		Lang:     req.EmailLang,
	}
	if _, err := ad.auth.SendMagicLink(c.Request().Context(), in); err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

func (ad *Adapter) magicLinkVerify(c echo.Context) error {
	var req struct {
		Token     string `json:"token"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	in := auth.MagicLinkVerifyInput{Token: req.Token}
	var tokens auth.AuthTokens
	var err error
	if auth.TwoFactorMode(req.Mode) {
		subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Response(), herr)
			return nil
		}
		// The service compares the ids, so a link belonging to another user is
		// refused before any session exists; comparing them here would answer 401
		// and still leave the owner with a session.
		_, tokens, err = ad.auth.VerifyMagicLinkForUser(c.Request().Context(), in, subject.UserID)
	} else {
		_, tokens, err = ad.auth.VerifyMagicLink(c.Request().Context(), in)
	}
	if err != nil {
		auth.WriteHTTPError(c.Response(), auth.MagicLinkVerifyHTTPError(err))
		return nil
	}
	ad.cfg.WriteTokens(c.Response(), c.Request(), http.StatusOK, tokens, nil)
	return nil
}

func (ad *Adapter) smsSend(c echo.Context) error {
	// First, before the body is even read: the reference checks config.sms at the
	// top of this route, so an unconfigured deployment answers 500 rather than
	// the 200 an unknown address would otherwise get. See Auth.SMSConfigured.
	if !ad.auth.SMSConfigured() {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrSMSNotConfigured)
		return nil
	}
	var req struct {
		UserID    string `json:"userId"`
		Email     string `json:"email"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
		TenantID  string `json:"tenantId"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	userID, tenantID := strings.TrimSpace(req.UserID), req.TenantID
	switch {
	case auth.TwoFactorMode(req.Mode):
		subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Response(), herr)
			return nil
		}
		userID, tenantID = subject.UserID, subject.TenantID
	case strings.TrimSpace(req.Email) != "":
		// An unknown address answers 200; an unknown userId 404s below. Only the
		// address is treated as enumerable, which is the reference's asymmetry.
		user, err := ad.auth.FindUser(c.Request().Context(), "", req.Email, tenantID)
		if err != nil {
			auth.WriteSuccess(c.Response(), http.StatusOK, nil)
			return nil
		}
		userID = user.ID
	case userID == "":
		auth.WriteHTTPError(c.Response(), auth.HTTPErrUserIDOrEmailRequired)
		return nil
	}

	user, err := ad.auth.FindUser(c.Request().Context(), userID, "", tenantID)
	if err != nil {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrUserNotFound)
		return nil
	}
	if strings.TrimSpace(user.PhoneNumber) == "" {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrPhoneNotSet)
		return nil
	}
	if _, err := ad.auth.SendSMSCode(c.Request().Context(), auth.SMSCodeSendInput{UserID: user.ID, TenantID: user.TenantID}); err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

func (ad *Adapter) smsVerify(c echo.Context) error {
	var req struct {
		UserID    string `json:"userId"`
		Code      string `json:"code"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
		TenantID  string `json:"tenantId"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	userID, tenantID := strings.TrimSpace(req.UserID), req.TenantID
	if auth.TwoFactorMode(req.Mode) {
		subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Response(), herr)
			return nil
		}
		userID, tenantID = subject.UserID, subject.TenantID
	} else if userID == "" {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrUserIDRequired)
		return nil
	}
	_, tokens, err := ad.auth.VerifySMSCode(c.Request().Context(), auth.SMSCodeVerifyInput{UserID: userID, TenantID: tenantID, Code: req.Code})
	if err != nil {
		auth.WriteHTTPError(c.Response(), auth.SMSVerifyHTTPError(err))
		return nil
	}
	ad.cfg.WriteTokens(c.Response(), c.Request(), http.StatusOK, tokens, nil)
	return nil
}

func (ad *Adapter) twoFactorSetup(c echo.Context) error {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrNoAccessToken)
		return nil
	}
	setup, err := ad.auth.NewTOTPEnrolment(user.Email)
	if err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	// The enrolment material is the whole body: no success envelope.
	auth.WriteJSON(c.Response(), http.StatusOK, setup)
	return nil
}

func (ad *Adapter) twoFactorVerifySetup(c echo.Context) error {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrNoAccessToken)
		return nil
	}
	// The code field is "token" on this route and "totpCode" on /2fa/verify.
	var req struct {
		Token  string `json:"token"`
		Secret string `json:"secret"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	if err := ad.auth.VerifyTOTPSetup(c.Request().Context(), user.ID, user.TenantID, req.Secret, req.Token); err != nil {
		auth.WriteHTTPError(c.Response(), auth.TOTPSetupHTTPError(err))
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

func (ad *Adapter) twoFactorVerify(c echo.Context) error {
	var req struct {
		TempToken string `json:"tempToken"`
		TOTPCode  string `json:"totpCode"`
	}
	if !auth.DecodeOptionalJSON(c.Response(), c.Request(), &req) {
		return nil
	}
	// Both arguments are the same envelope: this route has no missing-tempToken
	// branch, and it answers INVALID_ACCESS_TOKEN where its siblings answer
	// INVALID_TEMP_TOKEN.
	subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrInvalidStepUpToken, auth.HTTPErrInvalidStepUpToken)
	if !ok {
		auth.WriteHTTPError(c.Response(), herr)
		return nil
	}
	_, tokens, err := ad.auth.VerifyTOTP(c.Request().Context(), subject.UserID, subject.TenantID, req.TOTPCode)
	if err != nil {
		auth.WriteHTTPError(c.Response(), auth.TOTPVerifyHTTPError(err))
		return nil
	}
	ad.cfg.WriteTokens(c.Response(), c.Request(), http.StatusOK, tokens, nil)
	return nil
}

func (ad *Adapter) twoFactorDisable(c echo.Context) error {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrNoAccessToken)
		return nil
	}
	// Re-read the user rather than trust the access token: a require2FA flag set
	// after the token was issued still has to be honoured. A failed re-read falls
	// through rather than 404ing, matching the reference's optional chaining
	// (`currentUser?.require2FA`, auth.router.ts:884-885). That makes this term
	// fail OPEN where the settings term below fails closed — the asymmetry, and
	// why it stands, is written out in adapter/nethttp/passwordless.go.
	fresh, err := ad.auth.FindUser(c.Request().Context(), user.ID, "", user.TenantID)
	if err == nil && fresh.Require2FA {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrTwoFactorRequiredForUser)
		return nil
	}
	// The system-wide term is second, as in the reference (per-user at :884-888,
	// settings at :890-896). A settings store that cannot answer fails closed
	// with the reference generic 500 (handleError, :899-901 and :189-195);
	// TwoFactorPolicy logs the error through Config.Logger, because this body
	// carries none of it.
	required, err := ad.auth.TwoFactorPolicy(c.Request().Context())
	if err != nil {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrInternal)
		return nil
	}
	if required {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrTwoFactorRequiredByPolicy)
		return nil
	}
	if err := ad.auth.DisableTOTP(c.Request().Context(), user.ID, user.TenantID); err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}
