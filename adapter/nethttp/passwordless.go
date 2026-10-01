package nethttp

import (
	"net/http"
	"strings"

	auth "github.com/nik2208/awesome-go-auth"
)

// The passwordless entry points and the TOTP second factor: wire-contract §3.
//
// SendMagicLink and SendSMSCode still return the credential they minted, and
// these handlers still drop it: putting it in the response body would turn a
// second factor into no factor at all. Delivery is the service's job now, through
// the senders on Config (see delivery.go), so the only thing the send routes owe
// that seam is the precheck below.
//
// Bodies are decoded with auth.DecodeOptionalJSON, the decoder every
// body-reading route of the four adapters shares. An absent body is a body with
// every field omitted, which is what the reference does: express.json() leaves
// req.body as {} when there is nothing to parse, and each route then answers
// for the field it was missing — `email is required` on /magic-link/send,
// INVALID_MAGIC_LINK on /magic-link/verify, INVALID_ACCESS_TOKEN on /2fa/verify.
// Malformed JSON is still 400 INVALID_BODY; only emptiness is tolerated.

type magicLinkSendRequest struct {
	Email     string `json:"email"`
	Mode      string `json:"mode"`
	TempToken string `json:"tempToken"`
	TenantID  string `json:"tenantId"`
	// EmailLang is read in both modes (auth.router.ts:1080) and reaches the
	// sender untouched as MagicLinkDelivery.Lang.
	EmailLang string `json:"emailLang"`
}

type magicLinkVerifyRequest struct {
	Token     string `json:"token"`
	Mode      string `json:"mode"`
	TempToken string `json:"tempToken"`
}

type smsSendRequest struct {
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	Mode      string `json:"mode"`
	TempToken string `json:"tempToken"`
	TenantID  string `json:"tenantId"`
}

type smsVerifyRequest struct {
	UserID    string `json:"userId"`
	Code      string `json:"code"`
	Mode      string `json:"mode"`
	TempToken string `json:"tempToken"`
	TenantID  string `json:"tenantId"`
}

// twoFactorSetupRequest carries the client's copy of the enrolment secret back.
// The code field is named "token", not "code": that is the reference's field
// name on this route and the served client sends it (auth.js:599-601).
type twoFactorSetupRequest struct {
	Token  string `json:"token"`
	Secret string `json:"secret"`
}

// twoFactorVerifyRequest is the step-up call. Its code field is "totpCode",
// which is neither "token" nor "code" — the three routes disagree in the
// reference and the clients are written against the disagreement.
type twoFactorVerifyRequest struct {
	TempToken string `json:"tempToken"`
	TOTPCode  string `json:"totpCode"`
}

// MagicLinkSend handles POST <prefix>/magic-link/send.
func (a *Adapter) MagicLinkSend(w http.ResponseWriter, r *http.Request) {
	var req magicLinkSendRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	email, tenantID := req.Email, req.TenantID
	if auth.TwoFactorMode(req.Mode) {
		subject, herr, ok := a.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(w, herr)
			return
		}
		// The address comes from the step-up token; an email in the body is
		// ignored, so a caller holding a tempToken cannot redirect the link.
		user, err := a.auth.FindUser(r.Context(), subject.UserID, "", subject.TenantID)
		if err != nil {
			auth.WriteHTTPError(w, auth.HTTPErrUserNotFound)
			return
		}
		email, tenantID = user.Email, user.TenantID
	} else if strings.TrimSpace(email) == "" {
		auth.WriteHTTPError(w, auth.HTTPErrPasswordlessEmailRequired)
		return
	}
	// An unknown address answers 200 as well: the send call is silent about
	// whether it found anyone, which is what keeps this route from confirming
	// that an address is registered.
	//
	// The link base is resolved the same way in both modes — the reference
	// passes buildUiLink(resolveSiteUrl(req, …), '') to the strategy on each
	// branch (auth.router.ts:1104, 1114) — so a step-up link points back at the
	// front end that asked for it, like a login link does.
	in := auth.MagicLinkSendInput{
		Email:    email,
		TenantID: tenantID,
		LinkBase: a.linkBase(r),
		Lang:     req.EmailLang,
	}
	if _, err := a.auth.SendMagicLink(r.Context(), in); err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// MagicLinkVerify handles POST <prefix>/magic-link/verify.
func (a *Adapter) MagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	var req magicLinkVerifyRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	in := auth.MagicLinkVerifyInput{Token: req.Token}
	var tokens auth.AuthTokens
	var err error
	if auth.TwoFactorMode(req.Mode) {
		subject, herr, ok := a.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(w, herr)
			return
		}
		// The identity check is the service's, not the handler's, so that a link
		// belonging to somebody else is refused before a session exists. Comparing
		// ids here — after VerifyMagicLink returned — would answer 401 on the wire
		// and still leave the link's owner with a session they never asked for. The
		// link is consumed either way, as in the reference.
		_, tokens, err = a.auth.VerifyMagicLinkForUser(r.Context(), in, subject.UserID)
	} else {
		_, tokens, err = a.auth.VerifyMagicLink(r.Context(), in)
	}
	if err != nil {
		auth.WriteHTTPError(w, auth.MagicLinkVerifyHTTPError(err))
		return
	}
	a.cfg.WriteTokens(w, r, http.StatusOK, tokens, nil)
}

// SMSSend handles POST <prefix>/sms/send.
func (a *Adapter) SMSSend(w http.ResponseWriter, r *http.Request) {
	// First, before the body is even read: the reference checks config.sms at the
	// top of this route, so an unconfigured deployment answers 500 rather than
	// the 200 an unknown address would otherwise get. See Auth.SMSConfigured.
	if !a.auth.SMSConfigured() {
		auth.WriteHTTPError(w, auth.HTTPErrSMSNotConfigured)
		return
	}
	var req smsSendRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	userID, tenantID := strings.TrimSpace(req.UserID), req.TenantID
	switch {
	case auth.TwoFactorMode(req.Mode):
		subject, herr, ok := a.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(w, herr)
			return
		}
		userID, tenantID = subject.UserID, subject.TenantID
	case strings.TrimSpace(req.Email) != "":
		// An email outranks a userId, and an unknown one answers 200. An unknown
		// userId does not — it 404s below. The asymmetry is the reference's:
		// only the address is treated as enumerable.
		user, err := a.auth.FindUser(r.Context(), "", req.Email, tenantID)
		if err != nil {
			auth.WriteSuccess(w, http.StatusOK, nil)
			return
		}
		userID = user.ID
	case userID == "":
		auth.WriteHTTPError(w, auth.HTTPErrUserIDOrEmailRequired)
		return
	}

	user, err := a.auth.FindUser(r.Context(), userID, "", tenantID)
	if err != nil {
		auth.WriteHTTPError(w, auth.HTTPErrUserNotFound)
		return
	}
	// Untrimmed, as the reference tests it (`if (!user.phoneNumber)`,
	// auth.router.ts:1830 at v1.10.8): a number of only spaces is stored as sent
	// since #35, and it is a number here too.
	if user.PhoneNumber == "" {
		auth.WriteHTTPError(w, auth.HTTPErrPhoneNotSet)
		return
	}
	if _, err := a.auth.SendSMSCode(r.Context(), auth.SMSCodeSendInput{UserID: user.ID, TenantID: user.TenantID}); err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// SMSVerify handles POST <prefix>/sms/verify.
func (a *Adapter) SMSVerify(w http.ResponseWriter, r *http.Request) {
	var req smsVerifyRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	userID, tenantID := strings.TrimSpace(req.UserID), req.TenantID
	if auth.TwoFactorMode(req.Mode) {
		subject, herr, ok := a.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(w, herr)
			return
		}
		userID, tenantID = subject.UserID, subject.TenantID
	} else if userID == "" {
		auth.WriteHTTPError(w, auth.HTTPErrUserIDRequired)
		return
	}
	_, tokens, err := a.auth.VerifySMSCode(r.Context(), auth.SMSCodeVerifyInput{UserID: userID, TenantID: tenantID, Code: req.Code})
	if err != nil {
		auth.WriteHTTPError(w, auth.SMSVerifyHTTPError(err))
		return
	}
	a.cfg.WriteTokens(w, r, http.StatusOK, tokens, nil)
}

// TwoFactorSetup handles POST <prefix>/2fa/setup.
func (a *Adapter) TwoFactorSetup(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
		return
	}
	setup, err := a.auth.NewTOTPEnrolment(user.Email)
	if err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	// The enrolment material is the whole body: no success envelope, and the
	// secret is what the client sends back to /2fa/verify-setup.
	auth.WriteJSON(w, http.StatusOK, setup)
}

// TwoFactorVerifySetup handles POST <prefix>/2fa/verify-setup.
func (a *Adapter) TwoFactorVerifySetup(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
		return
	}
	var req twoFactorSetupRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	if err := a.auth.VerifyTOTPSetup(r.Context(), user.ID, user.TenantID, req.Secret, req.Token); err != nil {
		auth.WriteHTTPError(w, auth.TOTPSetupHTTPError(err))
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// TwoFactorVerify handles POST <prefix>/2fa/verify, the step-up call that turns
// a tempToken into a session.
func (a *Adapter) TwoFactorVerify(w http.ResponseWriter, r *http.Request) {
	var req twoFactorVerifyRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	// Both arguments are the same envelope: this route has no missing-tempToken
	// branch, and it answers INVALID_ACCESS_TOKEN where its siblings answer
	// INVALID_TEMP_TOKEN.
	subject, herr, ok := a.auth.StepUpSubject(req.TempToken, auth.HTTPErrInvalidStepUpToken, auth.HTTPErrInvalidStepUpToken)
	if !ok {
		auth.WriteHTTPError(w, herr)
		return
	}
	_, tokens, err := a.auth.VerifyTOTP(r.Context(), subject.UserID, subject.TenantID, req.TOTPCode)
	if err != nil {
		auth.WriteHTTPError(w, auth.TOTPVerifyHTTPError(err))
		return
	}
	a.cfg.WriteTokens(w, r, http.StatusOK, tokens, nil)
}

// TwoFactorDisable handles POST <prefix>/2fa/disable.
func (a *Adapter) TwoFactorDisable(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
		return
	}
	// Re-read the user rather than trust the access token: a require2FA flag
	// set after the token was issued still has to be honoured. The re-read fails
	// closed — a missing user is 404, any other read failure 500 — because since
	// #31 no gate has read the row before this handler; see
	// auth.Auth.TwoFactorDisableUserRefusal.
	if herr, refused := a.auth.TwoFactorDisableUserRefusal(r.Context(), user.ID, user.TenantID); refused {
		auth.WriteHTTPError(w, herr)
		return
	}
	// The system-wide term is second, as it is in the reference, where the
	// per-user check sits at :884-888 and the settings check at :890-896. Both
	// answer 403 2FA_REQUIRED, so only the message tells them apart.
	//
	// A settings store that cannot answer is the reference generic 500: its
	// getSettings throw falls out of the route into handleError
	// (auth.router.ts:899-901, :189-195). Failing closed is also the only safe
	// reading — an unreachable policy store is not permission to drop a factor.
	// The body carries no detail, so TwoFactorPolicy logs the error through
	// Config.Logger first, as the reference's handleError does (:193).
	required, err := a.auth.TwoFactorPolicy(r.Context())
	if err != nil {
		auth.WriteHTTPError(w, auth.HTTPErrInternal)
		return
	}
	if required {
		auth.WriteHTTPError(w, auth.HTTPErrTwoFactorRequiredByPolicy)
		return
	}
	if err := a.auth.DisableTOTP(r.Context(), user.ID, user.TenantID); err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}
