package auth

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
)

// This file is forced enrolment: the second branch of POST /login's 2FA
// challenge, made completable.
//
// When a second factor is demanded of an account — Config.Require2FA, or the
// user's own Require2FA flag — and the account has no factor it could present,
// the login does not open a session. It answers
//
//	403 {"requires2FASetup":true,"tempToken":"<jwt>","code":"2FA_SETUP_REQUIRED"}
//
// (auth.router.ts:562-568), and until now the tempToken in that body
// authenticated nothing: it was typed as the step-up token, the two enrolment
// routes sit behind the access-token gate, and no route accepted it — the
// [KNOWN GAP] the conformance suite carried. An account under a mandatory
// second-factor policy therefore had to be enrolled out of band before it could
// ever sign in.
//
// In the reference the same token works because it is an ordinary access
// token: the client sends it as a bearer credential to /2fa/setup and
// /2fa/verify-setup and enrols on the spot — and for five minutes it also
// authenticates every other protected route, before any second factor exists.
// This port keeps refusing that (temp-token-is-typed-not-an-access-token) and
// closes the gap with a third token type instead:
//
//   - The setup-required tempToken is an enrolment token, typed
//     tokenTypeEnrolment. It is not an access token, not a step-up token and
//     not a refresh token, so every route but the two enrolment routes refuses
//     it, and the enrolment routes refuse the other three types as an
//     enrolment token.
//   - It is honoured only while the login would still answer
//     2FA_SETUP_REQUIRED for its user (mustEnrolSecondFactor, re-read from the
//     store on every use). That is what makes it single-purpose: once the user
//     has a factor — from this token, another one, an administrator, anything —
//     every outstanding enrolment token is dead, so a replay after a successful
//     enrolment is refused without a store of spent tokens.
//   - POST /2fa/verify-setup with it does what the reference leaves to a second
//     login: once the code verifies and the secret is stored, it opens the
//     session exactly as POST /2fa/verify does. The password was verified by
//     the login that minted the token and the TOTP code by this request, so the
//     session is the one a password-and-TOTP login would have produced.
//
// Voluntary enrolment is unchanged: a signed-in user presents an access token,
// /2fa/verify-setup answers {"success":true}, and no new session is opened.

// tokenTypeEnrolment marks the token the 2FA_SETUP_REQUIRED answer carries. Like
// tokenTypeTemp it is reserved — issueToken writes typ after the
// Config.BuildTokenClaims merge — so no hook can turn one into another type.
const tokenTypeEnrolment = "2fa_setup"

// mustEnrolSecondFactor reports whether a second factor is demanded of user and
// user has none to present: the condition under which POST /login answers
// 2FA_SETUP_REQUIRED, and the only condition under which an enrolment token is
// honoured.
//
// "None to present" is availableTwoFactorMethods coming back empty, which is the
// reference's own test (auth.router.ts:556-563). It is wider than "no TOTP": a
// stored phone number on a deployment that can send SMS, or a deployment that
// can send magic links, is a factor too, and such an account is challenged
// rather than asked to enrol. Both the login and the enrolment routes read this
// one function, so the two cannot drift.
func (s *Service) mustEnrolSecondFactor(user User) bool {
	return s.requiresTwoFactor(user) && len(s.availableTwoFactorMethods(user)) == 0
}

// issueEnrolmentToken mints the token a 2FA_SETUP_REQUIRED answer carries. Its
// lifetime is Config.TempTokenTTL, the step-up token's, 5 minutes by default.
func (s *Service) issueEnrolmentToken(ctx context.Context, user User) (string, error) {
	token, _, err := s.issueToken(ctx, user, "", tokenTypeEnrolment, s.cfg.TempTokenTTL)
	return token, err
}

// VerifyEnrolmentToken resolves the user an enrolment token names, re-read from
// the store, for as long as that user still has to enrol.
//
// The answer is ErrInvalidToken for a token that does not verify as an
// enrolment token — a step-up token, an access token and a refresh token
// included — for one past its lifetime, for a user the store no longer has,
// and for a user who no longer needs to enrol: a factor has been enrolled since
// the token was minted, or the policy that demanded one has been lifted. Any
// other store failure is returned as itself, so a caller can answer it 500
// rather than read an outage as a bad credential.
//
// The returned User is the stored row, so Require2FA, the TOTP state and the
// email are current rather than whatever the token carried.
func (s *Service) VerifyEnrolmentToken(ctx context.Context, token string) (User, error) {
	claims, err := s.parseToken(token, tokenTypeEnrolment)
	if err != nil {
		return User{}, ErrInvalidToken
	}
	user, err := s.users.GetUserByID(ctx, claims.Sub, claims.Tid)
	switch {
	case errors.Is(err, ErrUserNotFound):
		return User{}, ErrInvalidToken
	case err != nil:
		return User{}, fmt.Errorf("auth: enrolment token: read user: %w", err)
	}
	if !s.mustEnrolSecondFactor(user) {
		return User{}, ErrInvalidToken
	}
	return user, nil
}

// CompleteTOTPEnrolment confirms a TOTP secret for a user an enrolment token
// named and opens the session that user's login could not: the forced half of
// POST /2fa/verify-setup.
//
// The user is re-read and must still need to enrol (ErrInvalidToken
// otherwise), so a direct caller cannot use this to replace a factor an account
// already has. The secret must be a base32 key of at least 128 bits (RFC 4226
// R6; ErrInvalidCode otherwise), because the session that follows claims the
// factor. Then it is VerifyTOTPSetup — the code checked against secret
// (ErrInvalidCode), the secret stored, identity.user.2fa.enabled raised — and
// then the tail of POST /2fa/verify: a session, and identity.auth.login.success
// with `method: "totp"`. The two events are the two the voluntary enrolment and
// the step-up login raise, in the order the two steps happen.
//
// A session that fails to open leaves the factor enrolled, which is the only
// order there is: the secret has to be stored before the account counts as
// holding a factor. The user then signs in with the password and the code.
func (s *Service) CompleteTOTPEnrolment(ctx context.Context, userID, tenantID, secret, code string) (User, AuthTokens, error) {
	user, err := s.users.GetUserByID(ctx, userID, tenantID)
	switch {
	case errors.Is(err, ErrUserNotFound):
		return User{}, AuthTokens{}, ErrInvalidToken
	case err != nil:
		return User{}, AuthTokens{}, fmt.Errorf("auth: complete enrolment: read user: %w", err)
	}
	if !s.mustEnrolSecondFactor(user) {
		return User{}, AuthTokens{}, ErrInvalidToken
	}
	// The session this opens says the account holds a second factor, so the
	// secret has to be one: an empty string decodes to an empty HMAC key whose
	// codes anybody can compute, and it would leave the account still owing
	// enrolment while its session claimed otherwise. A secret below the RFC
	// 4226 floor is refused as a code that does not verify.
	if !totpSecretIsStrong(secret) {
		return User{}, AuthTokens{}, ErrInvalidCode
	}
	if err := s.VerifyTOTPSetup(ctx, user.ID, user.TenantID, secret, code); err != nil {
		return User{}, AuthTokens{}, err
	}
	user.IsTOTPEnabled = true
	user.TOTPSecret = secret
	tokens, sessionID, err := s.issueSession(ctx, user)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	// The tail POST /2fa/verify ends with (node-auth auth.router.ts:968): the
	// login completed with a TOTP code, and the event says so in the same
	// words. It is not a publication point of its own in the dev line, whose
	// verify-setup never opens a session; it is the existing login site's
	// payload, reached from the one other place a password-plus-TOTP login now
	// completes.
	s.publish(ctx, func() Event {
		return Event{
			Name:      EventAuthLoginSuccess,
			UserID:    user.ID,
			SessionID: sessionID,
			Data:      map[string]any{"method": loginMethodTOTP},
		}
	})
	return user, tokens, nil
}

// minTOTPSecretBytes is RFC 4226 §4 requirement R6: "The length of the shared
// secret MUST be at least 128 bits." The secrets POST /2fa/setup mints are well
// above it (generateTOTPSecret).
const minTOTPSecretBytes = 16

// totpSecretIsStrong reports whether secret is a base32 key of at least
// minTOTPSecretBytes, which is what a forced enrolment requires before it opens
// a session on the strength of it. The voluntary path checks nothing of the
// kind, as the reference's does not; it opens no session.
func totpSecretIsStrong(secret string) bool {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	return err == nil && len(key) >= minTOTPSecretBytes
}

// TOTPEnrolmentRequest is the body POST <prefix>/2fa/setup and POST
// <prefix>/2fa/verify-setup read. The four adapters decode it with
// DecodeOptionalJSONBody, so an absent body is a body with every member
// omitted.
type TOTPEnrolmentRequest struct {
	// TempToken is the enrolment token of a 2FA_SETUP_REQUIRED answer, for a
	// forced enrolment. Absent on a voluntary one, which authenticates with an
	// access token instead; see TOTPEnrolmentCaller for the precedence.
	TempToken string `json:"tempToken"`
	// Token is the code from the authenticator app (verify-setup). The member
	// is named "token", not "code": that is the reference's field name on this
	// route and the served client sends it (auth.js:599-601).
	Token string `json:"token"`
	// Secret is the client's copy of the secret /2fa/setup returned
	// (verify-setup).
	Secret string `json:"secret"`
}

// TOTPEnrolmentCaller is who a request to POST <prefix>/2fa/setup or POST
// <prefix>/2fa/verify-setup acts for.
type TOTPEnrolmentCaller struct {
	// User is the principal. For a voluntary enrolment it is what the access
	// token carries, as the auth middleware builds it (Auth.VerifyAccess); for
	// a forced one it is the stored row VerifyEnrolmentToken returned.
	User User
	// Forced reports that the request presented an enrolment token — the
	// tempToken of a 2FA_SETUP_REQUIRED answer — rather than an access token.
	// POST /2fa/verify-setup opens a session for a forced enrolment and not for
	// a voluntary one.
	Forced bool
}

// TOTPEnrolmentCaller resolves who an enrolment request acts for, or the
// envelope to answer with. It is the gate the four adapters put on POST
// <prefix>/2fa/setup and POST <prefix>/2fa/verify-setup instead of the access
// middleware, and tempToken is the request body's tempToken member.
//
// The precedence is fixed, and every request that carries no enrolment token
// is answered exactly as the access middleware answers it:
//
//  1. A non-empty tempToken selects the forced path and is the whole decision:
//     an enrolment token VerifyEnrolmentToken accepts, or
//     401 {"error":"Invalid or expired temp token","code":"INVALID_TEMP_TOKEN"}
//     — the step-up routes' answer for a bad tempToken. An access credential on
//     the same request is ignored: a client that sent the enrolment token said
//     which enrolment it is completing.
//  2. Otherwise the access token, read as the middleware reads it — the
//     Authorization header, then the access cookie. None at all is
//     403 "No access token provided".
//  3. An access token VerifyAccess accepts is a voluntary enrolment.
//  4. An Authorization: Bearer credential that is not an access token is tried
//     as an enrolment token, because that is how a client written against the
//     reference presents it: its tempToken is an access token, so it sends it
//     as one. Only the header is tried — this port never sets an enrolment
//     token as a cookie — and only after the access check, so an access
//     credential always keeps its meaning.
//  5. Anything else is the middleware's own answer for the access token:
//     403 "Invalid or expired access token", or 401 SESSION_REVOKED.
//
// A store failure while re-reading the user is the generic 500.
func (a *Auth) TOTPEnrolmentCaller(ctx context.Context, r *http.Request, tempToken string) (TOTPEnrolmentCaller, HTTPError, bool) {
	if tempToken != "" {
		user, err := a.service.VerifyEnrolmentToken(ctx, tempToken)
		if err != nil {
			return TOTPEnrolmentCaller{}, enrolmentTokenHTTPError(err), false
		}
		return TOTPEnrolmentCaller{User: user, Forced: true}, HTTPError{}, true
	}
	accessToken := AccessTokenFromRequest(r)
	if accessToken == "" {
		return TOTPEnrolmentCaller{}, HTTPErrNoAccessToken, false
	}
	user, accessErr := a.service.VerifyAccess(ctx, accessToken)
	if accessErr == nil {
		return TOTPEnrolmentCaller{User: user}, HTTPError{}, true
	}
	if bearer := BearerToken(r.Header.Get("Authorization")); bearer != "" && bearer == accessToken {
		forced, err := a.service.VerifyEnrolmentToken(ctx, bearer)
		switch {
		case err == nil:
			return TOTPEnrolmentCaller{User: forced, Forced: true}, HTTPError{}, true
		case !errors.Is(err, ErrInvalidToken):
			return TOTPEnrolmentCaller{}, enrolmentTokenHTTPError(err), false
		}
	}
	return TOTPEnrolmentCaller{}, AccessHTTPError(accessErr), false
}

// enrolmentTokenHTTPError maps a VerifyEnrolmentToken failure: a token that is
// not honoured is the step-up routes' INVALID_TEMP_TOKEN, and a store that
// failed is the generic 500.
func enrolmentTokenHTTPError(err error) HTTPError {
	if errors.Is(err, ErrInvalidToken) {
		return HTTPErrInvalidTempToken
	}
	return HTTPErrorFor(err)
}

// TOTPEnrolmentHTTPError maps a Service.CompleteTOTPEnrolment failure: a user
// who no longer needs to enrol is INVALID_TEMP_TOKEN, as the gate answers for
// the same token, and everything else is what POST /2fa/verify-setup answers on
// the voluntary path (TOTPSetupHTTPError) — a bad code is
// 400 "Invalid TOTP code".
func TOTPEnrolmentHTTPError(err error) HTTPError {
	if errors.Is(err, ErrInvalidToken) {
		return HTTPErrInvalidTempToken
	}
	return TOTPSetupHTTPError(err)
}

// VerifyEnrolmentToken delegates to Service.VerifyEnrolmentToken.
func (a *Auth) VerifyEnrolmentToken(ctx context.Context, token string) (User, error) {
	return a.service.VerifyEnrolmentToken(ctx, token)
}

// CompleteTOTPEnrolment delegates to Service.CompleteTOTPEnrolment.
func (a *Auth) CompleteTOTPEnrolment(ctx context.Context, userID, tenantID, secret, code string) (User, AuthTokens, error) {
	return a.service.CompleteTOTPEnrolment(ctx, userID, tenantID, secret, code)
}
