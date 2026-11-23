package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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
//   - The secret is the server's, not the client's. POST /2fa/setup with an
//     enrolment token answers a secret derived from the token
//     (forcedEnrolmentSecret), and POST /2fa/verify-setup with the same token
//     accepts that secret and no other. The session that follows claims the
//     factor, so the factor must be one nobody else can compute codes for — an
//     all-zero key, or the RFC 6238 test vector, is refused like any secret
//     the server did not mint.
//   - The token is bound to the credential that minted it (enrolmentCredential,
//     the cred claim): once the account's password changes, every enrolment
//     token minted before is dead, so a reset after a suspected compromise
//     takes outstanding tokens with it. The login's email-verification gate is
//     applied again on every use.
//
// All of it is behind Config.EnrolOnLogin, off by default. It is trust on
// first use — whoever holds the password enrols the factor — and a deployment
// opts in to that; with the option off the 2FA_SETUP_REQUIRED tempToken is the
// step-up token it always was and the enrolment routes take an access token
// alone.
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
// lifetime is Config.EnrolmentTokenTTL when that is set, and otherwise
// Config.TempTokenTTL, the step-up token's, 5 minutes by default; the token's
// exp carries it, so a client reads the window off exp - iat. No other token
// is minted with EnrolmentTokenTTL: the step-up token keeps TempTokenTTL.
// It carries the cred claim, written after the hook merge like the session
// claims, so no hook can forge or drop it.
func (s *Service) issueEnrolmentToken(ctx context.Context, user User) (string, error) {
	token, _, err := s.mintToken(ctx, user, "", tokenTypeEnrolment, s.cfg.enrolmentTokenTTL(),
		map[string]any{"cred": s.enrolmentCredential(user)})
	return token, err
}

// enrolmentCredential binds an enrolment token to the credential state of the
// login that minted it: an HMAC under Config.Secret of the stored password
// hash. It reveals nothing about the hash, and any change to the password —
// a reset, a change, a migration rehash — changes it, so every token minted
// before no longer matches.
func (s *Service) enrolmentCredential(user User) string {
	return sign("awesome-go-auth/enrolment-credential/v1\x00"+user.PasswordHash, s.cfg.Secret)
}

// forcedEnrolmentSecretBytes is the length of the key forcedEnrolmentSecret
// derives: 160 bits, RFC 4226's recommendation, above its R6 floor of 128.
const forcedEnrolmentSecretBytes = 20

// forcedEnrolmentSecret is the TOTP secret of the forced enrolment an
// enrolment token authorises: an HMAC under Config.Secret of the token's
// tenant, subject and id, the first 160 bits base32-encoded. The server mints
// it from the token, so POST /2fa/setup can hand it out and POST
// /2fa/verify-setup recognise it without storing anything, and a client
// cannot substitute a secret of its own choosing — one whose codes anybody
// could compute — for the factor the session it is about to get will claim.
// Each token derives its own: a client that logs in again calls /2fa/setup
// again.
//
// The message carries a NUL and a slash, which no JWS signing input does, so
// no derived value is ever a signature under the same key.
func (s *Service) forcedEnrolmentSecret(claims tokenClaims) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret))
	_, _ = mac.Write([]byte("awesome-go-auth/forced-enrolment-secret/v1\x00" + claims.Tid + "\x00" + claims.Sub + "\x00" + claims.Jti))
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac.Sum(nil)[:forcedEnrolmentSecretBytes])
}

// VerifyEnrolmentToken resolves the user an enrolment token names, re-read from
// the store, for as long as that user still has to enrol.
//
// The answer is ErrInvalidToken whenever Config.EnrolOnLogin is off; for a
// token that does not verify as an enrolment token — a step-up token, an
// access token and a refresh token included — for one past its lifetime, for
// a user the store no longer has, and for a user who no longer needs to enrol:
// a factor has been enrolled since the token was minted, or the policy that
// demanded one has been lifted. It is ErrInvalidToken as well when the
// account's password has changed since the token was minted (the token's cred
// claim no longer matches), and when the login's email-verification gate
// would now refuse the account. Any other store failure is returned as
// itself, so a caller can answer it 500 rather than read an outage as a bad
// credential.
//
// The returned User is the stored row, so Require2FA, the TOTP state and the
// email are current rather than whatever the token carried.
func (s *Service) VerifyEnrolmentToken(ctx context.Context, token string) (User, error) {
	user, _, err := s.verifyEnrolmentToken(ctx, token)
	return user, err
}

func (s *Service) verifyEnrolmentToken(ctx context.Context, token string) (User, tokenClaims, error) {
	if !s.cfg.EnrolOnLogin {
		return User{}, tokenClaims{}, ErrInvalidToken
	}
	claims, err := s.parseToken(token, tokenTypeEnrolment)
	if err != nil {
		return User{}, tokenClaims{}, ErrInvalidToken
	}
	user, err := s.users.GetUserByID(ctx, claims.Sub, claims.Tid)
	switch {
	case errors.Is(err, ErrUserNotFound):
		return User{}, tokenClaims{}, ErrInvalidToken
	case err != nil:
		return User{}, tokenClaims{}, fmt.Errorf("auth: enrolment token: read user: %w", err)
	}
	if !s.mustEnrolSecondFactor(user) {
		return User{}, tokenClaims{}, ErrInvalidToken
	}
	// The credential that minted the token is still the account's, and the
	// login that minted it would still let the account in.
	if claims.Cred == "" || !secureEqual(claims.Cred, s.enrolmentCredential(user)) {
		return User{}, tokenClaims{}, ErrInvalidToken
	}
	if s.emailVerificationBlocksLogin(user) {
		return User{}, tokenClaims{}, ErrInvalidToken
	}
	return user, claims, nil
}

// NewForcedTOTPEnrolment is the forced half of POST <prefix>/2fa/setup: the
// secret and provisioning URI of the enrolment an enrolment token authorises.
// The secret is the server's (forcedEnrolmentSecret) and the same for every
// call with the same token; CompleteTOTPEnrolment accepts it and no other. A
// token VerifyEnrolmentToken refuses is ErrInvalidToken, a store failure
// itself. Nothing is stored.
func (s *Service) NewForcedTOTPEnrolment(ctx context.Context, enrolmentToken string) (TOTPSetup, error) {
	user, claims, err := s.verifyEnrolmentToken(ctx, enrolmentToken)
	if err != nil {
		return TOTPSetup{}, err
	}
	secret := s.forcedEnrolmentSecret(claims)
	return TOTPSetup{Secret: secret, OTPAuthURL: totpProvisioningURI(secret, user.Email, s.cfg.totpIssuer())}, nil
}

// CompleteTOTPEnrolment confirms the TOTP factor an enrolment token authorises
// and opens the session its user's login could not: the forced half of POST
// <prefix>/2fa/verify-setup.
//
// The token is verified again (VerifyEnrolmentToken; ErrInvalidToken), so a
// direct caller cannot use this to replace a factor an account already has.
// The secret must be the one NewForcedTOTPEnrolment answered for this token
// (ErrInvalidCode otherwise): the session that follows claims the factor, so
// it has to be one the server minted rather than one the client chose. Then
// it is VerifyTOTPSetup — the code checked against the secret
// (ErrInvalidCode), the secret stored, identity.user.2fa.enabled raised — and
// then the tail of POST /2fa/verify: a session, and
// identity.auth.login.success with `method: "totp"`. The two events are the
// two the voluntary enrolment and the step-up login raise, in the order the
// two steps happen.
//
// A session that fails to open leaves the factor enrolled, which is the only
// order there is: the secret has to be stored before the account counts as
// holding a factor. The user then signs in with the password and the code.
// Under Config.RevokeSessionsOnPasswordReset that includes a session given up
// because the account's password changed after the token was verified — a
// reset that landed while the enrolment was in flight — which is answered
// ErrInvalidToken (keepPasswordSession).
func (s *Service) CompleteTOTPEnrolment(ctx context.Context, enrolmentToken, secret, code string) (User, AuthTokens, error) {
	user, claims, err := s.verifyEnrolmentToken(ctx, enrolmentToken)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	minted := s.forcedEnrolmentSecret(claims)
	if !secureEqual(secret, minted) {
		return User{}, AuthTokens{}, ErrInvalidCode
	}
	if err := s.VerifyTOTPSetup(ctx, user.ID, user.TenantID, minted, code); err != nil {
		return User{}, AuthTokens{}, err
	}
	user.IsTOTPEnabled = true
	user.TOTPSecret = minted
	tokens, sessionID, err := s.issueSession(ctx, user)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	// The token's cred claim was checked against the password before the
	// session existed, and a revoking reset that landed in between would not
	// have seen this session (keepPasswordSession). A password changed by then
	// is answered as a token minted under another password is.
	if err := s.keepPasswordSession(ctx, user, sessionID); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			err = ErrInvalidToken
		}
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
	// (verify-setup). On a forced enrolment it must be that secret exactly.
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
	// EnrolmentToken is the enrolment token a forced request presented, body
	// or bearer: what NewForcedTOTPEnrolment and CompleteTOTPEnrolment take.
	// Empty on a voluntary enrolment.
	EnrolmentToken string
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
//
// With Config.EnrolOnLogin off there is no enrolment token to look for: steps
// 1 and 4 are skipped, a body tempToken is ignored as the routes always
// ignored it, and the gate is the access middleware exactly.
func (a *Auth) TOTPEnrolmentCaller(ctx context.Context, r *http.Request, tempToken string) (TOTPEnrolmentCaller, HTTPError, bool) {
	enrol := a.service.cfg.EnrolOnLogin
	if enrol && tempToken != "" {
		user, err := a.service.VerifyEnrolmentToken(ctx, tempToken)
		if err != nil {
			return TOTPEnrolmentCaller{}, enrolmentTokenHTTPError(err), false
		}
		return TOTPEnrolmentCaller{User: user, Forced: true, EnrolmentToken: tempToken}, HTTPError{}, true
	}
	accessToken := AccessTokenFromRequest(r)
	if accessToken == "" {
		return TOTPEnrolmentCaller{}, HTTPErrNoAccessToken, false
	}
	user, accessErr := a.service.VerifyAccess(ctx, accessToken)
	if accessErr == nil {
		return TOTPEnrolmentCaller{User: user}, HTTPError{}, true
	}
	if bearer := BearerToken(r.Header.Get("Authorization")); enrol && bearer != "" && bearer == accessToken {
		forced, err := a.service.VerifyEnrolmentToken(ctx, bearer)
		switch {
		case err == nil:
			return TOTPEnrolmentCaller{User: forced, Forced: true, EnrolmentToken: bearer}, HTTPError{}, true
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

// TOTPEnrolmentHTTPError maps a Service.NewForcedTOTPEnrolment or
// Service.CompleteTOTPEnrolment failure: a token no longer honoured is
// INVALID_TEMP_TOKEN, as the gate answers for the same token, and everything
// else is what POST /2fa/verify-setup answers on the voluntary path
// (TOTPSetupHTTPError) — a bad code, or a secret the server did not mint for
// the token, is 400 "Invalid TOTP code".
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

// NewForcedTOTPEnrolment delegates to Service.NewForcedTOTPEnrolment.
func (a *Auth) NewForcedTOTPEnrolment(ctx context.Context, enrolmentToken string) (TOTPSetup, error) {
	return a.service.NewForcedTOTPEnrolment(ctx, enrolmentToken)
}

// CompleteTOTPEnrolment delegates to Service.CompleteTOTPEnrolment.
func (a *Auth) CompleteTOTPEnrolment(ctx context.Context, enrolmentToken, secret, code string) (User, AuthTokens, error) {
	return a.service.CompleteTOTPEnrolment(ctx, enrolmentToken, secret, code)
}
