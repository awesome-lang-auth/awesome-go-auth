package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"
)

// This file is the authentication context of a session: how its user was
// proved, and when a second factor was last presented — recorded on the
// Session when it opens, and carried on every access token it mints as three
// claims a resource server can decide on without asking anybody:
//
//	amr       the authentication methods, RFC 8176 values: ["pwd"],
//	          ["pwd","otp","mfa"], ["email"], ["oauth"], …
//	auth_time when the session was opened (OIDC Core §2), a NumericDate
//	mfa_at    when a second factor was last presented, a NumericDate; absent
//	          when the session never presented one
//
// It has no counterpart in the reference, whose tokens say nothing about how
// they were obtained (buildPayload, auth.router.ts:378-384): a session opened
// by a password and one opened by a password and a TOTP code carry the same
// payload, so a route that wants a recent second factor before a privileged
// action has nothing to read. That is what this adds, and it is registered as
// the deviation access-tokens-carry-the-authentication-context.
//
// Three properties make the claims worth trusting, and each is pinned by a
// test:
//
//   - They are reserved (reservedClaimNames): Config.BuildTokenClaims, and so a
//     ClaimsWebhook, cannot set them on any token, and UserFieldClaims refuses
//     to map onto them — the protection the session claims already had.
//   - They come from the session row and nowhere else. A refresh carries them
//     forward unchanged, because Refresh mints from the row it has just read;
//     POST <prefix>/2fa/step-up is the one route that moves mfa_at, and it
//     writes only those two fields, through SessionAuthenticationStore.
//   - mfa_at is written only where a second factor was actually verified: POST
//     <prefix>/2fa/verify, the step-up branches of /sms/verify and
//     /magic-link/verify, and the step-up route. A login that skips the second
//     factor by design — the OAuth callback, and the admin console's login,
//     whose token is a different type and carries none of the three — never
//     has one.

// The amr values a session records. The first four are registered in RFC 8176
// §2; AMREmail and AMROAuth are this library's own names for the two methods
// that registry has no entry for — a link delivered to the user's mailbox, and
// a login federated to an OAuth provider.
const (
	// AMRPassword is a password login: POST <prefix>/login, a registration that
	// opens a session, and the IdP's /authorize.
	AMRPassword = "pwd"
	// AMROTP is a TOTP code: POST <prefix>/2fa/verify and the step-up route.
	AMROTP = "otp"
	// AMRSMS is a code delivered by SMS: POST <prefix>/sms/verify.
	AMRSMS = "sms"
	// AMRMFA says that more than one of the factors above was presented. It is
	// what a check for a second factor looks for, together with mfa_at.
	AMRMFA = "mfa"
	// AMREmail is a link delivered by email: POST <prefix>/magic-link/verify,
	// and the account-link token of POST <prefix>/link-verify.
	AMREmail = "email"
	// AMROAuth is a login federated to an OAuth provider: the callback of
	// GET <prefix>/oauth/{provider}.
	AMROAuth = "oauth"
)

// The three claim names. They are reserved: see reservedClaimNames.
const (
	ClaimAMR      = "amr"
	ClaimAuthTime = "auth_time"
	ClaimMFAAt    = "mfa_at"
)

// sessionAuth is how a session about to be opened was authenticated. Every
// caller of issueSession states one, so a new way of opening a session cannot
// compile without saying what it proved.
type sessionAuth struct {
	// methods are the amr values, in the order the factors were presented.
	methods []string
	// secondFactor is true when one of methods was verified as a second factor
	// on top of a first: AMRMFA is appended and MFAAt is the opening time.
	secondFactor bool
}

// authBy is a session proved by one factor.
func authBy(method string) sessionAuth { return sessionAuth{methods: []string{method}} }

// authBySecondFactor is a session proved by a first factor and then a second.
// Every step-up token this library mints is minted after a password verified
// (Service.LoginWithChallenge), so first is AMRPassword at every caller today.
func authBySecondFactor(first, second string) sessionAuth {
	return sessionAuth{methods: []string{first, second}, secondFactor: true}
}

// unknownAuth is a session whose opener cannot say how its user was proved —
// Service.IssueTokensForUser, a public method that takes the proof on trust.
// Its tokens carry no amr and no mfa_at rather than a guess.
var unknownAuth = sessionAuth{}

// apply records a on a session about to be created at now.
func (a sessionAuth) apply(session *Session, now time.Time) {
	if len(a.methods) == 0 {
		return
	}
	methods := slices.Clone(a.methods)
	if a.secondFactor {
		methods = appendMethod(methods, AMRMFA)
		at := now
		session.MFAAt = &at
	}
	session.AuthMethods = methods
}

// appendMethod appends method unless it is already there, keeping the order in
// which the factors were presented.
func appendMethod(methods []string, method string) []string {
	if slices.Contains(methods, method) {
		return methods
	}
	return append(methods, method)
}

// sessionAuthClaims is what an access token of session says about how it was
// authenticated: auth_time always (the session's CreatedAt), amr when the
// session recorded its methods, mfa_at when it presented a second factor. A
// zero CreatedAt — a store that does not persist it — yields no auth_time
// rather than year one.
func sessionAuthClaims(session Session) map[string]any {
	claims := make(map[string]any, 3)
	if !session.CreatedAt.IsZero() {
		claims[ClaimAuthTime] = session.CreatedAt.Unix()
	}
	if len(session.AuthMethods) > 0 {
		claims[ClaimAMR] = slices.Clone(session.AuthMethods)
	}
	if session.MFAAt != nil {
		claims[ClaimMFAAt] = session.MFAAt.Unix()
	}
	return claims
}

// SessionAuthenticationStore records a second factor on a session without
// rewriting the rest of its row. It is optional; POST <prefix>/2fa/step-up
// needs it and answers 501 without it.
//
// It is a seam of its own rather than UpdateSession because the step-up route
// races the two routes that write the same row. A step-up that read the row,
// verified the code and wrote the whole row back would put back a refresh-token
// hash a concurrent POST /refresh had just rotated out — reviving a spent
// refresh token — or clear the RevokedAt a concurrent logout had just set,
// resurrecting the session. Writing only the two fields closes both.
//
// What an implementor owes, as one atomic operation:
//
//   - The session with sessionID that is not revoked has its AuthMethods
//     replaced by methods and its MFAAt set to at; nothing else changes. The
//     updated session is returned.
//   - A session that is not there is ErrSessionNotFound, and a revoked one is
//     ErrSessionRevoked — both decided in the same atomic step as the write, so
//     that a revocation that wins the race is never undone. On DynamoDB that is
//     one UpdateItem with a condition on the item existing and carrying no
//     revocation, and ReturnValues ALL_NEW.
//
// MemorySessionStore implements it.
type SessionAuthenticationStore interface {
	RecordSecondFactor(ctx context.Context, sessionID string, methods []string, at time.Time) (Session, error)
}

// StepUpTOTP re-verifies the TOTP factor of the session an access token
// belongs to, records it — mfa_at moves to now, and amr gains AMROTP and
// AMRMFA — and mints a fresh access token carrying the new claims. It is POST
// <prefix>/2fa/step-up.
//
// Only the access token is minted: the refresh token and the session's lifetime
// are untouched, and the next refresh carries the new mfa_at forward because it
// mints from the row this call wrote. The returned AuthTokens has no
// RefreshToken.
//
// The session is validated whatever Config.SessionCheckOn says — it is about to
// be written to — so a revoked one is ErrSessionRevoked, and a missing,
// expired or mismatched one ErrInvalidToken. The user is re-read: no TOTP
// enrolled is ErrInvalidCredentials, a wrong code ErrInvalidCode, a user the
// store no longer has ErrUserNotFound. A session store without
// SessionAuthenticationStore, or with no way to look a session up by id, is
// ErrFeatureNotSupported. The code is checked as /2fa/verify checks it, with
// the same tolerance and, as there, no replay cache.
//
// It raises no event. A step-up is not a login, and neither tree has a
// publication point for it.
func (s *Service) StepUpTOTP(ctx context.Context, accessToken, code string) (AuthTokens, error) {
	claims, err := s.parseToken(accessToken, "access")
	if err != nil {
		return AuthTokens{}, err
	}
	if claims.Sid == "" {
		return AuthTokens{}, ErrInvalidToken
	}
	recorder, ok := s.sessions.(SessionAuthenticationStore)
	if !ok {
		return AuthTokens{}, ErrFeatureNotSupported
	}
	session, supported, err := s.lookupSession(ctx, claims.Sid, claims.Sub, claims.Tid)
	switch {
	case !supported:
		return AuthTokens{}, ErrFeatureNotSupported
	case errors.Is(err, ErrSessionNotFound):
		return AuthTokens{}, ErrInvalidToken
	case err != nil:
		return AuthTokens{}, fmt.Errorf("auth: step-up: read session: %w", err)
	}
	if err := s.validateSessionState(session, claims); err != nil {
		return AuthTokens{}, err
	}
	user, err := s.users.GetUserByID(ctx, claims.Sub, claims.Tid)
	if err != nil {
		return AuthTokens{}, userLookupError(err)
	}
	if !user.IsTOTPEnabled || user.TOTPSecret == "" {
		return AuthTokens{}, ErrInvalidCredentials
	}
	now := s.now()
	if !validateTOTPCode(user.TOTPSecret, code, now) {
		return AuthTokens{}, ErrInvalidCode
	}
	methods := appendMethod(appendMethod(slices.Clone(session.AuthMethods), AMROTP), AMRMFA)
	updated, err := recorder.RecordSecondFactor(ctx, session.ID, methods, now)
	switch {
	case errors.Is(err, ErrSessionRevoked):
		return AuthTokens{}, ErrSessionRevoked
	case errors.Is(err, ErrSessionNotFound):
		return AuthTokens{}, ErrInvalidToken
	case err != nil:
		return AuthTokens{}, fmt.Errorf("auth: step-up: record second factor: %w", err)
	}
	access, _, err := s.issueAccessToken(ctx, user, updated)
	if err != nil {
		return AuthTokens{}, err
	}
	return AuthTokens{AccessToken: access, ExpiresIn: s.cfg.AccessTokenTTL}, nil
}

// StepUpTOTP delegates to Service.StepUpTOTP.
func (a *Auth) StepUpTOTP(ctx context.Context, accessToken, code string) (AuthTokens, error) {
	return a.service.StepUpTOTP(ctx, accessToken, code)
}

// StepUpRoute is where POST <prefix>/2fa/step-up sits below the mount prefix.
// Exported for the reason RegisterRoute-style constants are: the four adapters
// mount it, the OpenAPI generator describes it and the conformance suite
// replays it.
const StepUpRoute = "/2fa/step-up"

// StepUpHTTPError maps a Service.StepUpTOTP failure. The credential failures
// are the access gate's own answers — the route authenticates itself, as GET
// /me does — and the factor failures are /2fa/verify's: no TOTP enrolled is
// 400 "User not found or 2FA not set up", a wrong code 401 "Invalid TOTP code".
func StepUpHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrSessionRevoked):
		return HTTPErrSessionRevoked
	case errors.Is(err, ErrInvalidToken):
		return HTTPErrInvalidAccessToken
	case errors.Is(err, ErrInvalidCode):
		return HTTPErrInvalidTOTPCode
	case errors.Is(err, ErrInvalidCredentials):
		return HTTPErrTOTPNotSetUp
	case errors.Is(err, ErrUserNotFound):
		return HTTPErrUserNotFound
	default:
		return HTTPErrorFor(err)
	}
}

// StepUpRequest is the body of POST <prefix>/2fa/step-up. The code member is
// named totpCode, as on POST <prefix>/2fa/verify.
type StepUpRequest struct {
	TOTPCode string `json:"totpCode"`
}

// WriteAccessToken delivers a re-minted access token and nothing else: the
// access cookie in cookie mode, or a top-level accessToken in bearer mode,
// beside {"success":true}. It is WriteTokens for the one route that does not
// rotate the refresh token, which WriteTokens would otherwise overwrite with an
// empty cookie.
func (c HTTPConfig) WriteAccessToken(w http.ResponseWriter, r *http.Request, status int, tokens AuthTokens) {
	body := successBody(nil)
	if IsBearerRequest(r) {
		body["accessToken"] = tokens.AccessToken
		WriteJSON(w, status, body)
		return
	}
	cookies := c.Cookies
	if cookies.AccessTokenMaxAge <= 0 && tokens.ExpiresIn > 0 {
		cookies.AccessTokenMaxAge = tokens.ExpiresIn
	}
	cookies.SetAccessTokenCookie(w, tokens.AccessToken)
	WriteJSON(w, status, body)
}
