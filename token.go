package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tokenAlg is the only JWS algorithm accepted for access and refresh tokens.
// Verification uses it as an explicit allow-list: the alg advertised by an
// incoming token never selects the verification routine, so "none" and any
// asymmetric algorithm are refused before the claims are read.
const tokenAlg = "HS256"

type tokenClaims struct {
	Sub string `json:"sub"`
	Sid string `json:"sid"`
	Tid string `json:"tid,omitempty"`
	Jti string `json:"jti"`
	Typ string `json:"typ"`
	Iss string `json:"iss"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// joseHeader is the JWT header of an issued token.
type joseHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// reservedClaimNames are the claims mintToken owns, so that nothing a
// Config.BuildTokenClaims hook returns survives under these names. The list
// exists so that a constructor which knows its claim names in advance —
// UserFieldClaims — can refuse one of them at startup instead of letting the
// mapping vanish silently on every mint; mintToken is the reservation itself,
// and TestReservedClaimNames_MatchIssueToken pins that the two agree.
//
// The first seven are the session claims, written after the merge on every
// token. The last three are the authentication context
// (authentication_context.go): deleted after the merge on every token, and
// written back on an access token only, from the session row — so a hook can
// neither put an mfa_at on a token nor keep one off.
var reservedClaimNames = []string{"sid", "tid", "jti", "typ", "iss", "iat", "exp", ClaimAMR, ClaimAuthTime, ClaimMFAAt}

// isReservedClaim reports whether name is one of reservedClaimNames, matched
// the way encoding/json matches an object member to a struct field: exactly,
// or else case-insensitively under Unicode simple folding (strings.EqualFold).
//
// Claim names are case-sensitive in JWT, so "MFA_AT" is, to the letter of RFC
// 7519, a claim of its own. But most consumers do not read a payload to the
// letter: they decode it into a struct — golang-jwt's custom claims, a
// hand-written authorizer, parseToken here — and encoding/json fills the field
// tagged "mfa_at" from "MFA_AT" whenever no exact "mfa_at" member is present,
// and from a later fold-equal member even when one is ("ſid" folds to "sid",
// and sorts after it). A hook that could put such a name on a token would be
// setting the reserved claim for every reader of that kind, so every
// fold-equal spelling is reserved with the name.
func isReservedClaim(name string) bool {
	for _, reserved := range reservedClaimNames {
		if strings.EqualFold(name, reserved) {
			return true
		}
	}
	return false
}

// deleteReservedClaims removes from claims every member isReservedClaim
// matches. mintToken and the IdP's payloadClaims call it on the hook's result
// before they write the reserved claims themselves, so that no spelling of a
// reserved name survives beside the one they write.
func deleteReservedClaims(claims map[string]any) {
	for name := range claims {
		if isReservedClaim(name) {
			delete(claims, name)
		}
	}
}

// issueToken mints one token for user — a refresh token, the 2FA step-up token
// or the enrolment token, which differ only in typ, sid and lifetime. None of
// them carries the authentication context; an access token is minted by
// issueAccessToken, which adds it from the session.
//
// The payload is assembled in the reference's order: the base claims first,
// the Config.BuildTokenClaims result spread over them, and the session claims
// written last (auth.router.ts:378-384 and :433, token.service.ts:19). The
// order is the guarantee: a hook can rename what the user is, not what the
// token is.
func (s *Service) issueToken(ctx context.Context, user User, sessionID, tokenType string, ttl time.Duration) (string, time.Time, error) {
	return s.mintToken(ctx, user, sessionID, tokenType, ttl, nil)
}

// issueAccessToken mints the access token of session for user, carrying the
// session's authentication context: auth_time, and amr and mfa_at when the
// session recorded them (sessionAuthClaims). Every access token this library
// mints for a session comes through here — the login, a refresh, the IdP's
// code exchange and refresh grant, the step-up route — so the claims cannot be
// present on one path and missing on another.
func (s *Service) issueAccessToken(ctx context.Context, user User, session Session) (string, time.Time, error) {
	return s.mintToken(ctx, user, session.ID, "access", s.cfg.AccessTokenTTL, sessionAuthClaims(session))
}

// mintToken is the one place a token is assembled. authClaims are written
// last, after the reserved claims, and are the only way the authentication
// context reaches a payload.
func (s *Service) mintToken(ctx context.Context, user User, sessionID, tokenType string, ttl time.Duration, authClaims map[string]any) (string, time.Time, error) {
	now := s.now()
	expiresAt := now.Add(ttl)
	jti, err := newID("jti")
	if err != nil {
		return "", time.Time{}, err
	}

	// The base claims are the six the reference's buildPayload emits, and they
	// are the only claims a hook may override: it spreads
	// config.buildTokenPayload(user) over exactly this object
	// (auth.router.ts:378-384), so a custom email or role wins here as it does
	// there. The refresh token carries the same set (token.service.ts:25-29).
	payloadClaims := map[string]any{
		"sub":             user.ID,
		"email":           user.Email,
		"role":            user.Role,
		"loginProvider":   user.loginProviderOrLocal(),
		"isEmailVerified": user.IsEmailVerified,
		"isTotpEnabled":   user.IsTOTPEnabled,
	}
	if s.cfg.BuildTokenClaims != nil {
		customClaims, err := s.cfg.BuildTokenClaims(ctx, user)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("auth: build token claims: %w", err)
		}
		for key, value := range customClaims {
			payloadClaims[key] = value
		}
	}
	// Every spelling of a reserved name the hook returned goes first — see
	// isReservedClaim — so that the assignments below are the only members of
	// the payload any reader, exact or case-insensitive, takes a reserved claim
	// from.
	deleteReservedClaims(payloadClaims)

	// The reserved claims are written after the merge so that nothing a hook
	// returns survives under these names. Each is a fact parseToken or its
	// callers decide on, and a hook that could set it would be choosing the
	// outcome rather than describing the user: sid binds the token to its
	// session (Refresh, Logout and the session check compare it), tid scopes
	// the user lookup, exp is the lifetime, iss and jti are the issuer check
	// and the per-token id, iat is when it was minted.
	//
	// typ is the one that matters most. It is the only thing telling an access
	// token, a refresh token and the step-up token apart — tokenTypeTemp is what
	// keeps a tempToken out of every route behind the access-token gate. A
	// hook returning {"typ": "access"} would have turned every tempToken handed
	// out *before* the second factor into a full session credential, which is
	// exactly the five-minute bypass the typed temp token exists to close (see
	// the temp-token-is-typed-not-an-access-token deviation). The reference
	// gets the same guarantee for its own session claims by assigning sid after
	// the merge (auth.router.ts:433) and stripping iat/exp before signing
	// (token.service.ts:19). These seven names are reservedClaimNames.
	payloadClaims["sid"] = sessionID
	payloadClaims["tid"] = user.TenantID
	payloadClaims["jti"] = jti
	payloadClaims["typ"] = tokenType
	payloadClaims["iss"] = s.cfg.Issuer
	payloadClaims["iat"] = now.Unix()
	payloadClaims["exp"] = expiresAt.Unix()

	// The authentication context is reserved the other way round: these
	// claims are not always present, so overwriting them is not enough — a
	// hook value under one of them would survive on every token the session
	// does not set it on, and an mfa_at the hook made up is exactly the claim a
	// resource server must be able to trust. So all three were deleted above,
	// with every other spelling of them, and are written back from the session
	// alone, on an access token alone.
	for key, value := range authClaims {
		payloadClaims[key] = value
	}

	// A refresh token is signed with Config.RefreshSecret when one is set, as
	// the reference signs it with refreshTokenSecret (token.service.ts:25-29);
	// every other type, and a refresh token without one, with Config.Secret.
	token, err := buildHS256JWT(payloadClaims, s.cfg.secretFor(tokenType))
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (s *Service) parseToken(token, expectedType string) (tokenClaims, error) {
	var claims tokenClaims
	header, payload, sig, err := splitToken(token)
	if err != nil {
		return claims, ErrInvalidToken
	}

	rawHeader, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return claims, ErrInvalidToken
	}
	if alg, ok := headerAlg(rawHeader); !ok || alg != tokenAlg {
		return claims, ErrInvalidToken
	}
	// The key is chosen by the type the caller expects, not by the typ the
	// token claims, so a token signed with the other secret fails here, before
	// its payload is read (token.service.ts:154 verifies with refreshTokenSecret).
	if !secureEqual(sign(header+"."+payload, s.cfg.secretFor(expectedType)), sig) {
		return claims, ErrInvalidToken
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return claims, ErrInvalidToken
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return claims, ErrInvalidToken
	}

	now := s.now()
	if claims.Iss != s.cfg.Issuer || claims.Typ != expectedType {
		return claims, ErrInvalidToken
	}
	if now.After(time.Unix(claims.Exp, 0).Add(s.cfg.ClockSkew)) {
		return claims, ErrInvalidToken
	}
	return claims, nil
}

// headerAlg returns the alg member of a decoded JOSE header, reporting false
// when the header is not a JSON object, carries no alg member, or carries one
// that is not a JSON string.
//
// The header is decoded into raw members rather than into joseHeader because
// encoding/json matches struct fields case-insensitively: unmarshalling into
// joseHeader accepts a header whose only algorithm member is "ALG", and a
// header reading {"alg":"none","ALG":"HS256"} would have its "none" overwritten
// by the later member and be accepted, while every spec-compliant verifier
// reads that same header as alg "none" and refuses it. joseHeader is still the
// type used to build headers, where the member names are ours to choose.
func headerAlg(rawHeader []byte) (string, bool) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(rawHeader, &members); err != nil {
		return "", false
	}
	rawAlg, ok := members["alg"]
	if !ok {
		return "", false
	}
	var alg string
	if err := json.Unmarshal(rawAlg, &alg); err != nil {
		return "", false
	}
	return alg, true
}

// buildHS256JWT creates a signed HS256 JWT using only standard library
// packages, mirroring BuildRS256JWT in jwks.go.
//
// The JWS signing input is exactly the ASCII string
// base64url(header) + "." + base64url(claims), both segments unpadded, as
// RFC 7515 section 5.1 requires — the header is inside the signed bytes, so it
// cannot be swapped on a token in flight.
func buildHS256JWT(claims map[string]any, secret string) (string, error) {
	headerBytes, err := json.Marshal(joseHeader{Alg: tokenAlg, Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("auth: jwt header: %w", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("auth: marshal claims: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sigInput := header + "." + payload
	return sigInput + "." + sign(sigInput, secret), nil
}
