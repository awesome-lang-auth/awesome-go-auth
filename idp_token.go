package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// The token endpoint, <prefix>/token.
//
// Nothing here has a counterpart in the reference, whose IdP mode signs RS256
// tokens and serves the JWKS document and nothing more (auth.router.ts:473-503;
// :927-957 at 1.10.8): it ships no authorization server. The rules below are
// therefore the OAuth and OIDC specifications', and each is cited to them.
//
//   - Client authentication is client_secret_basic or client_secret_post
//     (RFC 6749 §2.3.1), never both in one request, compared in constant time.
//   - authorization_code verifies the PKCE code_verifier when the code was
//     issued with a challenge (RFC 7636 §4.6) and issues a refresh token only
//     when the code was granted offline_access (OIDC Core §11).
//   - refresh_token rotates: every use consumes the presented token and issues
//     a new one, and a consumed token presented again revokes its whole family
//     (RFC 6819 §5.2.2.3, RFC 9700 §4.14.2).
//   - Every answer, success or refusal, is JSON with Cache-Control: no-store
//     and Pragma: no-cache, and every refusal is the RFC 6749 §5.2 error body.

// The grant types and the one PKCE method the endpoint implements, as the
// discovery document advertises them.
const (
	grantTypeAuthorizationCode = "authorization_code"
	grantTypeRefreshToken      = "refresh_token"
	pkceMethodS256             = "S256"
	oidcScopeOfflineAccess     = "offline_access"
	oidcScopeOpenID            = "openid"
)

// tokenBasicRealm is the realm of the WWW-Authenticate challenge a failed
// client_secret_basic attempt is answered with (RFC 6749 §5.2, RFC 7617).
const tokenBasicRealm = `Basic realm="token"`

// tokenError is one RFC 6749 §5.2 refusal. basicChallenge adds the
// WWW-Authenticate header the RFC requires on a 401 after the client tried the
// Authorization header.
type tokenError struct {
	status         int
	code           string
	description    string
	basicChallenge bool
}

func invalidRequest(description string) *tokenError {
	return &tokenError{status: http.StatusBadRequest, code: "invalid_request", description: description}
}

func invalidGrant(description string) *tokenError {
	return &tokenError{status: http.StatusBadRequest, code: "invalid_grant", description: description}
}

func tokenServerError() *tokenError {
	return &tokenError{status: http.StatusInternalServerError, code: "server_error", description: "the request could not be completed"}
}

// writeTokenJSON writes one answer of the token endpoint. RFC 6749 §5.1 and
// §5.2 require both headers on the success and on the error response alike.
func writeTokenJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body) //nolint:errcheck
}

func writeTokenError(w http.ResponseWriter, e *tokenError) {
	if e.basicChallenge {
		w.Header().Set("WWW-Authenticate", tokenBasicRealm)
	}
	body := map[string]any{"error": e.code}
	if e.description != "" {
		body["error_description"] = e.description
	}
	writeTokenJSON(w, e.status, body)
}

func (idp *IDP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, invalidRequest("the request body is not a form"))
		return
	}
	// The grant type is read before the client is authenticated, as it always
	// was here: a request for a grant this endpoint does not implement is
	// unsupported_grant_type whoever sends it, including a request with no form
	// at all.
	grantType := r.FormValue("grant_type")
	if grantType != grantTypeAuthorizationCode && grantType != grantTypeRefreshToken {
		writeTokenError(w, &tokenError{status: http.StatusBadRequest, code: "unsupported_grant_type",
			description: "grant_type must be authorization_code or refresh_token"})
		return
	}
	client, terr := idp.authenticateClient(r)
	if terr != nil {
		writeTokenError(w, terr)
		return
	}
	var body map[string]any
	if grantType == grantTypeAuthorizationCode {
		body, terr = idp.authorizationCodeGrant(r.Context(), r, client)
	} else {
		body, terr = idp.refreshTokenGrant(r.Context(), r, client)
	}
	if terr != nil {
		writeTokenError(w, terr)
		return
	}
	writeTokenJSON(w, http.StatusOK, body)
}

// authenticateClient resolves the client a token request authenticates as, by
// exactly one of the two methods the discovery document advertises
// (RFC 6749 §2.3.1):
//
//   - client_secret_basic: Authorization: Basic base64(id ":" secret), where id
//     and secret are each form-urlencoded before they are joined, so both are
//     decoded here. A client_id form parameter alongside it is allowed only
//     when it names the same client.
//   - client_secret_post: client_id and client_secret form parameters.
//
// A request using both is refused as invalid_request: §2.3 says a client MUST
// NOT use more than one method per request. A failed Basic attempt is the 401
// with a WWW-Authenticate challenge §5.2 requires; a failed post attempt stays
// the 401 it has always been. An unknown client and a wrong secret are the same
// refusal. The secret is compared in constant time, over digests so that its
// length does not leak either.
func (idp *IDP) authenticateClient(r *http.Request) (IDPClient, *tokenError) {
	invalidClient := func(basic bool) *tokenError {
		return &tokenError{status: http.StatusUnauthorized, code: "invalid_client",
			description: "client authentication failed", basicChallenge: basic}
	}
	if header := r.Header.Get("Authorization"); len(header) >= 6 && strings.EqualFold(header[:6], "Basic ") {
		if _, both := r.Form["client_secret"]; both {
			return IDPClient{}, invalidRequest("the client authenticated with both client_secret_basic and client_secret_post")
		}
		rawID, rawSecret, ok := r.BasicAuth()
		if !ok {
			return IDPClient{}, invalidClient(true)
		}
		clientID, err := url.QueryUnescape(rawID)
		if err != nil {
			return IDPClient{}, invalidClient(true)
		}
		secret, err := url.QueryUnescape(rawSecret)
		if err != nil {
			return IDPClient{}, invalidClient(true)
		}
		if formID, present := r.Form["client_id"]; present && (len(formID) != 1 || formID[0] != clientID) {
			return IDPClient{}, invalidRequest("client_id does not match the client in the Authorization header")
		}
		client, ok := idp.clients[clientID]
		if !ok || !clientSecretMatches(client, secret) {
			return IDPClient{}, invalidClient(true)
		}
		return client, nil
	}
	client, ok := idp.clients[r.FormValue("client_id")]
	if !ok || !clientSecretMatches(client, r.FormValue("client_secret")) {
		return IDPClient{}, invalidClient(false)
	}
	return client, nil
}

// clientSecretMatches compares the presented secret with the registered one in
// constant time. Both sides are hashed first because secureEqual returns early
// on a length mismatch.
func clientSecretMatches(client IDPClient, presented string) bool {
	return secureEqual(hashToken(client.ClientSecret), hashToken(presented))
}

// authorizationCodeGrant redeems a code (RFC 6749 §4.1.3).
func (idp *IDP) authorizationCodeGrant(ctx context.Context, r *http.Request, client IDPClient) (map[string]any, *tokenError) {
	// ConsumeCode is destructive: whichever request reaches the store first
	// gets the record and every later one, on any process, gets ErrInvalidCode.
	// That is the whole single-use guarantee, so nothing is cached here. The
	// expiry re-check is belt and braces against a store that does not honour
	// the "expired is absent" clause of the AuthCodeStore contract.
	meta, err := idp.codes.ConsumeCode(ctx, hashToken(r.FormValue("code")))
	if err != nil || idp.now().After(meta.ExpiresAt) {
		return nil, invalidGrant("the authorization code is invalid, expired or already used")
	}
	// RFC 6749 §4.1.3: the code must have been issued to the client now
	// redeeming it. The record carries ClientID precisely so the store can be
	// asked.
	if meta.ClientID != client.ClientID {
		return nil, invalidGrant("the authorization code was issued to another client")
	}
	// RFC 7636 §4.6: a code issued with a challenge is redeemed only with the
	// verifier it was derived from. The code is already consumed, so a wrong
	// guess burns it. A code issued without a challenge is redeemed as it always
	// was, with or without a code_verifier. S256 is the only method /authorize
	// accepts; a record carrying another is refused rather than compared.
	if meta.CodeChallenge != "" {
		verifier := r.FormValue("code_verifier")
		if verifier == "" {
			return nil, invalidGrant("code_verifier is required: the code was issued with a code_challenge")
		}
		if meta.CodeChallengeMethod != pkceMethodS256 || !validPKCEVerifier(verifier) ||
			!secureEqual(pkceS256Challenge(verifier), meta.CodeChallenge) {
			return nil, invalidGrant("code_verifier does not match the code_challenge")
		}
	}

	user, err := idp.authSvc.users.GetUserByID(ctx, meta.UserID, meta.TenantID)
	if err != nil {
		return nil, tokenServerError()
	}
	// The session pair, HS256. Which pair /token returns is decision D-15 of
	// the upstream plan and is not settled here; IssueIdPTokenPair exists for
	// a host that wants the RS256 pair now. expires_in below is this pair's
	// access lifetime, Config.AccessTokenTTL: the lifetime of the token in the
	// body, not IDPConfig.AccessTokenTTL, which governs only the IdP pair.
	//
	// The session's own refresh token stays inside the session. The
	// refresh_token of this response, when there is one, is the grant's opaque
	// token below, which is redeemed here and not at <prefix>/refresh.
	tokens, sessionID, err := idp.authSvc.issueSession(ctx, user)
	if err != nil {
		return nil, tokenServerError()
	}
	idTok, err := idp.buildIDToken(user, client.ClientID, meta.Nonce)
	if err != nil {
		return nil, tokenServerError()
	}
	body := map[string]any{
		"access_token": tokens.AccessToken,
		"id_token":     idTok,
		"token_type":   "Bearer",
		"expires_in":   int(tokens.ExpiresIn.Seconds()),
	}

	// OIDC Core §11: a refresh token is issued when the code was granted
	// offline_access, and not otherwise. §11 also asks for prompt=consent
	// unless "other conditions" permit offline access; here they are that
	// every client is registered by the host itself (NewIDP's clients) and the
	// user has just signed in interactively at /authorize. A client that does
	// not need to act while the user is away therefore holds no long-lived
	// credential, and one that does asks for it in the standard way.
	//
	// The grant checks the session on every refresh, and with a session store
	// that cannot look a session up it could not; rather than issue a token
	// whose revocation it cannot honour, it issues none (RFC 6749 §5.1 makes
	// refresh_token optional) and says why once per request.
	if scopeHas(meta.Scope, oidcScopeOfflineAccess) {
		if !idp.authSvc.canLookupSessions() {
			idp.logf("auth: idp: offline_access granted but the session store cannot look sessions up (SessionLookupStore or SessionAdminStore); no refresh token issued")
		} else {
			familyID, err := newID("rtf")
			if err != nil {
				return nil, tokenServerError()
			}
			refresh, err := idp.saveRefreshToken(ctx, IDPRefreshToken{
				FamilyID:  familyID,
				ClientID:  client.ClientID,
				UserID:    user.ID,
				TenantID:  user.TenantID,
				SessionID: sessionID,
				Scope:     meta.Scope,
				// The session's own expiry, to within the time since
				// issueSession: the family cannot outlive the session whose
				// access tokens it mints.
				ExpiresAt: idp.authSvc.now().Add(idp.authSvc.cfg.RefreshTokenTTL),
			})
			if err != nil {
				return nil, tokenServerError()
			}
			body["refresh_token"] = refresh
		}
	}
	return body, nil
}

// refreshTokenGrant redeems a refresh token (RFC 6749 §6), rotating it.
//
// Every refusal after the token was found also revokes its family where the
// refusal is evidence the token is in the wrong hands or no longer backed by a
// session: a replay of a used token, the token presented by another client
// (RFC 6749 §10.4 binds it to the client it was issued to, so another
// client's holding it is a leak), and a session that was revoked or has
// expired. The legitimate holder then signs in again, which is the cost RFC
// 9700 §4.14.2 accepts for refusing the attacker.
func (idp *IDP) refreshTokenGrant(ctx context.Context, r *http.Request, client IDPClient) (map[string]any, *tokenError) {
	presented := r.FormValue("refresh_token")
	if presented == "" {
		return nil, invalidRequest("refresh_token is required")
	}
	rec, err := idp.refreshTokens.ConsumeRefreshToken(ctx, hashToken(presented))
	switch {
	case errors.Is(err, ErrRefreshTokenReused):
		idp.revokeRefreshFamily(ctx, rec.FamilyID)
		return nil, invalidGrant("the refresh token was already used; every token of its grant is revoked")
	case errors.Is(err, ErrInvalidToken):
		return nil, invalidGrant("the refresh token is invalid, expired or revoked")
	case err != nil:
		return nil, tokenServerError()
	}
	if idp.now().After(rec.ExpiresAt) {
		return nil, invalidGrant("the refresh token is invalid, expired or revoked")
	}
	if rec.ClientID != client.ClientID {
		idp.revokeRefreshFamily(ctx, rec.FamilyID)
		return nil, invalidGrant("the refresh token was issued to another client")
	}
	// RFC 6749 §6: the requested scope may only narrow what was granted, and
	// an absent scope means the granted one. The narrowing reaches the answer —
	// its scope member, and whether an id_token is in it — and not the access
	// token, which is the session's HS256 token and carries no scope claim. The
	// rotated refresh token keeps the granted scope, as §6 requires.
	scope, ok := narrowScope(rec.Scope, r.FormValue("scope"))
	if !ok {
		return nil, &tokenError{status: http.StatusBadRequest, code: "invalid_scope",
			description: "the requested scope exceeds the scope originally granted"}
	}
	session, supported, err := idp.authSvc.lookupSession(ctx, rec.SessionID, rec.UserID, rec.TenantID)
	if !supported || err != nil ||
		idp.authSvc.validateSessionState(session, tokenClaims{Sid: rec.SessionID, Sub: rec.UserID, Tid: rec.TenantID}) != nil {
		idp.revokeRefreshFamily(ctx, rec.FamilyID)
		return nil, invalidGrant("the session behind the refresh token has ended")
	}
	user, err := idp.authSvc.users.GetUserByID(ctx, rec.UserID, rec.TenantID)
	if err != nil {
		idp.revokeRefreshFamily(ctx, rec.FamilyID)
		return nil, invalidGrant("the user behind the refresh token no longer exists")
	}

	access, _, err := idp.authSvc.issueToken(ctx, user, rec.SessionID, "access", idp.authSvc.cfg.AccessTokenTTL)
	if err != nil {
		return nil, tokenServerError()
	}
	rotated := rec
	refresh, err := idp.saveRefreshToken(ctx, rotated)
	if err != nil {
		return nil, tokenServerError()
	}
	body := map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    int(idp.authSvc.cfg.AccessTokenTTL.Seconds()),
	}
	if scope != "" {
		// RFC 6749 §5.1: required when it differs from what was requested,
		// and always sent here so a client never has to work it out.
		body["scope"] = scope
	}
	// OIDC Core §12.2: a refreshed ID token keeps iss, sub and aud, has a new
	// iat, and carries no nonce. It is issued while the effective scope still
	// includes openid, or when the code carried no scope at all — the code
	// exchange issues one regardless of scope, and a grant that never named a
	// scope cannot have narrowed it away.
	if scope == "" || scopeHas(scope, oidcScopeOpenID) {
		idTok, err := idp.buildIDToken(user, client.ClientID, "")
		if err != nil {
			return nil, tokenServerError()
		}
		body["id_token"] = idTok
	}
	return body, nil
}

// saveRefreshToken mints a new opaque token for rec's family and stores its
// hash, returning the clear-text value for the client.
func (idp *IDP) saveRefreshToken(ctx context.Context, rec IDPRefreshToken) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	rec.TokenHash = hashToken(token)
	if err := idp.refreshTokens.SaveRefreshToken(ctx, rec); err != nil {
		return "", err
	}
	return token, nil
}

// revokeRefreshFamily revokes a family, logging a store failure rather than
// answering with it: the request is refused either way, and the refusal is
// what the client has to see.
func (idp *IDP) revokeRefreshFamily(ctx context.Context, familyID string) {
	if err := idp.refreshTokens.RevokeRefreshTokenFamily(ctx, familyID); err != nil {
		idp.logf("auth: idp: revoke refresh token family %s: %v", familyID, err)
	}
}

// scopeHas reports whether the space-separated scope contains want.
func scopeHas(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// narrowScope resolves the scope of a refresh request against the granted
// one (RFC 6749 §6): an empty request is the granted scope, and any other is
// accepted only when every value in it was granted. The result keeps the
// request's order and drops duplicates.
func narrowScope(granted, requested string) (string, bool) {
	if strings.TrimSpace(requested) == "" {
		return strings.Join(strings.Fields(granted), " "), true
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(strings.Fields(requested)))
	for _, s := range strings.Fields(requested) {
		if !scopeHas(granted, s) {
			return "", false
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return strings.Join(out, " "), true
}

// pkceS256Challenge is the S256 code_challenge of verifier:
// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), unpadded (RFC 7636 §4.2).
func pkceS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validPKCEVerifier reports whether v is a code_verifier as RFC 7636 §4.1
// defines one: 43 to 128 characters of ALPHA / DIGIT / "-" / "." / "_" / "~".
func validPKCEVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// pkceAuthorizeError checks the PKCE parameters of an authorization request
// and returns the error_description of the refusal, or "" when they are
// acceptable: both absent, or an S256 challenge.
//
// S256 is the only method accepted. RFC 7636 §4.2 makes plain optional for a
// server and RFC 9700 §2.1.1 tells clients not to use it, since a plain
// challenge is the verifier itself and protects nothing once the authorization
// request is observed. Because §4.3 defaults an absent method to plain, a
// challenge without code_challenge_method is refused too, rather than being
// read as S256 — which would redeem it against a verifier the client never
// derived it from.
func pkceAuthorizeError(challenge, method string) string {
	switch {
	case challenge == "" && method == "":
		return ""
	case challenge == "":
		return "code_challenge_method was sent without a code_challenge"
	case method != pkceMethodS256:
		return "code_challenge_method must be S256; plain, and a code_challenge without a method, are not supported"
	}
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) != sha256.Size {
		return "code_challenge must be the unpadded base64url SHA-256 of the code_verifier"
	}
	return ""
}

// redirectAuthorizeError sends the authorization error response of RFC 6749
// §4.1.2.1 to the canonical redirect URI: error, error_description and the
// client's state, as query parameters.
func redirectAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	redir, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	q := redir.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	redir.RawQuery = q.Encode()
	http.Redirect(w, r, redir.String(), http.StatusFound)
}
