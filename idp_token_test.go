package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var _ IDPRefreshTokenStore = (*MemoryIDPRefreshTokenStore)(nil)

// A code_verifier and its S256 code_challenge, the challenge computed
// independently of this package:
//
//	printf %s "$verifier" | openssl dgst -sha256 -binary | base64 | tr "+/" "-_" | tr -d "="
const (
	idpTestVerifier  = "dBjftJeZ4CVP-mJ92K27uhbUJU1p1r_wW1gFWFOEjXk"
	idpTestChallenge = "ngF5GsXcbwljx6u133FFr3Xht9xooA_DuaX_3QwODtc"
)

func TestPKCES256MatchesAnIndependentDigest(t *testing.T) {
	if got := pkceS256Challenge(idpTestVerifier); got != idpTestChallenge {
		t.Fatalf("pkceS256Challenge = %q, want %q", got, idpTestChallenge)
	}
	if !validPKCEVerifier(idpTestVerifier) {
		t.Fatal("the test verifier must be valid")
	}
	for _, bad := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "+"} {
		if validPKCEVerifier(bad) {
			t.Errorf("validPKCEVerifier(%q) = true", bad)
		}
	}
	for _, ok := range []string{strings.Repeat("a", 43), strings.Repeat("Z9-._~", 21) + "ab"} {
		if !validPKCEVerifier(ok) {
			t.Errorf("validPKCEVerifier(%q) = false", ok)
		}
	}
}

// tokenErrorCode asserts a refusal of the token endpoint: the status, the RFC
// 6749 §5.2 error code, and the two cache headers §5.2 requires.
func assertTokenError(t *testing.T, status int, body map[string]any, header http.Header, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || body["error"] != wantCode {
		t.Fatalf("POST /token = %d %v, want %d error=%s", status, body, wantStatus, wantCode)
	}
	if header != nil && (header.Get("Cache-Control") != "no-store" || header.Get("Pragma") != "no-cache") {
		t.Errorf("refusal headers Cache-Control=%q Pragma=%q, want no-store / no-cache",
			header.Get("Cache-Control"), header.Get("Pragma"))
	}
	for _, leaked := range []string{"access_token", "refresh_token", "id_token"} {
		if _, ok := body[leaked]; ok {
			t.Errorf("a refusal carries %s: %v", leaked, body)
		}
	}
}

func TestIDPTokenPKCE(t *testing.T) {
	pkce := url.Values{"code_challenge": {idpTestChallenge}, "code_challenge_method": {"S256"}}

	t.Run("matching verifier", func(t *testing.T) {
		f := newIDPFixture(t)
		code := f.authorize(t, idpTestClient, pkce)
		status, body := f.token(t, code, idpTestClient, "code_verifier", idpTestVerifier)
		if status != http.StatusOK || body["access_token"] == nil {
			t.Fatalf("POST /token = %d %v, want 200 with tokens", status, body)
		}
	})
	t.Run("mismatched verifier", func(t *testing.T) {
		f := newIDPFixture(t)
		code := f.authorize(t, idpTestClient, pkce)
		status, body := f.token(t, code, idpTestClient, "code_verifier", strings.Repeat("x", 43))
		assertTokenError(t, status, body, nil, http.StatusBadRequest, "invalid_grant")
		// The code was consumed by the failed attempt: the right verifier
		// cannot rescue it afterwards.
		status, body = f.token(t, code, idpTestClient, "code_verifier", idpTestVerifier)
		assertTokenError(t, status, body, nil, http.StatusBadRequest, "invalid_grant")
	})
	t.Run("malformed verifier", func(t *testing.T) {
		f := newIDPFixture(t)
		code := f.authorize(t, idpTestClient, pkce)
		status, body := f.token(t, code, idpTestClient, "code_verifier", "short")
		assertTokenError(t, status, body, nil, http.StatusBadRequest, "invalid_grant")
	})
	t.Run("missing verifier", func(t *testing.T) {
		f := newIDPFixture(t)
		code := f.authorize(t, idpTestClient, pkce)
		status, body := f.token(t, code, idpTestClient)
		assertTokenError(t, status, body, nil, http.StatusBadRequest, "invalid_grant")
	})
	t.Run("no challenge is unchanged", func(t *testing.T) {
		f := newIDPFixture(t)
		code := f.authorize(t, idpTestClient, nil)
		if status, body := f.token(t, code, idpTestClient); status != http.StatusOK {
			t.Fatalf("POST /token = %d %v, want 200", status, body)
		}
		code = f.authorize(t, idpTestClient, nil)
		if status, body := f.token(t, code, idpTestClient, "code_verifier", idpTestVerifier); status != http.StatusOK {
			t.Fatalf("POST /token with an unneeded verifier = %d %v, want 200", status, body)
		}
	})
	t.Run("a stored record with another method is refused", func(t *testing.T) {
		// A code saved before /authorize validated the method, or by a store
		// written by hand, is not compared as though it were S256.
		f := newIDPFixture(t)
		if err := f.store.SaveCode(context.Background(), AuthCode{
			CodeHash: hashToken("legacy-plain"), UserID: f.user.ID, TenantID: idpTestTenant,
			ClientID: idpTestClient.ClientID, CodeChallenge: idpTestVerifier, CodeChallengeMethod: "plain",
			ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		status, body := f.token(t, "legacy-plain", idpTestClient, "code_verifier", idpTestVerifier)
		assertTokenError(t, status, body, nil, http.StatusBadRequest, "invalid_grant")
	})
}

func TestIDPAuthorizeRefusesUnsupportedPKCE(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params url.Values
	}{
		{"plain", url.Values{"code_challenge": {idpTestVerifier}, "code_challenge_method": {"plain"}}},
		{"challenge without a method", url.Values{"code_challenge": {idpTestChallenge}}},
		{"method without a challenge", url.Values{"code_challenge_method": {"S256"}}},
		{"challenge that is no SHA-256", url.Values{"code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIDPFixture(t)
			q := url.Values{
				"client_id":    {idpTestClient.ClientID},
				"redirect_uri": {idpTestClient.RedirectURIs[0]},
				"state":        {"st-1"},
			}
			for k, v := range tc.params {
				q[k] = v
			}
			form := url.Values{"email": {idpTestEmail}, "password": {idpTestPassword}, "tenant_id": {idpTestTenant}}
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				var resp *http.Response
				var err error
				if method == http.MethodGet {
					resp, err = f.client.Get(f.srv.URL + "/oidc/authorize?" + q.Encode())
				} else {
					resp, err = f.client.PostForm(f.srv.URL+"/oidc/authorize?"+q.Encode(), form)
				}
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusFound {
					t.Fatalf("%s /authorize = %d, want 302", method, resp.StatusCode)
				}
				loc, err := url.Parse(resp.Header.Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				if got := loc.Scheme + "://" + loc.Host + loc.Path; got != idpTestClient.RedirectURIs[0] {
					t.Fatalf("redirected to %s", got)
				}
				lq := loc.Query()
				if lq.Get("error") != "invalid_request" || lq.Get("state") != "st-1" || lq.Get("error_description") == "" || lq.Get("code") != "" {
					t.Fatalf("%s /authorize redirect query = %q", method, loc.RawQuery)
				}
			}
			if saved, _ := f.store.snapshot(); len(saved) != 0 {
				t.Fatalf("a refused authorization request saved %d codes", len(saved))
			}
		})
	}
}

func TestIDPTokenClientSecretBasic(t *testing.T) {
	codeForm := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}}
	}

	t.Run("basic authenticates", func(t *testing.T) {
		f := newIDPFixture(t)
		status, body, header := f.postToken(t, codeForm(f.authorize(t, idpTestClient, nil)), &idpTestClient)
		if status != http.StatusOK || body["access_token"] == nil {
			t.Fatalf("POST /token = %d %v", status, body)
		}
		if header.Get("Cache-Control") != "no-store" || header.Get("Pragma") != "no-cache" {
			t.Errorf("success headers Cache-Control=%q Pragma=%q", header.Get("Cache-Control"), header.Get("Pragma"))
		}
	})
	t.Run("basic with the same client_id in the form", func(t *testing.T) {
		f := newIDPFixture(t)
		form := codeForm(f.authorize(t, idpTestClient, nil))
		form.Set("client_id", idpTestClient.ClientID)
		if status, body, _ := f.postToken(t, form, &idpTestClient); status != http.StatusOK {
			t.Fatalf("POST /token = %d %v", status, body)
		}
	})
	t.Run("basic with a wrong secret is a 401 with a challenge", func(t *testing.T) {
		f := newIDPFixture(t)
		wrong := idpTestClient
		wrong.ClientSecret = "not-the-secret"
		status, body, header := f.postToken(t, codeForm(f.authorize(t, idpTestClient, nil)), &wrong)
		assertTokenError(t, status, body, header, http.StatusUnauthorized, "invalid_client")
		if got := header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
			t.Errorf("WWW-Authenticate = %q, want a Basic challenge", got)
		}
	})
	t.Run("post with a wrong secret is a 401 without a challenge", func(t *testing.T) {
		f := newIDPFixture(t)
		form := codeForm(f.authorize(t, idpTestClient, nil))
		form.Set("client_id", idpTestClient.ClientID)
		form.Set("client_secret", "not-the-secret")
		status, body, header := f.postToken(t, form, nil)
		assertTokenError(t, status, body, header, http.StatusUnauthorized, "invalid_client")
		if got := header.Get("WWW-Authenticate"); got != "" {
			t.Errorf("WWW-Authenticate = %q on a post attempt", got)
		}
	})
	t.Run("both methods at once are refused", func(t *testing.T) {
		f := newIDPFixture(t)
		code := f.authorize(t, idpTestClient, nil)
		form := codeForm(code)
		form.Set("client_id", idpTestClient.ClientID)
		form.Set("client_secret", idpTestClient.ClientSecret)
		status, body, header := f.postToken(t, form, &idpTestClient)
		assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_request")
		// Refused before the code was looked at: it is still redeemable.
		if status, body := f.token(t, code, idpTestClient); status != http.StatusOK {
			t.Fatalf("the code did not survive a refused client authentication: %d %v", status, body)
		}
	})
	t.Run("a different client_id beside basic is refused", func(t *testing.T) {
		f := newIDPFixture(t)
		form := codeForm(f.authorize(t, idpTestClient, nil))
		form.Set("client_id", idpTestOtherClient.ClientID)
		status, body, header := f.postToken(t, form, &idpTestClient)
		assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_request")
	})
}

// TestAuthenticateClientDecodesFormEncodedBasicCredentials: RFC 6749 §2.3.1
// form-urlencodes the id and the secret before they are joined with ":", so a
// secret containing ":" or "%" reaches the comparison decoded.
func TestAuthenticateClientDecodesFormEncodedBasicCredentials(t *testing.T) {
	client := IDPClient{ClientID: "app:one", ClientSecret: "s3cr%t:with+plus"}
	idp := &IDP{clients: map[string]IDPClient{client.ClientID: client}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=authorization_code"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(client.ClientID), url.QueryEscape(client.ClientSecret))
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	got, terr := idp.authenticateClient(req)
	if terr != nil || got.ClientID != client.ClientID {
		t.Fatalf("authenticateClient = %v, %+v", got.ClientID, terr)
	}

	bad := httptest.NewRequest(http.MethodPost, "/token", nil)
	bad.Header.Set("Authorization", "Basic not-base64!")
	if err := bad.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if _, terr := idp.authenticateClient(bad); terr == nil || terr.code != "invalid_client" || !terr.basicChallenge {
		t.Fatalf("a malformed Basic header = %+v, want invalid_client with a challenge", terr)
	}
}

// ---- refresh_token grant -----------------------------------------------------

func (f *idpFixture) refresh(t *testing.T, token string, client IDPClient, extra ...string) (int, map[string]any, http.Header) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		form.Set(extra[i], extra[i+1])
	}
	return f.postToken(t, form, nil)
}

// offlineGrant runs the code flow with offline_access and returns the body.
func (f *idpFixture) offlineGrant(t *testing.T, scope string) map[string]any {
	t.Helper()
	code := f.authorize(t, idpTestClient, url.Values{"scope": {scope}})
	status, body := f.token(t, code, idpTestClient)
	if status != http.StatusOK {
		t.Fatalf("POST /token = %d %v", status, body)
	}
	if s, _ := body["refresh_token"].(string); s == "" {
		t.Fatalf("no refresh token with scope %q: %v", scope, body)
	}
	return body
}

func TestIDPRefreshTokenIssuedOnlyWithOfflineAccess(t *testing.T) {
	f := newIDPFixture(t)
	for _, scope := range []string{"", "openid", "openid email profile"} {
		code := f.authorize(t, idpTestClient, url.Values{"scope": {scope}})
		status, body := f.token(t, code, idpTestClient)
		if status != http.StatusOK {
			t.Fatalf("scope %q: POST /token = %d", scope, status)
		}
		if _, ok := body["refresh_token"]; ok {
			t.Fatalf("scope %q: a refresh token was issued without offline_access: %v", scope, body)
		}
	}
	body := f.offlineGrant(t, "openid offline_access")
	// It is the grant's opaque token, not the session's HS256 refresh JWT,
	// and the code exchange's own answer is otherwise unchanged.
	if rt := body["refresh_token"].(string); strings.Count(rt, ".") == 2 {
		t.Fatalf("refresh_token looks like a JWT: %q", rt)
	}
	if _, ok := body["scope"]; ok {
		t.Errorf("the code exchange answer grew a scope member: %v", body)
	}
}

func TestIDPRefreshTokenRotates(t *testing.T) {
	f := newIDPFixture(t)
	first := f.offlineGrant(t, "openid email offline_access")
	firstRefresh := first["refresh_token"].(string)
	firstClaims := decodeJWTPayload(t, first["access_token"].(string))

	status, body, header := f.refresh(t, firstRefresh, idpTestClient)
	if status != http.StatusOK {
		t.Fatalf("refresh = %d %v", status, body)
	}
	if header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", header.Get("Cache-Control"))
	}
	second, _ := body["refresh_token"].(string)
	if second == "" || second == firstRefresh {
		t.Fatalf("refresh did not rotate the token: %v", body)
	}
	if body["token_type"] != "Bearer" || body["expires_in"] != float64(900) || body["scope"] != "openid email offline_access" {
		t.Fatalf("refresh body = %v", body)
	}
	claims := decodeJWTPayload(t, body["access_token"].(string))
	if claims["sid"] != firstClaims["sid"] || claims["sub"] != f.user.ID || claims["typ"] != "access" {
		t.Fatalf("refreshed access token claims = %v, want the same session %v", claims, firstClaims["sid"])
	}
	if _, err := f.idp.authSvc.Authenticate(context.Background(), body["access_token"].(string)); err != nil {
		t.Fatalf("the refreshed access token does not authenticate: %v", err)
	}
	idClaims := decodeJWTPayload(t, body["id_token"].(string))
	if idClaims["sub"] != f.user.ID || idClaims["aud"] != idpTestClient.ClientID || idClaims["iss"] != idpTestIssuer {
		t.Fatalf("refreshed id_token claims = %v", idClaims)
	}
	if _, ok := idClaims["nonce"]; ok {
		t.Errorf("a refreshed id_token carries a nonce (OIDC Core §12.2): %v", idClaims)
	}

	// The rotated token works in turn.
	if status, body, _ := f.refresh(t, second, idpTestClient); status != http.StatusOK {
		t.Fatalf("second refresh = %d %v", status, body)
	}
}

func TestIDPRefreshTokenReuseRevokesTheFamily(t *testing.T) {
	f := newIDPFixture(t)
	first := f.offlineGrant(t, "openid offline_access")["refresh_token"].(string)
	_, body, _ := f.refresh(t, first, idpTestClient)
	second := body["refresh_token"].(string)

	// The replay is refused...
	status, body, header := f.refresh(t, first, idpTestClient)
	assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_grant")
	// ...and it took the live token of the same family with it.
	status, body, header = f.refresh(t, second, idpTestClient)
	assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_grant")

	// Another grant of the same user and client is a different family and is
	// untouched.
	other := f.offlineGrant(t, "openid offline_access")["refresh_token"].(string)
	if status, body, _ := f.refresh(t, other, idpTestClient); status != http.StatusOK {
		t.Fatalf("an unrelated family was revoked: %d %v", status, body)
	}
}

func TestIDPRefreshTokenWrongClient(t *testing.T) {
	f := newIDPFixture(t)
	token := f.offlineGrant(t, "openid offline_access")["refresh_token"].(string)
	status, body, header := f.refresh(t, token, idpTestOtherClient)
	assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_grant")
	// Another client holding the token is a leak: the family is revoked, so
	// the rightful client cannot use it either.
	status, body, header = f.refresh(t, token, idpTestClient)
	assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_grant")

	// And the client must authenticate at all.
	token = f.offlineGrant(t, "openid offline_access")["refresh_token"].(string)
	wrong := idpTestClient
	wrong.ClientSecret = "nope"
	status, body, header = f.refresh(t, token, wrong)
	assertTokenError(t, status, body, header, http.StatusUnauthorized, "invalid_client")
	// Refused before the token was consumed, so it still works.
	if status, body, _ := f.refresh(t, token, idpTestClient); status != http.StatusOK {
		t.Fatalf("a refused client authentication burned the token: %d %v", status, body)
	}
}

func TestIDPRefreshTokenOverBasic(t *testing.T) {
	f := newIDPFixture(t)
	token := f.offlineGrant(t, "openid offline_access")["refresh_token"].(string)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
	if status, body, _ := f.postToken(t, form, &idpTestClient); status != http.StatusOK {
		t.Fatalf("refresh over client_secret_basic = %d %v", status, body)
	}
}

func TestIDPRefreshTokenScopeNarrowing(t *testing.T) {
	f := newIDPFixture(t)
	token := f.offlineGrant(t, "openid email offline_access")["refresh_token"].(string)

	status, body, _ := f.refresh(t, token, idpTestClient, "scope", "email email")
	if status != http.StatusOK {
		t.Fatalf("narrowed refresh = %d %v", status, body)
	}
	if body["scope"] != "email" {
		t.Fatalf("scope = %v, want the narrowed \"email\"", body["scope"])
	}
	// openid was narrowed away, so there is no ID token.
	if _, ok := body["id_token"]; ok {
		t.Fatalf("an id_token was issued for a scope without openid: %v", body)
	}
	// RFC 6749 §6: the rotated token keeps the granted scope, so a later
	// refresh without a scope parameter gets all of it back.
	status, body, _ = f.refresh(t, body["refresh_token"].(string), idpTestClient)
	if status != http.StatusOK || body["scope"] != "openid email offline_access" || body["id_token"] == nil {
		t.Fatalf("refresh after narrowing = %d %v, want the full granted scope and an id_token", status, body)
	}

	// Widening is invalid_scope.
	status, body, header := f.refresh(t, body["refresh_token"].(string), idpTestClient, "scope", "openid profile")
	assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_scope")
}

func TestIDPRefreshTokenExpiry(t *testing.T) {
	f := newIDPFixture(t)
	token := f.offlineGrant(t, "openid offline_access")["refresh_token"].(string)
	// The family lives as long as the session the code opened,
	// Config.RefreshTokenTTL; a day past it the token is refused by the
	// handler's own check, whatever the store's clock says.
	ttl := f.idp.authSvc.cfg.RefreshTokenTTL
	f.idp.now = func() time.Time { return time.Now().Add(ttl + 24*time.Hour) }
	status, body, header := f.refresh(t, token, idpTestClient)
	assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_grant")
}

func TestIDPRefreshTokenEndsWithTheSession(t *testing.T) {
	f := newIDPFixture(t)
	grant := f.offlineGrant(t, "openid offline_access")
	sid, _ := decodeJWTPayload(t, grant["access_token"].(string))["sid"].(string)
	sessions := f.idp.authSvc.sessions.(*MemorySessionStore)
	if err := sessions.RevokeSessionByID(context.Background(), sid); err != nil {
		t.Fatal(err)
	}
	status, body, header := f.refresh(t, grant["refresh_token"].(string), idpTestClient)
	assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_grant")
}

// noLookupSessionStore is a SessionStore with none of the optional lookups.
type noLookupSessionStore struct{ inner *MemorySessionStore }

func (s noLookupSessionStore) CreateSession(ctx context.Context, session Session) (Session, error) {
	return s.inner.CreateSession(ctx, session)
}

func (s noLookupSessionStore) GetSessionByRefreshTokenHash(ctx context.Context, hash string) (Session, error) {
	return s.inner.GetSessionByRefreshTokenHash(ctx, hash)
}

func (s noLookupSessionStore) UpdateSession(ctx context.Context, session Session) error {
	return s.inner.UpdateSession(ctx, session)
}

// TestIDPNoRefreshTokenWithoutSessionLookup: the grant checks the session on
// every refresh, so with a store that cannot look one up no token is issued.
func TestIDPNoRefreshTokenWithoutSessionLookup(t *testing.T) {
	var logged atomic.Value
	f := newIDPFixture(t, func(cfg *IDPConfig) {
		cfg.Logger = func(format string, args ...any) { logged.Store(format) }
	})
	f.idp.authSvc.sessions = noLookupSessionStore{inner: f.idp.authSvc.sessions.(*MemorySessionStore)}
	code := f.authorize(t, idpTestClient, url.Values{"scope": {"openid offline_access"}})
	status, body := f.token(t, code, idpTestClient)
	if status != http.StatusOK {
		t.Fatalf("POST /token = %d %v", status, body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatalf("a refresh token was issued with a store that cannot check its session: %v", body)
	}
	if msg, _ := logged.Load().(string); !strings.Contains(msg, "no refresh token issued") {
		t.Fatalf("logged %q", msg)
	}
}

func TestIDPRefreshGrantRefusals(t *testing.T) {
	f := newIDPFixture(t)
	status, body, header := f.refresh(t, "", idpTestClient)
	assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_request")
	status, body, header = f.refresh(t, "never-issued", idpTestClient)
	assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_grant")
	// A session refresh JWT is not a grant refresh token.
	_, tokens, err := f.idp.authSvc.Login(context.Background(), LoginInput{Email: idpTestEmail, Password: idpTestPassword, TenantID: idpTestTenant})
	if err != nil {
		t.Fatal(err)
	}
	status, body, header = f.refresh(t, tokens.RefreshToken, idpTestClient)
	assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_grant")
}

func TestIDPDiscoveryAdvertisesTheTokenEndpoint(t *testing.T) {
	f := newIDPFixture(t)
	resp, err := f.client.Get(f.srv.URL + "/oidc/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	for member, want := range map[string]string{
		"grant_types_supported":                 "authorization_code refresh_token",
		"token_endpoint_auth_methods_supported": "client_secret_basic client_secret_post",
		"code_challenge_methods_supported":      "S256",
		"scopes_supported":                      "openid email profile offline_access",
	} {
		raw, _ := doc[member].([]any)
		got := make([]string, 0, len(raw))
		for _, v := range raw {
			s, _ := v.(string)
			got = append(got, s)
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%s = %v, want [%s]", member, doc[member], want)
		}
	}
}

// ---- MemoryIDPRefreshTokenStore -------------------------------------------

func sampleRefreshToken(hash, family string, ttl time.Duration) IDPRefreshToken {
	return IDPRefreshToken{
		TokenHash: hash, FamilyID: family, ClientID: "app", UserID: "usr_1", TenantID: "t1",
		SessionID: "ses_1", Scope: "openid offline_access", ExpiresAt: time.Now().Add(ttl),
	}
}

func TestMemoryIDPRefreshTokenStoreContract(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryIDPRefreshTokenStore()
	rec := sampleRefreshToken("h1", "fam1", time.Hour)
	if err := s.SaveRefreshToken(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumeRefreshToken(ctx, "h1")
	if err != nil || got != rec {
		t.Fatalf("first consume = %+v, %v", got, err)
	}
	// A used token is a tombstone: its replay names the family.
	got, err = s.ConsumeRefreshToken(ctx, "h1")
	if !errors.Is(err, ErrRefreshTokenReused) || got.FamilyID != "fam1" {
		t.Fatalf("replay = %+v, %v; want the record with ErrRefreshTokenReused", got, err)
	}
	if _, err := s.ConsumeRefreshToken(ctx, "unknown"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unknown = %v", err)
	}

	// Revocation covers members saved before and after it.
	if err := s.SaveRefreshToken(ctx, sampleRefreshToken("h2", "fam1", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeRefreshTokenFamily(ctx, "fam1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRefreshToken(ctx, sampleRefreshToken("h3", "fam1", time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"h1", "h2", "h3"} {
		if _, err := s.ConsumeRefreshToken(ctx, h); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("%s of a revoked family = %v, want ErrInvalidToken", h, err)
		}
	}
	if err := s.RevokeRefreshTokenFamily(ctx, "never-seen"); err != nil {
		t.Fatalf("revoking an unknown family: %v", err)
	}

	// Expired is absent.
	if err := s.SaveRefreshToken(ctx, sampleRefreshToken("old", "fam2", -time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeRefreshToken(ctx, "old"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired = %v", err)
	}
}

func TestMemoryIDPRefreshTokenStoreConcurrentConsumersHaveOneWinner(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryIDPRefreshTokenStore()
	if err := s.SaveRefreshToken(ctx, sampleRefreshToken("race", "fam", time.Hour)); err != nil {
		t.Fatal(err)
	}
	var wins, reused int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ConsumeRefreshToken(ctx, "race")
			switch {
			case err == nil:
				atomic.AddInt32(&wins, 1)
			case errors.Is(err, ErrRefreshTokenReused):
				atomic.AddInt32(&reused, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 || reused != 31 {
		t.Fatalf("wins = %d, reused = %d; want 1 and 31", wins, reused)
	}
}

func TestNewIDPDefaultsRefreshTokenStore(t *testing.T) {
	idp, err := NewIDP(IDPConfig{Issuer: "https://idp.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := idp.refreshTokens.(*MemoryIDPRefreshTokenStore); !ok {
		t.Fatalf("nil RefreshTokens resolved to %T", idp.refreshTokens)
	}
	custom := NewMemoryIDPRefreshTokenStore()
	idp, err = NewIDP(IDPConfig{Issuer: "https://idp.example.com", RefreshTokens: custom}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if idp.refreshTokens != IDPRefreshTokenStore(custom) {
		t.Fatal("IDPConfig.RefreshTokens was not the store the IDP uses")
	}
}
