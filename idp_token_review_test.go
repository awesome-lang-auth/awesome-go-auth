package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// The cases the security review of #97 asked for: redirect_uri binding, POST
// only, public clients, the grant switch and its warning, code replay, store
// errors, a deleted user, the family expiry across rotations, and concurrent
// refreshes through the handler.

func TestIDPTokenRedirectURIMustMatchTheAuthorizationRequest(t *testing.T) {
	f := newIDPFixture(t)
	// RFC 6749 §4.1.3: present and identical.
	status, body := f.token(t, f.authorize(t, idpTestClient, nil), idpTestClient, "redirect_uri", dropParam)
	assertTokenError(t, status, body, nil, http.StatusBadRequest, "invalid_grant")
	status, body = f.token(t, f.authorize(t, idpTestClient, nil), idpTestClient, "redirect_uri", "https://app.example.com/other")
	assertTokenError(t, status, body, nil, http.StatusBadRequest, "invalid_grant")
	if status, body := f.token(t, f.authorize(t, idpTestClient, nil), idpTestClient); status != http.StatusOK {
		t.Fatalf("the matching redirect_uri = %d %v", status, body)
	}
}

func TestIDPTokenIsPostOnlyAndReadsNoQuery(t *testing.T) {
	f := newIDPFixture(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequest(method, f.srv.URL+"/oidc/token?grant_type=authorization_code", nil)
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost || body["error"] != "invalid_request" {
			t.Fatalf("%s /token = %d Allow=%q %v, want 405 Allow: POST invalid_request",
				method, resp.StatusCode, resp.Header.Get("Allow"), body)
		}
	}
	for _, name := range []string{"client_id", "client_secret", "code", "code_verifier", "refresh_token"} {
		code := f.authorize(t, idpTestClient, nil)
		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {idpTestClient.RedirectURIs[0]},
			"client_id": {idpTestClient.ClientID}, "client_secret": {idpTestClient.ClientSecret},
		}
		req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/oidc/token?"+url.Values{name: {"x"}}.Encode(),
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		assertTokenError(t, resp.StatusCode, body, resp.Header, http.StatusBadRequest, "invalid_request")
	}
}

func TestNewIDPRefusesEmptyAndDuplicateClientIDs(t *testing.T) {
	key := idpTestRSAKey(t)
	if _, err := NewIDP(IDPConfig{Signer: key}, nil, IDPClient{ClientID: " "}); err == nil {
		t.Fatal("an empty ClientID was accepted")
	}
	if _, err := NewIDP(IDPConfig{Signer: key}, nil, idpTestClient, idpTestClient); err == nil {
		t.Fatal("a ClientID registered twice was accepted")
	}
}

var idpTestPublicClient = IDPClient{
	ClientID: "spa", RedirectURIs: []string{"https://spa.example.com/cb"}, Name: "SPA",
}

func newPublicClientFixture(t *testing.T) *idpFixture {
	t.Helper()
	f := newIDPFixture(t)
	f.idp.clients[idpTestPublicClient.ClientID] = idpTestPublicClient
	return f
}

func TestIDPPublicClient(t *testing.T) {
	pkce := url.Values{"code_challenge": {idpTestChallenge}, "code_challenge_method": {"S256"}}

	t.Run("authorize requires PKCE", func(t *testing.T) {
		f := newPublicClientFixture(t)
		q := url.Values{"client_id": {"spa"}, "redirect_uri": {idpTestPublicClient.RedirectURIs[0]}, "state": {"s"}}
		resp, err := f.client.Get(f.srv.URL + "/oidc/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("state") != "s" {
			t.Fatalf("/authorize without a challenge for a public client = %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})
	t.Run("authenticates by client_id alone, with PKCE", func(t *testing.T) {
		f := newPublicClientFixture(t)
		code := f.authorize(t, idpTestPublicClient, pkce)
		status, body := f.token(t, code, idpTestPublicClient, "client_secret", dropParam, "code_verifier", idpTestVerifier)
		if status != http.StatusOK {
			t.Fatalf("public client exchange = %d %v", status, body)
		}
	})
	t.Run("an empty secret is not a credential", func(t *testing.T) {
		f := newPublicClientFixture(t)
		// The fixture's token() sends client_secret="" for this client.
		status, body := f.token(t, f.authorize(t, idpTestPublicClient, pkce), idpTestPublicClient, "code_verifier", idpTestVerifier)
		assertTokenError(t, status, body, nil, http.StatusUnauthorized, "invalid_client")
		// And Basic with an empty password is no better.
		form := url.Values{"grant_type": {"authorization_code"}, "code": {f.authorize(t, idpTestPublicClient, pkce)},
			"redirect_uri": {idpTestPublicClient.RedirectURIs[0]}, "code_verifier": {idpTestVerifier}}
		status, body, header := f.postToken(t, form, &idpTestPublicClient)
		assertTokenError(t, status, body, header, http.StatusUnauthorized, "invalid_client")
	})
	t.Run("a code without a challenge is refused at token too", func(t *testing.T) {
		f := newPublicClientFixture(t)
		if err := f.store.SaveCode(context.Background(), AuthCode{
			CodeHash: hashToken("no-pkce"), UserID: f.user.ID, TenantID: idpTestTenant, ClientID: "spa",
			RedirectURI: idpTestPublicClient.RedirectURIs[0], ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		status, body := f.token(t, "no-pkce", idpTestPublicClient, "client_secret", dropParam)
		assertTokenError(t, status, body, nil, http.StatusBadRequest, "invalid_grant")
	})
	t.Run("receives rotating refresh tokens", func(t *testing.T) {
		f := newPublicClientFixture(t)
		extra := url.Values{"scope": {"openid offline_access"}}
		for k, v := range pkce {
			extra[k] = v
		}
		code := f.authorize(t, idpTestPublicClient, extra)
		status, body := f.token(t, code, idpTestPublicClient, "client_secret", dropParam, "code_verifier", idpTestVerifier)
		token, _ := body["refresh_token"].(string)
		if status != http.StatusOK || token == "" {
			t.Fatalf("public client offline exchange = %d %v", status, body)
		}
		if status, body, _ := f.refresh(t, token, idpTestPublicClient, "client_secret", dropParam); status != http.StatusOK {
			t.Fatalf("public client refresh = %d %v", status, body)
		}
		status, body, header := f.refresh(t, token, idpTestPublicClient, "client_secret", dropParam)
		assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_grant")
	})
	t.Run("discovery advertises none only with a public client", func(t *testing.T) {
		if got := discoveryList(t, newIDPFixture(t), "token_endpoint_auth_methods_supported"); got != "client_secret_basic client_secret_post" {
			t.Fatalf("auth methods = %s", got)
		}
		if got := discoveryList(t, newPublicClientFixture(t), "token_endpoint_auth_methods_supported"); got != "client_secret_basic client_secret_post none" {
			t.Fatalf("auth methods with a public client = %s", got)
		}
	})
}

func discoveryList(t *testing.T, f *idpFixture, member string) string {
	t.Helper()
	resp, err := f.client.Get(f.srv.URL + "/oidc/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	raw, _ := doc[member].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

func TestIDPDisableRefreshTokenGrant(t *testing.T) {
	f := newIDPFixture(t, func(cfg *IDPConfig) { cfg.DisableRefreshTokenGrant = true })
	code := f.authorize(t, idpTestClient, url.Values{"scope": {"openid offline_access"}})
	status, body := f.token(t, code, idpTestClient)
	if status != http.StatusOK {
		t.Fatalf("exchange = %d %v", status, body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatalf("a refresh token was issued with the grant disabled: %v", body)
	}
	status, body, _ = f.refresh(t, "anything", idpTestClient)
	if status != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
		t.Fatalf("refresh with the grant disabled = %d %v, want unsupported_grant_type", status, body)
	}
	if got := discoveryList(t, f, "grant_types_supported"); got != "authorization_code" {
		t.Errorf("grant_types_supported = %s", got)
	}
	if got := discoveryList(t, f, "scopes_supported"); strings.Contains(got, "offline_access") {
		t.Errorf("scopes_supported = %s", got)
	}
	// Without a session lookup the grant is not advertised either.
	g := newIDPFixture(t)
	g.idp.authSvc.sessions = noLookupSessionStore{inner: g.idp.authSvc.sessions.(*MemorySessionStore)}
	if got := discoveryList(t, g, "grant_types_supported"); got != "authorization_code" {
		t.Errorf("grant_types_supported with no session lookup = %s", got)
	}
}

func TestIDPWarnsOnceAboutTheInMemoryRefreshStore(t *testing.T) {
	key := idpTestRSAKey(t)
	var mu sync.Mutex
	var lines []string
	logger := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, format)
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, l := range lines {
			if l == idpMemoryRefreshStoreWarning {
				n++
			}
		}
		return n
	}
	if _, err := NewIDP(IDPConfig{Signer: key, Logger: logger}, nil); err != nil {
		t.Fatal(err)
	}
	if count() != 1 {
		t.Fatalf("warned %d times, want once", count())
	}
	for _, cfg := range []IDPConfig{
		{Signer: key, Logger: logger, RefreshTokens: NewMemoryIDPRefreshTokenStore()},
		{Signer: key, Logger: logger, DisableRefreshTokenGrant: true},
	} {
		if _, err := NewIDP(cfg, nil); err != nil {
			t.Fatal(err)
		}
	}
	if count() != 1 {
		t.Fatalf("warned with an explicit store or the grant off: %d", count())
	}

	// An IDP with nowhere to log warns when WithIDP binds the Service.
	var bound []string
	idp, err := NewIDP(IDPConfig{Signer: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig("01234567890123456789012345678901")
	cfg.Logger = func(format string, args ...any) { bound = append(bound, format) }
	if _, err := NewWithConfig(cfg, WithIDP(idp)); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, l := range bound {
		if l == idpMemoryRefreshStoreWarning {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("warned %d times at bind, want once", n)
	}
}

// TestIDPReplayedCodeRevokesWhatItProduced: RFC 6749 §4.1.2.
func TestIDPReplayedCodeRevokesWhatItProduced(t *testing.T) {
	f := newIDPFixture(t)
	code := f.authorize(t, idpTestClient, url.Values{"scope": {"openid offline_access"}})
	status, body := f.token(t, code, idpTestClient)
	if status != http.StatusOK {
		t.Fatalf("exchange = %d %v", status, body)
	}
	refresh := body["refresh_token"].(string)
	access := body["access_token"].(string)

	status, body = f.token(t, code, idpTestClient)
	assertTokenError(t, status, body, nil, http.StatusBadRequest, "invalid_grant")

	status, body, header := f.refresh(t, refresh, idpTestClient)
	assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_grant")
	sid, _ := decodeJWTPayload(t, access)["sid"].(string)
	session, err := f.idp.authSvc.sessions.(*MemorySessionStore).GetSessionByID(context.Background(), sid)
	if err != nil || session.RevokedAt == nil {
		t.Fatalf("the replayed code's session = %+v, %v; want it revoked", session, err)
	}
}

// failingSessionStore answers every lookup with a store error.
type failingSessionStore struct{ *MemorySessionStore }

func (failingSessionStore) GetSessionByID(context.Context, string) (Session, error) {
	return Session{}, errors.New("throttled")
}

func TestIDPRefreshStoreErrorIsServerErrorAndRevokesNothing(t *testing.T) {
	f := newIDPFixture(t)
	token := f.offlineGrant(t, "openid offline_access")["refresh_token"].(string)
	real := f.idp.authSvc.sessions.(*MemorySessionStore)
	f.idp.authSvc.sessions = failingSessionStore{real}
	status, body, _ := f.refresh(t, token, idpTestClient)
	if status != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("refresh during a store outage = %d %v, want 500 server_error", status, body)
	}
	// The family was not revoked: the attempt consumed the token, so consuming
	// it again is a reuse, not a revoked-family refusal.
	f.idp.authSvc.sessions = real
	if _, err := f.idp.refreshTokens.ConsumeRefreshToken(context.Background(), hashToken(token)); !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("after an outage the family looks revoked: %v", err)
	}
}

func TestIDPRefreshDeletedUserIssuesNothing(t *testing.T) {
	f := newIDPFixture(t)
	token := f.offlineGrant(t, "openid offline_access")["refresh_token"].(string)
	if err := f.idp.authSvc.users.(*MemoryUserStore).DeleteUser(context.Background(), f.user.ID, idpTestTenant); err != nil {
		t.Fatal(err)
	}
	status, body, _ := f.refresh(t, token, idpTestClient)
	if status == http.StatusOK {
		t.Fatalf("a deleted user's grant was refreshed: %v", body)
	}
	for _, leaked := range []string{"access_token", "refresh_token", "id_token"} {
		if _, ok := body[leaked]; ok {
			t.Fatalf("a refusal for a deleted user carries %s", leaked)
		}
	}
}

func TestIDPRefreshRotationKeepsTheFamilyExpiry(t *testing.T) {
	f := newIDPFixture(t)
	store := f.idp.refreshTokens.(*MemoryIDPRefreshTokenStore)
	expiryOf := func(token string) time.Time {
		store.mu.Lock()
		defer store.mu.Unlock()
		return store.tokens[hashToken(token)].token.ExpiresAt
	}
	token := f.offlineGrant(t, "openid offline_access")["refresh_token"].(string)
	want := expiryOf(token)
	for i := 0; i < 2; i++ {
		_, body, _ := f.refresh(t, token, idpTestClient)
		token = body["refresh_token"].(string)
		if got := expiryOf(token); !got.Equal(want) {
			t.Fatalf("rotation %d moved ExpiresAt from %v to %v", i+1, want, got)
		}
	}
}

// TestIDPConcurrentRefreshesHaveOneWinner: sixteen requests race one token
// through the handler; at most one succeeds, and the family ends up revoked,
// the winner's rotated token included.
func TestIDPConcurrentRefreshesHaveOneWinner(t *testing.T) {
	f := newIDPFixture(t)
	token := f.offlineGrant(t, "openid offline_access")["refresh_token"].(string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var winners []string
	refused := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, body, _ := f.refresh(t, token, idpTestClient)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case status == http.StatusOK:
				winners = append(winners, body["refresh_token"].(string))
			case body["error"] == "invalid_grant":
				refused++
			}
		}()
	}
	wg.Wait()
	if len(winners) > 1 || len(winners)+refused != 16 {
		t.Fatalf("%d winners and %d invalid_grant of 16", len(winners), refused)
	}
	for _, rotated := range winners {
		status, body, header := f.refresh(t, rotated, idpTestClient)
		assertTokenError(t, status, body, header, http.StatusBadRequest, "invalid_grant")
	}
}
