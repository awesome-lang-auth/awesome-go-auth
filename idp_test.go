package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var _ AuthCodeStore = (*MemoryAuthCodeStore)(nil)

func sampleAuthCode(code string, ttl time.Duration) AuthCode {
	return AuthCode{
		CodeHash:            hashToken(code),
		UserID:              "usr_1",
		TenantID:            "t1",
		ClientID:            "app",
		Nonce:               "n-1",
		RedirectURI:         "https://app.example.com/cb",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		Scope:               "openid email",
		ExpiresAt:           time.Now().Add(ttl),
	}
}

// TestMemoryAuthCodeStoreConsumesOnce pins the single-use contract: the record
// comes back exactly once, intact, and every call after that — like a call
// before any save — answers ErrInvalidCode.
func TestMemoryAuthCodeStoreConsumesOnce(t *testing.T) {
	store := NewMemoryAuthCodeStore()
	ctx := context.Background()
	want := sampleAuthCode("code-1", time.Minute)

	if _, err := store.ConsumeCode(ctx, want.CodeHash); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("consume before save = %v, want ErrInvalidCode", err)
	}
	if err := store.SaveCode(ctx, want); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	got, err := store.ConsumeCode(ctx, want.CodeHash)
	if err != nil {
		t.Fatalf("first ConsumeCode: %v", err)
	}
	if got != want {
		t.Fatalf("ConsumeCode = %+v, want %+v", got, want)
	}
	if _, err := store.ConsumeCode(ctx, want.CodeHash); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("second ConsumeCode = %v, want ErrInvalidCode", err)
	}
}

// TestMemoryAuthCodeStoreExpiredIsAbsent: an expired record is indistinguishable
// from one that was never saved, is dropped on the attempt, and is swept by the
// next SaveCode so an abandoned flow does not pin memory.
func TestMemoryAuthCodeStoreExpiredIsAbsent(t *testing.T) {
	store := NewMemoryAuthCodeStore()
	ctx := context.Background()

	stale := sampleAuthCode("stale", -time.Second)
	if err := store.SaveCode(ctx, stale); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	if _, err := store.ConsumeCode(ctx, stale.CodeHash); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("consume expired = %v, want ErrInvalidCode", err)
	}
	if n := len(store.codes); n != 0 {
		t.Fatalf("expired record still stored after consume: %d entries", n)
	}

	if err := store.SaveCode(ctx, sampleAuthCode("stale-2", -time.Second)); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	fresh := sampleAuthCode("fresh", time.Minute)
	if err := store.SaveCode(ctx, fresh); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	if n := len(store.codes); n != 1 {
		t.Fatalf("SaveCode did not sweep the expired record: %d entries, want 1", n)
	}
	if _, err := store.ConsumeCode(ctx, fresh.CodeHash); err != nil {
		t.Fatalf("fresh record lost to the sweep: %v", err)
	}
}

// TestMemoryAuthCodeStoreConcurrentConsumersHaveOneWinner is the race the
// process-local map never had to face at scale: 32 redemptions of one code at
// once must produce exactly one record and 31 ErrInvalidCode.
func TestMemoryAuthCodeStoreConcurrentConsumersHaveOneWinner(t *testing.T) {
	const workers = 32
	store := NewMemoryAuthCodeStore()
	ctx := context.Background()
	code := sampleAuthCode("contended", time.Minute)
	if err := store.SaveCode(ctx, code); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}

	var wins, losses atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := store.ConsumeCode(ctx, code.CodeHash)
			switch {
			case err == nil:
				wins.Add(1)
				if got != code {
					t.Errorf("winner got %+v, want %+v", got, code)
				}
			case errors.Is(err, ErrInvalidCode):
				losses.Add(1)
			default:
				t.Errorf("ConsumeCode = %v, want nil or ErrInvalidCode", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins.Load() != 1 || losses.Load() != workers-1 {
		t.Fatalf("wins=%d losses=%d, want 1 and %d", wins.Load(), losses.Load(), workers-1)
	}
}

// TestNewIDPDefaultsCodesAndTTL keeps the pre-seam behaviour for callers that
// never set the new fields: an in-process store and a five-minute code.
func TestNewIDPDefaultsCodesAndTTL(t *testing.T) {
	idp, err := NewIDP(IDPConfig{Issuer: "https://idp.example.com"}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	if _, ok := idp.codes.(*MemoryAuthCodeStore); !ok {
		t.Fatalf("nil Codes resolved to %T, want *MemoryAuthCodeStore", idp.codes)
	}
	if got := idp.codeTTL(); got != 5*time.Minute {
		t.Fatalf("default codeTTL = %v, want 5m", got)
	}

	custom := NewMemoryAuthCodeStore()
	idp, err = NewIDP(IDPConfig{Issuer: "https://idp.example.com", Codes: custom, CodeTTL: 90 * time.Second}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	if idp.codes != AuthCodeStore(custom) {
		t.Fatal("IDPConfig.Codes was not the store the IDP uses")
	}
	if got := idp.codeTTL(); got != 90*time.Second {
		t.Fatalf("codeTTL = %v, want 90s", got)
	}
}

// recordingAuthCodeStore is the injected fake for the end-to-end test. It
// delegates the semantics to MemoryAuthCodeStore and records every call, which
// is what proves the handlers reach the interface rather than a private map.
type recordingAuthCodeStore struct {
	mu       sync.Mutex
	inner    *MemoryAuthCodeStore
	saved    []AuthCode
	consumed []string
}

func (s *recordingAuthCodeStore) SaveCode(ctx context.Context, code AuthCode) error {
	s.mu.Lock()
	s.saved = append(s.saved, code)
	s.mu.Unlock()
	return s.inner.SaveCode(ctx, code)
}

func (s *recordingAuthCodeStore) ConsumeCode(ctx context.Context, codeHash string) (AuthCode, error) {
	s.mu.Lock()
	s.consumed = append(s.consumed, codeHash)
	s.mu.Unlock()
	return s.inner.ConsumeCode(ctx, codeHash)
}

// The replay half delegates too, so the fixture's store is an
// AuthCodeReplayStore exactly as the default one is.
func (s *recordingAuthCodeStore) SaveRedemption(ctx context.Context, r AuthCodeRedemption) error {
	return s.inner.SaveRedemption(ctx, r)
}

func (s *recordingAuthCodeStore) RedemptionOf(ctx context.Context, codeHash string) (AuthCodeRedemption, error) {
	return s.inner.RedemptionOf(ctx, codeHash)
}

func (s *recordingAuthCodeStore) snapshot() ([]AuthCode, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuthCode(nil), s.saved...), append([]string(nil), s.consumed...)
}

const (
	idpTestIssuer   = "https://idp.example.com"
	idpTestEmail    = "idp@example.com"
	idpTestPassword = "supersecure"
	idpTestTenant   = "t1"
	idpTestCodeTTL  = 90 * time.Second
)

var (
	idpTestClient = IDPClient{
		ClientID: "app", ClientSecret: "app-secret",
		RedirectURIs: []string{"https://app.example.com/cb"}, Name: "App",
	}
	idpTestOtherClient = IDPClient{
		ClientID: "other", ClientSecret: "other-secret",
		RedirectURIs: []string{"https://other.example.com/cb"}, Name: "Other",
	}
)

type idpFixture struct {
	srv    *httptest.Server
	client *http.Client
	store  *recordingAuthCodeStore
	user   User
	idp    *IDP
}

// newIDPFixture mounts the IDP on an httptest server over a memory-backed
// Service with one registered, verified user, and an injected AuthCodeStore.
// Options edit the IDPConfig before NewIDP sees it.
func newIDPFixture(t *testing.T, opts ...func(*IDPConfig)) *idpFixture {
	t.Helper()
	svc, err := NewService(testConfig("01234567890123456789012345678901"), NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	user, _, err := svc.Register(context.Background(), RegisterInput{Email: idpTestEmail, Password: idpTestPassword, TenantID: idpTestTenant})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	store := &recordingAuthCodeStore{inner: NewMemoryAuthCodeStore()}
	cfg := IDPConfig{
		Issuer:         idpTestIssuer,
		AccessTokenTTL: 15 * time.Minute,
		Codes:          store,
		CodeTTL:        idpTestCodeTTL,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	idp, err := NewIDP(cfg, svc, idpTestClient, idpTestOtherClient)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	mux := http.NewServeMux()
	idp.RegisterHandlers(mux, "/oidc")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	// The authorize redirect points at the relying party, which does not
	// exist here; stop at the 302 and read Location.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &idpFixture{srv: srv, client: client, store: store, user: user, idp: idp}
}

// authorize logs the fixture user in through POST /authorize for the given
// client and returns the code from the redirect.
func (f *idpFixture) authorize(t *testing.T, client IDPClient, extra url.Values) string {
	t.Helper()
	q := url.Values{
		"client_id":    {client.ClientID},
		"redirect_uri": {client.RedirectURIs[0]},
		"state":        {"st-1"},
		"nonce":        {"n-1"},
	}
	for k, v := range extra {
		q[k] = v
	}
	form := url.Values{"email": {idpTestEmail}, "password": {idpTestPassword}, "tenant_id": {idpTestTenant}}
	resp, err := f.client.PostForm(f.srv.URL+"/oidc/authorize?"+q.Encode(), form)
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /authorize = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != client.RedirectURIs[0] {
		t.Fatalf("redirected to %s, want %s", got, client.RedirectURIs[0])
	}
	if loc.Query().Get("state") != "st-1" {
		t.Fatalf("state not echoed: %q", loc.RawQuery)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %q", loc.RawQuery)
	}
	return code
}

// token redeems code at POST /token as the given client, by client_secret_post.
func (f *idpFixture) token(t *testing.T, code string, client IDPClient, extra ...string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		"redirect_uri":  {client.RedirectURIs[0]},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		if extra[i+1] == dropParam {
			form.Del(extra[i])
			continue
		}
		form.Set(extra[i], extra[i+1])
	}
	status, body, _ := f.postToken(t, form, nil)
	return status, body
}

// postToken posts form to /token, authenticating with HTTP Basic when basic
// is not nil, and decodes the JSON answer whatever its status: every answer of
// the endpoint, refusals included, is a JSON object.
func (f *idpFixture) postToken(t *testing.T, form url.Values, basic *IDPClient) (int, map[string]any, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.srv.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic != nil {
		req.SetBasicAuth(url.QueryEscape(basic.ClientID), url.QueryEscape(basic.ClientSecret))
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /token body (status %d): %v", resp.StatusCode, err)
	}
	return resp.StatusCode, body, resp.Header
}

func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	_, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("splitToken: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

// TestIDPAuthorizeTokenUserInfoThroughStore walks the whole code flow over
// httptest with an injected store: /authorize saves a hashed record carrying
// the request's parameters, /token consumes it by the same hash and mints
// tokens, /userinfo honours the access token, and a replay of the code fails.
func TestIDPAuthorizeTokenUserInfoThroughStore(t *testing.T) {
	f := newIDPFixture(t)
	before := time.Now()
	code := f.authorize(t, idpTestClient, url.Values{
		"scope":                 {"openid email"},
		"code_challenge":        {idpTestChallenge},
		"code_challenge_method": {"S256"},
	})

	saved, consumed := f.store.snapshot()
	if len(saved) != 1 || len(consumed) != 0 {
		t.Fatalf("after /authorize: %d saves, %d consumes; want 1 and 0", len(saved), len(consumed))
	}
	rec := saved[0]
	if rec.CodeHash != hashToken(code) {
		t.Fatalf("stored CodeHash = %q, want hashToken(code) = %q", rec.CodeHash, hashToken(code))
	}
	if rec.CodeHash == code {
		t.Fatal("the clear-text code reached the store")
	}
	want := AuthCode{
		CodeHash: rec.CodeHash, UserID: f.user.ID, TenantID: idpTestTenant, ClientID: idpTestClient.ClientID,
		Nonce: "n-1", RedirectURI: idpTestClient.RedirectURIs[0],
		CodeChallenge: idpTestChallenge, CodeChallengeMethod: "S256", Scope: "openid email",
		ExpiresAt: rec.ExpiresAt,
	}
	if rec != want {
		t.Fatalf("stored record = %+v, want %+v", rec, want)
	}
	if ttl := rec.ExpiresAt.Sub(before); ttl < idpTestCodeTTL-5*time.Second || ttl > idpTestCodeTTL+5*time.Second {
		t.Fatalf("ExpiresAt is %v out, want about IDPConfig.CodeTTL = %v", ttl, idpTestCodeTTL)
	}

	status, body := f.token(t, code, idpTestClient, "code_verifier", idpTestVerifier)
	if status != http.StatusOK {
		t.Fatalf("POST /token = %d, want 200 (%v)", status, body)
	}
	_, consumed = f.store.snapshot()
	if len(consumed) != 1 || consumed[0] != hashToken(code) {
		t.Fatalf("/token consumed %v, want [%s]", consumed, hashToken(code))
	}
	accessToken, _ := body["access_token"].(string)
	idToken, _ := body["id_token"].(string)
	if accessToken == "" || idToken == "" {
		t.Fatalf("/token body missing tokens: %v", body)
	}
	// No offline_access, so no refresh token (OIDC Core §11).
	if _, ok := body["refresh_token"]; ok {
		t.Fatalf("/token issued a refresh token without offline_access: %v", body)
	}
	if body["token_type"] != "Bearer" || body["expires_in"] != float64(900) {
		t.Fatalf("/token body = %v, want Bearer / 900", body)
	}
	claims := decodeJWTPayload(t, idToken)
	if claims["iss"] != idpTestIssuer || claims["sub"] != f.user.ID || claims["aud"] != idpTestClient.ClientID || claims["nonce"] != "n-1" {
		t.Fatalf("id_token claims = %v", claims)
	}

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /userinfo = %d, want 200", resp.StatusCode)
	}
	var info map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("decode /userinfo: %v", err)
	}
	if info["sub"] != f.user.ID || info["email"] != idpTestEmail {
		t.Fatalf("/userinfo = %v", info)
	}

	// Single use: the same code again is refused, and the refusal came from
	// the store, not from anything the handler remembered.
	if status, _ := f.token(t, code, idpTestClient, "code_verifier", idpTestVerifier); status != http.StatusBadRequest {
		t.Fatalf("replayed code: POST /token = %d, want 400", status)
	}
	if _, consumed = f.store.snapshot(); len(consumed) != 2 {
		t.Fatalf("replay did not reach the store: %d consumes", len(consumed))
	}
}

// TestIDPTokenRejectsCodeIssuedToAnotherClient: a code minted for one client
// cannot be redeemed with another client's credentials (RFC 6749 §4.1.3), and
// the attempt burns the code.
func TestIDPTokenRejectsCodeIssuedToAnotherClient(t *testing.T) {
	f := newIDPFixture(t)
	code := f.authorize(t, idpTestClient, nil)

	if status, _ := f.token(t, code, idpTestOtherClient); status != http.StatusBadRequest {
		t.Fatalf("cross-client redemption: POST /token = %d, want 400", status)
	}
	if status, _ := f.token(t, code, idpTestClient); status != http.StatusBadRequest {
		t.Fatalf("code survived a cross-client attempt: POST /token = %d, want 400", status)
	}
}

// TestIDPTokenUnknownCode: a code the store never saw is invalid_grant, and the
// handler asked the store rather than short-circuiting.
func TestIDPTokenUnknownCode(t *testing.T) {
	f := newIDPFixture(t)
	status, _ := f.token(t, "never-issued", idpTestClient)
	if status != http.StatusBadRequest {
		t.Fatalf("POST /token = %d, want 400", status)
	}
	if _, consumed := f.store.snapshot(); len(consumed) != 1 || consumed[0] != hashToken("never-issued") {
		t.Fatalf("store consumed %v, want [hashToken(never-issued)]", consumed)
	}
}

// ---- Signing key, kid, JWKS document and the IdP token pair ----------------

var (
	idpTestKeyOnce sync.Once
	idpTestKeyVal  *rsa.PrivateKey
	idpTestKeyErr  error
)

// idpTestRSAKey is one RSA-2048 key shared by every test that injects a
// signer: generating it is the slow part of these tests under -race, and the
// tests only need a key that is not the ephemeral one.
func idpTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	idpTestKeyOnce.Do(func() { idpTestKeyVal, idpTestKeyErr = rsa.GenerateKey(rand.Reader, 2048) })
	if idpTestKeyErr != nil {
		t.Fatalf("rsa.GenerateKey: %v", idpTestKeyErr)
	}
	return idpTestKeyVal
}

func pemBlock(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// decodeJWTHeader is decodeJWTPayload for the first segment.
func decodeJWTHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	header, _, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("splitToken: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var members map[string]any
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return members
}

// verifyRS256 checks token against pub the way a resource server would —
// RSASSA-PKCS1 v1.5 over the SHA-256 of the signing input, which is what RS256
// is — and returns the decoded header and claims.
func verifyRS256(t *testing.T, token string, pub *rsa.PublicKey) (header, claims map[string]any) {
	t.Helper()
	h, p, s, err := splitToken(token)
	if err != nil {
		t.Fatalf("splitToken: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256([]byte(h + "." + p))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("RS256 signature does not verify: %v", err)
	}
	return decodeJWTHeader(t, token), decodeJWTPayload(t, token)
}

// jwkPublicKey turns a published JWK back into the key a resource server
// verifies with.
func jwkPublicKey(t *testing.T, k JWK) *rsa.PublicKey {
	t.Helper()
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
}

// recordingSigner is the crypto.Signer fake: it records what it was asked to
// sign and with which options, and delegates the signature to an RSA key so
// that the result still verifies. It is the shape a KMS-backed signer has.
type recordingSigner struct {
	key    *rsa.PrivateKey
	mu     sync.Mutex
	calls  int
	digest []byte
	opts   crypto.SignerOpts
	err    error
}

func (s *recordingSigner) Public() crypto.PublicKey { return s.key.Public() }

func (s *recordingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	s.digest = append([]byte(nil), digest...)
	s.opts = opts
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.key.Sign(r, digest, opts)
}

func (s *recordingSigner) snapshot() (int, []byte, crypto.SignerOpts) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, append([]byte(nil), s.digest...), s.opts
}

// TestParseRSAPrivateKeyPEM: the two PEM forms a host can hold parse to the
// same key; anything else is refused with a reason.
func TestParseRSAPrivateKeyPEM(t *testing.T) {
	key := idpTestRSAKey(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(key)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey(ecdsa): %v", err)
	}

	for _, tc := range []struct {
		name, pemText string
		ok            bool
		wantErr       string
	}{
		{name: "pkcs8", pemText: pemBlock("PRIVATE KEY", pkcs8), ok: true},
		{name: "pkcs1", pemText: pemBlock("RSA PRIVATE KEY", pkcs1), ok: true},
		{name: "garbage", pemText: "not a key at all", wantErr: "no PEM block"},
		{name: "empty", pemText: "", wantErr: "no PEM block"},
		{name: "other block type", pemText: pemBlock("CERTIFICATE", pkcs8), wantErr: "unsupported PEM block type"},
		{name: "pkcs8 ecdsa", pemText: pemBlock("PRIVATE KEY", ecPKCS8), wantErr: "want RSA"},
		{name: "pkcs1 truncated", pemText: pemBlock("RSA PRIVATE KEY", pkcs1[:len(pkcs1)/2]), wantErr: "parse PKCS#1"},
		{name: "pkcs8 truncated", pemText: pemBlock("PRIVATE KEY", pkcs8[:len(pkcs8)/2]), wantErr: "parse PKCS#8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRSAPrivateKeyPEM(tc.pemText)
			if !tc.ok {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ParseRSAPrivateKeyPEM = (%T, %v), want error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRSAPrivateKeyPEM: %v", err)
			}
			if !got.Equal(key) {
				t.Fatal("parsed key differs from the one encoded")
			}
		})
	}
}

// TestNewIDPRejectsNonRSASigner: RS256 is RSA, so a signer of any other kind
// is a construction error rather than a stream of tokens no JWKS consumer can
// verify.
func TestNewIDPRejectsNonRSASigner(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	if _, err := NewIDP(IDPConfig{Signer: ecKey}, nil); err == nil || !strings.Contains(err.Error(), "want *rsa.PublicKey") {
		t.Fatalf("NewIDP with an ECDSA signer = %v, want an RSA refusal", err)
	}
}

// TestNewIDPKeyIDDefaultAndOverride: the kid is the reference's constant
// unless configured, and whichever it is appears both in the JWKS document and
// in the header of every token the IDP signs, so a resource server can match
// the two.
func TestNewIDPKeyIDDefaultAndOverride(t *testing.T) {
	key := idpTestRSAKey(t)
	if DefaultIDPKeyID != "provisioner-key-1" {
		t.Fatalf("DefaultIDPKeyID = %q, want the reference constant", DefaultIDPKeyID)
	}
	for _, tc := range []struct{ name, configured, want string }{
		{"default", "", "provisioner-key-1"},
		{"override", "rot-2026-09", "rot-2026-09"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp, err := NewIDP(IDPConfig{Issuer: idpTestIssuer, Signer: key, KeyID: tc.configured}, nil)
			if err != nil {
				t.Fatalf("NewIDP: %v", err)
			}
			if got := idp.JWKS().Keys[0].Kid; got != tc.want {
				t.Fatalf("JWKS kid = %q, want %q", got, tc.want)
			}
			tokens, err := idp.IssueIdPTokenPair(context.Background(), User{ID: "usr_1", Email: idpTestEmail})
			if err != nil {
				t.Fatalf("IssueIdPTokenPair: %v", err)
			}
			idToken, err := idp.buildIDToken(User{ID: "usr_1", Email: idpTestEmail}, idpTestClient.ClientID, "")
			if err != nil {
				t.Fatalf("buildIDToken: %v", err)
			}
			for _, tok := range []string{tokens.AccessToken, tokens.RefreshToken, idToken} {
				header, _ := verifyRS256(t, tok, &key.PublicKey)
				if header["kid"] != tc.want {
					t.Fatalf("token header kid = %v, want %q", header["kid"], tc.want)
				}
			}
		})
	}
}

// TestIDPInjectedSignerSignsIDTokenOnly walks the code flow with a signer that
// records its calls: the id_token verifies against the key GET /jwks publishes
// and was the signer's only work, because the access and refresh tokens /token
// returns are still the HS256 session pair (reference-issues N35: enabling the
// IdP changes nothing about what the session routes sign).
func TestIDPInjectedSignerSignsIDTokenOnly(t *testing.T) {
	rec := &recordingSigner{key: idpTestRSAKey(t)}
	f := newIDPFixture(t, func(cfg *IDPConfig) { cfg.Signer = rec; cfg.KeyID = "kms-1" })
	code := f.authorize(t, idpTestClient, nil)
	status, body := f.token(t, code, idpTestClient)
	if status != http.StatusOK {
		t.Fatalf("POST /token = %d, want 200", status)
	}

	resp, err := f.client.Get(f.srv.URL + "/oidc/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer resp.Body.Close()
	var doc JWKS
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode /jwks: %v", err)
	}
	if len(doc.Keys) != 1 || doc.Keys[0].Kid != "kms-1" {
		t.Fatalf("/jwks = %+v, want the signer's key under kms-1", doc)
	}
	pub := jwkPublicKey(t, doc.Keys[0])
	if !pub.Equal(&rec.key.PublicKey) {
		t.Fatal("the published key is not the injected signer's")
	}

	idToken, _ := body["id_token"].(string)
	header, claims := verifyRS256(t, idToken, pub)
	if header["alg"] != "RS256" || header["typ"] != "JWT" || header["kid"] != "kms-1" {
		t.Fatalf("id_token header = %v", header)
	}
	if claims["sub"] != f.user.ID || claims["aud"] != idpTestClient.ClientID || claims["iss"] != idpTestIssuer {
		t.Fatalf("id_token claims = %v", claims)
	}
	// The access token is the HS256 session token; there is no refresh token
	// without offline_access, and with it the refresh token is opaque, so
	// neither is the signer's work.
	accessToken, _ := body["access_token"].(string)
	if alg := decodeJWTHeader(t, accessToken)["alg"]; alg != "HS256" {
		t.Fatalf("/token access_token alg = %v, want the HS256 session token", alg)
	}
	if calls, _, _ := rec.snapshot(); calls != 1 {
		t.Fatalf("signer was asked %d times during the code flow, want 1 (the id_token)", calls)
	}

	// The IdP pair is the signer's work too: two more signatures.
	if _, err := f.idp.IssueIdPTokenPair(context.Background(), f.user); err != nil {
		t.Fatalf("IssueIdPTokenPair: %v", err)
	}
	if calls, _, _ := rec.snapshot(); calls != 3 {
		t.Fatalf("signer was asked %d times after the pair, want 3", calls)
	}
}

// TestIDPJWKSDocumentShape pins the wire form of the JWKS document to the
// reference's (jwks.service.ts:168-179, :184-186): the six members in that
// order, the signer's key first under its kid, then IDPConfig.PublicKeys
// verbatim, and GET /jwks serving exactly that.
func TestIDPJWKSDocumentShape(t *testing.T) {
	key := idpTestRSAKey(t)
	old := JWK{Kty: "RSA", Use: "sig", Alg: "RS256", Kid: "provisioner-key-0", N: "AK1uZw", E: "AQAB"}
	f := newIDPFixture(t, func(cfg *IDPConfig) { cfg.Signer = key; cfg.PublicKeys = []JWK{old} })

	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	want := `{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"provisioner-key-1","n":"` + n + `","e":"AQAB"},` +
		`{"kty":"RSA","use":"sig","alg":"RS256","kid":"provisioner-key-0","n":"AK1uZw","e":"AQAB"}]}`
	got, err := json.Marshal(f.idp.JWKS())
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	if string(got) != want {
		t.Fatalf("JWKS() = %s\nwant      %s", got, want)
	}

	resp, err := f.client.Get(f.srv.URL + "/oidc/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /jwks: %v", err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("GET /jwks = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if strings.TrimSpace(string(raw)) != want {
		t.Fatalf("GET /jwks body = %s\nwant           %s", raw, want)
	}

	// Without extras the document is the reference's: exactly one key.
	single, err := NewIDP(IDPConfig{Signer: key}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	wantKey, err := NewRSAJWK(&key.PublicKey, DefaultIDPKeyID)
	if err != nil {
		t.Fatalf("NewRSAJWK: %v", err)
	}
	if doc := single.JWKS(); len(doc.Keys) != 1 || doc.Keys[0] != wantKey {
		t.Fatalf("JWKS() without extras = %+v", doc)
	}
	if k, err := NewRSAJWK(&key.PublicKey, "k"); err != nil || k.E != "AQAB" {
		t.Fatalf("NewRSAJWK = (%+v, %v), want e AQAB for 65537", k, err)
	}
}

// TestNewRSAJWKRefusesEmptyKey: a host builds IDPConfig.PublicKeys from keys
// it obtained elsewhere, so the nil a failed fetch leaves behind — or a key
// with no modulus — is an error at the call site, not a panic.
func TestNewRSAJWKRefusesEmptyKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		pub  *rsa.PublicKey
	}{
		{"nil key", nil},
		{"nil modulus", &rsa.PublicKey{E: 65537}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwk, err := NewRSAJWK(tc.pub, "k")
			if err == nil || !strings.Contains(err.Error(), "nil RSA public key") {
				t.Fatalf("NewRSAJWK = (%+v, %v), want a nil-key error", jwk, err)
			}
			if jwk != (JWK{}) {
				t.Fatalf("NewRSAJWK returned %+v alongside the error, want the zero JWK", jwk)
			}
		})
	}
}

// TestNewIDPEphemeralKeyWarnsOnce: with no Signer the IDP logs the reference's
// warning (token.service.ts:52-57) exactly once, at construction, through
// IDPConfig.Logger or, failing that, the Service's logger; with a Signer it
// logs nothing.
func TestNewIDPEphemeralKeyWarnsOnce(t *testing.T) {
	const want = "auth: IdP mode: no Signer configured — auto-generating an ephemeral RSA keypair. All tokens will be invalidated on restart. Set IDPConfig.Signer in production."
	var mu sync.Mutex
	var lines []string
	logger := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	logged := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
	reset := func() {
		mu.Lock()
		defer mu.Unlock()
		lines = nil
	}

	// DisableRefreshTokenGrant keeps the in-memory refresh store warning, which
	// has a test of its own, out of this count.
	idp, err := NewIDP(IDPConfig{Logger: logger, DisableRefreshTokenGrant: true}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	// Nothing after construction repeats it: not signing, not the document.
	if _, err := idp.IssueIdPTokenPair(context.Background(), User{ID: "usr_1"}); err != nil {
		t.Fatalf("IssueIdPTokenPair: %v", err)
	}
	idp.JWKS()
	idp.JWKSHandler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, DefaultJWKSPath, nil))
	if got := logged(); len(got) != 1 || got[0] != want {
		t.Fatalf("logged %q, want exactly one line %q", got, want)
	}

	// With no IDPConfig.Logger the Service's logger receives it.
	cfg := testConfig("01234567890123456789012345678901")
	cfg.Logger = logger
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	reset()
	if _, err := NewIDP(IDPConfig{DisableRefreshTokenGrant: true}, svc); err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	if got := logged(); len(got) != 1 || got[0] != want {
		t.Fatalf("logged through the Service %q, want exactly one line %q", got, want)
	}

	// An injected signer is silence.
	reset()
	if _, err := NewIDP(IDPConfig{Signer: idpTestRSAKey(t), Logger: logger, DisableRefreshTokenGrant: true}, svc); err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	if got := logged(); len(got) != 0 {
		t.Fatalf("logged %q with a Signer configured, want nothing", got)
	}
}

// TestIssueIdPTokenPairClaimsAndTTLs is generateIdProviderTokenPair
// (token.service.ts:73-95) claim by claim: the base claims with the hook
// spread over them, the hook's iat/exp/kid dropped, iss from IDPConfig.Issuer,
// iat = now, exp = now + lifetime with the 30d/90d defaults or the configured
// TTLs, RS256 under the kid, and no session claim anywhere.
func TestIssueIdPTokenPairClaimsAndTTLs(t *testing.T) {
	key := idpTestRSAKey(t)
	cfg := testConfig("01234567890123456789012345678901")
	cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) {
		return map[string]any{"dept": "ops", "role": "admin", "iat": 1, "exp": 2, "kid": "forged", "iss": "hook"}, nil
	}
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	user := User{ID: "usr_1", Email: idpTestEmail, Role: "user", TenantID: idpTestTenant, IsEmailVerified: true}
	fixed := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name           string
		cfg            IDPConfig
		wantAccessTTL  time.Duration
		wantRefreshTTL time.Duration
	}{
		{"defaults", IDPConfig{Issuer: idpTestIssuer, Signer: key}, 30 * 24 * time.Hour, 90 * 24 * time.Hour},
		{"configured", IDPConfig{Issuer: idpTestIssuer, Signer: key, AccessTokenTTL: time.Hour, RefreshTokenTTL: 2 * time.Hour}, time.Hour, 2 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp, err := NewIDP(tc.cfg, svc)
			if err != nil {
				t.Fatalf("NewIDP: %v", err)
			}
			idp.now = func() time.Time { return fixed }
			tokens, err := idp.IssueIdPTokenPair(context.Background(), user)
			if err != nil {
				t.Fatalf("IssueIdPTokenPair: %v", err)
			}
			if tokens.ExpiresIn != tc.wantAccessTTL {
				t.Fatalf("ExpiresIn = %v, want %v", tokens.ExpiresIn, tc.wantAccessTTL)
			}
			for _, tok := range []struct {
				name, token string
				ttl         time.Duration
			}{
				{"access", tokens.AccessToken, tc.wantAccessTTL},
				{"refresh", tokens.RefreshToken, tc.wantRefreshTTL},
			} {
				header, claims := verifyRS256(t, tok.token, &key.PublicKey)
				if want := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "provisioner-key-1"}; !reflect.DeepEqual(header, want) {
					t.Fatalf("%s header = %v, want %v", tok.name, header, want)
				}
				want := map[string]any{
					"sub": "usr_1", "email": idpTestEmail, "role": "admin", "loginProvider": "local",
					"isEmailVerified": true, "isTotpEnabled": false, "dept": "ops",
					"iss": idpTestIssuer,
					"iat": float64(fixed.Unix()), "exp": float64(fixed.Add(tok.ttl).Unix()),
				}
				if !reflect.DeepEqual(claims, want) {
					t.Fatalf("%s claims = %v\nwant           %v", tok.name, claims, want)
				}
			}
		})
	}
}

// TestIssueIdPTokenPairIssuerOnlyWhenConfigured: the reference spreads {iss}
// over the claims only when idProvider.issuer is set (token.service.ts:74-77),
// so with no Issuer a hook's iss survives, and with no hook there is no iss.
func TestIssueIdPTokenPairIssuerOnlyWhenConfigured(t *testing.T) {
	key := idpTestRSAKey(t)
	ctx := context.Background()
	idp, err := NewIDP(IDPConfig{Signer: key}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	tokens, err := idp.IssueIdPTokenPair(ctx, User{ID: "usr_1"})
	if err != nil {
		t.Fatalf("IssueIdPTokenPair: %v", err)
	}
	if _, claims := verifyRS256(t, tokens.AccessToken, &key.PublicKey); claims["iss"] != nil {
		t.Fatalf("iss = %v with no Issuer configured, want absent", claims["iss"])
	}

	cfg := testConfig("01234567890123456789012345678901")
	cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) {
		return map[string]any{"iss": "hook"}, nil
	}
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	idp, err = NewIDP(IDPConfig{Signer: key}, svc)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	tokens, err = idp.IssueIdPTokenPair(ctx, User{ID: "usr_1"})
	if err != nil {
		t.Fatalf("IssueIdPTokenPair: %v", err)
	}
	if _, claims := verifyRS256(t, tokens.AccessToken, &key.PublicKey); claims["iss"] != "hook" {
		t.Fatalf("iss = %v with no Issuer configured, want the hook's", claims["iss"])
	}
}

// TestIssueIdPTokenPairBaseClaimsMatchSessionTokens keeps payloadClaims and
// issueToken in step: for the same user the RS256 pair and the HS256 session
// pair start from the same six base claims (auth.router.ts:378-384), and the
// IdP pair carries none of the session claims.
func TestIssueIdPTokenPairBaseClaimsMatchSessionTokens(t *testing.T) {
	key := idpTestRSAKey(t)
	ctx := context.Background()
	svc, err := NewService(testConfig("01234567890123456789012345678901"), NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	user, _, err := svc.Register(ctx, RegisterInput{Email: idpTestEmail, Password: idpTestPassword, TenantID: idpTestTenant})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	idp, err := NewIDP(IDPConfig{Signer: key}, svc)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	pair, err := idp.IssueIdPTokenPair(ctx, user)
	if err != nil {
		t.Fatalf("IssueIdPTokenPair: %v", err)
	}
	session, err := svc.newSessionTokens(ctx, user)
	if err != nil {
		t.Fatalf("newSessionTokens: %v", err)
	}
	_, idpClaims := verifyRS256(t, pair.AccessToken, &key.PublicKey)
	sessionClaims := decodeJWTPayload(t, session.AccessToken)
	for _, name := range []string{"sub", "email", "role", "loginProvider", "isEmailVerified", "isTotpEnabled"} {
		if !reflect.DeepEqual(idpClaims[name], sessionClaims[name]) {
			t.Errorf("%s: IdP pair %v, session token %v", name, idpClaims[name], sessionClaims[name])
		}
	}
	for _, name := range []string{"sid", "jti", "typ", "tid"} {
		if _, ok := idpClaims[name]; ok {
			t.Errorf("IdP token carries the session claim %q", name)
		}
	}
}

// TestBuildRS256JWTAsksSignerForSHA256Digest pins the contract a KMS-backed
// signer is written against: one Sign call per token, the 32-byte SHA-256 of
// base64url(header).base64url(claims) as the digest, crypto.SHA256 as the
// options (PKCS#1 v1.5, not PSS), and the returned bytes as the signature,
// unchanged.
func TestBuildRS256JWTAsksSignerForSHA256Digest(t *testing.T) {
	rec := &recordingSigner{key: idpTestRSAKey(t)}
	token, err := BuildRS256JWT(rec, "kms-1", map[string]any{"sub": "usr_1", "n": 1})
	if err != nil {
		t.Fatalf("BuildRS256JWT: %v", err)
	}
	h, p, s, err := splitToken(token)
	if err != nil {
		t.Fatalf("splitToken: %v", err)
	}
	calls, digest, opts := rec.snapshot()
	if calls != 1 {
		t.Fatalf("signer called %d times, want 1", calls)
	}
	if want := sha256.Sum256([]byte(h + "." + p)); !bytes.Equal(digest, want[:]) {
		t.Fatalf("signer got digest %x, want SHA-256 of the signing input %x", digest, want)
	}
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		t.Fatalf("signer got opts %v, want crypto.SHA256", opts)
	}
	if _, pss := opts.(*rsa.PSSOptions); pss {
		t.Fatal("signer got PSS options; RS256 is PKCS#1 v1.5")
	}
	if strings.ContainsAny(h+p+s, "=+/") {
		t.Fatalf("token segments are not unpadded base64url: %s", token)
	}
	header, claims := verifyRS256(t, token, &rec.key.PublicKey)
	if want := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "kms-1"}; !reflect.DeepEqual(header, want) {
		t.Fatalf("header = %v, want %v", header, want)
	}
	if want := map[string]any{"sub": "usr_1", "n": float64(1)}; !reflect.DeepEqual(claims, want) {
		t.Fatalf("claims = %v, want %v", claims, want)
	}

	// A signer failure is the caller's error, and no signer is an error too.
	rec.mu.Lock()
	rec.err = errors.New("kms unavailable")
	rec.mu.Unlock()
	if _, err := BuildRS256JWT(rec, "kms-1", map[string]any{}); err == nil || !strings.Contains(err.Error(), "kms unavailable") {
		t.Fatalf("BuildRS256JWT with a failing signer = %v, want the signer's error", err)
	}
	if _, err := BuildRS256JWT(nil, "kms-1", map[string]any{}); err == nil {
		t.Fatal("BuildRS256JWT(nil signer) = nil error")
	}
}

// refusingSigner publishes pub and fails the test if asked to sign: what
// BuildRS256JWT must do with a key that is not RSA is stop before Sign.
type refusingSigner struct {
	t   *testing.T
	pub crypto.PublicKey
}

func (s refusingSigner) Public() crypto.PublicKey { return s.pub }

func (s refusingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	s.t.Error("BuildRS256JWT asked a non-RSA signer to sign")
	return nil, errors.New("refused")
}

// TestBuildRS256JWTRefusesNonRSASigner: called on its own by a host that signs
// elsewhere, with no NewIDP in front of it, BuildRS256JWT still refuses a
// signer whose key is not RSA — the alternative is a token whose header says
// RS256 over a signature no RS256 verifier accepts, and no error anywhere.
func TestBuildRS256JWTRefusesNonRSASigner(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	for _, tc := range []struct {
		name string
		pub  crypto.PublicKey
	}{
		{"ecdsa", ecKey.Public()},
		{"typed nil rsa", (*rsa.PublicKey)(nil)},
		{"rsa without modulus", &rsa.PublicKey{E: 65537}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := BuildRS256JWT(refusingSigner{t: t, pub: tc.pub}, "k", map[string]any{"sub": "usr_1"})
			if err == nil || !strings.Contains(err.Error(), "want *rsa.PublicKey") {
				t.Fatalf("BuildRS256JWT = (%q, %v), want an RSA refusal", token, err)
			}
			if token != "" {
				t.Fatalf("BuildRS256JWT returned %q alongside the error", token)
			}
		})
	}
	// The real ECDSA key, not wrapped, is refused the same way: its Sign would
	// have produced an ECDSA signature under an RS256 header.
	if _, err := BuildRS256JWT(ecKey, "k", map[string]any{}); err == nil || !strings.Contains(err.Error(), "want *rsa.PublicKey") {
		t.Fatalf("BuildRS256JWT(ecdsa key) = %v, want an RSA refusal", err)
	}
}

// TestIDPTokenExpiresInIsSessionAccessLifetime: /token returns the HS256
// session pair, so expires_in is that access token's lifetime,
// Config.AccessTokenTTL, whatever IDPConfig.AccessTokenTTL says — that field
// governs only the IdP pair, whose ExpiresIn still follows it. Before this the
// field reported IDPConfig.AccessTokenTTL raw: 0 when unset, and once the
// default became 30 days, a number describing no token in the response.
func TestIDPTokenExpiresInIsSessionAccessLifetime(t *testing.T) {
	sessionTTL := testConfig("01234567890123456789012345678901").AccessTokenTTL
	for _, tc := range []struct {
		name        string
		idpTTL      time.Duration
		wantPairTTL time.Duration
	}{
		{"unset", 0, 30 * 24 * time.Hour},
		{"configured", 2 * time.Hour, 2 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.idpTTL == sessionTTL || tc.wantPairTTL == sessionTTL {
				t.Fatalf("test cannot discriminate: IdP TTL %v equals the session TTL %v", tc.idpTTL, sessionTTL)
			}
			f := newIDPFixture(t, func(cfg *IDPConfig) { cfg.AccessTokenTTL = tc.idpTTL })
			code := f.authorize(t, idpTestClient, nil)
			status, body := f.token(t, code, idpTestClient)
			if status != http.StatusOK {
				t.Fatalf("POST /token = %d, want 200", status)
			}
			if body["expires_in"] != sessionTTL.Seconds() {
				t.Fatalf("expires_in = %v, want %v (Config.AccessTokenTTL in seconds)", body["expires_in"], sessionTTL.Seconds())
			}
			accessToken, _ := body["access_token"].(string)
			claims := decodeJWTPayload(t, accessToken)
			iat, _ := claims["iat"].(float64)
			exp, _ := claims["exp"].(float64)
			if got := time.Duration(exp-iat) * time.Second; got != sessionTTL {
				t.Fatalf("access token exp - iat = %v, want %v: expires_in does not describe the token beside it", got, sessionTTL)
			}

			pair, err := f.idp.IssueIdPTokenPair(context.Background(), f.user)
			if err != nil {
				t.Fatalf("IssueIdPTokenPair: %v", err)
			}
			if pair.ExpiresIn != tc.wantPairTTL {
				t.Fatalf("IdP pair ExpiresIn = %v, want %v (IDPConfig.AccessTokenTTL)", pair.ExpiresIn, tc.wantPairTTL)
			}
		})
	}
}
