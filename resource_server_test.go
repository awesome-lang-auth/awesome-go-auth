package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// testClock is the clock a JWKSClient measures its TTL against, so a cache can
// be made stale without waiting an hour. Every access is locked because the
// client reads it from its own goroutine during a background refresh.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func newTestClock() *testClock {
	return &testClock{at: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// jwksTestServer is a JWKS endpoint whose document, status and timing the test
// controls: swap the document to rotate a key, set a status to break a
// refresh, install a gate to hold a fetch open while assertions run.
type jwksTestServer struct {
	srv *httptest.Server

	mu      sync.Mutex
	doc     JWKS
	body    string // when non-empty, served instead of doc
	status  int
	fetches int
	gate    chan struct{}

	arrived chan struct{}
}

func newJWKSTestServer(t *testing.T, doc JWKS) *jwksTestServer {
	t.Helper()
	s := &jwksTestServer{doc: doc, status: http.StatusOK, arrived: make(chan struct{}, 64)}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		s.fetches++
		gate := s.gate
		s.mu.Unlock()

		select {
		case s.arrived <- struct{}{}:
		default:
		}
		if gate != nil {
			<-gate
		}

		// Read the response *after* the gate, so a test can swap the document
		// while the fetch is held open.
		s.mu.Lock()
		status, doc, body := s.status, s.doc, s.body
		s.mu.Unlock()

		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *jwksTestServer) serve(doc JWKS) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.doc, s.body, s.status = doc, "", http.StatusOK
}

func (s *jwksTestServer) serveBody(body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.status = body, http.StatusOK
}

func (s *jwksTestServer) fail(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
}

// jwksGate holds a fetch open inside the handler. Releasing is idempotent so
// that a test may release explicitly and the cleanup may release again — which
// is what keeps a failed assertion from deadlocking httptest.Server.Close on a
// request nobody ever let go.
type jwksGate struct {
	ch   chan struct{}
	once sync.Once
}

func (g *jwksGate) release() { g.once.Do(func() { close(g.ch) }) }

// hold blocks the next fetch inside the handler and drains any arrival
// recorded before now, so waitArrived observes only what happens after this
// call — a cache warmed a moment ago must not satisfy it.
func (s *jwksTestServer) hold(t *testing.T) *jwksGate {
	t.Helper()
	gate := &jwksGate{ch: make(chan struct{})}
	s.mu.Lock()
	s.gate = gate.ch
	s.mu.Unlock()
	for drained := false; !drained; {
		select {
		case <-s.arrived:
		default:
			drained = true
		}
	}
	t.Cleanup(func() { s.release(gate) })
	return gate
}

func (s *jwksTestServer) release(gate *jwksGate) {
	s.mu.Lock()
	if s.gate == gate.ch {
		s.gate = nil
	}
	s.mu.Unlock()
	gate.release()
}

func (s *jwksTestServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

// waitArrived blocks until one request has reached the handler.
func (s *jwksTestServer) waitArrived(t *testing.T) {
	t.Helper()
	select {
	case <-s.arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("no JWKS request arrived within 5s")
	}
}

// testKey is one RSA key plus the JWK that publishes it.
type testKey struct {
	kid string
	key *rsa.PrivateKey
	jwk JWK
}

func newTestKey(t *testing.T, kid string) testKey {
	t.Helper()
	// 2048 is the smallest modulus the reference generates
	// (jwks.service.ts:147); the tests sign and verify real signatures, so the
	// key has to be real too.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key %s: %v", kid, err)
	}
	jwk, err := NewRSAJWK(&key.PublicKey, kid)
	if err != nil {
		t.Fatalf("jwk %s: %v", kid, err)
	}
	return testKey{kid: kid, key: key, jwk: jwk}
}

func (k testKey) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	token, err := BuildRS256JWT(k.key, k.kid, claims)
	if err != nil {
		t.Fatalf("sign with %s: %v", k.kid, err)
	}
	return token
}

func rsClaims(overrides map[string]any) map[string]any {
	claims := map[string]any{
		"sub":             "usr_1",
		"email":           "rs@example.com",
		"role":            "member",
		"loginProvider":   "local",
		"isEmailVerified": true,
		"isTotpEnabled":   false,
		"tid":             "t1",
		"iss":             "https://issuer.example.test",
		"iat":             time.Now().Add(-time.Minute).Unix(),
		"exp":             time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range overrides {
		claims[k] = v
	}
	return claims
}

// newTestJWKSClient wires a client to s with a controllable clock.
func newTestJWKSClient(s *jwksTestServer, clock *testClock, ttl time.Duration) *JWKSClient {
	client := NewJWKSClient(ResourceServerConfig{JWKSURL: s.srv.URL, CacheTTL: ttl})
	client.setClock(clock.now)
	return client
}

// ---------------------------------------------------------------------------
// JWKSClient — caching, stale-while-revalidate, dedupe, invalidation
// ---------------------------------------------------------------------------

func TestJWKSClientServesFromCacheWithinTTL(t *testing.T) {
	k1 := newTestKey(t, "k1")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	clock := newTestClock()
	client := newTestJWKSClient(s, clock, time.Hour)

	for i := range 3 {
		if _, err := client.GetKey(context.Background(), "k1"); err != nil {
			t.Fatalf("GetKey %d: %v", i, err)
		}
		clock.advance(time.Minute)
	}
	if got := s.count(); got != 1 {
		t.Errorf("fetches = %d, want 1 — a document inside its TTL must come from memory", got)
	}
}

// TestJWKSClientStaleWhileRevalidate is the reference behaviour at
// jwks.service.ts:62-75: past the TTL the cached document is returned
// immediately and the refresh happens behind it, so no request ever waits for
// the issuer once the cache is warm.
func TestJWKSClientStaleWhileRevalidate(t *testing.T) {
	k1, k2 := newTestKey(t, "k1"), newTestKey(t, "k2")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	clock := newTestClock()
	client := newTestJWKSClient(s, clock, time.Hour)

	if _, err := client.GetKey(context.Background(), "k1"); err != nil {
		t.Fatalf("warm the cache: %v", err)
	}
	clock.advance(2 * time.Hour)

	gate := s.hold(t)
	// The stale read must return while the refresh is still blocked in the
	// handler; if it waited, this line would deadlock until the timeout.
	if _, err := client.GetKey(context.Background(), "k1"); err != nil {
		t.Fatalf("stale read: %v", err)
	}
	s.waitArrived(t)
	if got := s.count(); got != 2 {
		t.Fatalf("fetches = %d, want 2 — the stale read must have triggered a background refresh", got)
	}

	// Rotate while the refresh is held open, then let it land.
	s.serve(JWKS{Keys: []JWK{k2.jwk}})
	s.release(gate)

	if _, err := client.GetKey(context.Background(), "k2"); err != nil {
		t.Fatalf("after the background refresh landed: %v", err)
	}
	if got := s.count(); got != 2 {
		t.Errorf("fetches = %d, want 2 — the refreshed document is fresh again", got)
	}
}

// TestJWKSClientFailedRefreshKeepsStale is jwks.service.ts:70-73: the catch
// returns the cached document, so an issuer that is briefly unreachable cannot
// take the resource server down with it.
func TestJWKSClientFailedRefreshKeepsStale(t *testing.T) {
	k1 := newTestKey(t, "k1")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	clock := newTestClock()
	client := newTestJWKSClient(s, clock, time.Hour)

	if _, err := client.GetKey(context.Background(), "k1"); err != nil {
		t.Fatalf("warm the cache: %v", err)
	}
	clock.advance(2 * time.Hour)
	s.fail(http.StatusInternalServerError)

	// The refresh is held open while the stale read runs, so the order is
	// pinned rather than raced: the caller is served the old document, and only
	// then does the refresh get to fail.
	gate := s.hold(t)
	if _, err := client.GetKey(context.Background(), "k1"); err != nil {
		t.Fatalf("the stale read must be served from cache, got %v", err)
	}
	s.waitArrived(t)
	s.release(gate)

	// Whether the failed refresh has landed yet or is still in flight, the
	// answer is the same: the cached key. Nothing clears the cache on failure.
	if _, err := client.GetKey(context.Background(), "k1"); err != nil {
		t.Fatalf("a failed refresh must leave the stale document serving, got %v", err)
	}
	if got := s.count(); got < 2 {
		t.Errorf("fetches = %d, want at least 2 — the refresh must have been attempted", got)
	}
}

// TestJWKSClientDedupesInFlightFetches is jwks.service.ts:56-58: a burst on a
// cold cache is one HTTP call, not one per request.
func TestJWKSClientDedupesInFlightFetches(t *testing.T) {
	k1 := newTestKey(t, "k1")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	clock := newTestClock()
	client := newTestJWKSClient(s, clock, time.Hour)

	gate := s.hold(t)
	const callers = 8
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = client.GetKey(context.Background(), "k1")
		}()
	}
	s.waitArrived(t)
	s.release(gate)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d: %v", i, err)
		}
	}
	if got := s.count(); got != 1 {
		t.Errorf("fetches = %d, want 1 — %d concurrent callers must share one fetch", got, callers)
	}
}

func TestJWKSClientColdFetchFailuresSurface(t *testing.T) {
	s := newJWKSTestServer(t, JWKS{})
	clock := newTestClock()

	t.Run("non-200", func(t *testing.T) {
		s.fail(http.StatusServiceUnavailable)
		client := newTestJWKSClient(s, clock, time.Hour)
		if _, err := client.GetKey(context.Background(), "k1"); err == nil {
			t.Fatal("expected an error with no cache to fall back on")
		}
	})

	t.Run("not JSON", func(t *testing.T) {
		s.serveBody("<html>nope</html>")
		client := newTestJWKSClient(s, clock, time.Hour)
		_, err := client.GetKey(context.Background(), "k1")
		if err == nil || !strings.Contains(err.Error(), "parse JSON") {
			t.Fatalf("err = %v, want a JSON parse failure", err)
		}
	})

	t.Run("no keys array", func(t *testing.T) {
		s.serveBody(`{"notkeys":[]}`)
		client := newTestJWKSClient(s, clock, time.Hour)
		_, err := client.GetKey(context.Background(), "k1")
		if err == nil || !strings.Contains(err.Error(), `missing "keys" array`) {
			t.Fatalf("err = %v, want the missing-keys failure", err)
		}
	})
}

func TestJWKSClientInvalidateForcesARefetch(t *testing.T) {
	k1 := newTestKey(t, "k1")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	clock := newTestClock()
	client := newTestJWKSClient(s, clock, time.Hour)

	if _, err := client.GetKey(context.Background(), "k1"); err != nil {
		t.Fatalf("warm the cache: %v", err)
	}
	client.Invalidate()
	if _, err := client.GetKey(context.Background(), "k1"); err != nil {
		t.Fatalf("after Invalidate: %v", err)
	}
	if got := s.count(); got != 2 {
		t.Errorf("fetches = %d, want 2 — Invalidate must drop the cache", got)
	}
}

func TestJWKSClientUnknownKidIsDistinguishable(t *testing.T) {
	k1 := newTestKey(t, "k1")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	client := newTestJWKSClient(s, newTestClock(), time.Hour)

	_, err := client.GetKey(context.Background(), "nope")
	if !errors.Is(err, errJWKSKeyNotFound) {
		t.Fatalf("err = %v, want errJWKSKeyNotFound — the verifier retries on this and on nothing else", err)
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want it to wrap ErrInvalidToken so HTTPErrorFor maps it", err)
	}
}

// ---------------------------------------------------------------------------
// VerifyRS256
// ---------------------------------------------------------------------------

// TestVerifyRS256AcceptsAnIssuedToken pins the success path end to end: a
// token signed with the published key, with the issuer checked by string
// equality (token.service.ts:136-140).
func TestVerifyRS256AcceptsAnIssuedToken(t *testing.T) {
	k1 := newTestKey(t, "k1")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	client := newTestJWKSClient(s, newTestClock(), time.Hour)

	claims, err := VerifyRS256(context.Background(), k1.sign(t, rsClaims(nil)), client, "https://issuer.example.test")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims["sub"] != "usr_1" || claims["email"] != "rs@example.com" {
		t.Errorf("claims = %v, want the payload unchanged", claims)
	}
	if claims["iss"] != "https://issuer.example.test" {
		t.Errorf("iss = %v", claims["iss"])
	}

	// An empty expectedIssuer means the claim is not checked at all, which is
	// what an absent config.resourceServer.issuer does (token.service.ts:137).
	if _, err := VerifyRS256(context.Background(), k1.sign(t, rsClaims(map[string]any{"iss": "https://anyone.example"})), client, ""); err != nil {
		t.Errorf("unchecked issuer: %v", err)
	}
}

func TestVerifyRS256RefusalMatrix(t *testing.T) {
	k1 := newTestKey(t, "k1")
	stranger := newTestKey(t, "k1") // same kid, different key: a forged token
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	client := newTestJWKSClient(s, newTestClock(), time.Hour)

	// An HS256 token that names a published kid: the alg allow-list is the only
	// thing between this and a token verified with a key the attacker chose.
	hs256 := func() string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"k1"}`))
		payload, err := json.Marshal(rsClaims(nil))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		body := base64.RawURLEncoding.EncodeToString(payload)
		return header + "." + body + "." + sign(header+"."+body, "secret")
	}()
	none := func() string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"k1"}`))
		payload, err := json.Marshal(rsClaims(nil))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
	}()
	noKid := func() string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
		payload, err := json.Marshal(rsClaims(nil))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		body := base64.RawURLEncoding.EncodeToString(payload)
		return header + "." + body + ".ignored"
	}()

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"not a JWT", "nope", errRSInvalidTokenFormat},
		{"two segments", "a.b", errRSInvalidTokenFormat},
		{"header is not base64", "!!!.b.c", errRSInvalidTokenFormat},
		{"no kid header", noKid, errRSMissingKid},
		{"alg none", none, errRSInvalidOrExpired},
		{"alg HS256 under a published kid", hs256, errRSInvalidOrExpired},
		{"signed by another key", stranger.sign(t, rsClaims(nil)), errRSInvalidOrExpired},
		{"expired", k1.sign(t, rsClaims(map[string]any{"exp": time.Now().Add(-time.Second).Unix()})), errRSInvalidOrExpired},
		{"not yet valid", k1.sign(t, rsClaims(map[string]any{"nbf": time.Now().Add(time.Hour).Unix()})), errRSInvalidOrExpired},
		{"wrong issuer", k1.sign(t, rsClaims(map[string]any{"iss": "https://elsewhere.example"})), errRSIssuerMismatch},
		{"no issuer claim at all", k1.sign(t, rsClaims(map[string]any{"iss": nil})), errRSIssuerMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyRS256(context.Background(), tc.token, client, "https://issuer.example.test")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Errorf("err = %v, want it to wrap ErrInvalidToken", err)
			}
			if got := HTTPErrorFor(err); got != HTTPErrInvalidToken {
				t.Errorf("HTTPErrorFor = %+v, want the INVALID_TOKEN envelope", got)
			}
		})
	}

	t.Run("no client", func(t *testing.T) {
		if _, err := VerifyRS256(context.Background(), k1.sign(t, rsClaims(nil)), nil, ""); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestVerifyRS256RetriesOnceAcrossARotation is token.service.ts:116-125: a kid
// the cache does not carry invalidates the cache and is looked up once more, so
// a key rotated inside the TTL is picked up on the first request that needs it
// — once, and no more, whatever the retry finds.
//
// The clock is advanced past MinRefreshInterval before each rotation because a
// document fetched moments ago is not re-dropped; that rate limit has its own
// test below.
func TestVerifyRS256RetriesOnceAcrossARotation(t *testing.T) {
	k1, k2 := newTestKey(t, "k1"), newTestKey(t, "k2")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	clock := newTestClock()
	client := newTestJWKSClient(s, clock, time.Hour)

	if _, err := VerifyRS256(context.Background(), k1.sign(t, rsClaims(nil)), client, ""); err != nil {
		t.Fatalf("warm the cache with k1: %v", err)
	}
	if got := s.count(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}

	// The issuer rotates. The cache is still fresh (TTL is an hour), so only
	// the retry can find the new key.
	clock.advance(DefaultJWKSMinRefreshInterval + time.Second)
	s.serve(JWKS{Keys: []JWK{k1.jwk, k2.jwk}})
	if _, err := VerifyRS256(context.Background(), k2.sign(t, rsClaims(nil)), client, ""); err != nil {
		t.Fatalf("rotated key must verify after the invalidate-and-retry: %v", err)
	}
	if got := s.count(); got != 2 {
		t.Errorf("fetches = %d, want 2 — the miss costs exactly one refetch", got)
	}

	// A kid nobody published is refused, and costs one refetch and no more:
	// the retry misses too, and there is no second retry.
	clock.advance(DefaultJWKSMinRefreshInterval + time.Second)
	ghost := newTestKey(t, "k9")
	_, err := VerifyRS256(context.Background(), ghost.sign(t, rsClaims(nil)), client, "")
	if !errors.Is(err, errRSUnknownKey) {
		t.Fatalf("err = %v, want the unknown-signing-key refusal", err)
	}
	if got := s.count(); got != 3 {
		t.Errorf("fetches = %d, want 3 — a second miss must not retry again", got)
	}
}

// TestVerifyRS256UnknownKidCannotHammerTheIssuer is the rate limit: a flood of
// tokens naming keys nobody published must not turn into a flood of outbound
// requests. It is the jwks-unknown-kid-refetch-is-rate-limited deviation, and
// the reason the reference's unconditional invalidate-and-retry was not
// transcribed literally.
func TestVerifyRS256UnknownKidCannotHammerTheIssuer(t *testing.T) {
	k1 := newTestKey(t, "k1")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	clock := newTestClock()
	client := newTestJWKSClient(s, clock, time.Hour)

	// Twenty different unknown kids, back to back, on a cold cache. The first
	// costs the cold fetch; nothing after it costs anything, because the
	// document is younger than MinRefreshInterval and is not re-dropped. One
	// RSA key signs them all — it is the kid the cache is asked for, and
	// generating twenty real keys would cost seconds for nothing.
	ghost := newTestKey(t, "ghost")
	for i := 0; i < 20; i++ {
		token, err := BuildRS256JWT(ghost.key, fmt.Sprintf("ghost-%d", i), rsClaims(nil))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := VerifyRS256(context.Background(), token, client, ""); !errors.Is(err, errRSUnknownKey) {
			t.Fatalf("request %d: err = %v, want the unknown-signing-key refusal", i, err)
		}
	}
	if got := s.count(); got != 1 {
		t.Fatalf("fetches = %d, want 1 — an unknown kid must not cost one fetch per request", got)
	}

	// The document keeps serving the keys it does have while the limit holds:
	// the flood must not have cost legitimate traffic its cache either.
	if _, err := VerifyRS256(context.Background(), k1.sign(t, rsClaims(nil)), client, ""); err != nil {
		t.Fatalf("a published key must still verify from cache: %v", err)
	}
	if got := s.count(); got != 1 {
		t.Errorf("fetches = %d, want 1 — the cache must survive the flood", got)
	}

	// Past the interval the retry is allowed again, which is what keeps a real
	// rotation working: one more unknown kid, one more fetch, and no more.
	clock.advance(DefaultJWKSMinRefreshInterval + time.Second)
	if _, err := VerifyRS256(context.Background(), ghost.sign(t, rsClaims(nil)), client, ""); !errors.Is(err, errRSUnknownKey) {
		t.Fatalf("err = %v, want the unknown-signing-key refusal", err)
	}
	if got := s.count(); got != 2 {
		t.Errorf("fetches = %d, want 2 — the interval must let a rotation through", got)
	}

	// A negative MinRefreshInterval turns the limit off, which is the
	// "matching the reference exactly" escape hatch in the deviation entry:
	// the cold fetch plus one refetch per unknown kid, for ever.
	unlimited := NewJWKSClient(ResourceServerConfig{JWKSURL: s.srv.URL, MinRefreshInterval: -1})
	before := s.count()
	for i := 0; i < 3; i++ {
		token, err := BuildRS256JWT(ghost.key, fmt.Sprintf("unlimited-%d", i), rsClaims(nil))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := VerifyRS256(context.Background(), token, unlimited, ""); !errors.Is(err, errRSUnknownKey) {
			t.Fatalf("err = %v, want the unknown-signing-key refusal", err)
		}
	}
	// One cold fetch plus one refetch per request: the reference's cost.
	if got := s.count() - before; got != 4 {
		t.Errorf("fetches = %d, want 4 with the limit off", got)
	}
}

// TestVerifyRS256RefusesABadAlgWithoutCallingTheIssuer pins the hoisted
// allow-list: a junk token must not be able to make this server talk to the
// issuer at all, which it could while the alg check sat after the key lookup.
func TestVerifyRS256RefusesABadAlgWithoutCallingTheIssuer(t *testing.T) {
	k1 := newTestKey(t, "k1")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	client := newTestJWKSClient(s, newTestClock(), time.Hour)

	payload, err := json.Marshal(rsClaims(nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	for name, header := range map[string]string{
		"alg none":  `{"alg":"none","typ":"JWT","kid":"who-knows"}`,
		"alg HS256": `{"alg":"HS256","typ":"JWT","kid":"who-knows"}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := base64.RawURLEncoding.EncodeToString([]byte(header))
			token := h + "." + body + "." + sign(h+"."+body, "secret")
			if _, err := VerifyRS256(context.Background(), token, client, ""); !errors.Is(err, errRSInvalidOrExpired) {
				t.Fatalf("err = %v, want the refusal", err)
			}
		})
	}
	if got := s.count(); got != 0 {
		t.Errorf("fetches = %d, want 0 — a non-RS256 header must be refused before the network", got)
	}
}

// TestVerifyRS256JWKSOutageIsNotAnInvalidToken pins the split the doc comment
// promises: the token refusals wrap ErrInvalidToken and map to 401, while a
// failure to read the JWKS surfaces unwrapped and maps to 500. A host calling
// VerifyRS256 directly needs to be able to tell "your credential is bad" from
// "my issuer is down".
func TestVerifyRS256JWKSOutageIsNotAnInvalidToken(t *testing.T) {
	k1 := newTestKey(t, "k1")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	s.fail(http.StatusBadGateway)
	client := newTestJWKSClient(s, newTestClock(), time.Hour)

	_, err := VerifyRS256(context.Background(), k1.sign(t, rsClaims(nil)), client, "")
	if err == nil {
		t.Fatal("an unreachable JWKS must fail the verification")
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want a transport failure that does not wrap ErrInvalidToken", err)
	}
	if got := HTTPErrorFor(err); got != HTTPErrInternal {
		t.Errorf("HTTPErrorFor = %+v, want the 500 envelope: an issuer outage is this server's fault", got)
	}
}

// TestNewJWKSClientRefusesAnUnusableURL is the constructor check: a resource
// server pointed at nothing refuses at startup rather than 401ing every bearer
// request for the life of the process, which is how the reference refuses the
// same misconfiguration (jwks-auth.middleware.ts:38-40).
func TestNewJWKSClientRefusesAnUnusableURL(t *testing.T) {
	unusable := []struct{ name, raw string }{
		{"empty", ""},
		{"blank", "   "},
		{"no scheme", "auth.example.com/.well-known/jwks.json"},
		{"relative", "/.well-known/jwks.json"},
		{"wrong scheme", "file:///etc/jwks.json"},
		{"no host", "https://"},
		{"scheme only", "https:"},
		{"control character", "https://auth.example.test/\x7f"},
	}
	for _, tc := range unusable {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("NewJWKSClient(%q) did not panic; a misconfigured issuer endpoint must fail at startup", tc.raw)
				}
			}()
			_ = NewJWKSClient(ResourceServerConfig{JWKSURL: tc.raw})
		})
	}

	// Both schemes are usable: a resource server talking to an issuer over
	// plain http on a private network is a deployment choice, not an error.
	for _, raw := range []string{"http://auth.example.test/jwks", "https://auth.example.test/jwks"} {
		if c := NewJWKSClient(ResourceServerConfig{JWKSURL: raw}); c.URL() != raw {
			t.Errorf("URL() = %q, want %q", c.URL(), raw)
		}
	}
}

func TestJWKRSAPublicKeyRefusesNonSigningKeys(t *testing.T) {
	k1 := newTestKey(t, "k1")
	cases := map[string]JWK{
		"wrong kty":          {Kty: "EC", Alg: "RS256", Kid: "k1", N: k1.jwk.N, E: k1.jwk.E},
		"wrong alg":          {Kty: "RSA", Alg: "PS256", Kid: "k1", N: k1.jwk.N, E: k1.jwk.E},
		"unreadable modulus": {Kty: "RSA", Alg: "RS256", Kid: "k1", N: "!!!", E: k1.jwk.E},
		"empty modulus":      {Kty: "RSA", Alg: "RS256", Kid: "k1", N: "", E: k1.jwk.E},
		"unreadable exp":     {Kty: "RSA", Alg: "RS256", Kid: "k1", N: k1.jwk.N, E: "!!!"},
	}
	for name, jwk := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := jwk.RSAPublicKey(); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("err = %v, want a refusal", err)
			}
		})
	}

	// An alg-less JWK is accepted: alg is optional in RFC 7517 and the
	// reference reads only kty, n and e (jwks.service.ts:199-202).
	if _, err := (JWK{Kty: "RSA", Kid: "k1", N: k1.jwk.N, E: k1.jwk.E}).RSAPublicKey(); err != nil {
		t.Errorf("an alg-less RSA JWK must be usable: %v", err)
	}
	// And it round-trips: what NewRSAJWK publishes is what this reads back.
	pub, err := k1.jwk.RSAPublicKey()
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if pub.N.Cmp(k1.key.PublicKey.N) != 0 || pub.E != k1.key.PublicKey.E {
		t.Error("the JWK did not round-trip back to the original public key")
	}
}

// ---------------------------------------------------------------------------
// principal and route gating
// ---------------------------------------------------------------------------

// TestUserFromRS256ClaimsReadsTheTokenAndNothingElse pins what a resource
// server hands its handlers: the six reference base claims plus the tenant,
// every claim in CustomClaims, and no store field invented.
func TestUserFromRS256ClaimsReadsTheTokenAndNothingElse(t *testing.T) {
	user := UserFromRS256Claims(map[string]any{
		"sub":             "usr_7",
		"email":           "principal@example.com",
		"role":            "admin",
		"loginProvider":   "google",
		"isEmailVerified": true,
		"isTotpEnabled":   true,
		"tid":             "tenant-9",
		"scope":           "reports:read",
	})

	if user.ID != "usr_7" || user.Email != "principal@example.com" || user.Role != "admin" {
		t.Errorf("user = %+v", user)
	}
	if user.LoginProvider != "google" || user.TenantID != "tenant-9" {
		t.Errorf("user = %+v", user)
	}
	if !user.IsEmailVerified || !user.IsTOTPEnabled {
		t.Errorf("flags = %v/%v, want both true", user.IsEmailVerified, user.IsTOTPEnabled)
	}
	if user.CustomClaims["scope"] != "reports:read" {
		t.Errorf("custom claims = %v, want the whole payload carried through", user.CustomClaims)
	}
	if user.PasswordHash != "" || user.Roles != nil || user.Permissions != nil || user.Tenants != nil {
		t.Errorf("store-only fields must stay zero: %+v", user)
	}

	// Wrong-typed claims are absent, not a panic: the token comes from another
	// service and this one does not get to assume its shape.
	odd := UserFromRS256Claims(map[string]any{"sub": 7, "isEmailVerified": "yes"})
	if odd.ID != "" || odd.IsEmailVerified {
		t.Errorf("mistyped claims must read as absent, got %+v", odd)
	}
}

// TestVerifyLocalAccessTokenReadsNoStore is the cookie half of the middleware:
// the reference verifies it with tokenService.verifyAccessToken, a bare
// jwt.verify against the HS256 secret (token.service.ts:143-150,
// jwks-auth.middleware.ts:70-73), so this port must not reach for a user record
// either — a resource server has no user table to reach into.
func TestVerifyLocalAccessTokenReadsNoStore(t *testing.T) {
	users := NewMemoryUserStore()
	a, err := New(WithSecret("01234567890123456789012345678901"), WithUserStore(users), WithIssueSessionOnRegister(true))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	ctx := context.Background()
	user, tokens, err := a.Register(ctx, RegisterInput{Email: "cookie@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// The subject leaves the store — which is the state a resource server is
	// permanently in, since it has no store to have put him in.
	if err := users.DeleteUser(ctx, user.ID, user.TenantID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if _, err := a.Authenticate(ctx, tokens.AccessToken); err == nil {
		t.Fatal("Service.Authenticate is supposed to fail without the user record; " +
			"if it no longer does, this test proves nothing")
	}

	claims, err := a.service.verifyLocalAccessToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("the local verification must not depend on the user store: %v", err)
	}
	principal := UserFromRS256Claims(claims)
	if principal.ID != user.ID || principal.Email != "cookie@example.com" || principal.TenantID != "t1" {
		t.Errorf("principal = %+v, want it built from the token claims", principal)
	}

	// It is still a verification, not a decode: a foreign secret, a refresh
	// token and a tampered token are all refused.
	other, err := New(WithSecret("abcdefghijklmnopqrstuvwxyz012345"))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	if _, err := other.service.verifyLocalAccessToken(tokens.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a token signed with another secret must be refused, got %v", err)
	}
	if _, err := a.service.verifyLocalAccessToken(tokens.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Error("a refresh token must not pass as an access token: typ is what tells them apart here")
	}
	if _, err := a.service.verifyLocalAccessToken("not-a-jwt"); !errors.Is(err, ErrInvalidToken) {
		t.Error("garbage must be refused")
	}
}

// TestResourceServerPrincipalSelectsOnTheBearerPrefix pins the two edge cases
// the reference decides on the header prefix rather than on the extracted
// token (jwks-auth.middleware.ts:49-59): an empty bearer is a bearer request
// with no token, and the scheme match is case-sensitive.
func TestResourceServerPrincipalSelectsOnTheBearerPrefix(t *testing.T) {
	k1 := newTestKey(t, "k1")
	s := newJWKSTestServer(t, JWKS{Keys: []JWK{k1.jwk}})
	client := newTestJWKSClient(s, newTestClock(), time.Hour)

	a, err := New(WithSecret("01234567890123456789012345678901"), WithIssueSessionOnRegister(true))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	_, tokens, err := a.Register(context.Background(), RegisterInput{
		Email: "prefix@example.com", Password: "password1", TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	cookie := &http.Cookie{Name: AccessTokenCookieName, Value: tokens.AccessToken}

	t.Run("an empty bearer does not fall through to the cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.Header.Set("Authorization", "Bearer ")
		req.AddCookie(cookie)
		_, httpErr, ok := resourceServerPrincipal(req, a, client, "")
		if ok {
			t.Fatal("the cookie answered a bearer request; the reference reads token === '' and refuses")
		}
		if httpErr != HTTPErrNoAccessToken {
			t.Errorf("err = %+v, want the code-less 403", httpErr)
		}
	})

	t.Run("the scheme is case-sensitive, so a lowercase one reads the cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.Header.Set("Authorization", "bearer "+k1.sign(t, rsClaims(nil)))
		req.AddCookie(cookie)
		user, _, ok := resourceServerPrincipal(req, a, client, "")
		if !ok {
			t.Fatal("the cookie must answer: startsWith('Bearer ') does not match a lowercase scheme")
		}
		if user.Email != "prefix@example.com" {
			t.Errorf("email = %q, want the cookie principal, not the bearer one", user.Email)
		}
	})

	t.Run("no credential at all is the code-less 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		if _, httpErr, ok := resourceServerPrincipal(req, a, client, ""); ok || httpErr != HTTPErrNoAccessToken {
			t.Errorf("ok = %v, err = %+v", ok, httpErr)
		}
	})

	t.Run("a nil Auth fails the cookie closed rather than panicking", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.AddCookie(cookie)
		if _, httpErr, ok := resourceServerPrincipal(req, nil, client, ""); ok || httpErr != HTTPErrInvalidTokenRS {
			t.Errorf("ok = %v, err = %+v, want the 401", ok, httpErr)
		}
	})
}

// TestResourceServerGatedRoutesAreDocumentedRoutes keeps the gated list and the
// spec in step: every route it names must be one openAPIPaths documents, or
// the deletion in openAPIPathsFor would be silently doing nothing.
func TestResourceServerGatedRoutesAreDocumentedRoutes(t *testing.T) {
	prefix := DefaultAPIPrefix
	paths := openAPIPaths(prefix)
	gated := ResourceServerGatedRoutes()
	if len(gated) != 19 {
		t.Errorf("gated routes = %d, want 19", len(gated))
	}
	for route := range gated {
		if _, ok := paths[prefix+route]; !ok {
			t.Errorf("%q is gated but not in the OpenAPI paths", route)
		}
	}

	spec := GenerateOpenAPISpec(OpenAPIInfo{ResourceServer: true})
	specPaths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatalf("paths = %T", spec["paths"])
	}
	for route := range gated {
		if _, ok := specPaths[prefix+route]; ok {
			t.Errorf("%q is still documented in resource-server mode", route)
		}
	}
	if len(specPaths) != len(paths)-len(gated) {
		t.Errorf("resource-server spec has %d paths, want %d", len(specPaths), len(paths)-len(gated))
	}
	// The flag is the only difference: without it the spec is whole again.
	if got := len(GenerateOpenAPISpec(OpenAPIInfo{})["paths"].(map[string]any)); got != len(paths) {
		t.Errorf("default spec has %d paths, want %d", got, len(paths))
	}
	// Callers get their own copy.
	gated["/injected"] = http.MethodGet
	if _, leaked := ResourceServerGatedRoutes()["/injected"]; leaked {
		t.Error("ResourceServerGatedRoutes shares its map with the caller")
	}
}

// TestOpenAPIGatingRemovesOperationsNotPaths pins that the spec edit is
// per-operation. Every gated path carries one operation today, so the whole-path
// deletion this replaced gave the same answer; the test stands in a path with
// two methods, of which only one is gated, because that is the case where the
// two differ and where deleting the path would undocument a route the adapters
// still serve.
func TestOpenAPIGatingRemovesOperationsNotPaths(t *testing.T) {
	paths := map[string]any{
		"/auth/two-methods": map[string]any{
			"post": map[string]any{"operationId": "gated"},
			"get":  map[string]any{"operationId": "kept"},
		},
		"/auth/one-method": map[string]any{
			"post": map[string]any{"operationId": "gated"},
		},
	}

	removeOpenAPIOperation(paths, "/auth/two-methods", http.MethodPost)
	item, ok := paths["/auth/two-methods"].(map[string]any)
	if !ok {
		t.Fatalf("the path vanished with its gated operation; the surviving GET is still mounted")
	}
	if _, still := item["post"]; still {
		t.Error("the gated operation is still documented")
	}
	if _, kept := item["get"]; !kept {
		t.Error("the operation that was not gated must survive")
	}

	// The last operation takes the path with it: an empty path item is not a
	// valid thing to publish.
	removeOpenAPIOperation(paths, "/auth/one-method", http.MethodPost)
	if _, ok := paths["/auth/one-method"]; ok {
		t.Error("a path with no operations left must be dropped entirely")
	}

	// A route that is not there, and a method that is not, are both no-ops
	// rather than panics.
	removeOpenAPIOperation(paths, "/auth/absent", http.MethodPost)
	removeOpenAPIOperation(paths, "/auth/two-methods", http.MethodDelete)
	if len(paths["/auth/two-methods"].(map[string]any)) != 1 {
		t.Error("removing an operation that is not there must change nothing")
	}
}

func TestHTTPErrInvalidTokenRSIsTheReferenceBody(t *testing.T) {
	if HTTPErrInvalidTokenRS.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (jwks-auth.middleware.ts:77)", HTTPErrInvalidTokenRS.Status)
	}
	if HTTPErrInvalidTokenRS.Message != "Invalid or expired access token" {
		t.Errorf("message = %q", HTTPErrInvalidTokenRS.Message)
	}
	if HTTPErrInvalidTokenRS.Code != CodeInvalidToken {
		t.Errorf("code = %q, want %q", HTTPErrInvalidTokenRS.Code, CodeInvalidToken)
	}
	// It is deliberately not the session middleware envelope, which is 403 and
	// code-less. The two share a message and nothing else.
	if HTTPErrInvalidTokenRS == HTTPErrInvalidAccessToken {
		t.Error("the resource-server refusal must stay distinct from the session one")
	}
}
