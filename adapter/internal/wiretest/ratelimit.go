package wiretest

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// The rate-limiter slot: auth.HTTPConfig.RateLimiter, this port of the
// reference's RouterOptions.rateLimiter (auth.router.ts:46).
//
// The reference ships no algorithm — the slot is the whole feature. It
// collapses the option to an empty middleware list when nothing is configured
// (rl, auth.router.ts:468) and spreads ...rl onto every route of the auth
// router, first on each one: ahead of the auth middleware (GET /me, :656) and
// therefore ahead of the double-submit check, which that middleware performs
// and which the one route mounted without it repeats by hand inside its handler
// (:1489-1495). The JWKS document, registered above the chain, carries no rl
// (:490).
//
// That leaves four things to pin, and they are the four cases below: every auth
// route goes through the slot, once; the JWKS document does not, even behind a
// limiter that refuses everything it sees; a limiter that answers is answered
// before anything downstream runs — no CSRF cookie minted, no token verified,
// no store read; and a slot left empty is no change at all. All four run on
// each of the four adapters, because the slot is wired in each of the four
// mounts and an adapter that forgot one route would still pass every other
// group in this suite.
//
// Not asserted: the family's private development line carries a second,
// separate slot on its admin router (AdminOptions.rateLimiter,
// admin.router.ts:211, collapsed the same way at :577) and spreads it onto
// exactly one route, POST /users/:id/promote (:1030) — its admin login route
// (:614) carries none. That path is relative to the admin router's own mount,
// which the host app chooses and which defaults to /admin
// (admin.router.ts:190, openapi.ts:674), not to the API prefix. Those line
// numbers are in that private tree, not in auth.ReferenceRevision, which
// carries no admin rateLimiter at all. No admin route exists in this port, so
// none has a mount to assert against.

// rateLimitRecorder is the limiter under test in the first case: a middleware
// that records the request it was handed and calls through, so "the slot ran"
// is observable without changing any response.
type rateLimitRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (c *rateLimitRecorder) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.seen = append(c.seen, r.Method+" "+r.URL.EscapedPath())
		c.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// take returns what the slot has seen since the last call and clears it.
func (c *rateLimitRecorder) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := c.seen
	c.seen = nil
	return seen
}

// rateLimitRefusedBody is what the refusing limiter writes. It is deliberately
// not one of this port's error envelopes: a body that only the limiter can have
// produced is what makes "the limiter answered, and nothing else did" a fact
// about the bytes on the wire rather than about a status code two layers could
// both have written.
const rateLimitRefusedBody = `{"error":"Too many requests","code":"RATE_LIMITED"}`

// refusingRateLimiter is a limiter at its limit: it answers 429 and never calls
// through, which is the shape every real limiter has on a refusal.
func refusingRateLimiter(_ http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(rateLimitRefusedBody))
	})
}

// countingUserStore counts the lookup Service.Authenticate makes, which is how
// the refusal case proves the auth middleware never ran rather than only that
// its answer is absent.
//
// It embeds the concrete memory store rather than the UserStore interface, so
// every optional capability the store implements is still promoted and the env
// behaves exactly as any other env in this suite.
type countingUserStore struct {
	*auth.MemoryUserStore
	mu      sync.Mutex
	lookups int
}

func (s *countingUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	s.mu.Lock()
	s.lookups++
	s.mu.Unlock()
	return s.MemoryUserStore.GetUserByID(ctx, id, tenantID)
}

func (s *countingUserStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookups
}

func testRateLimit(t *testing.T, mount Mounter) {
	t.Run("every auth route passes through the slot exactly once", func(t *testing.T) {
		testRateLimitCoversEveryRoute(t, mount)
	})
	t.Run("the JWKS document is mounted outside the slot", func(t *testing.T) {
		testRateLimitSkipsJWKS(t, mount)
	})
	t.Run("a refusal short-circuits the CSRF and auth middlewares", func(t *testing.T) {
		testRateLimitRefusalShortCircuits(t, mount)
	})
	t.Run("no limiter changes nothing", func(t *testing.T) {
		testRateLimitNilIsTransparent(t, mount)
	})
}

// testRateLimitCoversEveryRoute replays every documented operation through a
// limiter that only counts, and requires exactly one pass per request.
//
// Exactly one, not at least one: a route wrapped twice would charge a caller
// two slots for one request, which on a real limiter halves the configured
// budget. Zero is the regression that matters more — a route the adapter
// mounted outside the guard — and the same assertion catches it.
//
// The OAuth pair is in this list whether or not a provider is configured, which
// is one step wider than the reference: with no provider it swaps in bare 404
// stubs carrying no rl (auth.router.ts:1361-1362, :1407-1408) where this port
// keeps its guarded handler. HTTPConfig.RateLimiter records that difference.
func testRateLimitCoversEveryRoute(t *testing.T, mount Mounter) {
	recorder := &rateLimitRecorder{}
	cfg := auth.DefaultHTTPConfig()
	cfg.RateLimiter = recorder.middleware
	env := NewEnv(t, mount, cfg)

	for _, route := range slices.Sorted(maps.Keys(documentedRoutes)) {
		method := documentedRoutes[route]
		t.Run(method+" "+route, func(t *testing.T) {
			probe, req := openAPIProbe(method, env.Config.Prefix()+route)
			recorder.take()
			env.Do(req)
			want := method + " " + probe
			if seen := recorder.take(); len(seen) != 1 || seen[0] != want {
				t.Fatalf("the rate-limiter slot saw %v, want exactly [%q]", seen, want)
			}
		})
	}
}

// testRateLimitSkipsJWKS pins the one route the reference deliberately leaves
// outside the slot.
//
// documentedRoutes cannot carry it: the JWKS document is mounted only under
// auth.WithIDP, so the sweep above never touches it and an adapter that folded
// the JWKS mount into its guard would break parity with the reference
// (auth.router.ts:490) with every other case here still green.
//
// The limiter is the refusing one, which makes the assertion a single fact
// about the bytes: a served document, behind a limiter that answers everything
// it is handed, can only mean the limiter was never handed this request.
func testRateLimitSkipsJWKS(t *testing.T, mount Mounter) {
	cfg := auth.DefaultHTTPConfig()
	cfg.RateLimiter = refusingRateLimiter
	env := NewEnv(t, mount, cfg, auth.WithIDP(newTestIDP()))
	assertJWKSDocument(t, env.Do(jwksRequest(env, http.MethodGet, auth.DefaultJWKSPath, "")))
}

// testRateLimitRefusalShortCircuits pins the slot's position in the chain.
//
// The request is a cookie-authenticated GET: it carries a valid access-token
// cookie and no CSRF cookie, so with no limiter in the way both middlewares
// leave a mark — the CSRF middleware mints and distributes the cookie, and the
// route verifies the token and reads the user it names from the user store.
// That is the control. The route is GET /me because it is the one whose
// credential check reaches the user store: since #31 the shared auth
// middleware verifies the token without a store read, as the reference's
// does, so a route behind it would leave no store mark to count. With the
// limiter refusing, all three marks have to be gone: the 429 body verbatim, no
// Set-Cookie at all, and not one store lookup. A limiter mounted inside the
// CSRF middleware or behind the credential check fails on one of them.
func testRateLimitRefusalShortCircuits(t *testing.T, mount Mounter) {
	probe := func(t *testing.T, limiter func(http.Handler) http.Handler) (*httptest.ResponseRecorder, int) {
		t.Helper()
		store := &countingUserStore{MemoryUserStore: auth.NewMemoryUserStore()}
		cfg := auth.DefaultHTTPConfig()
		cfg.RateLimiter = limiter
		env := NewEnv(t, mount, cfg, auth.WithUserStore(store))
		_, tokens := env.Seed("ratelimit@example.com")

		before := store.count()
		req := env.Request(http.MethodGet, "/me", nil)
		req.AddCookie(&http.Cookie{Name: hostAccess, Value: tokens.AccessToken})
		return env.Do(req), store.count() - before
	}

	t.Run("without a limiter both middlewares run", func(t *testing.T) {
		rec, lookups := probe(t, nil)
		AssertStatus(t, rec, http.StatusOK)
		Cookie(t, rec, hostCSRF)
		if lookups == 0 {
			t.Fatalf("the credential check made no store lookup, so the control proves nothing")
		}
	})

	t.Run("with a limiter at its limit neither does", func(t *testing.T) {
		rec, lookups := probe(t, refusingRateLimiter)
		AssertStatus(t, rec, http.StatusTooManyRequests)
		if got := rec.Body.String(); got != rateLimitRefusedBody {
			t.Errorf("body = %q, want the limiter's own %q", got, rateLimitRefusedBody)
		}
		// The CSRF middleware distributes the cookie to every cookie client that
		// arrives without one, so a single Set-Cookie here would mean it ran.
		AssertNoCookies(t, rec)
		if lookups != 0 {
			t.Errorf("the credential check made %d store lookup(s) behind a refusal, want 0", lookups)
		}
	})
}

// testRateLimitNilIsTransparent holds the nil slot to the one promise it makes:
// nothing.
//
// The default comes first, because it is the other half of that promise: the
// slot ships empty, as the reference's option ships absent (auth.router.ts:468).
//
// Then every documented operation is replayed twice — against an adapter
// mounted with no limiter and against one mounted with a limiter that records
// the request and calls through — and the two must answer identically in
// status, body and the set of cookies set. The second limiter deliberately is
// not the identity function: identity and a nil slot compile to the same
// handler graph, so comparing them is a test with no failure mode. A recorder
// puts a real extra handler in the chain of every route, and the assertion that
// it saw the request keeps the comparison from passing vacuously — so an
// adapter that drives a route differently once a limiter is configured (gin's
// abort bookkeeping, echo's error path, a request the limiter's chain fails to
// propagate) is caught here rather than only under a limiter that refuses.
//
// Cookie values are not compared: the CSRF token is fresh per response by
// design.
func testRateLimitNilIsTransparent(t *testing.T, mount Mounter) {
	if auth.DefaultHTTPConfig().RateLimiter != nil {
		t.Fatalf("DefaultHTTPConfig().RateLimiter is not nil — no limiter is the default, as the reference's absent option is (auth.router.ts:468)")
	}

	bare := NewEnv(t, mount, auth.DefaultHTTPConfig())
	recorder := &rateLimitRecorder{}
	observedCfg := auth.DefaultHTTPConfig()
	observedCfg.RateLimiter = recorder.middleware
	observed := NewEnv(t, mount, observedCfg)

	for _, route := range slices.Sorted(maps.Keys(documentedRoutes)) {
		method := documentedRoutes[route]
		t.Run(method+" "+route, func(t *testing.T) {
			_, bareReq := openAPIProbe(method, bare.Config.Prefix()+route)
			probe, observedReq := openAPIProbe(method, observed.Config.Prefix()+route)
			recorder.take()
			without, with := bare.Do(bareReq), observed.Do(observedReq)

			if want := method + " " + probe; len(recorder.take()) == 0 {
				t.Fatalf("the pass-through limiter never saw %q, so comparing the two answers proves nothing", want)
			}
			if without.Code != with.Code {
				t.Fatalf("status = %d with a pass-through limiter, %d without", with.Code, without.Code)
			}
			if without.Body.String() != with.Body.String() {
				t.Errorf("body = %q with a pass-through limiter, %q without", with.Body.String(), without.Body.String())
			}
			if a, b := cookieNames(without), cookieNames(with); !slices.Equal(a, b) {
				t.Errorf("cookies = %v with a pass-through limiter, %v without", b, a)
			}
		})
	}
}
