package wiretest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Conformance cases for how far Config.BuildTokenClaims reaches on the wire.
//
// The hook runs when a token is minted and when GET /me renders the profile,
// and nowhere else: the adapters' Middleware authenticates through
// Auth.Authenticate, which never calls it. With a ClaimsWebhook behind the hook
// that is the difference between one request per login and one per protected
// route, so the suite counts calls rather than trusting the wiring. The cases
// below cover the routes the mount itself guards; RunProtectedRouteSkipsClaimsHook
// covers a host route behind each adapter's native middleware, which only the
// adapter's own test file can build.

// ClaimsCounter is a Config.BuildTokenClaims hook that counts its calls and
// answers a fixed claim set. The set includes the reserved typ so that the
// cookie-login case in testClaims can see the reservation hold through the
// adapter: the access and refresh cookies it sets carry their own typ, not
// the hook's, while the hook's plan does reach both.
type ClaimsCounter struct {
	mu    sync.Mutex
	calls int
}

// Build is the hook. Wire it with auth.WithTokenClaimsBuilder(counter.Build).
func (c *ClaimsCounter) Build(_ context.Context, user auth.User) (map[string]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return map[string]any{"plan": "pro", "subjectEmail": user.Email, "typ": "access"}, nil
}

// Calls reports how many times Build has run since the last Reset.
func (c *ClaimsCounter) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// Reset zeroes the count.
func (c *ClaimsCounter) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = 0
}

// ProtectedMounter builds a handler serving GET /protected behind a's auth
// middleware — the shape of a host route — answering 200 with a JSON body that
// carries the context user's email under "email" and its CustomClaims under
// "customClaims".
type ProtectedMounter func(t *testing.T, a *auth.Auth) http.Handler

// RunProtectedRouteSkipsClaimsHook pins that a host route behind the adapter's
// middleware never runs Config.BuildTokenClaims and sees no CustomClaims, while
// GET /me on the same mount runs it exactly once and renders the result. Each
// adapter's test file calls it with its own ProtectedMounter.
func RunProtectedRouteSkipsClaimsHook(t *testing.T, mount Mounter, protect ProtectedMounter) {
	t.Helper()
	counter := &ClaimsCounter{}
	env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithTokenClaimsBuilder(counter.Build))
	_, tokens := env.Seed("protected@example.com")
	counter.Reset()

	handler := protect(t, env.Auth)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, bearerRequest(http.MethodGet, "/protected", tokens.AccessToken))
	AssertStatus(t, rec, http.StatusOK)
	body := Body(t, rec)
	if body["email"] != "protected@example.com" {
		t.Fatalf("the route saw email %v, want the token's user (body %s)", body["email"], rec.Body.String())
	}
	if body["customClaims"] != nil {
		t.Errorf("the middleware handed the route customClaims %v; VerifyAccess leaves them nil", body["customClaims"])
	}
	if got := counter.Calls(); got != 0 {
		t.Fatalf("the middleware ran Config.BuildTokenClaims %d times on a host route, want 0", got)
	}

	me := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tokens.AccessToken))
	AssertStatus(t, me, http.StatusOK)
	if got := counter.Calls(); got != 1 {
		t.Fatalf("GET /me ran Config.BuildTokenClaims %d times, want exactly 1", got)
	}
	custom, _ := Body(t, me)["customClaims"].(map[string]any)
	if custom["plan"] != "pro" {
		t.Fatalf("GET /me customClaims = %v, want the hook's result (body %s)", custom, me.Body.String())
	}
}

// jwtPayload decodes the claims segment of a compact JWS as the wire carries
// it. It does not verify the signature: these cases read what a token says,
// and the mount's own routes already proved it verifies.
func jwtPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q is not a three-segment JWS", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("token payload is not base64url: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("token payload is not JSON: %v", err)
	}
	return payload
}

func testClaims(t *testing.T, mount Mounter) {
	t.Run("GET /me runs the hook once and renders its claims", func(t *testing.T) {
		counter := &ClaimsCounter{}
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithTokenClaimsBuilder(counter.Build))
		_, tokens := env.Seed("meclaims@example.com")
		if got := counter.Calls(); got != 2 {
			t.Fatalf("seeding ran the hook %d times, want 2 (the access and refresh mints)", got)
		}
		counter.Reset()

		rec := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)
		if got := counter.Calls(); got != 1 {
			t.Fatalf("GET /me (bearer) ran the hook %d times, want exactly 1", got)
		}
		custom, _ := Body(t, rec)["customClaims"].(map[string]any)
		if custom["plan"] != "pro" || custom["subjectEmail"] != "meclaims@example.com" {
			t.Fatalf("customClaims = %v, want the hook's result (body %s)", custom, rec.Body.String())
		}

		// Cookie mode: the login mints two tokens, the profile read costs one call.
		counter.Reset()
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("meclaims@example.com")))
		AssertStatus(t, login, http.StatusOK)
		if got := counter.Calls(); got != 2 {
			t.Fatalf("login ran the hook %d times, want 2", got)
		}
		// The reservation holds on the wire: the hook answers typ "access" on
		// every mint, yet each cookie carries the typ issueToken gave it, while
		// the hook's plan is in both — so the hook did run into these tokens.
		for cookie, typ := range map[string]string{hostAccess: "access", hostRefresh: "refresh"} {
			payload := jwtPayload(t, Cookie(t, login, cookie).Value)
			if payload["typ"] != typ {
				t.Errorf("%s typ = %#v, want %q despite the hook returning typ access", cookie, payload["typ"], typ)
			}
			if payload["plan"] != "pro" {
				t.Errorf("%s lacks the hook's plan claim: %v", cookie, payload)
			}
		}
		rec = env.Do(Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), login))
		AssertStatus(t, rec, http.StatusOK)
		if got := counter.Calls(); got != 3 {
			t.Fatalf("GET /me (cookie) ran the hook %d more times, want exactly 1", got-2)
		}
	})

	// The read side of the fail-closed rule: a claims webhook that is down
	// fails a mint but not a profile read. GET /me answers 200 with
	// customClaims omitted, the failure is logged, and nothing is cached — the
	// next read after the endpoint recovers carries the claims again.
	t.Run("a claims webhook that fails leaves GET /me without customClaims", func(t *testing.T) {
		var fail atomic.Bool
		endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			if fail.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"claims":{"plan":"pro"}}`))
		}))
		t.Cleanup(endpoint.Close)
		hook, err := auth.NewClaimsWebhook(endpoint.URL, "s3cret")
		if err != nil {
			t.Fatalf("NewClaimsWebhook: %v", err)
		}

		var (
			mu     sync.Mutex
			logged []string
		)
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(),
			auth.WithTokenClaimsBuilder(hook.Build),
			auth.WithLogger(func(format string, args ...any) {
				mu.Lock()
				defer mu.Unlock()
				logged = append(logged, fmt.Sprintf(format, args...))
			}))
		user, tokens := env.Seed("down@example.com")

		fail.Store(true)
		me := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tokens.AccessToken))
		AssertStatus(t, me, http.StatusOK)
		body := Body(t, me)
		if body["email"] != "down@example.com" {
			t.Fatalf("GET /me body = %s, want the profile", me.Body.String())
		}
		if custom, present := body["customClaims"]; present {
			t.Fatalf("GET /me rendered customClaims %v while the webhook was down; want the member omitted", custom)
		}
		mu.Lock()
		lines := append([]string(nil), logged...)
		mu.Unlock()
		var saw bool
		for _, line := range lines {
			if strings.Contains(line, "custom claim enrichment skipped") && strings.Contains(line, user.ID) {
				saw = true
			}
		}
		if !saw {
			t.Fatalf("the logger did not see the skip line for %s; logged %q", user.ID, lines)
		}

		fail.Store(false)
		me = env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tokens.AccessToken))
		AssertStatus(t, me, http.StatusOK)
		custom, _ := Body(t, me)["customClaims"].(map[string]any)
		if custom["plan"] != "pro" {
			t.Fatalf("GET /me once the webhook answers again: customClaims = %v, want the webhook's claims (body %s)", custom, me.Body.String())
		}
	})

	t.Run("a mounted protected route never runs the hook", func(t *testing.T) {
		counter := &ClaimsCounter{}
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithTokenClaimsBuilder(counter.Build))
		_, tokens := env.Seed("guarded@example.com")
		counter.Reset()

		// GET /sessions is behind the auth middleware and renders no profile.
		rec := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/sessions", tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)
		if got := counter.Calls(); got != 0 {
			t.Fatalf("GET /sessions ran the hook %d times, want 0", got)
		}
		// And it still refuses what it always refused: the middleware's checks
		// did not go with the hook.
		anonymous := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/sessions", nil))
		AssertError(t, anonymous, http.StatusForbidden, "No access token provided", "")
		garbage := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/sessions", "not-a-token"))
		AssertError(t, garbage, http.StatusForbidden, "Invalid or expired access token", "")
	})

	// A ClaimsWebhook that cannot answer in time is a failing hook, and a
	// failing hook fails the mint: /login answers the same 500 it does for any
	// broken Config.BuildTokenClaims, and sets nothing.
	t.Run("a claims webhook that times out fails login with 500", func(t *testing.T) {
		// The endpoint hangs while hang is set. A hanging handler must drain
		// the request body first: the server only watches for the client going
		// away once the body has been read, so a handler that blocks before
		// reading it never sees its context cancelled when the client gives
		// up, and the server's Close would then wait on it forever. release is
		// the second way out, closed before the server closes (cleanups run
		// last-registered first).
		var hang atomic.Bool
		release := make(chan struct{})
		endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			if hang.Load() {
				select {
				case <-r.Context().Done():
				case <-release:
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"claims":{"plan":"pro"}}`))
		}))
		t.Cleanup(endpoint.Close)
		t.Cleanup(func() { close(release) })
		hook, err := auth.NewClaimsWebhook(endpoint.URL, "s3cret")
		if err != nil {
			t.Fatalf("NewClaimsWebhook: %v", err)
		}
		hook.Timeout = 100 * time.Millisecond

		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithTokenClaimsBuilder(hook.Build))
		env.Seed("webhook@example.com")

		hang.Store(true)
		rec := env.Do(env.Request(http.MethodPost, "/login", credentials("webhook@example.com")))
		AssertError(t, rec, http.StatusInternalServerError, "Internal server error", "")
		// No session was minted, so no token cookie. The CSRF cookie is not a
		// token: the CSRF middleware seeds it on any request that arrives
		// without one, whatever the route answers, as the other failed-login
		// cases in this suite allow for.
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)

		hang.Store(false)
		rec = env.Do(env.Request(http.MethodPost, "/login", credentials("webhook@example.com")))
		AssertStatus(t, rec, http.StatusOK)
		me := env.Do(Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), rec))
		AssertStatus(t, me, http.StatusOK)
		custom, _ := Body(t, me)["customClaims"].(map[string]any)
		if custom["plan"] != "pro" {
			t.Fatalf("customClaims = %v, want the webhook's claims (body %s)", custom, me.Body.String())
		}
	})
}
