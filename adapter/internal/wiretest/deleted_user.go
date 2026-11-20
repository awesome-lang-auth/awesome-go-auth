package wiretest

// The protected routes for a token whose user no longer exists (#31).
//
// The reference's createAuthMiddleware verifies the JWT, consults the session
// store only for the allcalls check, and sets req.user from the payload — it
// never reads the user store (awesome-node-auth v1.10.8
// auth.middleware.ts:44-61). A structurally valid, unexpired access token
// whose user has been deleted therefore reaches the handler, and each handler
// answers for the missing user itself: the four that look the user up answer
// 404 {"error":"User not found"} (auth.router.ts:1182-1185, :1471-1474,
// :1519-1521, :1591-1594), and /2fa/setup, which reads req.user.email and
// nothing else (:1369-1375), answers 200.
//
// Before #31 the port's gate resolved the user through the store and answered
// all of them 403 "Invalid or expired access token". Revoked-session handling
// is the gate's and is unchanged: SESSION_REVOKED under allcalls, pinned last.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// deletedUserEnv seeds a user, deletes the row straight from the store — the
// session and the access token are left as they were — and returns the env
// and the token pair the deleted user was issued.
func deletedUserEnv(t *testing.T, mount Mounter, opts ...auth.Option) (*Env, auth.AuthTokens) {
	t.Helper()
	store := auth.NewMemoryUserStore()
	env := NewEnv(t, mount, auth.DefaultHTTPConfig(), append([]auth.Option{auth.WithUserStore(store)}, opts...)...)
	user, tokens := env.Seed("deleted@example.com")
	if err := store.DeleteUser(context.Background(), user.ID, user.TenantID); err != nil {
		t.Fatalf("delete the user row: %v", err)
	}
	return env, tokens
}

func testDeletedUser(t *testing.T, mount Mounter) {
	t.Run("GET /me answers 404 User not found", func(t *testing.T) {
		env, tokens := deletedUserEnv(t, mount)
		rec := env.Do(bearer(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), tokens))
		AssertError(t, rec, http.StatusNotFound, "User not found", "")
	})

	// The lookup is the handler's first step, so the 404 outranks every
	// per-field refusal — an empty body included (auth.router.ts:1471-1479).
	for _, tc := range []struct {
		name string
		body any
	}{
		{"a complete body", map[string]string{"currentPassword": "password1", "newPassword": "newpassword1"}},
		{"no newPassword", map[string]string{"currentPassword": "password1"}},
		{"an empty body", nil},
	} {
		t.Run("POST /change-password answers 404 User not found, "+tc.name, func(t *testing.T) {
			env, tokens := deletedUserEnv(t, mount)
			rec := env.Do(bearer(env.Request(http.MethodPost, "/change-password", tc.body), tokens))
			AssertError(t, rec, http.StatusNotFound, "User not found", "")
		})
	}

	t.Run("POST /send-verification-email answers 404 User not found", func(t *testing.T) {
		env, tokens := deletedUserEnv(t, mount)
		rec := env.Do(bearer(env.Request(http.MethodPost, "/send-verification-email", nil), tokens))
		AssertError(t, rec, http.StatusNotFound, "User not found", "")
		if n := len(env.Delivered.EmailVerifications); n != 0 {
			t.Fatalf("%d verification mail(s) sent for a user that does not exist", n)
		}
	})

	t.Run("POST /change-email/request answers 404 User not found", func(t *testing.T) {
		env, tokens := deletedUserEnv(t, mount)
		rec := env.Do(bearer(env.Request(http.MethodPost, "/change-email/request", map[string]string{"newEmail": "free@example.com"}), tokens))
		AssertError(t, rec, http.StatusNotFound, "User not found", "")
		if n := len(env.Delivered.EmailChanges); n != 0 {
			t.Fatalf("%d email-change mail(s) sent for a user that does not exist", n)
		}
	})

	// The reference tests the new address before it looks the user up, so an
	// address in use is the 409 even for a deleted user (auth.router.ts:1586-1594).
	t.Run("POST /change-email/request: an address in use outranks the 404", func(t *testing.T) {
		env, tokens := deletedUserEnv(t, mount)
		env.Seed("taken@example.com")
		rec := env.Do(bearer(env.Request(http.MethodPost, "/change-email/request", map[string]string{"newEmail": "taken@example.com"}), tokens))
		AssertError(t, rec, http.StatusConflict, "Email address is already in use", "")
	})

	// No lookup at all in the reference: the enrolment URI is labelled with the
	// address the token carries.
	t.Run("POST /2fa/setup answers 200 from the token's address", func(t *testing.T) {
		env, tokens := deletedUserEnv(t, mount)
		rec := env.Do(bearer(env.Request(http.MethodPost, "/2fa/setup", nil), tokens))
		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "secret", "otpauthUrl")
		if uri, _ := body["otpauthUrl"].(string); !strings.Contains(uri, "deleted%40example.com") {
			t.Fatalf("otpauthUrl = %q, want it labelled with the token's address", uri)
		}
	})

	// A route that reads only the session store reaches its handler and answers
	// as it would for a live user: the gate itself refuses nothing here.
	t.Run("GET /sessions reaches the handler", func(t *testing.T) {
		env, tokens := deletedUserEnv(t, mount)
		rec := env.Do(bearer(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/sessions", nil), tokens))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "sessions")
	})

	t.Run("store writes", func(t *testing.T) { testDeletedUserStoreWrites(t, mount) })
	t.Run("a user-store read failure", func(t *testing.T) { testUserStoreReadFailure(t, mount) })
	t.Run("POST /2fa/disable after a tenant move", func(t *testing.T) { testTwoFactorDisableTenantMove(t, mount) })

	// The gate's own refusal is unchanged: under allcalls a revoked session is
	// SESSION_REVOKED before any handler runs, whether or not the user exists.
	t.Run("a revoked session is still SESSION_REVOKED under allcalls", func(t *testing.T) {
		env, tokens := deletedUserEnv(t, mount, auth.WithSessionCheckOn(auth.SessionCheckOnAllCalls))
		if err := env.Auth.Logout(context.Background(), tokens.RefreshToken); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		for _, req := range []*http.Request{
			httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil),
			env.Request(http.MethodPost, "/change-password", map[string]string{"currentPassword": "password1", "newPassword": "newpassword1"}),
			httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/sessions", nil),
		} {
			rec := env.Do(bearer(req, tokens))
			AssertError(t, rec, http.StatusUnauthorized, "Session has been revoked", auth.CodeSessionRevoked)
		}
	})
}

// recordEvents subscribes to every event on a new bus and returns the option
// that wires it and the list it fills.
func recordEvents() (auth.Option, *[]auth.Event) {
	bus := auth.NewEventBus()
	var (
		mu  sync.Mutex
		got []auth.Event
	)
	bus.Subscribe(auth.EventBusWildcard, func(ev auth.Event) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, ev)
	})
	return auth.WithEventBus(bus), &got
}

// testDeletedUserStoreWrites pins the routes whose handler writes the user
// store without looking the user up first. The reference's answer there is its
// store's: MemoryUserStore refuses a write to a missing row, so each is the
// generic, detail-free 500 — the body is exactly {"error":"Internal server
// error"} — and no event is raised. /2fa/disable, which re-reads the user
// first, fails closed with the 404.
func testDeletedUserStoreWrites(t *testing.T, mount Mounter) {
	for _, tc := range []struct {
		name, method, route string
		body                func() any
	}{
		{"PATCH /profile", http.MethodPatch, "/profile", func() any { return map[string]string{"firstName": "Mario", "lastName": "Rossi"} }},
		{"POST /add-phone", http.MethodPost, "/add-phone", func() any { return map[string]string{"phoneNumber": "+390123456789"} }},
		{"POST /2fa/verify-setup", http.MethodPost, "/2fa/verify-setup", func() any {
			const secret = "JBSWY3DPEHPK3PXP"
			return map[string]string{"secret": secret, "token": totpCode(t, secret, time.Now())}
		}},
		{"DELETE /account", http.MethodDelete, "/account", func() any { return nil }},
	} {
		t.Run(tc.name+" answers the store's 500, with no detail", func(t *testing.T) {
			bus, events := recordEvents()
			env, tokens := deletedUserEnv(t, mount, bus)
			*events = nil
			rec := env.Do(bearer(env.Request(tc.method, tc.route, tc.body()), tokens))
			AssertError(t, rec, http.StatusInternalServerError, "Internal server error", "")
			if len(*events) != 0 {
				t.Fatalf("a failed write raised %d event(s)", len(*events))
			}
		})
	}

	t.Run("POST /2fa/disable fails closed with 404 User not found", func(t *testing.T) {
		bus, events := recordEvents()
		env, tokens := deletedUserEnv(t, mount, bus)
		*events = nil
		rec := env.Do(bearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens))
		AssertError(t, rec, http.StatusNotFound, "User not found", "")
		if len(*events) != 0 {
			t.Fatalf("a refused disable raised %d event(s)", len(*events))
		}
	})
}

// brokenReadUserStore answers every GetUserByID with a store failure that is
// not ErrUserNotFound — an outage, not a missing row. Registration and login
// never read by id, so a user can still be seeded and logged in.
type brokenReadUserStore struct{ *auth.MemoryUserStore }

func (brokenReadUserStore) GetUserByID(context.Context, string, string) (auth.User, error) {
	return auth.User{}, errors.New("user store unavailable")
}

// A store read that fails for any reason other than a missing row is the
// reference's 500 (its findById throwing reaches handleError), never the 404
// that would tell a client the account is gone.
func testUserStoreReadFailure(t *testing.T, mount Mounter) {
	for _, tc := range []struct {
		name, method, route string
		body                any
	}{
		{"GET /me", http.MethodGet, "/me", nil},
		{"POST /change-password", http.MethodPost, "/change-password", map[string]string{"currentPassword": "password1", "newPassword": "newpassword1"}},
		{"POST /send-verification-email", http.MethodPost, "/send-verification-email", nil},
		{"POST /change-email/request", http.MethodPost, "/change-email/request", map[string]string{"newEmail": "free@example.com"}},
		{"POST /2fa/disable", http.MethodPost, "/2fa/disable", nil},
	} {
		t.Run(tc.name+" answers 500", func(t *testing.T) {
			env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(brokenReadUserStore{auth.NewMemoryUserStore()}))
			_, tokens := env.Seed("outage@example.com")
			rec := env.Do(bearer(env.Request(tc.method, tc.route, tc.body), tokens))
			AssertError(t, rec, http.StatusInternalServerError, "Internal server error", "")
		})
	}
}

// A user moved to another tenant after the token was minted is not the user
// the token names: the re-read is scoped by the token's tenant, misses, and
// the disable is refused even though the moved row carries require2FA.
func testTwoFactorDisableTenantMove(t *testing.T, mount Mounter) {
	store := auth.NewMemoryUserStore()
	env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
	user, tokens := env.Seed("moved@example.com")
	ctx := context.Background()
	if err := store.DeleteUser(ctx, user.ID, user.TenantID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	moved := user
	moved.TenantID = "t2"
	moved.Require2FA = true
	if _, err := store.CreateUser(ctx, moved); err != nil {
		t.Fatalf("recreate in t2: %v", err)
	}
	rec := env.Do(bearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens))
	AssertError(t, rec, http.StatusNotFound, "User not found", "")
}
