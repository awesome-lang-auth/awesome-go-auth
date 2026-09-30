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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
