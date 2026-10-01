package wiretest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Conformance cases for the password-management and email-verification group
// (wire-contract §2): POST /forgot-password, POST /reset-password,
// POST /change-password, POST /send-verification-email, GET /verify-email,
// POST /change-email/request, POST /change-email/confirm.
//
// A one-time token never appears in a response body — that is the point of it
// being a credential — so the flows that consume a token mint it through the
// service and then spend it over HTTP. That is also how a real deployment works:
// the token reaches the user by email, out of band.

// Reference TTLs for the three tokens in this group.
const (
	resetTokenTTL       = time.Hour
	verifyTokenTTL      = 24 * time.Hour
	emailChangeTokenTTL = time.Hour
)

// storeEnv mounts an adapter over a user store the test can inspect. Asserting
// on the stored row is what distinguishes "answered 200" from "did the work".
func storeEnv(t *testing.T, mount Mounter, cfg auth.HTTPConfig) (*Env, *auth.MemoryUserStore) {
	t.Helper()
	store := auth.NewMemoryUserStore()
	return NewEnv(t, mount, cfg, auth.WithUserStore(store)), store
}

// coreOnlyUserStore implements UserStore and nothing else, so every optional
// capability these routes reach for is absent. The reference reports such a
// store as 500, not 501 — a client that reads 501 as "feature not configured"
// must not see one here.
type coreOnlyUserStore struct{ inner *auth.MemoryUserStore }

func newCoreOnlyUserStore() coreOnlyUserStore {
	return coreOnlyUserStore{inner: auth.NewMemoryUserStore()}
}

func (s coreOnlyUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) {
	return s.inner.CreateUser(ctx, user)
}

func (s coreOnlyUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) {
	return s.inner.GetUserByEmail(ctx, email, tenantID)
}

func (s coreOnlyUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	return s.inner.GetUserByID(ctx, id, tenantID)
}

func bearer(req *http.Request, tokens auth.AuthTokens) *http.Request {
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	return req
}

// A credential-less request needs no help to reach the auth gate: CSRF
// enforcement is scoped to requests that carry an access-token cookie, so a
// request with no cookies at all is passed through and answered with the
// reference's "No access token provided". The three "unauthenticated gets 403"
// cases below therefore send a bare request — giving one a CSRF pair or a bearer
// strategy header would hide the ordering they exist to pin.

// assertOneTimeToken pins the shape of the one-time tokens this group mints.
//
// The reference mints 64 hex characters (crypto.randomBytes(32).toString('hex'),
// token.service.ts:270-272); this port renders the same 32 random bytes as 43
// base64url characters, because randomToken is shared with the API-key and IdP
// code paths. Both forms are URL-safe and opaque — no shipped client parses a
// token — so the difference is recorded here rather than left to be discovered,
// and switching the port to hex would have to change this assertion on purpose.
func assertOneTimeToken(t *testing.T, label, token string) {
	t.Helper()
	if len(token) != 43 {
		t.Errorf("%s = %d characters, want 43 (32 random bytes as base64url)", label, len(token))
	}
	for _, ch := range token {
		urlSafe := ch == '-' || ch == '_' ||
			(ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
		if !urlSafe {
			t.Errorf("%s carries %q, which is not safe in the emailed link", label, ch)
		}
	}
}

// assertSuccessBody pins the exact success envelope: {"success":true} and
// nothing else. A leaked token or a wrapped body fails here.
func assertSuccessBody(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	AssertStatus(t, rec, http.StatusOK)
	body := Body(t, rec)
	AssertKeys(t, body, "success")
	if body["success"] != true {
		t.Fatalf("success = %v, want true", body["success"])
	}
}

// assertTTL pins a stored expiry against the reference's TTL for that token.
func assertTTL(t *testing.T, label string, expiry *time.Time, want time.Duration) {
	t.Helper()
	if expiry == nil {
		t.Fatalf("%s expiry is nil, want now+%s", label, want)
	}
	drift := time.Until(*expiry) - want
	if drift < -time.Minute || drift > time.Minute {
		t.Errorf("%s expiry = now+%s, want now+%s", label, time.Until(*expiry).Round(time.Second), want)
	}
}

// malformed builds a request whose body is not JSON. Every route in this group
// accepts an *absent* body, as express.json() does, but a present-and-broken one
// is rejected with the port's own 400 INVALID_BODY.
func malformed(env *Env, method, route string) *http.Request {
	req := httptest.NewRequest(method, env.Config.Prefix()+route, strings.NewReader(`{"email":`))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// dropPassword makes a seeded account passwordless, which is what an OAuth-only
// or magic-link-only row looks like to these routes.
func dropPassword(t *testing.T, store *auth.MemoryUserStore, user auth.User) {
	t.Helper()
	if err := store.UpdatePassword(context.Background(), user.ID, user.TenantID, ""); err != nil {
		t.Fatalf("drop the stored password: %v", err)
	}
}

func storedUser(t *testing.T, store *auth.MemoryUserStore, user auth.User) auth.User {
	t.Helper()
	stored, err := store.GetUserByID(context.Background(), user.ID, user.TenantID)
	if err != nil {
		t.Fatalf("read back user %s: %v", user.ID, err)
	}
	return stored
}

func testPasswordAndEmail(t *testing.T, mount Mounter) {
	t.Run("ForgotPassword", func(t *testing.T) { testForgotPassword(t, mount) })
	t.Run("ResetPassword", func(t *testing.T) { testResetPassword(t, mount) })
	t.Run("ChangePassword", func(t *testing.T) { testChangePassword(t, mount) })
	t.Run("SendVerificationEmail", func(t *testing.T) { testSendVerificationEmail(t, mount) })
	t.Run("VerifyEmail", func(t *testing.T) { testVerifyEmail(t, mount) })
	t.Run("ChangeEmailRequest", func(t *testing.T) { testChangeEmailRequest(t, mount) })
	t.Run("ChangeEmailConfirm", func(t *testing.T) { testChangeEmailConfirm(t, mount) })
}

func testForgotPassword(t *testing.T, mount Mounter) {
	t.Run("a known address gets 200 and a stored token", func(t *testing.T) {
		env, store := storeEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("forgot@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/forgot-password", map[string]string{"email": "forgot@example.com", "tenantId": "t1"}))
		assertSuccessBody(t, rec)

		// No token is issued and no session starts, so nothing but the CSRF
		// cookie may be set.
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)

		stored := storedUser(t, store, user)
		if stored.ResetTokenHash == "" {
			t.Error("no reset token was persisted")
		}
		assertTTL(t, "reset token", stored.ResetTokenExpiresAt, resetTokenTTL)
	})

	// The anti-enumeration rule. An unknown address is answered exactly like a
	// known one: same status, same body, no hint of any kind.
	t.Run("an unknown address gets the same 200", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/forgot-password", map[string]string{"email": "nobody@example.com", "tenantId": "t1"}))
		assertSuccessBody(t, rec)
	})

	t.Run("an empty body gets 200", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/forgot-password", nil))
		assertSuccessBody(t, rec)
	})

	// An absent body is valid; a present but broken one is not. This is the
	// port's own convention, shared with /register and /login — the reference's
	// express.json() answers its own 400 for unparseable JSON.
	t.Run("a malformed body gets 400 INVALID_BODY", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(malformed(env, http.MethodPost, "/forgot-password"))
		AssertError(t, rec, http.StatusBadRequest, "Invalid request body", auth.CodeInvalidBody)
	})

	// The reference's own enumeration oracle, reproduced rather than fixed: a
	// store that cannot persist a reset token throws only once a user has been
	// found, so an existing address 500s where an unknown one still 200s.
	t.Run("an incapable store 500s, and only for an address that exists", func(t *testing.T) {
		store := newCoreOnlyUserStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
		env.Seed("forgotgap@example.com")

		known := env.Do(env.Request(http.MethodPost, "/forgot-password", map[string]string{"email": "forgotgap@example.com", "tenantId": "t1"}))
		AssertError(t, known, http.StatusInternalServerError, "Internal server error", "")

		unknown := env.Do(env.Request(http.MethodPost, "/forgot-password", map[string]string{"email": "nobody@example.com", "tenantId": "t1"}))
		assertSuccessBody(t, unknown)
	})
}

func testResetPassword(t *testing.T, mount Mounter) {
	t.Run("spends the token, replaces the password, and the token is single-use", func(t *testing.T) {
		env, store := storeEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("reset@example.com")

		// Minted through the service: no route may hand a reset token back to a
		// caller, so this is the only way a test can hold one.
		token, err := env.Auth.Service().ForgotPassword(context.Background(), auth.ForgotPasswordInput{Email: "reset@example.com", TenantID: "t1"})
		if err != nil {
			t.Fatalf("mint reset token: %v", err)
		}
		assertOneTimeToken(t, "reset token", token)

		rec := env.Do(env.Request(http.MethodPost, "/reset-password", map[string]string{"token": token, "password": "newpassword1"}))
		assertSuccessBody(t, rec)

		if stored := storedUser(t, store, user); stored.ResetTokenHash != "" || stored.ResetTokenExpiresAt != nil {
			t.Error("the reset token survived being spent")
		}

		fresh := env.Do(env.Request(http.MethodPost, "/login", map[string]string{"email": "reset@example.com", "password": "newpassword1", "tenantId": "t1"}))
		AssertStatus(t, fresh, http.StatusOK)
		stale := env.Do(env.Request(http.MethodPost, "/login", credentials("reset@example.com")))
		AssertError(t, stale, http.StatusUnauthorized, "Invalid credentials", auth.CodeInvalidCredentials)

		// Nothing is revoked: the session that existed before the reset still
		// works, as in the reference, which clears no cookie and kills no session.
		me := env.Do(bearer(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), tokens))
		AssertStatus(t, me, http.StatusOK)

		replay := env.Do(env.Request(http.MethodPost, "/reset-password", map[string]string{"token": token, "password": "thirdpassword1"}))
		AssertError(t, replay, http.StatusBadRequest, "Invalid reset token", "")
	})

	// Port-only: the reference applies no password policy on this route at all, so
	// a two-character password there is hashed and stored. Pinned as a divergence
	// rather than left to be discovered — the status, message and code are the
	// port's own catalog entry.
	t.Run("a too short password gets 400 WEAK_PASSWORD (port-only)", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("resetweak@example.com")
		token, err := env.Auth.Service().ForgotPassword(context.Background(), auth.ForgotPasswordInput{Email: "resetweak@example.com", TenantID: "t1"})
		if err != nil {
			t.Fatalf("mint reset token: %v", err)
		}
		rec := env.Do(env.Request(http.MethodPost, "/reset-password", map[string]string{"token": token, "password": "xy"}))
		AssertError(t, rec, http.StatusBadRequest, "Password is too weak", auth.CodeWeakPassword)
	})

	// Also pins the CSRF exemption: an unauthenticated caller that carries a CSRF
	// cookie but mirrors no header still reaches the handler, so the answer is
	// the token error and not CSRF_INVALID.
	t.Run("an unknown token gets 400 and the route is CSRF-exempt", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		req := env.Request(http.MethodPost, "/reset-password", map[string]string{"token": "nosuchtoken", "password": "newpassword1"})
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertError(t, env.Do(req), http.StatusBadRequest, "Invalid reset token", "")
	})

	t.Run("an incapable store gets 500 with the reference's wording", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(newCoreOnlyUserStore()))
		rec := env.Do(env.Request(http.MethodPost, "/reset-password", map[string]string{"token": "irrelevant", "password": "newpassword1"}))
		AssertError(t, rec, http.StatusInternalServerError, "UserStore does not implement findByResetToken", "")
	})
}

func testChangePassword(t *testing.T, mount Mounter) {
	t.Run("replaces the password", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("changepw@example.com")

		req := env.Request(http.MethodPost, "/change-password", map[string]string{"currentPassword": "password1", "newPassword": "newpassword1"})
		rec := env.Do(bearer(req, tokens))
		assertSuccessBody(t, rec)
		// No cookie is written and no session is revoked: the reference leaves
		// existing sessions alive after a password change.
		AssertNoCookies(t, rec)

		fresh := env.Do(env.Request(http.MethodPost, "/login", map[string]string{"email": "changepw@example.com", "password": "newpassword1", "tenantId": "t1"}))
		AssertStatus(t, fresh, http.StatusOK)

		// "Revokes nothing" asserted, not just claimed: the access token that
		// changed the password still works afterwards.
		me := env.Do(bearer(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), tokens))
		AssertStatus(t, me, http.StatusOK)
	})

	// The passwordless fall-through, and the reason this route exists for an
	// OAuth-only account: with no stored password the current-password comparison
	// is skipped entirely and newPassword alone sets the initial password
	// (wire-contract §2 "Passwordless-account path"; the compare sits inside
	// `if (user.password)`, auth.router.ts:1480-1489 at v1.10.8). Since #30 this
	// is Service.ChangePassword's own behaviour rather than an HTTP-layer detour.
	// Answering 401 "Current password is incorrect" here — reporting a password the
	// account does not have as wrong — makes the flow impossible, so the 200 is
	// pinned along with the stored effect.
	t.Run("a passwordless account sets an initial password", func(t *testing.T) {
		env, store := storeEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("changepwinitial@example.com")
		dropPassword(t, store, user)

		req := env.Request(http.MethodPost, "/change-password", map[string]string{"newPassword": "initialpw1"})
		rec := env.Do(bearer(req, tokens))
		assertSuccessBody(t, rec)
		AssertNoCookies(t, rec)

		if storedUser(t, store, user).PasswordHash == "" {
			t.Error("the account is still passwordless")
		}
		fresh := env.Do(env.Request(http.MethodPost, "/login", map[string]string{"email": "changepwinitial@example.com", "password": "initialpw1", "tenantId": "t1"}))
		AssertStatus(t, fresh, http.StatusOK)

		// A currentPassword sent by a passwordless account is ignored rather than
		// compared: the reference compares only when the account has a password,
		// so this too is a 200.
		other, otherTokens := env.Seed("changepwinitial2@example.com")
		dropPassword(t, store, other)
		ignored := env.Request(http.MethodPost, "/change-password", map[string]string{"currentPassword": "not-a-password", "newPassword": "initialpw2"})
		assertSuccessBody(t, env.Do(bearer(ignored, otherTokens)))
	})

	// Port-only, as on /reset-password: the reference has no password policy on
	// this route. Pinned as the divergence it is. The check runs after the
	// reference's own refusals, so a wrong current password with a weak new one
	// is the reference's 401, pinned below.
	t.Run("a too short new password gets 400 WEAK_PASSWORD (port-only)", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("changepwweak@example.com")
		req := env.Request(http.MethodPost, "/change-password", map[string]string{"currentPassword": "password1", "newPassword": "xy"})
		AssertError(t, env.Do(bearer(req, tokens)), http.StatusBadRequest, "Password is too weak", auth.CodeWeakPassword)
	})

	// The malformed-body rule holds behind the auth gate too, and the gate runs
	// first: this is a 400 only because the bearer token is valid.
	t.Run("a malformed body gets 400 INVALID_BODY", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("changepwbody@example.com")
		rec := env.Do(bearer(malformed(env, http.MethodPost, "/change-password"), tokens))
		AssertError(t, rec, http.StatusBadRequest, "Invalid request body", auth.CodeInvalidBody)
	})

	// 401 with no code, not the coded INVALID_CREDENTIALS a failed login returns.
	// The Angular interceptor will refresh-and-replay this 401 because
	// /change-password is not on its no-retry list; that hazard is the
	// reference's and is reproduced, not smoothed over.
	t.Run("a wrong current password gets 401 Current password is incorrect", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("changepwbad@example.com")
		req := env.Request(http.MethodPost, "/change-password", map[string]string{"currentPassword": "wrongpassword", "newPassword": "newpassword1"})
		AssertError(t, env.Do(bearer(req, tokens)), http.StatusUnauthorized, "Current password is incorrect", "")
	})

	// The port's policy never outranks the reference's own answer: a wrong
	// current password is 401 even when the new one is too short.
	t.Run("a wrong current password outranks a weak new one", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("changepwbadweak@example.com")
		req := env.Request(http.MethodPost, "/change-password", map[string]string{"currentPassword": "wrongpassword", "newPassword": "xy"})
		AssertError(t, env.Do(bearer(req, tokens)), http.StatusUnauthorized, "Current password is incorrect", "")
	})

	// 403, not 401, for a missing credential — the reference's auth middleware
	// answers 403 and carries no code.
	t.Run("unauthenticated gets 403", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		req := env.Request(http.MethodPost, "/change-password", map[string]string{"currentPassword": "password1", "newPassword": "newpassword1"})
		AssertError(t, env.Do(req), http.StatusForbidden, "No access token provided", "")
	})

	// The two 403s side by side, which is what fixes the order in place. Both
	// requests omit the CSRF header; only the session cookie differs. The reference
	// extracts the access token first, so no token means "No access token provided"
	// and a cookie-authenticated forgery means CSRF_INVALID
	// (auth.middleware.ts:29-32 then :33-42). This used to be a pinned divergence:
	// the port answered CSRF_INVALID to both.
	t.Run("the session cookie decides which gate answers", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("changepworder@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("changepworder@example.com")))
		body := map[string]string{"currentPassword": "password1", "newPassword": "newpassword1"}

		anonymous := env.Do(env.Request(http.MethodPost, "/change-password", body))
		AssertError(t, anonymous, http.StatusForbidden, "No access token provided", "")

		authenticated := env.Do(Replay(env.Request(http.MethodPost, "/change-password", body), login))
		AssertError(t, authenticated, http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
	})

	// An account with no password may not be given one silently: with neither
	// field supplied the reference answers 400 "New password is required". This is
	// the guard the passwordless fall-through above sits behind.
	t.Run("a passwordless account with an empty body gets 400", func(t *testing.T) {
		env, store := storeEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("changepwnone@example.com")
		dropPassword(t, store, user)
		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/change-password", nil)
		AssertError(t, env.Do(bearer(req, tokens)), http.StatusBadRequest, "New password is required", "")
	})

	// At v1.10.8 the missing-newPassword refusal is unconditional: it runs before
	// the comparison and for an account with a password too
	// (auth.router.ts:1476-1479). The port used to answer that account's request
	// with the port-only 400 WEAK_PASSWORD, whatever the current password.
	for _, current := range []string{"password1", "wrongpassword"} {
		t.Run("an absent newPassword gets 400 whatever the current password: "+current, func(t *testing.T) {
			env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
			_, tokens := env.Seed("changepwnonew@example.com")
			req := env.Request(http.MethodPost, "/change-password", map[string]string{"currentPassword": current})
			AssertError(t, env.Do(bearer(req, tokens)), http.StatusBadRequest, "New password is required", "")
		})
	}

	// An account that has a password must present it: an absent current password
	// is the same 401 as a wrong one (auth.router.ts:1480-1483 at v1.10.8), and
	// nothing is written.
	t.Run("an account with a password and no currentPassword gets 401", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("changepwnocurrent@example.com")
		req := env.Request(http.MethodPost, "/change-password", map[string]string{"newPassword": "newpassword1"})
		AssertError(t, env.Do(bearer(req, tokens)), http.StatusUnauthorized, "Current password is incorrect", "")

		stale := env.Do(env.Request(http.MethodPost, "/login", map[string]string{"email": "changepwnocurrent@example.com", "password": "newpassword1", "tenantId": "t1"}))
		AssertStatus(t, stale, http.StatusUnauthorized)
	})

	// This route sits behind the auth middleware, so unlike /reset-password it is
	// CSRF-checked for a cookie client.
	t.Run("cookie mode is CSRF-checked", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("changepwcsrf@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("changepwcsrf@example.com")))
		csrf := Cookie(t, login, hostCSRF).Value

		unmirrored := Replay(env.Request(http.MethodPost, "/change-password", map[string]string{"currentPassword": "password1", "newPassword": "newpassword1"}), login)
		AssertError(t, env.Do(unmirrored), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)

		mirrored := Replay(env.Request(http.MethodPost, "/change-password", map[string]string{"currentPassword": "password1", "newPassword": "newpassword1"}), login)
		mirrored.Header.Set(auth.CSRFHeaderName, csrf)
		assertSuccessBody(t, env.Do(mirrored))
	})
}

// unverify clears the verified flag on a seeded user. Register marks an address
// verified under the default mode, so this is how a test gets an unverified
// account without reaching past auth.New for the service config.
func unverify(t *testing.T, store *auth.MemoryUserStore, user auth.User) {
	t.Helper()
	if err := store.MarkEmailVerified(context.Background(), user.ID, user.TenantID, false); err != nil {
		t.Fatalf("unverify %s: %v", user.Email, err)
	}
}

func testSendVerificationEmail(t *testing.T, mount Mounter) {
	// The Flutter client posts this route with no body at all, so an absent body
	// has to be valid.
	t.Run("stores a 24 hour token and accepts an empty body", func(t *testing.T) {
		env, store := storeEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("verifysend@example.com")
		unverify(t, store, user)

		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/send-verification-email", nil)
		assertSuccessBody(t, env.Do(bearer(req, tokens)))

		stored := storedUser(t, store, user)
		if stored.EmailVerificationTokenHash == "" {
			t.Error("no verification token was persisted")
		}
		assertTTL(t, "verification token", stored.EmailVerificationTokenExpiry, verifyTokenTTL)
	})

	t.Run("an already verified address gets 400", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("verifydone@example.com")
		req := env.Request(http.MethodPost, "/send-verification-email", map[string]string{})
		AssertError(t, env.Do(bearer(req, tokens)), http.StatusBadRequest, "Email is already verified", "")
	})

	t.Run("unauthenticated gets 403", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/send-verification-email", nil)
		AssertError(t, env.Do(req), http.StatusForbidden, "No access token provided", "")
	})

	t.Run("an incapable store gets 500 with the reference's wording", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(newCoreOnlyUserStore()))
		_, tokens := env.Seed("verifygap@example.com")
		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/send-verification-email", nil)
		AssertError(t, env.Do(bearer(req, tokens)), http.StatusInternalServerError, "UserStore does not implement email verification", "")
	})
}

func testVerifyEmail(t *testing.T, mount Mounter) {
	t.Run("marks the address verified and the token is single-use", func(t *testing.T) {
		env, store := storeEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("verify@example.com")
		unverify(t, store, user)

		token, err := env.Auth.Service().SendVerificationEmailToken(context.Background(), auth.EmailVerificationInput{UserID: user.ID, TenantID: user.TenantID})
		if err != nil {
			t.Fatalf("mint verification token: %v", err)
		}
		assertOneTimeToken(t, "verification token", token)

		rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/verify-email?token="+token, nil))
		assertSuccessBody(t, rec)

		stored := storedUser(t, store, user)
		if !stored.IsEmailVerified {
			t.Error("the address is still unverified")
		}
		if stored.EmailVerificationTokenHash != "" || stored.EmailVerificationTokenExpiry != nil {
			t.Error("the verification token survived being spent")
		}

		replay := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/verify-email?token="+token, nil))
		AssertError(t, replay, http.StatusBadRequest, "Invalid verification token", "")
	})

	t.Run("a missing token gets 400 Token is required", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/verify-email", nil))
		AssertError(t, rec, http.StatusBadRequest, "Token is required", "")
	})

	t.Run("an unknown token gets 400 Invalid verification token", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/verify-email?token=nosuchtoken", nil))
		AssertError(t, rec, http.StatusBadRequest, "Invalid verification token", "")
	})

	// The query value is not trimmed. `if (!token)` in the reference sees a
	// truthy " ", so a whitespace-only token is a *lookup* failure there, not a
	// missing one — same 400, different message. Trimming would be friendlier and
	// no shipped client sends it, but the reference's answer wins, and the two
	// messages are only distinguishable by a test like this one.
	t.Run("a whitespace token is invalid, not missing", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/verify-email?token=%20", nil))
		AssertError(t, rec, http.StatusBadRequest, "Invalid verification token", "")
	})

	// The route performs no content negotiation and never redirects. A browser
	// asking for HTML still gets JSON; the HTML experience belongs to a static
	// page that calls this endpoint.
	t.Run("answers JSON even when the caller asks for HTML", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/verify-email?token=nosuchtoken", nil)
		req.Header.Set("Accept", "text/html")
		rec := env.Do(req)
		AssertStatus(t, rec, http.StatusBadRequest)
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		if location := rec.Header().Get("Location"); location != "" {
			t.Errorf("unexpected redirect to %q", location)
		}
	})

	t.Run("an incapable store gets 500 with the reference's wording", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(newCoreOnlyUserStore()))
		rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/verify-email?token=irrelevant", nil))
		AssertError(t, rec, http.StatusInternalServerError, "UserStore does not implement email verification", "")
	})
}

func testChangeEmailRequest(t *testing.T, mount Mounter) {
	t.Run("stores the pending address with a 1 hour token", func(t *testing.T) {
		env, store := storeEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("changemail@example.com")

		req := env.Request(http.MethodPost, "/change-email/request", map[string]string{"newEmail": "changed@example.com"})
		assertSuccessBody(t, env.Do(bearer(req, tokens)))

		stored := storedUser(t, store, user)
		if stored.PendingEmail != "changed@example.com" {
			t.Errorf("pending address = %q, want changed@example.com", stored.PendingEmail)
		}
		if stored.Email != "changemail@example.com" {
			t.Errorf("the address changed before confirmation: %q", stored.Email)
		}
		if stored.EmailChangeTokenHash == "" {
			t.Error("no email-change token was persisted")
		}
		assertTTL(t, "email-change token", stored.EmailChangeTokenExpiry, emailChangeTokenTTL)
	})

	// The deliberate asymmetry with /forgot-password: this route tells an
	// authenticated caller that an address is taken. Reproduced, not harmonised.
	t.Run("an address in use gets a code-less 409", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("changemailtaken@example.com")
		env.Seed("occupied@example.com")

		req := env.Request(http.MethodPost, "/change-email/request", map[string]string{"newEmail": "occupied@example.com"})
		AssertError(t, env.Do(bearer(req, tokens)), http.StatusConflict, "Email address is already in use", "")
	})

	t.Run("unauthenticated gets 403", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		req := env.Request(http.MethodPost, "/change-email/request", map[string]string{"newEmail": "changed@example.com"})
		AssertError(t, env.Do(req), http.StatusForbidden, "No access token provided", "")
	})

	// The one coded error in this group: an account whose only credential is its
	// address may not move that address.
	t.Run("a passwordless account gets 403 PASSWORD_REQUIRED", func(t *testing.T) {
		env, store := storeEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("changemailnopw@example.com")
		dropPassword(t, store, user)
		req := env.Request(http.MethodPost, "/change-email/request", map[string]string{"newEmail": "changed@example.com"})
		AssertError(t, env.Do(bearer(req, tokens)), http.StatusForbidden,
			"You must set a password before you can change your email address.", auth.CodePasswordRequired)
		if n := len(env.Delivered.EmailChanges); n != 0 {
			t.Fatalf("%d email-change mail(s) sent for a refused request", n)
		}
	})

	// The guard reads the stored row since #31 — the user in context is built
	// from the token and has no password hash — and it now runs where the
	// reference runs it, after the 409 (auth.router.ts:1586-1601 at v1.10.8).
	// It used to run first, so this request answered 403.
	t.Run("an address in use outranks PASSWORD_REQUIRED", func(t *testing.T) {
		env, store := storeEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("changemailnopw2@example.com")
		dropPassword(t, store, user)
		env.Seed("taken2@example.com")
		req := env.Request(http.MethodPost, "/change-email/request", map[string]string{"newEmail": "taken2@example.com"})
		AssertError(t, env.Do(bearer(req, tokens)), http.StatusConflict, "Email address is already in use", "")
	})

	t.Run("an incapable store gets 500 with the reference's wording", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(newCoreOnlyUserStore()))
		_, tokens := env.Seed("changemailgap@example.com")
		req := env.Request(http.MethodPost, "/change-email/request", map[string]string{"newEmail": "changed@example.com"})
		AssertError(t, env.Do(bearer(req, tokens)), http.StatusInternalServerError, "UserStore does not implement change-email", "")
	})
}

func testChangeEmailConfirm(t *testing.T, mount Mounter) {
	t.Run("applies the address, and the token is single-use", func(t *testing.T) {
		env, store := storeEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("confirmmail@example.com")

		token, err := env.Auth.Service().RequestEmailChange(context.Background(), auth.ChangeEmailRequestInput{
			UserID: user.ID, TenantID: user.TenantID, NewEmail: "confirmed@example.com",
		})
		if err != nil {
			t.Fatalf("mint email-change token: %v", err)
		}
		assertOneTimeToken(t, "email-change token", token)

		rec := env.Do(env.Request(http.MethodPost, "/change-email/confirm", map[string]string{"token": token}))
		assertSuccessBody(t, rec)

		stored := storedUser(t, store, user)
		if stored.Email != "confirmed@example.com" {
			t.Errorf("address = %q, want confirmed@example.com", stored.Email)
		}
		if stored.PendingEmail != "" || stored.EmailChangeTokenHash != "" || stored.EmailChangeTokenExpiry != nil {
			t.Error("the email-change token survived being spent")
		}

		// The session lives on and the access token still works, so /me reflects
		// the new address without a re-login.
		me := env.Do(bearer(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), tokens))
		AssertStatus(t, me, http.StatusOK)
		if got := Body(t, me)["email"]; got != "confirmed@example.com" {
			t.Errorf("GET /me email = %v, want confirmed@example.com", got)
		}

		replay := env.Do(env.Request(http.MethodPost, "/change-email/confirm", map[string]string{"token": token}))
		AssertError(t, replay, http.StatusBadRequest, "Invalid email-change token", "")
	})

	// No auth gate and no CSRF check: the emailed token is the credential, so the
	// link has to work from a browser with no session and a stale CSRF cookie.
	t.Run("an unknown token gets 400 and the route is CSRF-exempt", func(t *testing.T) {
		env, _ := storeEnv(t, mount, auth.DefaultHTTPConfig())
		req := env.Request(http.MethodPost, "/change-email/confirm", map[string]string{"token": "nosuchtoken"})
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertError(t, env.Do(req), http.StatusBadRequest, "Invalid email-change token", "")
	})

	t.Run("an incapable store gets 500 with the reference's wording", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(newCoreOnlyUserStore()))
		rec := env.Do(env.Request(http.MethodPost, "/change-email/confirm", map[string]string{"token": "irrelevant"}))
		AssertError(t, rec, http.StatusInternalServerError, "UserStore does not implement change-email", "")
	})
}
