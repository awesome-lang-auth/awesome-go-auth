package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Under Config.RevokeSessionsOnPasswordReset the token POST <admin>/login
// mints for a store account is bound to the password the login proved, and
// the guard — which reads the account on every console request anyway —
// refuses it once the account's password is another. Without that, a console
// token obtained with a leaked password lived out its 24 hours after a
// revoking reset: it is stateless, and no session of the account backs it.

const consoleEmail = "console@example.com"

func newConsoleResetFixture(t *testing.T, revoke bool) (*Auth, HTTPConfig) {
	t.Helper()
	a, err := newTestAuth(WithRevokeSessionsOnPasswordReset(revoke))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// POST <admin>/login resolves accounts in the empty tenant only.
	if _, _, err := a.Service().Register(context.Background(), RegisterInput{Email: consoleEmail, Password: "password1"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	cfg := DefaultHTTPConfig()
	cfg.Admin = AdminOptions{
		Enabled: true,
		AccessPolicy: AdminPredicate(func(context.Context, User, RolesPermissionsStore) (bool, error) {
			return true, nil
		}),
	}
	return a, cfg
}

// consoleLogin signs in at POST <admin>/login and returns the cookies the
// answer set.
func consoleLogin(t *testing.T, a *Auth, cfg HTTPConfig, email, password string) []*http.Cookie {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req := httptest.NewRequest(http.MethodPost, cfg.AdminPath()+AdminLoginPath, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.AdminHandler(cfg).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST <admin>/login = %d %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("POST <admin>/login set no cookie")
	}
	return cookies
}

// consoleGet sends a console request with cookies, accepting accept.
func consoleGet(a *Auth, cfg HTTPConfig, path, accept string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, cfg.AdminPath()+path, nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a.AdminHandler(cfg).ServeHTTP(rec, req)
	return rec
}

func resetConsoleAccount(t *testing.T, a *Auth, newPassword string) {
	t.Helper()
	ctx := context.Background()
	token, err := a.Service().ForgotPassword(ctx, ForgotPasswordInput{Email: consoleEmail})
	if err != nil || token == "" {
		t.Fatalf("forgot password: token %q, err %v", token, err)
	}
	if err := a.Service().ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: newPassword}); err != nil {
		t.Fatalf("reset: %v", err)
	}
}

// TestRevokingResetEndsTheConsoleToken is the verification's probe: a console
// cookie obtained with the old password opens the console before the reset
// and not after it. One obtained with the new password does.
func TestRevokingResetEndsTheConsoleToken(t *testing.T) {
	a, cfg := newConsoleResetFixture(t, true)
	stale := consoleLogin(t, a, cfg, consoleEmail, "password1")
	if rec := consoleGet(a, cfg, AdminPingPath, "", stale); rec.Code != http.StatusOK {
		t.Fatalf("before the reset: GET <admin>/api/ping = %d %s, want 200", rec.Code, rec.Body.String())
	}

	resetConsoleAccount(t, a, "newpassword1")

	if rec := consoleGet(a, cfg, AdminPingPath, "", stale); rec.Code != http.StatusUnauthorized {
		t.Errorf("after the revoking reset: GET <admin>/api/ping with the old password's cookie = %d %s, want 401", rec.Code, rec.Body.String())
	}
	fresh := consoleLogin(t, a, cfg, consoleEmail, "newpassword1")
	if rec := consoleGet(a, cfg, AdminPingPath, "", fresh); rec.Code != http.StatusOK {
		t.Errorf("a console login with the new password: GET <admin>/api/ping = %d %s, want 200", rec.Code, rec.Body.String())
	}
}

// TestConsoleTokenOutlivesAResetWithTheOptionOff pins the default: a reset
// leaves the console token alive, as it always has.
func TestConsoleTokenOutlivesAResetWithTheOptionOff(t *testing.T) {
	a, cfg := newConsoleResetFixture(t, false)
	cookies := consoleLogin(t, a, cfg, consoleEmail, "password1")
	resetConsoleAccount(t, a, "newpassword1")
	if rec := consoleGet(a, cfg, AdminPingPath, "", cookies); rec.Code != http.StatusOK {
		t.Errorf("option off, after a reset: GET <admin>/api/ping = %d %s, want 200", rec.Code, rec.Body.String())
	}
}

// TestStaleConsoleTokenIsAnsweredAsAnExpiredOne: under the option a browser
// whose console cookie predates the reset is shown the login form, as one
// whose cookie expired is, and every other console route answers 401.
func TestStaleConsoleTokenIsAnsweredAsAnExpiredOne(t *testing.T) {
	a, cfg := newConsoleResetFixture(t, true)
	stale := consoleLogin(t, a, cfg, consoleEmail, "password1")
	resetConsoleAccount(t, a, "newpassword1")

	rec := consoleGet(a, cfg, AdminShellPath, "text/html", stale)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="login"`) {
		t.Errorf("the shell with a cookie from before the reset = %d, want 200 and the login form; body %.200s", rec.Code, rec.Body.String())
	}
	if rec := consoleGet(a, cfg, AdminPingPath, "text/html", stale); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET <admin>/api/ping from a browser with a cookie from before the reset = %d, want 401", rec.Code)
	}
}

// TestConsoleTokenWithoutCredUnderTheOption: a store account's console token
// that carries no cred claim — minted before the option was turned on — is
// refused under it, and the root user's token, which names no stored account,
// is untouched.
func TestConsoleTokenWithoutCredUnderTheOption(t *testing.T) {
	a, cfg := newConsoleResetFixture(t, true)
	user, err := a.Service().users.GetUserByEmail(context.Background(), consoleEmail, "")
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	bare, err := a.AdminGuard(cfg).mintAdminToken(adminClaims{Sub: user.ID, Email: user.Email, Tid: user.TenantID})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if rec := consoleGet(a, cfg, AdminPingPath, "", []*http.Cookie{{Name: AccessTokenCookieName, Value: bare}}); rec.Code != http.StatusUnauthorized {
		t.Errorf("a store account's console token with no cred claim, option on = %d, want 401", rec.Code)
	}

	rootHash, err := hashPassword("rootpassword1", testBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Admin.RootUser = &AdminRootUser{Email: "root@example.com", PasswordHash: rootHash}
	root := consoleLogin(t, a, cfg, "root@example.com", "rootpassword1")
	if rec := consoleGet(a, cfg, AdminPingPath, "", root); rec.Code != http.StatusOK {
		t.Errorf("the root user's console token, option on = %d %s, want 200", rec.Code, rec.Body.String())
	}
}
