package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Under Config.RevokeSessionsOnPasswordReset an authorization code is bound to
// the password the /authorize login proved: a code minted with the old
// password does not open a session after a revoking reset, and a redemption
// already past that check when the reset lands keeps no session either.
// Without it, a code minted shortly before the reset — or one minted every few
// minutes by whoever holds the leaked password — redeemed for a fresh session
// the reset never saw.

// newResetIDPFixture is newIDPFixture over a service whose session check is
// allcalls, with RevokeSessionsOnPasswordReset as revoke and the given
// session store.
func newResetIDPFixture(t *testing.T, sessions SessionStore, revoke bool) (*idpFixture, *Service) {
	t.Helper()
	cfg := testConfig("01234567890123456789012345678901")
	cfg.RevokeSessionsOnPasswordReset = revoke
	cfg.SessionCheckOn = SessionCheckOnAllCalls
	svc, err := NewService(cfg, NewMemoryUserStore(), sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return newIDPFixtureOn(t, svc), svc
}

func resetIDPPassword(t *testing.T, svc *Service, newPassword string) {
	t.Helper()
	token := mintResetToken(t, svc, idpTestEmail)
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: token, NewPassword: newPassword}); err != nil {
		t.Fatalf("reset: %v", err)
	}
}

// TestRevokingResetRefusesACodeMintedBeforeIt is the verification's probe: a
// code minted with the old password, redeemed after a revoking reset, is
// invalid_grant. A code minted under the option redeems as any code does while
// the password stands, and one minted with the new password after the reset
// redeems too.
func TestRevokingResetRefusesACodeMintedBeforeIt(t *testing.T) {
	f, svc := newResetIDPFixture(t, NewMemorySessionStore(), true)
	ctx := context.Background()
	stale := f.authorize(t, idpTestClient, url.Values{"scope": {"openid offline_access"}})
	before := f.authorize(t, idpTestClient, url.Values{"scope": {"openid"}})
	if status, body := f.token(t, before, idpTestClient); status != http.StatusOK {
		t.Fatalf("a code redeemed before any reset = %d %v, want 200", status, body)
	}

	resetIDPPassword(t, svc, "newpassword1")

	status, body := f.token(t, stale, idpTestClient)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("a code minted before the revoking reset, redeemed after it = %d %v, want 400 invalid_grant", status, body)
	}
	if access, _ := body["access_token"].(string); access != "" {
		if _, err := svc.VerifyAccess(ctx, access); err == nil {
			t.Errorf("the access token that code got passes the all-calls session check after the revoking reset")
		}
	}

	after := f.authorizeWithPassword(t, idpTestClient, "newpassword1", url.Values{"scope": {"openid"}})
	if status, body := f.token(t, after, idpTestClient); status != http.StatusOK {
		t.Errorf("a code minted with the new password = %d %v, want 200", status, body)
	}
}

// TestACodeOutlivesAResetWithTheOptionOff pins the default: with the option off
// a reset revokes nothing, and a code minted before it redeems after it, as it
// always has.
func TestACodeOutlivesAResetWithTheOptionOff(t *testing.T) {
	f, svc := newResetIDPFixture(t, NewMemorySessionStore(), false)
	code := f.authorize(t, idpTestClient, url.Values{"scope": {"openid"}})
	resetIDPPassword(t, svc, "newpassword1")
	if status, body := f.token(t, code, idpTestClient); status != http.StatusOK {
		t.Errorf("a code minted before a reset, option off = %d %v, want 200", status, body)
	}
}

// redeemCode posts code to /token as idpTestClient. It reports a transport
// failure as an error rather than failing the test, so that it can run on a
// goroutine of its own.
func redeemCode(f *idpFixture, code string) (int, map[string]any, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {idpTestClient.ClientID},
		"client_secret": {idpTestClient.ClientSecret},
		"redirect_uri":  {idpTestClient.RedirectURIs[0]},
	}
	req, err := http.NewRequest(http.MethodPost, f.srv.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// TestRevokingResetLeavesNoSessionToACodeRedeemedInFlight: the redemption has
// read the account and passed the code's binding when the reset lands, and
// opens its session after the reset's revocation has looked. It reads the
// account again once the session exists, gives the session up and answers
// invalid_grant.
func TestRevokingResetLeavesNoSessionToACodeRedeemedInFlight(t *testing.T) {
	store := newHoldingSessionStore()
	f, svc := newResetIDPFixture(t, store, true)
	ctx := context.Background()
	code := f.authorize(t, idpTestClient, url.Values{"scope": {"openid offline_access"}})
	token := mintResetToken(t, svc, idpTestEmail)

	type answer struct {
		status int
		body   map[string]any
		err    error
	}
	done := make(chan answer, 1)
	store.arm()
	go func() {
		status, body, err := redeemCode(f, code)
		done <- answer{status, body, err}
	}()
	<-store.entered
	resetErr := svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "newpassword1"})
	close(store.release)
	got := <-done
	if resetErr != nil {
		t.Fatalf("reset with a redemption in flight: %v", resetErr)
	}
	if got.err != nil {
		t.Fatalf("POST /token: %v", got.err)
	}
	if got.status != http.StatusBadRequest || got.body["error"] != "invalid_grant" {
		t.Errorf("a redemption in flight across the revoking reset = %d %v, want 400 invalid_grant", got.status, got.body)
	}
	if access, _ := got.body["access_token"].(string); access != "" {
		if _, err := svc.VerifyAccess(ctx, access); err == nil {
			t.Errorf("the access token that redemption got passes the all-calls session check after the revoking reset")
		}
	}
	sessions, err := store.ListSessionsForUser(ctx, f.user.ID, idpTestTenant)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("the account has %d sessions, want 3: the registration's, the /authorize login's and the one /token opened", len(sessions))
	}
	for _, s := range sessions {
		if s.RevokedAt == nil {
			t.Errorf("session %s, opened with the old password, is live after the revoking reset", s.ID)
		}
	}
}

// TestAuthCodeCredentialIsSetOnlyUnderTheOption: with the option off a code is
// stored as it always was, Credential empty; with it on, Credential is set and
// is not the password hash.
func TestAuthCodeCredentialIsSetOnlyUnderTheOption(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		f, svc := newResetIDPFixture(t, NewMemorySessionStore(), revoke)
		f.authorize(t, idpTestClient, url.Values{"scope": {"openid"}})
		saved, _ := f.store.snapshot()
		if len(saved) != 1 {
			t.Fatalf("option %v: %d codes saved, want 1", revoke, len(saved))
		}
		credential := saved[0].Credential
		switch {
		case !revoke && credential != "":
			t.Errorf("option off: AuthCode.Credential = %q, want empty", credential)
		case revoke && credential == "":
			t.Error("option on: AuthCode.Credential is empty")
		case revoke && strings.Contains(credential, storedUser(t, svc, f.user.ID).PasswordHash):
			t.Error("option on: AuthCode.Credential carries the password hash")
		}
	}
}

// credentialDroppingCodeStore is an AuthCodeStore that does not keep
// AuthCode.Credential, as a store written before the field existed does not.
type credentialDroppingCodeStore struct{ *MemoryAuthCodeStore }

func (s credentialDroppingCodeStore) SaveCode(ctx context.Context, code AuthCode) error {
	code.Credential = ""
	return s.MemoryAuthCodeStore.SaveCode(ctx, code)
}

// TestACodeWithoutCredentialIsRefusedUnderTheOption: under the option a code
// whose credential the store did not keep is refused — nothing says which
// password it was minted under — rather than honoured across a reset.
func TestACodeWithoutCredentialIsRefusedUnderTheOption(t *testing.T) {
	cfg := testConfig("01234567890123456789012345678901")
	cfg.RevokeSessionsOnPasswordReset = true
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	f := newIDPFixtureOn(t, svc, func(c *IDPConfig) { c.Codes = credentialDroppingCodeStore{NewMemoryAuthCodeStore()} })
	code := f.authorize(t, idpTestClient, url.Values{"scope": {"openid"}})
	if status, body := f.token(t, code, idpTestClient); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("a code whose credential the store dropped = %d %v, want 400 invalid_grant", status, body)
	}
}
