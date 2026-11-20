package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

var _ SessionAuthenticationStore = (*MemorySessionStore)(nil)

// clockedService is a service whose clock the test moves, with a memory user
// and session store it can inspect.
type clockedService struct {
	svc      *Service
	users    *MemoryUserStore
	sessions *MemorySessionStore
	now      time.Time
}

func newClockedService(t *testing.T, tweak ...func(*Config)) *clockedService {
	t.Helper()
	c := &clockedService{
		users:    NewMemoryUserStore(),
		sessions: NewMemorySessionStore(),
		now:      time.Now().Truncate(time.Second),
	}
	cfg := testConfig(testSecret)
	for _, f := range tweak {
		f(&cfg)
	}
	svc, err := NewService(cfg, c.users, c.sessions)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.now = func() time.Time { return c.now }
	c.svc = svc
	return c
}

func (c *clockedService) advance(d time.Duration) { c.now = c.now.Add(d) }

// register creates a user with no session, whatever IssueSessionOnRegister says.
func (c *clockedService) register(t *testing.T, email string) User {
	t.Helper()
	user, _, err := c.svc.Register(context.Background(), RegisterInput{Email: email, Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return user
}

// enrol gives user a TOTP factor and returns the secret.
func (c *clockedService) enrol(t *testing.T, user User) string {
	t.Helper()
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.svc.VerifyTOTPSetup(context.Background(), user.ID, user.TenantID, secret, c.code(t, secret)); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	return secret
}

func (c *clockedService) code(t *testing.T, secret string) string {
	t.Helper()
	code, ok := generateTOTPCode(secret, c.now.Unix()/int64(TOTPPeriod/time.Second))
	if !ok {
		t.Fatal("generateTOTPCode failed")
	}
	return code
}

// payloadOf decodes a compact JWT's payload without verifying it.
func payloadOf(t *testing.T, token string) map[string]any {
	t.Helper()
	return decodeSegment(t, mustSegment(t, token, 1))
}

func amrOf(t *testing.T, claims map[string]any) []string {
	t.Helper()
	raw, present := claims[ClaimAMR]
	if !present {
		return nil
	}
	items, ok := raw.([]any)
	if !ok {
		t.Fatalf("amr = %#v, want an array", raw)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("amr holds %#v, want strings", item)
		}
		out = append(out, s)
	}
	return out
}

// assertContext checks the three claims of an access token.
func assertContext(t *testing.T, token string, wantAMR []string, wantAuthTime time.Time, wantMFAAt *time.Time) {
	t.Helper()
	claims := payloadOf(t, token)
	if got := amrOf(t, claims); !slices.Equal(got, wantAMR) {
		t.Errorf("amr = %v, want %v", got, wantAMR)
	}
	if got, _ := claims[ClaimAuthTime].(float64); int64(got) != wantAuthTime.Unix() {
		t.Errorf("auth_time = %v, want %d", claims[ClaimAuthTime], wantAuthTime.Unix())
	}
	got, present := claims[ClaimMFAAt]
	switch {
	case wantMFAAt == nil && present:
		t.Errorf("mfa_at = %v, want it absent: no second factor was presented", got)
	case wantMFAAt != nil && !present:
		t.Errorf("mfa_at is absent, want %d", wantMFAAt.Unix())
	case wantMFAAt != nil:
		if seconds, _ := got.(float64); int64(seconds) != wantMFAAt.Unix() {
			t.Errorf("mfa_at = %v, want %d", got, wantMFAAt.Unix())
		}
	}
}

// TestSessionOpenersRecordTheirAuthentication walks every way this package
// opens a session and pins what the session records and what its access token
// says.
func TestSessionOpenersRecordTheirAuthentication(t *testing.T) {
	ctx := context.Background()
	at := func(c *clockedService) *time.Time { now := c.now; return &now }

	t.Run("a password login", func(t *testing.T) {
		c := newClockedService(t)
		c.register(t, "pwd@example.com")
		_, tokens, err := c.svc.Login(ctx, LoginInput{Email: "pwd@example.com", Password: "password1", TenantID: "t1"})
		if err != nil {
			t.Fatal(err)
		}
		assertContext(t, tokens.AccessToken, []string{AMRPassword}, c.now, nil)
	})

	t.Run("a registration that opens a session", func(t *testing.T) {
		c := newClockedService(t) // testConfig turns IssueSessionOnRegister on
		_, tokens, err := c.svc.Register(ctx, RegisterInput{Email: "reg@example.com", Password: "password1", TenantID: "t1"})
		if err != nil || tokens.AccessToken == "" {
			t.Fatalf("register = %v, %+v", err, tokens)
		}
		assertContext(t, tokens.AccessToken, []string{AMRPassword}, c.now, nil)
	})

	t.Run("a password and a TOTP code", func(t *testing.T) {
		c := newClockedService(t)
		user := c.register(t, "totp@example.com")
		secret := c.enrol(t, user)
		_, tokens, err := c.svc.VerifyTOTP(ctx, user.ID, user.TenantID, c.code(t, secret))
		if err != nil {
			t.Fatal(err)
		}
		assertContext(t, tokens.AccessToken, []string{AMRPassword, AMROTP, AMRMFA}, c.now, at(c))
	})

	t.Run("a magic-link login", func(t *testing.T) {
		c := newClockedService(t)
		c.register(t, "link@example.com")
		token, err := c.svc.SendMagicLink(ctx, MagicLinkSendInput{Email: "link@example.com", TenantID: "t1"})
		if err != nil {
			t.Fatal(err)
		}
		_, tokens, err := c.svc.VerifyMagicLink(ctx, MagicLinkVerifyInput{Token: token})
		if err != nil {
			t.Fatal(err)
		}
		assertContext(t, tokens.AccessToken, []string{AMREmail}, c.now, nil)
	})

	t.Run("a password and a magic link", func(t *testing.T) {
		c := newClockedService(t)
		user := c.register(t, "link2fa@example.com")
		token, err := c.svc.SendMagicLink(ctx, MagicLinkSendInput{Email: "link2fa@example.com", TenantID: "t1"})
		if err != nil {
			t.Fatal(err)
		}
		_, tokens, err := c.svc.VerifyMagicLinkForUser(ctx, MagicLinkVerifyInput{Token: token}, user.ID)
		if err != nil {
			t.Fatal(err)
		}
		assertContext(t, tokens.AccessToken, []string{AMRPassword, AMREmail, AMRMFA}, c.now, at(c))
	})

	for _, tc := range []struct {
		name         string
		secondFactor bool
		want         []string
	}{
		{"an SMS login", false, []string{AMRSMS}},
		{"a password and an SMS code", true, []string{AMRPassword, AMRSMS, AMRMFA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newClockedService(t)
			user := c.register(t, "sms@example.com")
			if _, err := c.users.UpdatePhoneNumber(ctx, user.ID, user.TenantID, "+15555550100"); err != nil {
				t.Fatal(err)
			}
			code, err := c.svc.SendSMSCode(ctx, SMSCodeSendInput{UserID: user.ID, TenantID: user.TenantID})
			if err != nil {
				t.Fatal(err)
			}
			_, tokens, err := c.svc.VerifySMSCode(ctx, SMSCodeVerifyInput{UserID: user.ID, TenantID: user.TenantID, Code: code, SecondFactor: tc.secondFactor})
			if err != nil {
				t.Fatal(err)
			}
			var wantMFA *time.Time
			if tc.secondFactor {
				wantMFA = at(c)
			}
			assertContext(t, tokens.AccessToken, tc.want, c.now, wantMFA)
		})
	}

	t.Run("an OAuth login", func(t *testing.T) {
		c := newClockedService(t)
		oauth := NewOAuthService(OAuthProvider{Name: "acme", ClientID: "id", ClientSecret: "secret"})
		_, tokens, err := oauth.HandleCallback(ctx, c.svc, NewMemoryLinkedAccounts(), OAuthUserInfo{
			Provider: "acme", ProviderID: "acme-1", Email: "oauth@example.com",
		}, "t1", "")
		if err != nil {
			t.Fatal(err)
		}
		assertContext(t, tokens.AccessToken, []string{AMROAuth}, c.now, nil)
	})

	t.Run("a session whose proof is taken on trust", func(t *testing.T) {
		// IssueTokensForUser cannot say what proved the user, so it records no
		// method rather than a guess — and no second factor.
		c := newClockedService(t)
		user := c.register(t, "trust@example.com")
		_, tokens, err := c.svc.IssueTokensForUser(ctx, user.ID, user.TenantID)
		if err != nil {
			t.Fatal(err)
		}
		assertContext(t, tokens.AccessToken, nil, c.now, nil)
	})
}

// TestRefreshCarriesTheContextForward: a refresh mints from the session row,
// so amr, auth_time and mfa_at come through unchanged however much later it
// happens.
func TestRefreshCarriesTheContextForward(t *testing.T) {
	ctx := context.Background()
	c := newClockedService(t)
	user := c.register(t, "carry@example.com")
	secret := c.enrol(t, user)
	_, tokens, err := c.svc.VerifyTOTP(ctx, user.ID, user.TenantID, c.code(t, secret))
	if err != nil {
		t.Fatal(err)
	}
	opened := c.now

	c.advance(10 * time.Minute)
	refreshed, err := c.svc.Refresh(ctx, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	assertContext(t, refreshed.AccessToken, []string{AMRPassword, AMROTP, AMRMFA}, opened, &opened)

	// None of the three rides on the refresh token itself.
	for _, token := range []string{tokens.RefreshToken, refreshed.RefreshToken} {
		claims := payloadOf(t, token)
		for _, name := range []string{ClaimAMR, ClaimAuthTime, ClaimMFAAt} {
			if _, ok := claims[name]; ok {
				t.Errorf("a refresh token carries %s", name)
			}
		}
	}
}

// TestAuthenticationContextIsReserved: a claims hook — and a ClaimsWebhook
// behind one — can put none of the three on any token.
func TestAuthenticationContextIsReserved(t *testing.T) {
	ctx := context.Background()
	forged := map[string]any{
		ClaimAMR:      []any{"pwd", "otp", "mfa"},
		ClaimAuthTime: float64(1),
		ClaimMFAAt:    float64(4102444800), // 2100-01-01
		"plan":        "pro",
	}
	check := func(t *testing.T, c *clockedService) {
		t.Helper()
		c.register(t, "forger@example.com")
		_, tokens, err := c.svc.Login(ctx, LoginInput{Email: "forger@example.com", Password: "password1", TenantID: "t1"})
		if err != nil {
			t.Fatal(err)
		}
		// The access token says what the session recorded, not what the hook said.
		assertContext(t, tokens.AccessToken, []string{AMRPassword}, c.now, nil)
		if payloadOf(t, tokens.AccessToken)["plan"] != "pro" {
			t.Error("a non-reserved hook claim did not reach the token")
		}
		principal, err := c.svc.VerifyAccess(ctx, tokens.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		if !principal.MFAAt.IsZero() || !slices.Equal(principal.AuthMethods, []string{AMRPassword}) {
			t.Errorf("principal = %v / %v, want the session's context", principal.AuthMethods, principal.MFAAt)
		}
		// And none of the three on the other token types.
		temp, err := c.svc.IssueTempToken(ctx, User{ID: "usr_x", TenantID: "t1"})
		if err != nil {
			t.Fatal(err)
		}
		for name, token := range map[string]string{"refresh": tokens.RefreshToken, "step-up": temp} {
			claims := payloadOf(t, token)
			for _, claim := range []string{ClaimAMR, ClaimAuthTime, ClaimMFAAt} {
				if _, ok := claims[claim]; ok {
					t.Errorf("the %s token carries the hook's %s", name, claim)
				}
			}
		}
	}

	t.Run("a hand-written hook", func(t *testing.T) {
		check(t, newClockedService(t, func(cfg *Config) {
			cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) { return forged, nil }
		}))
	})

	t.Run("a claims webhook", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"claims": forged})
		}))
		defer srv.Close()
		hook, err := NewClaimsWebhook(srv.URL, "0123456789abcdef0123456789abcdef")
		if err != nil {
			t.Fatalf("NewClaimsWebhook: %v", err)
		}
		check(t, newClockedService(t, func(cfg *Config) { cfg.BuildTokenClaims = hook.Build }))
	})

	t.Run("UserFieldClaims refuses the names", func(t *testing.T) {
		for _, name := range []string{ClaimAMR, ClaimAuthTime, ClaimMFAAt} {
			if _, err := UserFieldClaims(map[string]string{name: "email"}); err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Errorf("UserFieldClaims(%q) = %v, want a reserved-name refusal", name, err)
			}
		}
	})
}

// TestVerifyAccessExposesTheContext: the principal the middleware hands a
// handler carries the three claims.
func TestVerifyAccessExposesTheContext(t *testing.T) {
	ctx := context.Background()
	c := newClockedService(t)
	user := c.register(t, "principal@example.com")
	secret := c.enrol(t, user)
	_, tokens, err := c.svc.VerifyTOTP(ctx, user.ID, user.TenantID, c.code(t, secret))
	if err != nil {
		t.Fatal(err)
	}
	principal, err := c.svc.VerifyAccess(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(principal.AuthMethods, []string{AMRPassword, AMROTP, AMRMFA}) {
		t.Errorf("AuthMethods = %v", principal.AuthMethods)
	}
	if !principal.AuthTime.Equal(c.now) || !principal.MFAAt.Equal(c.now) {
		t.Errorf("AuthTime = %v, MFAAt = %v, want %v for both", principal.AuthTime, principal.MFAAt, c.now)
	}
	// A user read from the store records no authentication.
	stored, err := c.svc.Authenticate(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if stored.AuthMethods != nil || !stored.MFAAt.IsZero() {
		t.Errorf("Authenticate filled the context from the store: %v %v", stored.AuthMethods, stored.MFAAt)
	}
}

// TestUserFromRS256ClaimsReadsTheContext: amr and auth_time are the OIDC
// claims, so a remote issuer's are read the same way; a mistyped claim is
// zero rather than half-read.
func TestUserFromRS256ClaimsReadsTheContext(t *testing.T) {
	user := UserFromRS256Claims(map[string]any{
		"sub": "usr_1", ClaimAMR: []any{"pwd", "otp"}, ClaimAuthTime: float64(1700000000), ClaimMFAAt: float64(1700000300),
	})
	if !slices.Equal(user.AuthMethods, []string{"pwd", "otp"}) || user.AuthTime.Unix() != 1700000000 || user.MFAAt.Unix() != 1700000300 {
		t.Fatalf("context = %v %v %v", user.AuthMethods, user.AuthTime, user.MFAAt)
	}
	bad := UserFromRS256Claims(map[string]any{
		ClaimAMR: []any{"pwd", 7}, ClaimAuthTime: "yesterday", ClaimMFAAt: float64(-5),
	})
	if bad.AuthMethods != nil || !bad.AuthTime.IsZero() || !bad.MFAAt.IsZero() {
		t.Fatalf("mistyped claims read as %v %v %v, want zero", bad.AuthMethods, bad.AuthTime, bad.MFAAt)
	}
}

// TestIDPTokensCarryTheContext: the code exchange records a password login and
// the refresh_token grant carries it forward; the IdP pair, which has no
// session, carries none — not even one a hook wrote.
func TestIDPTokensCarryTheContext(t *testing.T) {
	f := newIDPFixture(t)
	first := f.offlineGrant(t, "openid offline_access")
	access := first["access_token"].(string)
	claims := payloadOf(t, access)
	if got := amrOf(t, claims); !slices.Equal(got, []string{AMRPassword}) {
		t.Fatalf("code exchange amr = %v, want [pwd]", got)
	}
	if _, ok := claims[ClaimMFAAt]; ok {
		t.Fatal("the code exchange claims a second factor")
	}
	status, body, _ := f.refresh(t, first["refresh_token"].(string), idpTestClient)
	if status != http.StatusOK {
		t.Fatalf("refresh = %d %v", status, body)
	}
	refreshed := payloadOf(t, body["access_token"].(string))
	if got := amrOf(t, refreshed); !slices.Equal(got, []string{AMRPassword}) || refreshed[ClaimAuthTime] != claims[ClaimAuthTime] {
		t.Fatalf("refresh grant context = %v / %v, want the code exchange's", got, refreshed[ClaimAuthTime])
	}

	f.idp.authSvc.cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) {
		return map[string]any{
			ClaimMFAAt: float64(4102444800), ClaimAMR: []any{"mfa"}, ClaimAuthTime: float64(1),
			// The spellings a case-insensitive decoder folds onto the three.
			"MFA_AT": float64(4102444800), "Amr": []any{"mfa"}, "AUTH_TIME": float64(1),
			// Not the authentication context: kept, as the reference keeps it.
			"plan": "pro",
		}, nil
	}
	pair, err := f.idp.IssueIdPTokenPair(context.Background(), f.user)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{pair.AccessToken, pair.RefreshToken} {
		claims := payloadOf(t, token)
		for _, name := range []string{ClaimAMR, ClaimAuthTime, ClaimMFAAt, "MFA_AT", "Amr", "AUTH_TIME"} {
			if _, ok := claims[name]; ok {
				t.Errorf("the IdP pair carries the hook's %s", name)
			}
		}
		if claims["plan"] != "pro" {
			t.Error("the IdP pair lost a hook claim outside the authentication context")
		}
	}
}

// hiddenAuthStore is a session store without SessionAuthenticationStore.
type hiddenAuthStore struct {
	SessionStore
	SessionLookupStore
}

// TestStepUpTOTP pins the route's service half.
func TestStepUpTOTP(t *testing.T) {
	ctx := context.Background()

	login := func(t *testing.T, c *clockedService, email string) (User, string, AuthTokens) {
		t.Helper()
		user := c.register(t, email)
		secret := c.enrol(t, user)
		_, tokens, err := c.svc.VerifyTOTP(ctx, user.ID, user.TenantID, c.code(t, secret))
		if err != nil {
			t.Fatal(err)
		}
		return user, secret, tokens
	}

	t.Run("moves mfa_at and mints an access token alone", func(t *testing.T) {
		c := newClockedService(t)
		_, secret, tokens := login(t, c, "stepup@example.com")
		opened := c.now
		c.advance(10 * time.Minute) // within the access token's 15 minutes

		stepped, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, c.code(t, secret))
		if err != nil {
			t.Fatalf("StepUpTOTP: %v", err)
		}
		if stepped.RefreshToken != "" {
			t.Error("the step-up minted a refresh token; it must leave the session's alone")
		}
		now := c.now
		assertContext(t, stepped.AccessToken, []string{AMRPassword, AMROTP, AMRMFA}, opened, &now)
		if payloadOf(t, stepped.AccessToken)["sid"] != payloadOf(t, tokens.AccessToken)["sid"] {
			t.Error("the step-up token belongs to another session")
		}

		// The next refresh carries the new mfa_at forward, and the original
		// refresh token is still the session's.
		c.advance(time.Minute)
		refreshed, err := c.svc.Refresh(ctx, tokens.RefreshToken)
		if err != nil {
			t.Fatalf("Refresh after step-up: %v", err)
		}
		assertContext(t, refreshed.AccessToken, []string{AMRPassword, AMROTP, AMRMFA}, opened, &now)
	})

	t.Run("adds the factor to a session that had none", func(t *testing.T) {
		// A magic-link login opens a one-factor session for an account that
		// already holds TOTP: the factor predates the session, so a code of it
		// is a second factor the session had not presented.
		c := newClockedService(t)
		registered := c.register(t, "onefactor@example.com")
		secret := c.enrol(t, registered)
		// The stored row, as ConsumeMagicLink hands it over.
		user, err := c.users.GetUserByID(ctx, registered.ID, registered.TenantID)
		if err != nil {
			t.Fatal(err)
		}
		tokens, err := c.svc.CompleteMagicLinkLogin(ctx, user)
		if err != nil {
			t.Fatal(err)
		}
		opened := c.now
		assertContext(t, tokens.AccessToken, []string{AMREmail}, opened, nil)
		c.advance(time.Minute)
		stepped, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, c.code(t, secret))
		if err != nil {
			t.Fatal(err)
		}
		now := c.now
		assertContext(t, stepped.AccessToken, []string{AMREmail, AMROTP, AMRMFA}, opened, &now)
	})

	t.Run("refusals", func(t *testing.T) {
		c := newClockedService(t)
		user, secret, tokens := login(t, c, "refuse@example.com")

		if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, wrongCode(t, c, secret)); !errors.Is(err, ErrInvalidCode) {
			t.Errorf("wrong code = %v, want ErrInvalidCode", err)
		}
		if _, err := c.svc.StepUpTOTP(ctx, tokens.RefreshToken, c.code(t, secret)); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("a refresh token = %v, want ErrInvalidToken", err)
		}
		plain := c.register(t, "nofactor@example.com")
		_, plainTokens, _ := c.svc.Login(ctx, LoginInput{Email: plain.Email, Password: "password1", TenantID: "t1"})
		if _, err := c.svc.StepUpTOTP(ctx, plainTokens.AccessToken, "123456"); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("no factor enrolled = %v, want ErrInvalidCredentials", err)
		}

		// A logged-out session: refused, and still revoked afterwards — the
		// write cannot resurrect it.
		if err := c.svc.Logout(ctx, tokens.RefreshToken); err != nil {
			t.Fatal(err)
		}
		if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, c.code(t, secret)); !errors.Is(err, ErrSessionRevoked) {
			t.Errorf("revoked session = %v, want ErrSessionRevoked", err)
		}
		session, err := c.sessions.GetSessionByID(ctx, payloadOf(t, tokens.AccessToken)["sid"].(string))
		if err != nil || session.RevokedAt == nil {
			t.Fatalf("session after a refused step-up = %+v, %v, want it still revoked", session, err)
		}
		_ = user
	})

	t.Run("an expired session", func(t *testing.T) {
		c := newClockedService(t, func(cfg *Config) { cfg.AccessTokenTTL = 365 * 24 * time.Hour })
		_, secret, tokens := login(t, c, "expired@example.com")
		c.advance(c.svc.cfg.RefreshTokenTTL + time.Hour)
		if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, c.code(t, secret)); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("expired session = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("a rotation that happened first is kept", func(t *testing.T) {
		c := newClockedService(t)
		_, secret, tokens := login(t, c, "rotated@example.com")
		rotated, err := c.svc.Refresh(ctx, tokens.RefreshToken)
		if err != nil {
			t.Fatal(err)
		}
		// A step-up with the access token from before the rotation.
		if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, c.code(t, secret)); err != nil {
			t.Fatalf("StepUpTOTP: %v", err)
		}
		if _, err := c.svc.Refresh(ctx, tokens.RefreshToken); err == nil {
			t.Fatal("the step-up revived the rotated-out refresh token")
		}
		if _, err := c.svc.Refresh(ctx, rotated.RefreshToken); err != nil {
			t.Fatalf("the current refresh token stopped working: %v", err)
		}
	})

	t.Run("a store that cannot record the factor", func(t *testing.T) {
		c := newClockedService(t)
		_, secret, tokens := login(t, c, "nostore@example.com")
		c.svc.sessions = hiddenAuthStore{SessionStore: c.sessions, SessionLookupStore: c.sessions}
		if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, c.code(t, secret)); !errors.Is(err, ErrFeatureNotSupported) {
			t.Errorf("no SessionAuthenticationStore = %v, want ErrFeatureNotSupported", err)
		}
		if got := StepUpHTTPError(ErrFeatureNotSupported); got.Status != http.StatusNotImplemented {
			t.Errorf("StepUpHTTPError(ErrFeatureNotSupported) = %v, want 501", got)
		}
	})
}

// interleavingSessionStore runs between once after the step-up has read the
// session and before it writes: the window in which a concurrent refresh or
// logout lands. A step-up that wrote the row it read back would undo either.
type interleavingSessionStore struct {
	*MemorySessionStore
	between func()
}

func (s *interleavingSessionStore) GetSessionByID(ctx context.Context, sessionID string) (Session, error) {
	session, err := s.MemorySessionStore.GetSessionByID(ctx, sessionID)
	if s.between != nil {
		between := s.between
		s.between = nil
		between()
	}
	return session, err
}

// TestStepUpNeverUndoesAConcurrentWrite: a rotation or a logout that happens
// after the step-up read the session is kept, because the step-up writes only
// AuthMethods and MFAAt, atomically refusing a revoked row.
func TestStepUpNeverUndoesAConcurrentWrite(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*clockedService, *interleavingSessionStore, string, AuthTokens) {
		t.Helper()
		c := newClockedService(t)
		store := &interleavingSessionStore{MemorySessionStore: c.sessions}
		c.svc.sessions = store
		user := c.register(t, "interleave@example.com")
		secret := c.enrol(t, user)
		_, tokens, err := c.svc.VerifyTOTP(ctx, user.ID, user.TenantID, c.code(t, secret))
		if err != nil {
			t.Fatal(err)
		}
		return c, store, secret, tokens
	}

	t.Run("a rotation", func(t *testing.T) {
		c, store, secret, tokens := setup(t)
		var rotated AuthTokens
		store.between = func() {
			var err error
			if rotated, err = c.svc.Refresh(ctx, tokens.RefreshToken); err != nil {
				t.Fatalf("refresh between read and write: %v", err)
			}
		}
		if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, c.code(t, secret)); err != nil {
			t.Fatalf("StepUpTOTP: %v", err)
		}
		if _, err := c.svc.Refresh(ctx, tokens.RefreshToken); err == nil {
			t.Fatal("the rotated-out refresh token works again: the step-up wrote back the row it read")
		}
		if _, err := c.svc.Refresh(ctx, rotated.RefreshToken); err != nil {
			t.Fatalf("the current refresh token was lost: %v", err)
		}
	})

	t.Run("a logout", func(t *testing.T) {
		c, store, secret, tokens := setup(t)
		store.between = func() {
			if err := c.svc.Logout(ctx, tokens.RefreshToken); err != nil {
				t.Fatalf("logout between read and write: %v", err)
			}
		}
		if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, c.code(t, secret)); !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("StepUpTOTP across a logout = %v, want ErrSessionRevoked", err)
		}
		session, err := c.sessions.GetSessionByID(ctx, payloadOf(t, tokens.AccessToken)["sid"].(string))
		if err != nil || session.RevokedAt == nil {
			t.Fatalf("session = %+v, %v, want it still revoked", session, err)
		}
	})
}

func wrongCode(t *testing.T, c *clockedService, secret string) string {
	t.Helper()
	valid := map[string]bool{}
	for _, d := range []time.Duration{-TOTPPeriod, 0, TOTPPeriod} {
		code, _ := generateTOTPCode(secret, c.now.Add(d).Unix()/int64(TOTPPeriod/time.Second))
		valid[code] = true
	}
	for _, candidate := range []string{"000000", "111111", "222222"} {
		if !valid[candidate] {
			return candidate
		}
	}
	t.Fatal("no wrong code")
	return ""
}

// TestRecordSecondFactor pins MemorySessionStore's half of the seam.
func TestRecordSecondFactor(t *testing.T) {
	ctx := context.Background()
	store := NewMemorySessionStore()
	created := time.Now().Truncate(time.Second)
	if _, err := store.CreateSession(ctx, Session{ID: "ses_1", UserID: "usr_1", RefreshTokenHash: "h1", CreatedAt: created, AuthMethods: []string{AMRPassword}}); err != nil {
		t.Fatal(err)
	}
	at := created.Add(time.Minute)
	updated, err := store.RecordSecondFactor(ctx, "ses_1", []string{AMRPassword, AMROTP, AMRMFA}, at)
	if err != nil {
		t.Fatal(err)
	}
	if updated.RefreshTokenHash != "h1" || !updated.CreatedAt.Equal(created) || updated.MFAAt == nil || !updated.MFAAt.Equal(at) ||
		!slices.Equal(updated.AuthMethods, []string{AMRPassword, AMROTP, AMRMFA}) {
		t.Fatalf("updated = %+v", updated)
	}
	if _, err := store.RecordSecondFactor(ctx, "ses_missing", nil, at); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("missing session = %v, want ErrSessionNotFound", err)
	}
	if err := store.RevokeSessionByID(ctx, "ses_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordSecondFactor(ctx, "ses_1", nil, at.Add(time.Minute)); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("revoked session = %v, want ErrSessionRevoked", err)
	}
}

// TestAdminLoginNeverCarriesASecondFactor: the console's own login skips the
// second factor by design (a registered deviation), so its token must never
// claim one — not even for an account that has TOTP enrolled.
func TestAdminLoginNeverCarriesASecondFactor(t *testing.T) {
	c := newClockedService(t, func(cfg *Config) {
		cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) {
			return map[string]any{ClaimMFAAt: float64(4102444800), ClaimAMR: []any{"mfa"}}, nil
		}
	})
	// The console's login looks the address up in the empty tenant.
	user, _, err := c.svc.Register(context.Background(), RegisterInput{Email: "admin@example.com", Password: "password1"})
	if err != nil {
		t.Fatal(err)
	}
	c.enrol(t, user)
	if err := c.users.UpdateIsAdmin(context.Background(), user.ID, user.TenantID, true); err != nil {
		t.Fatal(err)
	}
	a := &Auth{service: c.svc}
	cfg := DefaultHTTPConfig()
	cfg.Admin = AdminOptions{Enabled: true, AccessPolicy: AdminIsAdminFlag()}

	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(`{"email":"admin@example.com","password":"password1"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.AdminHandler(cfg).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin login = %d %s", rec.Code, rec.Body.String())
	}
	var token string
	for _, cookie := range rec.Result().Cookies() {
		if strings.HasSuffix(cookie.Name, AccessTokenCookieName) && cookie.Value != "" {
			token = cookie.Value
		}
	}
	if token == "" {
		t.Fatal("the admin login set no token")
	}
	claims := payloadOf(t, token)
	for _, name := range []string{ClaimAMR, ClaimAuthTime, ClaimMFAAt} {
		if _, ok := claims[name]; ok {
			t.Errorf("the admin token carries %s: %v", name, claims)
		}
	}
}

// TestStepUpRefusesAFactorNewerThanTheSession pins the fix for the step-up
// bypass: whoever holds a session's access token can enrol a TOTP factor
// through the voluntary routes, so a code of a factor enrolled after the
// session opened proves nothing the token did not, and must not move mfa_at.
// Each case is a session's token in the wrong hands — the factor enrolled
// through it is the holder's own.
func TestStepUpRefusesAFactorNewerThanTheSession(t *testing.T) {
	ctx := context.Background()
	refused := func(t *testing.T, c *clockedService, token, code string) {
		t.Helper()
		sid := payloadOf(t, token)["sid"].(string)
		before, err := c.sessions.GetSessionByID(ctx, sid)
		if err != nil {
			t.Fatal(err)
		}
		c.advance(time.Second) // so that a write of mfa_at would show
		_, err = c.svc.StepUpTOTP(ctx, token, code)
		if !errors.Is(err, ErrReauthenticationRequired) {
			t.Fatalf("StepUpTOTP = %v, want ErrReauthenticationRequired", err)
		}
		if got := StepUpHTTPError(err); got != HTTPErrReauthenticationRequired || got.Status != http.StatusForbidden {
			t.Fatalf("StepUpHTTPError = %+v, want 403 %s", got, CodeReauthenticationRequired)
		}
		// Nothing was recorded on the session, and no budget was spent: the
		// code was never worth a guess.
		after, err := c.sessions.GetSessionByID(ctx, sid)
		if err != nil {
			t.Fatal(err)
		}
		if (before.MFAAt == nil) != (after.MFAAt == nil) || (after.MFAAt != nil && !after.MFAAt.Equal(*before.MFAAt)) ||
			!slices.Equal(before.AuthMethods, after.AuthMethods) {
			t.Fatalf("the refused step-up wrote the session: %v/%v -> %v/%v", before.AuthMethods, before.MFAAt, after.AuthMethods, after.MFAAt)
		}
		if after.StepUpAttempts != before.StepUpAttempts || after.RevokedAt != nil {
			t.Fatalf("StepUpAttempts = %d (was %d), revoked %v: a refusal before the code costs nothing",
				after.StepUpAttempts, before.StepUpAttempts, after.RevokedAt)
		}
	}
	mfaLogin := func(t *testing.T, c *clockedService, email string) (User, string, AuthTokens) {
		t.Helper()
		user := c.register(t, email)
		secret := c.enrol(t, user)
		_, tokens, err := c.svc.VerifyTOTP(ctx, user.ID, user.TenantID, c.code(t, secret))
		if err != nil {
			t.Fatal(err)
		}
		return user, secret, tokens
	}

	t.Run("a factor swapped in after an MFA login", func(t *testing.T) {
		c := newClockedService(t)
		user, original, tokens := mfaLogin(t, c, "swap@example.com")
		c.advance(10 * time.Minute)
		swapped := c.enrol(t, user) // the voluntary verify-setup, on the token alone
		refused(t, c, tokens.AccessToken, c.code(t, swapped))
		// The owner's own factor is gone from the account, so its code is no
		// better; the session is not bound to the new one either way.
		refused(t, c, tokens.AccessToken, c.code(t, original))
	})

	t.Run("a first factor enrolled on a password session", func(t *testing.T) {
		c := newClockedService(t)
		user := c.register(t, "first@example.com")
		_, tokens, err := c.svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: "t1"})
		if err != nil {
			t.Fatal(err)
		}
		secret := c.enrol(t, user)
		refused(t, c, tokens.AccessToken, c.code(t, secret))

		// The remedy: a fresh sign-in with the password and the new code opens
		// a session bound to the factor, which then steps up.
		_, fresh, err := c.svc.VerifyTOTP(ctx, user.ID, user.TenantID, c.code(t, secret))
		if err != nil {
			t.Fatal(err)
		}
		c.advance(time.Minute)
		if _, err := c.svc.StepUpTOTP(ctx, fresh.AccessToken, c.code(t, secret)); err != nil {
			t.Fatalf("a session opened after the enrolment = %v, want it to step up", err)
		}
	})

	t.Run("a factor disabled and enrolled again", func(t *testing.T) {
		c := newClockedService(t)
		user, _, tokens := mfaLogin(t, c, "reenrol@example.com")
		if err := c.svc.DisableTOTP(ctx, user.ID, user.TenantID); err != nil {
			t.Fatal(err)
		}
		again := c.enrol(t, user)
		refused(t, c, tokens.AccessToken, c.code(t, again))
	})

	t.Run("a session whose opener could not say how its user was proved", func(t *testing.T) {
		c := newClockedService(t)
		user := c.register(t, "trusted@example.com")
		secret := c.enrol(t, user)
		_, tokens, err := c.svc.IssueTokensForUser(ctx, user.ID, user.TenantID)
		if err != nil {
			t.Fatal(err)
		}
		// Otherwise its step-up would claim mfa with no known first factor.
		refused(t, c, tokens.AccessToken, c.code(t, secret))
	})

	t.Run("a store that did not keep the binding", func(t *testing.T) {
		c := newClockedService(t)
		_, secret, tokens := mfaLogin(t, c, "lost@example.com")
		sid := payloadOf(t, tokens.AccessToken)["sid"].(string)
		session, err := c.sessions.GetSessionByID(ctx, sid)
		if err != nil {
			t.Fatal(err)
		}
		session.TOTPBinding = ""
		if err := c.sessions.UpdateSession(ctx, session); err != nil {
			t.Fatal(err)
		}
		refused(t, c, tokens.AccessToken, c.code(t, secret))
	})

	t.Run("a rotation of Config.Secret ends the binding", func(t *testing.T) {
		c := newClockedService(t)
		_, secret, tokens := mfaLogin(t, c, "rotate@example.com")
		if got := c.svc.totpBinding(User{IsTOTPEnabled: true, TOTPSecret: secret}); got == "" || strings.Contains(got, secret) {
			t.Fatalf("binding %q is empty or carries the secret", got)
		}
		sid := payloadOf(t, tokens.AccessToken)["sid"].(string)
		session, _ := c.sessions.GetSessionByID(ctx, sid)
		c.svc.cfg.Secret = strings.Repeat("r", 40)
		if secureEqual(session.TOTPBinding, c.svc.totpBinding(User{IsTOTPEnabled: true, TOTPSecret: secret})) {
			t.Fatal("the binding does not depend on Config.Secret")
		}
	})
}

// TestStepUpFailureBudget: wrong codes are counted on the session, an accepted
// code resets the count, and the wrong code that reaches StepUpFailureLimit
// revokes the session — after which neither the step-up nor the refresh token
// works, whatever is presented.
func TestStepUpFailureBudget(t *testing.T) {
	ctx := context.Background()
	login := func(t *testing.T, c *clockedService, email string) (string, AuthTokens) {
		t.Helper()
		user := c.register(t, email)
		secret := c.enrol(t, user)
		_, tokens, err := c.svc.VerifyTOTP(ctx, user.ID, user.TenantID, c.code(t, secret))
		if err != nil {
			t.Fatal(err)
		}
		return secret, tokens
	}
	sessionOf := func(t *testing.T, c *clockedService, tokens AuthTokens) Session {
		t.Helper()
		session, err := c.sessions.GetSessionByID(ctx, payloadOf(t, tokens.AccessToken)["sid"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return session
	}

	t.Run("an accepted code resets the count", func(t *testing.T) {
		c := newClockedService(t)
		secret, tokens := login(t, c, "budget-reset@example.com")
		for i := 1; i < StepUpFailureLimit; i++ {
			if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, wrongCode(t, c, secret)); !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("wrong code %d = %v, want ErrInvalidCode", i, err)
			}
		}
		if got := sessionOf(t, c, tokens).StepUpAttempts; got != StepUpFailureLimit-1 {
			t.Fatalf("StepUpAttempts = %d, want %d", got, StepUpFailureLimit-1)
		}
		if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, c.code(t, secret)); err != nil {
			t.Fatalf("the right code after %d wrong ones = %v", StepUpFailureLimit-1, err)
		}
		if got := sessionOf(t, c, tokens).StepUpAttempts; got != 0 {
			t.Fatalf("StepUpAttempts after an accepted code = %d, want 0", got)
		}
		// A fresh budget: StepUpFailureLimit-1 more wrong codes do not end it.
		for i := 1; i < StepUpFailureLimit; i++ {
			if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, wrongCode(t, c, secret)); !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("wrong code %d after the reset = %v, want ErrInvalidCode", i, err)
			}
		}
	})

	t.Run("the last wrong code revokes the session", func(t *testing.T) {
		c := newClockedService(t)
		secret, tokens := login(t, c, "budget-revoke@example.com")
		for i := 1; i < StepUpFailureLimit; i++ {
			if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, wrongCode(t, c, secret)); !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("wrong code %d = %v, want ErrInvalidCode", i, err)
			}
		}
		_, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, wrongCode(t, c, secret))
		if !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("wrong code %d = %v, want ErrSessionRevoked", StepUpFailureLimit, err)
		}
		if got := StepUpHTTPError(err); got != HTTPErrSessionRevoked {
			t.Fatalf("StepUpHTTPError = %+v, want 401 SESSION_REVOKED", got)
		}
		if session := sessionOf(t, c, tokens); session.RevokedAt == nil {
			t.Fatal("the session is not revoked")
		}
		if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, c.code(t, secret)); !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("the right code after the budget = %v, want ErrSessionRevoked", err)
		}
		if _, err := c.svc.Refresh(ctx, tokens.RefreshToken); err == nil {
			t.Fatal("the refresh token outlived the revocation")
		}
	})

	t.Run("a store without the seam is still refused before any code", func(t *testing.T) {
		c := newClockedService(t)
		secret, tokens := login(t, c, "budget-nostore@example.com")
		c.svc.sessions = hiddenAuthStore{SessionStore: c.sessions, SessionLookupStore: c.sessions}
		if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, wrongCode(t, c, secret)); !errors.Is(err, ErrFeatureNotSupported) {
			t.Fatalf("no SessionAuthenticationStore = %v, want ErrFeatureNotSupported", err)
		}
	})
}

// TestRecordStepUpAttempt pins MemorySessionStore's half of the budget: the
// count goes up one per call, and the call that takes it past the limit
// revokes the session in the same step.
func TestRecordStepUpAttempt(t *testing.T) {
	ctx := context.Background()
	store := NewMemorySessionStore()
	created := time.Now().Truncate(time.Second)
	if _, err := store.CreateSession(ctx, Session{ID: "ses_1", UserID: "usr_1", RefreshTokenHash: "h1", CreatedAt: created}); err != nil {
		t.Fatal(err)
	}
	at := created.Add(time.Minute)
	for want := 1; want <= 3; want++ {
		updated, err := store.RecordStepUpAttempt(ctx, "ses_1", 3, at)
		if err != nil {
			t.Fatal(err)
		}
		if updated.StepUpAttempts != want || updated.RevokedAt != nil || updated.RefreshTokenHash != "h1" {
			t.Fatalf("attempt %d: %+v", want, updated)
		}
	}
	revoked, err := store.RecordStepUpAttempt(ctx, "ses_1", 3, at)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.StepUpAttempts != 4 || revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(at) {
		t.Fatalf("the attempt past the limit = %+v, want the session revoked at %v", revoked, at)
	}
	if _, err := store.RecordStepUpAttempt(ctx, "ses_1", 3, at); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("a revoked session = %v, want ErrSessionRevoked", err)
	}
	if _, err := store.RecordStepUpAttempt(ctx, "ses_missing", 3, at); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("a missing session = %v, want ErrSessionNotFound", err)
	}

	// RecordSecondFactor resets the count.
	if _, err := store.CreateSession(ctx, Session{ID: "ses_2", UserID: "usr_1", RefreshTokenHash: "h2", CreatedAt: created}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordStepUpAttempt(ctx, "ses_2", 3, at); err != nil {
		t.Fatal(err)
	}
	reset, err := store.RecordSecondFactor(ctx, "ses_2", []string{AMRPassword, AMROTP, AMRMFA}, at)
	if err != nil {
		t.Fatal(err)
	}
	if reset.StepUpAttempts != 0 {
		t.Fatalf("StepUpAttempts after RecordSecondFactor = %d, want 0", reset.StepUpAttempts)
	}
}

// concurrentAttemptsStore runs before once at the start of the next
// RecordStepUpAttempt: the attempts of concurrent requests that got their
// counts first.
type concurrentAttemptsStore struct {
	*MemorySessionStore
	before func()
}

func (s *concurrentAttemptsStore) RecordStepUpAttempt(ctx context.Context, sessionID string, limit int, at time.Time) (Session, error) {
	if s.before != nil {
		before := s.before
		s.before = nil
		before()
	}
	return s.MemorySessionStore.RecordStepUpAttempt(ctx, sessionID, limit, at)
}

// TestStepUpCountsTheAttemptBeforeTheCode: when concurrent requests have
// already taken every try the budget holds, the next one is refused without
// its code being checked — even the right code — so a burst of parallel
// guesses gets StepUpFailureLimit checks and no more.
func TestStepUpCountsTheAttemptBeforeTheCode(t *testing.T) {
	ctx := context.Background()
	c := newClockedService(t)
	store := &concurrentAttemptsStore{MemorySessionStore: c.sessions}
	c.svc.sessions = store
	user := c.register(t, "burst@example.com")
	secret := c.enrol(t, user)
	_, tokens, err := c.svc.VerifyTOTP(ctx, user.ID, user.TenantID, c.code(t, secret))
	if err != nil {
		t.Fatal(err)
	}
	sid := payloadOf(t, tokens.AccessToken)["sid"].(string)
	store.before = func() {
		for i := 0; i < StepUpFailureLimit; i++ {
			if _, err := c.sessions.RecordStepUpAttempt(ctx, sid, StepUpFailureLimit, c.now); err != nil {
				t.Fatalf("concurrent attempt %d: %v", i+1, err)
			}
		}
	}
	if _, err := c.svc.StepUpTOTP(ctx, tokens.AccessToken, c.code(t, secret)); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("the right code past the budget = %v, want ErrSessionRevoked without a check", err)
	}
	if session, _ := c.sessions.GetSessionByID(ctx, sid); session.RevokedAt == nil {
		t.Fatal("the attempt past the budget did not revoke the session")
	}
}

// TestReservedClaimSpellingsAreDeleted: a hook cannot get a reserved claim
// past a case-insensitive decoder by spelling it differently. encoding/json
// fills a field tagged "mfa_at" from "MFA_AT" when no exact member is present,
// and a field tagged "sid" from a later "ſid" even when one is; mintToken
// therefore deletes every spelling strings.EqualFold matches before it writes
// the reserved claims, and the IdP pair strips the authentication context the
// same way.
func TestReservedClaimSpellingsAreDeleted(t *testing.T) {
	ctx := context.Background()
	spellings := map[string]any{
		"MFA_AT":    float64(4102444800),
		"Amr":       []any{"pwd", "otp", "mfa"},
		"Auth_Time": float64(1),
		"\u017fid":  "ses_forged", // ſid: folds to sid, and sorts after it
		"TYP":       "refresh",
		"Exp":       float64(4102444800),
		"plan":      "pro",
	}
	c := newClockedService(t, func(cfg *Config) {
		cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) { return spellings, nil }
	})
	c.register(t, "spelling@example.com")
	_, tokens, err := c.svc.Login(ctx, LoginInput{Email: "spelling@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{"access": tokens.AccessToken, "refresh": tokens.RefreshToken} {
		claims := payloadOf(t, token)
		for spelling := range spellings {
			if _, ok := claims[spelling]; ok && spelling != "plan" {
				t.Errorf("the %s token carries the hook's %q", name, spelling)
			}
		}
		if claims["plan"] != "pro" {
			t.Errorf("the %s token lost a non-reserved hook claim", name)
		}
	}

	// What a struct decoder — the shape of golang-jwt's custom claims — reads
	// off the access token: the session's own sid and no second factor.
	var decoded struct {
		Sid   string `json:"sid"`
		Typ   string `json:"typ"`
		MFAAt *int64 `json:"mfa_at"`
	}
	raw, err := json.Marshal(payloadOf(t, tokens.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.MFAAt != nil {
		t.Errorf("a struct decoder reads mfa_at = %d off a password-only session", *decoded.MFAAt)
	}
	if decoded.Sid == "ses_forged" || decoded.Typ != "access" {
		t.Errorf("a struct decoder reads sid %q, typ %q", decoded.Sid, decoded.Typ)
	}
	if _, err := c.svc.VerifyAccess(ctx, tokens.AccessToken); err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if _, err := c.svc.Refresh(ctx, tokens.RefreshToken); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
}
