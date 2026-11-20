package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// enrolmentService is a deployment that demands a second factor of everyone and
// can deliver none: no magic-link and no SMS sender, so an account without TOTP
// has no method at all and the login answers 2FA_SETUP_REQUIRED.
func enrolmentService(t *testing.T, store UserStore) *Service {
	t.Helper()
	cfg := testConfig(testSecret)
	cfg.SendMagicLink = nil
	cfg.SendSMSCode = nil
	cfg.Require2FA = true
	if store == nil {
		store = NewMemoryUserStore()
	}
	svc, err := NewService(cfg, store, NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

// setupChallenge registers email and logs in, returning the user and the
// enrolment token of the 2FA_SETUP_REQUIRED challenge.
func setupChallenge(t *testing.T, svc *Service, email string) (User, string) {
	t.Helper()
	ctx := context.Background()
	user, tokens, err := svc.Register(ctx, RegisterInput{Email: email, Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if tokens.AccessToken != "" {
		t.Fatal("registration under Require2FA opened a session")
	}
	result, err := svc.LoginWithChallenge(ctx, LoginInput{Email: email, Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.Challenge == nil || !result.Challenge.SetupRequired {
		t.Fatalf("login = %+v, want a setup-required challenge", result)
	}
	if result.Tokens.AccessToken != "" {
		t.Fatal("the setup-required login opened a session")
	}
	return user, result.Challenge.TempToken
}

func codeFor(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, ok := generateTOTPCode(secret, at.Unix()/int64(TOTPPeriod/time.Second))
	if !ok {
		t.Fatal("generateTOTPCode failed")
	}
	return code
}

// TestLoginWithChallenge_SetupRequiredMintsAnEnrolmentToken: the token the
// 2FA_SETUP_REQUIRED branch hands out is an enrolment token and only that, and
// the challenge branch still hands out the step-up token.
func TestLoginWithChallenge_SetupRequiredMintsAnEnrolmentToken(t *testing.T) {
	svc := enrolmentService(t, nil)
	user, token := setupChallenge(t, svc, "setup@example.com")

	got, err := svc.VerifyEnrolmentToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyEnrolmentToken: %v", err)
	}
	if got.ID != user.ID {
		t.Fatalf("enrolment token names %q, want %q", got.ID, user.ID)
	}
	if _, err := svc.VerifyTempToken(token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyTempToken(enrolment token) = %v, want ErrInvalidToken: it must not complete a step-up", err)
	}

	// A user with a factor is challenged, and that token is not an enrolment
	// token: it is held after the password alone and must not enrol a
	// replacement factor.
	plain := NewMemoryUserStore()
	other := enrolmentService(t, plain)
	enrolled := enrolTOTPUser(t, other, "enrolled@example.com")
	result, err := other.LoginWithChallenge(context.Background(), LoginInput{Email: enrolled.Email, Password: "password1", TenantID: "t1"})
	if err != nil || result.Challenge == nil || result.Challenge.SetupRequired {
		t.Fatalf("login of an enrolled user = %+v, %v, want a step-up challenge", result, err)
	}
	if _, err := other.VerifyEnrolmentToken(context.Background(), result.Challenge.TempToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyEnrolmentToken(step-up token) = %v, want ErrInvalidToken", err)
	}
}

// TestEnrolmentTokenIsNoOtherCredential: every verifier in the package that
// reads an access, step-up or refresh token refuses the enrolment token.
func TestEnrolmentTokenIsNoOtherCredential(t *testing.T) {
	svc := enrolmentService(t, nil)
	_, token := setupChallenge(t, svc, "nothingelse@example.com")
	ctx := context.Background()

	if _, err := svc.VerifyAccess(ctx, token); err == nil {
		t.Error("VerifyAccess accepted the enrolment token")
	}
	if _, err := svc.Authenticate(ctx, token); err == nil {
		t.Error("Authenticate accepted the enrolment token")
	}
	if _, err := svc.Me(ctx, token); err == nil {
		t.Error("Me accepted the enrolment token")
	}
	if _, err := svc.Refresh(ctx, token); err == nil {
		t.Error("Refresh accepted the enrolment token")
	}
	if err := svc.LogoutAccessToken(ctx, token); err == nil {
		t.Error("LogoutAccessToken accepted the enrolment token")
	}
	if _, err := svc.verifyLocalAccessToken(token); err == nil {
		t.Error("the resource-server cookie path accepted the enrolment token")
	}

	a := &Auth{service: svc}
	cfg := DefaultHTTPConfig()
	cfg.Admin = AdminOptions{Enabled: true, AccessPolicy: AdminIsAdminFlag()}
	if _, ok := a.AdminGuard(cfg).verifyToken(token); ok {
		t.Error("the admin guard accepted the enrolment token")
	}
	req := httptest.NewRequest(http.MethodGet, "/rs", nil)
	req.AddCookie(&http.Cookie{Name: hostCookiePrefix + AccessTokenCookieName, Value: token})
	if _, _, ok := ResourceServerPrincipal(req, a, nil, ""); ok {
		t.Error("ResourceServerPrincipal accepted the enrolment token as a cookie")
	}
}

// TestVerifyEnrolmentToken_Refusals: the token is honoured only while the
// login would still answer 2FA_SETUP_REQUIRED for its user.
func TestVerifyEnrolmentToken_Refusals(t *testing.T) {
	ctx := context.Background()

	t.Run("past its lifetime", func(t *testing.T) {
		svc := enrolmentService(t, nil)
		_, token := setupChallenge(t, svc, "expiry@example.com")
		later := time.Now().Add(svc.cfg.TempTokenTTL + svc.cfg.ClockSkew + time.Second)
		svc.now = func() time.Time { return later }
		if _, err := svc.VerifyEnrolmentToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("VerifyEnrolmentToken after expiry = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("once a factor exists", func(t *testing.T) {
		svc := enrolmentService(t, nil)
		user, token := setupChallenge(t, svc, "factor@example.com")
		secret, _ := generateTOTPSecret()
		if err := svc.VerifyTOTPSetup(ctx, user.ID, user.TenantID, secret, codeFor(t, secret, time.Now())); err != nil {
			t.Fatalf("enrol: %v", err)
		}
		if _, err := svc.VerifyEnrolmentToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("VerifyEnrolmentToken after enrolment = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("once the policy is lifted", func(t *testing.T) {
		store := NewMemoryUserStore()
		cfg := testConfig(testSecret)
		cfg.SendMagicLink, cfg.SendSMSCode = nil, nil
		svc, err := NewService(cfg, store, NewMemorySessionStore())
		if err != nil {
			t.Fatal(err)
		}
		user, _, err := svc.Register(ctx, RegisterInput{Email: "lifted@example.com", Password: "password1", TenantID: "t1"})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.UpdateRequire2FA(ctx, user.ID, user.TenantID, true); err != nil {
			t.Fatal(err)
		}
		result, err := svc.LoginWithChallenge(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: "t1"})
		if err != nil || result.Challenge == nil || !result.Challenge.SetupRequired {
			t.Fatalf("login under the per-user flag = %+v, %v, want setup required", result, err)
		}
		if _, err := svc.VerifyEnrolmentToken(ctx, result.Challenge.TempToken); err != nil {
			t.Fatalf("VerifyEnrolmentToken while the flag is set = %v", err)
		}
		if err := store.UpdateRequire2FA(ctx, user.ID, user.TenantID, false); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.VerifyEnrolmentToken(ctx, result.Challenge.TempToken); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("VerifyEnrolmentToken after the flag was cleared = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("a user the store no longer has", func(t *testing.T) {
		store := NewMemoryUserStore()
		svc := enrolmentService(t, store)
		user, token := setupChallenge(t, svc, "gone@example.com")
		if err := store.DeleteUser(ctx, user.ID, user.TenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.VerifyEnrolmentToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("VerifyEnrolmentToken for a deleted user = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("the other token types", func(t *testing.T) {
		svc := enrolmentService(t, nil)
		user, _ := setupChallenge(t, svc, "types@example.com")
		temp, err := svc.IssueTempToken(ctx, user)
		if err != nil {
			t.Fatal(err)
		}
		access, _, err := svc.issueToken(ctx, user, "ses_x", "access", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		refresh, _, err := svc.issueToken(ctx, user, "ses_x", "refresh", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		for name, token := range map[string]string{"step-up": temp, "access": access, "refresh": refresh} {
			if _, err := svc.VerifyEnrolmentToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("VerifyEnrolmentToken(%s token) = %v, want ErrInvalidToken", name, err)
			}
		}
	})
}

// failingByIDStore fails the id lookup with an error that is not
// ErrUserNotFound: a store outage.
type failingByIDStore struct{ *MemoryUserStore }

var errStoreDown = errors.New("store is down")

func (failingByIDStore) GetUserByID(context.Context, string, string) (User, error) {
	return User{}, errStoreDown
}

// TestTOTPEnrolmentCaller_StoreFailureIsAServerError: an outage while the
// enrolment token's user is re-read is a 500, not a credential the client is
// told to throw away.
func TestTOTPEnrolmentCaller_StoreFailureIsAServerError(t *testing.T) {
	store := failingByIDStore{NewMemoryUserStore()}
	svc := enrolmentService(t, store)
	_, token := setupChallenge(t, svc, "outage@example.com")
	a := &Auth{service: svc}

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/setup", nil)
	_, herr, ok := a.TOTPEnrolmentCaller(context.Background(), req, token)
	if ok || herr != HTTPErrInternal {
		t.Fatalf("TOTPEnrolmentCaller during an outage = %v, %v, want the generic 500", herr, ok)
	}
	bearer := httptest.NewRequest(http.MethodPost, "/auth/2fa/setup", nil)
	bearer.Header.Set("Authorization", "Bearer "+token)
	if _, herr, ok := a.TOTPEnrolmentCaller(context.Background(), bearer, ""); ok || herr != HTTPErrInternal {
		t.Fatalf("TOTPEnrolmentCaller(bearer) during an outage = %v, %v, want the generic 500", herr, ok)
	}
}

// TestTOTPEnrolmentCaller_BodyTokenWins: a request that carries an enrolment
// token in its body is a forced enrolment whatever access credential rides
// along, and a bad one is refused rather than fallen back from.
func TestTOTPEnrolmentCaller_BodyTokenWins(t *testing.T) {
	svc := enrolmentService(t, nil)
	user, token := setupChallenge(t, svc, "precedence@example.com")
	other, _, err := svc.Register(context.Background(), RegisterInput{Email: "bystander@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	access, _, err := svc.issueToken(context.Background(), other, "ses_b", "access", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a := &Auth{service: svc}

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/setup", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	caller, _, ok := a.TOTPEnrolmentCaller(context.Background(), req, token)
	if !ok || !caller.Forced || caller.User.ID != user.ID {
		t.Fatalf("caller = %+v, %v, want the enrolment token's user, forced", caller, ok)
	}
	if _, herr, ok := a.TOTPEnrolmentCaller(context.Background(), req, "garbage"); ok || herr != HTTPErrInvalidTempToken {
		t.Fatalf("a bad body token beside a good access token = %v, %v, want INVALID_TEMP_TOKEN", herr, ok)
	}
	// Without a body token the access credential decides, as it always has.
	caller, _, ok = a.TOTPEnrolmentCaller(context.Background(), req, "")
	if !ok || caller.Forced || caller.User.ID != other.ID {
		t.Fatalf("caller = %+v, %v, want the access token's user, voluntary", caller, ok)
	}
}

// TestCompleteTOTPEnrolment opens the session the login could not, raises the
// two events the voluntary enrolment and the step-up login raise, and mints a
// session that says the factor is enrolled.
func TestCompleteTOTPEnrolment(t *testing.T) {
	h := newEventHarness(t, func(cfg *Config) {
		cfg.Require2FA = true
		cfg.SendMagicLink, cfg.SendSMSCode = nil, nil
	})
	user, _ := h.register(t, "complete@example.com")
	result, err := h.svc.LoginWithChallenge(h.ctx, LoginInput{Email: user.Email, Password: harnessPassword, TenantID: harnessTenant})
	if err != nil || result.Challenge == nil || !result.Challenge.SetupRequired {
		t.Fatalf("login = %+v, %v, want setup required", result, err)
	}
	h.reset()

	secret, _ := generateTOTPSecret()
	_, tokens, err := h.svc.CompleteTOTPEnrolment(h.ctx, user.ID, user.TenantID, secret, h.totpCode(t, secret))
	if err != nil {
		t.Fatalf("CompleteTOTPEnrolment: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("tokens = %+v, want a session", tokens)
	}
	principal, err := h.svc.VerifyAccess(h.ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if !principal.IsTOTPEnabled {
		t.Error("the session's access token says isTotpEnabled false after enrolment")
	}

	got := h.events()
	if len(got) != 2 {
		t.Fatalf("published %v, want identity.user.2fa.enabled then identity.auth.login.success", eventNamesOf(got))
	}
	if got[0].Name != EventUser2FAEnabled || got[0].UserID != user.ID {
		t.Errorf("first event = %+v, want %s for %s", got[0], EventUser2FAEnabled, user.ID)
	}
	login := got[1]
	if login.Name != EventAuthLoginSuccess || login.UserID != user.ID || login.SessionID == "" {
		t.Errorf("second event = %+v, want %s with a session", login, EventAuthLoginSuccess)
	}
	if login.Data["method"] != loginMethodTOTP {
		t.Errorf("login method = %v, want %q, the /2fa/verify payload", login.Data["method"], loginMethodTOTP)
	}
	for _, ev := range got {
		if ev.CorrelationID != harnessCorrelationID || ev.IP != harnessIP || ev.UserAgent != harnessUserAgent {
			t.Errorf("%s lost its request provenance: %+v", ev.Name, ev)
		}
	}
}

// TestCompleteTOTPEnrolment_RefusesAnAccountWithAFactor: called directly, it
// cannot replace the factor an account already holds.
func TestCompleteTOTPEnrolment_RefusesAnAccountWithAFactor(t *testing.T) {
	store := NewMemoryUserStore()
	svc := enrolmentService(t, store)
	user := enrolTOTPUser(t, svc, "keeps@example.com")
	before, err := store.GetUserByID(context.Background(), user.ID, user.TenantID)
	if err != nil {
		t.Fatal(err)
	}

	secret, _ := generateTOTPSecret()
	_, tokens, err := svc.CompleteTOTPEnrolment(context.Background(), user.ID, user.TenantID, secret, codeFor(t, secret, time.Now()))
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("CompleteTOTPEnrolment for an enrolled user = %v, want ErrInvalidToken", err)
	}
	if tokens.AccessToken != "" {
		t.Fatal("a refused enrolment opened a session")
	}
	after, _ := store.GetUserByID(context.Background(), user.ID, user.TenantID)
	if after.TOTPSecret != before.TOTPSecret {
		t.Fatal("a refused enrolment replaced the stored TOTP secret")
	}
	if got := TOTPEnrolmentHTTPError(err); got != HTTPErrInvalidTempToken {
		t.Errorf("TOTPEnrolmentHTTPError = %v, want INVALID_TEMP_TOKEN", got)
	}
}

// TestCompleteTOTPEnrolment_RefusesASecretThatIsNoFactor: an empty secret
// decodes to an empty HMAC key, so its codes verify and anybody can compute
// them. The forced path refuses it, and any key below RFC 4226's 128 bits,
// before it stores anything or opens a session; the token stays usable.
func TestCompleteTOTPEnrolment_RefusesASecretThatIsNoFactor(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryUserStore()
	svc := enrolmentService(t, store)
	user, token := setupChallenge(t, svc, "weak@example.com")

	short := "MFRGGZDF" // base32 of five bytes
	for name, secret := range map[string]string{"empty": "", "short": short, "not base32": "not-a-secret!"} {
		t.Run(name, func(t *testing.T) {
			code, ok := generateTOTPCode(secret, time.Now().Unix()/int64(TOTPPeriod/time.Second))
			if !ok {
				code = "000000"
			}
			_, tokens, err := svc.CompleteTOTPEnrolment(ctx, user.ID, user.TenantID, secret, code)
			if !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("CompleteTOTPEnrolment(%q) = %v, want ErrInvalidCode", secret, err)
			}
			if tokens.AccessToken != "" {
				t.Fatal("a refused enrolment opened a session")
			}
			stored, _ := store.GetUserByID(ctx, user.ID, user.TenantID)
			if stored.IsTOTPEnabled {
				t.Fatal("a refused enrolment enabled TOTP")
			}
		})
	}
	if _, err := svc.VerifyEnrolmentToken(ctx, token); err != nil {
		t.Fatalf("the enrolment token died with a refused secret: %v", err)
	}
	if !totpSecretIsStrong(mustSecret(t)) {
		t.Fatal("a secret /2fa/setup mints is below the floor the forced path enforces")
	}
}

func mustSecret(t *testing.T) string {
	t.Helper()
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	return secret
}
