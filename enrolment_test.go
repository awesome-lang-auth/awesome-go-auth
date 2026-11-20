package auth

import (
	"context"
	"encoding/base32"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	cfg.EnrolOnLogin = true
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
		cfg.EnrolOnLogin = true
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
		cfg.EnrolOnLogin = true
		cfg.SendMagicLink, cfg.SendSMSCode = nil, nil
	})
	user, _ := h.register(t, "complete@example.com")
	result, err := h.svc.LoginWithChallenge(h.ctx, LoginInput{Email: user.Email, Password: harnessPassword, TenantID: harnessTenant})
	if err != nil || result.Challenge == nil || !result.Challenge.SetupRequired {
		t.Fatalf("login = %+v, %v, want setup required", result, err)
	}
	h.reset()

	setup, err := h.svc.NewForcedTOTPEnrolment(h.ctx, result.Challenge.TempToken)
	if err != nil {
		t.Fatalf("NewForcedTOTPEnrolment: %v", err)
	}
	secret := setup.Secret
	_, tokens, err := h.svc.CompleteTOTPEnrolment(h.ctx, result.Challenge.TempToken, secret, h.totpCode(t, secret))
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

	// An enrolment token for the account, as one minted before its factor
	// existed would be.
	token, err := svc.issueEnrolmentToken(context.Background(), before)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := svc.parseToken(token, tokenTypeEnrolment)
	if err != nil {
		t.Fatal(err)
	}
	secret := svc.forcedEnrolmentSecret(claims)
	_, tokens, err := svc.CompleteTOTPEnrolment(context.Background(), token, secret, codeFor(t, secret, time.Now()))
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

// TestCompleteTOTPEnrolment_AcceptsOnlyTheMintedSecret: the session a forced
// enrolment opens claims the factor, so the factor must be the one the server
// minted for the token at /2fa/setup. Every other secret — an empty one, which
// decodes to an empty HMAC key; keys long enough but known to everybody, such
// as all zeros or the RFC 6238 test vector; a strong secret of the client's
// own; the secret another token minted — is refused before anything is stored
// or opened, and the token stays usable.
func TestCompleteTOTPEnrolment_AcceptsOnlyTheMintedSecret(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryUserStore()
	svc := enrolmentService(t, store)
	user, token := setupChallenge(t, svc, "weak@example.com")

	// A second login mints a second token, with a secret of its own.
	second, err := svc.LoginWithChallenge(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: "t1"})
	if err != nil || second.Challenge == nil {
		t.Fatalf("second login = %+v, %v", second, err)
	}
	otherSetup, err := svc.NewForcedTOTPEnrolment(ctx, second.Challenge.TempToken)
	if err != nil {
		t.Fatal(err)
	}

	refused := map[string]string{
		"empty":               "",
		"short":               "MFRGGZDF", // base32 of five bytes
		"not base32":          "not-a-secret!",
		"all zeros, 128 bits": "AAAAAAAAAAAAAAAAAAAAAAAAAA",
		"the RFC 6238 key":    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", // "12345678901234567890"
		"the client's own":    mustSecret(t),
		"another token's":     otherSetup.Secret,
	}
	for name, secret := range refused {
		t.Run(name, func(t *testing.T) {
			code, ok := generateTOTPCode(secret, time.Now().Unix()/int64(TOTPPeriod/time.Second))
			if !ok {
				code = "000000"
			}
			_, tokens, err := svc.CompleteTOTPEnrolment(ctx, token, secret, code)
			if !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("CompleteTOTPEnrolment(%q) = %v, want ErrInvalidCode", secret, err)
			}
			if got := TOTPEnrolmentHTTPError(err); got != HTTPErrInvalidTOTPSetupCode {
				t.Fatalf("TOTPEnrolmentHTTPError = %+v, want 400 Invalid TOTP code", got)
			}
			if tokens.AccessToken != "" {
				t.Fatal("a refused enrolment opened a session")
			}
			stored, _ := store.GetUserByID(ctx, user.ID, user.TenantID)
			if stored.IsTOTPEnabled || stored.TOTPSecret != "" {
				t.Fatal("a refused enrolment stored a factor")
			}
		})
	}
	if _, err := svc.VerifyEnrolmentToken(ctx, token); err != nil {
		t.Fatalf("the enrolment token died with a refused secret: %v", err)
	}

	// The minted secret: deterministic per token, a 160-bit base32 key, and
	// the one that completes.
	setup, err := svc.NewForcedTOTPEnrolment(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := svc.NewForcedTOTPEnrolment(ctx, token)
	if setup.Secret != again.Secret || setup.Secret == otherSetup.Secret {
		t.Fatalf("minted secrets: %q, %q, other token %q; want one per token, stable", setup.Secret, again.Secret, otherSetup.Secret)
	}
	if !strings.Contains(setup.OTPAuthURL, "secret="+setup.Secret) {
		t.Fatalf("the provisioning URI %q does not carry the minted secret", setup.OTPAuthURL)
	}
	if key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret); err != nil || len(key) != forcedEnrolmentSecretBytes {
		t.Fatalf("minted secret %q decodes to %d bytes (%v), want %d", setup.Secret, len(key), err, forcedEnrolmentSecretBytes)
	}
	_, tokens, err := svc.CompleteTOTPEnrolment(ctx, token, setup.Secret, codeFor(t, setup.Secret, time.Now()))
	if err != nil || tokens.AccessToken == "" {
		t.Fatalf("the minted secret = %+v, %v, want a session", tokens, err)
	}
	stored, _ := store.GetUserByID(ctx, user.ID, user.TenantID)
	if stored.TOTPSecret != setup.Secret {
		t.Fatal("the stored factor is not the minted secret")
	}
}

// TestEnrolmentToken_BoundToTheCredential: a token minted before the account's
// password changed is dead, so a reset after a suspected compromise takes the
// outstanding tokens with it; and a token whose cred claim was dropped is no
// token at all.
func TestEnrolmentToken_BoundToTheCredential(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryUserStore()
	svc := enrolmentService(t, store)
	user, token := setupChallenge(t, svc, "reset@example.com")
	setup, err := svc.NewForcedTOTPEnrolment(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	// The password changes, as a reset or POST /change-password changes it.
	hash, err := hashPassword("a-new-password-1", svc.cfg.BcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdatePassword(ctx, user.ID, user.TenantID, hash); err != nil {
		t.Fatalf("update password: %v", err)
	}
	if _, err := svc.VerifyEnrolmentToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyEnrolmentToken after a password change = %v, want ErrInvalidToken", err)
	}
	if _, _, err := svc.CompleteTOTPEnrolment(ctx, token, setup.Secret, codeFor(t, setup.Secret, time.Now())); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("CompleteTOTPEnrolment after a password change = %v, want ErrInvalidToken", err)
	}
	if stored, _ := store.GetUserByID(ctx, user.ID, user.TenantID); stored.IsTOTPEnabled {
		t.Fatal("a token minted before the password change enrolled a factor")
	}
	// A login with the new password mints a token that works.
	result, err := svc.LoginWithChallenge(ctx, LoginInput{Email: user.Email, Password: "a-new-password-1", TenantID: "t1"})
	if err != nil || result.Challenge == nil {
		t.Fatalf("login with the new password = %+v, %v", result, err)
	}
	if _, err := svc.VerifyEnrolmentToken(ctx, result.Challenge.TempToken); err != nil {
		t.Fatalf("a token minted after the change = %v", err)
	}

	// The claim is required: the same token without it does not verify.
	stripped := map[string]any{}
	for k, v := range decodeSegment(t, mustSegment(t, result.Challenge.TempToken, 1)) {
		if k != "cred" {
			stripped[k] = v
		}
	}
	forged, err := buildHS256JWT(stripped, svc.cfg.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyEnrolmentToken(ctx, forged); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("an enrolment token without its cred claim = %v, want ErrInvalidToken", err)
	}
}

// TestEnrolmentToken_ReappliesTheEmailGate: the login's email-verification
// gate is applied again on every use, so an address that stopped counting as
// verified since the token was minted stops the enrolment too.
func TestEnrolmentToken_ReappliesTheEmailGate(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryUserStore()
	svc := enrolmentService(t, store)
	user, token := setupChallenge(t, svc, "gate@example.com")
	if err := store.MarkEmailVerified(ctx, user.ID, user.TenantID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyEnrolmentToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyEnrolmentToken for an address the login would refuse = %v, want ErrInvalidToken", err)
	}
}

// TestEnrolOnLoginOff_KeepsTheEarlierBehaviour: with Config.EnrolOnLogin off,
// the default, the 2FA_SETUP_REQUIRED answer carries the step-up token it
// always did, no enrolment token is honoured, and the enrolment gate is the
// access middleware exactly — a body tempToken is ignored.
func TestEnrolOnLoginOff_KeepsTheEarlierBehaviour(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(testSecret)
	cfg.SendMagicLink, cfg.SendSMSCode = nil, nil
	cfg.Require2FA = true
	if cfg.EnrolOnLogin {
		t.Fatal("EnrolOnLogin is on by default")
	}
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Register(ctx, RegisterInput{Email: "off@example.com", Password: "password1", TenantID: "t1"}); err != nil {
		t.Fatal(err)
	}
	result, err := svc.LoginWithChallenge(ctx, LoginInput{Email: "off@example.com", Password: "password1", TenantID: "t1"})
	if err != nil || result.Challenge == nil || !result.Challenge.SetupRequired || len(result.Challenge.Methods) != 0 {
		t.Fatalf("login = %+v, %v, want the setup-required challenge", result, err)
	}
	token := result.Challenge.TempToken
	if _, err := svc.VerifyTempToken(token); err != nil {
		t.Fatalf("the setup-required token is not the step-up token: %v", err)
	}
	if _, err := svc.VerifyEnrolmentToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyEnrolmentToken with the option off = %v, want ErrInvalidToken", err)
	}
	// Not even a genuine enrolment token, minted while the option was on.
	user, _ := svc.users.GetUserByEmail(ctx, "off@example.com", "t1")
	genuine, err := svc.issueEnrolmentToken(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyEnrolmentToken(ctx, genuine); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("an enrolment token with the option off = %v, want ErrInvalidToken", err)
	}

	a := &Auth{service: svc}
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/setup", nil)
	if _, herr, ok := a.TOTPEnrolmentCaller(ctx, req, genuine); ok || herr != HTTPErrNoAccessToken {
		t.Fatalf("a body tempToken with the option off = %v, %v, want 403 No access token provided", herr, ok)
	}
	req.Header.Set("Authorization", "Bearer "+genuine)
	if _, herr, ok := a.TOTPEnrolmentCaller(ctx, req, ""); ok || herr != HTTPErrInvalidAccessToken {
		t.Fatalf("a bearer enrolment token with the option off = %v, %v, want 403 Invalid or expired access token", herr, ok)
	}
}

// TestTOTPEnrolmentCaller_RefusesTheTokenAsACookie: the enrolment token is
// never set as a cookie, and presented as the access cookie it is what any
// other bad access token is.
func TestTOTPEnrolmentCaller_RefusesTheTokenAsACookie(t *testing.T) {
	svc := enrolmentService(t, nil)
	_, token := setupChallenge(t, svc, "cookie@example.com")
	a := &Auth{service: svc}
	for _, name := range []string{AccessTokenCookieName, hostCookiePrefix + AccessTokenCookieName} {
		req := httptest.NewRequest(http.MethodPost, "/auth/2fa/setup", nil)
		req.AddCookie(&http.Cookie{Name: name, Value: token})
		if caller, herr, ok := a.TOTPEnrolmentCaller(context.Background(), req, ""); ok || herr != HTTPErrInvalidAccessToken {
			t.Fatalf("the enrolment token as cookie %s = %+v, %v, %v, want 403 Invalid or expired access token", name, caller, herr, ok)
		}
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
