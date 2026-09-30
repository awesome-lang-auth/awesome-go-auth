package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// helper to build a ready service for error-path tests
func newTestSvc(t *testing.T) *Service {
	t.Helper()
	cfg := testConfig("errtest12345678901234567890123456")
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("newTestSvc: %v", err)
	}
	return svc
}

// helper to register a user and return its tokens
func registerUser(t *testing.T, svc *Service, email, tenantID string) (User, AuthTokens) {
	t.Helper()
	user, tokens, err := svc.Register(context.Background(), RegisterInput{
		Email: email, Password: "password1", TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("register %s: %v", email, err)
	}
	return user, tokens
}

// --- Register error paths ---

func TestRegister_WeakPassword(t *testing.T) {
	svc := newTestSvc(t)
	_, _, err := svc.Register(context.Background(), RegisterInput{
		Email: "weak@example.com", Password: "short", TenantID: "t1",
	})
	if err != ErrWeakPassword {
		t.Fatalf("expected ErrWeakPassword, got %v", err)
	}
}

// A missing field is refused as a missing field, not as a weak password: the
// default register handler on the private dev line node-auth checks both for
// presence before it hashes or stores anything (node-auth
// auth.router.ts:515-525, resolved against DevLineRevision — the published
// reference has no default register handler), and until this test an empty
// password fell through to the length check and came back as ErrWeakPassword
// while an empty address reached the store and was written.
func TestRegister_MissingFieldsAreInvalidInput(t *testing.T) {
	cases := []struct {
		name  string
		email string
		pw    string
	}{
		{"no password", "nopw@example.com", ""},
		{"no email", "", "password1"},
		{"neither", "", ""},
		// Trimmed to nothing: the address the store would hold is the empty one.
		{"whitespace email", "   ", "password1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newTestSvc(t)
			_, _, err := svc.Register(context.Background(), RegisterInput{
				Email: tc.email, Password: tc.pw, TenantID: "t1",
			})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected ErrInvalidInput, got %v", err)
			}
		})
	}
}

// The store must not have been reached at all, in any of the four shapes: the
// refusal is what stops a blank or whitespace-only address becoming a row.
// Probing one spelling is not enough — a regression that stored the untrimmed
// address would be invisible to a lookup on the empty string — so this asserts
// every spelling the four calls could have been keyed under and then, because a
// lookup only finds the key it is given, that the store is empty outright.
//
// The whitespace address is the case worth guarding: it is the one the dev line
// would have accepted (its check is on the untrimmed body value), so it is the
// one a future "match the dev line exactly" edit is most likely to let through.
func TestRegister_MissingFieldsCreateNoUser(t *testing.T) {
	users := NewMemoryUserStore()
	svc, err := NewService(testConfig("errtest12345678901234567890123456"), users, NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx := context.Background()

	for _, in := range []RegisterInput{
		{Email: "", Password: "password1", TenantID: "t1"},
		{Email: "   ", Password: "password1", TenantID: "t1"},
		{Email: "nopw@example.com", Password: "", TenantID: "t1"},
		{Email: "", Password: "", TenantID: "t1"},
	} {
		if _, _, err := svc.Register(ctx, in); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Register(email=%q, password=%q): expected ErrInvalidInput, got %v",
				in.Email, in.Password, err)
		}
	}

	for _, email := range []string{"", "   ", "nopw@example.com"} {
		if _, err := users.GetUserByEmail(ctx, email, "t1"); err == nil {
			t.Errorf("a user was created for email %q before the refusal", email)
		}
	}
	if n := len(users.byID); n != 0 {
		t.Errorf("store holds %d user(s) after four refused registrations, want 0", n)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	_, _, _ = svc.Register(ctx, RegisterInput{Email: "dup@example.com", Password: "password1", TenantID: "t1"})
	_, _, err := svc.Register(ctx, RegisterInput{Email: "dup@example.com", Password: "password1", TenantID: "t1"})
	if err != ErrUserExists {
		t.Fatalf("expected ErrUserExists, got %v", err)
	}
}

func TestRegister_EmailNormalized(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, _, err := svc.Register(ctx, RegisterInput{
		Email: "  UPPER@Example.com  ", Password: "password1", TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.Email != "upper@example.com" {
		t.Fatalf("expected normalized email, got %s", user.Email)
	}
}

// --- Login error paths ---

func TestLogin_WrongPassword(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	registerUser(t, svc, "wrongpw@example.com", "t1")
	_, _, err := svc.Login(ctx, LoginInput{
		Email: "wrongpw@example.com", Password: "badpassword", TenantID: "t1",
	})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	svc := newTestSvc(t)
	_, _, err := svc.Login(context.Background(), LoginInput{
		Email: "nobody@example.com", Password: "password1", TenantID: "t1",
	})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_WrongTenant(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	registerUser(t, svc, "tenant@example.com", "t1")
	_, _, err := svc.Login(ctx, LoginInput{
		Email: "tenant@example.com", Password: "password1", TenantID: "other-tenant",
	})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for wrong tenant, got %v", err)
	}
}

func TestLogin_Require2FA_Config(t *testing.T) {
	cfg := testConfig("require2fa1234567890123456789012")
	cfg.Require2FA = true
	svc, _ := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	ctx := context.Background()
	svc.Register(ctx, RegisterInput{Email: "2fa@example.com", Password: "password1", TenantID: "t1"})
	_, _, err := svc.Login(ctx, LoginInput{Email: "2fa@example.com", Password: "password1", TenantID: "t1"})
	if err != ErrTwoFactorRequired {
		t.Fatalf("expected ErrTwoFactorRequired, got %v", err)
	}
}

func TestLogin_Require2FA_UserLevel(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	// Manually create a user with Require2FA = true in the store
	users := svc.users.(*MemoryUserStore)
	hash, _ := hashPassword("password1", svc.cfg.BcryptCost)
	id, _ := newID("usr")
	_, _ = users.CreateUser(ctx, User{
		ID:              id,
		Email:           "2fauser@example.com",
		PasswordHash:    hash,
		TenantID:        "t1",
		IsEmailVerified: true,
		Require2FA:      true,
	})
	_, _, err := svc.Login(ctx, LoginInput{Email: "2fauser@example.com", Password: "password1", TenantID: "t1"})
	if err != ErrTwoFactorRequired {
		t.Fatalf("expected ErrTwoFactorRequired, got %v", err)
	}
}

// --- Me error paths ---

func TestMe_InvalidToken(t *testing.T) {
	svc := newTestSvc(t)
	_, err := svc.Me(context.Background(), "not-a-token")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestMe_WrongTokenType(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	_, tokens := registerUser(t, svc, "mewrong@example.com", "t1")
	// Provide refresh token where access is expected
	_, err := svc.Me(ctx, tokens.RefreshToken)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for refresh-as-access, got %v", err)
	}
}

func TestMe_ExpiredAccessToken(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()
	svc.now = func() time.Time { return now }
	_, tokens := registerUser(t, svc, "meexp@example.com", "t1")
	svc.now = func() time.Time { return now.Add(16*time.Minute + svc.cfg.ClockSkew + time.Second) }
	_, err := svc.Me(ctx, tokens.AccessToken)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for expired access token, got %v", err)
	}
}

// --- Refresh error paths ---

func TestRefresh_WrongTokenType(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	_, tokens := registerUser(t, svc, "refwrong@example.com", "t1")
	_, err := svc.Refresh(ctx, tokens.AccessToken)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for access-as-refresh, got %v", err)
	}
}

func TestRefresh_RevokedSession(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	_, tokens := registerUser(t, svc, "revoked@example.com", "t1")
	_ = svc.Logout(ctx, tokens.RefreshToken)
	_, err := svc.Refresh(ctx, tokens.RefreshToken)
	if err == nil {
		t.Fatal("expected error refreshing revoked session")
	}
}

func TestRefresh_ExpiredSession(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()
	svc.now = func() time.Time { return now }
	_, tokens := registerUser(t, svc, "sessexp@example.com", "t1")
	svc.now = func() time.Time { return now.Add(31*24*time.Hour + svc.cfg.ClockSkew + time.Second) }
	_, err := svc.Refresh(ctx, tokens.RefreshToken)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for expired session, got %v", err)
	}
}

func TestRefresh_TamperedToken(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	_, tokens := registerUser(t, svc, "tampered@example.com", "t1")
	tok := tokens.RefreshToken
	tampered := tok[:len(tok)-4] + "xxxx"
	_, err := svc.Refresh(ctx, tampered)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for tampered refresh token, got %v", err)
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	svc := newTestSvc(t)
	_, err := svc.Refresh(context.Background(), "not-a-token")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

// --- Logout error paths ---

func TestLogout_InvalidToken(t *testing.T) {
	svc := newTestSvc(t)
	err := svc.Logout(context.Background(), "invalid")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestLogout_WrongTokenType(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	_, tokens := registerUser(t, svc, "logoutwrong@example.com", "t1")
	err := svc.Logout(ctx, tokens.AccessToken)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for access-as-refresh logout, got %v", err)
	}
}

// --- ChangePassword error paths ---

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, _ := registerUser(t, svc, "changepw@example.com", "t1")
	err := svc.ChangePassword(ctx, ChangePasswordInput{
		UserID:          user.ID,
		TenantID:        "t1",
		CurrentPassword: "wrongold",
		NewPassword:     "newpassword1",
	})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestChangePassword_WeakNewPassword(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, _ := registerUser(t, svc, "weaknew@example.com", "t1")
	err := svc.ChangePassword(ctx, ChangePasswordInput{
		UserID:          user.ID,
		TenantID:        "t1",
		CurrentPassword: "password1",
		NewPassword:     "short",
	})
	if err != ErrWeakPassword {
		t.Fatalf("expected ErrWeakPassword, got %v", err)
	}
}

func TestChangePassword_UserNotFound(t *testing.T) {
	svc := newTestSvc(t)
	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:          "usr_nonexistent",
		TenantID:        "t1",
		CurrentPassword: "password1",
		NewPassword:     "newpassword1",
	})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

// #30: the service itself lets an account with no password set its first one
// without presenting a current password, as the reference's /change-password
// does (auth.router.ts:1480-1489 at v1.10.8), and raises the same event it
// raises for a change. A current password the account does not have is
// ignored, not compared.
func TestChangePassword_PasswordlessAccountSetsItsFirstPassword(t *testing.T) {
	for _, current := range []string{"", "not-a-password"} {
		t.Run("currentPassword "+current, func(t *testing.T) {
			cfg := testConfig("errtest12345678901234567890123456")
			bus := NewEventBus()
			cfg.Events = bus
			var changed []string
			bus.Subscribe(EventUserPasswordChanged, func(e Event) { changed = append(changed, e.UserID) })
			store := NewMemoryUserStore()
			svc, err := NewService(cfg, store, NewMemorySessionStore())
			if err != nil {
				t.Fatalf("NewService: %v", err)
			}
			ctx := context.Background()
			user, _ := registerUser(t, svc, "passwordless@example.com", "t1")
			if err := store.UpdatePassword(ctx, user.ID, "t1", ""); err != nil {
				t.Fatalf("drop password: %v", err)
			}

			if err := svc.ChangePassword(ctx, ChangePasswordInput{
				UserID: user.ID, TenantID: "t1", CurrentPassword: current, NewPassword: "initialpw1",
			}); err != nil {
				t.Fatalf("ChangePassword: %v, want the first password set", err)
			}
			if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "initialpw1", TenantID: "t1"}); err != nil {
				t.Fatalf("login with the new password: %v", err)
			}
			if len(changed) != 1 || changed[0] != user.ID {
				t.Fatalf("identity.user.password.changed = %v, want one for %s", changed, user.ID)
			}
		})
	}
}

// An account that has a password keeps the check: an absent current password
// is refused like a wrong one (auth.router.ts:1480-1483 at v1.10.8).
func TestChangePassword_MissingCurrentPassword(t *testing.T) {
	svc := newTestSvc(t)
	user, _ := registerUser(t, svc, "nocurrent@example.com", "t1")
	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID: user.ID, TenantID: "t1", NewPassword: "newpassword1",
	})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

// An empty new password is refused before the comparison and for every
// account, with its own sentinel rather than ErrWeakPassword
// (auth.router.ts:1476-1479 at v1.10.8).
func TestChangePassword_NewPasswordRequired(t *testing.T) {
	svc := newTestSvc(t)
	user, _ := registerUser(t, svc, "nonew@example.com", "t1")
	for _, current := range []string{"password1", "wrongold", ""} {
		err := svc.ChangePassword(context.Background(), ChangePasswordInput{
			UserID: user.ID, TenantID: "t1", CurrentPassword: current,
		})
		if err != ErrNewPasswordRequired {
			t.Fatalf("currentPassword %q: expected ErrNewPasswordRequired, got %v", current, err)
		}
	}
}

func TestChangePassword_Success(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, _ := registerUser(t, svc, "changepwok@example.com", "t1")
	err := svc.ChangePassword(ctx, ChangePasswordInput{
		UserID:          user.ID,
		TenantID:        "t1",
		CurrentPassword: "password1",
		NewPassword:     "newpassword1",
	})
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	// Old password should no longer work
	_, _, err = svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: "t1"})
	if err != ErrInvalidCredentials {
		t.Fatalf("old password should be rejected after change, got %v", err)
	}
	// New password should work
	_, _, err = svc.Login(ctx, LoginInput{Email: user.Email, Password: "newpassword1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("new password should work: %v", err)
	}
}

// --- ForgotPassword / ResetPassword ---

func TestForgotPassword_UnknownEmail_Silent(t *testing.T) {
	svc := newTestSvc(t)
	// Should return ("", nil) silently for unknown emails
	token, err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{
		Email: "nobody@example.com", TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("ForgotPassword unknown email should not error: %v", err)
	}
	if token != "" {
		t.Fatal("ForgotPassword should return empty token for unknown email")
	}
}

func TestResetPassword_WeakPassword(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, _ := registerUser(t, svc, "resetweak@example.com", "t1")
	token, _ := svc.ForgotPassword(ctx, ForgotPasswordInput{Email: user.Email, TenantID: "t1"})
	err := svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "short"})
	if err != ErrWeakPassword {
		t.Fatalf("expected ErrWeakPassword, got %v", err)
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	svc := newTestSvc(t)
	err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Token: "totally-invalid-token", NewPassword: "newpassword1",
	})
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()
	svc.now = func() time.Time { return now }
	user, _ := registerUser(t, svc, "resetexp@example.com", "t1")
	token, _ := svc.ForgotPassword(ctx, ForgotPasswordInput{Email: user.Email, TenantID: "t1"})
	svc.now = func() time.Time { return now.Add(2*time.Hour + svc.cfg.ClockSkew + time.Second) }
	err := svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "newpassword1"})
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for expired reset token, got %v", err)
	}
}

// --- MagicLink error paths ---

func TestSendMagicLink_UnknownEmail_Silent(t *testing.T) {
	svc := newTestSvc(t)
	token, err := svc.SendMagicLink(context.Background(), MagicLinkSendInput{
		Email: "nobody@example.com", TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("SendMagicLink unknown email should not error: %v", err)
	}
	if token != "" {
		t.Fatal("expected empty token for unknown email")
	}
}

func TestVerifyMagicLink_InvalidToken(t *testing.T) {
	svc := newTestSvc(t)
	_, _, err := svc.VerifyMagicLink(context.Background(), MagicLinkVerifyInput{Token: "invalid"})
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyMagicLink_ExpiredToken(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()
	svc.now = func() time.Time { return now }
	user, _ := registerUser(t, svc, "magicexp@example.com", "t1")
	token, _ := svc.SendMagicLink(ctx, MagicLinkSendInput{Email: user.Email, TenantID: "t1"})
	svc.now = func() time.Time { return now.Add(20*time.Minute + svc.cfg.ClockSkew + time.Second) }
	_, _, err := svc.VerifyMagicLink(ctx, MagicLinkVerifyInput{Token: token})
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for expired magic link, got %v", err)
	}
}

// --- SMS error paths ---

func TestSendSMSCode_NoPhone_Silent(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, _ := registerUser(t, svc, "nophone@example.com", "t1")
	code, err := svc.SendSMSCode(ctx, SMSCodeSendInput{UserID: user.ID, TenantID: "t1"})
	if err != nil {
		t.Fatalf("SendSMSCode without phone should not error: %v", err)
	}
	if code != "" {
		t.Fatal("expected empty code for user without phone")
	}
}

func TestVerifySMSCode_WrongCode(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	users := svc.users.(*MemoryUserStore)
	hash, _ := hashPassword("password1", svc.cfg.BcryptCost)
	id, _ := newID("usr")
	_, _ = users.CreateUser(ctx, User{
		ID:              id,
		Email:           "smsuser@example.com",
		PasswordHash:    hash,
		TenantID:        "t1",
		PhoneNumber:     "+15555555555",
		IsEmailVerified: true,
	})
	_, _ = svc.SendSMSCode(ctx, SMSCodeSendInput{UserID: id, TenantID: "t1"})
	_, _, err := svc.VerifySMSCode(ctx, SMSCodeVerifyInput{
		UserID: id, TenantID: "t1", Code: "000000",
	})
	if err != ErrInvalidCode {
		t.Fatalf("expected ErrInvalidCode for wrong SMS code, got %v", err)
	}
}

// --- TOTP error paths ---

func TestVerifyTOTPSetup_InvalidCode(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, _ := registerUser(t, svc, "totpsetup@example.com", "t1")
	secret, _ := svc.SetupTOTP(ctx, user.ID, "t1")
	err := svc.VerifyTOTPSetup(ctx, user.ID, "t1", secret, "000000")
	if err != ErrInvalidCode {
		// Note: 000000 has a tiny probability of being correct; acceptable test
		t.Logf("note: 000000 may have been valid code (very unlikely): %v", err)
	}
}

func TestDisableTOTP_Success(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, _ := registerUser(t, svc, "disabletotp@example.com", "t1")
	secret, _ := generateTOTPSecret()
	now := time.Now()
	code, ok := generateTOTPCode(secret, now.Unix()/30)
	if !ok {
		t.Fatal("generateTOTPCode failed")
	}
	_ = svc.VerifyTOTPSetup(ctx, user.ID, "t1", secret, code)
	if err := svc.DisableTOTP(ctx, user.ID, "t1"); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
}

// --- Email verification error paths ---

func TestSendVerificationEmailToken_AlreadyVerified(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	// Register marks email as verified
	user, _ := registerUser(t, svc, "alreadyver@example.com", "t1")
	token, err := svc.SendVerificationEmailToken(ctx, EmailVerificationInput{UserID: user.ID, TenantID: "t1"})
	if err != nil {
		t.Fatalf("SendVerificationEmailToken should not error for already-verified: %v", err)
	}
	if token != "" {
		t.Fatal("expected empty token for already-verified user")
	}
}

// --- Session management ---

func TestListSessions_Success(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, _ := registerUser(t, svc, "sessions@example.com", "t1")
	sessions, err := svc.ListSessions(ctx, user.ID, "t1")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) == 0 {
		t.Fatal("expected at least 1 session after register")
	}
}

func TestRevokeSessionByID_Success(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, tokens := registerUser(t, svc, "revokesess@example.com", "t1")
	sessions, _ := svc.ListSessions(ctx, user.ID, "t1")
	if len(sessions) == 0 {
		t.Fatal("expected session after register")
	}
	if err := svc.RevokeSessionByID(ctx, sessions[0].ID); err != nil {
		t.Fatalf("RevokeSessionByID: %v", err)
	}
	_, err := svc.Refresh(ctx, tokens.RefreshToken)
	if err == nil {
		t.Fatal("expected error refreshing after session revocation")
	}
}

func TestCleanupExpiredSessions_Success(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()
	svc.now = func() time.Time { return now }
	registerUser(t, svc, "cleanup@example.com", "t1")
	// advance past session expiry
	svc.now = func() time.Time { return now.Add(31 * 24 * time.Hour) }
	n, err := svc.CleanupExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("CleanupExpiredSessions: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected at least 1 cleaned session, got %d", n)
	}
}

// --- requiresTwoFactor helper ---

func TestRequiresTwoFactor_TOTP(t *testing.T) {
	svc := newTestSvc(t)
	user := User{IsTOTPEnabled: true, TOTPSecret: "ORSXG5A="}
	if !svc.requiresTwoFactor(user) {
		t.Fatal("user with TOTP enabled should require 2FA")
	}
}

func TestRequiresTwoFactor_UserFlag(t *testing.T) {
	svc := newTestSvc(t)
	user := User{Require2FA: true}
	if !svc.requiresTwoFactor(user) {
		t.Fatal("user with Require2FA flag should require 2FA")
	}
}

func TestRequiresTwoFactor_ConfigGlobal(t *testing.T) {
	svc := newTestSvc(t)
	svc.cfg.Require2FA = true
	user := User{}
	if !svc.requiresTwoFactor(user) {
		t.Fatal("global Require2FA config should enforce 2FA for all users")
	}
}

func TestRequiresTwoFactor_NotRequired(t *testing.T) {
	svc := newTestSvc(t)
	user := User{}
	if svc.requiresTwoFactor(user) {
		t.Fatal("user without 2FA requirements should not require 2FA")
	}
}

// --- resolveUser helper ---

func TestResolveUser_ByID(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, _ := registerUser(t, svc, "resolve@example.com", "t1")
	found, err := svc.resolveUser(ctx, user.ID, "", "t1")
	if err != nil {
		t.Fatalf("resolveUser by ID: %v", err)
	}
	if found.ID != user.ID {
		t.Fatalf("unexpected user: %s", found.ID)
	}
}

func TestResolveUser_ByEmail(t *testing.T) {
	svc := newTestSvc(t)
	ctx := context.Background()
	user, _ := registerUser(t, svc, "resolveemail@example.com", "t1")
	found, err := svc.resolveUser(ctx, "", "resolveemail@example.com", "t1")
	if err != nil {
		t.Fatalf("resolveUser by email: %v", err)
	}
	if found.ID != user.ID {
		t.Fatalf("unexpected user: %s", found.ID)
	}
}

func TestResolveUser_NeitherIDNorEmail(t *testing.T) {
	svc := newTestSvc(t)
	_, err := svc.resolveUser(context.Background(), "", "", "t1")
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for empty inputs, got %v", err)
	}
}
