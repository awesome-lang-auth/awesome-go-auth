package auth

import (
	"context"
	"testing"
	"time"
)

// strPtr addresses a literal, for the optional fields of UpdateProfileInput
// where nil and "" mean different things.
func strPtr(s string) *string { return &s }

func TestPasswordResetFlow(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "reset@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	resetToken, err := svc.ForgotPassword(ctx, ForgotPasswordInput{Email: user.Email, TenantID: user.TenantID})
	if err != nil || resetToken == "" {
		t.Fatalf("forgot password: %v", err)
	}
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: resetToken, NewPassword: "password2"}); err != nil {
		t.Fatalf("reset password: %v", err)
	}

	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err == nil {
		t.Fatal("old password should no longer work")
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password2", TenantID: user.TenantID}); err != nil {
		t.Fatalf("new password should work: %v", err)
	}
}

func TestMagicLinkFlow(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "magic@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	token, err := svc.SendMagicLink(ctx, MagicLinkSendInput{Email: user.Email, TenantID: user.TenantID})
	if err != nil || token == "" {
		t.Fatalf("send magic link: %v", err)
	}
	_, tokens, err := svc.VerifyMagicLink(ctx, MagicLinkVerifyInput{Token: token})
	if err != nil {
		t.Fatalf("verify magic link: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("tokens should be issued after magic link verification")
	}
}

func TestSMSLoginFlow(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "sms@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	mu := svc.users.(*MemoryUserStore)
	mu.mu.Lock()
	u := mu.byID[user.ID]
	u.PhoneNumber = "+390000000000"
	mu.byID[user.ID] = u
	mu.mu.Unlock()

	code, err := svc.SendSMSCode(ctx, SMSCodeSendInput{UserID: user.ID, TenantID: user.TenantID})
	if err != nil || code == "" {
		t.Fatalf("send sms code: %v", err)
	}
	_, tokens, err := svc.VerifySMSCode(ctx, SMSCodeVerifyInput{UserID: user.ID, TenantID: user.TenantID, Code: code})
	if err != nil {
		t.Fatalf("verify sms code: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("access token expected")
	}
}

func testServiceWithEmailVerificationMode(t *testing.T, mode string) *Service {
	t.Helper()
	cfg := testConfig("01234567890123456789012345678901")
	cfg.EmailVerificationMode = mode
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

func TestEmailVerificationAndEmailChangeFlow(t *testing.T) {
	svc := testServiceWithEmailVerificationMode(t, EmailVerificationModeStrict)
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "verify@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.IsEmailVerified {
		t.Fatal("strict mode should register an unverified user")
	}

	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != ErrEmailNotVerified {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}

	verifyToken, err := svc.SendVerificationEmailToken(ctx, EmailVerificationInput{UserID: user.ID, TenantID: user.TenantID})
	if err != nil || verifyToken == "" {
		t.Fatalf("send verification token: %v", err)
	}
	if err := svc.VerifyEmail(ctx, VerifyEmailInput{Token: verifyToken}); err != nil {
		t.Fatalf("verify email: %v", err)
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != nil {
		t.Fatalf("login should work after email verification: %v", err)
	}

	changeToken, err := svc.RequestEmailChange(ctx, ChangeEmailRequestInput{UserID: user.ID, TenantID: user.TenantID, NewEmail: "verify2@example.com"})
	if err != nil {
		t.Fatalf("request email change: %v", err)
	}
	if err := svc.ConfirmEmailChange(ctx, ConfirmEmailChangeInput{Token: changeToken}); err != nil {
		t.Fatalf("confirm email change: %v", err)
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: "verify2@example.com", Password: "password1", TenantID: user.TenantID}); err != nil {
		t.Fatalf("login with new email should work: %v", err)
	}
}

func TestEmailVerificationModeNoneRegistersVerified(t *testing.T) {
	svc := testServiceWithEmailVerificationMode(t, EmailVerificationModeNone)
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "none@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !user.IsEmailVerified {
		t.Fatal("none mode should register a verified user")
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != nil {
		t.Fatalf("login should work right after register: %v", err)
	}
	token, err := svc.SendVerificationEmailToken(ctx, EmailVerificationInput{UserID: user.ID, TenantID: user.TenantID})
	if err != nil || token != "" {
		t.Fatalf("expected no verification token for a verified user, got %q (%v)", token, err)
	}
}

func TestEmailVerificationModeUnsetBehavesLikeNone(t *testing.T) {
	svc := testServiceWithEmailVerificationMode(t, "")
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "unset@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !user.IsEmailVerified {
		t.Fatal("an unset mode should keep registering verified users")
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != nil {
		t.Fatalf("login should work right after register: %v", err)
	}
}

func TestEmailVerificationModeLazyAllowsLoginWhileUnverified(t *testing.T) {
	svc := testServiceWithEmailVerificationMode(t, EmailVerificationModeLazy)
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "lazy@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.IsEmailVerified {
		t.Fatal("lazy mode should register an unverified user")
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != nil {
		t.Fatalf("lazy mode should allow login while unverified: %v", err)
	}

	verifyToken, err := svc.SendVerificationEmailToken(ctx, EmailVerificationInput{UserID: user.ID, TenantID: user.TenantID})
	if err != nil || verifyToken == "" {
		t.Fatalf("send verification token: %v", err)
	}
	if err := svc.VerifyEmail(ctx, VerifyEmailInput{Token: verifyToken}); err != nil {
		t.Fatalf("verify email: %v", err)
	}
	verified, err := svc.users.GetUserByID(ctx, user.ID, user.TenantID)
	if err != nil || !verified.IsEmailVerified {
		t.Fatalf("user should be verified after VerifyEmail: %v", err)
	}
}

func TestEmailVerificationModeStrictRefusesLoginUntilVerified(t *testing.T) {
	svc := testServiceWithEmailVerificationMode(t, EmailVerificationModeStrict)
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "strict@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.IsEmailVerified {
		t.Fatal("strict mode should register an unverified user")
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != ErrEmailNotVerified {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}

	evs, ok := svc.users.(EmailVerificationStore)
	if !ok {
		t.Fatal("memory user store should implement EmailVerificationStore")
	}
	if err := evs.MarkEmailVerified(ctx, user.ID, user.TenantID, true); err != nil {
		t.Fatalf("mark email verified: %v", err)
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != nil {
		t.Fatalf("login should work once the address is verified: %v", err)
	}
}

// createUnverifiedUser writes a user straight to the store, the way an admin
// provisioning path, a data import or a custom UserStore would.
func createUnverifiedUser(t *testing.T, svc *Service, email string) User {
	t.Helper()
	pw, err := hashPassword("password1", svc.cfg.BcryptCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now()
	user, err := svc.users.CreateUser(context.Background(), User{
		ID:              "usr_provisioned",
		Email:           email,
		PasswordHash:    pw,
		TenantID:        "t1",
		IsEmailVerified: false,
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

// Before EmailVerificationMode existed, Login refused every unverified user
// regardless of configuration. The default none keeps that gate in force, so
// only lazy relaxes it. The three tests below pin one mode each against a user
// that never went through Register, which is the only way the gate is
// observable at all.
func TestEmailVerificationModeNoneRefusesExternallyCreatedUnverifiedUser(t *testing.T) {
	svc := testServiceWithEmailVerificationMode(t, EmailVerificationModeNone)
	ctx := context.Background()

	user := createUnverifiedUser(t, svc, "provisioned-none@example.com")
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != ErrEmailNotVerified {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}
}

// The unset mode resolves to none, so it must gate the same way. This is the
// case that decides whether the PR is backwards compatible for embedders that
// build a Config literal instead of calling DefaultConfig.
func TestEmailVerificationModeUnsetRefusesExternallyCreatedUnverifiedUser(t *testing.T) {
	svc := testServiceWithEmailVerificationMode(t, "")
	ctx := context.Background()

	user := createUnverifiedUser(t, svc, "provisioned-unset@example.com")
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != ErrEmailNotVerified {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}
}

func TestEmailVerificationModeLazyAllowsExternallyCreatedUnverifiedUser(t *testing.T) {
	svc := testServiceWithEmailVerificationMode(t, EmailVerificationModeLazy)
	ctx := context.Background()

	user := createUnverifiedUser(t, svc, "provisioned-lazy@example.com")
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != nil {
		t.Fatalf("lazy mode should not enforce verification: %v", err)
	}
}

func TestEmailVerificationModeStrictRefusesExternallyCreatedUnverifiedUser(t *testing.T) {
	svc := testServiceWithEmailVerificationMode(t, EmailVerificationModeStrict)
	ctx := context.Background()

	user := createUnverifiedUser(t, svc, "provisioned-strict@example.com")
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != ErrEmailNotVerified {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}
}

// The strict-mode register gap this file used to pin (#21) is closed: see
// TestRegister_StrictVerificationWinsOverTheOption in register_session_test.go.

func TestTOTPFlow(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	now := time.Now()
	svc.now = func() time.Time { return now }

	user, _, err := svc.Register(ctx, RegisterInput{Email: "totp@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	secret, err := svc.SetupTOTP(ctx, user.ID, user.TenantID)
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	code, ok := generateTOTPCode(secret, now.Unix()/30)
	if !ok {
		t.Fatal("failed to generate totp code")
	}
	if err := svc.VerifyTOTPSetup(ctx, user.ID, user.TenantID, secret, code); err != nil {
		t.Fatalf("verify setup: %v", err)
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != ErrTwoFactorRequired {
		t.Fatalf("expected 2FA required after setup, got %v", err)
	}
	_, tokens, err := svc.VerifyTOTP(ctx, user.ID, user.TenantID, code)
	if err != nil {
		t.Fatalf("verify totp: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("access token expected")
	}
}

func TestResolveUserHelper(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	user, _, err := svc.Register(ctx, RegisterInput{Email: "resolve@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	byID, err := svc.resolveUser(ctx, user.ID, "", user.TenantID)
	if err != nil || byID.ID != user.ID {
		t.Fatalf("resolve by id failed: %v", err)
	}

	byEmail, err := svc.resolveUser(ctx, "", user.Email, user.TenantID)
	if err != nil || byEmail.ID != user.ID {
		t.Fatalf("resolve by email failed: %v", err)
	}

	if _, err := svc.resolveUser(ctx, "", "", user.TenantID); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if _, err := svc.resolveUser(ctx, "   ", "   ", user.TenantID); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for whitespace identifiers, got %v", err)
	}
}

func TestUpdateProfileAndDeleteAccountFlow(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "profile@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	updated, err := svc.UpdateProfile(ctx, UpdateProfileInput{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		FirstName: strPtr("Mario"),
		LastName:  strPtr("Rossi"),
	})
	if err != nil {
		t.Fatalf("update profile: %v", err)
	}
	if updated.FirstName != "Mario" || updated.LastName != "Rossi" {
		t.Fatalf("unexpected updated profile: %+v", updated)
	}

	// A partial patch leaves the field it omits alone: nil means "not submitted",
	// which is what the reference's omitted key means (§3.5). A plain string here
	// made every partial call erase the other name.
	partial, err := svc.UpdateProfile(ctx, UpdateProfileInput{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		FirstName: strPtr("Luigi"),
	})
	if err != nil {
		t.Fatalf("partial update profile: %v", err)
	}
	if partial.FirstName != "Luigi" || partial.LastName != "Rossi" {
		t.Fatalf("partial update did not preserve lastName: %+v", partial)
	}

	// An explicit empty string still clears, which is the reference's nullable
	// field. That is the distinction nil could not carry.
	cleared, err := svc.UpdateProfile(ctx, UpdateProfileInput{
		UserID:   user.ID,
		TenantID: user.TenantID,
		LastName: strPtr(""),
	})
	if err != nil {
		t.Fatalf("clear lastName: %v", err)
	}
	if cleared.FirstName != "Luigi" || cleared.LastName != "" {
		t.Fatalf("explicit empty lastName did not clear: %+v", cleared)
	}

	if err := svc.DeleteAccount(ctx, DeleteAccountInput{UserID: user.ID, TenantID: user.TenantID}); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err == nil {
		t.Fatal("expected login to fail after account deletion")
	}
}

func TestSessionCheckAllCallsRejectsRevokedSessionOnMe(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig("01234567890123456789012345678901")
	cfg.SessionCheckOn = SessionCheckOnAllCalls
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	_, tokens, err := svc.Register(ctx, RegisterInput{Email: "sessioncheck@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := svc.Logout(ctx, tokens.RefreshToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := svc.Me(ctx, tokens.AccessToken); err != ErrSessionRevoked {
		t.Fatalf("expected ErrSessionRevoked, got %v", err)
	}
}
