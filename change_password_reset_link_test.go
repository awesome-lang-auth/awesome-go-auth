package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Tests for the change-password-ends-the-reset-link deviation: once
// Service.ChangePassword has written the new password it clears the account's
// reset token, so a link whose token was stored before the change no longer
// sets a password after it. ForgotPassword stores a token only once its mail
// went out, so asking again no longer cuts off a link whose mail could not be
// delivered; changing the password does. A request whose mail is still out
// when the password changes is the one link the clear cannot end
// (TestChangePasswordLeavesALinkStillBeingMailed).

// resetLinkStore is a MemoryUserStore whose two writes on this path can be
// steered: afterPassword runs once the password is written, and clear, when
// set, replaces ClearResetToken.
type resetLinkStore struct {
	*MemoryUserStore
	afterPassword func()
	clear         func(ctx context.Context, userID, tenantID string) error
}

func (s *resetLinkStore) UpdatePassword(ctx context.Context, userID, tenantID, hash string) error {
	if err := s.MemoryUserStore.UpdatePassword(ctx, userID, tenantID, hash); err != nil {
		return err
	}
	if s.afterPassword != nil {
		s.afterPassword()
	}
	return nil
}

func (s *resetLinkStore) ClearResetToken(ctx context.Context, userID, tenantID string) error {
	if s.clear != nil {
		return s.clear(ctx, userID, tenantID)
	}
	return s.MemoryUserStore.ClearResetToken(ctx, userID, tenantID)
}

// newResetLinkSvc builds a service with no reset sender — so ForgotPassword
// stores the token at once and hands it back — over store, with one account
// holding the password "password1" and a reset token minted for it.
func newResetLinkSvc(t *testing.T, store *resetLinkStore, logged *[]string) (*Service, User, string) {
	t.Helper()
	cfg := DefaultConfig("resetlinkchange12345678901234567")
	cfg.BcryptCost = testBcryptCost
	if logged != nil {
		cfg.Logger = func(format string, args ...any) { *logged = append(*logged, fmt.Sprintf(format, args...)) }
	}
	svc, err := NewService(cfg, store, NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	user := seedUser(t, svc, "changereset@example.com")
	hash, err := hashPassword("password1", cfg.BcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MemoryUserStore.UpdatePassword(context.Background(), user.ID, user.TenantID, hash); err != nil {
		t.Fatalf("set the password: %v", err)
	}
	token, err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: user.Email, TenantID: user.TenantID})
	if err != nil || token == "" {
		t.Fatalf("mint a reset token: %q, %v", token, err)
	}
	return svc, user, token
}

func changePasswordInput(user User) ChangePasswordInput {
	return ChangePasswordInput{UserID: user.ID, TenantID: user.TenantID, CurrentPassword: "password1", NewPassword: "newpassword1"}
}

// TestChangePasswordEndsTheResetLink: a link minted before the change is
// refused after it, the new password is the account's, and a link asked for
// after the change works as any other.
func TestChangePasswordEndsTheResetLink(t *testing.T) {
	ctx := context.Background()
	store := &resetLinkStore{MemoryUserStore: NewMemoryUserStore()}
	svc, user, token := newResetLinkSvc(t, store, nil)

	if err := svc.ChangePassword(ctx, changePasswordInput(user)); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if stored := storedUser(t, svc, user.ID); stored.ResetTokenHash != "" || stored.ResetTokenExpiresAt != nil {
		t.Error("the reset token survived the password change")
	}
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "takeover123"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("the link minted before the change: err = %v, want ErrInvalidToken", err)
	}
	if !verifyPassword("newpassword1", storedUser(t, svc, user.ID).PasswordHash) {
		t.Error("the changed password is not the account's")
	}

	later, err := svc.ForgotPassword(ctx, ForgotPasswordInput{Email: user.Email, TenantID: user.TenantID})
	if err != nil {
		t.Fatalf("a reset asked for after the change: %v", err)
	}
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: later, NewPassword: "thirdpassword1"}); err != nil {
		t.Fatalf("the link minted after the change: %v", err)
	}
}

// TestChangePasswordSurvivesAFailedClear: the password has changed by the
// time the clear runs, so a store that fails it does not fail the change. The
// failure is logged with the user, and the link lives out its TTL.
func TestChangePasswordSurvivesAFailedClear(t *testing.T) {
	ctx := context.Background()
	var logged []string
	store := &resetLinkStore{MemoryUserStore: NewMemoryUserStore()}
	svc, user, token := newResetLinkSvc(t, store, &logged)
	store.clear = func(context.Context, string, string) error { return errors.New("table unavailable") }

	if err := svc.ChangePassword(ctx, changePasswordInput(user)); err != nil {
		t.Fatalf("change password with a failing clear: %v, want nil: the password did change", err)
	}
	if !verifyPassword("newpassword1", storedUser(t, svc, user.ID).PasswordHash) {
		t.Error("the changed password is not the account's")
	}
	var line string
	for _, l := range logged {
		if strings.Contains(l, "reset token could not be cleared") {
			line = l
		}
	}
	if line == "" || !strings.Contains(line, user.ID) || !strings.Contains(line, "table unavailable") {
		t.Errorf("log = %q, want a line naming the user and the store's error", logged)
	}
	if strings.Contains(line, user.Email) {
		t.Errorf("the log line names the address: %q", line)
	}
	// What a failed clear leaves: the link, until it expires. The store
	// clears again, for the reset's own clear.
	store.clear = nil
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "afterfailedclear1"}); err != nil {
		t.Errorf("the link a failed clear left: %v, want it to work until it expires", err)
	}
}

// TestChangePasswordClearsWhenTheCallerGoesAway: a caller whose context ends
// right after the password is written — a client that hung up — still gets
// the link cleared, since the password it follows has changed.
func TestChangePasswordClearsWhenTheCallerGoesAway(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &resetLinkStore{MemoryUserStore: NewMemoryUserStore()}
	svc, user, token := newResetLinkSvc(t, store, nil)
	store.afterPassword = cancel
	store.clear = func(ctx context.Context, userID, tenantID string) error {
		if err := ctx.Err(); err != nil {
			return err // a store behind a network call
		}
		return store.MemoryUserStore.ClearResetToken(ctx, userID, tenantID)
	}

	if err := svc.ChangePassword(ctx, changePasswordInput(user)); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if ctx.Err() == nil {
		t.Fatal("the context was not cancelled after the write; the case tests nothing")
	}
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: token, NewPassword: "takeover123"}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("the link minted before the change, after the caller went away: err = %v, want ErrInvalidToken", err)
	}
}

// TestChangePasswordClearKeepsTheDeadline: the clear runs without the
// caller's cancellation but not past its deadline.
func TestChangePasswordClearKeepsTheDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	store := &resetLinkStore{MemoryUserStore: NewMemoryUserStore()}
	svc, user, _ := newResetLinkSvc(t, store, nil)
	var seen time.Time
	var had bool
	store.clear = func(ctx context.Context, userID, tenantID string) error {
		seen, had = ctx.Deadline()
		return store.MemoryUserStore.ClearResetToken(ctx, userID, tenantID)
	}
	if err := svc.ChangePassword(ctx, changePasswordInput(user)); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if !had || !seen.Equal(deadline) {
		t.Errorf("the clear saw deadline %v (set: %v), want the caller's %v", seen, had, deadline)
	}
}

// TestChangePasswordLeavesALinkStillBeingMailed pins the window the
// change-password-ends-the-reset-link entry names, so that the docs cannot
// drift from it: a ForgotPassword whose mail is still with the sender when
// the password changes stores its token after the change's clear, and that
// link sets a password after the change. ForgotPassword stores a token only
// once its send has returned, and UserPasswordStore has no write conditional
// on the password. If this starts failing, the window has closed: say so in
// the entry, the CHANGELOG and ChangePassword's doc.
func TestChangePasswordLeavesALinkStillBeingMailed(t *testing.T) {
	ctx := context.Background()
	store := &resetLinkStore{MemoryUserStore: NewMemoryUserStore()}
	cfg := DefaultConfig("resetlinkchange12345678901234567")
	cfg.BcryptCost = testBcryptCost
	mailed := make(chan string, 1)
	release := make(chan struct{})
	cfg.SendPasswordReset = func(_ context.Context, d PasswordResetDelivery) error {
		mailed <- d.Token // the mail is out; its token is not stored yet
		<-release
		return nil
	}
	svc, err := NewService(cfg, store, NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	user := seedUser(t, svc, "changereset@example.com")
	hash, err := hashPassword("password1", cfg.BcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MemoryUserStore.UpdatePassword(ctx, user.ID, user.TenantID, hash); err != nil {
		t.Fatalf("set the password: %v", err)
	}

	asked := make(chan error, 1)
	go func() {
		_, err := svc.ForgotPassword(ctx, ForgotPasswordInput{Email: user.Email, TenantID: user.TenantID})
		asked <- err
	}()
	token := <-mailed
	if err := svc.ChangePassword(ctx, changePasswordInput(user)); err != nil {
		close(release)
		t.Fatalf("change password: %v", err)
	}
	close(release)
	if err := <-asked; err != nil {
		t.Fatalf("forgot password: %v", err)
	}

	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "resetpassword1"}); err != nil {
		t.Fatalf("the link whose mail was out when the password changed: err = %v, want nil, the documented window; "+
			"if the window has closed, update the docs that name it", err)
	}
	if !verifyPassword("resetpassword1", storedUser(t, svc, user.ID).PasswordHash) {
		t.Error("the link set no password")
	}
}
