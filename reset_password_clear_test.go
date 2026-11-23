package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Tests for the last step of Service.ResetPassword: once the new password is
// written, the spent token is cleared without the caller's cancellation,
// bounded by its deadline, as ChangePassword's clear is. On a Go net/http
// server a client that half-closes its connection cancels the request
// context, and a clear cut short there left the spent link able to set the
// password again until it expired. The fixtures are change_password_reset_link_test.go's.

// TestResetPasswordClearsWhenTheCallerGoesAway: a caller whose context ends
// right after the new password is written still gets the spent link cleared,
// and the reset answers success: the password it asked for is the account's.
func TestResetPasswordClearsWhenTheCallerGoesAway(t *testing.T) {
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

	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "resetpassword1"}); err != nil {
		t.Errorf("reset whose client went away after the write: err = %v, want nil: the password was written", err)
	}
	if ctx.Err() == nil {
		t.Fatal("the context was not cancelled after the write; the case tests nothing")
	}
	if !verifyPassword("resetpassword1", storedUser(t, svc, user.ID).PasswordHash) {
		t.Fatal("the reset password is not the account's")
	}
	store.afterPassword = nil
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: token, NewPassword: "takeover123"}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("the spent link, after its client went away: err = %v, want ErrInvalidToken", err)
	}
	if !verifyPassword("resetpassword1", storedUser(t, svc, user.ID).PasswordHash) {
		t.Error("the spent link set the password again")
	}
}

// TestResetPasswordClearKeepsTheDeadline: the clear runs without the caller's
// cancellation but not past its deadline.
func TestResetPasswordClearKeepsTheDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	store := &resetLinkStore{MemoryUserStore: NewMemoryUserStore()}
	svc, _, token := newResetLinkSvc(t, store, nil)
	var seen time.Time
	var had bool
	store.clear = func(ctx context.Context, userID, tenantID string) error {
		seen, had = ctx.Deadline()
		return store.MemoryUserStore.ClearResetToken(ctx, userID, tenantID)
	}
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "resetpassword1"}); err != nil {
		t.Fatalf("reset password: %v", err)
	}
	if !had || !seen.Equal(deadline) {
		t.Errorf("the clear saw deadline %v (set: %v), want the caller's %v", seen, had, deadline)
	}
}

// TestResetPasswordFailedClearFailsTheReset pins what the detach leaves as it
// was: a clear the store refuses still fails the reset, although the password
// has changed by then, because the spent link may still work. Unlike
// ChangePassword's clear, this one is the reference's own step.
func TestResetPasswordFailedClearFailsTheReset(t *testing.T) {
	store := &resetLinkStore{MemoryUserStore: NewMemoryUserStore()}
	svc, user, token := newResetLinkSvc(t, store, nil)
	refused := errors.New("table unavailable")
	store.clear = func(context.Context, string, string) error { return refused }

	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: token, NewPassword: "resetpassword1"}); !errors.Is(err, refused) {
		t.Errorf("reset with a failing clear: err = %v, want the store's error", err)
	}
	if !verifyPassword("resetpassword1", storedUser(t, svc, user.ID).PasswordHash) {
		t.Error("the password was not written before the clear")
	}
}
