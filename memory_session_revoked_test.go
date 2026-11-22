package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Tests for MemorySessionStore.UpdateSession keeping a revocation: a write
// that would clear one is refused with ErrSessionRevoked, so a refresh that
// read a session before it was revoked cannot bring it back by writing its
// rotated copy.

func TestMemorySessionStoreUpdateSessionKeepsARevocation(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	session := Session{
		ID:               "ses_kept",
		UserID:           "u1",
		TenantID:         "t1",
		RefreshTokenHash: "hash_before",
		ExpiresAt:        time.Now().Add(time.Hour),
		CreatedAt:        time.Now(),
	}
	if _, err := store.CreateSession(ctx, session); err != nil {
		t.Fatalf("create: %v", err)
	}
	read := session // what a refresh read before the revocation
	if err := store.RevokeSessionByID(ctx, session.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	read.RefreshTokenHash = "hash_rotated"
	if err := store.UpdateSession(ctx, read); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("writing back the copy read before the revocation: err = %v, want ErrSessionRevoked", err)
	}
	stored, err := store.GetSessionByID(ctx, session.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.RevokedAt == nil || stored.RefreshTokenHash != "hash_before" {
		t.Errorf("stored = revoked %v, hash %q; want it revoked and unchanged", stored.RevokedAt != nil, stored.RefreshTokenHash)
	}
	if _, err := store.GetSessionByRefreshTokenHash(ctx, "hash_rotated"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("the refused write indexed its token hash: err = %v", err)
	}

	// A write that keeps the revocation — a second logout, say — still lands.
	now := time.Now()
	stored.RevokedAt = &now
	if err := store.UpdateSession(ctx, stored); err != nil {
		t.Errorf("a write that keeps the revocation: %v", err)
	}
}

// interleavingSessionStore runs afterRead once, right after the session a
// refresh asked for has been read: where a revocation racing the refresh
// lands.
type interleavingSessionStore struct {
	*MemorySessionStore
	afterRead func()
}

func (s *interleavingSessionStore) GetSessionByRefreshTokenHash(ctx context.Context, hash string) (Session, error) {
	session, err := s.MemorySessionStore.GetSessionByRefreshTokenHash(ctx, hash)
	if hook := s.afterRead; hook != nil {
		s.afterRead = nil
		hook()
	}
	return session, err
}

// TestRefreshInFlightDoesNotUndoARevocation: a password reset that revokes the
// account's sessions while a refresh of one of them is in flight — read
// before, written after — leaves that session revoked. The refresh answers
// ErrSessionRevoked (401 SESSION_REVOKED on the wire) instead of rotating it
// back to life.
func TestRefreshInFlightDoesNotUndoARevocation(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig("resetsessions123456789012345678901")
	cfg.RevokeSessionsOnPasswordReset = true
	store := &interleavingSessionStore{MemorySessionStore: NewMemorySessionStore()}
	svc, err := NewService(cfg, NewMemoryUserStore(), store)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	_, tokens := registerUser(t, svc, "inflight@example.com", "t1")
	resetToken := mintResetToken(t, svc, "inflight@example.com")

	var resetErr error
	store.afterRead = func() {
		resetErr = svc.ResetPassword(ctx, ResetPasswordInput{Token: resetToken, NewPassword: "newpassword1"})
	}
	if _, err := svc.Refresh(ctx, tokens.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("the refresh in flight: err = %v, want ErrSessionRevoked", err)
	}
	if resetErr != nil {
		t.Fatalf("the reset during the refresh: %v", resetErr)
	}
	stored, err := store.GetSessionByID(ctx, svc.sessionIDOf(tokens))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.RevokedAt == nil {
		t.Error("the session the reset revoked was written back unrevoked")
	}
	if _, err := svc.Refresh(ctx, tokens.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("a later refresh: err = %v, want ErrSessionRevoked", err)
	}
}
