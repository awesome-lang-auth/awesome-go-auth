package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Under Config.RevokeSessionsOnPasswordReset the revocation runs after the
// password write, and a caller that goes away then — on a Go net/http server a
// client that half-closes its connection cancels the request context — must
// not cut it short: the password has changed by then, and a revocation that
// stopped there left every session alive behind a 500 nobody read. It runs
// without the caller's cancellation, bounded by the caller's deadline.

// cancellingUserStore is a MemoryUserStore whose UpdatePassword, once the
// write has landed, calls cancel: the caller going away right after it.
type cancellingUserStore struct {
	*MemoryUserStore
	cancel context.CancelFunc
}

func (s *cancellingUserStore) UpdatePassword(ctx context.Context, userID, tenantID, passwordHash string) error {
	err := s.MemoryUserStore.UpdatePassword(ctx, userID, tenantID, passwordHash)
	if s.cancel != nil {
		s.cancel()
	}
	return err
}

// ctxSessionStore is a recordingSessionStore that honours its context, as a
// store on database/sql's *Context calls does, and records the deadline its
// listing and its bulk revocation were handed.
type ctxSessionStore struct {
	*recordingSessionStore
	mu        sync.Mutex
	deadlines []time.Time
}

func (s *ctxSessionStore) seen(ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		s.mu.Lock()
		s.deadlines = append(s.deadlines, deadline)
		s.mu.Unlock()
	}
	return ctx.Err()
}

func (s *ctxSessionStore) ListSessionsForUser(ctx context.Context, userID, tenantID string) ([]Session, error) {
	if err := s.seen(ctx); err != nil {
		return nil, err
	}
	return s.recordingSessionStore.ListSessionsForUser(ctx, userID, tenantID)
}

func (s *ctxSessionStore) RevokeSessionByID(ctx context.Context, sessionID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.recordingSessionStore.RevokeSessionByID(ctx, sessionID)
}

// ctxBulkSessionStore adds a UserSessionRevoker that honours its context.
type ctxBulkSessionStore struct{ *ctxSessionStore }

func (s ctxBulkSessionStore) RevokeSessionsForUser(ctx context.Context, userID, tenantID string) error {
	if err := s.seen(ctx); err != nil {
		return err
	}
	return revokeAllInMemory(ctx, s.MemorySessionStore, userID, tenantID)
}

func newCtxSessionStores() map[string]func() (SessionStore, *ctxSessionStore) {
	return map[string]func() (SessionStore, *ctxSessionStore){
		"listing": func() (SessionStore, *ctxSessionStore) {
			s := &ctxSessionStore{recordingSessionStore: &recordingSessionStore{MemorySessionStore: NewMemorySessionStore(), refuse: map[string]error{}}}
			return s, s
		},
		"UserSessionRevoker": func() (SessionStore, *ctxSessionStore) {
			s := &ctxSessionStore{recordingSessionStore: &recordingSessionStore{MemorySessionStore: NewMemorySessionStore(), refuse: map[string]error{}}}
			return ctxBulkSessionStore{s}, s
		},
	}
}

// TestRevokingResetOutlivesACallerThatGoesAwayAfterTheWrite is the
// verification's probe: the caller's context ends right after the password
// write, and the session opened before the reset is revoked all the same.
func TestRevokingResetOutlivesACallerThatGoesAwayAfterTheWrite(t *testing.T) {
	for name, build := range newCtxSessionStores() {
		t.Run(name, func(t *testing.T) {
			users := &cancellingUserStore{MemoryUserStore: NewMemoryUserStore()}
			sessions, _ := build()
			cfg := testConfig("resetsessions123456789012345678901")
			cfg.RevokeSessionsOnPasswordReset = true
			svc, err := NewService(cfg, users, sessions)
			if err != nil {
				t.Fatalf("new service: %v", err)
			}
			_, before := registerUser(t, svc, "hangup@example.com", "t1")
			token := mintResetToken(t, svc, "hangup@example.com")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			users.cancel = cancel
			if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "newpassword1"}); err != nil {
				t.Errorf("reset whose caller went away after the write: err = %v, want nil", err)
			}
			users.cancel = nil
			login(t, svc, "hangup@example.com", "newpassword1") // the new password is in force
			if _, err := svc.Refresh(context.Background(), before.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
				t.Errorf("the session opened before the reset: refresh err = %v, want ErrSessionRevoked", err)
			}
		})
	}
}

// TestRevokingResetKeepsTheCallersDeadline: detached from the cancellation,
// not from the deadline — the store is handed the caller's.
func TestRevokingResetKeepsTheCallersDeadline(t *testing.T) {
	for name, build := range newCtxSessionStores() {
		t.Run(name, func(t *testing.T) {
			sessions, seen := build()
			cfg := testConfig("resetsessions123456789012345678901")
			cfg.RevokeSessionsOnPasswordReset = true
			svc, err := NewService(cfg, NewMemoryUserStore(), sessions)
			if err != nil {
				t.Fatalf("new service: %v", err)
			}
			registerUser(t, svc, "deadline@example.com", "t1")
			token := mintResetToken(t, svc, "deadline@example.com")

			deadline := time.Now().Add(time.Minute)
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "newpassword1"}); err != nil {
				t.Fatalf("reset: %v", err)
			}
			seen.mu.Lock()
			defer seen.mu.Unlock()
			if len(seen.deadlines) != 1 || !seen.deadlines[0].Equal(deadline) {
				t.Errorf("the revocation was handed deadlines %v, want exactly the caller's %v", seen.deadlines, deadline)
			}
		})
	}
}
