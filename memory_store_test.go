package auth

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMemorySessionStore_ListRevokeAndCleanup(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	now := time.Now()

	_, _ = store.CreateSession(ctx, Session{ID: "s1", UserID: "u1", TenantID: "t1", RefreshTokenHash: "h1", ExpiresAt: now.Add(1 * time.Hour)})
	_, _ = store.CreateSession(ctx, Session{ID: "s2", UserID: "u1", TenantID: "t2", RefreshTokenHash: "h2", ExpiresAt: now.Add(1 * time.Hour)})
	_, _ = store.CreateSession(ctx, Session{ID: "s3", UserID: "u2", TenantID: "t1", RefreshTokenHash: "h3", ExpiresAt: now.Add(-1 * time.Hour)})

	sessions, err := store.ListSessionsForUser(ctx, "u1", "t1")
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != "s1" {
		t.Fatalf("unexpected filtered sessions: %+v", sessions)
	}

	if err := store.RevokeSessionByID(ctx, "s1"); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	revoked, err := store.GetSessionByRefreshTokenHash(ctx, "h1")
	if err != nil {
		t.Fatalf("get revoked session: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("revoked session should have RevokedAt")
	}
	if err := store.RevokeSessionByID(ctx, "missing"); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}

	deleted, err := store.DeleteExpiredSessions(ctx, now)
	if err != nil {
		t.Fatalf("cleanup expired sessions: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted session, got %d", deleted)
	}
	if _, err := store.GetSessionByRefreshTokenHash(ctx, "h3"); err != ErrSessionNotFound {
		t.Fatalf("expected expired session removed, got %v", err)
	}
}

// The three admin listers, and the by-id lookup beside them, are optional
// capabilities resolved by type assertion, so nothing fails at build time if an
// implementation drifts away from its interface — it just stops being found at
// run time, on a route, in M8. These lines are what makes that a compile error
// instead.
var (
	_ AdminUserStore  = (*MemoryUserStore)(nil)
	_ UserLookupStore = (*MemoryUserStore)(nil)
	_ SessionLister   = (*MemorySessionStore)(nil)
	_ RoleLister      = (*MemoryRolesPermissionsStore)(nil)
)

func TestMemorySessionStore_GetAllSessions(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	now := time.Now()

	// Inserted out of order, and across two users and two tenants, so that the
	// assertion below is about the ordering rule and not about insertion order.
	for _, id := range []string{"s3", "s1", "s4", "s2"} {
		_, _ = store.CreateSession(ctx, Session{
			ID: id, UserID: "u" + id[1:2], TenantID: "t1",
			RefreshTokenHash: "h" + id[1:2], ExpiresAt: now.Add(time.Hour),
		})
	}

	all, err := store.GetAllSessions(ctx, 10, 0)
	if err != nil {
		t.Fatalf("GetAllSessions: %v", err)
	}
	if got := sessionIDs(all); got != "s1,s2,s3,s4" {
		t.Fatalf("expected Session.ID ascending across all users, got %s", got)
	}

	page, err := store.GetAllSessions(ctx, 2, 1)
	if err != nil {
		t.Fatalf("GetAllSessions page: %v", err)
	}
	if got := sessionIDs(page); got != "s2,s3" {
		t.Fatalf("unexpected page: %s", got)
	}
}

// A revoked session is a tombstone in this store and an expired one is still a
// row until DeleteExpiredSessions runs. SessionLister returns both: dropping
// them is the presentation layer's job, and Auth.ListSessions is where it
// happens.
func TestMemorySessionStore_GetAllSessions_IncludesRevokedAndExpired(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	now := time.Now()

	_, _ = store.CreateSession(ctx, Session{ID: "s1", UserID: "u1", RefreshTokenHash: "h1", ExpiresAt: now.Add(time.Hour)})
	_, _ = store.CreateSession(ctx, Session{ID: "s2", UserID: "u1", RefreshTokenHash: "h2", ExpiresAt: now.Add(time.Hour)})
	_, _ = store.CreateSession(ctx, Session{ID: "s3", UserID: "u2", RefreshTokenHash: "h3", ExpiresAt: now.Add(-time.Hour)})
	if err := store.RevokeSessionByID(ctx, "s2"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	all, err := store.GetAllSessions(ctx, 100, 0)
	if err != nil {
		t.Fatalf("GetAllSessions: %v", err)
	}
	if got := sessionIDs(all); got != "s1,s2,s3" {
		t.Fatalf("revoked and expired sessions must still be listed, got %s", got)
	}
}

// ListSessionsForUser ranges over a map, so before it sorted, the device list at
// GET /sessions came back shuffled on every call.
func TestMemorySessionStore_ListSessionsForUser_IsOrdered(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	now := time.Now()
	for _, id := range []string{"s9", "s2", "s7", "s1"} {
		_, _ = store.CreateSession(ctx, Session{
			ID: id, UserID: "u1", TenantID: "t1",
			RefreshTokenHash: "h" + id, ExpiresAt: now.Add(time.Hour),
		})
	}
	for range 8 {
		sessions, err := store.ListSessionsForUser(ctx, "u1", "t1")
		if err != nil {
			t.Fatalf("ListSessionsForUser: %v", err)
		}
		if got := sessionIDs(sessions); got != "s1,s2,s7,s9" {
			t.Fatalf("expected a stable ID-ascending order, got %s", got)
		}
	}
}

func sessionIDs(sessions []Session) string {
	ids := make([]string, 0, len(sessions))
	for _, session := range sessions {
		ids = append(ids, session.ID)
	}
	return strings.Join(ids, ",")
}
