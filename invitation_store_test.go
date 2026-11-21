package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// MemoryInvitationStore against the InvitationStore contract: the points a
// shared implementation owes, run against the one implementation this package
// ships. A store written for DynamoDB can run the same assertions.

var storeEpoch = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

func storeInvitation(id, tokenHash, userID string) Invitation {
	return Invitation{
		ID:        id,
		TokenHash: tokenHash,
		UserID:    userID,
		TenantID:  "t1",
		Email:     userID + "@example.com",
		Metadata:  map[string]any{"k": "v"},
		CreatedAt: storeEpoch,
		ExpiresAt: storeEpoch.Add(time.Hour),
	}
}

func TestMemoryInvitationStoreCreate(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryInvitationStore()
	if err := s.CreateInvitation(ctx, storeInvitation("inv_1", "h1", "u1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	for name, inv := range map[string]Invitation{
		"the same id":   storeInvitation("inv_1", "h2", "u2"),
		"the same hash": storeInvitation("inv_2", "h1", "u2"),
	} {
		if err := s.CreateInvitation(ctx, inv); !errors.Is(err, ErrAlreadyExists) {
			t.Errorf("%s: %v, want ErrAlreadyExists", name, err)
		}
	}
	for name, inv := range map[string]Invitation{
		"no id":   storeInvitation("", "h3", "u3"),
		"no hash": storeInvitation("inv_3", "", "u3"),
	} {
		if err := s.CreateInvitation(ctx, inv); err == nil {
			t.Errorf("%s was stored", name)
		}
	}
}

func TestMemoryInvitationStoreConsume(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryInvitationStore()
	_ = s.CreateInvitation(ctx, storeInvitation("inv_1", "h1", "u1"))

	if _, err := s.ConsumeInvitation(ctx, "unknown", storeEpoch); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("unknown hash = %v", err)
	}
	// At ExpiresAt the token is no longer honoured, a moment before it is.
	if _, err := s.ConsumeInvitation(ctx, "h1", storeEpoch.Add(time.Hour)); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("consume at expiry = %v", err)
	}
	at := storeEpoch.Add(time.Hour - time.Nanosecond)
	got, err := s.ConsumeInvitation(ctx, "h1", at)
	if err != nil || got.AcceptedAt == nil || !got.AcceptedAt.Equal(at) || got.ID != "inv_1" {
		t.Fatalf("consume = %+v, %v", got, err)
	}
	if _, err := s.ConsumeInvitation(ctx, "h1", at); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("second consume = %v, want ErrInvitationNotFound", err)
	}
	// An accepted invitation cannot be revoked.
	if revoked, err := s.RevokeInvitation(ctx, "inv_1", at); !errors.Is(err, ErrInvitationNotPending) || revoked.AcceptedAt == nil {
		t.Fatalf("revoke after consume = %+v, %v", revoked, err)
	}
}

func TestMemoryInvitationStoreConsumeIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryInvitationStore()
	_ = s.CreateInvitation(ctx, storeInvitation("inv_1", "h1", "u1"))
	const n = 32
	var wg sync.WaitGroup
	results := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Half consume, half revoke: exactly one write of either kind wins.
			if i%2 == 0 {
				_, results[i] = s.ConsumeInvitation(ctx, "h1", storeEpoch)
			} else {
				_, results[i] = s.RevokeInvitation(ctx, "inv_1", storeEpoch)
			}
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, err := range results {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("%d writes won, want exactly 1", wins)
	}
	pending, _ := s.ListPendingInvitations(ctx, 10, 0)
	if len(pending) != 0 {
		t.Fatalf("the invitation is still pending after a winner: %+v", pending)
	}
}

func TestMemoryInvitationStoreRevoke(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryInvitationStore()
	_ = s.CreateInvitation(ctx, storeInvitation("inv_1", "h1", "u1"))
	if _, err := s.RevokeInvitation(ctx, "inv_nope", storeEpoch); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("unknown = %v", err)
	}
	// Expired and still pending is revocable.
	later := storeEpoch.Add(2 * time.Hour)
	got, err := s.RevokeInvitation(ctx, "inv_1", later)
	if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(later) {
		t.Fatalf("revoke = %+v, %v", got, err)
	}
	again, err := s.RevokeInvitation(ctx, "inv_1", later)
	if !errors.Is(err, ErrInvitationNotPending) || again.RevokedAt == nil {
		t.Fatalf("second revoke = %+v, %v", again, err)
	}
	if _, err := s.ConsumeInvitation(ctx, "h1", storeEpoch); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("consume after revoke = %v", err)
	}
}

func TestMemoryInvitationStoreListings(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryInvitationStore()
	// Created out of order, so the order below is the store's.
	for _, i := range []int{3, 1, 4, 2, 5} {
		user := "u1"
		if i%2 == 0 {
			user = "u2"
		}
		_ = s.CreateInvitation(ctx, storeInvitation(fmt.Sprintf("inv_%d", i), fmt.Sprintf("h%d", i), user))
	}
	_, _ = s.ConsumeInvitation(ctx, "h5", storeEpoch)
	_, _ = s.RevokeInvitation(ctx, "inv_4", storeEpoch)

	ids := func(invitations []Invitation) string {
		out := make([]string, 0, len(invitations))
		for _, inv := range invitations {
			out = append(out, inv.ID)
		}
		return strings.Join(out, ",")
	}
	all, _ := s.ListPendingInvitations(ctx, 10, 0)
	if got := ids(all); got != "inv_1,inv_2,inv_3" {
		t.Fatalf("pending = %s, want the three neither accepted nor revoked, by id", got)
	}
	for _, tc := range []struct {
		limit, offset int
		want          string
	}{
		{2, 0, "inv_1,inv_2"},
		{2, 2, "inv_3"},
		{2, -5, "inv_1,inv_2"},
		{0, 0, ""},
		{-1, 0, ""},
		{2, 3, ""},
	} {
		page, err := s.ListPendingInvitations(ctx, tc.limit, tc.offset)
		if err != nil || ids(page) != tc.want || page == nil {
			t.Errorf("ListPendingInvitations(%d, %d) = %q, %v, want %q", tc.limit, tc.offset, ids(page), err, tc.want)
		}
	}
	forUser, _ := s.PendingInvitationsForUser(ctx, "u1")
	if got := ids(forUser); got != "inv_1,inv_3" {
		t.Fatalf("pending for u1 = %s (inv_5 is accepted)", got)
	}
	forOther, _ := s.PendingInvitationsForUser(ctx, "u2")
	if got := ids(forOther); got != "inv_2" {
		t.Fatalf("pending for u2 = %s (inv_4 is revoked)", got)
	}
}

func TestMemoryInvitationStoreKeepsItsOwnCopy(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryInvitationStore()
	inv := storeInvitation("inv_1", "h1", "u1")
	_ = s.CreateInvitation(ctx, inv)
	inv.Metadata["k"] = "changed by the caller"

	listed, _ := s.ListPendingInvitations(ctx, 10, 0)
	if listed[0].Metadata["k"] != "v" {
		t.Fatal("the caller's map is the store's")
	}
	listed[0].Metadata["k"] = "changed through a listing"
	consumed, _ := s.ConsumeInvitation(ctx, "h1", storeEpoch)
	if consumed.Metadata["k"] != "v" {
		t.Fatal("a listing's map is the store's")
	}
	*consumed.AcceptedAt = storeEpoch.Add(time.Minute)
	again, _ := s.RevokeInvitation(ctx, "inv_1", storeEpoch)
	if !again.AcceptedAt.Equal(storeEpoch) {
		t.Fatal("a returned AcceptedAt points at the store's")
	}
}

// TestMemoryInvitationStoreRelease: a consume is handed back only by a release
// that names it — the record accepted at that instant and not revoked — and
// the record is then pending in every respect: listed, revocable, and its
// token honoured again.
func TestMemoryInvitationStoreRelease(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryInvitationStore()
	_ = s.CreateInvitation(ctx, storeInvitation("inv_1", "h1", "u1"))
	if err := s.ReleaseInvitation(ctx, "inv_1", storeEpoch); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("release of a pending record = %v, want ErrInvitationNotFound", err)
	}
	if err := s.ReleaseInvitation(ctx, "inv_nope", storeEpoch); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("release of an unknown id = %v", err)
	}

	first, err := s.ConsumeInvitation(ctx, "h1", storeEpoch)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := s.ReleaseInvitation(ctx, "inv_1", storeEpoch.Add(time.Second)); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("release naming another instant = %v, want ErrInvitationNotFound", err)
	}
	if pending, _ := s.PendingInvitationsForUser(ctx, "u1"); len(pending) != 0 {
		t.Fatalf("a refused release changed the record: %+v", pending)
	}
	if err := s.ReleaseInvitation(ctx, "inv_1", *first.AcceptedAt); err != nil {
		t.Fatalf("release: %v", err)
	}
	for name, read := range map[string]func() ([]Invitation, error){
		"listing":  func() ([]Invitation, error) { return s.ListPendingInvitations(ctx, 10, 0) },
		"per user": func() ([]Invitation, error) { return s.PendingInvitationsForUser(ctx, "u1") },
	} {
		if got, _ := read(); len(got) != 1 || got[0].AcceptedAt != nil {
			t.Fatalf("%s after release = %+v, want the record pending", name, got)
		}
	}

	// A release that arrives twice, or late, undoes nothing that came after
	// the consume it names.
	if err := s.ReleaseInvitation(ctx, "inv_1", *first.AcceptedAt); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("second release = %v, want ErrInvitationNotFound", err)
	}
	second, err := s.ConsumeInvitation(ctx, "h1", storeEpoch.Add(time.Minute))
	if err != nil {
		t.Fatalf("the token after the release: %v", err)
	}
	if err := s.ReleaseInvitation(ctx, "inv_1", *first.AcceptedAt); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("a late release of the first consume = %v, want ErrInvitationNotFound", err)
	}
	if revoked, err := s.RevokeInvitation(ctx, "inv_1", storeEpoch); !errors.Is(err, ErrInvitationNotPending) ||
		revoked.AcceptedAt == nil || !revoked.AcceptedAt.Equal(*second.AcceptedAt) {
		t.Fatalf("the second acceptance = %+v, %v, want it standing", revoked, err)
	}

	// A revoked record is never released.
	_ = s.CreateInvitation(ctx, storeInvitation("inv_2", "h2", "u2"))
	revoked, _ := s.RevokeInvitation(ctx, "inv_2", storeEpoch)
	if err := s.ReleaseInvitation(ctx, "inv_2", *revoked.RevokedAt); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("release of a revoked record = %v", err)
	}
}

// TestMemoryInvitationStoreReleaseIsAtomicAgainstRevoke: a release and a
// revocation racing over an accepted record leave it either pending (the
// revocation came first and found it accepted) or revoked (the release came
// first), and never accepted and revoked at once. Run under -race.
func TestMemoryInvitationStoreReleaseIsAtomicAgainstRevoke(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 64; i++ {
		s := NewMemoryInvitationStore()
		_ = s.CreateInvitation(ctx, storeInvitation("inv_1", "h1", "u1"))
		accepted, err := s.ConsumeInvitation(ctx, "h1", storeEpoch)
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		var wg sync.WaitGroup
		var releaseErr, revokeErr error
		wg.Add(2)
		go func() { defer wg.Done(); releaseErr = s.ReleaseInvitation(ctx, "inv_1", *accepted.AcceptedAt) }()
		go func() { defer wg.Done(); _, revokeErr = s.RevokeInvitation(ctx, "inv_1", storeEpoch) }()
		wg.Wait()

		if releaseErr != nil {
			t.Fatalf("release = %v: nothing but the release can undo an acceptance", releaseErr)
		}
		pending, _ := s.PendingInvitationsForUser(ctx, "u1")
		switch {
		case revokeErr == nil:
			if len(pending) != 0 {
				t.Fatalf("revoked, and still pending: %+v", pending)
			}
			final, err := s.RevokeInvitation(ctx, "inv_1", storeEpoch)
			if !errors.Is(err, ErrInvitationNotPending) || final.RevokedAt == nil || final.AcceptedAt != nil {
				t.Fatalf("final = %+v, %v, want revoked and not accepted", final, err)
			}
		case errors.Is(revokeErr, ErrInvitationNotPending):
			if len(pending) != 1 || pending[0].AcceptedAt != nil || pending[0].RevokedAt != nil {
				t.Fatalf("the revocation lost, so the release must have won: %+v", pending)
			}
		default:
			t.Fatalf("revoke = %v", revokeErr)
		}
	}
}

// TestMemoryInvitationStorePrunesEndedRecords: an accepted or revoked record
// is kept a day, so that a second revocation still answers
// ErrInvitationNotPending, and forgotten by the next create after that, token
// index included. A pending record is never pruned, however long expired.
func TestMemoryInvitationStorePrunesEndedRecords(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryInvitationStore()
	_ = s.CreateInvitation(ctx, storeInvitation("inv_a", "ha", "ua"))
	_ = s.CreateInvitation(ctx, storeInvitation("inv_r", "hr", "ur"))
	_ = s.CreateInvitation(ctx, storeInvitation("inv_p", "hp", "up"))
	if _, err := s.ConsumeInvitation(ctx, "ha", storeEpoch); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if _, err := s.RevokeInvitation(ctx, "inv_r", storeEpoch); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	create := func(id string, at time.Time) {
		t.Helper()
		inv := storeInvitation(id, "h-"+id, "u-"+id)
		inv.CreatedAt, inv.ExpiresAt = at, at.Add(time.Hour)
		if err := s.CreateInvitation(ctx, inv); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	create("inv_x", storeEpoch.Add(memoryInvitationRetention-time.Minute))
	for _, id := range []string{"inv_a", "inv_r"} {
		if _, err := s.RevokeInvitation(ctx, id, storeEpoch); !errors.Is(err, ErrInvitationNotPending) {
			t.Fatalf("%s within the retention = %v, want ErrInvitationNotPending", id, err)
		}
	}

	create("inv_y", storeEpoch.Add(memoryInvitationRetention+time.Minute))
	for _, id := range []string{"inv_a", "inv_r"} {
		if _, err := s.RevokeInvitation(ctx, id, storeEpoch); !errors.Is(err, ErrInvitationNotFound) {
			t.Fatalf("%s past the retention = %v, want ErrInvitationNotFound", id, err)
		}
	}
	s.mu.Lock()
	records, tokens := len(s.byID), len(s.byToken)
	_, tokenKept := s.byToken["ha"]
	s.mu.Unlock()
	if records != 3 || tokens != 3 || tokenKept {
		t.Fatalf("records = %d, tokens = %d (ha kept: %v), want the three pending ones and their tokens alone", records, tokens, tokenKept)
	}
	if pending, _ := s.PendingInvitationsForUser(ctx, "up"); len(pending) != 1 {
		t.Fatalf("the long-expired pending record = %+v, want it kept", pending)
	}
}
