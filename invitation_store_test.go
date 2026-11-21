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
