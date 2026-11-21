package auth

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// MemoryInvitationStore is the in-process InvitationStore: a map of records by
// id and an index of ids by token hash, behind one mutex, which is what makes
// ConsumeInvitation and RevokeInvitation atomic against each other.
//
// Like MemoryAuthCodeStore it is correct only while every request is served by
// the same process, and it keeps every record it was given — accepted and
// revoked ones included — for the life of the process. A deployment with more
// than one instance, or one that restarts, supplies a shared store; see
// InvitationStore for what that store owes.
type MemoryInvitationStore struct {
	mu      sync.Mutex
	byID    map[string]Invitation
	byToken map[string]string
}

// NewMemoryInvitationStore creates an empty store.
func NewMemoryInvitationStore() *MemoryInvitationStore {
	return &MemoryInvitationStore{
		byID:    make(map[string]Invitation),
		byToken: make(map[string]string),
	}
}

// CreateInvitation stores a new invitation. An empty id or token hash is
// refused, and so is an id or a hash the store already holds
// (ErrAlreadyExists): both are random, so a collision is a caller's bug.
func (s *MemoryInvitationStore) CreateInvitation(_ context.Context, invitation Invitation) error {
	if invitation.ID == "" || invitation.TokenHash == "" {
		return errors.New("auth: invitation needs an id and a token hash")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.byID[invitation.ID]; taken {
		return ErrAlreadyExists
	}
	if _, taken := s.byToken[invitation.TokenHash]; taken {
		return ErrAlreadyExists
	}
	s.byID[invitation.ID] = cloneInvitation(invitation)
	s.byToken[invitation.TokenHash] = invitation.ID
	return nil
}

// ConsumeInvitation accepts the pending, unexpired invitation stored under
// tokenHash, once: AcceptedAt is set to now and the record returned. Anything
// else is ErrInvitationNotFound.
func (s *MemoryInvitationStore) ConsumeInvitation(_ context.Context, tokenHash string, now time.Time) (Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byToken[tokenHash]
	if !ok {
		return Invitation{}, ErrInvitationNotFound
	}
	invitation, ok := s.byID[id]
	if !ok || !invitation.Pending() || invitation.Expired(now) {
		return Invitation{}, ErrInvitationNotFound
	}
	accepted := now
	invitation.AcceptedAt = &accepted
	s.byID[id] = invitation
	return cloneInvitation(invitation), nil
}

// RevokeInvitation revokes the pending invitation id, expired or not. An
// accepted or already revoked one is returned unchanged with
// ErrInvitationNotPending; an unknown id is ErrInvitationNotFound.
func (s *MemoryInvitationStore) RevokeInvitation(_ context.Context, id string, now time.Time) (Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invitation, ok := s.byID[id]
	if !ok {
		return Invitation{}, ErrInvitationNotFound
	}
	if !invitation.Pending() {
		return cloneInvitation(invitation), ErrInvitationNotPending
	}
	revoked := now
	invitation.RevokedAt = &revoked
	s.byID[id] = invitation
	return cloneInvitation(invitation), nil
}

// ListPendingInvitations pages the invitations neither accepted nor revoked,
// expired ones included, by ID ascending.
func (s *MemoryInvitationStore) ListPendingInvitations(_ context.Context, limit, offset int) ([]Invitation, error) {
	return pageOf(s.pending(func(Invitation) bool { return true }), limit, offset), nil
}

// PendingInvitationsForUser returns userID's invitations neither accepted nor
// revoked, expired ones included, by ID ascending.
func (s *MemoryInvitationStore) PendingInvitationsForUser(_ context.Context, userID string) ([]Invitation, error) {
	return s.pending(func(invitation Invitation) bool { return invitation.UserID == userID }), nil
}

// pending collects the pending records that match, ordered by ID, each a copy.
func (s *MemoryInvitationStore) pending(match func(Invitation) bool) []Invitation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Invitation, 0)
	for _, invitation := range s.byID {
		if invitation.Pending() && match(invitation) {
			out = append(out, cloneInvitation(invitation))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// cloneInvitation copies the parts of a record that would otherwise be shared:
// the metadata map and the two timestamps behind pointers.
func cloneInvitation(invitation Invitation) Invitation {
	invitation.Metadata = copyMetadata(invitation.Metadata)
	if invitation.AcceptedAt != nil {
		at := *invitation.AcceptedAt
		invitation.AcceptedAt = &at
	}
	if invitation.RevokedAt != nil {
		at := *invitation.RevokedAt
		invitation.RevokedAt = &at
	}
	return invitation
}
