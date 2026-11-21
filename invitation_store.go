package auth

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// memoryInvitationRetention is how long MemoryInvitationStore keeps a record
// after it was accepted or revoked. Within it a second revocation still
// answers ErrInvitationNotPending, the 409 of the admin route; past it the
// record is forgotten, token index included, and the same call answers
// ErrInvitationNotFound, the 404. A pending record — expired or not — is
// never pruned: it stays listed until it is revoked.
const memoryInvitationRetention = 24 * time.Hour

// MemoryInvitationStore is the in-process InvitationStore: a map of records by
// id, an index of ids by token hash and one of the pending ids by user, behind
// one mutex, which is what makes ConsumeInvitation, RevokeInvitation and
// ReleaseInvitation atomic against one another.
//
// Like MemoryAuthCodeStore it is correct only while every request is served by
// the same process. It keeps a pending record until it is accepted or revoked,
// and an accepted or revoked one for a day after that; each CreateInvitation
// forgets the records that ended before then, so what the store holds is
// bounded by the invitations outstanding and the ones that ended recently, not
// by every invitation ever made. The listings read the pending index and never
// the ended records. A deployment with more than one instance, or one that
// restarts, supplies a shared store; see InvitationStore for what that store
// owes.
type MemoryInvitationStore struct {
	mu      sync.Mutex
	byID    map[string]Invitation
	byToken map[string]string
	// pendingByUser holds the ids of the pending records, by user id.
	pendingByUser map[string]map[string]struct{}
}

// NewMemoryInvitationStore creates an empty store.
func NewMemoryInvitationStore() *MemoryInvitationStore {
	return &MemoryInvitationStore{
		byID:          make(map[string]Invitation),
		byToken:       make(map[string]string),
		pendingByUser: make(map[string]map[string]struct{}),
	}
}

// CreateInvitation stores a new invitation. An empty id or token hash is
// refused, and so is an id or a hash the store already holds
// (ErrAlreadyExists): both are random, so a collision is a caller's bug.
//
// It first forgets the records that ended more than a day before the new
// one's CreatedAt.
func (s *MemoryInvitationStore) CreateInvitation(_ context.Context, invitation Invitation) error {
	if invitation.ID == "" || invitation.TokenHash == "" {
		return errors.New("auth: invitation needs an id and a token hash")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(invitation.CreatedAt)
	if _, taken := s.byID[invitation.ID]; taken {
		return ErrAlreadyExists
	}
	if _, taken := s.byToken[invitation.TokenHash]; taken {
		return ErrAlreadyExists
	}
	s.byID[invitation.ID] = cloneInvitation(invitation)
	s.byToken[invitation.TokenHash] = invitation.ID
	if invitation.Pending() {
		s.indexPendingLocked(invitation)
	}
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
	s.unindexPendingLocked(invitation)
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
	s.unindexPendingLocked(invitation)
	return cloneInvitation(invitation), nil
}

// ReleaseInvitation returns invitation id to pending when it is accepted at
// acceptedAt and not revoked. Anything else is ErrInvitationNotFound and
// changes nothing.
func (s *MemoryInvitationStore) ReleaseInvitation(_ context.Context, id string, acceptedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	invitation, ok := s.byID[id]
	if !ok || invitation.AcceptedAt == nil || invitation.RevokedAt != nil || !invitation.AcceptedAt.Equal(acceptedAt) {
		return ErrInvitationNotFound
	}
	invitation.AcceptedAt = nil
	s.byID[id] = invitation
	s.indexPendingLocked(invitation)
	return nil
}

// ListPendingInvitations pages the invitations neither accepted nor revoked,
// expired ones included, by ID ascending.
func (s *MemoryInvitationStore) ListPendingInvitations(_ context.Context, limit, offset int) ([]Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Invitation, 0)
	for _, ids := range s.pendingByUser {
		out = s.appendRecordsLocked(out, ids)
	}
	return pageOf(sortInvitations(out), limit, offset), nil
}

// PendingInvitationsForUser returns userID's invitations neither accepted nor
// revoked, expired ones included, by ID ascending.
func (s *MemoryInvitationStore) PendingInvitationsForUser(_ context.Context, userID string) ([]Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortInvitations(s.appendRecordsLocked(make([]Invitation, 0), s.pendingByUser[userID])), nil
}

// appendRecordsLocked appends a copy of the record of each id.
func (s *MemoryInvitationStore) appendRecordsLocked(out []Invitation, ids map[string]struct{}) []Invitation {
	for id := range ids {
		if invitation, ok := s.byID[id]; ok {
			out = append(out, cloneInvitation(invitation))
		}
	}
	return out
}

func (s *MemoryInvitationStore) indexPendingLocked(invitation Invitation) {
	ids, ok := s.pendingByUser[invitation.UserID]
	if !ok {
		ids = make(map[string]struct{})
		s.pendingByUser[invitation.UserID] = ids
	}
	ids[invitation.ID] = struct{}{}
}

func (s *MemoryInvitationStore) unindexPendingLocked(invitation Invitation) {
	ids := s.pendingByUser[invitation.UserID]
	delete(ids, invitation.ID)
	if len(ids) == 0 {
		delete(s.pendingByUser, invitation.UserID)
	}
}

// pruneLocked forgets the records that were accepted or revoked more than
// memoryInvitationRetention before now, with their token index entries.
func (s *MemoryInvitationStore) pruneLocked(now time.Time) {
	cutoff := now.Add(-memoryInvitationRetention)
	for id, invitation := range s.byID {
		ended := invitation.AcceptedAt
		if ended == nil {
			ended = invitation.RevokedAt
		}
		if ended == nil || !ended.Before(cutoff) {
			continue
		}
		delete(s.byID, id)
		if s.byToken[invitation.TokenHash] == id {
			delete(s.byToken, invitation.TokenHash)
		}
	}
}

// sortInvitations orders records by ID, ascending.
func sortInvitations(invitations []Invitation) []Invitation {
	sort.Slice(invitations, func(i, j int) bool { return invitations[i].ID < invitations[j].ID })
	return invitations
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
