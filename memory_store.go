package auth

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// MemoryUserStore is a thread-safe in-memory implementation of UserStore.
type MemoryUserStore struct {
	mu                 sync.RWMutex
	byID               map[string]User
	byEmail            map[string]string
	byResetToken       map[string]string
	byMagicToken       map[string]string
	byVerifyToken      map[string]string
	byEmailChangeToken map[string]string
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		byID:               make(map[string]User),
		byEmail:            make(map[string]string),
		byResetToken:       make(map[string]string),
		byMagicToken:       make(map[string]string),
		byVerifyToken:      make(map[string]string),
		byEmailChangeToken: make(map[string]string),
	}
}

func userEmailKey(email, tenantID string) string {
	return tenantID + ":" + normalizeEmail(email)
}

func (s *MemoryUserStore) CreateUser(_ context.Context, user User) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[user.ID]; ok {
		return User{}, ErrUserExists
	}
	key := userEmailKey(user.Email, user.TenantID)
	if _, ok := s.byEmail[key]; ok {
		return User{}, ErrUserExists
	}
	s.byID[user.ID] = user
	s.byEmail[key] = user.ID
	return user, nil
}

func (s *MemoryUserStore) GetUserByEmail(_ context.Context, email, tenantID string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := userEmailKey(email, tenantID)
	id, ok := s.byEmail[key]
	if !ok {
		return User{}, errors.New("user not found")
	}
	u, ok := s.byID[id]
	if !ok {
		return User{}, errors.New("user not found")
	}
	return u, nil
}

func (s *MemoryUserStore) GetUserByID(_ context.Context, id, tenantID string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok || u.TenantID != tenantID {
		return User{}, errors.New("user not found")
	}
	return u, nil
}

// FindUserByID makes MemoryUserStore satisfy UserLookupStore: GetUserByID
// without the tenant comparison. byID is keyed on the id alone and CreateUser
// refuses an id another tenant already holds, so there is never a second record
// to choose between.
func (s *MemoryUserStore) FindUserByID(_ context.Context, id string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok {
		return User{}, errors.New("user not found")
	}
	return u, nil
}

func (s *MemoryUserStore) UpdateProfile(_ context.Context, userID, tenantID, firstName, lastName string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return User{}, errors.New("user not found")
	}
	u.FirstName = firstName
	u.LastName = lastName
	u.UpdatedAt = time.Now()
	s.byID[userID] = u
	return u, nil
}

func (s *MemoryUserStore) DeleteUser(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	delete(s.byID, userID)
	delete(s.byEmail, userEmailKey(u.Email, u.TenantID))
	if u.ResetTokenHash != "" {
		delete(s.byResetToken, u.ResetTokenHash)
	}
	if u.MagicLinkTokenHash != "" {
		delete(s.byMagicToken, u.MagicLinkTokenHash)
	}
	if u.EmailVerificationTokenHash != "" {
		delete(s.byVerifyToken, u.EmailVerificationTokenHash)
	}
	if u.EmailChangeTokenHash != "" {
		delete(s.byEmailChangeToken, u.EmailChangeTokenHash)
	}
	return nil
}

func (s *MemoryUserStore) UpdatePassword(_ context.Context, userID, tenantID, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.PasswordHash = passwordHash
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateResetToken(_ context.Context, userID, tenantID, tokenHash string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.ResetTokenHash != "" {
		delete(s.byResetToken, u.ResetTokenHash)
	}
	u.ResetTokenHash = tokenHash
	u.ResetTokenExpiresAt = &expiry
	s.byResetToken[tokenHash] = userID
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) GetUserByResetTokenHash(_ context.Context, tokenHash string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.byResetToken[tokenHash]
	if !ok {
		return User{}, ErrInvalidToken
	}
	u, ok := s.byID[uid]
	if !ok {
		return User{}, ErrInvalidToken
	}
	return u, nil
}

func (s *MemoryUserStore) ClearResetToken(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.ResetTokenHash != "" {
		delete(s.byResetToken, u.ResetTokenHash)
	}
	u.ResetTokenHash = ""
	u.ResetTokenExpiresAt = nil
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateMagicLinkToken(_ context.Context, userID, tenantID, tokenHash string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.MagicLinkTokenHash != "" {
		delete(s.byMagicToken, u.MagicLinkTokenHash)
	}
	u.MagicLinkTokenHash = tokenHash
	u.MagicLinkTokenExpiresAt = &expiry
	s.byMagicToken[tokenHash] = userID
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) GetUserByMagicLinkTokenHash(_ context.Context, tokenHash string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.byMagicToken[tokenHash]
	if !ok {
		return User{}, ErrInvalidToken
	}
	u, ok := s.byID[uid]
	if !ok {
		return User{}, ErrInvalidToken
	}
	return u, nil
}

func (s *MemoryUserStore) ClearMagicLinkToken(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.MagicLinkTokenHash != "" {
		delete(s.byMagicToken, u.MagicLinkTokenHash)
	}
	u.MagicLinkTokenHash = ""
	u.MagicLinkTokenExpiresAt = nil
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateSMSCode(_ context.Context, userID, tenantID, codeHash string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.SMSCodeHash = codeHash
	u.SMSCodeExpiresAt = &expiry
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) GetUserBySMSCodeHash(_ context.Context, userID, tenantID, codeHash string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return User{}, ErrInvalidCode
	}
	if !secureEqual(u.SMSCodeHash, codeHash) {
		return User{}, ErrInvalidCode
	}
	return u, nil
}

func (s *MemoryUserStore) ClearSMSCode(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.SMSCodeHash = ""
	u.SMSCodeExpiresAt = nil
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateTOTPSecret(_ context.Context, userID, tenantID, secret string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.TOTPSecret = secret
	u.IsTOTPEnabled = enabled
	s.byID[userID] = u
	return nil
}

// UpdateRequire2FA makes MemoryUserStore satisfy UserTwoFactorPolicyStore, which
// with ListUsers above is what turns the admin console's twoFAPolicy section on.
// It writes the one flag and touches nothing else; see the interface.
func (s *MemoryUserStore) UpdateRequire2FA(_ context.Context, userID, tenantID string, required bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.Require2FA = required
	s.byID[userID] = u
	return nil
}

// UpdateIsAdmin makes MemoryUserStore satisfy UserAdminFlagStore, which is what
// POST <admin>/users/:id/promote needs for method=flag. It writes the one flag
// and touches nothing else; see the interface.
func (s *MemoryUserStore) UpdateIsAdmin(_ context.Context, userID, tenantID string, isAdmin bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.IsAdmin = isAdmin
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateEmailVerificationToken(_ context.Context, userID, tenantID, tokenHash string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.EmailVerificationTokenHash != "" {
		delete(s.byVerifyToken, u.EmailVerificationTokenHash)
	}
	u.EmailVerificationTokenHash = tokenHash
	u.EmailVerificationTokenExpiry = &expiry
	s.byVerifyToken[tokenHash] = userID
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) GetUserByEmailVerificationTokenHash(_ context.Context, tokenHash string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.byVerifyToken[tokenHash]
	if !ok {
		return User{}, ErrInvalidToken
	}
	u, ok := s.byID[uid]
	if !ok {
		return User{}, ErrInvalidToken
	}
	return u, nil
}

func (s *MemoryUserStore) MarkEmailVerified(_ context.Context, userID, tenantID string, verified bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.IsEmailVerified = verified
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) ClearEmailVerificationToken(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.EmailVerificationTokenHash != "" {
		delete(s.byVerifyToken, u.EmailVerificationTokenHash)
	}
	u.EmailVerificationTokenHash = ""
	u.EmailVerificationTokenExpiry = nil
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateEmailChangeToken(_ context.Context, userID, tenantID, pendingEmail, tokenHash string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.EmailChangeTokenHash != "" {
		delete(s.byEmailChangeToken, u.EmailChangeTokenHash)
	}
	u.PendingEmail = normalizeEmail(pendingEmail)
	u.EmailChangeTokenHash = tokenHash
	u.EmailChangeTokenExpiry = &expiry
	s.byEmailChangeToken[tokenHash] = userID
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) GetUserByEmailChangeTokenHash(_ context.Context, tokenHash string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.byEmailChangeToken[tokenHash]
	if !ok {
		return User{}, ErrInvalidToken
	}
	u, ok := s.byID[uid]
	if !ok {
		return User{}, ErrInvalidToken
	}
	return u, nil
}

func (s *MemoryUserStore) ApplyEmailChange(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	oldKey := userEmailKey(u.Email, u.TenantID)
	newKey := userEmailKey(u.PendingEmail, u.TenantID)
	if _, exists := s.byEmail[newKey]; exists {
		return ErrUserExists
	}
	delete(s.byEmail, oldKey)
	u.Email = u.PendingEmail
	u.PendingEmail = ""
	s.byEmail[newKey] = u.ID
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) ClearEmailChangeToken(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.EmailChangeTokenHash != "" {
		delete(s.byEmailChangeToken, u.EmailChangeTokenHash)
	}
	u.EmailChangeTokenHash = ""
	u.EmailChangeTokenExpiry = nil
	u.PendingEmail = ""
	s.byID[userID] = u
	return nil
}

// MemorySessionStore is a thread-safe in-memory implementation of SessionStore.
type MemorySessionStore struct {
	mu            sync.RWMutex
	byID          map[string]Session
	byTokenHashed map[string]string
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		byID:          make(map[string]Session),
		byTokenHashed: make(map[string]string),
	}
}

func (s *MemorySessionStore) CreateSession(_ context.Context, session Session) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[session.ID] = session
	s.byTokenHashed[session.RefreshTokenHash] = session.ID
	return session, nil
}

func (s *MemorySessionStore) GetSessionByRefreshTokenHash(_ context.Context, tokenHash string) (Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sid, ok := s.byTokenHashed[tokenHash]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	session, ok := s.byID[sid]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	return session, nil
}

func (s *MemorySessionStore) GetSessionByID(_ context.Context, sessionID string) (Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.byID[sessionID]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	return session, nil
}

func (s *MemorySessionStore) UpdateSession(_ context.Context, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.byID[session.ID]
	if !ok {
		return ErrSessionNotFound
	}
	if current.RefreshTokenHash != session.RefreshTokenHash {
		delete(s.byTokenHashed, current.RefreshTokenHash)
		s.byTokenHashed[session.RefreshTokenHash] = session.ID
	}
	s.byID[session.ID] = session
	return nil
}

func (s *MemorySessionStore) ListSessionsForUser(_ context.Context, userID, tenantID string) ([]Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Session, 0)
	for _, session := range s.byID {
		if session.UserID == userID && session.TenantID == tenantID {
			out = append(out, session)
		}
	}
	// Same order as GetAllSessions below, for the same reason: the range above is
	// over a map, so without this the device list a user sees at GET /sessions is
	// shuffled on every call. Nothing could have depended on the previous order —
	// there was not one — so fixing it here is free.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemorySessionStore) RevokeSessionByID(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.byID[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	now := time.Now()
	session.RevokedAt = &now
	s.byID[sessionID] = session
	return nil
}

func (s *MemorySessionStore) DeleteExpiredSessions(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for id, session := range s.byID {
		if now.After(session.ExpiresAt) {
			delete(s.byID, id)
			delete(s.byTokenHashed, session.RefreshTokenHash)
			deleted++
		}
	}
	return deleted, nil
}

// pageOf applies the limit/offset contract the three admin listers share to an
// already-ordered slice, and is the one place that contract is implemented: a
// non-positive limit is an empty page, a negative offset is read as zero, an
// offset at or past the end is an empty page, and no result ever aliases items.
//
// The copy is not defensive tidiness. items is built out of the store's own maps
// while the lock is held, and a caller handed a sub-slice of it would be holding
// a window onto memory the store still owns; a fresh slice is what lets the doc
// on the three interfaces promise the page belongs to the caller.
func pageOf[T any](items []T, limit, offset int) []T {
	if limit <= 0 || offset >= len(items) {
		return []T{}
	}
	if offset < 0 {
		offset = 0
	}
	// end < 0 is offset+limit overflowing int, which a limit parsed out of a
	// query string can reach; it means "everything from offset", same as an end
	// past the tail.
	end := offset + limit
	if end > len(items) || end < 0 {
		end = len(items)
	}
	page := make([]T, end-offset)
	copy(page, items[offset:end])
	return page
}

// ListUsers makes MemoryUserStore satisfy AdminUserStore, and with it defines
// the order this package calls normative: User.ID ascending, by Go string
// comparison. See AdminUserStore for why the order is a contract and not an
// implementation detail, and for what tenantID does and does not select — in
// particular that an empty tenantID lists every user rather than only the users
// stored under the empty tenant.
func (s *MemoryUserStore) ListUsers(_ context.Context, tenantID string, limit, offset int) ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := make([]User, 0, len(s.byID))
	for _, user := range s.byID {
		if tenantID != "" && user.TenantID != tenantID {
			continue
		}
		all = append(all, user)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return pageOf(all, limit, offset), nil
}

// GetAllSessions makes MemorySessionStore satisfy SessionLister: every session
// of every user, ordered by Session.ID ascending, paged by the shared rules.
//
// Revoked and expired sessions are both included, which is what SessionLister
// specifies and what ListSessionsForUser beside it already does — this store
// tombstones rather than deletes, so dropping the dead ones belongs above the
// store, not in it.
func (s *MemorySessionStore) GetAllSessions(_ context.Context, limit, offset int) ([]Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := make([]Session, 0, len(s.byID))
	for _, session := range s.byID {
		all = append(all, session)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return pageOf(all, limit, offset), nil
}
