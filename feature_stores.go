package auth

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryAuthCodeStore is an in-process implementation of AuthCodeStore. It is
// the IDP's default and is correct only while /authorize and /token are served
// by the same process; see IDPConfig.Codes.
//
// A single mutex covers both methods, so ConsumeCode's lookup-and-delete is
// atomic and exactly one of any number of concurrent consumers receives the
// record. Expired entries are dropped on the next SaveCode so a flow the user
// abandoned does not pin memory until restart.
type MemoryAuthCodeStore struct {
	mu    sync.Mutex
	codes map[string]AuthCode
}

func NewMemoryAuthCodeStore() *MemoryAuthCodeStore {
	return &MemoryAuthCodeStore{codes: make(map[string]AuthCode)}
}

func (s *MemoryAuthCodeStore) SaveCode(_ context.Context, code AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for hash, existing := range s.codes {
		if now.After(existing.ExpiresAt) {
			delete(s.codes, hash)
		}
	}
	s.codes[code.CodeHash] = code
	return nil
}

func (s *MemoryAuthCodeStore) ConsumeCode(_ context.Context, codeHash string) (AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.codes[codeHash]
	if !ok {
		return AuthCode{}, ErrInvalidCode
	}
	delete(s.codes, codeHash)
	if time.Now().After(code.ExpiresAt) {
		return AuthCode{}, ErrInvalidCode
	}
	return code, nil
}

// MemoryIDPRefreshTokenStore is an in-process implementation of
// IDPRefreshTokenStore, and the IDP's default; see IDPConfig.RefreshTokens.
//
// One mutex covers every method, which is what makes ConsumeRefreshToken's
// check-and-mark atomic. A used token stays in the map as a tombstone until it
// expires, so that its replay is recognised; a revoked family is remembered
// until the latest expiry among its members, so that a member saved after the
// revocation is still refused. Both are swept on the next SaveRefreshToken.
type MemoryIDPRefreshTokenStore struct {
	mu     sync.Mutex
	tokens map[string]memoryIDPRefreshToken
	// revoked maps a revoked family to the time after which every member it
	// can have is expired.
	revoked map[string]time.Time
}

type memoryIDPRefreshToken struct {
	token IDPRefreshToken
	used  bool
}

func NewMemoryIDPRefreshTokenStore() *MemoryIDPRefreshTokenStore {
	return &MemoryIDPRefreshTokenStore{
		tokens:  make(map[string]memoryIDPRefreshToken),
		revoked: make(map[string]time.Time),
	}
}

func (s *MemoryIDPRefreshTokenStore) SaveRefreshToken(_ context.Context, token IDPRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for hash, entry := range s.tokens {
		if now.After(entry.token.ExpiresAt) {
			delete(s.tokens, hash)
		}
	}
	for family, until := range s.revoked {
		if now.After(until) {
			delete(s.revoked, family)
		}
	}
	if until, ok := s.revoked[token.FamilyID]; ok && token.ExpiresAt.After(until) {
		s.revoked[token.FamilyID] = token.ExpiresAt
	}
	s.tokens[token.TokenHash] = memoryIDPRefreshToken{token: token}
	return nil
}

func (s *MemoryIDPRefreshTokenStore) ConsumeRefreshToken(_ context.Context, tokenHash string) (IDPRefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.tokens[tokenHash]
	if !ok {
		return IDPRefreshToken{}, ErrInvalidToken
	}
	if time.Now().After(entry.token.ExpiresAt) {
		delete(s.tokens, tokenHash)
		return IDPRefreshToken{}, ErrInvalidToken
	}
	if _, revoked := s.revoked[entry.token.FamilyID]; revoked {
		return IDPRefreshToken{}, ErrInvalidToken
	}
	if entry.used {
		return entry.token, ErrRefreshTokenReused
	}
	entry.used = true
	s.tokens[tokenHash] = entry
	return entry.token, nil
}

func (s *MemoryIDPRefreshTokenStore) RevokeRefreshTokenFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	until := s.revoked[familyID]
	for _, entry := range s.tokens {
		if entry.token.FamilyID == familyID && entry.token.ExpiresAt.After(until) {
			until = entry.token.ExpiresAt
		}
	}
	s.revoked[familyID] = until
	return nil
}

// MemoryMetadataStore is an in-memory implementation of UserMetadataStore.
type MemoryMetadataStore struct {
	mu   sync.RWMutex
	data map[string]map[string]any
}

func NewMemoryMetadataStore() *MemoryMetadataStore {
	return &MemoryMetadataStore{data: make(map[string]map[string]any)}
}

func (s *MemoryMetadataStore) GetMetadata(_ context.Context, userID string) (map[string]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	current := s.data[userID]
	out := make(map[string]any, len(current))
	for k, v := range current {
		out[k] = v
	}
	return out, nil
}

func (s *MemoryMetadataStore) UpdateMetadata(_ context.Context, userID string, metadata map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.data[userID]
	if current == nil {
		current = make(map[string]any)
	}
	for k, v := range metadata {
		current[k] = v
	}
	s.data[userID] = current
	return nil
}

func (s *MemoryMetadataStore) ClearMetadata(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, userID)
	return nil
}

// MemoryRolesPermissionsStore is an in-memory RBAC store.
type MemoryRolesPermissionsStore struct {
	mu              sync.RWMutex
	rolePermissions map[string]map[string]struct{}
	userRoles       map[string]map[string]map[string]struct{}
}

func NewMemoryRolesPermissionsStore() *MemoryRolesPermissionsStore {
	return &MemoryRolesPermissionsStore{
		rolePermissions: make(map[string]map[string]struct{}),
		userRoles:       make(map[string]map[string]map[string]struct{}),
	}
}

func (s *MemoryRolesPermissionsStore) AddRoleToUser(_ context.Context, userID, role string, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rolePermissions[role]; !ok {
		return ErrRoleNotFound
	}
	if s.userRoles[userID] == nil {
		s.userRoles[userID] = make(map[string]map[string]struct{})
	}
	if s.userRoles[userID][tenantID] == nil {
		s.userRoles[userID][tenantID] = make(map[string]struct{})
	}
	s.userRoles[userID][tenantID][role] = struct{}{}
	return nil
}

func (s *MemoryRolesPermissionsStore) RemoveRoleFromUser(_ context.Context, userID, role string, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.userRoles[userID] != nil && s.userRoles[userID][tenantID] != nil {
		delete(s.userRoles[userID][tenantID], role)
	}
	return nil
}

func (s *MemoryRolesPermissionsStore) GetRolesForUser(_ context.Context, userID, tenantID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userScoped := s.userRoles[userID]
	if userScoped == nil {
		return nil, nil
	}
	rolesMap := userScoped[tenantID]
	roles := make([]string, 0, len(rolesMap))
	for role := range rolesMap {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles, nil
}

func (s *MemoryRolesPermissionsStore) CreateRole(_ context.Context, role string, permissions []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	permSet := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		permSet[permission] = struct{}{}
	}
	s.rolePermissions[role] = permSet
	return nil
}

func (s *MemoryRolesPermissionsStore) DeleteRole(_ context.Context, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rolePermissions, role)
	for userID := range s.userRoles {
		for tenantID := range s.userRoles[userID] {
			delete(s.userRoles[userID][tenantID], role)
		}
	}
	return nil
}

func (s *MemoryRolesPermissionsStore) AddPermissionToRole(_ context.Context, role, permission string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rolePermissions[role] == nil {
		s.rolePermissions[role] = make(map[string]struct{})
	}
	s.rolePermissions[role][permission] = struct{}{}
	return nil
}

func (s *MemoryRolesPermissionsStore) RemovePermissionFromRole(_ context.Context, role, permission string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rolePermissions[role], permission)
	return nil
}

func (s *MemoryRolesPermissionsStore) GetPermissionsForRole(_ context.Context, role string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	perms := make([]string, 0, len(s.rolePermissions[role]))
	for permission := range s.rolePermissions[role] {
		perms = append(perms, permission)
	}
	sort.Strings(perms)
	return perms, nil
}

func (s *MemoryRolesPermissionsStore) GetPermissionsForUser(ctx context.Context, userID, tenantID string) ([]string, error) {
	roles, err := s.GetRolesForUser(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	permissions := make([]string, 0, len(roles)*2)
	for _, role := range roles {
		perms, err := s.GetPermissionsForRole(ctx, role)
		if err != nil {
			return nil, err
		}
		for _, permission := range perms {
			if _, ok := seen[permission]; ok {
				continue
			}
			seen[permission] = struct{}{}
			permissions = append(permissions, permission)
		}
	}
	sort.Strings(permissions)
	return permissions, nil
}

func (s *MemoryRolesPermissionsStore) UserHasPermission(ctx context.Context, userID, permission, tenantID string) (bool, error) {
	permissions, err := s.GetPermissionsForUser(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	for _, current := range permissions {
		if current == permission {
			return true, nil
		}
	}
	return false, nil
}

// MemoryTenantStore is an in-memory tenant/membership store.
type MemoryTenantStore struct {
	mu          sync.RWMutex
	byID        map[string]Tenant
	userTenants map[string]map[string]struct{}
	tenantUsers map[string]map[string]struct{}
}

func NewMemoryTenantStore() *MemoryTenantStore {
	return &MemoryTenantStore{
		byID:        make(map[string]Tenant),
		userTenants: make(map[string]map[string]struct{}),
		tenantUsers: make(map[string]map[string]struct{}),
	}
}

func (s *MemoryTenantStore) CreateTenant(_ context.Context, tenant Tenant) (Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[tenant.ID]; exists {
		return Tenant{}, ErrAlreadyExists
	}
	s.byID[tenant.ID] = tenant
	return tenant, nil
}

func (s *MemoryTenantStore) GetTenantByID(_ context.Context, id string) (Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tenant, ok := s.byID[id]
	if !ok {
		return Tenant{}, ErrTenantNotFound
	}
	return tenant, nil
}

func (s *MemoryTenantStore) GetAllTenants(_ context.Context) ([]Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, 0, len(s.byID))
	for _, tenant := range s.byID {
		out = append(out, tenant)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemoryTenantStore) UpdateTenant(_ context.Context, id string, update Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.byID[id]
	if !ok {
		return ErrTenantNotFound
	}
	current.Name = update.Name
	current.IsActive = update.IsActive
	current.Config = update.Config
	s.byID[id] = current
	return nil
}

func (s *MemoryTenantStore) DeleteTenant(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
	delete(s.tenantUsers, id)
	for userID := range s.userTenants {
		delete(s.userTenants[userID], id)
	}
	return nil
}

func (s *MemoryTenantStore) AssociateUserWithTenant(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[tenantID]; !ok {
		return ErrTenantNotFound
	}
	if s.userTenants[userID] == nil {
		s.userTenants[userID] = make(map[string]struct{})
	}
	if s.tenantUsers[tenantID] == nil {
		s.tenantUsers[tenantID] = make(map[string]struct{})
	}
	s.userTenants[userID][tenantID] = struct{}{}
	s.tenantUsers[tenantID][userID] = struct{}{}
	return nil
}

func (s *MemoryTenantStore) DisassociateUserFromTenant(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.userTenants[userID] != nil {
		delete(s.userTenants[userID], tenantID)
	}
	if s.tenantUsers[tenantID] != nil {
		delete(s.tenantUsers[tenantID], userID)
	}
	return nil
}

func (s *MemoryTenantStore) GetTenantsForUser(_ context.Context, userID string) ([]Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, 0, len(s.userTenants[userID]))
	for tenantID := range s.userTenants[userID] {
		if tenant, ok := s.byID[tenantID]; ok {
			out = append(out, tenant)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemoryTenantStore) GetUsersForTenant(_ context.Context, tenantID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.tenantUsers[tenantID]))
	for userID := range s.tenantUsers[tenantID] {
		out = append(out, userID)
	}
	sort.Strings(out)
	return out, nil
}

// GetAllRoles makes MemoryRolesPermissionsStore satisfy RoleLister: every role
// CreateRole has defined, name-ascending, matching GetPermissionsForRole and
// GetRolesForUser above.
//
// The set is rolePermissions, not the roles users happen to hold. A role created
// and assigned to nobody is still a role — GET /admin/api/roles exists to show
// exactly that — and a role with no permissions is too, since CreateRole with an
// empty list creates one.
func (s *MemoryRolesPermissionsStore) GetAllRoles(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	roles := make([]string, 0, len(s.rolePermissions))
	for role := range s.rolePermissions {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles, nil
}
