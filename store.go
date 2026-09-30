package auth

import (
	"context"
	"time"
)

// UserStore persists and resolves users.
type UserStore interface {
	CreateUser(ctx context.Context, user User) (User, error)
	GetUserByEmail(ctx context.Context, email, tenantID string) (User, error)
	GetUserByID(ctx context.Context, id, tenantID string) (User, error)
}

// UserAccountStore adds account lifecycle operations.
type UserAccountStore interface {
	UpdateProfile(ctx context.Context, userID, tenantID, firstName, lastName string) (User, error)
	DeleteUser(ctx context.Context, userID, tenantID string) error
}

// SessionStore persists refresh-token sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, session Session) (Session, error)
	GetSessionByRefreshTokenHash(ctx context.Context, tokenHash string) (Session, error)
	UpdateSession(ctx context.Context, session Session) error
}

// SessionLookupStore resolves sessions by session ID.
type SessionLookupStore interface {
	GetSessionByID(ctx context.Context, sessionID string) (Session, error)
}

// UserPasswordStore adds password lifecycle methods.
type UserPasswordStore interface {
	UpdatePassword(ctx context.Context, userID, tenantID, passwordHash string) error
	UpdateResetToken(ctx context.Context, userID, tenantID, tokenHash string, expiry time.Time) error
	GetUserByResetTokenHash(ctx context.Context, tokenHash string) (User, error)
	ClearResetToken(ctx context.Context, userID, tenantID string) error
}

// MagicLinkStore persists magic link state.
type MagicLinkStore interface {
	UpdateMagicLinkToken(ctx context.Context, userID, tenantID, tokenHash string, expiry time.Time) error
	GetUserByMagicLinkTokenHash(ctx context.Context, tokenHash string) (User, error)
	ClearMagicLinkToken(ctx context.Context, userID, tenantID string) error
}

// SMSStore persists sms code state.
type SMSStore interface {
	UpdateSMSCode(ctx context.Context, userID, tenantID, codeHash string, expiry time.Time) error
	GetUserBySMSCodeHash(ctx context.Context, userID, tenantID, codeHash string) (User, error)
	ClearSMSCode(ctx context.Context, userID, tenantID string) error
}

// TOTPStore persists authenticator setup.
type TOTPStore interface {
	UpdateTOTPSecret(ctx context.Context, userID, tenantID, secret string, enabled bool) error
}

// UserTwoFactorPolicyStore sets the require-2FA flag on one user. It is the
// reference's optional IUserStore.updateRequire2FA — a method its interface does
// not declare and which the admin router reaches for with a `typeof … ===
// 'function'` test (admin.router.ts:827, :649) — expressed here the way
// SessionAdminStore and AdminUserStore are: a narrow interface the core
// type-asserts the configured store to, with the assertion's failure answering
// the reference's own 501.
//
// It has exactly one consumer, POST /admin/api/2fa-policy, which walks the whole
// user table in pages of 100 and calls this once per row. Two consequences
// follow for an implementor:
//
//   - It is called N times for a table of N users and it is not batched. That is
//     the reference's shape (admin.router.ts:843) and there is no bulk form to
//     offer instead, because the route has no transaction either: a failure
//     part-way leaves the prefix already written and answers 500.
//   - It must write the flag and nothing else. The route is a policy switch and
//     the value it carries is the administrator's; a store that also cleared a
//     TOTP secret or revoked a session on the way through would be making a
//     decision the route did not ask for and the reference does not make.
//
// tenantID is the parameter the reference has not got, added for the reason
// every other write in this file carries one: the walk lists users across every
// tenant, so the row's own TenantID is the only thing that says which user an id
// names. Together with AdminUserStore it is also what turns the console's
// twoFAPolicy feature flag on — the reference requires both methods for the same
// flag (:649-650).
type UserTwoFactorPolicyStore interface {
	UpdateRequire2FA(ctx context.Context, userID, tenantID string, required bool) error
}

// UserAdminFlagStore sets User.IsAdmin on one user. It is the seam POST
// <admin>/users/:id/promote needs for method=flag, and the assertion's failure
// is that route's 501.
//
// # Why it is one flag and not the reference's patch
//
// The dev line's seam is a *general* writer: it casts the configured store to
// `IUserStore & { update?(userId, patch: Partial<BaseUser>): Promise<void> }`
// and calls it with the object literal `{isAdmin: true}` (node-auth
// admin.router.ts:1035-1040, the type at :212-214). A faithful transcription
// would be `Update(ctx, userID string, patch map[string]any) error` or a
// *User-shaped patch type, and both were declined:
//
//   - Partial<T> has no Go counterpart that keeps the field names checked. A
//     map[string]any patch moves every field name from the compiler to a
//     string literal, on the one call in this package that grants somebody the
//     admin console.
//   - The route is the interface's only consumer and writes one field. A seam
//     wider than its consumer is a seam an implementor has to guess the
//     contract of — "which fields may arrive, and what does a store do with one
//     it does not persist?" — and nothing in either tree answers that, because
//     nothing in either tree calls update with any other patch.
//
// So it is narrowed to what the route actually does, the way
// UserTwoFactorPolicyStore is narrowed to the one flag its route writes. The
// wire is unaffected: the 501 a store that does not implement this gets is the
// reference's own message, naming the reference's own method.
//
// # What an implementor owes
//
// Write the flag and nothing else. This is the field the 'is-admin-flag' access
// policy reads (admin.go, AdminPolicyIsAdminFlag) — a store that also granted a
// role, or cleared one, would be making an authorisation decision the route did
// not ask for and the reference does not make. It is also why there is no
// revoke beside it: neither tree has a route that clears the flag, and adding
// one here would be a product decision rather than a port. AuthConfigurator's
// revokeAdmin is the dev line's only such site and it is a facade method, not a
// route (node-auth auth-configurator.ts:133).
//
// tenantID is the parameter the reference has not got, carried for the reason
// UserAccountStore.DeleteUser carries one: every seam on this surface has it, so
// a store implements one convention rather than two. The route passes "",
// because the reference's update(id, patch) addresses a user by id alone — see
// (*Auth).adminPromoteUser for what that costs a multi-tenant deployment, which
// is exactly what DELETE <admin>/api/users/:id already costs it.
type UserAdminFlagStore interface {
	UpdateIsAdmin(ctx context.Context, userID, tenantID string, isAdmin bool) error
}

// EmailVerificationStore persists verification flow.
type EmailVerificationStore interface {
	UpdateEmailVerificationToken(ctx context.Context, userID, tenantID, tokenHash string, expiry time.Time) error
	GetUserByEmailVerificationTokenHash(ctx context.Context, tokenHash string) (User, error)
	MarkEmailVerified(ctx context.Context, userID, tenantID string, verified bool) error
	ClearEmailVerificationToken(ctx context.Context, userID, tenantID string) error
}

// EmailChangeStore persists pending email change flow.
type EmailChangeStore interface {
	UpdateEmailChangeToken(ctx context.Context, userID, tenantID, pendingEmail, tokenHash string, expiry time.Time) error
	GetUserByEmailChangeTokenHash(ctx context.Context, tokenHash string) (User, error)
	ApplyEmailChange(ctx context.Context, userID, tenantID string) error
	ClearEmailChangeToken(ctx context.Context, userID, tenantID string) error
}

// SessionAdminStore exposes session listing and cleanup primitives.
type SessionAdminStore interface {
	ListSessionsForUser(ctx context.Context, userID, tenantID string) ([]Session, error)
	RevokeSessionByID(ctx context.Context, sessionID string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error)
}

// UserMetadataStore manages arbitrary key/value user metadata.
type UserMetadataStore interface {
	GetMetadata(ctx context.Context, userID string) (map[string]any, error)
	UpdateMetadata(ctx context.Context, userID string, metadata map[string]any) error
	ClearMetadata(ctx context.Context, userID string) error
}

// RolesPermissionsStore manages RBAC assignments and permissions.
type RolesPermissionsStore interface {
	AddRoleToUser(ctx context.Context, userID, role string, tenantID string) error
	RemoveRoleFromUser(ctx context.Context, userID, role string, tenantID string) error
	GetRolesForUser(ctx context.Context, userID, tenantID string) ([]string, error)
	CreateRole(ctx context.Context, role string, permissions []string) error
	DeleteRole(ctx context.Context, role string) error
	AddPermissionToRole(ctx context.Context, role, permission string) error
	RemovePermissionFromRole(ctx context.Context, role, permission string) error
	GetPermissionsForRole(ctx context.Context, role string) ([]string, error)
	GetPermissionsForUser(ctx context.Context, userID, tenantID string) ([]string, error)
	UserHasPermission(ctx context.Context, userID, permission, tenantID string) (bool, error)
}

// The three admin listers — AdminUserStore, SessionLister and RoleLister —
// are the store seams M8's admin router needs in order to enumerate anything.
//
// The reference declares exactly three optional methods for that surface:
// IUserStore.listUsers (user-store.interface.ts:130), ISessionStore.getAllSessions
// (session-store.interface.ts:91) and IRolesPermissionsStore.getAllRoles
// (roles-permissions-store.interface.ts:155). All three are optional there and
// all three are optional here, by the convention SessionAdminStore and
// UserMetadataStore already follow: a narrow interface the core type-asserts the
// configured store to, answering ErrFeatureNotSupported when the assertion
// fails. That sentinel is what the router turns into the reference's own status
// — `501 {error: 'IUserStore.listUsers is not implemented', users: [], total: 0}`
// (admin.router.ts:754) and its two siblings (:1093, :1133).
//
// No route in this package consumes them yet; M8 does. They ship now because the
// seam is what a store implementor builds against, and because one of them is the
// bottleneck of the whole admin surface: until this interface existed, the only
// way for this package to reach a user whose id it did not already hold was
// TenantStore.GetUsersForTenant, so a single-tenant deployment whose tenant had
// no membership rows had nothing to page through at all.
//
// # Ordering
//
// All three answer in a total order, and that order is part of the contract
// rather than an implementation detail, because two of the reference's own
// consumers depend on it:
//
//   - The 'first-user' access policy hands the admin surface to
//     `listUsers(1, 0)[0]`, described as "the first registered user (lowest-ID)"
//     (admin.router.ts:27; the check is at :373-374). A store with no order gives
//     the console to an arbitrary user, and to a different one after a restart.
//   - POST /admin/api/2fa-policy walks the entire table in pages of 100 —
//     `listUsers(batchSize, offset)` until a page comes back shorter than the
//     batch (admin.router.ts:836-847). Without an order that is stable across
//     those calls the walk silently skips users and updates others twice.
//
// The reference does not itself supply that order. Every implementation it ships
// is `SELECT * FROM users LIMIT ? OFFSET ?` with no ORDER BY
// (sqlite-user-store.example.ts:305, mysql-user-store.example.ts:356),
// `find({}).skip().limit()` in natural order (mongodb-user-store.example.ts:327),
// or a Map's insertion order (in-memory-user-store.ts:175) — so "lowest-ID" is a
// promise its own stores do not keep. This port keeps it. The normative order is
// **ID ascending, by Go string comparison**: MemoryUserStore sorts on User.ID,
// MemorySessionStore on Session.ID, MemoryRolesPermissionsStore on the role name,
// which is what every other list method in this package already does
// (TenantStore.GetAllTenants, GetUsersForTenant, RolesPermissionsStore.GetRolesForUser).
// A store whose natural key order differs — a single-table design with a
// tenant-prefixed sort key, say — may answer in its own order, but that is a
// deviation its own register has to carry, not a licence this one grants.
//
// # Paging
//
// limit and offset are the reference's, positionally and in meaning, and the
// rules below bind all three interfaces:
//
//   - limit <= 0 returns an empty page and no error. The 2fa-policy walk
//     terminates on a short page, so a store that reads a non-positive limit as
//     "no limit" turns a malformed query string into a full-table update.
//   - offset < 0 is read as 0; an offset at or past the end returns an empty page
//     rather than an error.
//   - A page shorter than limit means nothing follows it. That is the walk's
//     termination condition, so a store may not return a short page mid-list.
//   - The slice belongs to the caller and shares no backing array with the store.
//
// There is deliberately no Count method. `GET /admin/api/users` reports
// `safe.length + offset + (safe.length === limit ? 1 : 0)` (admin.router.ts:782),
// a number whose only job is to tell the table whether to draw a "next" button
// and which is off by one whenever the last page happens to be full; the sessions
// route computes the same thing (:1109). Reproducing that is M8's work and needs
// no store support, whereas a real count is the one query a keyed store cannot
// serve cheaply — and no reference consumer asks for it.

// AdminUserStore lists users for the admin surface. It is the reference's
// IUserStore.listUsers (user-store.interface.ts:130) with one parameter added.
//
// # What tenantID means, and what it does not
//
// tenantID filters on User.TenantID: the column every user record already
// carries, and which userEmailKey already makes part of a user's identity. It is
// *not* a membership query. TenantStore.AssociateUserWithTenant and
// GetUsersForTenant (tenant-store.interface.ts:112) answer "which users belong to
// this tenant", a many-to-many relation kept in its own table, and this interface
// deliberately never consults it: a user whose TenantID is "acme" and who is
// additionally associated with "globex" is listed under "acme" and nowhere else.
// Keeping the two apart is the point of the parameter — the membership join is
// precisely the reachability dead end this interface exists to route around, and
// answering listing out of it would rebuild the dead end inside the fix.
//
// An empty tenantID is the one place in this package where an empty tenant is a
// wildcard rather than a literal: it means no filter at all — every user, in
// every tenant, including users whose own TenantID is empty. Everywhere else in
// store.go, "" is an ordinary tenant value matching only records stored under it.
// The exception is not cosmetic. GET /admin/api/users takes no tenant parameter
// (admin.router.ts:748 onwards) and neither does the 'first-user' policy's
// `listUsers(1, 0)` (:373), so "every user" has to be expressible, and the
// reference's signature — which carries no tenant at all — says that is the
// default reading. The ambiguity this introduces is unobservable in the
// deployment that would suffer from it: where every user's TenantID is empty,
// filtering on the empty tenant and not filtering at all return the same set —
// which is the single-tenant deployment, the common one. It becomes
// observable only in a tree that mixes tenanted users with untenanted ones, which
// is migration residue rather than a configuration.
//
// # Why the parameter exists
//
// The reference has no tenancy on this route, so the faithful signature is
// ListUsers(ctx, limit, offset) and a multi-tenant console would filter the page
// after the fact. That is wrong in the direction that matters: filtering after
// the page has been cut means a tenant with ten users is invisible behind a
// hundred thousand belonging to someone else, and every route above it inherits
// the problem. Pushing the predicate into the store instead costs one parameter,
// is what every other user-facing method in store.go already does, and — see
// below — is the form a keyed store can actually satisfy. U13 passes "" and gets
// the reference's behaviour exactly.
//
// # Implementing it on a key-value store
//
// The first implementor is a DynamoDB single-table design, and the requirement
// there is that this be served without a table Scan. It can be: a secondary index
// with a *constant* partition key (GSI1PK = "USER") and a sort key of
// `<tenantID>#<id>` answers both forms as a Query — unscoped with no sort-key
// condition, scoped with begins_with(GSI1SK, tenantID+"#"). Nothing here is
// keyed on the tenant itself, which is deliberate: a tenant-partitioned index
// serves the scoped form and forces a cross-partition Scan for the unscoped one,
// which is the form the reference's only consumers use.
//
// Two honest limits on that. First, the constant partition key is a hot key under
// write load; sharding it (USER#0..USER#n) is the usual answer and costs an
// n-way merge to keep the order. Second, offset is positional, and no key-value
// store can seek to the Nth item: offset N costs reading and discarding N index
// entries. That is bounded rather than unbounded — the route clamps limit to 100
// and the filter path asks for 500 rows at offset 0 — but it is a real cost, and
// the only signature that removes it is a cursor, which cannot express the
// reference's `total` arithmetic and would change the wire. Offset stays.
//
// The `<tenantID>#<id>` sort key above orders the unscoped listing by
// (TenantID, ID) rather than by ID alone. That is a deviation from the normative
// order documented above, and the store that makes it registers it.
type AdminUserStore interface {
	ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]User, error)
}

// UserLookupStore resolves a user by id alone, in whichever tenant holds it. It
// is the reference's IUserStore.findById (user-store.interface.ts:5), which
// carries no tenant because nothing in the reference's user model has one to
// carry.
//
// # Why it is not GetUserByID
//
// UserStore.GetUserByID carries a tenant and reads "" as a literal: the tenant
// whose id is the empty string. That reading is load-bearing. Its other callers
// pass a tenant they already hold — the access token's tid on /me and /refresh,
// the tenant an OAuth state or an IDP code was minted for, the one a request
// named — and a "" that widened to every tenant there would let a token issued
// in the empty tenant, or a request that named none, resolve an account in any
// other. So that reading cannot change, and the one caller that has an id and no
// tenant needs a method of its own.
//
// That caller is the admin console. GET <admin>/api/users lists every user in
// every tenant, because AdminUserStore.ListUsers is the one method in this file
// that reads "" as a wildcard. GET <admin>/api/users/:id then has to find the
// user the listing showed, with no tenant to pass, because the reference's route
// has none (admin.router.ts:789-800). Through GetUserByID(id, "") the console
// listed users its own detail route answered 404 for, in exactly the deployment
// that stores users under a tenant. This interface is how the two routes agree.
//
// There is no tenant parameter at all, rather than one that is "" for a
// wildcard. A third reading of the empty tenant in one file is the ambiguity
// this interface exists to remove, and a signature with nothing to pass says
// what it does.
//
// # What an implementor owes
//
//   - Match on User.ID alone, whatever the record's TenantID is, the empty
//     tenant included. The returned User carries its own TenantID, which is how
//     a caller learns where the user lives.
//   - A user that is not there is an error. As with GetUserByID there is no
//     sentinel, and the one route consuming this answers 404 for any error.
//   - Never choose between two records. The method is sound only because a user
//     id names at most one user across every tenant — the precondition the
//     reference's findById rests on, and one this package's tenant-less seams
//     (UserMetadataStore, LinkedAccountStore, TenantStore.GetTenantsForUser)
//     already assume. MemoryUserStore enforces it at CreateUser, and the ids the
//     core mints are 128 random bits (newID), but a store keyed on (tenant, id)
//     can hold one id twice if a host supplied it. Such a store answers an error
//     for that id rather than either record: an operator shown the wrong
//     account's detail is worse off than one shown none.
//
// # Implementing it on a key-value store
//
// The directory index AdminUserStore describes cannot serve this. Its sort key
// is <tenantID>#<id>, so the id is the suffix, and a key condition matches a
// sort key only by equality, range or prefix: an id behind an unknown tenant is
// reachable only by reading the whole directory partition and filtering it,
// which costs what a Scan costs. What serves it is an item keyed on the id
// alone. That is either a pointer written beside the profile, the way a store
// already keeps an email pointer for GetUserByEmail, or an index entry keyed on
// the user id that the store already writes for another reason —
// GetTenantsForUser needs one. The second costs no new write, but a lookup
// through it has that entry's lifecycle: if a membership can be removed while
// the user stays, the lookup loses the user with it.
//
// # Optional, with a fallback
//
// A store without it is not refused. The admin route falls back to
// GetUserByID(id, ""), which is what it did before this interface existed and
// is the right answer for every single-tenant deployment; see the
// admin-user-detail-spans-tenants-only-through-a-lookup-store deviation.
type UserLookupStore interface {
	FindUserByID(ctx context.Context, id string) (User, error)
}

// SessionLister lists sessions across all users, for the admin sessions table.
// It is the reference's ISessionStore.getAllSessions (session-store.interface.ts:91),
// consumed by GET /admin/api/sessions (admin.router.ts:1086 onwards).
//
// Unlike AdminUserStore this carries no tenantID, and the asymmetry is
// deliberate rather than an oversight. The tenant parameter on the user lister
// buys reachability: without it, a tenant's users can only be found through a
// membership table that a single-tenant deployment never populates. Sessions have
// no such dead end — every session is already listable, and Session.TenantID
// rides on each record returned — so a tenant parameter here would buy a
// predicate a caller can apply itself, at the price of a second signature the
// reference does not have. GET /admin/api/sessions has no tenant notion either.
//
// The order is Session.ID ascending, and the paging rules are the ones stated
// above.
//
// Nothing is filtered out. Revoked and expired sessions are both returned, which
// matches SessionAdminStore.ListSessionsForUser and is the same division of
// labour: this port tombstones a revoked session rather than deleting it, because
// /refresh needs the tombstone to answer SESSION_REVOKED instead of "not found",
// so dropping the dead ones is the presentation layer's job and Auth.ListSessions
// is where it already happens. The reference's interface doc says "all active
// sessions" (session-store.interface.ts:85) and gets that for free, because its
// revokeSession deletes the row. A store that also deletes is therefore not in
// conflict with this rule — it simply has nothing to return.
type SessionLister interface {
	GetAllSessions(ctx context.Context, limit, offset int) ([]Session, error)
}

// RoleLister enumerates every role name defined in the store. It is the
// reference's IRolesPermissionsStore.getAllRoles (roles-permissions-store.interface.ts:155),
// consumed by GET /admin/api/roles (admin.router.ts:1129 onwards).
//
// It is separate from RolesPermissionsStore rather than a method on it for the
// same reason the reference marks it optional: every other method there is keyed
// on a role, a user or a permission the caller already names, and a store can
// serve all of them without ever being able to enumerate. Folding this in would
// make the whole RBAC surface unimplementable for such a store.
//
// There is no limit/offset, matching the reference — the roles of a deployment
// are a bounded, human-authored set, and the route pairs each name with its
// permissions in a fan-out it makes no attempt to page (admin.router.ts:1136-1141).
// The order is the role name ascending, matching GetPermissionsForRole and
// GetRolesForUser. Roles with no permissions are still roles and are still
// listed; CreateRole with an empty permission list creates one.
type RoleLister interface {
	GetAllRoles(ctx context.Context) ([]string, error)
}

// AuthCode is one OIDC authorization code as the IDP stores it between
// /authorize and /token. CodeHash is hashToken of the value the client was
// given; the clear-text code is never persisted. RedirectURI is the canonical
// entry from IDPClient.RedirectURIs that the authorization request matched.
// CodeChallenge and CodeChallengeMethod are the PKCE pair of the
// authorization request (RFC 7636), which /authorize accepts only as S256 and
// /token verifies against the code_verifier when a challenge was recorded.
// Scope is the requested scope, space-separated: offline_access in it is what
// makes /token issue a refresh token, and the refresh_token grant narrows
// within it.
type AuthCode struct {
	CodeHash            string
	UserID              string
	TenantID            string
	ClientID            string
	Nonce               string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	ExpiresAt           time.Time
}

// AuthCodeStore persists OIDC authorization codes for the IDP.
//
// Design note. The IDP endpoints are net-new relative to the TypeScript
// reference, which ships no authorization server, so there is no wire contract
// to cite; the shape below is chosen for the runtimes this library targets.
//
//   - The store is keyed by hashToken(code), never by the code itself. The
//     client carries a 24-byte random token in the redirect; the store sees
//     only its SHA-256, so a dump of the backing table cannot be redeemed at
//     /token. This matches how refresh tokens, reset tokens and magic links
//     are already held.
//   - ConsumeCode is the only read and it is destructive: it returns a record
//     exactly once and answers ErrInvalidCode for every later call with the
//     same hash, including concurrent ones. That is the single-use guarantee
//     /token relies on. It used to come from a process-local map, which holds
//     only while /authorize and /token run in the same process; a serverless
//     or multi-instance deployment must supply a shared implementation via
//     IDPConfig.Codes, and its ConsumeCode must be atomic (a conditional
//     delete, a row lock, or a DEL-and-check pipeline, not a read followed by a
//     delete).
//   - An expired record is absent: ConsumeCode returns ErrInvalidCode for it
//     and is free to delete it. Implementations may also sweep expired rows on
//     SaveCode or on a schedule. The handler re-checks ExpiresAt regardless.
//   - SaveCode overwrites an existing record with the same CodeHash. The codes
//     are random, so in practice this never happens; the rule exists so an
//     implementation need not detect the collision.
//   - Errors other than ErrInvalidCode are surfaced by /authorize and /token as
//     plain 500s; the store is not expected to map them.
type AuthCodeStore interface {
	SaveCode(ctx context.Context, code AuthCode) error
	ConsumeCode(ctx context.Context, codeHash string) (AuthCode, error)
}

// IDPRefreshToken is one refresh token the IDP's token endpoint issued, as the
// store holds it. TokenHash is hashToken of the value the client was given; the
// clear-text token is never persisted.
//
// Every token minted by rotating another shares its FamilyID, ClientID,
// UserID, TenantID, SessionID, Scope and ExpiresAt, so a family is one grant:
// one authorization code redeemed with offline_access, and everything rotated
// from it. SessionID is the session that redemption opened, whose access
// tokens every refresh mints. Scope is the scope the code was granted, which
// RFC 6749 §6 keeps on every rotated token even when a refresh request narrows
// the access token's. ExpiresAt is the family's absolute end — the session's
// expiry — and rotation never extends it.
type IDPRefreshToken struct {
	TokenHash string
	FamilyID  string
	ClientID  string
	UserID    string
	TenantID  string
	SessionID string
	Scope     string
	ExpiresAt time.Time
}

// IDPRefreshTokenStore persists the refresh tokens of the IDP's refresh_token
// grant. It is a separate store from AuthCodeStore and from the SessionStore:
// the token is opaque, single-use, and rotated on every use, and a family is
// revoked as a whole when a used token comes back (RFC 6819 §5.2.2.3, RFC 9700
// §4.14.2).
//
// What an implementation must guarantee — the handler relies on each point and
// checks none of them twice, except the expiry:
//
//   - Keyed by hashToken(token), never by the token. A dump of the table must
//     not be redeemable.
//   - SaveRefreshToken stores a new, unused token. Hashes are random, so an
//     implementation need not detect a collision; it may overwrite.
//   - ConsumeRefreshToken is atomic, and exactly one call ever returns a nil
//     error for a given hash, however many run concurrently and on however many
//     processes: a conditional update from unused to used, not a read followed
//     by a write. The token is marked used, not deleted.
//   - A second ConsumeRefreshToken of a used token returns the record together
//     with ErrRefreshTokenReused, so the IDP learns the family to revoke. This
//     is why a used token has to be kept, as a tombstone, until its ExpiresAt.
//   - An unknown or expired token, and any token of a revoked family, is
//     absent: ConsumeRefreshToken returns ErrInvalidToken and no record.
//   - RevokeRefreshTokenFamily is permanent and covers every member of the
//     family, including one saved after the revocation. Rotation is a consume
//     followed by a save, and a concurrent replay can revoke the family between
//     the two; the token saved afterwards must still be refused. A revoked
//     family can be forgotten once its ExpiresAt has passed, since every member
//     is expired by then. Revoking an unknown family is not an error.
//   - Errors other than the two sentinels are answered by /token as a 500
//     server_error; the store is not expected to map them.
//
// MemoryIDPRefreshTokenStore is the in-process implementation and the default.
// Like MemoryAuthCodeStore it is correct only while every /token request is
// served by the same process.
type IDPRefreshTokenStore interface {
	SaveRefreshToken(ctx context.Context, token IDPRefreshToken) error
	ConsumeRefreshToken(ctx context.Context, tokenHash string) (IDPRefreshToken, error)
	RevokeRefreshTokenFamily(ctx context.Context, familyID string) error
}

// TenantStore manages tenants and user memberships.
type TenantStore interface {
	CreateTenant(ctx context.Context, tenant Tenant) (Tenant, error)
	GetTenantByID(ctx context.Context, id string) (Tenant, error)
	GetAllTenants(ctx context.Context) ([]Tenant, error)
	UpdateTenant(ctx context.Context, id string, update Tenant) error
	DeleteTenant(ctx context.Context, id string) error
	AssociateUserWithTenant(ctx context.Context, userID, tenantID string) error
	DisassociateUserFromTenant(ctx context.Context, userID, tenantID string) error
	GetTenantsForUser(ctx context.Context, userID string) ([]Tenant, error)
	GetUsersForTenant(ctx context.Context, tenantID string) ([]string, error)
}
