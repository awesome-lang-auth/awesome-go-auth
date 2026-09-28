package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The read half of the admin API: fourteen routes, every one of them a GET,
// mounted behind the guard U12 built.
//
// M8 is split by class of risk rather than by route count, and the invariant
// this file carries is shape against shape — each response body is the
// reference handler's, field for field, and nothing here writes. The three
// files that follow own the mutations, the secret redaction and the upload
// surface; the two reads that belong to those classes rather than to this one
// (GET /api/api-keys at :1253 and GET /api/webhooks at :1363) are deliberately
// absent, because the webhook listing masks its secret to "***" and reviewing
// that apart from the writes that set the value is how a masking rule gets
// missed.
//
// # What every route here has in common
//
//   - It is mounted with AdminGuard.Protect, never ProtectShell. The marker
//     branch belongs to the login shell alone; see the
//     admin-unauthenticated-get-serves-only-the-login-form deviation for what
//     GET /admin/api/users would otherwise be.
//   - Its errors are {"error": "…"} — writeAdminError — and not the auth
//     router's HTTPError envelope. The admin router is a second router and
//     carries none of the first one's conventions.
//   - A store it needs and does not have is a 404 naming the store, and a store
//     it has that cannot enumerate is a 501 naming the method. Those are two
//     different absences and the reference keeps them apart by asking whether it
//     was given a store, never by reading an error (:1130 against :1133); this
//     port's ErrFeatureNotSupported collapses them, so the check on the store
//     comes first and the sentinel is only ever read afterwards.
//   - A list is always a non-nil slice, so an empty one serialises as [] and not
//     as null. Every shipped client iterates these.
//
// # What none of them establishes
//
// None reads AdminUserFromContext. The principal is unavailable under
// AdminPolicyOpen and under the legacy secret — both authorise without
// identifying — and no route in the reference's read half consults req.user
// either: the console shows the deployment, not the administrator. A route that
// did need an id would have to handle the false second result rather than
// assume it.

// The read routes, relative to the admin mount. Eight are fixed paths; the six
// that carry a path parameter are matched by matchAdminRead below.
const (
	AdminUsersPath         = "/api/users"          // admin.router.ts:748
	AdminActionsPath       = "/api/actions"        // admin.router.ts:946
	AdminSettingsPath      = "/api/settings"       // admin.router.ts:951
	AdminSessionsPath      = "/api/sessions"       // admin.router.ts:1086
	AdminRolesPath         = "/api/roles"          // admin.router.ts:1129
	AdminTenantsPath       = "/api/tenants"        // admin.router.ts:1176
	AdminMailTemplatesPath = "/api/templates/mail" // admin.router.ts:1448
	AdminUITemplatesPath   = "/api/templates/ui"   // admin.router.ts:1470
)

// adminReadRoute names one of the fourteen. It exists because six of them carry
// a parameter, which the path-equality cases in AdminHandler cannot express, and
// splitting the family across two shapes would put half the route table in the
// switch and half here.
type adminReadRoute int

const (
	adminRouteNone adminReadRoute = iota
	adminRouteUsers
	adminRouteUserByID
	adminRouteUserMetadata
	adminRouteUserLinkedAccounts
	adminRouteUserRoles
	adminRouteUserTenants
	adminRouteActions
	adminRouteSettings
	adminRouteSessions
	adminRouteRoles
	adminRouteTenants
	adminRouteTenantUsers
	adminRouteMailTemplates
	adminRouteUITemplates
)

// matchAdminRead classifies a path below the admin mount, returning the route
// and its decoded parameter.
//
// rel is the *escaped* path, and that is the whole reason this does not simply
// read r.URL.Path. Express matches its route patterns against the raw pathname
// and decodes each captured parameter afterwards (layer.js decode_param), so a
// user id containing %2F is one segment there and reaches the handler as a
// string with a slash in it. r.URL.Path is already decoded, and splitting it
// would see two segments and match nothing. The auth router's unlink route
// settled this the same way (account.go, adapter/nethttp/oauth.go), and the
// answer is the same here.
func matchAdminRead(rel string) (adminReadRoute, string) {
	switch rel {
	case AdminUsersPath:
		return adminRouteUsers, ""
	case AdminActionsPath:
		return adminRouteActions, ""
	case AdminSettingsPath:
		return adminRouteSettings, ""
	case AdminSessionsPath:
		return adminRouteSessions, ""
	case AdminRolesPath:
		return adminRouteRoles, ""
	case AdminTenantsPath:
		return adminRouteTenants, ""
	case AdminMailTemplatesPath:
		return adminRouteMailTemplates, ""
	case AdminUITemplatesPath:
		return adminRouteUITemplates, ""
	}
	if id, tail, ok := adminPathParam(rel, AdminUsersPath); ok {
		switch tail {
		case "":
			return adminRouteUserByID, id
		case "/metadata":
			return adminRouteUserMetadata, id
		case "/linked-accounts":
			return adminRouteUserLinkedAccounts, id
		case "/roles":
			return adminRouteUserRoles, id
		case "/tenants":
			return adminRouteUserTenants, id
		}
		return adminRouteNone, ""
	}
	if id, tail, ok := adminPathParam(rel, AdminTenantsPath); ok && tail == "/users" {
		return adminRouteTenantUsers, id
	}
	return adminRouteNone, ""
}

// adminPathParam splits "<prefix>/<:param>[<tail>]", returning the parameter
// decoded and the tail as it was.
//
// The parameter is one segment and never empty, which is what Express's ":id"
// matches. A segment whose percent-encoding does not decode is no match at all;
// net/http has already refused a request whose path could not be parsed, so the
// branch is unreachable in practice and is written as a miss rather than as a
// status of its own.
func adminPathParam(rel, prefix string) (param, tail string, ok bool) {
	if !strings.HasPrefix(rel, prefix+"/") {
		return "", "", false
	}
	rest := rel[len(prefix)+1:]
	segment := rest
	if cut := strings.IndexByte(rest, '/'); cut >= 0 {
		segment, tail = rest[:cut], rest[cut:]
	}
	if segment == "" {
		return "", "", false
	}
	decoded, err := url.PathUnescape(segment)
	if err != nil {
		return "", "", false
	}
	return decoded, tail, true
}

// adminReadRegistered reports whether the reference registers this route in
// this deployment at all.
//
// Twelve of the fourteen are registered unconditionally and answer their own
// 404 when the store they need is absent. The two template listings are not:
// they sit inside `if (featTemplates && options.templateStore)` (:1444), so a
// deployment with no template store has no such route rather than a guarded one
// — which is why this is asked in AdminHandler, before the guard, and not
// inside the handler. An unregistered route answers Express's own 404 to an
// anonymous caller; a registered one behind the guard would answer 401.
func (a *Auth) adminReadRegistered(route adminReadRoute) bool {
	switch route {
	case adminRouteNone:
		return false
	case adminRouteMailTemplates, adminRouteUITemplates:
		return a.service.cfg.Templates != nil
	default:
		return true
	}
}

// serveAdminRead dispatches one classified read. It runs behind Protect, so
// everything below may assume an authorised caller and nothing below may assume
// an identified one.
func (a *Auth) serveAdminRead(w http.ResponseWriter, r *http.Request, route adminReadRoute, param string) {
	switch route {
	case adminRouteUsers:
		a.adminListUsers(w, r)
	case adminRouteUserByID:
		a.adminGetUser(w, r, param)
	case adminRouteUserMetadata:
		a.adminGetUserMetadata(w, r, param)
	case adminRouteUserLinkedAccounts:
		a.adminGetUserLinkedAccounts(w, r, param)
	case adminRouteUserRoles:
		a.adminGetUserRoles(w, r, param)
	case adminRouteUserTenants:
		a.adminGetUserTenants(w, r, param)
	case adminRouteActions:
		a.adminListActions(w, r)
	case adminRouteSettings:
		a.adminGetSettings(w, r)
	case adminRouteSessions:
		a.adminListSessions(w, r)
	case adminRouteRoles:
		a.adminListRoles(w, r)
	case adminRouteTenants:
		a.adminListTenants(w, r)
	case adminRouteTenantUsers:
		a.adminListTenantUsers(w, r, param)
	case adminRouteMailTemplates:
		a.adminListMailTemplates(w, r)
	case adminRouteUITemplates:
		a.adminListUITranslations(w, r)
	default:
		http.NotFound(w, r)
	}
}

// ── users ────────────────────────────────────────────────────────────────────

// adminUserRow is the projection GET <admin>/api/users answers with
// (admin.router.ts:764-773). It is hand-picked there and hand-picked here: the
// eight keys are the reference's eight, in its order.
//
// It is deliberately not PublicUser. Three of these keys PublicUser does not
// carry (require2FA, phoneNumber, createdAt) and three of PublicUser's this does
// not (sub, loginProvider, tenantId), because the two shapes answer different
// questions — PublicUser is what a user is told about themselves, this is what
// an operator is shown about everybody.
//
// isAdmin is absent, and its absence is the reference's rather than a choice
// made here: the reference serialises that field nowhere at all, this route
// included. See User.IsAdmin.
//
// The three optional strings and createdAt are omitempty because the
// reference's values are `undefined` for a store that does not carry them —
// every one of role, phoneNumber, isEmailVerified, isTotpEnabled and require2FA
// is optional on BaseUser (user.model.ts:5, :26, :32, :37, :39) and createdAt is
// not declared on it at all, which is why the handler reaches for it through an
// index expression — and JSON.stringify omits an undefined member rather than
// writing null. The three booleans are emitted unconditionally instead: Go
// cannot tell a stored false from an absent field, and false is what every store
// that has the column reports.
type adminUserRow struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	Role            string     `json:"role,omitempty"`
	IsEmailVerified bool       `json:"isEmailVerified"`
	IsTOTPEnabled   bool       `json:"isTotpEnabled"`
	Require2FA      bool       `json:"require2FA"`
	PhoneNumber     string     `json:"phoneNumber,omitempty"`
	CreatedAt       *time.Time `json:"createdAt,omitempty"`
}

func newAdminUserRow(user User) adminUserRow {
	row := adminUserRow{
		ID:              user.ID,
		Email:           user.Email,
		Role:            user.Role,
		IsEmailVerified: user.IsEmailVerified,
		IsTOTPEnabled:   user.IsTOTPEnabled,
		Require2FA:      user.Require2FA,
		PhoneNumber:     user.PhoneNumber,
	}
	if !user.CreatedAt.IsZero() {
		createdAt := user.CreatedAt
		row.CreatedAt = &createdAt
	}
	return row
}

// adminUserDetail is GET <admin>/api/users/:id's body (:793-796), and it is
// five keys where the table above is eight.
//
// That the detail view carries less than the row that links to it is the
// reference's, not an omission here: require2FA, phoneNumber and createdAt are
// in the list projection and not in this one. Widening it would be an
// unrequested addition to the contract on the one route an operator reads most
// closely.
type adminUserDetail struct {
	ID              string `json:"id"`
	Email           string `json:"email"`
	Role            string `json:"role,omitempty"`
	IsEmailVerified bool   `json:"isEmailVerified"`
	IsTOTPEnabled   bool   `json:"isTotpEnabled"`
}

// adminListUsers is GET <admin>/api/users (:748-786), the one route in this file
// with arithmetic of its own.
//
// Four things about it are reproduced literally rather than improved, because
// the SPA's table is written against them:
//
//   - limit defaults to 20 and is clamped to 100; offset defaults to 0. Neither
//     is clamped from below — a negative limit reaches the store, which answers
//     an empty page by the contract on AdminUserStore, and a negative offset
//     reaches both the store and the reported total.
//   - A filter fetches a 500-row batch at offset 0 and filters it in memory on
//     an email-or-id substring. It is best-effort by construction: a deployment
//     with more than 500 users cannot find the 501st by typing its address, and
//     the reference says so in a comment rather than fixing it (:759-761).
//   - The filtered page is the batch sliced [offset, offset+limit), and total is
//     the length before the slice — so under a filter total is exact.
//   - Unfiltered, total is `len(page) + offset + (len(page) == limit ? 1 : 0)`,
//     whose only job is to tell the table whether to draw a "next" button, and
//     which is off by one whenever the last page happens to be exactly full.
//     That is the arithmetic, and reproducing it is the point: a table that
//     drew no "next" where the reference drew one would be a different console.
//     There is no Count seam to do better with, deliberately — see AdminUserStore.
func (a *Auth) adminListUsers(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit := adminQueryInt(query.Get("limit"), 20)
	if limit > 100 {
		limit = 100
	}
	offset := adminQueryInt(query.Get("offset"), 0)
	filter := strings.TrimSpace(strings.ToLower(query.Get("filter")))

	batchLimit, batchOffset := limit, offset
	if filter != "" {
		batchLimit, batchOffset = 500, 0
	}

	// The tenant is "", which AdminUserStore alone reads as a wildcard: every
	// user in every tenant. That is what the reference's listUsers(limit,
	// offset) means, since it has no tenancy on this route at all.
	users, err := a.service.ListUsers(r.Context(), "", batchLimit, batchOffset)
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		// The reference checks `!userStore.listUsers` before it calls anything
		// and answers a 501 that still carries an empty page, so the table
		// renders "0 users" instead of breaking on an absent key (:753-756).
		// This is one of three answers it gives to this same missing
		// capability: the guard's 'first-user' arm answers 500 with a sentence
		// (:377, ported in AdminGuard.authorise) and the 2FA-policy walk
		// answers a bare 501 with no users/total at all (:832).
		WriteJSON(w, http.StatusNotImplemented, map[string]any{
			"error": "IUserStore.listUsers is not implemented",
			"users": []adminUserRow{},
			"total": 0,
		})
		return
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	rows := make([]adminUserRow, 0, len(users))
	for _, user := range users {
		rows = append(rows, newAdminUserRow(user))
	}

	if filter != "" {
		matched := make([]adminUserRow, 0, len(rows))
		for _, row := range rows {
			if strings.Contains(strings.ToLower(row.Email), filter) ||
				strings.Contains(strings.ToLower(row.ID), filter) {
				matched = append(matched, row)
			}
		}
		total := len(matched)
		low, high := adminSliceBounds(len(matched), offset, limit)
		WriteJSON(w, http.StatusOK, map[string]any{
			"users": matched[low:high],
			"total": total,
		})
		return
	}

	total := len(rows) + offset
	if len(rows) == limit {
		total++
	}
	WriteJSON(w, http.StatusOK, map[string]any{"users": rows, "total": total})
}

// adminGetUser is GET <admin>/api/users/:id (:789-800).
//
// The reference's findById(id) carries no tenant, and neither does anything in
// the console's read half: the listing above this route spans every tenant, so
// the id is all this route is given. adminFindUser resolves it the way the
// listing reached it.
func (a *Auth) adminGetUser(w http.ResponseWriter, r *http.Request, id string) {
	user, err := a.adminFindUser(r.Context(), id)
	if err != nil {
		// findById answers null for a user that is not there and the route
		// turns that into 404 (:791). UserStore has no not-found sentinel to
		// separate that from the store itself failing, so both are the 404 —
		// which is the reference's answer for the case that actually occurs,
		// and the one that tells a caller nothing about the store.
		writeAdminError(w, http.StatusNotFound, "User not found")
		return
	}
	WriteJSON(w, http.StatusOK, adminUserDetail{
		ID:              user.ID,
		Email:           user.Email,
		Role:            user.Role,
		IsEmailVerified: user.IsEmailVerified,
		IsTOTPEnabled:   user.IsTOTPEnabled,
	})
}

// adminFindUser resolves a user the console names by id alone.
//
// A store that implements UserLookupStore is asked across every tenant. That is
// the reference's findById, and it is what makes the detail route agree with
// GET <admin>/api/users: a user the listing shows is a user this finds.
//
// A store that does not is asked GetUserByID(id, ""), the empty tenant as a
// literal, which is what this route did before the interface existed. That is
// still right for every single-tenant deployment. In a multi-tenant one it
// answers 404 for a user the listing shows under another tenant, and the
// admin-user-detail-spans-tenants-only-through-a-lookup-store deviation records
// that rather than a 501 the reference never answers here.
//
// The fallback runs when the capability is absent, never after the lookup
// fails. A store that spans tenants and does not hold the id has already
// answered for the empty tenant too, so asking again could only disagree with it.
func (a *Auth) adminFindUser(ctx context.Context, id string) (User, error) {
	if lookup, ok := a.service.users.(UserLookupStore); ok {
		return lookup.FindUserByID(ctx, id)
	}
	return a.service.users.GetUserByID(ctx, id, "")
}

// adminGetUserMetadata is GET <admin>/api/users/:id/metadata (:855-863). The
// body is the metadata object itself, unwrapped, exactly as res.json(metadata)
// sends it.
func (a *Auth) adminGetUserMetadata(w http.ResponseWriter, r *http.Request, id string) {
	if a.service.metadata == nil {
		writeAdminError(w, http.StatusNotFound, "User metadata store not configured")
		return
	}
	metadata, err := a.service.GetMetadata(r.Context(), id)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if metadata == nil {
		// A store that answers nil for a user it holds nothing for would put
		// `null` on the wire, and the panel does Object.entries on this.
		metadata = map[string]any{}
	}
	WriteJSON(w, http.StatusOK, metadata)
}

// adminGetUserLinkedAccounts is GET <admin>/api/users/:id/linked-accounts
// (:880-887). The entries are PublicLinkedAccount, the same projection
// GET <prefix>/linked-accounts already answers with, because the reference's two
// routes both hand back the store's LinkedAccount records unchanged.
func (a *Auth) adminGetUserLinkedAccounts(w http.ResponseWriter, r *http.Request, id string) {
	if a.oauth == nil || a.oauth.LinkedAccounts == nil {
		writeAdminError(w, http.StatusNotFound, "Linked accounts store not configured")
		return
	}
	accounts, err := a.ListLinkedAccounts(r.Context(), id)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"linkedAccounts": accounts})
}

// adminGetUserRoles is GET <admin>/api/users/:id/roles (:893-901).
//
// The tenant is "", because the reference's getRolesForUser(id) carries none —
// and unlike adminGetUser's, this "" is not a gap UserLookupStore closes. The
// tenant here is RolesPermissionsStore's: the scope of an *assignment*, not the
// tenant a user record is stored under. The console's own writers assign in the
// empty scope — POST /api/users/:id/roles with no tenantId, and POST
// <admin>/users/:id/promote with method=role — so reading "" is what shows an
// operator the roles the console just gave. Resolving the user and reading
// under its TenantID instead would hide every one of them in a multi-tenant
// deployment: the same listed-but-missing mismatch, moved from the user to the
// role.
//
// enrichFromStores reads a user's roles under that user's own tenant, so an
// assignment made here in the empty scope does not reach the tokens of a user
// stored under another tenant. That is a question about the RBAC scope rather
// than about where a user lives, and it is not this route's to settle.
func (a *Auth) adminGetUserRoles(w http.ResponseWriter, r *http.Request, id string) {
	if a.service.rbac == nil {
		writeAdminError(w, http.StatusNotFound, "RBAC store not configured")
		return
	}
	roles, err := a.service.rbac.GetRolesForUser(r.Context(), id, "")
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"roles": adminStrings(roles)})
}

// adminGetUserTenants is GET <admin>/api/users/:id/tenants (:933-941). The route
// asks the store for whole tenants and answers with their ids alone
// (`tenants.map(t => t.id)`), which is what the user panel's tenant picker
// reads.
func (a *Auth) adminGetUserTenants(w http.ResponseWriter, r *http.Request, id string) {
	if a.service.tenants == nil {
		writeAdminError(w, http.StatusNotFound, "Tenant store not configured")
		return
	}
	tenants, err := a.service.tenants.GetTenantsForUser(r.Context(), id)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	ids := make([]string, 0, len(tenants))
	for _, tenant := range tenants {
		ids = append(ids, tenant.ID)
	}
	WriteJSON(w, http.StatusOK, map[string]any{"tenantIds": ids})
}

// ── control ──────────────────────────────────────────────────────────────────

// adminListActions is GET <admin>/api/actions (:946-948).
//
// It is a registry listing and not a store read: there it answers
// ActionRegistry.getAllMeta(), a module-level Map that the @webhookAction
// decorator fills at import time with {id, label, category, description,
// dependsOn?} for each method a host has exposed to the inbound-webhook sandbox
// (tools/webhook-action.ts:56, :79-81).
//
// This port has no such registry. The settings half of the same feature is here
// — AuthSettings.EnabledWebhookActions is the administrator's allowlist, and
// WebhookConfig.AllowedActions the per-subscription subset — but nothing
// registers an action, because the sandbox that would call one is the tools
// router, which this port has not reached. So the answer is the one the
// reference gives for an empty registry, which is the answer a deployment that
// has decorated nothing already gets there: an empty list. Inventing a
// registration seam to fill it would be inventing the half of the feature that
// decides what a webhook may execute, which is not a read-only PR's to design.
func (a *Auth) adminListActions(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]any{"actions": []any{}})
}

// adminGetSettings is GET <admin>/api/settings (:951-959). The body is the
// settings object itself, unwrapped; AuthSettings.MarshalJSON is what keeps a
// cleared enabledWebhookActions on the wire as [] rather than dropping it.
func (a *Auth) adminGetSettings(w http.ResponseWriter, r *http.Request) {
	store := a.service.cfg.Settings
	if store == nil {
		writeAdminError(w, http.StatusNotFound, "Settings store not configured")
		return
	}
	settings, err := store.GetSettings(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	WriteJSON(w, http.StatusOK, settings)
}

// ── sessions ─────────────────────────────────────────────────────────────────

// adminListSessions is GET <admin>/api/sessions (:1086-1112). The paging,
// filtering and total arithmetic are adminListUsers' — the reference computes
// the same expression at :1109 — with three differences, all of them this port's
// stores rather than this route's logic:
//
//   - The reference's `!options.sessionStore` 404 (:1087) has no counterpart.
//     NewService requires a session store, so one is always configured and the
//     only absence expressible here is the capability, which is the 501 below.
//   - The filter matches the user id alone. The reference also matches the
//     session's `ipAddress`, defaulted to the empty string, and this port's
//     Session carries no such column —
//     SessionInfo declares ipAddress, userAgent, lastActiveAt and data as
//     optional (session.model.ts:20-27) and none of the four is stored here, so
//     PublicSession cannot project what was never recorded.
//   - The page is whatever the store returned, revoked sessions included. This
//     port tombstones a revoked session where the reference deletes the row, so
//     its admin table never shows one; filtering them out here would return a
//     page shorter than limit, which the paging contract reserves for "nothing
//     follows" and which would silently truncate the listing at the first
//     revoked session. Auth.ListSessions is where the tombstones are dropped,
//     and it is dropping them from one user's own list, where the page is whole.
func (a *Auth) adminListSessions(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit := adminQueryInt(query.Get("limit"), 20)
	if limit > 100 {
		limit = 100
	}
	offset := adminQueryInt(query.Get("offset"), 0)
	filter := strings.TrimSpace(strings.ToLower(query.Get("filter")))

	batchLimit, batchOffset := limit, offset
	if filter != "" {
		batchLimit, batchOffset = 500, 0
	}

	sessions, err := a.service.ListAllSessions(r.Context(), batchLimit, batchOffset)
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		WriteJSON(w, http.StatusNotImplemented, map[string]any{
			"error":    "ISessionStore.getAllSessions is not implemented",
			"sessions": []PublicSession{},
			"total":    0,
		})
		return
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	rows := NewPublicSessions(sessions)
	if filter != "" {
		matched := make([]PublicSession, 0, len(rows))
		for _, row := range rows {
			if strings.Contains(strings.ToLower(row.UserID), filter) {
				matched = append(matched, row)
			}
		}
		total := len(matched)
		low, high := adminSliceBounds(len(matched), offset, limit)
		WriteJSON(w, http.StatusOK, map[string]any{
			"sessions": matched[low:high],
			"total":    total,
		})
		return
	}

	total := len(rows) + offset
	if len(rows) == limit {
		total++
	}
	WriteJSON(w, http.StatusOK, map[string]any{"sessions": rows, "total": total})
}

// ── roles ────────────────────────────────────────────────────────────────────

// adminRole is one entry of GET <admin>/api/roles: a name and the permissions
// the store holds for it (:1136-1141).
type adminRole struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// adminListRoles is GET <admin>/api/roles (:1129-1146), and it is the route that
// makes the 404/501 split visible.
//
// No RBAC store at all is a 404 (:1130). A store that cannot enumerate is a 501
// naming the optional method, and it carries an empty roles array so the tab
// renders (:1133). The reference tells the two apart by asking whether it was
// given a store, never by reading an error, and so does this: s.rbac is checked
// here, and Service.ListAllRoles' ErrFeatureNotSupported can then only mean the
// second.
//
// The permissions fan-out is unpaged, as there. The roles of a deployment are a
// bounded, human-authored set; a failure inside the fan-out lands in the same
// catch as everything else and is a 500.
func (a *Auth) adminListRoles(w http.ResponseWriter, r *http.Request) {
	if a.service.rbac == nil {
		writeAdminError(w, http.StatusNotFound, "RBAC store not configured")
		return
	}
	ctx := r.Context()
	names, err := a.service.ListAllRoles(ctx)
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		WriteJSON(w, http.StatusNotImplemented, map[string]any{
			"error": "IRolesPermissionsStore.getAllRoles is not implemented",
			"roles": []adminRole{},
		})
		return
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	roles := make([]adminRole, 0, len(names))
	for _, name := range names {
		permissions, err := a.service.rbac.GetPermissionsForRole(ctx, name)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		roles = append(roles, adminRole{Name: name, Permissions: adminStrings(permissions)})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

// ── tenants ──────────────────────────────────────────────────────────────────

// adminTenantRow is the wire shape of a Tenant, which nothing in this package
// serialised before the console did. The names and their optionality are the
// reference's Tenant interface (tenant.model.ts:10-19), which is what the admin
// SPA's tenant table reads.
//
// isActive is emitted unconditionally: it is optional there, but every tenant
// createTenant makes carries it (`isActive: isActive ?? true`, :1183) and Go
// cannot tell a stored false from an absent field.
type adminTenantRow struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	IsActive  bool           `json:"isActive"`
	Config    map[string]any `json:"config,omitempty"`
	CreatedAt *time.Time     `json:"createdAt,omitempty"`
}

func newAdminTenantRow(tenant Tenant) adminTenantRow {
	row := adminTenantRow{
		ID:       tenant.ID,
		Name:     tenant.Name,
		IsActive: tenant.IsActive,
		Config:   tenant.Config,
	}
	if !tenant.CreatedAt.IsZero() {
		createdAt := tenant.CreatedAt
		row.CreatedAt = &createdAt
	}
	return row
}

// adminListTenants is GET <admin>/api/tenants (:1176-1184).
func (a *Auth) adminListTenants(w http.ResponseWriter, r *http.Request) {
	if a.service.tenants == nil {
		writeAdminError(w, http.StatusNotFound, "Tenant store not configured")
		return
	}
	tenants, err := a.service.tenants.GetAllTenants(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	rows := make([]adminTenantRow, 0, len(tenants))
	for _, tenant := range tenants {
		rows = append(rows, newAdminTenantRow(tenant))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"tenants": rows})
}

// adminListTenantUsers is GET <admin>/api/tenants/:id/users (:1213-1221).
//
// The id is decoded twice, and that is not a slip. Express has already decoded
// the captured parameter by the time the handler runs, and this handler calls
// decodeURIComponent on it again (:1216) — so the reference addresses a tenant
// whose id contains a slash or a percent by double-encoding it, and a single
// decode here would make that tenant unreachable. The second decode is inside
// the route's try, so a value it cannot decode is the same 500 the rest of the
// body answers with, which is what the branch below reproduces.
func (a *Auth) adminListTenantUsers(w http.ResponseWriter, r *http.Request, id string) {
	if a.service.tenants == nil {
		writeAdminError(w, http.StatusNotFound, "Tenant store not configured")
		return
	}
	tenantID, err := url.PathUnescape(id)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	userIDs, err := a.service.tenants.GetUsersForTenant(r.Context(), tenantID)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"userIds": adminStrings(userIDs)})
}

// ── templates ────────────────────────────────────────────────────────────────

// adminListMailTemplates is GET <admin>/api/templates/mail (:1448-1455), and
// adminListUITranslations GET <admin>/api/templates/ui (:1470-1477). Both hand
// back the store's records unchanged — MailTemplate and UITranslation already
// carry the reference's field names — and both exist only where a template store
// does; see adminReadRegistered.
//
// Neither pages. The reference's listMailTemplates and listUiTranslations take
// no limit or offset (template-store.interface.ts:13-43), because the set is one
// row per mail the library sends and one per UI page.
func (a *Auth) adminListMailTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := a.service.cfg.Templates.ListMailTemplates(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if templates == nil {
		templates = []MailTemplate{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"templates": templates})
}

func (a *Auth) adminListUITranslations(w http.ResponseWriter, r *http.Request) {
	translations, err := a.service.cfg.Templates.ListUITranslations(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if translations == nil {
		translations = []UITranslation{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"translations": translations})
}

// ── the query string ─────────────────────────────────────────────────────────

// adminQueryInt is `parseInt(req.query[name] || '<def>', 10)` (:750-751,
// :1090-1091).
//
// An absent or empty parameter is the default, because the empty string is
// falsy and the || substitutes the literal. A value with a leading integer is
// that integer whatever follows it, because parseInt stops at the first
// character it cannot use — parseInt('12abc', 10) is 12, and the route then
// pages by 12.
//
// JavaScript answers NaN for a value with no leading integer at all, and the NaN
// flows onward through Math.min, the store call and the `safe.length === limit`
// comparison alike. An int cannot carry it, and there is no single behaviour to
// reproduce even in principle: the reference's own in-memory store slices to an
// empty page for LIMIT NaN while its SQL examples throw it into the 500 catch.
// The default is used instead, which is the answer for the only spelling a
// client sends — none — and which keeps the page and its total well-formed. The
// same substitution covers a value beyond int range, where parseInt yields a
// float and the total stops being an integer at all.
func adminQueryInt(raw string, def int) int {
	s := strings.TrimSpace(raw)
	if s == "" {
		return def
	}
	start := 0
	if s[0] == '+' || s[0] == '-' {
		start = 1
	}
	end := start
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == start {
		return def
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return def
	}
	return n
}

// adminSliceBounds is Array.prototype.slice's index normalisation, which is what
// `safe.slice(offset, offset + limit)` applies on the two filtered paths
// (:780, :1103).
//
// It matters because offset is not clamped from below anywhere in the reference:
// a negative one counts from the end there rather than from the start, so
// ?filter=a&offset=-5 answers the last five matches and not the first page.
//
// The start index is normalised into [0, length] before limit is added to it, so
// the sum cannot overflow whatever a query string put in either — limit has
// already been clamped to 100 above, and a negative one leaves an empty page.
func adminSliceBounds(length, start, limit int) (int, int) {
	n := int64(length)
	begin := int64(start)
	switch {
	case begin < -n:
		begin = 0
	case begin < 0:
		begin += n
	case begin > n:
		begin = n
	}
	end := begin + int64(limit)
	switch {
	case end < begin:
		end = begin
	case end > n:
		end = n
	}
	return int(begin), int(end)
}

// adminStrings makes a store's list safe to serialise: a nil slice would be
// null, and every client here iterates.
func adminStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
