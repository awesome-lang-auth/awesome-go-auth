package auth

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// The mutating half of the admin API: sixteen routes that change state, mounted
// behind the guard U12 built and beside the fourteen reads U13 ported.
//
// M8 is split by class of risk rather than by route count, and the invariant
// this file carries is **does it write the right row** — which store method each
// route reaches, with which arguments, and what it answers afterwards. The eight
// credential routes (the API-key and webhook halves, admin.router.ts:1250-1440)
// are deliberately absent: they go together in their own PR, whose invariant is
// secret redaction, because reviewing a masking rule apart from the writes that
// set the value it masks is how a masking rule gets missed.
//
// # What every route here has in common
//
//   - It is mounted with AdminGuard.Protect, never ProtectShell, like every read
//     beside it — a write reached through the marker branch would be worse than
//     a read reached through it.
//   - Its errors are {"error": "…"} — writeAdminError — and not the auth
//     router's HTTPError envelope.
//   - Fifteen of the sixteen answer {"success": true} and say nothing about what
//     changed. The exception is POST /api/tenants, which answers the row it
//     created, and POST /api/2fa-policy, which answers a count beside the flag.
//   - A body that will not decode leaves the zero value in every field and falls
//     into whichever validation branch that reaches, which is where
//     express.json's own failure on these routes also ends up for a client that
//     sent no usable body. adminLogin settled this shape (admin.go); the same
//     treatment is applied here rather than a second one invented.
//   - Required-field checks are the reference's falsy tests and are not trimmed.
//     `if (!role)` refuses "" and accepts " ", so a role named by a single space
//     is created on both sides.
//
// # What none of them establishes
//
// None reads AdminUserFromContext, for the reason admin_read.go gives: the
// principal is unavailable under AdminPolicyOpen and under the legacy secret,
// and no handler in the reference's admin router consults req.user either. So
// nothing here is attributed — an admin console that deletes a user records no
// actor, on both sides.
//
// # Two of the sixteen publish
//
// The two user↔role routes raise identity.role.assigned and
// identity.role.revoked (node-auth admin.router.ts:1002, :1020). The other
// fourteen raise nothing, and that is the dev line's map rather than an
// omission: no admin route publishes a user deleted, a session revoked, a
// tenant created or a role defined, although the names for all four are
// declared. event_publication_test.go pins the whole map.
//
// Both go through (*Auth).publishAdminEvent, which is why these two handlers
// take an HTTPConfig the other fourteen do not: the console sits outside
// EventContextMiddleware on both lines, so the request provenance is read off
// the request at the publication site the way the dev line's own
// publishAdminEvent reads it. That function carries the whole argument.
//
// # Existence, and what these routes do not check
//
// Not one of the six deletes looks the row up first, and not one answers 404 for
// a row that was not there: each calls its store method and answers
// {"success": true} if the call returned. That is the reference's shape and it is
// reproduced rather than tidied, because an idempotent delete that reports what
// it did is a different wire contract from one that always says success.
//
// The consequence is worth stating where a reader will meet it. The reference's
// own stores make those calls silent no-ops for a missing row — `DELETE FROM …
// WHERE id = ?` affects nothing and throws nothing — while this package's
// in-memory stores report not-found (MemoryUserStore.DeleteUser,
// MemorySessionStore.RevokeSessionByID). On such a store a repeat delete is a
// 500 here where it is a 200 there. The difference is the store's and not the
// route's: reading a not-found sentinel to synthesise success would invent a
// distinction the reference's route does not draw, which is the discipline
// admin_read.go already applies to the two absences GET /api/roles keeps apart.

// The write routes' own paths, relative to the admin mount. The other fourteen
// reuse a read path with a different method, or add a parameter to one.
const (
	// AdminTwoFAPolicyPath is the bulk require-2FA switch (admin.router.ts:820).
	AdminTwoFAPolicyPath = "/api/2fa-policy"
	// AdminSettingsUIPath is the branding patch (admin.router.ts:974). There is
	// no GET here: the UI block is read through GET /api/settings.
	AdminSettingsUIPath = "/api/settings/ui"
)

// adminWriteRoute names one of the sixteen. It is matchAdminRead's counterpart
// and exists for the same reason: ten of the sixteen carry a path parameter and
// two carry two, which the path-equality cases in AdminHandler cannot express.
type adminWriteRoute int

const (
	adminWriteNone adminWriteRoute = iota
	adminWriteDeleteUser
	adminWriteTwoFAPolicy
	adminWriteUserMetadata
	adminWriteAddUserRole
	adminWriteRemoveUserRole
	adminWriteSettings
	adminWriteSettingsUI
	adminWriteRevokeSession
	adminWriteCreateRole
	adminWriteDeleteRole
	adminWriteCreateTenant
	adminWriteDeleteTenant
	adminWriteAddTenantUser
	adminWriteRemoveTenantUser
	adminWriteMailTemplate
	adminWriteUITemplate
)

// adminWriteParams carries a matched route's path parameters, each decoded once
// — Express's own decode_param, and not the second decode several handlers
// apply on top of it.
//
// ID is the first parameter of the pattern: the user id, the session handle, the
// role name or the tenant id, depending on the route. Sub is the second where
// there is one — the role name of DELETE /api/users/:id/roles/:role, the user id
// of DELETE /api/tenants/:id/users/:userId — and empty otherwise.
type adminWriteParams struct {
	ID  string
	Sub string
}

// matchAdminWrite classifies a method and a path below the admin mount.
//
// rel is the *escaped* path, for matchAdminRead's reason exactly: Express matches
// its patterns against the raw pathname and decodes each captured parameter
// afterwards, so a parameter carrying %2F is one segment there and would be two
// here if this read r.URL.Path. The method is part of the match rather than
// checked afterwards because Express routes on both — DELETE /api/users/:id and
// GET /api/users/:id are two layers, and a path with no layer for the method
// used falls through to the router's 404.
func matchAdminWrite(method, rel string) (adminWriteRoute, adminWriteParams) {
	switch method {
	case http.MethodPost:
		switch rel {
		case AdminTwoFAPolicyPath:
			return adminWriteTwoFAPolicy, adminWriteParams{}
		case AdminRolesPath:
			return adminWriteCreateRole, adminWriteParams{}
		case AdminTenantsPath:
			return adminWriteCreateTenant, adminWriteParams{}
		case AdminMailTemplatesPath:
			return adminWriteMailTemplate, adminWriteParams{}
		case AdminUITemplatesPath:
			return adminWriteUITemplate, adminWriteParams{}
		}
		if id, tail, ok := adminPathParam(rel, AdminUsersPath); ok && tail == "/roles" {
			return adminWriteAddUserRole, adminWriteParams{ID: id}
		}
		if id, tail, ok := adminPathParam(rel, AdminTenantsPath); ok && tail == "/users" {
			return adminWriteAddTenantUser, adminWriteParams{ID: id}
		}
	case http.MethodPut:
		if rel == AdminSettingsPath {
			return adminWriteSettings, adminWriteParams{}
		}
		if id, tail, ok := adminPathParam(rel, AdminUsersPath); ok && tail == "/metadata" {
			return adminWriteUserMetadata, adminWriteParams{ID: id}
		}
	case http.MethodPatch:
		if rel == AdminSettingsUIPath {
			return adminWriteSettingsUI, adminWriteParams{}
		}
	case http.MethodDelete:
		if id, tail, ok := adminPathParam(rel, AdminUsersPath); ok {
			if tail == "" {
				return adminWriteDeleteUser, adminWriteParams{ID: id}
			}
			if role, ok := adminSubParam(tail, "/roles"); ok {
				return adminWriteRemoveUserRole, adminWriteParams{ID: id, Sub: role}
			}
			return adminWriteNone, adminWriteParams{}
		}
		if handle, tail, ok := adminPathParam(rel, AdminSessionsPath); ok && tail == "" {
			return adminWriteRevokeSession, adminWriteParams{ID: handle}
		}
		if name, tail, ok := adminPathParam(rel, AdminRolesPath); ok && tail == "" {
			return adminWriteDeleteRole, adminWriteParams{ID: name}
		}
		if id, tail, ok := adminPathParam(rel, AdminTenantsPath); ok {
			if tail == "" {
				return adminWriteDeleteTenant, adminWriteParams{ID: id}
			}
			if userID, ok := adminSubParam(tail, "/users"); ok {
				return adminWriteRemoveTenantUser, adminWriteParams{ID: id, Sub: userID}
			}
			return adminWriteNone, adminWriteParams{}
		}
	}
	return adminWriteNone, adminWriteParams{}
}

// adminSubParam splits "<prefix>/<:param>" off the tail adminPathParam left
// behind, for the two patterns that capture twice.
//
// The parameter is one segment and never empty, which is what Express's ":role"
// and ":userId" match, and nothing may follow it: the reference registers no
// route below either, so a longer path is a miss rather than a match with the
// remainder discarded.
func adminSubParam(tail, prefix string) (string, bool) {
	param, rest, ok := adminPathParam(tail, prefix)
	if !ok || rest != "" {
		return "", false
	}
	return param, true
}

// adminWriteRegistered reports whether the reference registers this route in
// this deployment at all, and is adminReadRegistered's counterpart.
//
// Fourteen of the sixteen are registered unconditionally and answer their own
// 404 or 501 for the store they were not given. The two template writes are not:
// they sit in the same `if (featTemplates && options.templateStore)` block as
// the two template listings (:1444), so a deployment with no template store has
// no such route rather than a guarded one — which is why this is asked in
// AdminHandler, before the guard. An unregistered route answers Express's own
// 404 to an anonymous caller; a registered one behind the guard would answer 401.
func (a *Auth) adminWriteRegistered(route adminWriteRoute) bool {
	switch route {
	case adminWriteNone:
		return false
	case adminWriteMailTemplate, adminWriteUITemplate:
		return a.service.cfg.Templates != nil
	default:
		return true
	}
}

// serveAdminWrite dispatches one classified write. It runs behind Protect, so
// everything below may assume an authorised caller and nothing below may assume
// an identified one.
func (a *Auth) serveAdminWrite(w http.ResponseWriter, r *http.Request, cfg HTTPConfig, route adminWriteRoute, params adminWriteParams) {
	switch route {
	case adminWriteDeleteUser:
		a.adminDeleteUser(w, r, params.ID)
	case adminWriteTwoFAPolicy:
		a.adminSetTwoFAPolicy(w, r)
	case adminWriteUserMetadata:
		a.adminUpdateUserMetadata(w, r, params.ID)
	case adminWriteAddUserRole:
		a.adminAddUserRole(w, r, cfg, params.ID)
	case adminWriteRemoveUserRole:
		a.adminRemoveUserRole(w, r, cfg, params.ID, params.Sub)
	case adminWriteSettings:
		a.adminUpdateSettings(w, r)
	case adminWriteSettingsUI:
		a.adminPatchSettingsUI(w, r)
	case adminWriteRevokeSession:
		a.adminRevokeSession(w, r, params.ID)
	case adminWriteCreateRole:
		a.adminCreateRole(w, r)
	case adminWriteDeleteRole:
		a.adminDeleteRole(w, r, params.ID)
	case adminWriteCreateTenant:
		a.adminCreateTenant(w, r)
	case adminWriteDeleteTenant:
		a.adminDeleteTenant(w, r, params.ID)
	case adminWriteAddTenantUser:
		a.adminAddTenantUser(w, r, params.ID)
	case adminWriteRemoveTenantUser:
		a.adminRemoveTenantUser(w, r, params.ID, params.Sub)
	case adminWriteMailTemplate:
		a.adminUpdateMailTemplate(w, r)
	case adminWriteUITemplate:
		a.adminUpdateUITranslations(w, r)
	default:
		http.NotFound(w, r)
	}
}

// ── users ────────────────────────────────────────────────────────────────────

// adminDeleteUser is DELETE <admin>/api/users/:id (:803-815).
//
// # What it deletes, and what it leaves behind
//
// One row. The reference calls userStore.deleteUser(id) and nothing else, so the
// deleted user's sessions, role assignments, tenant memberships, metadata and
// linked accounts all survive the account they belonged to. That is not an
// oversight this port is free to read past: the same codebase cascades in the
// *other* direction on the user's own route — DELETE <prefix>/account revokes
// every session, strips every role, leaves every tenant and clears the metadata
// before the record goes (auth.router.ts:1597-1636, ported as
// Service.DeleteAccount) — so the reference knows what the cleanup is and the
// admin console simply does not do it.
//
// Calling Service.DeleteAccount here would therefore be a silent product
// decision, not a port: it would revoke sessions the reference leaves live and
// publish an EventUserDeleted the reference's admin route publishes nowhere. The
// store call is what is reproduced, and the orphans are stated rather than
// swept up. A deployment that wants the cascade has it one call away in
// Auth.DeleteAccount.
//
// # The capability, and the tenant
//
// The reference tests `typeof store['deleteUser'] === 'function'` and answers a
// bare 501 naming the method when it is absent (:810) — no store-not-configured
// 404 above it, because the user store is the one store createAdminRouter is
// always handed. UserAccountStore is this port's counterpart and bundles
// UpdateProfile with DeleteUser, so a store carrying only the second does not
// satisfy it; that pairing is Service.DeleteAccount's already and is not
// re-litigated on an admin route.
//
// The tenant is "", because the reference's deleteUser(id) carries none, and
// UserStore reads "" as an ordinary tenant value rather than as a wildcard. So
// in a deployment that stores users under a non-empty tenant this route deletes
// nothing the listing above it shows. That is the gap GET /api/users/:id had,
// and UserLookupStore is the seam that closed it there (adminFindUser). A write
// that resolves its tenant through it first changes which row the write
// reaches, which is this file's invariant, and this route does not do that yet.
func (a *Auth) adminDeleteUser(w http.ResponseWriter, r *http.Request, id string) {
	store, ok := a.service.users.(UserAccountStore)
	if !ok {
		writeAdminError(w, http.StatusNotImplemented, "IUserStore.deleteUser is not implemented")
		return
	}
	if err := store.DeleteUser(r.Context(), id, ""); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// adminTwoFAPolicyBatchSize is the reference's `const batchSize = 100` (:837).
// It is the walk's page size and its termination condition both, so it is one
// constant rather than two literals.
const adminTwoFAPolicyBatchSize = 100

// adminSetTwoFAPolicy is POST <admin>/api/2fa-policy (:820-852), the one route
// in the admin router that touches every row in the user table.
//
// # The walk
//
// offset starts at 0 and the page size is 100. Each page is listUsers(100,
// offset); an empty page ends the walk before anything is counted, every user in
// a non-empty page is updated, `updated` grows by the page's length, and a page
// shorter than 100 ends the walk after the count. Otherwise offset advances by
// 100 and it goes round again. So the walk's termination is "a short page means
// nothing follows", which is exactly the promise AdminUserStore's paging rules
// make — and the reason those rules say a store may not return a short page
// mid-list, and that a non-positive limit must be an empty page rather than an
// unlimited one.
//
// `updated` counts users *listed*, not rows changed. The reference adds
// batch.length whatever the store did with each id (:844), so a policy store
// that no-ops for a user still reports it; the number is what the SPA shows and
// it is reproduced rather than made honest.
//
// The reference updates a page with Promise.all (:843) and this port updates it
// in order. The difference is unobservable on the wire in the successful case
// and is the same partial write in the failing one: Promise.all rejects on the
// first rejection with the rest of the page already in flight, so a failure
// there leaves an arbitrary prefix of the table updated and answers 500 —
// which is what a sequential walk that stops at the first error also leaves and
// also answers. Neither is a transaction and the route promises none.
//
// # Three 501s for one capability, and their order
//
// This is the third of the three distinct answers the reference gives for a
// missing lister, and the three are deliberately not unified: the guard's
// 'first-user' arm answers 500 with a sentence (:377), GET /api/users answers
// 501 with an empty page so the table renders (:754), and this answers a bare
// 501 with no users or total at all (:832) — because there is no page here to
// be empty.
//
// The order of the two 501s is the reference's and is load-bearing: the
// require-2FA capability is tested first (:827) and the lister second (:831), so
// a store that can enumerate and cannot write answers the *write* message. A
// deployment reading these to decide what to implement gets told about the write
// first on both sides.
func (a *Auth) adminSetTwoFAPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Required any `json:"required"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	// `typeof required !== 'boolean'` (:823): absent, null, and a value of any
	// other type are all the 400. The field is `any` and the check is a type
	// assertion because that is the same question; a *bool would not ask it —
	// encoding/json allocates the pointee before it discovers the type is wrong,
	// so {"required": "yes"} would arrive as a non-nil pointer to false and this
	// route would clear the flag on every user in the deployment.
	required, ok := body.Required.(bool)
	if !ok {
		writeAdminError(w, http.StatusBadRequest, `"required" must be a boolean`)
		return
	}

	policy, ok := a.service.users.(UserTwoFactorPolicyStore)
	if !ok {
		writeAdminError(w, http.StatusNotImplemented, "IUserStore.updateRequire2FA is not implemented")
		return
	}
	if _, ok := a.service.users.(AdminUserStore); !ok {
		writeAdminError(w, http.StatusNotImplemented, "IUserStore.listUsers is not implemented")
		return
	}

	ctx := r.Context()
	offset, updated := 0, 0
	for {
		// The tenant is "", which AdminUserStore alone reads as a wildcard: every
		// user in every tenant, which is what a policy the reference applies to
		// `listUsers(batchSize, offset)` covers.
		batch, err := a.service.ListUsers(ctx, "", adminTwoFAPolicyBatchSize, offset)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		if len(batch) == 0 {
			break
		}
		for _, user := range batch {
			// The tenant is the listed row's own. The reference's
			// updateRequire2FA(id, required) carries none, and "" here would
			// address a different user than the one the page just named in any
			// deployment that stores users under a tenant — the wildcard listing
			// hands back rows from every tenant, so the row is the only thing
			// that knows which one this is.
			if err := policy.UpdateRequire2FA(ctx, user.ID, user.TenantID, required); err != nil {
				writeAdminError(w, http.StatusInternalServerError, "Internal server error")
				return
			}
		}
		updated += len(batch)
		if len(batch) < adminTwoFAPolicyBatchSize {
			break
		}
		offset += adminTwoFAPolicyBatchSize
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "updated": updated})
}

// adminUpdateUserMetadata is PUT <admin>/api/users/:id/metadata (:866-878).
//
// It is a PUT that merges, and the mismatch is the reference's own: the method
// is PUT, the handler hands the whole decoded body to updateMetadata, and that
// method's contract is "Merge (shallow-patch) the provided key/value pairs into
// the user's existing metadata. Fields not present in `metadata` are left
// untouched" (user-metadata-store.interface.ts:40-44). So a body of
// {"plan": "pro"} sets one key and leaves the rest, and there is no way through
// this route to remove a key — UserMetadataStore.ClearMetadata is not on it.
// Both sides behave identically because both delegate the semantics to the same
// interface contract; nothing here replaces.
//
// The route neither loads the user nor 404s for one that is not there: metadata
// is keyed by id alone, as the read beside it is, so a write against an unknown
// id creates a row for it.
func (a *Auth) adminUpdateUserMetadata(w http.ResponseWriter, r *http.Request, id string) {
	if a.service.metadata == nil {
		writeAdminError(w, http.StatusNotFound, "User metadata store not configured")
		return
	}
	var metadata map[string]any
	_ = json.NewDecoder(r.Body).Decode(&metadata)
	if metadata == nil {
		// A body that was absent, null, or not an object. express.json leaves
		// req.body as {} for the first, and the merge of an empty patch is a
		// no-op that still answers success — which is what the store is asked
		// for rather than a nil map no implementor was promised.
		metadata = map[string]any{}
	}
	if err := a.service.metadata.UpdateMetadata(r.Context(), id, metadata); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// adminAddUserRole is POST <admin>/api/users/:id/roles (:904-914).
//
// tenantId is read off the *body* and not off the path, and it is optional:
// absent means the empty tenant, which is the assignment GET
// /api/users/:id/roles reads back. A console that posts a tenant here and then
// reads the roles list back sees nothing, because that read carries no tenant
// either — the reference's arrangement, and visible in its own SPA.
//
// The user id is used as Express decoded it and is not decoded a second time,
// unlike the role name of the delete below. The asymmetry is the reference's:
// :909 passes req.params['id'] straight through.
//
// It publishes identity.role.assigned after the store call and before the
// answer (node-auth admin.router.ts:1002-1006), and it is the single
// publication point in either tree that passes a tenant id — the one off the
// body, not off the path, so an assignment made without a tenantId publishes
// without one. `data` is {role} alone: the tenant rides on the event's own
// field. The publish is inside the reference's try, where a throw would be the
// flat 500; nothing here can throw, because a panicking subscriber is contained
// by the bus (see the event-handler-panic-does-not-fail-the-publisher
// deviation).
func (a *Auth) adminAddUserRole(w http.ResponseWriter, r *http.Request, cfg HTTPConfig, id string) {
	if a.service.rbac == nil {
		writeAdminError(w, http.StatusNotFound, "RBAC store not configured")
		return
	}
	var body struct {
		Role     string `json:"role"`
		TenantID string `json:"tenantId"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Role == "" {
		writeAdminError(w, http.StatusBadRequest, "role is required")
		return
	}
	if err := a.service.rbac.AddRoleToUser(r.Context(), id, body.Role, body.TenantID); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	a.publishAdminEvent(r, cfg, func() Event {
		return Event{
			Name:     EventRoleAssigned,
			UserID:   id,
			TenantID: body.TenantID,
			Data:     map[string]any{"role": body.Role},
		}
	})
	writeAdminSuccess(w)
}

// adminRemoveUserRole is DELETE <admin>/api/users/:id/roles/:role (:917-928).
//
// The role is decoded twice and the id once, exactly as written (:921-922).
// Express has already decoded both captured parameters by the time the handler
// runs, and the handler calls decodeURIComponent on the second again — so a role
// named "billing/admin" is addressed by double-encoding it, and a single decode
// here would make that role unremovable. The second decode is inside the route's
// try, so a value it cannot decode is the same 500 the rest of the body answers
// with. adminListTenantUsers settled this shape for the reads.
//
// There is no tenant: the reference's removeRoleFromUser(id, role) carries none,
// so this removes the untenanted assignment and leaves a tenanted one in place —
// the same tenant the read route reports, and *not* necessarily the one the post
// above created. The identity.role.revoked it publishes carries none either
// (node-auth admin.router.ts:1020-1023), which is the asymmetry with the post
// above showing up a second time, on the event this time.
//
// `data["role"]` is the *decoded* name — the value handed to the store, not the
// path segment — so a subscriber sees the role that was actually removed. The
// publish is after the store call, so a role that could not be decoded has
// already answered 500 and published nothing.
func (a *Auth) adminRemoveUserRole(w http.ResponseWriter, r *http.Request, cfg HTTPConfig, id, rawRole string) {
	if a.service.rbac == nil {
		writeAdminError(w, http.StatusNotFound, "RBAC store not configured")
		return
	}
	role, ok := adminDecodeAgain(w, rawRole)
	if !ok {
		return
	}
	if err := a.service.rbac.RemoveRoleFromUser(r.Context(), id, role, ""); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	a.publishAdminEvent(r, cfg, func() Event {
		return Event{Name: EventRoleRevoked, UserID: id, Data: map[string]any{"role": role}}
	})
	writeAdminSuccess(w)
}

// ── control ──────────────────────────────────────────────────────────────────

// adminUpdateSettings is PUT <admin>/api/settings (:962-971): the body is the
// patch, handed to the store unexamined.
//
// The store merges shallowly — MergeSettings is that rule and
// ISettingsStore.updateSettings is its contract — so a field the body does not
// carry is left as stored and a field it does carry replaces the stored one
// outright. The one place that bites is `ui`, which is one field of the patch
// and is therefore replaced whole: a PUT carrying a `ui` object with one colour
// in it drops the other seven. That is why the reference has the PATCH route
// below, and reproducing the division of labour is what keeps the two routes
// meaning what they mean.
//
// A key AuthSettings does not declare is dropped here where the reference's
// Record<string, unknown> spread would store it. That is the settled consequence
// of AuthSettings being a type rather than a map — SettingsStore.UpdateSettings
// takes an AuthSettings and has since the seam shipped — and not a decision this
// route makes.
func (a *Auth) adminUpdateSettings(w http.ResponseWriter, r *http.Request) {
	store := a.service.cfg.Settings
	if store == nil {
		writeAdminError(w, http.StatusNotFound, "Settings store not configured")
		return
	}
	var patch AuthSettings
	_ = json.NewDecoder(r.Body).Decode(&patch)
	if _, err := store.UpdateSettings(r.Context(), patch); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// adminPatchSettingsUI is PATCH <admin>/api/settings/ui (:974-987), and the
// division of labour between it and the PUT above is the whole point of it.
//
// The store's merge is shallow and `ui` is one field of the patch, so a store
// asked to write {ui: {...}} replaces the branding block whole. This route
// therefore does the sub-object merge *itself*: read the current settings, spread
// the patch over the stored ui, and send the merged block back down (:979-981).
// The reference's own comment calls that "avoids the GET+PUT race", which it
// only partly does — the read and the write are still two calls and two admins
// patching different colours at once can still lose one — but the merge belongs
// here either way. Moving it into the store would make {ui: {...}} mean
// something different from every other field of the patch and would be a
// different product, not a tidier one.
//
// The merged block is always written, even when the patch is empty and even when
// nothing was stored: `{...(current.ui || {}), ...uiPatch}` is an object in every
// case, so a PATCH with an empty body stores an empty ui where there was none.
//
// The 500 carries the error's own message rather than the flat "Internal server
// error" the other fifteen answer with (:984-985). That asymmetry is the
// reference's and is kept: this route is the only one whose failure an operator
// cannot diagnose from the status alone — it makes two store calls where the
// others make one — and the message goes only to a caller the guard has already
// admitted to a console that serves the whole user table.
func (a *Auth) adminPatchSettingsUI(w http.ResponseWriter, r *http.Request) {
	store := a.service.cfg.Settings
	if store == nil {
		writeAdminError(w, http.StatusNotFound, "Settings store not configured")
		return
	}
	var patch UISettings
	_ = json.NewDecoder(r.Body).Decode(&patch)

	ctx := r.Context()
	current, err := store.GetSettings(ctx)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := store.UpdateSettings(ctx, AuthSettings{UI: mergeUISettings(current.UI, &patch)}); err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeAdminSuccess(w)
}

// mergeUISettings is `{...(current || {}), ...patch}` over the eight declared
// fields: a field the patch carries wins, a field it does not carry keeps the
// stored value, and the result is never nil so that the caller always has a
// block to write.
//
// Everything it returns is freshly allocated, so neither input can be mutated
// through the result — the rule copySettings already holds this type to.
func mergeUISettings(current, patch *UISettings) *UISettings {
	merged := copyUISettings(current)
	if merged == nil {
		merged = &UISettings{}
	}
	if patch == nil {
		return merged
	}
	if patch.PrimaryColor != nil {
		merged.PrimaryColor = copyString(patch.PrimaryColor)
	}
	if patch.SecondaryColor != nil {
		merged.SecondaryColor = copyString(patch.SecondaryColor)
	}
	if patch.LogoURL != nil {
		merged.LogoURL = copyString(patch.LogoURL)
	}
	if patch.SiteName != nil {
		merged.SiteName = copyString(patch.SiteName)
	}
	if patch.LogoPath != nil {
		merged.LogoPath = copyString(patch.LogoPath)
	}
	if patch.BgColor != nil {
		merged.BgColor = copyString(patch.BgColor)
	}
	if patch.BgImage != nil {
		merged.BgImage = copyString(patch.BgImage)
	}
	if patch.CardBg != nil {
		merged.CardBg = copyString(patch.CardBg)
	}
	return merged
}

// ── sessions ─────────────────────────────────────────────────────────────────

// adminRevokeSession is DELETE <admin>/api/sessions/:handle (:1116-1124). The
// handle is decoded twice, as the tenant id of the read beside it is.
//
// The reference's `!options.sessionStore` 404 (:1117) has no counterpart, for
// adminListSessions' reason: NewService requires a session store, so one is
// always configured. The capability is a different matter — revokeSession is a
// required method of ISessionStore there and RevokeSessionByID is an optional
// one here — and a store without it is the 500 the reference's own TypeError
// would land in, not a 501: the reference declares no 501 on this route because
// it declares the method mandatory.
//
// Nothing is looked up and nothing is reported. A handle that names no session
// is whatever the store makes of it, and this package's stores answer
// ErrSessionNotFound, which is the 500 discussed at the top of this file.
func (a *Auth) adminRevokeSession(w http.ResponseWriter, r *http.Request, rawHandle string) {
	handle, ok := adminDecodeAgain(w, rawHandle)
	if !ok {
		return
	}
	if err := a.service.RevokeSessionByID(r.Context(), handle); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// ── roles ────────────────────────────────────────────────────────────────────

// adminCreateRole is POST <admin>/api/roles (:1150-1160).
//
// permissions is optional and is passed through as it arrives: absent is a nil
// slice, which CreateRole's contract creates a role with no permissions from —
// "a role with no permissions is still a role", as RoleLister puts it, and the
// listing beside this route shows one.
//
// It is a create that is also an overwrite. The reference calls createRole with
// no existence check, and MemoryRolesPermissionsStore replaces the permission set
// of a name that already exists; a second POST with a shorter list is therefore
// how the console edits a role, and there is no other route that does.
func (a *Auth) adminCreateRole(w http.ResponseWriter, r *http.Request) {
	if a.service.rbac == nil {
		writeAdminError(w, http.StatusNotFound, "RBAC store not configured")
		return
	}
	var body struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Name == "" {
		writeAdminError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := a.service.rbac.CreateRole(r.Context(), body.Name, body.Permissions); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// adminDeleteRole is DELETE <admin>/api/roles/:name (:1163-1171). The name is
// decoded twice, and the answer is success whether or not the role existed.
//
// What else goes with it is the store's business and not the route's. This
// package's RolesPermissionsStore.DeleteRole also drops the role from every
// user holding it, which is the only reading that leaves the store consistent —
// the alternative is an assignment naming a role that is gone — but the route
// asks for none of that and reports none of it.
func (a *Auth) adminDeleteRole(w http.ResponseWriter, r *http.Request, rawName string) {
	if a.service.rbac == nil {
		writeAdminError(w, http.StatusNotFound, "RBAC store not configured")
		return
	}
	name, ok := adminDecodeAgain(w, rawName)
	if !ok {
		return
	}
	if err := a.service.rbac.DeleteRole(r.Context(), name); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// ── tenants ──────────────────────────────────────────────────────────────────

// adminCreateTenant is POST <admin>/api/tenants (:1187-1197), and it is the one
// write in this file that answers a row rather than {"success": true}: the body
// is `{tenant}`, holding what the store returned, in the shape the listing above
// it uses.
//
// isActive defaults to true through `isActive ?? true` (:1192), so an absent
// field and a null one are both true and only an explicit false is false. A
// *bool is that distinction.
//
// The id and the timestamp are minted here where the reference's store mints
// them. TenantStore.CreateTenant takes a whole Tenant — the caller names the id,
// as Service.CreateTenant already does with the same "tnt" prefix — so a route
// that did not generate one would be asking the store to create a tenant with an
// empty id. Config is not on this route's body and is left nil, which
// adminTenantRow omits.
func (a *Auth) adminCreateTenant(w http.ResponseWriter, r *http.Request) {
	if a.service.tenants == nil {
		writeAdminError(w, http.StatusNotFound, "Tenant store not configured")
		return
	}
	var body struct {
		Name     string `json:"name"`
		IsActive any    `json:"isActive"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Name == "" {
		writeAdminError(w, http.StatusBadRequest, "name is required")
		return
	}
	// `isActive ?? true` (:1192): only an explicit false is false, and absent and
	// null are both true. The field is `any` for adminSetTwoFAPolicy's reason —
	// a *bool would decode {"isActive": "x"} to false — and a value that is
	// neither a boolean nor null takes the default, which is the truthy reading
	// of everything the reference would store there bar 0 and "".
	isActive := true
	if value, ok := body.IsActive.(bool); ok {
		isActive = value
	}
	id, err := newID("tnt")
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	tenant, err := a.service.tenants.CreateTenant(r.Context(), Tenant{
		ID:        id,
		Name:      body.Name,
		IsActive:  isActive,
		CreatedAt: a.service.now(),
	})
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"tenant": newAdminTenantRow(tenant)})
}

// adminDeleteTenant is DELETE <admin>/api/tenants/:id (:1200-1208). The id is
// decoded twice and the answer is success whether or not the tenant existed.
//
// Nothing is said about the users in it. This package's
// TenantStore.DeleteTenant drops the membership rows with the tenant, because a
// membership naming a tenant that is gone is not a state any read can render;
// the users themselves keep their own User.TenantID, which is a different column
// and which AdminUserStore lists on. Neither fact is this route's to report.
func (a *Auth) adminDeleteTenant(w http.ResponseWriter, r *http.Request, rawID string) {
	if a.service.tenants == nil {
		writeAdminError(w, http.StatusNotFound, "Tenant store not configured")
		return
	}
	id, ok := adminDecodeAgain(w, rawID)
	if !ok {
		return
	}
	if err := a.service.tenants.DeleteTenant(r.Context(), id); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// adminAddTenantUser is POST <admin>/api/tenants/:id/users (:1224-1234) and
// adminRemoveTenantUser its delete (:1237-1248). Both are membership writes
// against TenantStore, and both decode the tenant id a second time — the delete
// decodes its user id a second time as well (:1241-1242).
//
// The double decode is the sibling of the one U13 found on GET
// /api/tenants/:id/users (:1216), and all three routes of the family do it, so
// a tenant addressed by double-encoding on the read is addressed the same way on
// both writes. The user id in the *body* of the post is not decoded at all, and
// the one in the *path* of the delete is decoded twice: the same identifier
// reaches the store through two different treatments depending on which route
// carried it, which is the reference's and is reproduced.
func (a *Auth) adminAddTenantUser(w http.ResponseWriter, r *http.Request, rawID string) {
	if a.service.tenants == nil {
		writeAdminError(w, http.StatusNotFound, "Tenant store not configured")
		return
	}
	var body struct {
		UserID string `json:"userId"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.UserID == "" {
		writeAdminError(w, http.StatusBadRequest, "userId is required")
		return
	}
	tenantID, ok := adminDecodeAgain(w, rawID)
	if !ok {
		return
	}
	if err := a.service.tenants.AssociateUserWithTenant(r.Context(), body.UserID, tenantID); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

func (a *Auth) adminRemoveTenantUser(w http.ResponseWriter, r *http.Request, rawID, rawUserID string) {
	if a.service.tenants == nil {
		writeAdminError(w, http.StatusNotFound, "Tenant store not configured")
		return
	}
	userID, ok := adminDecodeAgain(w, rawUserID)
	if !ok {
		return
	}
	tenantID, ok := adminDecodeAgain(w, rawID)
	if !ok {
		return
	}
	if err := a.service.tenants.DisassociateUserFromTenant(r.Context(), userID, tenantID); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// ── templates ────────────────────────────────────────────────────────────────

// adminUpdateMailTemplate is POST <admin>/api/templates/mail (:1458-1467), an
// upsert whose patch is not partial.
//
// The handler destructures four names out of the body and rebuilds an object
// literal from three of them — `{ baseHtml, baseText, translations }` (:1462) —
// and that literal carries all three *keys* whatever the body held, with the
// value `undefined` where the body had nothing. The store then spreads it over
// the existing record (`{...existing, ...template}`,
// memory-template.store.ts:22), and a spread copies a key holding undefined like
// any other. So a POST naming only an id blanks the stored bodies and
// translations rather than leaving them alone.
//
// That is why all three fields are passed here rather than only the ones the
// body carried. MailTemplatePatch's nil-means-keep rule is written for a caller
// that constructs the patch from what it means to change; this route is a caller
// that always means all three, because the reference's object literal always
// carries all three. Sending nil for an absent baseHtml would make this route a
// partial update where the reference has a replace — a different wire contract on
// a route that writes, and the one shape the shipped SPA would not notice because
// it always sends the whole template.
//
// The route is registered only where a TemplateStore is; see
// adminWriteRegistered.
func (a *Auth) adminUpdateMailTemplate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID           string                       `json:"id"`
		BaseHTML     string                       `json:"baseHtml"`
		BaseText     string                       `json:"baseText"`
		Translations map[string]map[string]string `json:"translations"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.ID == "" {
		writeAdminError(w, http.StatusBadRequest, "id is required")
		return
	}
	if body.Translations == nil {
		// The `translations: undefined` the literal carries when the body had
		// none. An empty map is the nearest stored value — the store normalises
		// a nil one to {} on the way out either way — and it is what makes the
		// blanking above actually blank.
		body.Translations = map[string]map[string]string{}
	}
	_, err := a.service.cfg.Templates.UpdateMailTemplate(r.Context(), body.ID, MailTemplatePatch{
		BaseHTML:     &body.BaseHTML,
		BaseText:     &body.BaseText,
		Translations: body.Translations,
	})
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// adminUpdateUITranslations is POST <admin>/api/templates/ui (:1480-1489).
//
// Both fields are required by a falsy test, so an absent or null translations
// object is the 400 and an empty one is not: `{}` is truthy in JavaScript, so
// {"page": "login", "translations": {}} is accepted and replaces the page's
// translations with nothing. A non-nil empty map is that value here.
//
// The write is a replace and not a merge, in the store rather than in the route:
// updateUiTranslations sets `{page, translations}` (memory-template.store.ts:34),
// so a language the body does not name is dropped. A caller changing one string
// reads the page back and posts the whole map, which is what the SPA does.
func (a *Auth) adminUpdateUITranslations(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Page         string                       `json:"page"`
		Translations map[string]map[string]string `json:"translations"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Page == "" || body.Translations == nil {
		writeAdminError(w, http.StatusBadRequest, "page and translations are required")
		return
	}
	if _, err := a.service.cfg.Templates.UpdateUITranslations(r.Context(), body.Page, body.Translations); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// ── the shared answers ───────────────────────────────────────────────────────

// writeAdminSuccess is the body fifteen of these sixteen routes answer with. It
// is `res.json({ success: true })` and it carries nothing about what changed —
// not a count, not a row, not whether anything was there to change.
func writeAdminSuccess(w http.ResponseWriter) {
	WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

// adminDecodeAgain applies the second decodeURIComponent the routes that have
// one apply, writing the 500 their catch would have produced when it fails.
//
// net/http has already refused a request whose path could not be parsed and
// adminPathParam has already decoded the segment once, so reaching this failure
// takes a parameter whose *decoded* form is itself invalid percent-encoding —
// "%zz" arriving as "%25zz", say. The reference lands that in the route's own
// catch and answers its generic 500, which is what this reproduces.
func adminDecodeAgain(w http.ResponseWriter, raw string) (string, bool) {
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return "", false
	}
	return decoded, true
}
