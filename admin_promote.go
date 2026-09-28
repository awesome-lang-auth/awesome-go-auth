package auth

import (
	"encoding/json"
	"net/http"
)

// The fifty-first route: POST <admin>/users/{id}/promote, which grants somebody
// the admin console.
//
// # Which tree this comes from
//
// The published reference does not have it. At ReferenceRevision the admin
// router registers fifty routes and none of them is this one — the gap is
// visible between DELETE /api/users/:id/roles/:role (admin.router.ts:917-928)
// and GET /api/users/:id/tenants (:933), which the dev line's :1030 sits
// between. Every citation in this file therefore carries the "node-auth "
// prefix and resolves against DevLineRevision, the convention the event plane
// already uses; a reviewer who greps the published tree for "promote" finds
// nothing, and that is the expected result rather than a missing port.
//
// This is the same bet U18 made for the nineteen publication points and it is
// registered the same way: see the
// admin-promote-route-comes-from-the-development-line deviation, which covers
// this route and AdminOptions.RateLimiter together.
//
// # The path has no /api, and that is the source's
//
// Every other route on this surface is under /api — fifty of the fifty-one.
// This one is `router.post('/users/:id/promote', …)` (node-auth
// admin.router.ts:1030), registered between two /api/users routes, in the same
// block, by the same hand. It reads like a slip and it is reproduced anyway,
// because the wire contract is what the dev line's clients will be written
// against and a port that quietly "fixed" it would 404 for every one of them.
// The spelling a reader expects — POST <admin>/api/users/{id}/promote — is
// mounted nowhere and answers the router's own 404; wiretest asserts that
// explicitly, so the absence is pinned rather than incidental.
//
// # Its two methods are two different products
//
// `method: 'flag'` writes User.IsAdmin, which is what the 'is-admin-flag'
// access policy reads (AdminPolicyIsAdminFlag). `method: 'role'` — the default,
// and the branch a body-less POST takes — creates an `admin` role in the RBAC
// store and assigns it. Neither implies the other: a deployment guarding the
// console with AdminIsAdminFlag is not affected by the role branch at all, and
// one guarding it with an AdminPredicate over the RBAC store is not affected by
// the flag branch. The route does not say so and this comment does, because
// choosing the wrong one is a promotion that silently grants nothing.
//
// Neither branch checks that the user exists. The flag branch writes through the
// store, which may report not-found (a 500 here), and the role branch assigns a
// role to whatever id it was handed — creating an assignment for a user that
// never existed, which the reference also does and which GET
// /api/users/:id/roles will read back.
//
// # What guards it
//
// AdminGuard.Protect, like every other route under this mount bar the
// documentation pair, plus AdminOptions.RateLimiter ahead of it — the one route
// on either line that carries a limiter. Ordering and the reasoning are on that
// field.

const (
	// AdminPromoteUsersPath is the collection this route hangs off, and the one
	// thing to notice about it is the missing /api. See this file's header.
	AdminPromoteUsersPath = "/users"
	// AdminPromoteSuffix is the last segment of the pattern:
	// <admin>/users/{id}/promote.
	AdminPromoteSuffix = "/promote"
)

const (
	// adminPromoteRole is the role name both branches write, hard-coded in the
	// source as the string 'admin' three times over (node-auth
	// admin.router.ts:1043, :1053-1054, :1057). It is not configurable there and
	// is not made configurable here: a deployment whose admin role is called
	// something else uses POST /api/users/:id/roles, which takes the name.
	adminPromoteRole = "admin"
	// The two method values. adminPromoteMethodRole is also the default for an
	// absent or null `method`, which is the reference's `?? 'role'` (node-auth
	// admin.router.ts:1032).
	adminPromoteMethodFlag = "flag"
	adminPromoteMethodRole = "role"
)

// matchAdminPromote classifies a method and a path below the admin mount,
// returning the user id when this is the route.
//
// rel is the escaped path, for matchAdminRead's reason exactly: Express matches
// its patterns against the raw pathname and decodes each captured parameter
// afterwards. The id is used as Express decoded it and is not decoded a second
// time — node-auth admin.router.ts:1031 passes req.params['id'] straight
// through, the way POST /api/users/:id/roles does and unlike the role name of
// DELETE /api/users/:id/roles/:role.
//
// Nothing may follow "/promote": the reference registers no route below it, so a
// longer path is a miss rather than a match with the remainder discarded.
func matchAdminPromote(method, rel string) (string, bool) {
	if method != http.MethodPost {
		return "", false
	}
	id, tail, ok := adminPathParam(rel, AdminPromoteUsersPath)
	if !ok || tail != AdminPromoteSuffix {
		return "", false
	}
	return id, true
}

// adminPromoteUser is POST <admin>/users/:id/promote (node-auth
// admin.router.ts:1030-1063).
//
// # The body, and what it answers with
//
// `{method?: 'flag' | 'role'}`, defaulting to 'role' for an absent or null
// value — `(req.body as {method?: …} | undefined)?.method ?? 'role'` (:1032) —
// and for a body that is absent, empty or not JSON at all, which decodes into
// the same nil.
//
// Only the literal 'flag' takes the flag branch. Every other string falls
// through to the role branch, including "" and "Flag", because the source's
// test is `method === 'flag'` (:1034) and its cast to the union is erased at
// run time. And the answer echoes what the caller sent, not the branch that
// ran: `res.json({success: true, method})` (:1045, :1059) reports method as
// resolved, so POST with {"method": "bogus"} assigns the admin *role* and
// answers {"success": true, "method": "bogus"}. The published event does not
// echo it — both payloads carry a hard-coded 'flag' or 'role' (:1043, :1057) —
// so a subscriber always learns which branch ran even when the answer does not
// say. Both quirks are reproduced.
//
// The one place this parts company with the source is a `method` that is
// neither a string nor null — {"method": 5}. There the cast is a no-op, 5 is not
// 'flag', the role branch runs and the number is echoed back; here the body
// fails to decode into a *string, `method` stays the default, the role branch
// runs and "role" is echoed back. The branch is the same on both sides and only
// the echo differs, on a body no client and no declared type produces. This is
// the decode rule admin_write.go settled for all sixteen writes — a body that
// will not decode leaves the zero value in every field — applied rather than a
// second one invented for one route.
//
// # method=flag
//
// The reference type-asserts its user store to a writer and answers 501 naming
// the method when it has none (:1035-1039), which is the shape POST
// /api/2fa-policy and DELETE /api/users/:id already have. UserAdminFlagStore is
// this port's counterpart; the message is the reference's, word for word,
// including the fact that it names `IUserStore.update` — a method this port does
// not have and deliberately narrowed. See that interface.
//
// The tenant passed to the store is "", which is adminDeleteUser's and for the
// same reason: the reference's update(id, patch) carries none. In a deployment
// that stores users under a non-empty tenant this route therefore promotes
// nobody and answers 500 where the row exists under another tenant — the same
// gap DELETE <admin>/api/users/:id has. The store-level half of the fix exists
// now, as UserLookupStore; adminDeleteUser says why neither write resolves
// through it yet.
//
// There is no 404 above the 501 and none below it. The user store is the one
// store createAdminRouter is always handed, and a row that is not there is
// whatever the store says it is.
//
// # method=role
//
// 404 without an RBAC store, the message every other RBAC route on this surface
// answers with (:1049-1052). Then createRole('admin') and
// addRoleToUser(userId, 'admin'), in that order and both awaited (:1053-1054).
//
// createRole first is load-bearing and is not a convenience: it is what makes
// the route work on a store whose addRoleToUser has a foreign key to the role
// table. The permissions are absent there — `createRole('admin')` with one
// argument — which is nil here.
//
// What a store does with a createRole for a name it already holds is the
// store's business, and it is worth knowing what this package's own store does:
// MemoryRolesPermissionsStore replaces the role's permission set outright, so
// promoting a second user through method=role clears every permission the
// `admin` role had been given. That is the same thing POST /api/roles with no
// permissions already does to it, it is not a behaviour this route invents, and
// it is not worked around here — a route that skipped the create for an
// existing role would be a different route from the reference's, and would
// break exactly the foreign-key store the create is there for.
//
// The assignment carries no tenant — `addRoleToUser(userId, 'admin')` (:1054) —
// so it lands in the empty tenant, which is the one GET /api/users/:id/roles
// reads back. POST /api/users/:id/roles takes a tenantId and this does not;
// that asymmetry is the reference's.
//
// # The catch
//
// One try wraps both branches and answers a flat 500 (:1060-1062), so a store
// that fails anywhere leaves whatever it had already written in place. The role
// branch is the one where that is visible: a createRole that succeeded and an
// addRoleToUser that failed leaves an `admin` role defined and nobody holding
// it, and there is no transaction on either side.
func (a *Auth) adminPromoteUser(w http.ResponseWriter, r *http.Request, cfg HTTPConfig, id string) {
	var body struct {
		Method *string `json:"method"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	method := adminPromoteMethodRole
	if body.Method != nil {
		method = *body.Method
	}

	if method == adminPromoteMethodFlag {
		flags, ok := a.service.users.(UserAdminFlagStore)
		if !ok {
			writeAdminError(w, http.StatusNotImplemented, "IUserStore.update is required for method=flag")
			return
		}
		if err := flags.UpdateIsAdmin(r.Context(), id, "", true); err != nil {
			writeAdminError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		a.publishAdminEvent(r, cfg, func() Event {
			return Event{
				Name:   EventRoleAssigned,
				UserID: id,
				Data:   map[string]any{"role": adminPromoteRole, "method": adminPromoteMethodFlag},
			}
		})
		WriteJSON(w, http.StatusOK, map[string]any{"success": true, "method": method})
		return
	}

	if a.service.rbac == nil {
		writeAdminError(w, http.StatusNotFound, "RBAC store not configured")
		return
	}
	ctx := r.Context()
	if err := a.service.rbac.CreateRole(ctx, adminPromoteRole, nil); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if err := a.service.rbac.AddRoleToUser(ctx, id, adminPromoteRole, ""); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	a.publishAdminEvent(r, cfg, func() Event {
		return Event{
			Name:   EventRoleAssigned,
			UserID: id,
			Data:   map[string]any{"role": adminPromoteRole, "method": adminPromoteMethodRole},
		}
	})
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "method": method})
}
