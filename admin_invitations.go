package auth

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"
)

// The admin half of the invitation flow (invitation.go): three routes that
// exist only when Config.Invitations is set, behind the same AdminGuard.Protect
// as every other admin route — so AdminOptions.MachineAccess, the session
// policy and the legacy secret all decide them exactly as they decide the
// rest — and answering with the admin envelope, {"error": "…"}.
//
//	POST   <admin>/api/users/invitations        invite an address
//	GET    <admin>/api/users/invitations        list the outstanding invitations
//	DELETE <admin>/api/users/invitations/{id}   revoke one
//
// None of the three is the reference's, whose admin router creates no account
// at all (admin.router.ts:748-933 are the user routes: list, detail, delete and
// the reads below them). They hang off the users collection because an
// invitation is how a user comes to exist, and the price of that is one path
// the reference's own routes already claim: GET <admin>/api/users/:id with the
// id "invitations". With an InvitationStore configured the listing wins, so a
// user whose id is literally "invitations" cannot be read through the detail
// route — an id this package never mints, since every id it creates carries a
// "usr_" prefix. Without a store the path is the detail route's, exactly as it
// was.
//
// The admin router's OpenAPI document does not describe the three: it is a
// transcription of the reference's generator, which has no such routes, as it
// has no promote route either (openapi_admin.go).

// AdminInvitationsPath is the invitation collection, below the admin mount.
// DELETE takes an invitation id one segment below it.
const AdminInvitationsPath = AdminUsersPath + "/invitations"

// adminInvitationRoute names one of the three.
type adminInvitationRoute int

const (
	adminInvitationNone adminInvitationRoute = iota
	adminInvitationCreate
	adminInvitationList
	adminInvitationRevoke
)

// matchAdminInvitation classifies a method and an escaped path below the admin
// mount, as matchAdminWrite does, returning the invitation id for a revoke.
func matchAdminInvitation(method, rel string) (adminInvitationRoute, string) {
	if rel == AdminInvitationsPath {
		switch method {
		case http.MethodPost:
			return adminInvitationCreate, ""
		case http.MethodGet, http.MethodHead:
			return adminInvitationList, ""
		}
		return adminInvitationNone, ""
	}
	if method == http.MethodDelete {
		if id, tail, ok := adminPathParam(rel, AdminInvitationsPath); ok && tail == "" {
			return adminInvitationRevoke, id
		}
	}
	return adminInvitationNone, ""
}

// adminInvitationRegistered reports whether the route exists in this
// deployment: only with an InvitationStore. It is asked in AdminHandler before
// the guard, like adminWriteRegistered, so that without a store the three
// paths answer what they answered before the flow existed.
func (a *Auth) adminInvitationRegistered(route adminInvitationRoute) bool {
	return route != adminInvitationNone && a.service.InvitationsEnabled()
}

// serveAdminInvitation dispatches one classified route, behind Protect.
func (a *Auth) serveAdminInvitation(w http.ResponseWriter, r *http.Request, cfg HTTPConfig, route adminInvitationRoute, id string) {
	switch route {
	case adminInvitationCreate:
		a.adminCreateInvitation(w, r, cfg)
	case adminInvitationList:
		a.adminListInvitations(w, r)
	case adminInvitationRevoke:
		a.adminRevokeInvitation(w, r, cfg, id)
	default:
		http.NotFound(w, r)
	}
}

// adminActor is who the guard admitted, for the audit an invitation carries:
// the machine principal MachineAccess named, or the signed-in user's id. Both
// empty under AdminOpen and the legacy secret, which identify nobody.
func adminActor(ctx context.Context) (by, kind string) {
	if principal, ok := AdminMachinePrincipalFromContext(ctx); ok {
		return principal, InvitedByMachine
	}
	if user, ok := AdminUserFromContext(ctx); ok && user.ID != "" {
		return user.ID, InvitedByUser
	}
	return "", ""
}

// adminInvitationContext is the context the service is called with: the
// request's, carrying the event provenance the admin router installs for its
// own publications (publishAdminEvent), since the console sits outside
// EventContextMiddleware.
func adminInvitationContext(r *http.Request, cfg HTTPConfig) context.Context {
	return ContextWithEventContext(r.Context(), EventContextFromRequest(r, cfg))
}

// adminCreateInvitation is POST <admin>/api/users/invitations.
//
// The body is {email, role?, tenantId?, metadata?, emailLang?}, and it must be
// sent as application/json. tenantId is the spelling every body in this
// package uses for a tenant. A JSON body that will not decode leaves every
// field zero, the rule admin_write.go settled, and so answers the missing
// address.
//
// The refusals, in order:
//
//   - 415 "Content-Type must be application/json". The admin router has no
//     CSRF layer and its guard reads the session cookie, so a cross-site form
//     — which can send text/plain, never application/json without a CORS
//     preflight — would otherwise be able to invite an address of its
//     choosing with a signed-in administrator's cookie. This route is the one
//     that turns such a request into an account, so it is the one that
//     refuses every other content type; a machine caller sends JSON anyway.
//   - 400 "Email is required", and 400 "Email is not a valid address" for one
//     that is not a single plain mailbox (ErrInvalidInvitationEmail).
//   - 501 "Invitations are not available under the first-user access
//     policy": AdminFirstUser names the console's user by user-id order, and
//     an invitation creates its account, with a random id, at once, so any
//     invitation — whoever sends it — could make the invitee that user.
//     Nothing is created.
//   - 501 "Invitation delivery is not configured": no Config.SendInvitation,
//     and AdminOptions.RevealInvitationToken not set. Nothing is created — an
//     invitation nobody can deliver would only reserve the address.
//   - 501 "UserStore does not implement <capability>", for the three the flow
//     needs (Service.InviteUser).
//   - 409 "User already exists": the address has an account, and it is not a
//     pending one Config.InvitationReinvite lets this call invite again.
//   - 409 "Pending invitation has a different role or tenant": a
//     re-invitation that names a role or a tenant other than the pending
//     account's (ErrInvitationMismatch). A re-invitation reuses the account as
//     it is; to change either, revoke the invitation and invite again.
//   - 502 "Invitation could not be delivered": the sender failed. The call has
//     been undone, so repeating it is safe.
//
// Success is 201 when an account was created and 200 when a pending one was
// invited again, both {"success": true, "invitationId", "userId", "email",
// "expiresAt"}. The token is never in it — with one exception: no sender is
// configured and AdminOptions.RevealInvitationToken is set, in which case the
// caller is the delivery and the answer adds "token" and "acceptUrl". A sender
// always wins over the option, so a deployment that has one never hands a
// token to an HTTP caller.
func (a *Auth) adminCreateInvitation(w http.ResponseWriter, r *http.Request, cfg HTTPConfig) {
	if !jsonContentType(r) {
		writeAdminError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var body struct {
		Email     string         `json:"email"`
		Role      string         `json:"role"`
		TenantID  string         `json:"tenantId"`
		Metadata  map[string]any `json:"metadata"`
		EmailLang string         `json:"emailLang"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if strings.TrimSpace(body.Email) == "" {
		writeAdminError(w, http.StatusBadRequest, "Email is required")
		return
	}
	if firstUserPolicy(cfg.Admin.AccessPolicy) {
		writeAdminError(w, http.StatusNotImplemented, "Invitations are not available under the first-user access policy")
		return
	}
	hasSender := a.service.cfg.SendInvitation != nil
	reveal := !hasSender && cfg.Admin.RevealInvitationToken
	if !hasSender && !reveal {
		writeAdminError(w, http.StatusNotImplemented, "Invitation delivery is not configured")
		return
	}
	if gap := a.service.invitationCapabilityGap(); gap != "" {
		writeAdminError(w, http.StatusNotImplemented, "UserStore does not implement "+gap)
		return
	}

	by, kind := adminActor(r.Context())
	linkBase := cfg.LinkBase(a.ResolveSiteURL(r))
	result, err := a.service.InviteUser(adminInvitationContext(r, cfg), InviteUserInput{
		Email:         body.Email,
		TenantID:      body.TenantID,
		Role:          body.Role,
		Metadata:      body.Metadata,
		InvitedBy:     by,
		InvitedByKind: kind,
		LinkBase:      linkBase,
		Lang:          body.EmailLang,
	})
	switch {
	case errors.Is(err, ErrInvalidInput):
		writeAdminError(w, http.StatusBadRequest, "Email is required")
		return
	case errors.Is(err, ErrInvalidInvitationEmail):
		writeAdminError(w, http.StatusBadRequest, "Email is not a valid address")
		return
	case errors.Is(err, ErrUserExists):
		writeAdminError(w, http.StatusConflict, "User already exists")
		return
	case errors.Is(err, ErrInvitationMismatch):
		writeAdminError(w, http.StatusConflict, "Pending invitation has a different role or tenant")
		return
	case errors.Is(err, ErrDeliveryFailed):
		writeAdminError(w, http.StatusBadGateway, "Invitation could not be delivered")
		return
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	answer := map[string]any{
		"success":      true,
		"invitationId": result.Invitation.ID,
		"userId":       result.User.ID,
		"email":        result.Invitation.Email,
		"expiresAt":    result.Invitation.ExpiresAt,
	}
	if reveal {
		base := linkBase
		if base == "" {
			// No site URL to build on: the link is the route under the mount
			// prefix, relative to this host, rather than a path with no
			// prefix at all.
			base = cfg.Prefix()
		}
		answer["token"] = result.Token
		answer["acceptUrl"] = InvitationURL(base, result.Token)
	}
	status := http.StatusCreated
	if !result.AccountCreated {
		status = http.StatusOK
	}
	WriteJSON(w, status, answer)
}

// jsonContentType reports whether the request declares an application/json
// body, parameters such as charset allowed.
func jsonContentType(r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}

// firstUserPolicy reports whether the console is guarded by AdminFirstUser,
// the one policy an invitation can subvert: it names its user by user-id
// order, and an invitation writes an account with a random id at once.
func firstUserPolicy(policy *AdminAccessPolicy) bool {
	return policy != nil && policy.Predicate == nil && policy.Kind == AdminPolicyFirstUser
}

// adminInvitationRow is one invitation in the listing. It carries neither the
// token, which nothing stores, nor its hash.
type adminInvitationRow struct {
	ID            string         `json:"id"`
	UserID        string         `json:"userId"`
	Email         string         `json:"email"`
	TenantID      string         `json:"tenantId,omitempty"`
	Role          string         `json:"role,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	InvitedBy     string         `json:"invitedBy,omitempty"`
	InvitedByKind string         `json:"invitedByKind,omitempty"`
	CreatedAt     time.Time      `json:"createdAt"`
	ExpiresAt     time.Time      `json:"expiresAt"`
	// Status is "pending", or "expired" once ExpiresAt has passed: the
	// listing holds every invitation neither accepted nor revoked.
	Status string `json:"status"`
}

func newAdminInvitationRow(invitation Invitation, now time.Time) adminInvitationRow {
	status := "pending"
	if invitation.Expired(now) {
		status = "expired"
	}
	return adminInvitationRow{
		ID:            invitation.ID,
		UserID:        invitation.UserID,
		Email:         invitation.Email,
		TenantID:      invitation.TenantID,
		Role:          invitation.Role,
		Metadata:      invitation.Metadata,
		InvitedBy:     invitation.InvitedBy,
		InvitedByKind: invitation.InvitedByKind,
		CreatedAt:     invitation.CreatedAt,
		ExpiresAt:     invitation.ExpiresAt,
		Status:        status,
	}
}

// adminListInvitations is GET <admin>/api/users/invitations: the invitations
// neither accepted nor revoked, expired ones included and marked, in id order,
// paged by limit (default 20, at most 100) and offset as GET <admin>/api/users
// pages, with the same best-effort total.
func (a *Auth) adminListInvitations(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit := adminQueryInt(query.Get("limit"), 20)
	if limit > 100 {
		limit = 100
	}
	offset := adminQueryInt(query.Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}
	invitations, err := a.service.ListPendingInvitations(r.Context(), limit, offset)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	now := a.service.now()
	rows := make([]adminInvitationRow, 0, len(invitations))
	for _, invitation := range invitations {
		rows = append(rows, newAdminInvitationRow(invitation, now))
	}
	total := len(rows) + offset
	if len(rows) == limit {
		total++
	}
	WriteJSON(w, http.StatusOK, map[string]any{"invitations": rows, "total": total})
}

// adminRevokeInvitation is DELETE <admin>/api/users/invitations/{id}: 200
// {"success": true, "accountRemoved": …} for a pending invitation, expired or
// not; 404 "Invitation not found" for an unknown id; 409 "Invitation is no
// longer pending" for one already accepted or revoked. See
// Service.RevokeInvitation for which account goes with it — only one nothing
// has used — and Auth.RevokeInvitation, which this calls, for the linked
// accounts it also consults.
func (a *Auth) adminRevokeInvitation(w http.ResponseWriter, r *http.Request, cfg HTTPConfig, id string) {
	by, kind := adminActor(r.Context())
	result, err := a.RevokeInvitation(adminInvitationContext(r, cfg), id, by, kind)
	switch {
	case errors.Is(err, ErrInvitationNotFound):
		writeAdminError(w, http.StatusNotFound, "Invitation not found")
		return
	case errors.Is(err, ErrInvitationNotPending):
		writeAdminError(w, http.StatusConflict, "Invitation is no longer pending")
		return
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"success": true, "accountRemoved": result.AccountRemoved})
}
