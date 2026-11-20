package auth

import (
	"context"
	"net/http"
)

// Machine access to the admin API: AdminOptions.MachineAccess, a seam through
// which a back-office service reaches the guarded admin routes on a credential
// the host verifies.
//
// The reference offers two credentials for this surface and neither fits a
// service. The deprecated adminSecret is one shared bearer string for every
// caller, with no identity to audit (admin.router.ts:252-266). The session
// policies need a user account and a session token, which for a service means
// a password and a second factor kept in a secret store, and a login before
// every batch — the interim arrangement a deployment is forced into without
// this. A host that already authenticates its services — IAM-signed requests
// at an API gateway, mutual TLS, a scoped API key — has no way to say so.
//
// The seam is a function rather than a credential type because the deciding
// is the host's: this package cannot verify a SigV4 signature it never sees,
// and should not ship a parser for headers whose trust depends on the
// deployment in front of it. What the package owns is where the decision sits
// — ahead of the session policy, on every guarded route — and the audit
// record each admitted call leaves.

// EventAdminMachineAccess is raised for every admin request MachineAccess
// admits, through the admin router's publisher, so it carries the request's
// correlation id, client address and user agent. Its data is the principal
// the host named, the method and the path below the admin mount:
//
//	{"principal": "svc:identity", "method": "DELETE", "path": "/api/users/usr_…"}
//
// It names no user, because the caller is not one, and no tenant.
//
// It is deliberately outside the identity.* vocabulary EventNames returns:
// that list is the reference's, and nothing may join it without the reference
// declaring it first. So IsEventName reports false for it, and a webhook
// subscription offered the vocabulary does not list it — a subscriber that
// wants it subscribes to the name, or to the wildcard. With no event bus
// configured nothing is recorded at all; a deployment that relies on this as
// its audit trail configures one.
const EventAdminMachineAccess = "identity.admin.machine.access"

type adminMachinePrincipalContextKey struct{}

// AdminMachinePrincipalFromContext returns the principal AdminOptions.MachineAccess
// admitted the request as, and whether it was a machine request at all. A
// handler behind the guard reads it the way it reads AdminUserFromContext for
// a person; the two are never both set.
func AdminMachinePrincipalFromContext(ctx context.Context) (string, bool) {
	principal, ok := ctx.Value(adminMachinePrincipalContextKey{}).(string)
	return principal, ok && principal != ""
}

// machineAccess runs AdminOptions.MachineAccess for r. It reports whether the
// request is admitted, and the context the handler should see when it is: the
// principal installed, the audit event raised.
func (g *AdminGuard) machineAccess(r *http.Request) (bool, context.Context) {
	decide := g.cfg.Admin.MachineAccess
	if decide == nil {
		return false, nil
	}
	principal, ok := decide(r)
	if !ok {
		return false, nil
	}
	if principal == "" {
		g.auth.service.logf("auth: admin: MachineAccess admitted a request without naming a principal; " +
			"it is refused on the machine path and left to the session policy")
		return false, nil
	}
	path := adminRouterPath(r, g.cfg)
	g.auth.publishAdminEvent(r, g.cfg, func() Event {
		return Event{
			Name: EventAdminMachineAccess,
			Data: map[string]any{"principal": principal, "method": r.Method, "path": path},
		}
	})
	return true, context.WithValue(r.Context(), adminMachinePrincipalContextKey{}, principal)
}
