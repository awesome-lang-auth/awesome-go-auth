package nethttp

import (
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// The public half of the invitation flow (invitation.go in the root package):
// POST <prefix>/invitations/accept. The admin half is inside AdminHandler.
//
// The handler is written once, here, and the chi, gin and echo mounts serve it
// as they serve the OAuth group: the route is entirely body-driven, so a second
// implementation would only be somewhere for the adapters to drift.

// InvitationAcceptHandler serves POST <prefix>/invitations/accept, already
// wrapped in guard — the event-context carrier, the rate-limiter slot and the
// CSRF middleware, which exempts the route as it exempts /reset-password.
// Mount mounts it only when Auth.InvitationsEnabled, and never under
// HTTPConfig.ResourceServer; HTTPConfig.ClosedRegistration leaves it mounted.
func (a *Adapter) InvitationAcceptHandler() http.Handler {
	return a.guard(http.HandlerFunc(a.AcceptInvitation))
}

// AcceptInvitation handles POST <prefix>/invitations/accept {token, password}.
// The answer is auth.HTTPConfig.WriteInvitationAcceptance's: the login's
// challenge when a second factor is demanded, the registration's 201
// otherwise; every refusal of the token is the one 401 INVALID_INVITATION.
func (a *Adapter) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	var req auth.InvitationAcceptRequest
	if !auth.DecodeOptionalJSON(w, r, &req) {
		return
	}
	acceptance, err := a.auth.AcceptInvitation(r.Context(), auth.AcceptInvitationInput(req))
	if err != nil {
		auth.WriteHTTPError(w, auth.InvitationAcceptHTTPError(err))
		return
	}
	a.cfg.WriteInvitationAcceptance(w, r, acceptance)
}
