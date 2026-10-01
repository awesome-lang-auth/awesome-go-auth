package auth

// This file is the event vocabulary: the twenty-six `identity.*` names the
// reference declares, and the two functions that hand the whole set to a caller
// that needs to enumerate it.
//
// Two trees are cited here and the difference between them is the whole reason
// this file is worth a header comment.
//
// The names themselves come from awesome-node-auth's
// src/events/auth-event-names.ts, which ships in both trees. What does *not*
// ship in the published reference is any code that publishes them: at
// ReferenceRevision the only `.publish` call outside the bus is
// AuthTools.track re-emitting whatever the host handed it (auth-tools.ts:231),
// so every name below is declared and none is raised by the library itself. The
// private development line is where the event plane exists — nineteen
// publication points in its auth router, four in its admin router and three in
// its configurator, twenty-six in all — and it is the tree this port follows,
// because it is the behaviour the family's next release will have.
//
// A reader who checks the published reference and finds no publisher has
// therefore checked the right file in the wrong tree, not found an invention.
// The convention this package already uses for that (see DevLineRevision) is
// followed throughout: a citation written "node-auth <file>:<line>" resolves
// against DevLineRevision, a bare "<file>:<line>" against ReferenceRevision.
//
// One name is dev-line only. USER_EMAIL_CHANGED / EventUserEmailChanged
// (node-auth auth-event-names.ts:9) does not exist at ReferenceRevision, whose
// file runs to twenty-five entries and stops at permission.revoked
// (auth-event-names.ts:5-40). It is carried because the route that raises it —
// POST <prefix>/change-email/confirm — exists in this port already, and a
// vocabulary that omitted the one name that route needs would force U18 to
// invent a spelling. The other twenty-five are byte-identical in the two trees.

// The identity.* event vocabulary, in the reference's declaration order and
// under the reference's grouping (auth-event-names.ts:5-40, node-auth
// auth-event-names.ts:5-41).
//
// These are untyped string constants rather than values of a named string type,
// and that is a decision rather than an oversight. A named type — the Go
// analogue of the reference's `AuthEventName` union (auth-event-names.ts:42) —
// would buy exhaustiveness nowhere, because Go has no exhaustive switch, and
// would cost a conversion at every boundary that already speaks `string`:
// Event.Name, EventBus.Subscribe's first parameter, WebhookConfig.Events,
// OutgoingWebhookEvent.Event, TelemetryEvent.EventName, TelemetryFilter.EventName
// and StreamEvent.Type are all `string` today, and every one of them is a place a
// caller will want to write a constant from this list. Untyped constants are
// assignable to all of them with no conversion and no API change, and they
// still fail the compile on a misspelling at the call site, which is the whole
// of what the union buys a TypeScript caller.
//
// The wire strings are what a subscriber matches on and what a webhook
// subscription stores, so they are the load-bearing half; the Go identifiers
// are this port's own and may be read as a convenience. Nothing may change a
// string here without changing it in the reference first.
const (
	// ---- User ----------------------------------------------------------------

	// EventUserCreated is raised once an account exists, by the register route
	// (node-auth auth.router.ts:813). Its data carries the email and whether the
	// host's onRegister hook or the default handler created the account.
	EventUserCreated = "identity.user.created"
	// EventUserDeleted is raised by the self-service account deletion route
	// after the cookies are cleared (node-auth auth.router.ts:1776).
	EventUserDeleted = "identity.user.deleted"
	// EventUserEmailChanged is the one name in this list that does not exist at
	// ReferenceRevision; see the file comment. The dev line raises it from
	// POST /change-email/confirm with both addresses in its data (node-auth
	// auth-event-names.ts:9, raised at node-auth auth.router.ts:1175).
	EventUserEmailChanged = "identity.user.email.changed"
	// EventUserEmailVerified is raised by the verification route once the flag
	// is written and the token cleared (node-auth auth.router.ts:1096).
	EventUserEmailVerified = "identity.user.email.verified"
	// EventUserPasswordChanged is raised by the authenticated change-password
	// route (node-auth auth.router.ts:1030). Note that the reset-password route
	// raises nothing: see EventNames for what that asymmetry means for U18.
	EventUserPasswordChanged = "identity.user.password.changed"
	// EventUser2FAEnabled is raised once a TOTP secret is confirmed and stored
	// (node-auth auth.router.ts:943). The digits in the Go identifiers here
	// follow Config.Require2FA, which is already the package's spelling of the
	// same concept.
	EventUser2FAEnabled = "identity.user.2fa.enabled"
	// EventUser2FADisabled is raised once the secret is removed (node-auth
	// auth.router.ts:997).
	EventUser2FADisabled = "identity.user.2fa.disabled"
	// EventUserLinked and EventUserUnlinked are declared by both trees and
	// raised by neither. The account-linking routes this port already serves —
	// POST <prefix>/link-verify and DELETE <prefix>/linked-accounts/... — are
	// the obvious sites, and U18 may not add them: a port does not publish where
	// the source does not. They are exported because a host that wires its own
	// linking flow needs the spelling, and because the webhook admin UI offers
	// the declared vocabulary, not the raised subset.
	EventUserLinked   = "identity.user.linked"
	EventUserUnlinked = "identity.user.unlinked"

	// ---- Session -------------------------------------------------------------

	// EventSessionCreated, EventSessionRevoked and EventSessionExpired are
	// declared and never raised, in either tree. Every place a session is
	// created the dev line raises a login or oauth success instead, with the
	// session id on the payload.
	EventSessionCreated = "identity.session.created"
	EventSessionRevoked = "identity.session.revoked"
	EventSessionExpired = "identity.session.expired"
	// EventSessionRotated is raised by the refresh route, and it is the only
	// session.* name with a publisher: its data carries the previous session id
	// (node-auth auth.router.ts:733).
	EventSessionRotated = "identity.session.rotated"

	// ---- Authentication ------------------------------------------------------

	// EventAuthLoginSuccess is the busiest name in the vocabulary: five of the
	// dev line's twenty-six publication points raise it, one per credential
	// (node-auth auth.router.ts:649 local, :968 totp, :1267 and :1282
	// magic-link, :1408 sms). Each distinguishes itself by a `method` key in
	// data rather than by a name of its own, which is why U18 must not invent
	// per-credential names.
	EventAuthLoginSuccess = "identity.auth.login.success"
	// EventAuthLoginFailed is raised only from the local login route, and only
	// for a 401 — the dev line's catch tests the status before publishing
	// (node-auth auth.router.ts:656), so a 500 from a broken store raises
	// nothing. It carries the attempted email and no user id, because at that
	// point there may be no user.
	EventAuthLoginFailed = "identity.auth.login.failed"
	// EventAuthLogout is raised after the cookies are cleared (node-auth
	// auth.router.ts:692), and only on the success path: the dev line's catch
	// clears the cookies a second time and publishes nothing.
	EventAuthLogout = "identity.auth.logout"
	// EventAuthOAuthSuccess is raised once per completed OAuth callback, from
	// handleOAuthLogin — the shared helper all three callback routes reach, and
	// therefore one publication point serving three routes (node-auth
	// auth.router.ts:1444). It is a separate name from EventAuthLoginSuccess
	// even though an OAuth callback is a login, and it is raised only on the
	// path that issues tokens: a callback that diverts to the 2FA page returns
	// before it (:1440).
	EventAuthOAuthSuccess = "identity.auth.oauth.success"
	// EventAuthOAuthConflict is raised three times, once per conflict site
	// (node-auth auth.router.ts:1480, :1530, :1580), and is the one name raised
	// on a path that ends in a redirect rather than a JSON body. It carries no
	// user id — there is no user yet — and carries the provider, the address
	// (cut to 320 UTF-16 code units) and the provider account id, the three
	// keys oauthConflictEventData picks (router-events.ts:54-67 at 1.10.8).
	EventAuthOAuthConflict = "identity.auth.oauth.conflict"

	// ---- Tenant --------------------------------------------------------------

	// The four tenant names are declared by both trees and raised by neither,
	// although Service.CreateTenant and Service.AddUserToTenant exist here and
	// the equivalents exist there. U18 does not add them for the same reason it
	// does not add the linking names.
	EventTenantCreated     = "identity.tenant.created"
	EventTenantDeleted     = "identity.tenant.deleted"
	EventTenantUserAdded   = "identity.tenant.user.added"
	EventTenantUserRemoved = "identity.tenant.user.removed"

	// ---- Authorization -------------------------------------------------------

	// EventRoleAssigned and EventRoleRevoked are the two names raised from
	// outside the auth router. Five sites raise the first — three in the admin
	// router (node-auth admin.router.ts:1002, :1041, :1055) and two in the
	// configurator's promoteToAdmin (node-auth auth-configurator.ts:92, :104) —
	// and two raise the second (node-auth admin.router.ts:1020,
	// auth-configurator.ts:133). The four admin-router sites are this port's as
	// of M8: POST <admin>/api/users/{id}/roles, DELETE
	// <admin>/api/users/{id}/roles/{role} and both branches of POST
	// <admin>/users/{id}/promote. The three configurator sites have no
	// counterpart here and are the remainder of U18's twenty-six that U18 could
	// not reach — AuthConfigurator is the dev line's imperative facade over its
	// routers, and this port's facade is Auth, whose surface is the routes.
	//
	// node-auth admin.router.ts:1002 is also the single publication point in the
	// whole of the dev line that passes a tenant id. Every other one leaves
	// Event.TenantID empty.
	EventRoleAssigned = "identity.role.assigned"
	EventRoleRevoked  = "identity.role.revoked"
	// EventPermissionGranted and EventPermissionRevoked are declared and never
	// raised, in either tree.
	EventPermissionGranted = "identity.permission.granted"
	EventPermissionRevoked = "identity.permission.revoked"
)

// eventNames is the vocabulary in the reference's declaration order. It is a
// package-level slice so that the order is written once; EventNames copies it
// rather than returning it, for the reason CompatibilityNotes returns a fresh
// value — a caller that sorts or truncates its own view must not change the
// next caller's.
var eventNames = []string{
	EventUserCreated,
	EventUserDeleted,
	EventUserEmailChanged,
	EventUserEmailVerified,
	EventUserPasswordChanged,
	EventUser2FAEnabled,
	EventUser2FADisabled,
	EventUserLinked,
	EventUserUnlinked,

	EventSessionCreated,
	EventSessionRevoked,
	EventSessionExpired,
	EventSessionRotated,

	EventAuthLoginSuccess,
	EventAuthLoginFailed,
	EventAuthLogout,
	EventAuthOAuthSuccess,
	EventAuthOAuthConflict,

	EventTenantCreated,
	EventTenantDeleted,
	EventTenantUserAdded,
	EventTenantUserRemoved,

	EventRoleAssigned,
	EventRoleRevoked,
	EventPermissionGranted,
	EventPermissionRevoked,
}

// EventNames returns the whole identity.* vocabulary, in the reference's
// declaration order.
//
// The order is the reference's grouping — user, session, authentication,
// tenant, authorization — and not alphabetical, because the two consumers that
// show the list to a person show it in this order: a webhook admin screen
// offers the names as checkboxes, and the OpenAPI document describes the
// `events` field of a webhook subscription by enumerating them. Sorting would
// scatter `identity.user.2fa.enabled` away from the rest of the user block for
// no gain.
//
// Three things need the full set rather than the fifteen names anything
// actually raises, and each needs it for a different reason:
//
//   - The webhook admin UI (U14 and the admin routes behind it) offers a
//     subscriber every name the library might ever raise, not the subset it
//     raises today. A subscription created against a name nothing raises yet is
//     valid and simply never fires; one that could not be created at all would
//     have to be created again after every release that adds a publisher.
//   - The OpenAPI document describes the format of WebhookConfig.Events. The
//     wildcard aside (WebhookEventWildcard), this list is the domain of that
//     field.
//   - The conformance test that U18 ends with asserts that this port raises an
//     event at each of the twenty-six places the dev line raises one. That test
//     counts publication points against the dev line, not names against this
//     list — the two numbers are both twenty-six by coincidence, since fifteen
//     distinct names cover twenty-six sites and twenty-six names are declared.
//     It needs this function to assert that every name it expects is a name the
//     package actually declares, so that a typo in the test fails the test
//     rather than silently passing against a name nobody publishes.
//
// The returned slice is freshly allocated and shares nothing with the package.
func EventNames() []string {
	out := make([]string, len(eventNames))
	copy(out, eventNames)
	return out
}

// IsEventName reports whether name is one of the declared identity.* names.
//
// It is a membership test over the vocabulary and nothing more: it does not
// reject a name this library never raises, and it does not accept
// WebhookEventWildcard, which is a subscription term rather than an event name
// — WebhookConfig.Matches handles that one, and a store or an admin route that
// validates a subscription has to allow both this and the wildcard.
//
// The linear scan is deliberate. Twenty-six comparisons of short strings that
// share a seven-byte prefix cost less than the map lookup that would replace
// them, and a map would have to be built at init time for a function that a
// validating admin route calls at most once per request.
func IsEventName(name string) bool {
	for _, known := range eventNames {
		if known == name {
			return true
		}
	}
	return false
}
