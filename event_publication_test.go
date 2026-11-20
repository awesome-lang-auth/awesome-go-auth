package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file is the conformance test for the event plane: it pins, site by site,
// that this port raises an identity.* event at every place the source raises
// one — and says, for each place it does not, which surface is missing and
// which milestone will add it.
//
// Which source. Not the published reference: at ReferenceRevision nothing in
// awesome-node-auth publishes at all, and the one `.publish` outside the bus is
// AuthTools.track re-emitting what a host handed it (auth-tools.ts:231). The
// publication points live in the private development line, and every citation
// in the table below is therefore a dev-line citation written in the convention
// this package already uses: "node-auth <file>:<line>" resolves against
// DevLineRevision, a bare "<file>:<line>" against ReferenceRevision.
// TestPublicationSitesCiteTheDevLine is where that is enforced rather than
// trusted, so a reader who checks the published tree and finds no publisher has
// checked the right file in the wrong tree.
//
// The arithmetic this file exists to make machine-checked was 19 + 7 = 26 when
// U18 wrote it, and M8 has moved it to 23 + 3 = 26. Twenty-six publication
// points; nineteen in the dev line's auth router and four in its admin router,
// both of which this port now has; three in its configurator, which it does
// not and will not. The plan asks for "26 publication points out of 26
// exercised by the tests", and a comment claiming that is worth nothing — the
// interesting failure is not a site that stops publishing, which any assertion
// catches, but a site quietly reclassified as unreachable the first time it is
// inconvenient.
//
// TestPublicationSiteReachabilityFollowsTheFile is what makes that impossible:
// reachability is not a field an editor may set as they please, it is a
// function of which dev-line FILE the citation names, and the table has to
// agree with the file or the test fails. Marking a live auth.router.ts site
// unreachable to silence it fails; claiming a configurator publication this
// port does not have fails too.
//
// That per-file grain is why U16 could not port two of admin.router.ts's four
// sites and leave the other two alone. Making the promote pair reachable means
// saying this port has that file, and saying so obliges the role pair beside
// them — which U14 mounted as routes and left silent — to publish as well. The
// invariant did its job: it turned "add the two events my PR needs" into "port
// the file's publication points", which is the only version of that claim a
// reader can check.
//
// The table is declarative on purpose. Exercise drives the port and asserts
// nothing about events; what the payload has to be is data. That split is what
// lets the identical nineteen exercises run a second time against a service
// with no bus, where the whole assertion is that nothing was published at all.

// ── the twenty-six ───────────────────────────────────────────────────────────

// publicationSite is one of the twenty-six places the dev line publishes.
type publicationSite struct {
	// Citation is the dev-line file:line, resolved against DevLineRevision.
	Citation string
	// Route is the surface the dev line publishes from, for a reader.
	Route string
	// Event is the name raised. It must be a declared name — asserted, so that a
	// typo here fails rather than quietly pinning nothing.
	Event string
	// DataKeys is the exact key set of the event's `data` object. Exact, not
	// "at least": a payload that grew a key is as much a difference from the
	// source as one that lost a key, and a subscriber written against the dev
	// line sees both.
	DataKeys []string
	// DataValues pins the values that are fixed for this site. A key whose value
	// is decided at run time — a session id, an address the exercise chose — is
	// left out and checked by Assert instead.
	DataValues map[string]any
	// WantUserID and WantSessionID are whether the payload names a user and a
	// session. Both are facts about the site rather than about the name: the
	// failed login carries no user id although a user may well exist, and only
	// the eight sites that follow an issueTokens carry a session.
	WantUserID    bool
	WantSessionID bool
	// WantTenantID is whether the payload names a tenant, and it is true at
	// exactly one of the twenty-six: node-auth admin.router.ts:1002, which reads
	// a tenantId off the request body. U18 could assert "no reachable site fills
	// this in" because that one was out of reach; now that it is reachable the
	// claim has to be per-site, and TestExactlyOneSitePassesATenant keeps it
	// from becoming per-site in the wrong direction.
	WantTenantID bool
	// Exercise drives this port to the point the dev line publishes. It is
	// non-nil exactly for the reachable sites, and it asserts only on what the
	// port returned — never on what was published, so that the same function can
	// be run against a service with no bus.
	Exercise func(t *testing.T, h *eventHarness)
	// Assert is the site's extra check on the published event, for what a
	// declarative value cannot say. Optional.
	Assert func(t *testing.T, ev Event)
	// Unreachable names the surface this port does not have, and Milestone the
	// milestone that will add it. Both non-empty exactly for the unreachable
	// sites, and both are required: "this port does not publish it yet" is only
	// an acceptable answer when it says what is missing and when that changes.
	Unreachable string
	Milestone   string
}

func (s publicationSite) reachable() bool { return s.Exercise != nil }

// publicationSites is U18's map of the dev line, verified against the tree
// rather than copied: the nineteen `publishRouterEvent` calls in
// node-auth src/router/auth.router.ts, the four `publishAdminEvent` calls in
// node-auth src/router/admin.router.ts and the three
// `this.options.eventBus?.publish` calls in node-auth src/auth-configurator.ts.
//
// Fifteen distinct names cover the twenty-six sites, and eleven of the
// twenty-six declared names are raised by neither tree. EventNames() is the
// vocabulary and this is the publication map; they are different lists that
// happen to be the same length.
func publicationSites() []publicationSite {
	return []publicationSite{
		// ── node-auth src/router/auth.router.ts: the nineteen this port has ──

		{
			Citation: "node-auth auth.router.ts:649", Route: "POST <prefix>/login",
			Event:    EventAuthLoginSuccess,
			DataKeys: []string{"method"}, DataValues: map[string]any{"method": loginMethodLocal},
			WantUserID: true, WantSessionID: true,
			Exercise: func(t *testing.T, h *eventHarness) {
				h.register(t, "login-success@example.com")
				h.reset()
				if _, _, err := h.svc.Login(h.ctx, LoginInput{
					Email: "login-success@example.com", Password: harnessPassword, TenantID: harnessTenant,
				}); err != nil {
					t.Fatalf("login: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:656", Route: "POST <prefix>/login, in the catch, for a 401 only",
			Event:    EventAuthLoginFailed,
			DataKeys: []string{"method", "email"},
			DataValues: map[string]any{
				"method": loginMethodLocal, "email": "login-failed@example.com",
			},
			WantUserID: false, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) {
				h.register(t, "login-failed@example.com")
				h.reset()
				if _, _, err := h.svc.Login(h.ctx, LoginInput{
					Email: "login-failed@example.com", Password: "not-the-password", TenantID: harnessTenant,
				}); err == nil {
					t.Fatal("login with a wrong password succeeded")
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:692", Route: "POST <prefix>/logout",
			Event: EventAuthLogout, DataKeys: nil,
			WantUserID: true, WantSessionID: true,
			Exercise: func(t *testing.T, h *eventHarness) {
				_, tokens := h.register(t, "logout@example.com")
				h.reset()
				if err := h.svc.Logout(h.ctx, tokens.RefreshToken); err != nil {
					t.Fatalf("logout: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:733", Route: "POST <prefix>/refresh",
			Event: EventSessionRotated, DataKeys: []string{"previousSessionId"},
			WantUserID: true, WantSessionID: true,
			Exercise: func(t *testing.T, h *eventHarness) {
				_, tokens := h.register(t, "rotate@example.com")
				h.reset()
				if _, err := h.svc.Refresh(h.ctx, tokens.RefreshToken); err != nil {
					t.Fatalf("refresh: %v", err)
				}
			},
			// The two ids are equal in this port and differ in the dev line; see
			// the session-rotated-reports-one-session-id deviation. What holds in
			// both trees, and what this asserts, is that the key names the session
			// the presented token came from.
			Assert: func(t *testing.T, ev Event) {
				if ev.Data["previousSessionId"] != ev.SessionID {
					t.Fatalf("previousSessionId = %v, want the rotated session %q "+
						"(see the session-rotated-reports-one-session-id deviation)",
						ev.Data["previousSessionId"], ev.SessionID)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:813", Route: "POST <prefix>/register",
			Event:    EventUserCreated,
			DataKeys: []string{"email", "method"},
			// 'custom' is the other branch there and is unreachable here: this
			// port has no onRegister hook. See registerMethodDefault.
			DataValues: map[string]any{
				"email": "created@example.com", "method": registerMethodDefault,
			},
			WantUserID: true, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) {
				// With Config.IssueSessionOnRegister off, so that the site's own
				// event is the only one: with it on, the session the registration
				// opens raises identity.auth.login.success after it, as a login
				// does — TestRegister_OnOpensTheLoginsSession pins that.
				h.svc.cfg.IssueSessionOnRegister = false
				h.reset()
				h.register(t, "created@example.com")
			},
		},
		{
			Citation: "node-auth auth.router.ts:943", Route: "POST <prefix>/2fa/verify-setup",
			Event: EventUser2FAEnabled, DataKeys: nil,
			WantUserID: true, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) {
				user, _ := h.register(t, "2fa-on@example.com")
				secret := h.totpSecret(t, user)
				h.reset()
				if err := h.svc.VerifyTOTPSetup(h.ctx, user.ID, harnessTenant, secret, h.totpCode(t, secret)); err != nil {
					t.Fatalf("verify totp setup: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:968", Route: "POST <prefix>/2fa/verify",
			Event:    EventAuthLoginSuccess,
			DataKeys: []string{"method"}, DataValues: map[string]any{"method": loginMethodTOTP},
			WantUserID: true, WantSessionID: true,
			Exercise: func(t *testing.T, h *eventHarness) {
				user, _ := h.register(t, "2fa-login@example.com")
				secret := h.enableTOTP(t, user)
				h.reset()
				if _, _, err := h.svc.VerifyTOTP(h.ctx, user.ID, harnessTenant, h.totpCode(t, secret)); err != nil {
					t.Fatalf("verify totp: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:997", Route: "POST <prefix>/2fa/disable",
			Event: EventUser2FADisabled, DataKeys: nil,
			WantUserID: true, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) {
				user, _ := h.register(t, "2fa-off@example.com")
				h.enableTOTP(t, user)
				h.reset()
				if err := h.svc.DisableTOTP(h.ctx, user.ID, harnessTenant); err != nil {
					t.Fatalf("disable totp: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:1030", Route: "POST <prefix>/change-password",
			Event: EventUserPasswordChanged, DataKeys: nil,
			WantUserID: true, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) {
				user, _ := h.register(t, "changepw@example.com")
				h.reset()
				if err := h.svc.ChangePassword(h.ctx, ChangePasswordInput{
					UserID: user.ID, TenantID: harnessTenant,
					CurrentPassword: harnessPassword, NewPassword: "a-new-password",
				}); err != nil {
					t.Fatalf("change password: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:1096", Route: "GET <prefix>/verify-email",
			Event: EventUserEmailVerified, DataKeys: nil,
			WantUserID: true, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) {
				user, _ := h.register(t, "verify-email@example.com")
				token, err := h.svc.SendVerificationEmailToken(h.ctx, EmailVerificationInput{
					UserID: user.ID, TenantID: harnessTenant,
				})
				if err != nil || token == "" {
					t.Fatalf("send verification token = %q, %v", token, err)
				}
				h.reset()
				if err := h.svc.VerifyEmail(h.ctx, VerifyEmailInput{Token: token}); err != nil {
					t.Fatalf("verify email: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:1175", Route: "POST <prefix>/change-email/confirm",
			Event:    EventUserEmailChanged,
			DataKeys: []string{"oldEmail", "newEmail"},
			DataValues: map[string]any{
				"oldEmail": "old-address@example.com", "newEmail": "new-address@example.com",
			},
			WantUserID: true, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) {
				user, _ := h.register(t, "old-address@example.com")
				token, err := h.svc.RequestEmailChange(h.ctx, ChangeEmailRequestInput{
					UserID: user.ID, TenantID: harnessTenant, NewEmail: "new-address@example.com",
				})
				if err != nil || token == "" {
					t.Fatalf("request email change = %q, %v", token, err)
				}
				h.reset()
				if err := h.svc.ConfirmEmailChange(h.ctx, ConfirmEmailChangeInput{Token: token}); err != nil {
					t.Fatalf("confirm email change: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:1267", Route: "POST <prefix>/magic-link/verify, mode=2fa",
			Event:    EventAuthLoginSuccess,
			DataKeys: []string{"method"}, DataValues: map[string]any{"method": loginMethodMagicLink},
			WantUserID: true, WantSessionID: true,
			Exercise: func(t *testing.T, h *eventHarness) {
				user, _ := h.register(t, "magic-stepup@example.com")
				token := h.magicLinkToken(t, "magic-stepup@example.com")
				h.reset()
				// The step-up branch: the link has to belong to the user the temp
				// token already identified.
				if _, _, err := h.svc.VerifyMagicLinkForUser(h.ctx, MagicLinkVerifyInput{Token: token}, user.ID); err != nil {
					t.Fatalf("verify magic link for user: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:1282", Route: "POST <prefix>/magic-link/verify, mode=login",
			Event:    EventAuthLoginSuccess,
			DataKeys: []string{"method"}, DataValues: map[string]any{"method": loginMethodMagicLink},
			WantUserID: true, WantSessionID: true,
			Exercise: func(t *testing.T, h *eventHarness) {
				h.register(t, "magic-login@example.com")
				token := h.magicLinkToken(t, "magic-login@example.com")
				h.reset()
				if _, _, err := h.svc.VerifyMagicLink(h.ctx, MagicLinkVerifyInput{Token: token}); err != nil {
					t.Fatalf("verify magic link: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:1408", Route: "POST <prefix>/sms/verify",
			Event:    EventAuthLoginSuccess,
			DataKeys: []string{"method"}, DataValues: map[string]any{"method": loginMethodSMS},
			WantUserID: true, WantSessionID: true,
			Exercise: func(t *testing.T, h *eventHarness) {
				user := h.seedWithPhone(t, "sms@example.com", "+15555550100")
				code, err := h.svc.SendSMSCode(h.ctx, SMSCodeSendInput{UserID: user.ID, TenantID: harnessTenant})
				if err != nil || code == "" {
					t.Fatalf("send sms code = %q, %v", code, err)
				}
				h.reset()
				if _, _, err := h.svc.VerifySMSCode(h.ctx, SMSCodeVerifyInput{
					UserID: user.ID, TenantID: harnessTenant, Code: code,
				}); err != nil {
					t.Fatalf("verify sms code: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:1444", Route: "handleOAuthLogin, reached by all three OAuth callbacks",
			Event:    EventAuthOAuthSuccess,
			DataKeys: []string{"provider", "redirectTo"},
			DataValues: map[string]any{
				"provider": "acme", "redirectTo": harnessSiteURL,
			},
			WantUserID: true, WantSessionID: true,
			Exercise: func(t *testing.T, h *eventHarness) {
				f := h.oauth(t)
				h.reset()
				if _, err := f.complete(t, "acme", "oauth-new@example.com"); err != nil {
					t.Fatalf("oauth complete: %v", err)
				}
			},
		},
		{
			Citation: "node-auth auth.router.ts:1480", Route: "GET <prefix>/oauth/google/callback, in the catch",
			Event:    EventAuthOAuthConflict,
			DataKeys: []string{"provider", "email", "providerAccountId"},
			DataValues: map[string]any{
				"provider": "google", "email": "google-held@example.com",
				"providerAccountId": "google-account-1",
			},
			WantUserID: false, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) { h.oauthConflict(t, "google") },
		},
		{
			Citation: "node-auth auth.router.ts:1530", Route: "GET <prefix>/oauth/github/callback, in the catch",
			Event:    EventAuthOAuthConflict,
			DataKeys: []string{"provider", "email", "providerAccountId"},
			DataValues: map[string]any{
				"provider": "github", "email": "github-held@example.com",
				"providerAccountId": "github-account-1",
			},
			WantUserID: false, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) { h.oauthConflict(t, "github") },
		},
		{
			Citation: "node-auth auth.router.ts:1580", Route: "GET <prefix>/oauth/{provider}/callback, in the catch",
			Event:    EventAuthOAuthConflict,
			DataKeys: []string{"provider", "email", "providerAccountId"},
			DataValues: map[string]any{
				"provider": "acme", "email": "acme-held@example.com",
				"providerAccountId": "acme-account-1",
			},
			WantUserID: false, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) { h.oauthConflict(t, "acme") },
		},
		{
			Citation: "node-auth auth.router.ts:1776", Route: "DELETE <prefix>/account",
			Event: EventUserDeleted, DataKeys: nil,
			WantUserID: true, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) {
				user, _ := h.register(t, "deleted@example.com")
				h.reset()
				if err := h.svc.DeleteAccount(h.ctx, DeleteAccountInput{UserID: user.ID, TenantID: harnessTenant}); err != nil {
					t.Fatalf("delete account: %v", err)
				}
			},
		},

		// ── node-auth src/router/admin.router.ts: the four M8 brought in reach ──
		//
		// These four are driven over HTTP and the nineteen above are not, and
		// that is the substance rather than an inconvenience. The nineteen
		// publish from Service methods, which receive the request provenance on
		// a context an adapter's EventContextMiddleware installed; the admin
		// console is outside that middleware on both lines, so its four read the
		// request at the publication site instead — the dev line's
		// publishAdminEvent calling getRequestEventContext(req), ported as
		// (*Auth).publishAdminEvent. adminEventFixture.do sends the three
		// harness values as a header, a header and a socket address, so the
		// provenance assertion in TestEveryReachableSitePublishes is checking
		// that path end to end and not a context the test installed itself.

		// This is also the single publication point in the whole of the dev line
		// that passes a tenant id, and it reads it off the request *body* — so
		// the exercise sends one, and WantTenantID is true here and nowhere else.
		{
			Citation: "node-auth admin.router.ts:1002", Route: "POST <admin>/api/users/:id/roles",
			Event: EventRoleAssigned, DataKeys: []string{"role"},
			DataValues: map[string]any{"role": "editor"},
			WantUserID: true, WantSessionID: false, WantTenantID: true,
			Exercise: func(t *testing.T, h *eventHarness) {
				f := h.admin(t)
				// The role has to exist first: MemoryRolesPermissionsStore
				// refuses an assignment naming a role it does not hold, which is
				// the same rule that makes the promote route's createRole call
				// load-bearing rather than decorative. POST /api/roles publishes
				// nothing, and the reset below makes that assertable.
				f.do(t, http.MethodPost, AdminRolesPath, `{"name": "editor"}`)
				h.reset()
				f.do(t, http.MethodPost, "/api/users/role-target/roles",
					`{"role": "editor", "tenantId": "`+harnessTenant+`"}`)
			},
			// The tenant is the body's and not the path's: this route has no
			// tenant in its pattern at all.
			Assert: func(t *testing.T, ev Event) {
				if ev.TenantID != harnessTenant {
					t.Fatalf("TenantID = %q, want the tenantId the body carried (%q)", ev.TenantID, harnessTenant)
				}
			},
		},
		{
			Citation: "node-auth admin.router.ts:1020", Route: "DELETE <admin>/api/users/:id/roles/:role",
			Event: EventRoleRevoked, DataKeys: []string{"role"},
			DataValues: map[string]any{"role": "editor"},
			WantUserID: true, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) {
				f := h.admin(t)
				h.reset()
				f.do(t, http.MethodDelete, "/api/users/role-target/roles/editor", "")
			},
		},
		{
			Citation: "node-auth admin.router.ts:1041", Route: "POST <admin>/users/:id/promote, method=flag",
			Event: EventRoleAssigned, DataKeys: []string{"role", "method"},
			DataValues: map[string]any{"role": "admin", "method": adminPromoteMethodFlag},
			WantUserID: true, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) {
				f := h.admin(t)
				// method=flag writes through the user store, so unlike the other
				// three this one needs the row to exist — and in the empty
				// tenant, because the route addresses it by id alone.
				h.seedUntenanted(t, "promote-flag")
				h.reset()
				f.do(t, http.MethodPost, "/users/promote-flag/promote", `{"method": "flag"}`)
			},
		},
		{
			Citation: "node-auth admin.router.ts:1055", Route: "POST <admin>/users/:id/promote, method=role",
			Event: EventRoleAssigned, DataKeys: []string{"role", "method"},
			DataValues: map[string]any{"role": "admin", "method": adminPromoteMethodRole},
			WantUserID: true, WantSessionID: false,
			Exercise: func(t *testing.T, h *eventHarness) {
				f := h.admin(t)
				h.reset()
				// No body at all, which is the branch an absent `method` takes.
				f.do(t, http.MethodPost, "/users/promote-role/promote", "")
			},
		},

		// ── node-auth src/auth-configurator.ts: the three with no counterpart ──

		// These three differ from every other site in the map in one further way:
		// they publish through the bus directly rather than through
		// publishRouterEvent, so they carry no correlation id, no client address
		// and no user agent. A configurator method is not serving a request.
		{
			Citation: "node-auth auth-configurator.ts:92", Route: "AuthConfigurator.promoteToAdmin, method=flag",
			Event: EventRoleAssigned, DataKeys: []string{"role", "method"},
			WantUserID: true, WantSessionID: false,
			Unreachable: "this port has no configurator: AuthConfigurator is the dev line's imperative " +
				"facade over the routers, and nothing in this package corresponds to it",
			Milestone: "none planned — the facade this port offers is Auth, whose surface is the routes",
		},
		{
			Citation: "node-auth auth-configurator.ts:104", Route: "AuthConfigurator.promoteToAdmin, method=role",
			Event: EventRoleAssigned, DataKeys: []string{"role", "method"},
			WantUserID: true, WantSessionID: false,
			Unreachable: "this port has no configurator: AuthConfigurator is the dev line's imperative " +
				"facade over the routers, and nothing in this package corresponds to it",
			Milestone: "none planned — the facade this port offers is Auth, whose surface is the routes",
		},
		{
			Citation: "node-auth auth-configurator.ts:133", Route: "AuthConfigurator.revokeAdmin",
			Event: EventRoleRevoked, DataKeys: []string{"role", "method"},
			WantUserID: true, WantSessionID: false,
			Unreachable: "this port has no configurator: AuthConfigurator is the dev line's imperative " +
				"facade over the routers, and nothing in this package corresponds to it",
			Milestone: "none planned — the facade this port offers is Auth, whose surface is the routes",
		},
	}
}

// ── the arithmetic ───────────────────────────────────────────────────────────

// The three files the dev line publishes from, and how many times each does.
// The counts are the whole of the map's claim about the source, and they are
// what a maintainer re-derives with a grep when the dev line moves:
//
//	grep -c publishRouterEvent   node-auth/src/router/auth.router.ts   # 19 + 1 def
//	grep -c publishAdminEvent    node-auth/src/router/admin.router.ts  #  4 + 1 def
//	grep -c 'eventBus?.publish'  node-auth/src/auth-configurator.ts    #  3
//
// Two of the three are ported. The third will not be: AuthConfigurator is the
// dev line's imperative facade over its routers — promoteToAdmin and
// revokeAdmin, called by a host's own bootstrap code rather than by a request —
// and this port's facade is Auth, whose surface is the routes. Its three sites
// are unreachable permanently and say so.
var devLineFiles = []struct {
	file string
	// sites is how many publication points the file holds.
	sites int
	// ported is whether this port has the surface the file is.
	ported bool
}{
	{file: "node-auth auth.router.ts:", sites: 19, ported: true},
	{file: "node-auth admin.router.ts:", sites: 4, ported: true},
	{file: "node-auth auth-configurator.ts:", sites: 3, ported: false},
}

// TestPublicationSiteCountIsTwentySix is the 23 + 3 = 26 this milestone leaves
// behind — U18's 19 + 7 with the admin router's four moved across — written as
// arithmetic rather than as a sentence.
func TestPublicationSiteCountIsTwentySix(t *testing.T) {
	sites := publicationSites()
	if len(sites) != 26 {
		t.Fatalf("the map has %d sites, want the dev line's 26", len(sites))
	}

	var reachable, unreachable int
	for _, s := range sites {
		if s.reachable() {
			reachable++
		} else {
			unreachable++
		}
	}
	if reachable != 23 || unreachable != 3 {
		t.Errorf("reachable = %d and unreachable = %d, want 23 and 3. "+
			"Moving a site between the two columns is a claim about which surfaces this port has; "+
			"if one really has moved, the counts here and in devLineFiles move with it. "+
			"The three that remain are the configurator's, which has no counterpart here at all.",
			reachable, unreachable)
	}

	seen := make(map[string]bool, len(sites))
	for _, s := range sites {
		if seen[s.Citation] {
			t.Errorf("citation %q appears twice: each of the twenty-six is one line of one file", s.Citation)
		}
		seen[s.Citation] = true
	}
}

// TestPublicationSiteReachabilityFollowsTheFile is the test that makes
// "unreachable" mean something.
//
// Reachability is not an editorial choice. A site in the dev line's auth router
// is a route this port serves, so it must be exercised; a site in the admin
// router or the configurator is a surface this port does not have, so it must
// carry the surface that is missing and the milestone that will add it. The
// table has to agree with the file the citation names, which is what stops a
// failing auth.router.ts site from being reclassified into silence — the one
// failure mode a conformance test that could not tell "not ported" from
// "broken" would actually have.
func TestPublicationSiteReachabilityFollowsTheFile(t *testing.T) {
	counts := make(map[string]int, len(devLineFiles))

	for _, s := range publicationSites() {
		var matched bool
		for _, f := range devLineFiles {
			if !strings.HasPrefix(s.Citation, f.file) {
				continue
			}
			matched = true
			counts[f.file]++
			switch {
			case f.ported && !s.reachable():
				t.Errorf("%s is in %s, a file this port has ported, but the map marks it unreachable "+
					"(%q). A publication that has stopped happening is a regression to fix, not a site "+
					"to reclassify.", s.Citation, f.file, s.Unreachable)
			case !f.ported && s.reachable():
				t.Errorf("%s is in %s, a file this port has no counterpart for, yet the map exercises "+
					"it. Either the surface now exists — in which case devLineFiles says so — or the "+
					"exercise is testing something other than this site.", s.Citation, f.file)
			case !f.ported && (strings.TrimSpace(s.Unreachable) == "" || strings.TrimSpace(s.Milestone) == ""):
				t.Errorf("%s is unreachable and must name both the surface this port lacks and the "+
					"milestone that will add it; without those, \"not yet\" is indistinguishable from "+
					"\"broken\".", s.Citation)
			}
			break
		}
		if !matched {
			t.Errorf("citation %q is in none of the three files the dev line publishes from", s.Citation)
		}
	}

	for _, f := range devLineFiles {
		if counts[f.file] != f.sites {
			t.Errorf("the map holds %d sites from %s, want %d", counts[f.file], f.file, f.sites)
		}
	}
}

// TestPublicationSitesCiteTheDevLine pins the convention, because the whole map
// is worthless if a reader resolves it against the wrong tree: the published
// reference has no publication points at all, so a bare citation here would
// send them to a file that does not contain what it claims.
//
// It also checks the table against itself — every name declared, every pinned
// value under a declared key — so that a typo pins nothing silently.
func TestPublicationSitesCiteTheDevLine(t *testing.T) {
	for _, s := range publicationSites() {
		if !strings.HasPrefix(s.Citation, "node-auth ") {
			t.Errorf("citation %q has no \"node-auth \" prefix. Every publication point is the dev "+
				"line's; at %s nothing in the library publishes, and the only .publish outside the bus "+
				"is AuthTools.track re-emitting a host's own event (auth-tools.ts:231).",
				s.Citation, ReferenceRevision)
		}
		if !IsEventName(s.Event) {
			t.Errorf("site %s raises %q, which is not a declared event name: a typo here would pin "+
				"nothing at all", s.Citation, s.Event)
		}
		declared := make(map[string]bool, len(s.DataKeys))
		for _, k := range s.DataKeys {
			declared[k] = true
		}
		for k := range s.DataValues {
			if !declared[k] {
				t.Errorf("site %s pins a value for data[%q], which is not in its DataKeys",
					s.Citation, k)
			}
		}
	}
}

// TestEveryReachableSitePublishes is the conformance test proper: twenty-three
// of twenty-three, each driven to the point the dev line publishes and each
// checked for the payload the dev line builds there.
func TestEveryReachableSitePublishes(t *testing.T) {
	for _, site := range publicationSites() {
		if !site.reachable() {
			continue
		}
		t.Run(site.Citation, func(t *testing.T) {
			h := newEventHarness(t)
			site.Exercise(t, h)

			ev := h.only(t)
			if ev.Name != site.Event {
				t.Fatalf("raised %q, want %q", ev.Name, site.Event)
			}
			if got, want := dataKeys(ev.Data), sortedCopy(site.DataKeys); !equalKeys(got, want) {
				t.Errorf("data keys = %v, want exactly %v", got, want)
			}
			for k, want := range site.DataValues {
				if got := ev.Data[k]; got != want {
					t.Errorf("data[%q] = %v, want %v", k, got, want)
				}
			}
			if (ev.UserID != "") != site.WantUserID {
				t.Errorf("UserID = %q, want a user id: %v", ev.UserID, site.WantUserID)
			}
			if (ev.SessionID != "") != site.WantSessionID {
				t.Errorf("SessionID = %q, want a session id: %v", ev.SessionID, site.WantSessionID)
			}
			// Exactly one site in the dev line passes a tenant id, and now that
			// it is reachable this is per-site rather than blanket. A site that
			// filled it in anyway would be improving on the source.
			if (ev.TenantID != "") != site.WantTenantID {
				t.Errorf("TenantID = %q, want a tenant id: %v. node-auth admin.router.ts:1002 is the "+
					"only publication point in either tree that passes one.",
					ev.TenantID, site.WantTenantID)
			}
			if ev.Timestamp.IsZero() {
				t.Error("Timestamp is zero: Publish fills it when the publisher leaves it unset")
			}
			// The trap this whole file exists to catch. Publishing through
			// EventBus.Publish rather than PublishContext compiles, passes every
			// assertion above, and silently drops the three fields that join an
			// event to the request that caused it.
			if ev.CorrelationID != harnessCorrelationID || ev.IP != harnessIP || ev.UserAgent != harnessUserAgent {
				t.Errorf("request provenance = {%q, %q, %q}, want {%q, %q, %q}. This site published "+
					"through EventBus.Publish instead of PublishContext, or through a context the "+
					"carrier was never installed on.",
					ev.CorrelationID, ev.IP, ev.UserAgent,
					harnessCorrelationID, harnessIP, harnessUserAgent)
			}
			if site.Assert != nil {
				site.Assert(t, ev)
			}
		})
	}
}

// TestExactlyOneSitePassesATenant keeps WantTenantID from being set by anyone
// who finds it convenient.
//
// It is a fact about the dev line, not a preference: one of the twenty-six
// publication points reads a tenantId, off the body of POST
// <admin>/api/users/:id/roles (node-auth admin.router.ts:1002-1006). Every
// other site leaves the field empty, including the promote pair beside it,
// whose route has no tenant anywhere — not in the pattern, not in the body, not
// in the store call. A second site claiming a tenant is either a dev-line
// change that moves this number, or a payload this port invented.
func TestExactlyOneSitePassesATenant(t *testing.T) {
	var withTenant []string
	for _, s := range publicationSites() {
		if s.WantTenantID {
			withTenant = append(withTenant, s.Citation)
		}
	}
	if len(withTenant) != 1 || withTenant[0] != "node-auth admin.router.ts:1002" {
		t.Errorf("sites passing a tenant id = %v, want exactly [node-auth admin.router.ts:1002]", withTenant)
	}
}

// TestEveryReachableSiteIsSilentWithoutABus runs the same twenty-three
// exercises against a deployment that configured no bus, which is the
// overwhelming majority of them. Nothing may change: not the return values, and
// above all not whether the call succeeds.
func TestEveryReachableSiteIsSilentWithoutABus(t *testing.T) {
	for _, site := range publicationSites() {
		if !site.reachable() {
			continue
		}
		t.Run(site.Citation, func(t *testing.T) {
			h := newEventHarness(t)
			h.detachBus()
			site.Exercise(t, h)
			if got := h.events(); len(got) != 0 {
				t.Fatalf("a service with no bus published %v", eventNamesOf(got))
			}
		})
	}
}

// TestPublishWithoutABusAllocatesNothing pins the shape of Service.publish
// rather than its behaviour, and it is the reason the publication sites pass a
// closure instead of an Event.
//
// Every payload in this package is an Event holding a map literal. Had publish
// taken a value, that map would be built at every site on every request whether
// or not anyone was listening — and nobody is, in most deployments. The builder
// moves the construction behind the nil check, and the closure stays on the
// stack because publish neither stores it nor lets it outlive the call.
//
// That last part is a property of the compiler's escape analysis rather than of
// the source, so it is asserted rather than assumed: an edit that let the
// builder escape would compile, pass every other test here, and quietly put an
// allocation on the hot path of every deployment that subscribes to nothing.
func TestPublishWithoutABusAllocatesNothing(t *testing.T) {
	svc := testService(t)
	if svc.cfg.Events != nil {
		t.Fatal("testService came with a bus; this test needs the unconfigured case")
	}
	ctx := context.Background()

	allocs := testing.AllocsPerRun(100, func() {
		svc.publish(ctx, func() Event {
			return Event{
				Name:   EventUserCreated,
				UserID: "usr_1",
				Data:   map[string]any{"email": "a@example.com", "method": registerMethodDefault},
			}
		})
	})
	if allocs != 0 {
		t.Errorf("publish with no bus allocated %.0f times per call, want 0. "+
			"The builder is escaping — check that Service.publish still only calls it.", allocs)
	}
}

// ── the login-failed gate ────────────────────────────────────────────────────

// The dev line's failed-login publication is its only one inside a catch and
// its only conditional one: `err.statusCode === 401`. Everything about it that
// matters is in what it does *not* publish for, which the site table cannot
// express — the table asserts that an event is raised, and these are the cases
// where none may be.
func TestLoginFailedPublishesOnlyForTheReferences401(t *testing.T) {
	t.Run("a wrong password is the 401 and publishes", func(t *testing.T) {
		h := newEventHarness(t)
		h.register(t, "gate@example.com")
		h.reset()
		if _, _, err := h.svc.Login(h.ctx, LoginInput{
			Email: "gate@example.com", Password: "wrong", TenantID: harnessTenant,
		}); err != ErrInvalidCredentials {
			t.Fatalf("login = %v, want ErrInvalidCredentials", err)
		}
		if ev := h.only(t); ev.Name != EventAuthLoginFailed {
			t.Fatalf("raised %q, want %q", ev.Name, EventAuthLoginFailed)
		}
	})

	t.Run("an unknown address is the same 401 and carries the address as sent", func(t *testing.T) {
		h := newEventHarness(t)
		h.reset()
		if _, _, err := h.svc.Login(h.ctx, LoginInput{
			Email: "  Nobody@Example.COM  ", Password: harnessPassword, TenantID: harnessTenant,
		}); err != ErrInvalidCredentials {
			t.Fatalf("login = %v, want ErrInvalidCredentials", err)
		}
		// The dev line puts req.body.email on the payload untouched (node-auth
		// auth.router.ts:657), so a subscriber sees the submitted value and not
		// the normalised one the lookup used.
		if got := h.only(t).Data["email"]; got != "  Nobody@Example.COM  " {
			t.Errorf("data[\"email\"] = %q, want the address as submitted", got)
		}
	})

	t.Run("an unverified address is a 403 and publishes nothing", func(t *testing.T) {
		// node-auth local.strategy.ts:40 throws EMAIL_NOT_VERIFIED with a 403,
		// and the dev line's catch tests for 401 before it publishes.
		h := newEventHarness(t, func(cfg *Config) { cfg.EmailVerificationMode = EmailVerificationModeStrict })
		h.register(t, "unverified@example.com")
		h.reset()
		if _, _, err := h.svc.Login(h.ctx, LoginInput{
			Email: "unverified@example.com", Password: harnessPassword, TenantID: harnessTenant,
		}); err != ErrEmailNotVerified {
			t.Fatalf("login = %v, want ErrEmailNotVerified", err)
		}
		if got := h.events(); len(got) != 0 {
			t.Fatalf("a 403 refusal published %v; a failed login and an unverified address are "+
				"different events, and only the first is identity.auth.login.failed", eventNamesOf(got))
		}
	})

	t.Run("a broken host hook is a 500 and publishes nothing", func(t *testing.T) {
		// The reference's equivalent reaches handleError as a generic 500. A
		// publication here would report an outage as a wave of credential
		// stuffing.
		boom := fmt.Errorf("the migration service is down")
		h := newEventHarness(t, func(cfg *Config) {
			cfg.PasswordVerifier = func(context.Context, User, string) (bool, bool, error) {
				return false, false, boom
			}
		})
		h.register(t, "hook@example.com")
		h.reset()
		if _, _, err := h.svc.Login(h.ctx, LoginInput{
			Email: "hook@example.com", Password: "wrong", TenantID: harnessTenant,
		}); err == nil {
			t.Fatal("a failing password verifier let the login through")
		}
		if got := h.events(); len(got) != 0 {
			t.Fatalf("a 500 published %v", eventNamesOf(got))
		}
	})
}

// TestLoginChallengeDoesNotPublishALogin guards the one place this port's shape
// could raise an event the dev line does not. Login and LoginWithChallenge are
// two methods here and one route there, so the publication lives in the tail
// they share; a challenge is not a login — no session exists yet — and the dev
// line returns before issueTokens on that branch (node-auth
// auth.router.ts:571-578 precedes :580-581).
func TestLoginChallengeDoesNotPublishALogin(t *testing.T) {
	h := newEventHarness(t)
	user, _ := h.register(t, "challenged@example.com")
	h.enableTOTP(t, user)
	h.reset()

	result, err := h.svc.LoginWithChallenge(h.ctx, LoginInput{
		Email: "challenged@example.com", Password: harnessPassword, TenantID: harnessTenant,
	})
	if err != nil {
		t.Fatalf("login with challenge: %v", err)
	}
	if result.Challenge == nil {
		t.Fatal("a TOTP-enabled account did not get a challenge")
	}
	if got := h.events(); len(got) != 0 {
		t.Fatalf("the challenge branch published %v, want nothing until the second factor lands",
			eventNamesOf(got))
	}
}

// ── names raised by neither tree ─────────────────────────────────────────────

// TestDeclaredButUnraisedNamesStayUnraised is the other half of the port
// discipline. Eleven of the twenty-six declared names are raised by neither
// tree, and this port has the obvious call site for several of them:
// Service.CreateTenant, Service.AddUserToTenant, Service.AssignRole and
// Service.RevokeSessionByID are all sitting there wanting an event.
//
// Adding one is how a port stops being a port. The vocabulary is the
// reference's and the publication points are the dev line's; the intersection
// is not this package's to invent, and a host that wants these can raise them
// on its own bus.
func TestDeclaredButUnraisedNamesStayUnraised(t *testing.T) {
	raised := make(map[string]bool)
	for _, s := range publicationSites() {
		raised[s.Event] = true
	}
	// The fifteen the dev line raises, so that this list and the map cannot
	// drift apart silently.
	if len(raised) != 15 {
		t.Fatalf("the map raises %d distinct names, want the dev line's 15", len(raised))
	}

	wantUnraised := []string{
		EventUserLinked, EventUserUnlinked,
		EventSessionCreated, EventSessionRevoked, EventSessionExpired,
		EventTenantCreated, EventTenantDeleted, EventTenantUserAdded, EventTenantUserRemoved,
		EventPermissionGranted, EventPermissionRevoked,
	}
	if len(wantUnraised)+len(raised) != len(EventNames()) {
		t.Fatalf("%d raised + %d unraised != %d declared names",
			len(raised), len(wantUnraised), len(EventNames()))
	}
	for _, name := range wantUnraised {
		if raised[name] {
			t.Errorf("%s is raised by the map, but neither tree publishes it. If the dev line has "+
				"grown a publication point, the map grows a site with its citation; if this port has "+
				"invented one, it is a fork rather than a port.", name)
		}
	}

	// And the behavioural half: the Service methods that are the obvious sites
	// raise nothing at all.
	h := newEventHarness(t)
	user, _ := h.register(t, "unraised@example.com")
	if err := h.svc.CreateRole(h.ctx, "admin", []string{"users:read"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	h.reset()

	tenant, err := h.svc.CreateTenant(h.ctx, "acme", nil)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := h.svc.AddUserToTenant(h.ctx, user.ID, tenant.ID); err != nil {
		t.Fatalf("add user to tenant: %v", err)
	}
	if err := h.svc.AssignRole(h.ctx, user.ID, "admin", harnessTenant); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if got := h.events(); len(got) != 0 {
		t.Fatalf("the tenant and role methods published %v, want nothing: no site in either tree "+
			"raises identity.tenant.*, and the identity.role.* sites are the admin router's four "+
			"routes rather than these methods — Service.AssignRole is the store call underneath one "+
			"of them, and a host calling it directly is not serving an admin request",
			eventNamesOf(got))
	}
}

// ── harness ──────────────────────────────────────────────────────────────────

const (
	harnessTenant        = "t1"
	harnessPassword      = "a-good-password"
	harnessCorrelationID = "corr-01234567"
	harnessIP            = "203.0.113.7"
	harnessUserAgent     = "conformance/1.0"
	harnessSiteURL       = "https://app.example.com"
)

// eventHarness is a Service with a bus attached and a request context installed,
// recording everything published.
//
// The context is the load-bearing half. It carries an EventContext exactly as
// EventContextMiddleware would, so every assertion about CorrelationID, IP and
// UserAgent is an assertion that the site reached PublishContext — which is the
// one mistake in this PR that no other test would notice.
type eventHarness struct {
	svc   *Service
	users *MemoryUserStore
	bus   *EventBus
	ctx   context.Context

	// detached is the unconfigured deployment. It is a field rather than just a
	// nil on the Service because the OAuth half of the harness builds its own
	// Auth, lazily and after detachBus has been called, and it has to be built
	// without a bus too.
	detached bool

	mu  sync.Mutex
	got []Event

	oauthFixture *oauthEventFixture
	adminFixture *adminEventFixture
}

func newEventHarness(t *testing.T, tweaks ...func(*Config)) *eventHarness {
	t.Helper()
	h := &eventHarness{bus: NewEventBus(), users: NewMemoryUserStore()}

	cfg := h.config(tweaks...)
	svc, err := NewService(cfg, h.users, NewMemorySessionStore(),
		WithRolesPermissionsStore(NewMemoryRolesPermissionsStore()),
		WithTenantStore(NewMemoryTenantStore()))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	h.svc = svc
	h.bus.Subscribe(EventBusWildcard, func(ev Event) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.got = append(h.got, ev)
	})
	h.ctx = ContextWithEventContext(context.Background(), h.eventContext())
	return h
}

func (h *eventHarness) config(tweaks ...func(*Config)) Config {
	cfg := testConfig(testSecret)
	// Lazy, so that Register leaves the address unverified — which is what makes
	// the verify-email site reachable — while login still works, which every
	// login site needs.
	cfg.EmailVerificationMode = EmailVerificationModeLazy
	cfg.Events = h.busOrNil()
	for _, tweak := range tweaks {
		tweak(&cfg)
	}
	return cfg
}

func (h *eventHarness) eventContext() EventContext {
	return EventContext{
		CorrelationID: harnessCorrelationID,
		IP:            harnessIP,
		UserAgent:     harnessUserAgent,
	}
}

func (h *eventHarness) busOrNil() *EventBus {
	if h.detached {
		return nil
	}
	return h.bus
}

// detachBus is the unconfigured deployment: the bus goes away and every
// publication must become a no-op.
func (h *eventHarness) detachBus() {
	h.detached = true
	h.svc.cfg.Events = nil
}

func (h *eventHarness) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.got = nil
}

func (h *eventHarness) events() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Event(nil), h.got...)
}

// only returns the single event the exercise published, and fails when there
// was not exactly one. "Exactly one" is deliberate: it catches a site that
// stopped publishing and a site that started publishing twice, and the second
// is what a shared tail like completeLocalLogin could quietly introduce.
func (h *eventHarness) only(t *testing.T) Event {
	t.Helper()
	got := h.events()
	if len(got) != 1 {
		t.Fatalf("published %d events, want exactly 1: %v", len(got), eventNamesOf(got))
	}
	return got[0]
}

func (h *eventHarness) register(t *testing.T, email string) (User, AuthTokens) {
	t.Helper()
	user, tokens, err := h.svc.Register(h.ctx, RegisterInput{
		Email: email, Password: harnessPassword, TenantID: harnessTenant,
	})
	if err != nil {
		t.Fatalf("register %q: %v", email, err)
	}
	return user, tokens
}

// seedWithPhone writes a user straight to the store, because no route sets a
// phone number and the SMS site needs one.
func (h *eventHarness) seedWithPhone(t *testing.T, email, phone string) User {
	t.Helper()
	now := time.Now()
	user, err := h.users.CreateUser(context.Background(), User{
		ID: "usr_" + email, Email: email, TenantID: harnessTenant, PhoneNumber: phone,
		IsEmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("seed %q: %v", email, err)
	}
	return user
}

func (h *eventHarness) totpSecret(t *testing.T, user User) string {
	t.Helper()
	secret, err := h.svc.SetupTOTP(h.ctx, user.ID, harnessTenant)
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	return secret
}

func (h *eventHarness) totpCode(t *testing.T, secret string) string {
	t.Helper()
	code, ok := generateTOTPCode(secret, time.Now().Unix()/int64(TOTPPeriod/time.Second))
	if !ok {
		t.Fatal("generateTOTPCode failed")
	}
	return code
}

func (h *eventHarness) enableTOTP(t *testing.T, user User) string {
	t.Helper()
	secret := h.totpSecret(t, user)
	if err := h.svc.VerifyTOTPSetup(h.ctx, user.ID, harnessTenant, secret, h.totpCode(t, secret)); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	return secret
}

func (h *eventHarness) magicLinkToken(t *testing.T, email string) string {
	t.Helper()
	token, err := h.svc.SendMagicLink(h.ctx, MagicLinkSendInput{Email: email, TenantID: harnessTenant})
	if err != nil || token == "" {
		t.Fatalf("send magic link = %q, %v", token, err)
	}
	return token
}

// seedUntenanted writes a user straight to the store in the empty tenant,
// because that is the only tenant the admin console addresses: every write on
// that surface passes "" where the reference's call passes no tenant at all.
func (h *eventHarness) seedUntenanted(t *testing.T, id string) User {
	t.Helper()
	now := time.Now()
	user, err := h.users.CreateUser(context.Background(), User{
		ID: id, Email: id + "@example.com", TenantID: "",
		IsEmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("seed %q: %v", id, err)
	}
	return user
}

// ── the admin half of the harness ────────────────────────────────────────────

// The four admin sites publish from HTTP handlers rather than from Service
// methods, so exercising them needs the mounted console and a real request.
//
// That is not ceremony. The whole question U12 left for U18 — "how does event
// context reach admin routes?" — is answered by (*Auth).publishAdminEvent
// reading the request at publish time, because this surface is outside the
// carrier middleware the nineteen auth sites rely on. A service-level exercise
// could not tell that answer from a broken one: it would have to install the
// carrier itself, which is precisely the thing that does not happen here.
//
// It is built here rather than borrowed from adapter/internal/wiretest for the
// reason the OAuth fixture gives: that package is the adapters' shared suite
// and cannot be imported from this one.
type adminEventFixture struct {
	auth    *Auth
	handler http.Handler
	mount   string
}

// admin builds the console lazily and reuses it, so the four sites share one
// mount — and so that detachBus, which runs before any exercise, is already in
// force when the Auth is constructed.
func (h *eventHarness) admin(t *testing.T) *adminEventFixture {
	t.Helper()
	if h.adminFixture != nil {
		return h.adminFixture
	}
	a, err := NewWithConfig(h.config(),
		WithUserStore(h.users),
		WithSessionStore(NewMemorySessionStore()),
		WithRBACProvider(NewMemoryRolesPermissionsStore()),
	)
	if err != nil {
		t.Fatalf("new auth with an admin console: %v", err)
	}
	cfg := DefaultHTTPConfig()
	// AdminOpen so that no credential is needed: this file is about what is
	// published, and who may reach the route is admin.go's suite.
	cfg.Admin = AdminOptions{Enabled: true, AccessPolicy: AdminOpen()}
	f := &adminEventFixture{auth: a, handler: a.AdminHandler(cfg), mount: cfg.AdminPath()}
	h.adminFixture = f
	return f
}

// do issues one admin request and fails unless it succeeded.
//
// The three harness values arrive the way a real caller's would — a
// correlation header, a User-Agent header and a socket address — and not on a
// context this test installed. So the provenance assertion in
// TestEveryReachableSitePublishes is checking the whole path: a site that
// published through EventBus.Publish, or that expected a carrier no adapter
// installs on this surface, fails it on all three fields.
func (f *adminEventFixture) do(t *testing.T, method, route, body string) {
	t.Helper()
	req := httptest.NewRequest(method, f.mount+route, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CorrelationIDHeader, harnessCorrelationID)
	req.Header.Set("User-Agent", harnessUserAgent)
	req.RemoteAddr = harnessIP + ":51413"

	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s = %d, want 200: %s", method, f.mount+route, rec.Code, rec.Body.String())
	}
}

// ── the OAuth half of the harness ────────────────────────────────────────────

// The two OAuth names are the only ones published from Auth rather than from
// Service — Auth.OAuthComplete is this port's handleOAuthLogin plus the three
// callbacks' catch — so exercising them needs the whole wiring and a server to
// answer the token and userinfo calls.
//
// It is built here rather than borrowed from adapter/internal/wiretest, which
// has one already: that package is the adapters' shared conformance suite, it
// cannot be imported from this one, and it is being edited in parallel.
type oauthEventFixture struct {
	auth   *Auth
	server *httptest.Server

	mu      sync.Mutex
	profile map[string]any
}

// oauth builds the OAuth wiring lazily and reuses it, so the three conflict
// sites and the success site share one provider server.
func (h *eventHarness) oauth(t *testing.T) *oauthEventFixture {
	t.Helper()
	if h.oauthFixture != nil {
		return h.oauthFixture
	}
	f := &oauthEventFixture{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/token") {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "provider-access-token"})
			return
		}
		f.mu.Lock()
		profile := f.profile
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(profile)
	}))
	t.Cleanup(f.server.Close)

	// The dev line writes Google, GitHub and the generic provider as three
	// separate callback routes with three copies of the same catch; all three
	// are configured here so each conflict site can be exercised against the
	// provider name its citation carries.
	providers := make([]OAuthProvider, 0, 3)
	for _, name := range []string{"google", "github", "acme"} {
		providers = append(providers, OAuthProvider{
			Name:         name,
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURL:  "https://api.example.com/auth/oauth/" + name + "/callback",
			AuthURL:      "https://provider.example.com/authorize",
			TokenURL:     f.server.URL + "/token",
			UserInfoURL:  f.server.URL + "/userinfo",
			Scopes:       []string{"openid", "email"},
		})
	}
	conflict := DefaultOAuthProvisioning()
	conflict.OnEmailMatch = OAuthEmailMatchConflict

	a, err := NewWithConfig(h.config(),
		WithUserStore(h.users),
		WithSessionStore(NewMemorySessionStore()),
		WithSiteURLs(harnessSiteURL),
		WithOAuth(OAuthWiring{
			Service:        NewOAuthService(providers...),
			LinkedAccounts: NewMemoryLinkedAccounts(),
			PendingLinks:   NewMemoryPendingLinks(),
			AllowedOrigins: []string{harnessSiteURL},
			SiteURL:        harnessSiteURL,
			TenantID:       harnessTenant,
			Provisioning:   &conflict,
		}),
	)
	if err != nil {
		t.Fatalf("new auth with oauth: %v", err)
	}
	f.auth = a
	h.oauthFixture = f
	return f
}

// complete drives one whole callback: begin, to mint the signed state and stash
// its nonce, then complete with the code the provider would have handed back.
func (f *oauthEventFixture) complete(t *testing.T, provider, email string) (OAuthCompleteResult, error) {
	t.Helper()
	providerID := provider + "-account-1"
	f.mu.Lock()
	f.profile = map[string]any{
		// Both keys, because the default profile mapping reads `sub` for Google
		// and the generic provider and `id` for GitHub.
		"sub": providerID, "id": providerID,
		"email": email, "email_verified": true, "name": "OAuth User",
	}
	f.mu.Unlock()

	begun, err := f.auth.OAuthBegin(context.Background(), OAuthBeginInput{
		Provider: provider, Origin: harnessSiteURL,
	})
	if err != nil {
		t.Fatalf("oauth begin: %v", err)
	}
	ctx := ContextWithEventContext(context.Background(), EventContext{
		CorrelationID: harnessCorrelationID,
		IP:            harnessIP,
		UserAgent:     harnessUserAgent,
	})
	return f.auth.OAuthComplete(ctx, OAuthCompleteInput{
		Provider: provider, Code: "provider-code", State: begun.State,
	})
}

// oauthConflict seeds an address under a local account and then presents it
// from the provider, which under OnEmailMatch: conflict is the reference's
// OAUTH_ACCOUNT_CONFLICT.
func (h *eventHarness) oauthConflict(t *testing.T, provider string) {
	t.Helper()
	f := h.oauth(t)
	email := provider + "-held@example.com"
	h.register(t, email)
	h.reset()

	if _, err := f.complete(t, provider, email); err == nil {
		t.Fatal("a held address did not conflict")
	}
}

// ── small helpers ────────────────────────────────────────────────────────────

func dataKeys(data map[string]any) []string {
	if len(data) == 0 {
		return nil
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedCopy(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	out := append([]string(nil), keys...)
	sort.Strings(out)
	return out
}

func equalKeys(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func eventNamesOf(events []Event) []string {
	names := make([]string, 0, len(events))
	for _, ev := range events {
		names = append(names, ev.Name)
	}
	return names
}
