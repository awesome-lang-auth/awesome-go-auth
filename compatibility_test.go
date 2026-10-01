package auth

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// These tests are what stops the deviation register drifting away from what the
// port actually does, and away from what the README tells a reader it does.
//
// The README half used to be a second copy, asserted only by identity: the test
// required every id and citation to appear somewhere in README.md. That caught a
// deletion and nothing else. An entry could be reworded on either side, weakened,
// or reversed outright — the README could assert the exact opposite of the
// register — and the suite stayed green. So the README section is now generated
// from CompatibilityNotes() and compared byte for byte, and the identity-only
// mirror test is gone: it asserted a subset of what the comparison asserts.
//
// What is left is three things, and the prose is deliberately still free within
// them:
//
//   - Identity, exactly. TestCompatibilityNotesRegister compares the whole ID
//     set. Dropping a deviation fails, and so does adding one — an addition has
//     to be a deliberate act, declared here as well as in the register.
//   - Sameness with the README, exactly.
//     TestREADMEIsGeneratedFromCompatibilityNotes re-renders the section and
//     compares it to the committed file, so a Go edit that was not regenerated
//     fails, and a README edit with no Go edit behind it fails.
//   - Substance, by load-bearing token. TestCompatibilityNotesClaims requires a
//     handful of wire facts per entry — the status codes, the header and field
//     names, the numbers, the reference mechanism. Generation alone cannot carry
//     this: someone who weakens an entry *and* regenerates has a green README.
//     These claims are what makes that fail too. They are what the entry means,
//     not how it is phrased, so a rewrite survives while a hollowing-out or a
//     reversal does not.
//   - Form. TestCompatibilityNotesAreWellFormed requires every field populated
//     and every citation shaped like file:line, so an entry cannot be reduced to
//     an unfalsifiable sentence with the evidence removed.

// updateREADME rewrites the generated section of README.md from the register
// instead of asserting against it. This is the regeneration path the section's
// own header comment points at:
//
//	go test -run TestREADMEIsGeneratedFromCompatibilityNotes -update .
var updateREADME = flag.Bool("update", false,
	"rewrite the generated deviations section of README.md from CompatibilityNotes()")

// wantDeviationIDs is the register. Changing this set is the point at which a
// deviation is added or retired, and it must be changed together with
// CompatibilityNotes — after which README.md is regenerated, not edited.
var wantDeviationIDs = []string{
	"admin-console-requires-an-explicit-policy",
	"admin-cookie-secure-flag-is-configured-not-forwarded",
	"admin-credential-listings-are-ordered",
	"admin-guard-accepts-only-typed-session-tokens",
	"admin-listings-are-ordered-by-id",
	"admin-promote-route-comes-from-the-development-line",
	"admin-unauthenticated-get-serves-only-the-login-form",
	"admin-upload-base-url-is-derived-from-the-mount",
	"admin-upload-refusals-answer-the-admin-envelope",
	"admin-user-detail-spans-tenants-only-through-a-lookup-store",
	"advertised-2fa-methods-require-store-support",
	"config-require2fa-is-a-system-policy-term",
	"cookie-max-age-follows-configured-ttl",
	"csrf-cookie-not-reissued-with-tokens",
	"docs-routes-are-opt-in",
	"event-handler-panic-does-not-fail-the-publisher",
	"forgot-password-succeeds-on-delivery-failure",
	"identity-events-are-raised-from-the-development-line",
	"inbound-webhook-script-runs-out-of-process",
	"jwks-cors-wildcard-string-form",
	"jwks-unknown-kid-refetch-is-rate-limited",
	"link-request-exempts-bearer-from-csrf",
	"oauth-provisioning-is-a-policy-not-a-function",
	"one-time-tokens-are-base64url",
	"password-policy-on-reset-and-change",
	"register-issues-a-session",
	"register-route-is-always-mounted",
	"resource-server-gates-all-credential-routes",
	"session-rotated-reports-one-session-id",
	"sse-slow-consumer-is-disconnected",
	"temp-token-is-typed-not-an-access-token",
	"tools-request-bodies-are-typed",
	"tools-router-requires-an-explicit-guard-decision",
	"tools-track-ip-comes-from-the-configured-seam",
	"totp-accepts-one-step-of-skew",
	"totp-issuer-defaults-to-config-issuer",
	"totp-setup-omits-qrcode",
	"ui-config-verify-email-follows-the-effective-mode",
	"ui-ssr-config-json-is-html-escaped",
}

// wantClaims are the facts each entry has to keep stating. They are wire facts
// and named reference mechanisms rather than phrases, so they hold across a
// rewording and fail on a reversal. Each must appear somewhere in the entry.
var wantClaims = map[string][]string{
	"forgot-password-succeeds-on-delivery-failure": {"200", "500", "enumeration"},
	"jwks-cors-wildcard-string-form": {
		"Access-Control-Allow-Origin", "string | string[]", "corsOrigins === '*'",
	},
	"temp-token-is-typed-not-an-access-token": {"access token", "second factor"},
	"link-request-exempts-bearer-from-csrf":   {"Bearer", "CSRF_INVALID", "CORS-safelisted"},
	"password-policy-on-reset-and-change":     {"WEAK_PASSWORD", "400", "minLength: 8"},
	"totp-setup-omits-qrcode":                 {"otpauthUrl", "qrCode"},
	"totp-issuer-defaults-to-config-issuer":   {"otpauthUrl", "awesome-node-auth", "Config.Issuer", "TwoFactorAppName"},
	"totp-accepts-one-step-of-skew":           {"TOTPSkew", "epochTolerance", "totp.strategy.ts"},
	"one-time-tokens-are-base64url":           {"43", "64", "base64url"},
	"oauth-provisioning-is-a-policy-not-a-function": {
		"findOrCreateUser", "403", "OAUTH_EMAIL_NOT_VERIFIED", "OAUTH_EMAIL_DOMAIN_NOT_ALLOWED",
		"OAUTH_USER_NOT_PROVISIONED", "OAUTH_ACCOUNT_CONFLICT", "AutoCreate",
	},
	"advertised-2fa-methods-require-store-support": {"available2faMethods", "501"},
	"config-require2fa-is-a-system-policy-term":    {"Config.Require2FA", "2FA_REQUIRED", "403", "200", "AuthConfig"},
	"resource-server-gates-all-credential-routes": {
		"404", "isResourceServer", "/magic-link/send", "/reset-password", "HTTPConfig.ResourceServer",
		// The kept set is store-dependent. The entry once claimed the opposite,
		// so the correction is pinned rather than left to the prose.
		"user store",
	},
	"jwks-unknown-kid-refetch-is-rate-limited": {
		"MinRefreshInterval", "invalidateCache", "RS256", "401",
	},
	"csrf-cookie-not-reissued-with-tokens": {"Set-Cookie", "setTokenCookies"},
	// Both answers; that the default is the reference's and the session is an
	// opt-in addition (an entry that lost "off by default" would read as a
	// divergence every deployment carries); and — the part that must survive
	// every reword — that the email verification gate wins over the option,
	// which is what nik2208/awesome-go-auth#21 was filed about.
	"register-issues-a-session": {
		"201", "userId", "accessToken", "refreshToken", "Set-Cookie",
		"sendTokens", "POST /login", "off by default",
		"Config.IssueSessionOnRegister", "WithIssueSessionOnRegister(true)", "issueSessionOnRegister",
		"email verification gate wins", "EmailVerificationModeStrict", "EMAIL_NOT_VERIFIED",
		"nik2208/awesome-go-auth#21", "cases_register_test.go",
	},
	// The last four claims are U15's: the entry now covers all three routers,
	// and the one fact a reader must not lose is that the admin console's pair
	// is the only route under <admin>/api/* that AdminGuard.Protect is not
	// spread onto. An entry reduced to "the docs routes are opt-in" would read
	// as a convenience default rather than as a published, unauthenticated
	// description of the admin API.
	"docs-routes-are-opt-in": {
		"HTTPConfig.Docs.Enabled", "OpenAPIInfo.Docs", "NODE_ENV", "404",
		"/openapi.json", "/docs", "swagger-ui-dist@5",
		"AdminOptions.Docs.Enabled", "ToolsOptions.Docs.Enabled",
		"AdminGuard.Protect", "anonymous caller",
	},
	// Which refusals are this port's and which is the reference's, the two
	// numbers, and — the claim that keeps the entry from reading as a hardening
	// — that the reference's own answer is produced by the *host application's*
	// error handler and so cannot be ported at all. The last two pin the bound
	// the reference does not have and the extension list that is unchanged,
	// `svg` included: an entry that quietly dropped svg would be a different
	// product from the reference's console.
	"admin-upload-refusals-answer-the-admin-envelope": {
		"multer", "fileFilter", "fileSize", "next(err)",
		"host application", "400", "413", "500",
		"Only image files are allowed", "No file uploaded",
		"UploadStore", "svg",
	},
	// Both answers, the field that is unchanged beside the one that is not, and
	// the reference mechanism — an option tested for truthiness against its own
	// documented default — so the entry cannot be reduced to "the URL differs".
	"admin-upload-base-url-is-derived-from-the-mount": {
		"AdminOptions.UploadBaseURL", "effectiveUploadBaseUrl", "apiPrefix",
		"@default '/auth'", "/ui/assets/uploads", "url === filename",
		"filename", "UploadFS",
	},
	"cookie-max-age-follows-configured-ttl": {
		"Max-Age=2592000", "Max-Age=604800", "RefreshTokenTTL", "refreshTokenExpiresIn",
	},
	// Both halves of the derivation, so the entry cannot be reduced to "the flag
	// differs" without saying which term this port does not have.
	"ui-config-verify-email-follows-the-effective-mode": {
		"features.verifyEmail", "SendEmailVerification", "EmailVerificationMode",
		"emailVerificationMode !== 'none'", "requireEmailVerification",
	},
	"register-route-is-always-mounted": {
		"features.register", "onRegister", "404", "Service.Register",
	},
	// Both halves of the difference — what the reference does to the request and
	// what this port does to the remaining handlers — plus the mechanism that
	// causes it, because "EventEmitter" is the fact that makes the reference's
	// behaviour checkable rather than asserted. An entry that kept the recover
	// and lost the 500 would read as an implementation note about Go instead of
	// a difference a subscriber can observe.
	"event-handler-panic-does-not-fail-the-publisher": {
		"EventEmitter", "recover", "500", "EventBus.Publish",
		"remaining handlers", "goroutine",
	},
	// Both behaviours, the escape sequence itself, the sink, and — the part a
	// reword must not lose — that the difference is invisible to JSON.parse and
	// that turning the escaping off is what would have taken a deliberate call.
	// An entry keeping only "the bytes differ" reads as an incompatibility to
	// fix rather than a hole deliberately left closed. The last claim keeps the
	// two sinks that are *not* closed on the record, so that the M8 admin panel
	// has to decide about them rather than inherit them.
	"ui-ssr-config-json-is-html-escaped": {
		"window.__AUTH_CONFIG__", "JSON.stringify", `<`, "</script>",
		"JSON.parse", "SetEscapeHTML(false)", "siteName", "customCss", "logoUrl",
	},
	// Both halves of the asymmetry — that this port publishes and that the
	// published reference publishes nothing at all — plus the three things a
	// reader needs in order to check the claim rather than take it: that the
	// publication points come from the development line, the arithmetic of the
	// twenty-six, and that AuthTools.track is a host's own event being re-emitted
	// rather than a publication point. An entry that kept "raises events" and
	// lost "the reference raises none" would read as a port of something,
	// which is exactly what it is not.
	"identity-events-are-raised-from-the-development-line": {
		"PublishContext", "nineteen", "twenty-six", "AuthTools.track",
		"nik2208/node-auth", "DevLineRevision", "Config.Events",
		"nothing in the library publishes at all",
		// M8's four. The entry has to keep naming the admin console as a
		// publisher and the reason its provenance arrives by a different road,
		// or the next reader concludes the console is silent — which it was
		// until U16 and which is the state the wording described for five PRs.
		"identity.role.assigned", "identity.role.revoked",
		"publishAdminEvent", "EventContextMiddleware",
	},
	// The route's existence is the deviation, so the claims are the things that
	// make it checkable against a tree that does not contain it: which tree it
	// does come from, both method values and the answer each gives for the
	// capability it needs, the path quirk a client will trip over, and the
	// limiter slot that arrived with it. An entry reduced to "there is a promote
	// route" would not let a reviewer tell a port from an invention.
	"admin-promote-route-comes-from-the-development-line": {
		"nik2208/node-auth", "fifty", "method", "flag", "role",
		"IUserStore.update is required for method=flag", "RBAC store not configured",
		"identity.role.assigned", "UserAdminFlagStore",
		"AdminOptions.RateLimiter", "HTTPConfig.RateLimiter", "<admin>/login",
		"not under `/api`",
	},
	// The wire fact (one session row per login rather than per refresh), the
	// payload fact (the two ids are equal), the reference mechanism that makes
	// the claim checkable, and — the half most likely to be lost in a reword —
	// that single-use rotation still holds, because an entry reduced to "the
	// session id does not change" reads as a missing security property.
	"session-rotated-reports-one-session-id": {
		"previousSessionId", "sessionId", "issueTokens", "revoke",
		"single-use", "identity.session.rotated",
	},
	// M8's guard. These four are the security entries of the milestone and the
	// claims are chosen so that a reword survives and a hollowing-out does not:
	// each keeps the reference behaviour being declined, the mechanism that
	// causes it, and the way back where there is one.
	//
	// The no-policy entry must keep both the refusal and the one-call escape,
	// because an entry that dropped AdminOpen() would read as a capability this
	// port removed rather than one it made explicit — and it must keep the
	// reason the reference's own warning could not be ported, which is that
	// Config.Logger discards by default.
	"admin-console-requires-an-explicit-policy": {
		"AdminMounted", "Admin.Enabled", "AccessPolicy", "adminSecret",
		"404", "AdminOpen()", "process.stderr", "Config.Logger",
	},
	// Both halves of the branch — which route still reaches a handler and what
	// every other route answers — plus the exploit shape, because an entry that
	// kept only "the marker is narrowed" would not tell a reader what it is
	// narrowed away from.
	"admin-unauthenticated-get-serves-only-the-login-form": {
		"adminNeedsAuth", "401", "text/html", "GET", "login form",
		"/admin/api/users", "__ADMIN_CONFIG__", "Admin.Secret",
	},
	// The accepted set, the refused set, and the reason isRoot is confined —
	// the last is what makes the reference's bootstrap override reproducible at
	// all, so an entry that lost it would read as gratuitous strictness.
	"admin-guard-accepts-only-typed-session-tokens": {
		"typ", "iss", "jwt.verify", "isRoot", "refresh token", "second factor",
		"BuildTokenClaims", "temp-token-is-typed-not-an-access-token",
	},
	// The order itself, the three seams that promise it, the reference's own
	// unordered stores, and the two facts that make the entry more than a
	// preference: that offset paging is meaningless without an order, and that
	// the guard's own access decision reads the first row of one. The last claim
	// pins what is *not* covered, so an entry that quietly widened to the
	// template listings — which match the reference's insertion order — would
	// fail here.
	"admin-listings-are-ordered-by-id": {
		"ID ascending", "AdminUserStore", "SessionLister", "RoleLister",
		"ORDER BY", "listUsers(1, 0)", "first registered user", "offset",
		"AdminPolicyFirstUser", "insertion order",
	},
	// The sibling entry for the two listings the one above left out. The claims
	// pin both orders — they are different, and an entry that collapsed them
	// into one sentence would be describing neither table — the tiebreak that
	// makes the first a total order, the reference mechanism (an optional
	// listAll nothing implements, paged positionally against a best-effort
	// total), and what the missing row costs on these two screens specifically:
	// an entry reduced to "the rows come back in some order" would lose the only
	// reason the fix is worth a register entry.
	"admin-credential-listings-are-ordered": {
		"CreatedAt", "ID ascending", "first-insertion", "APIKeyAdminStore",
		"WebhookAdminStore", "listAll", "IApiKeyStore", "IWebhookStore",
		"offset", "revoke", "admin-listings-are-ordered-by-id",
	},
	// The seam and the fallback beside it, the literal "" the fallback asks for
	// and the 404 it costs, the reference's tenant-less findById, and the reason
	// the empty tenant cannot simply widen — the token's tid — because an entry
	// that lost that last one reads as a missing convenience rather than a
	// refusal to widen the auth path's own read. The ambiguity rule is pinned so
	// the entry cannot be reduced to "it now finds users", and the two writes are
	// pinned so the gap they still have stays on the record.
	"admin-user-detail-spans-tenants-only-through-a-lookup-store": {
		"UserLookupStore", "FindUserByID", "MemoryUserStore", "GetUserByID(id, \"\")",
		"404", "User not found", "findById", "tid", "501", "two tenants",
		"<tenantID>#<id>", "DELETE <admin>/api/users/{id}", "method=flag",
	},
	// M9's guard, and the one entry of this milestone that declines a reference
	// default outright. The claims keep the refusal, the three things a mount
	// needs, the one-call way back, and the two facts that make the refusal an
	// argument rather than a preference: that the reference says nothing at all
	// here where its admin router at least writes to process.stderr, and what
	// an open door actually costs — an outgoing webhook leaving the deployment
	// in its own name, and SMS that is paid for.
	"tools-router-requires-an-explicit-guard-decision": {
		"ToolsMounted", "Tools.Enabled", "Tools.Access", "authMiddleware",
		"404", "ToolsPublic()", "process.stderr", "outgoing webhook", "sms",
	},
	// The header that is read nowhere, the seam that is read instead and its
	// default, the reference's own two halves, and the precedent that decided
	// it. `trust proxy` is what makes the reference's rule undecidable from
	// inside a library rather than merely different, so an entry that lost it
	// would read as this port preferring its own taste.
	"tools-track-ip-comes-from-the-configured-seam": {
		"X-Forwarded-For", "HTTPConfig.ClientIP", "socket peer",
		"req.socket.remoteAddress", "trust proxy", "telemetry store",
		"admin-cookie-secure-flag-is-configured-not-forwarded",
	},
	// Both statuses, both routes, the Go type that forces the question and the
	// TypeScript cast that avoids it, plus the two facts that keep the entry
	// honest: that a bodyless call is still accepted, and that the reference's
	// own refusal for a malformed body is the same 400 from express.json.
	"tools-request-bodies-are-typed": {
		"400", "202", "map[string]any", "Record<string, unknown>",
		"express.json", "<tools>/track", "<tools>/notify",
	},
	// The seam, the thing it replaces, and the three answers that are the whole
	// of its contract. The claims keep: that no JavaScript runs here and what
	// does instead; that the intersection of the two allowlists is resolved in
	// the core; that a missing runner refuses rather than acknowledges, with the
	// status a provider sees; and the split an implementation must not get
	// backwards, between a script that threw and a runner that could not run one.
	"inbound-webhook-script-runs-out-of-process": {
		"InboundScriptRunner", "node:vm", "ScriptRunner",
		"EnabledWebhookActions", "AllowedActions", "400", "onWebhook",
		"no result", "redeliver", "timeout",
	},
	// Both directions of the reference's failure, the seam this port reads
	// instead, and the precedent — ClientIP — that decided it.
	"admin-cookie-secure-flag-is-configured-not-forwarded": {
		"X-Forwarded-Proto", "CookieOptions.Secure", "__Host-", "__Secure-",
		"HTTPConfig.ClientIP", "resolveAdminCookieName", "CookiePrefix",
	},
	// Both policies — the bound here and the unbounded queue there — the Node
	// mechanism that makes the reference's behaviour checkable rather than
	// asserted, the knob, and the two facts a reader needs in order not to
	// misread the entry: that ending the stream is what makes the gap visible
	// (an entry reduced to "slow clients are dropped" reads as a defect), and
	// that neither implementation replays, so a reconnect resumes from now.
	// Without that last claim the entry invites a host to believe the browser's
	// automatic reconnect repairs what the disconnect cost.
	"sse-slow-consumer-is-disconnected": {
		"WithSseSendBuffer", "64", "res.write", "backpressure",
		"EventSource", "Last-Event-ID", "http.ResponseController",
		"EventBus.Publish",
	},
}

// citationPattern is the reference source citation shape: a TypeScript file and
// either a line or a line range.
var citationPattern = regexp.MustCompile(`^[a-z0-9.\-]+\.ts:\d+(-\d+)?$`)

// entryText flattens an entry so a claim can be asserted against the whole of
// it. Which field carries a fact is an editorial matter; that the entry states
// it is not.
func entryText(d Deviation) string {
	parts := []string{d.ID, d.Title, d.Surface, d.Behaviour, d.Reference, d.Why}
	for _, n := range d.Notes {
		parts = append(parts, n.Label, n.Text)
	}
	return strings.Join(parts, "\n")
}

func TestCompatibilityNotesRegister(t *testing.T) {
	notes := CompatibilityNotes()

	got := make(map[string]bool, len(notes.KnownDeviations))
	for _, d := range notes.KnownDeviations {
		if got[d.ID] {
			t.Errorf("deviation %q is listed twice", d.ID)
		}
		got[d.ID] = true
	}

	want := make(map[string]bool, len(wantDeviationIDs))
	for _, id := range wantDeviationIDs {
		want[id] = true
		if !got[id] {
			t.Errorf("deviation %q has dropped out of CompatibilityNotes; "+
				"retiring one means removing it from wantDeviationIDs and regenerating the README too", id)
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("deviation %q is new to CompatibilityNotes; add it to wantDeviationIDs, "+
				"give it an entry in wantClaims and regenerate the README", id)
		}
	}
}

func TestCompatibilityNotesClaims(t *testing.T) {
	for _, d := range CompatibilityNotes().KnownDeviations {
		t.Run(d.ID, func(t *testing.T) {
			claims, ok := wantClaims[d.ID]
			if !ok {
				t.Fatalf("no claims pinned for %q: every deviation needs the facts that make it "+
					"falsifiable, or the entry can be emptied without failing anything", d.ID)
			}
			text := entryText(d)
			for _, claim := range claims {
				if !strings.Contains(text, claim) {
					t.Errorf("entry no longer states %q.\nRewording is fine; dropping the fact is "+
						"the thing this catches. Entry was:\n%s", claim, text)
				}
			}
		})
	}
}

func TestCompatibilityNotesAreWellFormed(t *testing.T) {
	for _, d := range CompatibilityNotes().KnownDeviations {
		t.Run(d.ID, func(t *testing.T) {
			for _, f := range []struct{ name, value string }{
				{"ID", d.ID},
				{"Title", d.Title},
				{"Surface", d.Surface},
				{"Behaviour", d.Behaviour},
				{"Reference", d.Reference},
				{"Why", d.Why},
			} {
				if strings.TrimSpace(f.value) == "" {
					t.Errorf("%s is empty", f.name)
				}
			}
			for i, n := range d.Notes {
				if strings.TrimSpace(n.Label) == "" || strings.TrimSpace(n.Text) == "" {
					t.Errorf("note %d has an empty label or text", i)
				}
			}
			if len(d.Citations) == 0 {
				t.Error("no citation: a claim about the reference that cannot be checked is not a record of one")
			}
			for _, c := range d.Citations {
				if !citationPattern.MatchString(c) {
					t.Errorf("citation %q is not file:line or file:line-line into %s", c, ReferenceRevision)
				}
			}
		})
	}
}

func TestCompatibilityNotesDescribeBothDeliveryModes(t *testing.T) {
	notes := CompatibilityNotes()
	for _, f := range []struct{ name, value, want string }{
		{"ContractTarget", notes.ContractTarget, "awesome-node-auth"},
		{"ReferenceRevision", notes.ReferenceRevision, "cc01e997"},
		{"CookieConventions", notes.CookieConventions, "X-CSRF-Token"},
		{"BearerConventions", notes.BearerConventions, AuthStrategyHeader},
	} {
		if !strings.Contains(f.value, f.want) {
			t.Errorf("%s = %q, which no longer mentions %q", f.name, f.value, f.want)
		}
	}
	if notes.ReferenceRevision != ReferenceRevision {
		t.Errorf("ReferenceRevision = %q, want the package constant %q", notes.ReferenceRevision, ReferenceRevision)
	}
}

// The README is the half of the discipline a human actually reads, and it is
// generated rather than mirrored: this test is the binding. It fails in both
// directions, which is the whole point — the earlier identity-only mirror let a
// README line assert the opposite of the register it claimed to reflect.
func TestREADMEIsGeneratedFromCompatibilityNotes(t *testing.T) {
	const path = "README.md"

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// A checkout with autocrlf on would otherwise fail on every line.
	readme := strings.ReplaceAll(string(raw), "\r\n", "\n")
	want := renderCompatibilityNotes()

	if *updateREADME {
		updated, err := replaceGeneratedSection(readme, want)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("%s regenerated from CompatibilityNotes()", path)
		return
	}

	got, err := generatedSection(readme)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("the deviations section of %s does not match CompatibilityNotes().\n\n"+
			"That section is generated, not hand-maintained. If you changed the register, "+
			"regenerate it;\nif you changed the README, make the change in "+
			"CompatibilityNotes() (compatibility.go) instead and\nthen regenerate:\n\n"+
			"    go test -run TestREADMEIsGeneratedFromCompatibilityNotes -update .\n\n%s",
			path, firstDifference(got, want))
	}
}

// firstDifference reports where the committed section and the freshly rendered
// one part company, because a whole-section dump is unreadable and the first
// differing line is almost always the edit that caused the failure.
func firstDifference(got, want string) string {
	gotLines, wantLines := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
		g, w := "", ""
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if g != w {
			return fmt.Sprintf("first difference at line %d of the section:\n"+
				"  README.md:                %q\n"+
				"  CompatibilityNotes() renders: %q", i+1, g, w)
		}
	}
	return "the sections differ only in trailing content"
}

// A caller that sorts or filters the register must not affect the next caller.
func TestCompatibilityNotesReturnsAFreshValue(t *testing.T) {
	first := CompatibilityNotes()
	if len(first.KnownDeviations) == 0 {
		t.Fatal("no deviations to test against")
	}
	first.KnownDeviations[0].ID = "clobbered"
	first.KnownDeviations = first.KnownDeviations[:0]

	if second := CompatibilityNotes(); len(second.KnownDeviations) == 0 || second.KnownDeviations[0].ID == "clobbered" {
		t.Error("CompatibilityNotes shares state between calls: editing one caller's copy changed the next's")
	}
}
