package auth

// This file is the register of the places this port knowingly does not
// reproduce awesome-node-auth.
//
// The standing rule is the opposite: reproduce the reference including its
// quirks, because the family's shipped clients (ng-awesome-node-auth,
// awesome-node-auth-flutter, the served auth.js) are pinned to it and this
// port's whole value is that they work against it unchanged. Every place the
// rule is set aside is therefore a fact a consumer needs, and until now those
// facts lived only in prose — README sections and CHANGELOG entries — which the
// next person could fold away in good faith with nothing failing.
//
// So this list is the single source of truth. The README's "Deliberate
// deviations from the reference" section is *generated* from it by
// compatibility_markdown.go, and compatibility_test.go regenerates that section
// and compares it byte for byte against the committed README. Editing an entry
// here without regenerating fails; editing the README by hand fails; adding a
// deviation without a README entry is not possible, because the README entry is
// this entry. The register test additionally pins the id set and the wire facts
// each entry has to keep stating, so that an entry cannot be hollowed out even
// by someone who does regenerate.
//
// Because the section is generated, the prose fields below are markdown: the
// backticks and emphasis a reader sees in the README are written here, once.
// They are ordinary sentences otherwise, and a caller that serialises the
// register gets prose it can render or strip as it likes.
//
// What belongs here: a deliberate, client-visible difference in behaviour. What
// does not: a bug (fix it), a feature the port has not reached yet (that is a
// gap, and belongs in an issue), or an internal implementation choice that no
// caller can observe on the wire.

// ReferenceRevision names the revision every Deviation.Citations entry resolves
// against. The citations are file:line, so they mean nothing without it.
const ReferenceRevision = "awesome-node-auth@cc01e997 (npm 1.9.0)"

// DevLineRevision names the second tree this package cites: nik2208/node-auth,
// the private line the published reference is cut from.
//
// Nothing in the deviation register resolves against it. Deviation.Citations is
// ReferenceRevision only, and compatibility_test.go enforces that. This
// constant exists because a few wire facts outside the register do come from
// the dev line, and a reader has to be able to tell which tree a file:line in a
// doc comment means: a citation written as "node-auth auth.router.ts:N" is this
// revision, a bare "auth.router.ts:N" is ReferenceRevision.
//
// One such fact exists today, and it is deliberate rather than accidental: the
// INVALID_INPUT refusal on POST /register (CodeInvalidInput in wire.go,
// ErrInvalidInput in errors.go, the check in Service.Register). The dev line
// mounts that route by default and gives its default handler a presence check
// on the two fields; the published reference mounts /register only when the
// host supplies options.onRegister (auth.router.ts:713), has no default handler
// at all, and therefore has no message and no code of its own there. Copying
// the dev line's answer is a bet that the published tree will grow the same
// one. When the dev line ships, ReferenceRevision moves forward and those
// citations fold back into it.
const DevLineRevision = "nik2208/node-auth@e8af923 (unreleased, package.json 1.9.0)"

// Deviation is one place this port deliberately answers differently from the
// reference.
//
// The two behaviours are recorded separately, and the reference's carries a
// citation, so that a reader can check the claim rather than take it — and so
// that a maintainer who changes one of them has to come here and say so.
type Deviation struct {
	// ID is the stable handle for this deviation. It never changes once
	// published: the README keys its mirror on it and the tests pin the set, so
	// renaming one is a deliberate, visible act rather than a silent edit.
	ID string `json:"id"`
	// Title is the one-line heading a human reads first. It becomes the README
	// section heading for this entry.
	Title string `json:"title"`
	// Surface is the route or API surface affected, written as it is mounted —
	// paths are relative to the configured prefix, spelled <prefix> here.
	Surface string `json:"surface"`
	// Behaviour is what this port does.
	Behaviour string `json:"behaviour"`
	// Reference is what awesome-node-auth does instead.
	Reference string `json:"reference"`
	// Citations locate Reference in the reference source, as file:line or
	// file:line-line, resolved against ReferenceRevision.
	Citations []string `json:"citations"`
	// Why is the reason the standing rule was set aside. An entry without one is
	// not a decision, it is a bug that has not been recognised yet.
	Why string `json:"why"`
	// Notes carries any further labelled paragraphs this entry needs beyond the
	// four above — how to observe the difference, what a host can do about it.
	// Most entries need none.
	Notes []DeviationNote `json:"notes,omitempty"`
}

// DeviationNote is one extra labelled paragraph on a Deviation.
type DeviationNote struct {
	Label string `json:"label"`
	Text  string `json:"text"`
}

// APICompatibilityNotes is the contract this port targets, plus every known
// deviation from it.
type APICompatibilityNotes struct {
	// ContractTarget names the clients the wire shape is pinned to.
	ContractTarget string `json:"contractTarget"`
	// ReferenceRevision is ReferenceRevision, carried in the value so a caller
	// that serialises these notes ships the revision its citations need.
	ReferenceRevision string `json:"referenceRevision"`
	// CookieConventions and BearerConventions summarise the two delivery modes.
	CookieConventions string `json:"cookieConventions"`
	BearerConventions string `json:"bearerConventions"`
	// KnownDeviations is the register, in no significant order.
	KnownDeviations []Deviation `json:"knownDeviations"`
}

// CompatibilityNotes returns the wire contract this port targets and the known
// deviations from it.
//
// The result is freshly built on every call and shares nothing with the
// package, so a caller may sort, filter or edit it without affecting anyone
// else's view.
func CompatibilityNotes() APICompatibilityNotes {
	return APICompatibilityNotes{
		ContractTarget: "awesome-node-auth, as consumed by ng-awesome-node-auth, " +
			"awesome-node-auth-flutter and the served auth.js",
		ReferenceRevision: ReferenceRevision,
		CookieConventions: "Cookie mode is the default: login, register and refresh answer " +
			`{"success": true} and set accessToken, refreshToken and csrf-token, each ` +
			"resolved __Host- / __Secure- / bare from the cookie policy and read back in " +
			"that order. CSRF is double-submit on X-CSRF-Token, enforced for " +
			"cookie-authenticated unsafe methods only.",
		BearerConventions: "X-Auth-Strategy: bearer (exact, case-sensitive) switches to " +
			"top-level accessToken/refreshToken in the body and sets no cookies at all. " +
			"Protected routes then read Authorization: Bearer <accessToken> and are exempt " +
			"from CSRF.",
		KnownDeviations: []Deviation{
			{
				ID:      "forgot-password-succeeds-on-delivery-failure",
				Title:   "`forgot-password`: unconditional 200 on delivery failure",
				Surface: "`POST <prefix>/forgot-password`",
				Behaviour: `Always ` + "`200 {\"success\": true}`" + ` — when the mail was sent, when the ` +
					"configured sender returns an error, and when no sender is configured at " +
					"all. The reset token stays stored in every case. A *store* failure still " +
					"answers `500`, which is the reference's behaviour and is kept.",
				Reference: "The send sits inside the route's `try`, so a throwing mailer reaches " +
					"`handleError` and answers `500`.",
				Citations: []string{"auth.router.ts:787-798"},
				Why: "That `500` fires only for an address that **exists**, so a broken mail " +
					"gateway turns the one route whose purpose is to reveal nothing about who is " +
					"registered into an account-enumeration oracle. The contract records the " +
					"status as `[UNTESTED]`, and no client can depend on one that appears only " +
					"when the operator's mailer is down.",
				Notes: []DeviationNote{{
					Label: "Observing the failure",
					Text: "Only the HTTP surface swallows it. `Auth.ForgotPassword` absorbs " +
						"`ErrDeliveryFailed` (and nothing else) and logs `auth: password reset " +
						"delivery failed; the route still answered success: …`, without naming the " +
						"address. `Service.ForgotPassword` still returns the error, so a direct " +
						"library caller learns about it.",
				}},
			},
			{
				ID:      "temp-token-is-typed-not-an-access-token",
				Title:   "The 2FA step-up token is typed, not an access token",
				Surface: "`POST <prefix>/login` (the `tempToken` in a 2FA challenge) and the step-up routes that accept it",
				Behaviour: "The step-up token carries its own type. It is accepted by the " +
					"second-factor routes and by nothing else, and an ordinary access token is " +
					"not accepted in its place.",
				Reference: "Mints the `tempToken` as an ordinary 5-minute access token with no " +
					"claim distinguishing it, so it authenticates any protected route for five " +
					"minutes before the second factor has been presented, and a full access " +
					"token also passes as a `tempToken`.",
				Citations: []string{"auth.router.ts:572-575", "token.service.ts:20-24"},
				Why: "Reproducing it would mean shipping a five-minute bypass of the second " +
					"factor the challenge exists to demand. The type claim is not on the wire — " +
					"the token is opaque to every client — and the reference's own sharing is " +
					"`[UNTESTED]` there, so no shipped client depends on it. The cost is that the " +
					"`tempToken` in a `2FA_SETUP_REQUIRED` answer cannot reach the enrolment " +
					"routes, which sit behind the access-token gate.",
			},
			{
				ID:      "refresh-secret-falls-back-to-secret",
				Title:   "The refresh-token secret is optional and may equal the access-token secret",
				Surface: "`auth.Config.RefreshSecret` / `auth.WithRefreshSecret`, and every refresh token `POST <prefix>/login`, `POST <prefix>/register` and `POST <prefix>/refresh` mint",
				Behaviour: "Signs and verifies refresh tokens with `Config.RefreshSecret` when it is " +
					"set, and with `Config.Secret` — the access-token secret — when it is empty, " +
					"which is the default. Construction succeeds whether the two are different, " +
					"equal, or the refresh one is unset, with or without a session store. When " +
					"they coincide the refresh token is still refused as an access credential, by " +
					"its `typ` claim.",
				Reference: "`refreshTokenSecret` is a required member of `AuthConfig`, separate " +
					"from `accessTokenSecret`, and signs and verifies every refresh token. Since " +
					"1.10.3 the router also refuses to be constructed when " +
					"`refreshTokenSecret === accessTokenSecret` and a session store is configured, " +
					"throwing `refreshTokenSecret must differ from accessTokenSecret when a " +
					"sessionStore is configured` (auth.router.ts:843-844 at 1.10.8).",
				Citations: []string{"auth-config.model.ts:147-148", "token.service.ts:25-29", "token.service.ts:154"},
				Why: "Until `RefreshSecret` existed this port signed both tokens with `Config.Secret`, " +
					"so every deployment running it today has the two secrets equal and a session " +
					"store configured. The reference's refusal would stop every one of them from " +
					"starting on an upgrade within `0.x`. The fallback keeps them running unchanged, " +
					"while a deployment that sets `RefreshSecret` gets the reference's separation " +
					"of the two trust domains. The refusal is planned for v1.0.0, where a breaking " +
					"change of configuration belongs.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Set `WithRefreshSecret` to a value different from `WithSecret`'s. " +
						"Doing so on a running deployment invalidates every refresh token " +
						"outstanding at that moment, so every session signs in again once.",
				}},
			},
			{
				ID:    "idp-mode-adds-an-oauth-authorization-server",
				Title: "IdP mode also serves an OAuth 2.0 / OIDC authorization server",
				Surface: "`GET <prefix>/.well-known/openid-configuration`, `<prefix>/authorize`, " +
					"`POST <prefix>/token` and `GET <prefix>/userinfo`, mounted by `auth.WithIDP`",
				Behaviour: "Beside the JWKS route, an `Auth` built `WithIDP` serves the four OIDC " +
					"endpoints of the authorization-code flow. `authorize` accepts PKCE as `S256` only " +
					"and refuses `plain` with the RFC 6749 §4.1.2.1 `invalid_request` redirect. `token` " +
					"authenticates the client by `client_secret_basic` or `client_secret_post` — never " +
					"both — verifies the `code_verifier` of a code issued with a challenge, and " +
					"implements two grants: `authorization_code`, which returns the HS256 session access " +
					"token and an RS256 `id_token`, plus a `refresh_token` only when the code was granted " +
					"`offline_access`; and `refresh_token`, which rotates that opaque token on every use " +
					"and revokes its whole family when a used one comes back, when another client " +
					"presents it, or when its session has ended. Every `token` refusal is the RFC 6749 " +
					"§5.2 JSON body (`invalid_request`, `invalid_client`, `invalid_grant`, " +
					"`invalid_scope`, `unsupported_grant_type`) with `Cache-Control: no-store`; " +
					"`authorize` and `userinfo` refuse in plain text.",
				Reference: "Its IdP mode signs RS256 token pairs (`generateIdProviderTokenPair`) and serves " +
					"the JWKS document, and nothing more: there is no discovery document, no " +
					"`/authorize`, no `/token` and no `/userinfo`, so no PKCE, no client authentication " +
					"and no refresh grant to compare against. The same holds at 1.10.8 " +
					"(auth.router.ts:927-957 there).",
				Citations: []string{"auth.router.ts:473-503", "token.service.ts:40-44"},
				Why: "The port has carried these four endpoints since its first IdP release, and a " +
					"relying party that finds an authorization server has to be able to rely on it: a " +
					"PKCE challenge that was recorded and never checked protected nothing, and a " +
					"client library speaking plain OAuth expects Basic authentication, the §5.2 error " +
					"body and a refresh grant. None of it reaches a family client, which never calls " +
					"these routes, and none of it changes the reference's own IdP surface, the JWKS " +
					"route, which this port reproduces separately. Every rule is the specification's " +
					"(RFC 6749, RFC 7636, OIDC Core §11 and §12.2, RFC 9700 §4.14.2), because there is " +
					"no reference behaviour to follow.",
				Notes: []DeviationNote{{
					Label: "What is still open",
					Text: "Which token pair `token` returns — the HS256 session pair it returns today or " +
						"the RS256 pair `IssueIdPTokenPair` mints — is decision D-15 of the upstream plan " +
						"and is not settled by this entry.",
				}},
			},
			{
				ID:      "link-request-exempts-bearer-from-csrf",
				Title:   "`link-request` exempts a bearer credential from CSRF",
				Surface: "`POST <prefix>/link-request`",
				Behaviour: "A request carrying a real `Authorization: Bearer` credential is exempt " +
					"from the double-submit check, as it is on every other route. Without one " +
					"the check is enforced whether or not the request is cookie-authenticated.",
				Reference: "Gates its hand-written double-submit check on `config.csrf.enabled` " +
					"alone, with no `usingBearer` term — unlike its own auth middleware " +
					"(`auth.middleware.ts:35`) — so it answers `403 CSRF_INVALID` to a " +
					"bearer-authenticated caller that carries no cookie pair.",
				Citations: []string{"auth.router.ts:1489-1495"},
				Why: "`Authorization` is not CORS-safelisted, so no cross-site page can set it and " +
					"the exemption costs no CSRF protection: every request it admits is one an " +
					"attacker could not have forged. The family contract records the reference's " +
					"behaviour as a MISMATCH that breaks native bearer clients with no cookie " +
					"jar, and marks it `[UNTESTED]`. A client that sends the pair is accepted by " +
					"both.",
			},
			{
				ID:      "password-policy-on-reset-and-change",
				Title:   "A password policy on `reset-password` and `change-password`",
				Surface: "`POST <prefix>/reset-password` and `POST <prefix>/change-password`",
				Behaviour: "Rejects a new password shorter than `Config.MinPasswordLen` with " +
					"`400 {\"error\": \"Password is too weak\", \"code\": \"WEAK_PASSWORD\"}`, checked " +
					"before the current-password comparison on `/change-password`.",
				Reference: "Applies no strength check on either route — the password goes " +
					"straight to `passwordService.hash`. Its own OpenAPI document declares " +
					"`minLength: 8` on both bodies and nothing enforces it.",
				Citations: []string{"auth.router.ts:801-825", "auth.router.ts:904-932"},
				Why: "The reference will hash and store a two-character password on a route " +
					"reached with a mailed token, which silently undoes whatever policy the host " +
					"applied at registration. `WEAK_PASSWORD` has no reference counterpart, so a " +
					"client that does not know the code still sees a `400` it must show the user " +
					"either way. The check order differs too: the reference would report a wrong " +
					"current password first.",
			},
			{
				ID:        "totp-setup-omits-qrcode",
				Title:     "`2fa/setup` omits the QR code",
				Surface:   "`POST <prefix>/2fa/setup`",
				Behaviour: "Answers `{\"secret\", \"otpauthUrl\"}` and nothing else.",
				Reference: "Also returns `qrCode`, the same provisioning URI rendered as a PNG " +
					"data URL.",
				Citations: []string{"auth.router.ts:832-835"},
				Why: "The root package is stdlib plus `golang.org/x/crypto` and a QR encoder is " +
					"neither. A client renders `otpauthUrl` itself, which is what the Rust port of " +
					"this family does too. A client that displays the reference's PNG directly " +
					"has to encode the URI instead.",
			},
			{
				ID:      "totp-issuer-defaults-to-config-issuer",
				Title:   "The default TOTP issuer is `Config.Issuer`, not `awesome-node-auth`",
				Surface: "`POST <prefix>/2fa/setup`, the issuer in `otpauthUrl`",
				Behaviour: "Labels the provisioning URI with `Config.TwoFactorAppName` when it is " +
					"set and with `Config.Issuer` when it is not — `awesome-go-auth` on " +
					"`DefaultConfig` — as both the label prefix and the `issuer` parameter, in " +
					"otplib's `issuer:account` form.",
				Reference: "Labels it with `config.twoFactor.appName` and falls back to the " +
					"literal `'awesome-node-auth'` — its own package name — when no app name is " +
					"configured.",
				Citations: []string{"auth.router.ts:830", "totp.strategy.ts:11-17"},
				Why: "The reference's fallback names the library, not the deployment, which is " +
					"the wrong thing to show a user who opens their authenticator app. This port " +
					"has carried `Config.Issuer` there since the route existed, so enrolments " +
					"made before `TwoFactorAppName` was added sit under that name in users' apps, " +
					"and switching the default now would file every new enrolment under a " +
					"different name from the old ones on the same deployment. The difference is " +
					"visible only on a deployment that sets neither field: one that sets " +
					"`TwoFactorAppName` — the reference's `appName` — gets exactly the " +
					"reference's label.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "`WithTwoFactorAppName(\"awesome-node-auth\")`. Any name given is carried " +
						"verbatim; only the fallback differs.",
				}},
			},
			{
				ID:      "totp-accepts-one-step-of-skew",
				Title:   "TOTP codes from the adjacent 30-second steps are accepted",
				Surface: "`POST <prefix>/2fa/verify-setup` and `POST <prefix>/2fa/verify`, the two routes that check a TOTP code (`/2fa/disable` takes none, in either implementation)",
				Behaviour: "Accepts a code from the previous or the next 30-second step as well as " +
					"the current one: `validateTOTPCode` tries `TOTPSkew = 1` step either side " +
					"of now (`totp.go`), so three codes are valid at any instant and each code " +
					"is accepted over a 90-second window — its own step and the 30 seconds " +
					"before and after it — where the reference's window is 30.",
				Reference: "Accepts the current step only. `TotpStrategy.verify` in " +
					"`totp.strategy.ts` calls `totp.verify(token, { secret })` and sets no other " +
					"option, and otplib's `verify` — `@otplib/totp` 13.4.0, the version the " +
					"reference's package-lock.json pins for `otplib ^13.3.0` (13.4.1 today, same " +
					"default) — defaults its window to zero seconds either " +
					"side of now: `epochTolerance:f=0` in the `verify` method of " +
					"`@otplib/totp`'s `dist/index.js`, documented in its " +
					"types as `default: 0 = current period only`. A code is refused from the " +
					"first second of the step after its own.",
				Citations: []string{"totp.strategy.ts:22-25", "auth.router.ts:846", "auth.router.ts:868"},
				Why: "An authenticator runs on the phone's clock, and a user reads a code some " +
					"seconds before the server sees it, so with no tolerance a code read in the " +
					"last seconds of a step — or on a phone a few seconds adrift — is refused " +
					"and the user has to try again, at every step boundary. RFC 6238 §5.2 " +
					"recommends allowing one step for exactly that delay, and one step is the " +
					"tolerance mainstream verifiers ship with. The cost is that three of the " +
					"million possible codes are valid at any instant instead of one.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Not possible: `TOTPSkew` is a constant, not a knob, and no knob is " +
						"planned. A deployment gets the one-step window whether or not it wants it.",
				}},
			},
			{
				ID:        "one-time-tokens-are-base64url",
				Title:     "One-time tokens are base64url, not hex",
				Surface:   "The reset-password, email-verification and email-change tokens carried in mailed links",
				Behaviour: "Renders 32 random bytes as 43 base64url characters.",
				Reference: "Renders the same 32 random bytes as 64 hexadecimal characters.",
				Citations: []string{"token.service.ts:270-272"},
				Why: "`randomToken` is shared with the API-key and IdP code paths, which have no " +
					"reason to be hex. Both forms are URL-safe and opaque, and no shipped client " +
					"parses or measures a token — but a host that pinned a column width or a " +
					"validation regex to 64 hex characters has to widen it.",
			},
			{
				ID:      "advertised-2fa-methods-require-store-support",
				Title:   "An advertised 2FA method must be one the store supports",
				Surface: "`POST <prefix>/login`, the `available2faMethods` list in a 2FA challenge",
				Behaviour: "Advertises a second factor only when the configured user store " +
					"implements the capability that factor needs, as well as the configuration " +
					"and user state the reference checks.",
				Reference: "Checks configuration and user state alone, so it can advertise a " +
					"method whose route then answers `501` because the store does not implement it.",
				Citations: []string{"auth.router.ts:557-559"},
				Why: "A client picks its next request from this list, so advertising a factor " +
					"that cannot complete strands the login with no way forward. The extra term " +
					"can only ever remove an option that would have failed; a deployment whose " +
					"store implements the capability sees the reference's list.",
			},
			{
				ID:      "config-require2fa-is-a-system-policy-term",
				Title:   "`Config.Require2FA` is a deployment-level 2FA policy the reference has no equivalent of",
				Surface: "`POST <prefix>/2fa/disable` and `POST <prefix>/login`",
				Behaviour: "`Config.Require2FA` is a third term in two decisions the reference " +
					"makes with two. On `/2fa/disable` it is ORed with the stored `require2FA` " +
					"into the system-policy refusal, so a deployment that sets it and configures " +
					"no settings store at all answers " +
					"`403 {\"error\":\"Cannot disable 2FA: required by system policy\",\"code\":\"2FA_REQUIRED\"}` " +
					"where the reference answers `200 {\"success\":true}` and turns the factor " +
					"off. At login it is ORed into the challenge term, so a user with no enrolled " +
					"TOTP and no per-user flag is challenged where the reference logs them " +
					"straight in.",
				Reference: "Has no config-level `require2FA`: the name exists only on the settings " +
					"store and on the user record, never on `AuthConfig`. `/2fa/disable` refuses " +
					"on the per-user flag and on the stored setting and on nothing else, and " +
					"login challenges on an enrolled TOTP or the per-user flag alone",
				Citations: []string{
					"auth.router.ts:880-902", "auth.router.ts:552",
					"settings-store.interface.ts:64", "user.model.ts:39",
				},
				Why: "A deployment-wide switch is what an embedder without the admin router has " +
					"instead of the Control panel: the reference reaches the same policy by " +
					"writing `require2FA: true` through a settings store, which requires running " +
					"a store and an admin surface to write it. The term is additive and " +
					"inert by default — `Config.Require2FA` is `false` unless a deployment sets " +
					"it, and a deployment that leaves it alone gets the reference's answers on " +
					"both routes, including with a settings store attached. Both wire shapes are " +
					"the reference's own: the `403` body is the one it sends for the stored " +
					"setting, and the challenge is the one it sends for the per-user flag, so a " +
					"client meets nothing it has no branch for.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Leave `Config.Require2FA` unset (the default) and express the policy " +
						"through a `SettingsStore` holding `require2FA: true`, which is the " +
						"reference's own term and produces the same `/2fa/disable` refusal with no " +
						"login-side difference.",
				}},
			},
			{
				ID:      "csrf-cookie-not-reissued-with-tokens",
				Title:   "The CSRF cookie is not reissued alongside tokens",
				Surface: "`Set-Cookie` on every route that issues tokens, including `POST <prefix>/login` and `POST <prefix>/refresh`",
				Behaviour: "The CSRF cookie is written by the router-level auto-init only, when " +
					"the request carries no readable one. Issuing tokens does not reissue it, so " +
					"one response never carries two `Set-Cookie` headers for that name.",
				Reference: "`setTokenCookies` sets a fresh `csrf-token` cookie on every cookie-mode " +
					"issuance — it is reached from `sendTokens` (`auth.router.ts:403`) and from the " +
					"OAuth redirect path — in addition to the router-level auto-init, so a first " +
					"login emits two `Set-Cookie` headers for the same name with different values " +
					"in one response.",
				Citations: []string{"token.service.ts:204-209", "auth.router.ts:529-538"},
				Why: "Which of two same-name `Set-Cookie` headers survives is left to the cookie " +
					"jar, so the reference's pair makes the token a client will send back " +
					"ambiguous on exactly the response that establishes it. Emitting one keeps " +
					"the double-submit pair consistent. The cookie stays JS-readable and valid " +
					"either way, so a client that reads it per request — as all three family " +
					"clients do — cannot tell the difference.",
			},
			{
				ID:      "oauth-provisioning-is-a-policy-not-a-function",
				Title:   "OAuth provisioning is a configured policy, with three refusals the reference has no counterpart for",
				Surface: "`GET <prefix>/oauth/{provider}/callback`",
				Behaviour: "Resolves the callback under `OAuthWiring.Provisioning` " +
					"(`OAuthProvisioning{AutoCreate, AllowedEmailDomains, RequireVerifiedEmail, " +
					"OnEmailMatch, FieldMap}`). Three of its outcomes are refusals with no reference " +
					"counterpart, all `403` JSON on the callback: `OAUTH_EMAIL_NOT_VERIFIED` when " +
					"`RequireVerifiedEmail` is set and the provider asserted nothing, " +
					"`OAUTH_EMAIL_DOMAIN_NOT_ALLOWED` when the address is outside " +
					"`AllowedEmailDomains`, and `OAUTH_USER_NOT_PROVISIONED` when the identity is " +
					"unknown and `AutoCreate` is false, or when the address belongs to an account and " +
					"`OnEmailMatch` is `reject`. The fourth, `OnEmailMatch: \"conflict\"`, is the " +
					"reference's own `OAUTH_ACCOUNT_CONFLICT`: the stash and the 302 to " +
					"`/account-conflict`, sent exactly as the reference sends them. An account the " +
					"callback creates records the provider as `loginProvider`, takes " +
					"`isEmailVerified` from the provider's claim — true when the provider said " +
					"nothing, which is the common case — and fills further columns from `FieldMap`.",
				Reference: "Has no provisioning at all: `findOrCreateUser(profile, state)` is an " +
					"abstract method the integrator implements, and the library knows only two " +
					"outcomes from it — a user, which becomes a session, or an `AuthError` coded " +
					"`OAUTH_ACCOUNT_CONFLICT`, which becomes the stash and the redirect. Anything " +
					"else that function throws reaches `handleError`, which answers `500` unless it " +
					"is an `AuthError` carrying its own status.",
				Citations: []string{
					"generic-oauth.strategy.ts:169-172", "google.strategy.ts:67",
					"github.strategy.ts:78", "auth.router.ts:1346-1355",
				},
				Why: "This port's consumer configures the library from a file; it cannot subclass a " +
					"strategy, so a policy expressed as configuration is the only form the " +
					"reference's function can take here. The refusals are what that policy needs to " +
					"say and the reference never had to: its integrator would have thrown whatever " +
					"they liked. Defaults reproduce what this port did before the policy existed — " +
					"`AutoCreate` true, `OnEmailMatch` `link`, no domain list, no verification " +
					"demand — so a deployment that configures nothing cannot see any of the three " +
					"codes. `OnEmailMatch` exists because linking by address across providers is the " +
					"account-takeover shape the reference's own store interface warns about " +
					"(`findByProviderAccount`, `user-store.interface.ts:105-119`), and the port's " +
					"default is the unsafe one only because changing it silently would lock accounts " +
					"out of deployments that rely on it.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Leave `OAuthWiring.Provisioning` nil. The callback then behaves as it " +
						"always has, no refusal is reachable, and the only policy-driven answer that " +
						"can appear is the reference's own account conflict — which needs " +
						"`OnEmailMatch: \"conflict\"` and so cannot appear either.",
				}},
			},
			{
				ID:      "cookie-max-age-follows-configured-ttl",
				Title:   "Cookie `Max-Age` follows the configured TTL, not a hardcoded 7 days",
				Surface: "`Set-Cookie` on every cookie-mode route that issues tokens, including `POST <prefix>/login`, `POST <prefix>/register` and `POST <prefix>/refresh`",
				Behaviour: "Derives each token cookie's `Max-Age` from the lifetime of the token it " +
					"carries — the access cookie from `Config.AccessTokenTTL`, the refresh cookie " +
					"from `Config.RefreshTokenTTL` — unless the deployment sets " +
					"`CookieOptions.AccessTokenMaxAge` or `RefreshTokenMaxAge` explicitly. On " +
					"`DefaultConfig` that is `Max-Age=900` on the access cookie and " +
					"`Max-Age=2592000` (30 days) on the refresh cookie.",
				Reference: "Hardcodes both lifetimes in `setTokenCookies`, ignoring configuration: " +
					"`maxAge: 15 * 60 * 1000` on the access cookie and " +
					"`maxAge: 7 * 24 * 60 * 60 * 1000` on the refresh cookie, so it always emits " +
					"`Max-Age=604800` there whatever `refreshTokenExpiresIn` says.",
				Citations: []string{"token.service.ts:28", "token.service.ts:195", "token.service.ts:199-202"},
				Why: "Deriving the cookie lifetime from the configured TTL is the point: a cookie " +
					"must not outlive, or expire before, the token it carries. The reference's " +
					"hardcoded value silently contradicts its own `refreshTokenExpiresIn` — that " +
					"option signs the refresh token (defaulting to `7d`), so raising it to 30 days " +
					"leaves the token valid for 30 days while the browser drops the cookie " +
					"carrying it after 7, ending the session early with a credential nobody can " +
					"present. The divergence is a header value, not a validity change: each port " +
					"honours its own tokens' server-side expiry either way. The access cookie " +
					"matches the reference on `DefaultConfig` (both 15 minutes, `Max-Age=900`) and " +
					"diverges on any custom `AccessTokenTTL`; the refresh cookie diverges at the " +
					"default too, because `Config.RefreshTokenTTL` is 30 days here where the " +
					"reference's refresh token defaults to `7d`.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "A host that needs the reference's literal headers sets " +
						"`CookieOptions.RefreshTokenMaxAge` to 7 days (and `AccessTokenMaxAge` to 15 " +
						"minutes); an explicit value is never overwritten by the derivation.",
				}},
			},
			{
				ID:      "jwks-cors-wildcard-string-form",
				Title:   "The JWKS CORS wildcard is the one-element `[]string{\"*\"}`, not an entry",
				Surface: "`GET <prefix>/.well-known/jwks.json`",
				Behaviour: "A `JWKSCORSOrigins` of exactly `[]string{\"*\"}` answers " +
					"`Access-Control-Allow-Origin: *` to every request, the same as leaving the " +
					"field nil. Every other slice is an allowlist: a listed `Origin` is echoed " +
					"back, an unlisted one gets no `Access-Control-Allow-Origin` header at all, " +
					"and an entry `*` inside a longer slice is an ordinary entry that matches " +
					"only an `Origin` header of literally `*`.",
				Reference: "`jwksCorsOrigins` is typed `string | string[]` and the wildcard test is " +
					"`corsOrigins === '*'` against the whole value, so only the *string* is the " +
					"wildcard. Every array is an allowlist, including `['*']`, whose one entry " +
					"matches only the `Origin` header `*` — one no browser sends — so that value " +
					"disables the header rather than opening the route.",
				Citations: []string{"auth.router.ts:492-500", "auth-config.model.ts:102"},
				Why: "Go has no `string | string[]`, and `[]string` is the shape every other list " +
					"in this package has, so one of the two readings of `{\"*\"}` had to win. The " +
					"reference's own documented default for the field is the wildcard " +
					"(`@default '*'`), so the slice that spells it is read as the string form " +
					"rather than as an allowlist that can never match — the reading a host " +
					"writing `{\"*\"}` plainly intends. The difference is confined to that single " +
					"value: nil, the empty slice and every other allowlist behave exactly as the " +
					"reference does.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "A deployment that means the reference's `['*']` — an allowlist no " +
						"browser `Origin` can match — writes the empty slice `[]string{}` here, " +
						"which sends the header to nobody. Note also that neither implementation " +
						"sends `Vary: Origin` while both send `Cache-Control: public, max-age=3600`, " +
						"so an allowlisted response must not reach a shared cache.",
				}},
			},
			{
				ID:      "resource-server-gates-all-credential-routes",
				Title:   "Resource-server mode unmounts the whole credential set, not six routes of it",
				Surface: "`HTTPConfig.ResourceServer`: the nineteen routes of `ResourceServerGatedRoutes`",
				Behaviour: "Registers none of the nineteen routes that mint, deliver or consume a " +
					"credential, so each answers `404` — `/register`, `/login`, " +
					"`/refresh`, `/logout`, `/forgot-password`, `/reset-password`, " +
					"`/change-password`, `/send-verification-email`, `/verify-email`, " +
					"`/change-email/request`, `/change-email/confirm`, `/magic-link/send`, " +
					"`/magic-link/verify`, `/sms/send`, `/sms/verify`, `/2fa/setup`, " +
					"`/2fa/verify-setup`, `/2fa/verify` and `/2fa/disable`. " +
					"`GenerateOpenAPISpec` drops the same nineteen under " +
					"`OpenAPIInfo.ResourceServer`, so the published spec and the mount agree. " +
					"What stays is `/me`, the session routes, `/profile`, `/add-phone`, " +
					"`/account` and the OAuth and linking group — and those still need a local " +
					"user store: `/me` reads it through `Service.Authenticate`, `/profile`, " +
					"`/add-phone` and `/account` write it, and the OAuth callback provisions a " +
					"user and mints a local session. The flag is about credentials, not about " +
					"store independence. The deployment with no user store is the one that " +
					"mounts `ResourceServerMiddleware` on its own routes, whose bearer and " +
					"cookie paths both build the principal from verified claims and read no " +
					"store at all.",
				Reference: "Guards six registrations on `isResourceServer` — `/login`, `/logout`, " +
					"`/refresh`, `/register`, `/forgot-password` and `/reset-password` — and " +
					"leaves the other thirteen mounted. Those thirteen reach handlers that read " +
					"and write the user store the mode says this instance does not have, so a " +
					"caller gets a `500` from a failing store lookup, or a `200` on a route that " +
					"mailed nothing, rather than a routing answer.",
				Citations: []string{
					"auth.router.ts:507-510",
					"auth.router.ts:541",
					"auth.router.ts:590",
					"auth.router.ts:622",
					"auth.router.ts:713",
					"auth.router.ts:777",
					"auth.router.ts:802",
				},
				Why: "The reference's own comment for the flag is that this instance has no local " +
					"user DB and only token verification makes sense, and the six guards are an " +
					"incomplete application of exactly that rule: a magic link cannot be minted, " +
					"an SMS code cannot be stored and a TOTP secret cannot be enrolled without " +
					"the store the mode has removed. Leaving them mounted turns a configuration " +
					"mistake into a runtime failure on a credential route, which is the worst " +
					"place to discover it. Gating all nineteen makes the mode mean one thing, " +
					"and makes it checkable: the same list drives the mount, the OpenAPI spec " +
					"and the conformance suite. It is drawn at the credential and not at the " +
					"store deliberately: gating every store-reading route would unmount `/me` " +
					"and the account routes from the deployment that has both a store and a " +
					"remote issuer, which is the commoner configuration, to protect one that " +
					"has no reason to mount the auth router at all.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Leave `HTTPConfig.ResourceServer` unset and mount " +
						"`ResourceServerMiddleware` on the host's own routes: the bearer " +
						"verification is independent of the gating, and every auth route then stays " +
						"mounted as it is today. A host that wants the reference's partial set " +
						"mounts two routers — one with the flag, one without — under different " +
						"prefixes.",
				}},
			},
			{
				ID:      "jwks-unknown-kid-refetch-is-rate-limited",
				Title:   "An unknown `kid` refetches the JWKS at most once per `MinRefreshInterval`",
				Surface: "`VerifyRS256` / `JWKSClient`: the rotation retry behind every bearer token",
				Behaviour: "On a `kid` the cached JWKS does not carry, the cache is invalidated and " +
					"the key looked up once more — but only when the cached document is older " +
					"than `ResourceServerConfig.MinRefreshInterval` (default " +
					"`DefaultJWKSMinRefreshInterval`, 30 seconds). Inside that window the token " +
					"is refused with `Unknown signing key` and no HTTP call is made, so N " +
					"requests bearing unknown `kid`s cost at most one outbound fetch per " +
					"interval. A negative `MinRefreshInterval` turns the limit off and restores " +
					"the reference behaviour exactly. The `RS256` allow-list is also checked " +
					"before the key lookup rather than after it, so an `alg: none` or `alg: " +
					"HS256` token never reaches the issuer at all; both orderings answer `401` " +
					"`INVALID_TOKEN`, only the logged message differs.",
				Reference: "Calls `jwksClient.invalidateCache()` and retries on every unknown `kid`, " +
					"with no interval and no cap. `invalidateCache` clears the cached document " +
					"*and* the in-flight `fetchPromise`, so concurrent requests do not even " +
					"coalesce onto one fetch, and the `algorithms: ['RS256']` pin is inside " +
					"`jwt.verify`, which runs after the key lookup.",
				Citations: []string{
					"token.service.ts:116-125",
					"token.service.ts:136",
					"jwks.service.ts:101-105",
					"jwks.service.ts:56-58",
				},
				Why: "Unrestricted, the retry is an unauthenticated request amplifier: anyone who " +
					"can reach the resource server makes it call the issuer once per request by " +
					"sending a random `kid`, and because the in-flight handle is dropped too, a " +
					"burst multiplies rather than coalesces. Worse, the refusal is collateral: " +
					"every legitimate request arriving between the invalidation and the next " +
					"document landing takes the cold path and blocks on the issuer, which is the " +
					"one thing the stale-while-revalidate cache exists to prevent. The interval " +
					"costs a real rotation nothing — a cached document is typically an hour old " +
					"by the time a token names a key it does not carry, so the first such token " +
					"still refetches and still verifies — and only refuses the case of two " +
					"rotations inside 30 seconds. `node-jwks-rsa` ships the same guard as its " +
					"`rateLimit` option for the same reason.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Set `ResourceServerConfig.MinRefreshInterval` to any negative duration: " +
						"every unknown `kid` then invalidates and refetches, as the reference " +
						"does. Nothing else in the verifier changes.",
				}},
			},
			{
				ID: "register-issues-a-session",
				Title: "`register` opens a session, where the reference only creates the " +
					"account — provisional, tracked as `nik2208/awesome-go-auth#21`",
				Surface: "`POST <prefix>/register`",
				Behaviour: "Mints a token pair for the new account and delivers it with the " +
					"`201`, through the same delivery switch every other issuing route uses: " +
					"in cookie mode the response is " +
					"`201 {\"success\": true, \"userId\": \"…\"}` plus `Set-Cookie` for " +
					"`accessToken` and `refreshToken`, and in bearer mode (`X-Auth-Strategy: " +
					"bearer`) the same body with top-level `accessToken` and `refreshToken` " +
					"fields and no cookies at all. A refresh session row is created with it, so " +
					"the account is logged in as soon as it exists and `GET <prefix>/me` " +
					"answers on the credential the registration returned.",
				Reference: "Mounts the route at all only when the host supplies " +
					"`options.onRegister`; without it there is no `POST <prefix>/register` in " +
					"the reference and the path answers `404` where this port answers `201` " +
					"(or `400 INVALID_INPUT` for a body missing a credential). That " +
					"unconditional mount is a second, smaller difference on this surface, and " +
					"it is named here rather than kept as a separate entry because a host that " +
					"has no register route has no session question to ask. Where the reference " +
					"*is* mounted it answers `201 {\"success\": true, \"userId\": user.id}` and " +
					"nothing else: the register route never reaches `sendTokens` — the one " +
					"function that writes `setTokenCookies` or the body tokens — and never " +
					"reaches `issueTokens`, so no cookie is set, no token is returned and no " +
					"session row is created. The caller is unauthenticated after a successful " +
					"registration and has to `POST /login` with the credentials it just chose.",
				Citations: []string{
					"auth.router.ts:713-730",
					"auth.router.ts:726",
					"auth.router.ts:399-406",
				},
				Why: "**Provisional, and recorded rather than endorsed.** The entry exists so " +
					"that a difference which is client-visible today is visible in the contract " +
					"too; it is not a settled product decision. What it costs is a bypass of the " +
					"email verification gate: `Service.Register` sets `IsEmailVerified` from the " +
					"configured mode and then mints the token pair unconditionally, so under " +
					"`strict` a brand-new account walks away holding a usable access token that " +
					"`POST <prefix>/login` would have refused for the same user with `403 " +
					"EMAIL_NOT_VERIFIED`. The registration hands out exactly the credential the " +
					"gate exists to withhold. The family already carries that as a defect and " +
					"not as a decision: it is tracked as " +
					"[nik2208/awesome-go-auth#21](https://github.com/nik2208/awesome-go-auth/issues/21), and " +
					"`awesome-lambda-auth`'s contract suite pins the current behaviour under " +
					"protest in `test/contract/cases_register_test.go`, which calls it " +
					"security-relevant and is written to fail the moment #21 lands. This entry " +
					"follows that suite: when #21 lands, the behaviour changes and the entry is " +
					"retired, not reworded. " +
					"What has kept the issuance in place so far is only the first-run cost of " +
					"the alternative — a registration that leaves the caller logged out makes " +
					"the first thing a new account does re-present the password it typed one " +
					"screen earlier, and issuing here removes that round trip. That argument " +
					"covers the round trip and nothing else; it is not a reason to skip a " +
					"verification gate the deployment asked for, and where the two conflict the " +
					"gate is the stronger claim. " +
					"The difference has stayed invisible this long because it costs the shipped " +
					"clients nothing: " +
					"`ng-awesome-node-auth` posts the registration `withCredentials` and reads " +
					"only `userId` off the body, so the cookies simply land in the jar and its " +
					"next session check succeeds instead of redirecting to the login form; the " +
					"Flutter client reads `userId` (or `id`) and ignores every other field, so " +
					"on native it discards the tokens and logs in exactly as it does today, and " +
					"on web it inherits the same cookie jar. Neither reads a field this port " +
					"omits, and neither has a branch that a present session breaks — but a " +
					"client that does not notice is not a client that consented, and it is the " +
					"gate, not the client, that #21 is about.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Not possible today: there is no knob. The issuance is unconditional " +
						"in the handler and no configuration field switches it off, which is part " +
						"of why `nik2208/awesome-go-auth#21` is open rather than closed as " +
						"configurable: a deployment running `EmailVerificationModeStrict` cannot " +
						"opt out of the email verification bypass described above. The only way " +
						"to get the reference's answer now is to not mount " +
						"`POST <prefix>/register` — `HTTPConfig.ResourceServer` unmounts it along " +
						"with the rest of the credential set — and create accounts through " +
						"`UserStore` itself, verifying the address before the first login. Read " +
						"\"no knob\" as the state of this release and not as a decision that it " +
						"stays that way: the fix for #21 is expected to remove the issuance " +
						"rather than add a switch.",
				}},
			},
			{
				ID:      "ui-config-verify-email-follows-the-effective-mode",
				Title:   "`ui/config`: `features.verifyEmail` follows the effective verification mode",
				Surface: "`GET <prefix>/ui/config`, the `features.verifyEmail` flag",
				Behaviour: "Answers `true` when `Config.SendEmailVerification` is wired *and* the " +
					"effective `Config.EmailVerificationMode` is `lazy` or `strict`. An unset mode " +
					"is `none` here as it is everywhere else in this port, and `DefaultConfig` " +
					"writes `none` into the field outright, so a deployment that wired the sender " +
					"and left the mode alone is told `false` and its login page offers no " +
					"verify-email affordance.",
				Reference: "Asks `(sendVerificationEmail || mailer) && (emailVerificationMode !== 'none' " +
					"|| requireEmailVerification)`. An *unset* mode passes the second term, since " +
					"`undefined !== 'none'` is true in JavaScript, so the same deployment is told " +
					"`true` — even though the reference's own fallback makes an unset mode behave " +
					"as `'none'` in every decision that acts on it. Its deprecated " +
					"`requireEmailVerification` boolean is a third route to `true`, reaching it " +
					"even with the mode set to `'none'`; this port has no field of that name.",
				Citations: []string{"ui.router.ts:121", "auth-config.model.ts:286-298"},
				Why: "The family's clients read `features` to decide which affordances to render, " +
					"so a flag that differs is a difference a consumer sees: a node-auth " +
					"deployment that wired a verification sender and never set the mode loses the " +
					"verify-email affordance when it moves here. Reproducing the term costs more " +
					"than it buys. It needs a distinction between an unset `EmailVerificationMode` " +
					"and one set to `none` that nothing else in this port makes — the service " +
					"normalises the empty string to `none` for registration, for login and for the " +
					"2FA path — and `DefaultConfig` erases that distinction anyway, so the flag " +
					"would answer differently for two configurations that behave identically on " +
					"every route, according to which of the two the host happened to build. It " +
					"would also advertise a step the deployment does not perform: with the " +
					"effective mode `none`, `Register` marks the address verified on the spot and " +
					"verification never comes up. Answering for what this deployment does is the " +
					"reading closest to what the flag means.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Set `Config.EmailVerificationMode` to `lazy` or `strict` — which is what " +
						"a deployment that wires a verification sender generally means — and the " +
						"flag answers `true`, as the reference does for the same deployment. There " +
						"is no way to reach `true` with the mode at `none`, because the legacy " +
						"boolean that reaches it there does not exist here.",
				}},
			},
			{
				ID:      "register-route-is-always-mounted",
				Title:   "`POST <prefix>/register` is unconditional, and `ui/config` reports it as such",
				Surface: "`POST <prefix>/register`, and the `features.register` flag of `GET <prefix>/ui/config`",
				Behaviour: "Registration is part of the library rather than a hook the host supplies: " +
					"every adapter mounts `POST <prefix>/register` on `Service.Register` on every " +
					"deployment, and `GET <prefix>/ui/config` answers `features.register: true` to " +
					"match. Resource-server mode is the one thing that unmounts the route, with " +
					"the rest of the credential set — see " +
					"`resource-server-gates-all-credential-routes` — and the flag does not follow " +
					"it there, which is what the reference does too for a resource server that " +
					"supplied the hook.",
				Reference: "Mounts `/register` only when `routerOptions.onRegister` is supplied, the " +
					"host having written the account-creation function itself, and reports " +
					"`!!routerOptions?.onRegister` in `features.register`. A deployment that " +
					"supplies no hook answers `404` on the route and tells the UI to hide the " +
					"sign-up affordance.",
				Citations: []string{"auth.router.ts:712-715", "ui.router.ts:115"},
				Why: "This port ships registration instead of asking for it: `Service.Register` " +
					"applies the password policy, hashes the password, applies the email " +
					"verification mode and writes through `UserStore`. There is no hook that can " +
					"be absent, so there is nothing for the route's presence to be conditional on, " +
					"and the flag — derived from the wiring rather than configured — answers for " +
					"the routes this port actually serves. The difference runs one way only: a " +
					"client is offered sign-up against a deployment whose node-auth counterpart, " +
					"having no `onRegister`, would have hidden it.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Not available from configuration. A host that wants no public sign-up " +
						"mounts the adapter on its own mux and refuses `POST <prefix>/register` " +
						"there, or runs in resource-server mode; `features.register` still answers " +
						"`true` in the first case, so such a host hides the affordance in its own " +
						"UI rather than reading the flag.",
				}},
			},
			{
				ID:    "docs-routes-are-opt-in",
				Title: "The documentation routes are off until asked for, and the document describes them",
				Surface: "`HTTPConfig.Docs.Enabled`: `GET <prefix>/openapi.json` and " +
					"`GET <prefix>/docs`; `ToolsOptions.Docs.Enabled` and " +
					"`AdminOptions.Docs.Enabled` for the same pair on the tools router and the " +
					"admin console",
				Behaviour: "Registers neither route unless `HTTPConfig.Docs.Enabled` is set, so a " +
					"deployment that configures nothing answers `404` for both. Set, the two " +
					"answer what the reference answers, to a request carrying no credential of " +
					"any kind: the generated document as `application/json`, and the reference's " +
					"Swagger UI page reproduced byte for byte, `swagger-ui-dist@5` from the unpkg " +
					"CDN included. Neither route has an auth gate, as neither has one there; both " +
					"sit behind the CSRF middleware, as every reference route registered after " +
					"the router-level auto-init does, which on a `GET` only writes the " +
					"`csrf-token` cookie to a reader who arrives without one. The served document " +
					"additionally describes those same two paths, which is what `OpenAPIInfo.Docs` " +
					"adds; the reference's generator describes neither, under any option. " +
					"The same flag, the same default and the same unguarded posture apply to the " +
					"tools router's pair under `ToolsOptions.Docs.Enabled` and to the admin " +
					"console's `GET <admin>/api/openapi.json` and `GET <admin>/api/docs` under " +
					"`AdminOptions.Docs.Enabled`, each served by its own generator — " +
					"`GenerateToolsOpenAPISpec` and `GenerateAdminOpenAPISpec`, the ports of the " +
					"reference's second and third builders. The admin pair is the one that costs " +
					"most to enable: every other route under `<admin>/api/*` is registered behind " +
					"`AdminGuard.Protect` and these two are not, so an anonymous caller reads the " +
					"whole admin API description and — because the document's path items follow " +
					"the configured stores — learns which optional features the deployment wired.",
				Reference: "Registers both when `swagger === true || (swagger !== false && " +
					"NODE_ENV !== 'production')`. The option defaults to `'auto'`, which is the " +
					"second arm, so a deployment that configures nothing serves them everywhere " +
					"except where the process environment sets `NODE_ENV` to exactly " +
					"`production`. Its generator emits the auth routes and stops, so neither " +
					"`/openapi.json` nor `/docs` appears in the document it serves. All three of " +
					"its routers carry the same option and the same default, and all three " +
					"register the pair with no guard — on `createAdminRouter` that is the only " +
					"exception to a `guard` spread onto every other `/api/*` route.",
				Citations: []string{
					"auth.router.ts:123-131",
					"auth.router.ts:529-538",
					"auth.router.ts:1652-1654",
					"auth.router.ts:1656-1677",
					"openapi.ts:1646-1669",
					"admin.router.ts:1493-1521",
					"tools.router.ts:332-352",
				},
				Why: "What a library serves must follow from its own configuration, not from a " +
					"process-wide variable it never sees set. `NODE_ENV` is a Node convention " +
					"with no Go counterpart — there is no one variable a Go deployment agrees " +
					"on, and picking one would make these routes appear and disappear on a value " +
					"the caller never passed to this library. Reading the ambient environment is " +
					"the host's call, and `Docs.Enabled` is where its answer goes, which is also " +
					"the reference's own `swagger: true | false` for a host that wants to decide " +
					"rather than infer. Defaulting to off rather than to on is the safe " +
					"direction of that choice: an unserved document is a missing convenience, a " +
					"served one is a description of the surface an attacker would otherwise have " +
					"to guess — and `<prefix>/docs` is more than a description. The page is the " +
					"reference's, so it loads `swagger-ui-dist@5` from the unpkg CDN with no " +
					"subresource integrity, and whatever that CDN serves then runs on the auth " +
					"origin, where the `csrf-token` cookie is readable from JavaScript by design. " +
					"A deployment should keep the UI route off in production, or serve it behind " +
					"a `Content-Security-Policy` that pins the CDN. " +
					"The admin console's pair is where that argument is sharpest, and the " +
					"decision there was to reproduce the reference's posture rather than to " +
					"tidy it: putting `AdminGuard.Protect` in front of those two would answer " +
					"`401` where the reference answers `200` and would break any tooling that " +
					"reads the document, and a port that silently closes a door is a port whose " +
					"other doors a reader can no longer trust to be the reference's. What this " +
					"port does instead is put the decision where a host makes it — the routes " +
					"are not registered until `AdminOptions.Docs.Enabled` is set — and say on " +
					"that field, in the generated document's own `security` blocks, and here " +
					"what enabling them publishes.",
				Notes: []DeviationNote{
					{
						Label: "Restoring the reference's default",
						Text: "One line where the `HTTPConfig` is built — " +
							"`cfg.Docs.Enabled = os.Getenv(\"APP_ENV\") != \"production\"` — with " +
							"whatever variable the deployment actually uses, and the same for " +
							"`cfg.Tools.Docs.Enabled` and `cfg.Admin.Docs.Enabled`. Nothing else " +
							"changes: the routes, the bodies and the mount are the same either " +
							"way.",
					},
					{
						Label: "Why the document lists itself",
						Text: "The wire conformance suite compares the generated document to the " +
							"mounted routes in both directions, on every adapter: a documented " +
							"operation that answers `404` fails, and so does a mounted route the " +
							"document omits. A document that hid the endpoint serving it would " +
							"have to be exempted from the second half, and the exemption is what " +
							"lets a spec drift. `OpenAPIInfo.Docs` is set with " +
							"`HTTPConfig.Docs.Enabled` and describes exactly the two paths that " +
							"flag mounts.",
					},
				},
			},
			{
				ID:    "identity-events-are-raised-from-the-development-line",
				Title: "The library raises `identity.*` events where the published reference raises none",
				Surface: "`auth.Config.Events` / `auth.WithEventBus`, and the twenty-three routes " +
					"that publish through it",
				Behaviour: "Twenty-three publication points raise fifteen of the twenty-six declared " +
					"`identity.*` names. Nineteen are in the auth router: login success and failure, " +
					"logout, session rotation, registration, the two 2FA transitions, password " +
					"change, email verification, email change, the magic-link and SMS logins, the " +
					"OAuth success and conflict, and the account delete. Four are in the admin " +
					"console: `identity.role.assigned` from `POST <admin>/api/users/{id}/roles` and " +
					"from both branches of `POST <admin>/users/{id}/promote`, and " +
					"`identity.role.revoked` from `DELETE <admin>/api/users/{id}/roles/{role}`. " +
					"Each carries the payload and the `data` keys the development line builds there, " +
					"and each goes through `EventBus.PublishContext`, so the correlation id, client " +
					"address and user agent the request carried travel with it — reaching the " +
					"nineteen from the carrier `EventContextMiddleware` installs and the four from " +
					"the request itself, because the admin console sits outside that middleware on " +
					"both lines exactly as the development line's own `publishAdminEvent` reads the " +
					"request rather than a carrier. A deployment that configures no bus — the " +
					"default, and the common case — publishes nothing and allocates nothing.",
				Reference: "At this revision **nothing in the library publishes at all**. " +
					"`AuthEventBus.publish` exists, is documented and is never called from the router; " +
					"the twenty-six names are declared and none is raised. The single `.publish` " +
					"outside the bus is `AuthTools.track`, which re-emits an event a *host* handed it " +
					"rather than one the library observed. A host wiring `new AuthEventBus()` into " +
					"`routerOptions.eventBus` at this revision receives nothing.",
				Citations: []string{"auth-event-bus.ts:55-64", "auth-event-names.ts:5-40", "auth-tools.ts:231"},
				Why: "The publication points are not invented, they are ported: they exist in " +
					"nik2208/node-auth, the private development line the published package is cut " +
					"from, where `publishRouterEvent` is called nineteen times in the auth router, " +
					"`publishAdminEvent` four times in the admin router and the bus three times in " +
					"the configurator — twenty-six " +
					"in all. That is the behaviour the family's next release has, and the whole event " +
					"plane this milestone builds (webhook delivery, the SSE stream, the telemetry " +
					"store) subscribes to a bus that would otherwise never speak. Shipping the " +
					"vocabulary without the publishers would mean every consumer downstream " +
					"subscribing to silence. The alternative — waiting for the dev line to ship — " +
					"would leave this port's `EventBus` as documented dead code it already was.",
				Notes: []DeviationNote{
					{
						Label: "Which tree a citation means",
						Text: "The citations on this entry are the published reference, as every " +
							"entry in this register is. The publication points themselves are cited " +
							"in the source as `node-auth <file>:<line>`, which resolves against " +
							"`DevLineRevision`; a bare `<file>:<line>` is `ReferenceRevision`. A " +
							"reviewer who greps the published tree for `publishRouterEvent` finds " +
							"nothing, and that is the expected result rather than a missing port.",
					},
					{
						Label: "What is deliberately not published",
						Text: "Eleven of the twenty-six declared names are raised by neither tree, " +
							"and this port has the obvious call site for several — " +
							"`identity.tenant.created` next to `Service.CreateTenant`, " +
							"`identity.user.linked` next to the account-linking routes. None is " +
							"raised. The three remaining development-line points are in its " +
							"`AuthConfigurator`, an imperative facade over its routers that this " +
							"port has no counterpart for and will not grow one for: the facade " +
							"offered here is `auth.Auth`, whose surface is the routes. " +
							"`event_publication_test.go` pins all twenty-six, exercises the " +
							"twenty-three and names the missing surface for each of the three.",
					},
				},
			},
			{
				ID:      "session-rotated-reports-one-session-id",
				Title:   "Refreshing rotates the token inside the session instead of opening a new one",
				Surface: "`POST <prefix>/refresh`, and the `identity.session.rotated` event it raises",
				Behaviour: "The refresh token is rotated in place: the stored hash and expiry of the " +
					"*existing* session row are rewritten, the session id is unchanged, and no row is " +
					"revoked. The `sid` claim of the new token pair is therefore the same as the old " +
					"one, `GET <prefix>/sessions` shows one row per login however often it refreshes, " +
					"and on the `identity.session.rotated` payload `data.previousSessionId` is equal " +
					"to the event's own `sessionId`.",
				Reference: "`issueTokens` creates a **new** session on every call and, when it was " +
					"given the previous `sid` — which the refresh route passes — revokes the old one " +
					"immediately after. So a refresh moves the session id, the session list grows a " +
					"row per refresh and loses the revoked one, and the development line's " +
					"`identity.session.rotated` carries two different ids: the new session in " +
					"`sessionId` and the one just revoked in `data.previousSessionId`.",
				Citations: []string{"auth.router.ts:425-439", "auth.router.ts:649"},
				Why: "The difference predates the event by a long way — it is how this port's " +
					"`Service.Refresh` has always worked — but until U18 nothing exposed it, and the " +
					"event is what makes it a fact a consumer has to know rather than an internal " +
					"choice. A subscriber that reads `previousSessionId` to stitch a session lineage " +
					"together gets a self-edge here and a chain there, and it would have no way to " +
					"find that out from the payload. Recording it was the alternative to changing " +
					"rotation semantics inside a PR about publishing events: moving the session id on " +
					"every refresh changes what `GET <prefix>/sessions` returns and invalidates every " +
					"`sid` a host has stored, which is a wire change and belongs to its own PR with " +
					"its own conformance run.",
				Notes: []DeviationNote{
					{
						Label: "What still holds",
						Text: "Both halves of what rotation is for are unaffected: the presented " +
							"refresh token is single-use, because the stored hash is replaced by the " +
							"new one, and a stolen token stops working the moment the legitimate " +
							"client refreshes. `POST <prefix>/logout` revokes the session in both " +
							"ports. Only the identity of the session across a refresh differs.",
					},
					{
						Label: "Reading the event safely",
						Text: "Treat `data.previousSessionId` as \"the session the presented refresh " +
							"token belonged to\", which is true in both ports, rather than as \"a " +
							"session that has just been revoked\", which is true only in the " +
							"reference. A subscriber keying a session-management view on " +
							"`sessionId` needs no change.",
					},
				},
			},
			{
				ID:      "event-handler-panic-does-not-fail-the-publisher",
				Title:   "A panicking event handler is contained instead of failing the request that published",
				Surface: "`auth.EventBus.Publish` and `PublishContext`, and therefore every route that will publish an `identity.*` event",
				Behaviour: "Each handler runs with `recover` around it. A handler that panics is " +
					"logged and stepped over, the remaining handlers for that event still run, " +
					"and `Publish` returns normally — so the route that published answers as " +
					"though nothing had gone wrong.",
				Reference: "`AuthEventBus` extends Node's `EventEmitter` and publishes with two " +
					"`emit` calls, which invoke their listeners inline. A listener that throws " +
					"propagates out of `emit`, out of `publish`, and into whatever published: " +
					"for the router that is the route handler's own `catch`, which passes the " +
					"error to `handleError` and answers `500` for work that already succeeded. " +
					"The listeners after the one that threw are never called, and the wildcard " +
					"channel is never reached if the throw came from the named one.",
				Citations: []string{"auth-event-bus.ts:48", "auth-event-bus.ts:55-64"},
				Why: "The reference's behaviour here is a consequence of extending `EventEmitter` " +
					"rather than a decision it took, and the Go form of it is worse than the " +
					"Node form. A panic that is not recovered unwinds the goroutine " +
					"`net/http` serves the request on; the server recovers it at the top, drops " +
					"the connection and logs, so a bug in a telemetry subscriber becomes a " +
					"failed request with no response body rather than a `500` with one. Nothing " +
					"about the auth operation is undone either way — the account is created, " +
					"the session is minted, the password is changed — so the choice is only " +
					"between reporting a subscriber's bug as a failure of the operation and " +
					"reporting it where it belongs. Containment also keeps one broken " +
					"subscriber from silencing the others, which the reference's ordering makes " +
					"a real hazard: an SSE handler registered after a webhook handler stops " +
					"receiving events entirely the moment the webhook handler throws.",
				Notes: []DeviationNote{
					{
						Label: "Observing it",
						Text: "Subscribe two handlers to one name, panic in the first, and both " +
							"the second handler and the caller of `Publish` proceed; the panic " +
							"appears on the standard logger as " +
							"`auth: recovered panic in event handler for \"<name>\"`. Under the " +
							"reference the second listener is not called and the publishing " +
							"request fails.",
					},
					{
						Label: "For a host that wants the failure",
						Text: "A handler that must not fail silently should report its own errors " +
							"— to its logger, its error tracker, its metrics — rather than " +
							"panicking. There is no knob that restores the reference's " +
							"propagation, because a bus whose delivery semantics depend on " +
							"configuration is a bus no downstream consumer can reason about.",
					},
				},
			},
			{
				ID:      "sse-slow-consumer-is-disconnected",
				Title:   "A slow SSE consumer is disconnected instead of being buffered without limit",
				Surface: "`auth.SseManager.Serve` — every `text/event-stream` this port writes",
				Behaviour: "Each connection has a bounded queue of pending frames, `WithSseSendBuffer` " +
					"frames deep and 64 by default. `Broadcast` never blocks and never waits on a " +
					"reader: a frame that does not fit means the connection is closed, its " +
					"registration removed and the handler returned, so the stream ends. A single " +
					"write is bounded the same way, by a ten second deadline set through " +
					"`http.ResponseController`, and a write that misses it ends the stream too. " +
					"A browser's `EventSource` reconnects on its own afterwards.",
				Reference: "`SseManager` writes straight to the Express `Response` and ignores the " +
					"`false` that `res.write` returns when the socket buffer is full — the " +
					"backpressure signal Node offers. The unwritten frames sit in the stream's " +
					"internal queue, which has no bound, so a consumer that stops reading costs " +
					"the server memory until the socket is torn down by the client or the OS. " +
					"Nothing disconnects it, and nothing tells the publisher, because `broadcast` " +
					"returns `void`.",
				Citations: []string{"sse-manager.ts:204-221", "sse-manager.ts:249-253"},
				Why: "There is no portable way to reproduce it. Node's answer comes from stream " +
					"backpressure, where an ignored `false` degrades into memory growth and " +
					"nothing else; Go's equivalent is a channel, and the three things a full one " +
					"can do are block the publisher, drop the frame, or end the connection. " +
					"Blocking is not available: `EventBus.Publish` is synchronous and runs on the " +
					"goroutine serving an HTTP request, so one client that stopped reading would " +
					"stall every login in the process. Dropping is available and is the worse of " +
					"the two remaining, because it is silent — neither implementation replays, so " +
					"a dropped frame is not recoverable by any client, and a client that is never " +
					"told has no way to know its view is now wrong. Ending the connection makes " +
					"the same gap visible at the one moment a client can act on it. The bound is " +
					"also what keeps one misbehaving reader from being a memory-exhaustion vector " +
					"against the auth process, which on the reference is the operator's problem " +
					"and here is not.",
				Notes: []DeviationNote{
					{
						Label: "Observing it",
						Text: "Open a stream, stop reading from the socket, and broadcast more " +
							"than `WithSseSendBuffer` frames to a topic it holds: the response " +
							"ends and `ConnectionCount` drops. Under the reference the stream " +
							"stays open and the frames accumulate in the server's memory.",
					},
					{
						Label: "What a reconnecting client gets",
						Text: "Nothing it missed. Neither implementation reads the `Last-Event-ID` " +
							"header a browser sends when its `EventSource` reconnects, neither " +
							"retains a delivered event, and the per-connection last event id is " +
							"only ever compared against the next event's — so a reconnect resumes " +
							"from *now*. Whatever was raised while the client was away is gone in " +
							"both, and the difference this entry records is only how the gap " +
							"happens: abruptly and observably here, silently and without bound " +
							"there.",
					},
					{
						Label: "For a host that wants the frames kept",
						Text: "Raise `WithSseSendBuffer` to the burst the slowest client must " +
							"survive; it trades memory for tolerance, one queue per connection. " +
							"There is no unbounded setting, and there deliberately is not: an " +
							"unbounded queue on a Go server is the memory-exhaustion vector above " +
							"with a configuration flag in front of it. Delivery that has to " +
							"survive a disconnect needs an event log the client can replay from, " +
							"which is a guarantee neither this port nor the reference offers.",
					},
				},
			},
			{
				ID:      "ui-ssr-config-json-is-html-escaped",
				Title:   "The SSR-injected `__AUTH_CONFIG__` is HTML-escaped JSON, and cannot be broken out of",
				Surface: "`GET <prefix>/ui/<page>`, the `<script>window.__AUTH_CONFIG__ = …</script>` block",
				Behaviour: "Serialises the config object with `encoding/json` at its default " +
					"settings, which escape `<`, `>` and `&` as `\\u003c`, `\\u003e` and " +
					"`\\u0026`. Any `</script>` inside `siteName`, `logoUrl` or `customCss` " +
					"therefore reaches the browser as `\\u003c/script\\u003e`: it stays inside " +
					"the string, the script block ends where the server put its `</script>`, and " +
					"the value `JSON.parse` yields is character for character the one that was " +
					"configured. The bytes on the wire differ from the reference's whenever any " +
					"string in the document contains one of those three characters — a " +
					"`customCss` with a child selector is enough.",
				Reference: "Writes `JSON.stringify(config)` straight into the `<script>` block. " +
					"`JSON.stringify` escapes nothing for HTML, and a `<script>` element is " +
					"terminated by the byte sequence `</script>` wherever it appears, quoted or " +
					"not — so a `siteName` of `x</script><img src=x onerror=…>` closes the " +
					"block and the rest is parsed as markup and runs. The same page HTML-escapes " +
					"that identical `siteName` five characters at a time before putting it in " +
					"`<title>` and `<h1 class=\"site-name\">`, so the omission is in one sink " +
					"rather than a decision about the value.",
				Citations: []string{"ui.router.ts:272", "ui.router.ts:217-226"},
				Why: "Reproducing the reference including its quirks is the standing rule here, " +
					"and this is the register that exists for the cases where it is set aside. " +
					"It is set aside because the cost and the benefit are as lopsided as they " +
					"get. What reproducing it buys is byte-identical output for configurations " +
					"containing `<`, `>` or `&`; what it costs is an HTML injection into every " +
					"page this port serves, reachable by whoever can set the branding. No client " +
					"can observe the difference: `\\u003c` and `<` are the same character to " +
					"`JSON.parse`, so `window.__AUTH_CONFIG__` is the identical object either " +
					"way, and the escaping is visible only to something reading the raw bytes of " +
					"the HTML — which is not what the family's clients do with this block. " +
					"Turning the escaping off would have taken an explicit " +
					"`Encoder.SetEscapeHTML(false)`, so keeping it is also the reading where the " +
					"unsafe behaviour is the one that has to be asked for. The direction of the " +
					"difference matters too: this is the only entry in this register where the " +
					"port is *stricter* than the reference, and a deployment cannot be broken by " +
					"a hole being closed.",
				Notes: []DeviationNote{
					{
						Label: "Matching the reference exactly",
						Text: "Not available from configuration, and deliberately so. A host that " +
							"needs the exact bytes serves its own page: `UIOptions.Assets` takes " +
							"any `fs.FS`, and `(*Auth).UIConfig` returns the same document to " +
							"marshal however it likes.",
					},
					{
						Label: "The two sinks this does not close",
						Text: "`customCss` is written into a second `<style>` element unescaped " +
							"and `logoUrl` into an `<img src=\"…\">` attribute unescaped, both " +
							"exactly as the reference writes them, because there escaping would " +
							"change what renders rather than only how it is encoded. " +
							"`UIOptions.CustomCSS` is read from the static configuration alone " +
							"and is therefore the host's own code; `logoUrl` can also come from " +
							"a `SettingsStore`, whose only writer in this release is the host's " +
							"own code, since the admin panel that would let an operator write " +
							"one arrives in M8. A deployment that lets a lower-privileged actor " +
							"write either value is trusting that actor with the auth origin.",
					},
				},
			},
			{
				ID:      "admin-console-requires-an-explicit-policy",
				Title:   "An admin console with no access policy is not served at all",
				Surface: "`HTTPConfig.Admin`: the whole admin surface under `Admin.Path`, `/admin` by default",
				Behaviour: "Mounts nothing unless `HTTPConfig.AdminMounted()` — `Admin.Enabled` set " +
					"*and* one of `Admin.AccessPolicy` or `Admin.Secret` configured. With the " +
					"flag on and neither of those, no route under `Admin.Path` is registered and " +
					"the console answers `404` everywhere, on all four adapters. The " +
					"reference's own default is one call away and keeps its own name: " +
					"`AccessPolicy: auth.AdminOpen()` serves every route to every caller, " +
					"which is what `'open'` means there.",
				Reference: "Builds the router regardless. The selection is `accessPolicy`, then " +
					"`adminSecret`, then neither — and the third arm writes the line " +
					"\"[awesome-node-auth] WARNING: createAdminRouter called without " +
					"`accessPolicy` or `adminSecret`. Admin routes are unprotected. Set " +
					"accessPolicy in production.\" to `process.stderr`, and installs a guard " +
					"that calls `next()` for every request. The console, including every route " +
					"that reads or writes the user table, is then served to anyone who can " +
					"reach the port.",
				Citations: []string{
					"admin.router.ts:511-537",
					"admin.router.ts:531-536",
				},
				Why: "Reproducing the reference including its quirks is the standing rule, and it " +
					"is set aside here because the quirk is an open administrative console and " +
					"because — uniquely in this register — reproducing it costs a deployment " +
					"nothing to move away from. `HTTPConfig.Admin` is new in this release, so " +
					"there is no existing Go deployment whose configuration this can break: no " +
					"host has ever set these fields, and the first host to set them reads the " +
					"field doc while doing it. That is not true of the reference, whose " +
					"`createAdminRouter` has shipped with this default since 1.8.0 and cannot " +
					"withdraw it without breaking callers. " +
					"The second half of the reasoning is that `process.stderr` has no " +
					"counterpart here. This package writes diagnostics through " +
					"`Config.Logger`, which defaults to nil and discards them, so a faithful " +
					"port of the warning would be a line nobody sees in front of a door " +
					"nobody closed. Refusing to mount is the same statement made where it " +
					"cannot be missed, and `AdminMounted()` is exported so a host can turn " +
					"the refusal into its own startup error in one line: " +
					"`if cfg.Admin.Enabled && !cfg.AdminMounted() { log.Fatal(\"admin: no access policy\") }`. " +
					"Choosing `AdminOpen()` explicitly also puts the decision in the " +
					"deployment's own configuration, where a reviewer reading the host's " +
					"source can see it, instead of in the absence of a field.",
			},
			{
				ID:      "admin-unauthenticated-get-serves-only-the-login-form",
				Title:   "The unauthenticated browser branch of the admin guard reaches the shell and nothing else",
				Surface: "`HTTPConfig.Admin`: every route behind `AdminGuard.Protect`, and `GET <admin>/`",
				Behaviour: "Honours the `adminNeedsAuth` marker on exactly one route: the HTML shell, " +
					"which is the only thing that can render the built-in login form. Every " +
					"other guarded route answers `401 {\"error\":\"Unauthorized\"}` to an " +
					"unauthenticated request whatever its `Accept` header says. The shell " +
					"rendered through that branch additionally carries no feature flags: " +
					"`window.__ADMIN_CONFIG__` reports every `feat*` member as `false` and an " +
					"empty `uploadBaseUrl`, so the page discloses the mount path and the login " +
					"form and nothing about the deployment. The vendored `admin.js` reloads the " +
					"page after a successful login, so it has the real flags before it draws a " +
					"tab.",
				Reference: "Sets `(req as any).adminNeedsAuth = true` and calls `next()` for **any** " +
					"guarded `GET` whose `Accept` contains `text/html`, when no `loginPath` is " +
					"configured. The marker is advisory: no handler behind the guard reads it " +
					"except the shell, so `GET /admin/api/ping` and — as the rest of the admin " +
					"API lands behind the same guard — `GET /admin/api/users` answer normally " +
					"to a request carrying no credential at all. `curl -H 'Accept: text/html' " +
					"…/admin/api/users` is the whole exploit. The shell it serves through the " +
					"same branch carries the full feature object regardless.",
				Citations: []string{
					"admin.router.ts:309-325",
					"admin.router.ts:709",
					"admin.router.ts:741-743",
					"admin.router.ts:748",
				},
				Why: "The branch exists so a browser arriving without a session sees a login form " +
					"rather than a JSON `401`, and that purpose is served entirely by the one " +
					"route that renders the form. Extending it to every `GET` is not a decision " +
					"the reference makes anywhere in prose — the comment at the marker says " +
					"\"so the UI router can show the built-in login form\" — it is the " +
					"consequence of putting the marker on the request instead of on the route. " +
					"Reproducing it would mean shipping a library whose admin API is readable " +
					"by anyone who sets a request header, which is not a quirk a client can " +
					"depend on but a hole a deployment can be breached through, and M8's " +
					"remaining PRs all mount behind this same guard. " +
					"Emptying the feature flags on that render is the same argument applied to " +
					"the one thing the shell would otherwise disclose: the flag object is the " +
					"body of `GET <admin>/api/ping`, a route that requires a session, so " +
					"serving it beside the login form would hand out through the door what the " +
					"lock next to it refuses. No client notices, because the SPA reloads after " +
					"login. Under `Admin.Secret` the shell is unguarded by design and still " +
					"carries the full object, exactly as there — this narrowing is the marker " +
					"branch only.",
			},
			{
				ID:      "admin-guard-accepts-only-typed-session-tokens",
				Title:   "The admin guard accepts an admin token or an access token, and `isRoot` only on the first",
				Surface: "`HTTPConfig.Admin`: the `Authorization: Bearer` and cookie credential every guarded admin route reads",
				Behaviour: "Verifies HS256 over `Admin.JWTSecret` and then checks three claims the " +
					"reference does not: `typ`, `iss` and — for the store lookup — `tid`. Two " +
					"types are accepted. `typ: \"admin\"` is the token `POST <admin>/login` " +
					"mints and the only one on which the `isRoot` claim is honoured; " +
					"`typ: \"access\"` is an ordinary session token, which is the integration " +
					"the reference documents when it says `jwtSecret` must match " +
					"`AuthConfig.accessTokenSecret`, and on which `isRoot` is ignored outright. " +
					"Everything else is not a credential: a refresh token, and the typed " +
					"step-up token a user holds after a password and before a second factor, " +
					"are both `401`.",
				Reference: "Signs `{sub, email, isRoot}` with `expiresIn: '24h'` and verifies with a " +
					"bare `jwt.verify(rawToken, jwtSecret)`. Nothing distinguishes one token " +
					"from another, so every token that secret signs is an admin credential. " +
					"The 2FA step-up token always is: it is `generateTokenPair(...).accessToken` " +
					"with a five-minute expiry and no marking claim (auth.router.ts:563-566, " +
					":572-575), signed with `config.accessTokenSecret`, which is the secret " +
					"`jwtSecret` is documented as having to match. So a user who has proved a " +
					"password and not the second factor the deployment requires can present " +
					"that token to the console and be judged by the access policy as though the " +
					"second factor had been given. The refresh token is signed with " +
					"`config.refreshTokenSecret` there (token.service.ts:25-29) and is therefore " +
					"a second admin credential only in a deployment that sets both secrets to " +
					"one value — where it is one for seven days rather than five minutes. This " +
					"port signs both with Config.Secret unless `Config.RefreshSecret` is set, and " +
					"leaves it unset by default, so refusing it here is not hypothetical. " +
					"A payload carrying `isRoot: true` short-circuits the user-store lookup and " +
					"the policy together, whatever minted it.",
				Citations: []string{
					"admin.router.ts:76-79",
					"admin.router.ts:300",
					"admin.router.ts:343-352",
					"admin.router.ts:585",
				},
				Why: "This port already types its tokens and already refuses an untyped one: " +
					"`typ` is a reserved claim `issueToken` writes after the " +
					"`Config.BuildTokenClaims` merge precisely so that a hook cannot turn a " +
					"step-up token into a session, which is the " +
					"`temp-token-is-typed-not-an-access-token` deviation. A guard that verified " +
					"a signature and stopped would be the one door in the building that " +
					"reopened it, and it would reopen it on the console. The `iss` check is the " +
					"same argument: `parseToken` refuses a token from another issuer on every " +
					"other route, and the admin surface is not the place to start accepting " +
					"one. " +
					"Confining `isRoot` to the admin token is what makes the reference's " +
					"bootstrap override safe to reproduce at all. A claim that bypasses the " +
					"user store must have exactly one minter, and `POST <admin>/login` is it; " +
					"without the type check the claim could also arrive on an access token, " +
					"where `Config.BuildTokenClaims` is a host hook free to return any name " +
					"the reserved set does not cover — so a mapping written for some unrelated " +
					"purpose could grant the console. " +
					"What it costs: a host that mints admin tokens with some third-party " +
					"signer has to add `typ`, `iss` and an `exp`. The documented integration " +
					"— the auth router's own login — is unaffected, because its tokens already " +
					"carry all three.",
			},
			{
				ID:      "admin-cookie-secure-flag-is-configured-not-forwarded",
				Title:   "The admin session cookie's `Secure` flag and name come from the configuration, never from a request header",
				Surface: "`POST <admin>/login` and `POST <admin>/logout`: the `Set-Cookie` they write",
				Behaviour: "Derives both the `Secure` attribute and the `__Host-` / `__Secure-` prefix " +
					"from `CookieOptions.Secure`, `CookieOptions.Path` and " +
					"`CookieOptions.Domain` — `CookieOptions.CookieName`, the same function the " +
					"auth routes name their own cookies with, whose `Secure` defaults to `true` " +
					"here. `X-Forwarded-Proto` is read nowhere and changes nothing. " +
					"`AdminOptions.CookiePrefix` still overrides the prefix outright, as there, " +
					"and the `__Host-` requirements (`Secure`, `Path=/`, no `Domain`) are " +
					"reapplied after it. The guard's read order is unchanged: " +
					"`__Host-accessToken`, `__Secure-accessToken`, `accessToken`.",
				Reference: "Computes `isSecure` per request as `req.secure || req.headers['x-forwarded-proto'] " +
					"=== 'https'` and feeds it to `resolveAdminCookieName`, so a request header " +
					"decides both whether the cookie carrying a 24-hour admin session is marked " +
					"`Secure` and which of the three names it is written under. The failure is " +
					"bidirectional: a spoofed `https` over plaintext writes a `Secure`, " +
					"possibly `__Host-` cookie the browser then drops, and a genuine TLS " +
					"deployment whose proxy does not set the header writes a bare, non-`Secure` " +
					"`accessToken` holding that same session.",
				Citations: []string{
					"admin.router.ts:218-231",
					"admin.router.ts:243-252",
					"admin.router.ts:591",
					"admin.router.ts:601-611",
					"admin.router.ts:619",
				},
				Why: "`HTTPConfig.ClientIP` settled this class of question a release ago and in this " +
					"direction: a forwarded header is only as trustworthy as the trust " +
					"configuration behind it, that configuration is the host's knowledge, and " +
					"this package ships no parser that would pretend otherwise. Here the seam " +
					"the host needs already exists and is already being read three cookies " +
					"over — `CookieOptions.Secure` is the operator's statement about the " +
					"deployment — so honouring the header would mean letting a caller " +
					"contradict the operator about one cookie and not the other three. " +
					"It also removes a way for the login route and the guard to disagree: the " +
					"reference's own `resolveAdminCookieName` comment says it exists so that " +
					"\"the guard reads exactly the cookie that was written by the admin login " +
					"handler\", which holds only while every request agrees about `isSecure`, " +
					"and a proxy that sets the header on some paths and not others breaks it. " +
					"The direction of the difference is the safe one in the case that matters: " +
					"where the reference would emit a non-`Secure` admin session cookie, this " +
					"port emits a `Secure` one.",
				Notes: []DeviationNote{
					{
						Label: "Matching the reference exactly",
						Text: "Not available from configuration, deliberately. A deployment " +
							"terminating TLS at a proxy sets `Cookies.Secure` — its default — " +
							"and gets the right answer on every request without a header; one " +
							"genuinely serving plain HTTP sets it to false and says so once, " +
							"in its own source, instead of per request from outside.",
					},
				},
			},
			{
				ID:      "admin-listings-are-ordered-by-id",
				Title:   "The admin listings answer in a defined order, where the reference's own stores impose none",
				Surface: "`HTTPConfig.Admin`: the paged and listing reads — `GET <admin>/api/users`, `/api/sessions`, `/api/roles`, `/api/tenants`, `/api/users/{id}/roles`, `/api/users/{id}/tenants` and `/api/tenants/{id}/users`",
				Behaviour: "Answers in a total order, and states it as part of the store contract " +
					"rather than as an implementation detail: **ID ascending, by Go string " +
					"comparison**. `AdminUserStore.ListUsers` orders by `User.ID`, " +
					"`SessionLister.GetAllSessions` by `Session.ID`, `RoleLister.GetAllRoles` " +
					"and `RolesPermissionsStore.GetRolesForUser` by the role name, and the " +
					"tenant listings by the tenant or user id — which is what every other list " +
					"method in this package already did. A store that cannot answer in that " +
					"order may answer in its own, but owes its callers the same kind of entry " +
					"this one is. The two listings that are *not* covered stay as the " +
					"reference has them: `GET <admin>/api/templates/mail` and " +
					"`/api/templates/ui` come back in first-insertion order, matching its " +
					"`Map` iteration, and a user's linked accounts in the order they were " +
					"linked.",
				Reference: "Declares no order anywhere, and none of its shipped stores supplies one. " +
					"`listUsers` is `SELECT * FROM users LIMIT ? OFFSET ?` with no `ORDER BY` " +
					"in the SQLite and MySQL examples, `find({}).skip().limit()` in natural " +
					"order in the MongoDB one, and a `Map`'s insertion order in the in-memory " +
					"one. So the console's own paging is undefined against its own examples: " +
					"a row can appear on two consecutive pages or on neither, and nothing in " +
					"the router notices, because `total` is the best-effort expression at " +
					"`:782` rather than a count. Its `'first-user'` access policy reads " +
					"`listUsers(1, 0)[0]` and calls that user \"the first registered user\" " +
					"(`:25-27`), which under a `SELECT` with no `ORDER BY` is whichever row " +
					"the engine happened to return.",
				Citations: []string{
					"admin.router.ts:748",
					"admin.router.ts:782",
					"admin.router.ts:1086",
					"admin.router.ts:1129",
					"sqlite-user-store.example.ts:305",
					"mysql-user-store.example.ts:356",
					"mongodb-user-store.example.ts:327",
					"in-memory-user-store.ts:175",
				},
				Why: "`offset` without an order is not paging. The reference's route signature is " +
					"positional — limit and offset, page after page — and a positional cursor " +
					"over an unordered set is a different set each time it is asked, so an " +
					"operator walking the users table can be shown one account twice and " +
					"another not at all, with nothing on the wire to say so. Reproducing the " +
					"absence would mean reproducing a defect that only manifests as missing " +
					"rows, which is the one class of wire difference a client cannot detect " +
					"and a reviewer cannot see. " +
					"The second reason is that the guard already depends on the order: " +
					"`AdminPolicyFirstUser` grants the console to `ListUsers(ctx, \"\", 1, 0)[0]`, " +
					"so under an unordered store the answer to \"who may administer this " +
					"deployment\" is whatever the query planner felt like — and it can differ " +
					"between two requests. An access decision cannot rest on that. " +
					"Nothing is given up by fixing it. No shipped client reads these routes — " +
					"they are the admin SPA's, and the SPA renders whatever order it is sent — " +
					"and an order is strictly more information than no order, so a consumer " +
					"written against the reference cannot break on receiving one. The cost " +
					"falls entirely on a store implementor, which is why it is stated on the " +
					"three interfaces rather than only here.",
			},
			{
				ID:      "admin-credential-listings-are-ordered",
				Title:   "The two credential listings answer in a defined order, where the reference ships no implementation to have one",
				Surface: "`HTTPConfig.Admin`: the credential reads — `GET <admin>/api/api-keys` and `GET <admin>/api/webhooks`",
				Behaviour: "Answers in a total order, stated on the store interface rather than in the " +
					"route, and the two orders differ because the two tables do. API keys come " +
					"back **newest first: `CreatedAt` descending, ties broken by `ID` ascending** " +
					"(`APIKeyAdminStore.ListAll`), because a key carries the `createdAt` the " +
					"console shows and the key just minted is the one an operator came to look " +
					"at; a record with a zero `CreatedAt` sorts last. Webhooks come back in " +
					"**first-insertion order** (`WebhookAdminStore.ListWebhooks`), which is the " +
					"order `MemoryWebhookStore` keeps and the one `WebhookStore.FindByEvent` " +
					"already fans out in, because `WebhookConfig` carries no timestamp at all " +
					"and inventing a column to sort on would be a different store contract. The " +
					"`ID` tiebreak is the load-bearing half of the first: `CreatedAt` alone is " +
					"not a total order — two keys can share an instant, and a column with second " +
					"resolution will make them share it often — and `limit`/`offset` paging over " +
					"a partial order repeats some rows and drops others. A store that cannot " +
					"hold to either order may answer in its own, and owes its callers an entry " +
					"like this one.",
				Reference: "Declares no order for either, and ships no implementation of either method " +
					"that could have one. `listAll?` is optional on `IApiKeyStore` and on " +
					"`IWebhookStore` alike, described as needed \"only for admin management " +
					"screens\", and nothing in the tree implements it — the example stores in " +
					"those interfaces' own doc comments cover `findByEvent` and the mandatory " +
					"finders and stop there. So the console's paging over these two tables is " +
					"undefined against its own examples, exactly as `listUsers` is: the routes " +
					"page positionally with `limit` and `offset` (`:1263-1265`, `:1372`) and " +
					"report `total` as the best-effort expression at `:1288` and `:1383` rather " +
					"than as a count, so a row can appear on two consecutive pages or on neither " +
					"and nothing on the wire says so.",
				Citations: []string{
					"admin.router.ts:1265",
					"admin.router.ts:1288",
					"admin.router.ts:1372",
					"admin.router.ts:1383",
					"api-key-store.interface.ts:74-78",
					"webhook-store.interface.ts:119-123",
				},
				Why: "This is `admin-listings-are-ordered-by-id`'s argument applied to the two " +
					"listings that entry deliberately left out. It left them out because the " +
					"orders are not that entry's — neither of these is ID ascending — and " +
					"because neither was client-visible until a route served it, which is this " +
					"release. " +
					"The argument itself is unchanged: `offset` without an order is not paging, " +
					"a positional cursor over an unordered set is a different set each time it " +
					"is asked, and the resulting defect only manifests as missing rows, which is " +
					"the one class of wire difference a client cannot detect and a reviewer " +
					"cannot see. " +
					"What is new is what the missing row *is* here. On the users table a row " +
					"paged past is an account an operator did not see; on the key table it is a " +
					"credential nobody revokes, and on the webhook table it is an endpoint still " +
					"receiving identity events that nobody knows is subscribed. A console whose " +
					"whole purpose on these two screens is to let an operator find and revoke " +
					"cannot page over a set that reshuffles between pages. " +
					"Nothing is given up by fixing it. No shipped client reads these routes — " +
					"they are the admin SPA's, and the SPA renders whatever order it is sent — " +
					"and an order is strictly more information than no order, so a consumer " +
					"written against the reference cannot break on receiving one. The cost falls " +
					"on a store implementor, which is why both orders are stated on the " +
					"interfaces and not only here.",
			},
			{
				ID:      "admin-user-detail-spans-tenants-only-through-a-lookup-store",
				Title:   "`GET <admin>/api/users/{id}` reaches a user in another tenant only through `UserLookupStore`",
				Surface: "`HTTPConfig.Admin`: `GET <admin>/api/users/{id}`",
				Behaviour: "Resolves the id through `auth.UserLookupStore.FindUserByID` when the " +
					"configured user store implements it — by id alone, across every tenant, " +
					"which is how `GET <admin>/api/users` lists — and answers the reference's " +
					"body. `MemoryUserStore` implements it. A store that does not is asked " +
					"`UserStore.GetUserByID(id, \"\")`, which reads the empty tenant as a " +
					"literal, so a user stored under a non-empty tenant is " +
					"`404 {\"error\": \"User not found\"}` although the listing shows it. A " +
					"store that holds one id under two tenants answers an error for that id " +
					"rather than either record, and the route answers that `404` too.",
				Reference: "`findById(id)` is a mandatory `IUserStore` method and carries no tenant " +
					"(`user-store.interface.ts:5`). The route calls it with the path parameter " +
					"and answers `404` only for `null` (`admin.router.ts:789-800`). An id is the " +
					"whole of a user's key there, so the listing and the detail route cannot " +
					"disagree about which users exist.",
				Citations: []string{
					"user-store.interface.ts:5",
					"admin.router.ts:789-800",
				},
				Why: "This port's mandatory by-id read is tenant-scoped, and its empty tenant has " +
					"to stay a literal: `/me`, `/refresh` and the access-token check hand the " +
					"token's `tid` to `GetUserByID`, and an empty `tid` that widened to every " +
					"tenant would resolve an account in any of them. So the tenant-spanning read " +
					"is a separate, optional seam that only the admin console reaches for. " +
					"Adding it to `UserStore` would break every store written against 0.11.0 for " +
					"a route most deployments never mount, and refusing without it would put a " +
					"`501` on a route whose reference answers none. The fallback is what the " +
					"route did in 0.11.0, and a single-tenant deployment — every user under the " +
					"empty tenant, which is what the reference's console assumes — sees the " +
					"reference's answer either way. The ambiguity refusal can only fire on a " +
					"store that let a host supply an id another tenant already holds; there, " +
					"showing an operator one of two accounts, picked by the store, is the one " +
					"answer worse than none.",
				Notes: []DeviationNote{
					{
						Label: "Matching the reference exactly",
						Text: "Implement `auth.UserLookupStore` on the user store. A key-value " +
							"store cannot serve it from the directory index behind " +
							"`AdminUserStore.ListUsers`: that index sorts on `<tenantID>#<id>`, " +
							"and a key condition cannot match a suffix. It needs an item keyed " +
							"on the id alone; the interface's doc comment sets out the two ways " +
							"to have one.",
					},
					{
						Label: "What this does not cover",
						Text: "`DELETE <admin>/api/users/{id}` and `POST <admin>/users/{id}/promote` " +
							"with `method=flag` still pass the empty tenant whatever the store " +
							"implements, so in a multi-tenant deployment neither reaches a user " +
							"the listing shows under another tenant. Both are writes, and " +
							"resolving a write's row through this seam changes which row it " +
							"reaches; neither has been moved onto it yet. " +
							"`GET <admin>/api/users/{id}/roles` also passes the empty tenant and " +
							"is not a case of this at all: its tenant is the scope of a role " +
							"assignment, and the console's own writers assign in the empty scope.",
					},
				},
			},
			{
				ID:      "tools-router-requires-an-explicit-guard-decision",
				Title:   "A tools router with no stated access posture is not served at all",
				Surface: "`HTTPConfig.Tools`: the whole tools surface under `Tools.Path`, `/tools` by default",
				Behaviour: "Mounts nothing unless `HTTPConfig.ToolsMounted()` — `Tools.Enabled` set, a " +
					"`Tools.AuthTools` facade supplied *and* `Tools.Access` configured. With the " +
					"flag on and no access decision, no route under `Tools.Path` is registered " +
					"and every tools path answers `404`, on all four adapters, the two " +
					"unguarded documentation routes included. The reference's own default is " +
					"one named call away: `Access: auth.ToolsPublic()` serves every route to " +
					"every caller, which is what an empty `protect` list means there. " +
					"`auth.ToolsProtected(mw)` is the other posture, and it answers nil — so " +
					"nothing mounts — for a nil `mw`, because a configuration that degrades " +
					"from guarded to open when a variable was left unassigned is the failure " +
					"this entry is about.",
				Reference: "Builds the router regardless. The guard slot is " +
					"`const protect: RequestHandler[] = authMiddleware ? [authMiddleware] : []`, " +
					"and nothing at all is said when it is left empty — unlike " +
					"`createAdminRouter`, which at least writes a line to `process.stderr`. All " +
					"four feature flags default to `true`, so the router a host gets by " +
					"forgetting `authMiddleware` is not a stub: `POST /track/:eventName`, " +
					"`POST /notify/:target` and `GET /stream` answer anyone who can reach the " +
					"port, and so does `GET /telemetry` wherever a telemetry store is " +
					"configured.",
				Citations: []string{
					"tools.router.ts:117-135",
					"tools.router.ts:121-124",
					"tools.router.ts:135",
					"tools.router.ts:140-245",
					"admin.router.ts:531-536",
				},
				Why: "The two grounds that decided " +
					"`admin-console-requires-an-explicit-policy` both hold here, and the " +
					"second holds with more force. `HTTPConfig.Tools` is new in this release, " +
					"so no existing Go deployment's configuration can be broken by refusing: " +
					"no host has ever set these fields, and the first to set them reads the " +
					"field doc while doing it. And the reference's signal cannot be ported " +
					"because there is none — this package writes diagnostics through " +
					"`Config.Logger`, which defaults to nil and discards them, and here the " +
					"reference does not even print the warning its admin router prints. " +
					"What is different is the surface, and it is priced rather than assumed. " +
					"`track` and `notify` do not read the user table; they write telemetry and " +
					"send messages, and that door costs more rather than less. " +
					"`POST /track/:eventName` takes `userId`, `tenantId` and `sessionId` from " +
					"the request body and only falls back to the authenticated principal, so " +
					"an anonymous caller forges telemetry attributed to any user — and `Track` " +
					"fans that forgery out to all four sinks: it is persisted, it is published " +
					"on the event bus where the host's own subscribers act on it, it is " +
					"broadcast to the SSE connections holding `user:<id>`, and it fires every " +
					"matching outgoing webhook, which is the deployment POSTing " +
					"attacker-chosen content to a third party in its own name and under its " +
					"own signature. `POST /notify/:target` sends on the `sse`, `email` and " +
					"`sms` channels, so with a mailer and an SMS transport configured an " +
					"anonymous caller makes the deployment send a named user mail and SMS — " +
					"which costs money and sender reputation, neither refundable. And " +
					"`GET /stream` with no principal still resolves to the topic `global`, " +
					"which carries every tracked event as a whole telemetry record, user id, " +
					"session id, IP and user agent included. Requiring the host to name the " +
					"posture is the same statement made where it cannot be missed, and " +
					"`ToolsMounted()` is exported so a host can turn the refusal into its own " +
					"startup error in one line: " +
					"`if cfg.Tools.Enabled && !cfg.ToolsMounted() { log.Fatal(\"tools: no access decision\") }`.",
				Notes: []DeviationNote{
					{
						Label: "Restoring the reference's default",
						Text: "One field where the `HTTPConfig` is built — " +
							"`cfg.Tools.Access = auth.ToolsPublic()` — and the router is served " +
							"exactly as `createToolsRouter(tools, {})` serves it. Nothing else " +
							"changes: the routes, the bodies, the mount and the four feature " +
							"flags are the same either way. The name is the point: a reviewer " +
							"reading the host's own source sees the posture, instead of having " +
							"to notice a field that is not there.",
					},
					{
						Label: "What the guard does and does not cover",
						Text: "`Tools.Access` is spread onto the routes the reference spreads " +
							"`...protect` onto: `track`, `notify`, `stream` and the telemetry " +
							"query. Two route groups never see it, there or here. The inbound " +
							"webhook is registered with no guard at all, because the caller is " +
							"a third-party provider with no session to present, and the two " +
							"documentation routes carry none either — so `GET <tools>/docs` " +
							"and `GET <tools>/openapi.json` are readable by anyone who can " +
							"reach the mount even when everything else is guarded. Keep " +
							"`Tools.Docs.Enabled` off in production for the reason " +
							"`docs-routes-are-opt-in` gives.",
					},
				},
			},
			{
				ID:      "tools-track-ip-comes-from-the-configured-seam",
				Title:   "The tracked client address comes from `HTTPConfig.ClientIP`, never from `X-Forwarded-For`",
				Surface: "`POST <tools>/track/{eventName}`: the `ip` of the telemetry record it persists, of the SSE frame that carries that record, and of the event it publishes on the bus",
				Behaviour: "Resolves the address through `HTTPConfig.ClientIP`, the one seam every " +
					"event this port raises already uses: the socket peer with its port " +
					"stripped by default, and whatever a configured function returns " +
					"otherwise. `X-Forwarded-For` is read nowhere on this route and changes " +
					"nothing — not even as a fallback when `ClientIP` is unset, which would be " +
					"the untrusted parser under another name and would make the default " +
					"deployment the spoofable one. A deployment behind a proxy it operates " +
					"sets `cfg.ClientIP` once and gets the forwarded address here and on the " +
					"auth router's events alike; one that configures nothing records the peer " +
					"that connected, which is a value no caller can choose. `User-Agent` is " +
					"recorded as sent, as there.",
				Reference: "Resolves it at the route, and differently from anywhere else in the tree: " +
					"`req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() ?? " +
					"req.socket.remoteAddress` — the left-most element of the header, trusted " +
					"unconditionally, with `req.socket.remoteAddress` only as the fallback. " +
					"Behind a proxy the deployment does not control, or behind none at all, " +
					"the caller therefore chooses the address that is written into the " +
					"telemetry store, broadcast to every connection holding the topic as part " +
					"of the whole record, and carried on the event the host's own bus " +
					"subscribers act on.",
				Citations: []string{
					"tools.router.ts:144",
					"tools.router.ts:154-155",
					"auth-tools.ts:203-214",
					"auth-tools.ts:233-246",
				},
				Why: "Reproducing the route's own rule would not add a second address rule " +
					"beside the host's, it would override it. `HTTPConfig.ClientIP` exists " +
					"because Express's `req.ip` means the socket peer or the left-most " +
					"unvouched `X-Forwarded-For` element depending on `trust proxy`, which is " +
					"an application setting this port cannot see — so the port takes the " +
					"unambiguous half and hands the host the function pointer, shipping no " +
					"parser of its own. A deployment that has set it has stated in its own " +
					"source which hop it trusts; a route that read element 0 of the header " +
					"anyway would discard that statement on the one surface where the address " +
					"is written into a durable record. A seam a single route is free to ignore " +
					"is not a seam. " +
					"The record is also the wrong place to be wrong. `Track` puts the address " +
					"on the `TelemetryEvent` the store keeps, on the frame every SSE " +
					"connection holding the topic receives, and — once a host calls `Bridge` — " +
					"in the same column as the library's own `identity.*` events, which is a " +
					"security log in every deployment that keeps one. And this is the surface " +
					"an unauthenticated caller is most likely to be standing on: see " +
					"`tools-router-requires-an-explicit-guard-decision`. " +
					"`admin-cookie-secure-flag-is-configured-not-forwarded` decided the same " +
					"class of question in the same direction one release earlier, and the " +
					"asymmetry of the two failures settles it: a lost client address is " +
					"recovered by one line of configuration, and a forged one already written " +
					"into a telemetry store is not recovered at all. Nothing shipped is " +
					"affected either way — `ng-awesome-node-auth`, the Flutter client and the " +
					"served `auth.js` never call `/tools`.",
				Notes: []DeviationNote{
					{
						Label: "Restoring the reference's rule",
						Text: "`cfg.ClientIP = func(r *http.Request) string { ... }`, reading " +
							"whichever header the deployment's own balancer sets and trusting " +
							"only the hops it operates. It applies to the auth router's events " +
							"too, which is the point: one statement about the deployment, one " +
							"meaning everywhere. A host that wants the reference's exact line " +
							"writes the first comma-separated element of `X-Forwarded-For` with " +
							"`RemoteAddr` as the fallback, in its own source, where a reviewer " +
							"can see that the deployment vouches for it.",
					},
				},
			},
			{
				ID:      "tools-request-bodies-are-typed",
				Title:   "The tools bodies are decoded, so a field of the wrong type is refused instead of recorded",
				Surface: "`POST <tools>/track/{eventName}` and `POST <tools>/notify/{target}`: the JSON request body",
				Behaviour: "Decodes the body into the documented types and answers `400` with this " +
					"router's own error envelope — a bare `{\"error\": ...}` — when it does not " +
					"fit, handing the facade nothing. On `track` that means `data` must be a " +
					"JSON object, because `AuthTools.Track` takes a `map[string]any`, and " +
					"`userId`, `tenantId`, `sessionId` and `correlationId` must be strings. On " +
					"`notify` only `metadata` is constrained, to an object; `data` there is " +
					"`any` and a scalar or an array is accepted, because `AuthTools.Notify` " +
					"takes `any`. An absent or empty body is not an error on either route: it " +
					"is the reference's `req.body = {}`, so a bodyless POST tracks an event " +
					"with no payload and still answers `202`.",
				Reference: "Reads its fields off `req.body as Record<string, unknown>` and casts each " +
					"one, and a TypeScript cast is a no-op at runtime. `{\"data\": 42}` is " +
					"therefore tracked as the number 42 and `{\"userId\": 5}` reaches the " +
					"telemetry record as the number 5 in a field the store interface declares " +
					"a string — both answered `202`. Its only refusal on these two routes is " +
					"`express.json`'s own, before the handler runs, for a body that is not " +
					"JSON at all.",
				Citations: []string{
					"tools.router.ts:143",
					"tools.router.ts:149-157",
					"tools.router.ts:168",
					"tools.router.ts:171-176",
					"auth-tools.ts:199",
				},
				Why: "Go has to decide what a mistyped field means, and the three answers are " +
					"not equal. Widening is not available: `data` becomes `Event.Data` at step " +
					"2 of the fan-out and that field is `map[string]any` across this package " +
					"so that an event is assignable to the webhook envelope and the telemetry " +
					"record without a runtime type check — the narrowing is older than this " +
					"route and `Track` cannot undo it. Reading each field leniently and " +
					"dropping what does not fit would answer `202` — *accepted* — to a caller " +
					"whose payload was silently discarded, which is the one outcome that " +
					"cannot be noticed from the outside. Refusing says so, at the edge, where " +
					"the caller can see it and fix it. " +
					"The status is also the reference's own in the case that actually happens: " +
					"a client sending a malformed body already gets `400` there, from " +
					"`express.json`, and what differs is the body — an Express error page " +
					"written by the host application against this router's `{\"error\": ...}`, " +
					"which is the envelope its own `503`, `501` and `400` use. No shipped " +
					"client is affected; the callers of these two routes are a host's own " +
					"services.",
				Notes: []DeviationNote{
					{
						Label: "Sending a scalar payload to track",
						Text: "Name it: `{\"data\": {\"value\": 42}}` rather than " +
							"`{\"data\": 42}`. That is what every publication point in both trees " +
							"does anyway — all twenty-six of the dev line's publish sites pass " +
							"an object literal — and it is the shape a consumer of the telemetry " +
							"record or the SSE frame can read a named field out of.",
					},
				},
			},
			{
				ID:      "admin-upload-refusals-answer-the-admin-envelope",
				Title:   "A refused upload is answered by the router, not by the host application",
				Surface: "`POST <admin>/api/upload/logo` and `POST <admin>/api/upload/bg-image`",
				Behaviour: "Refuses in the admin router's own `{\"error\": \"…\"}` envelope, with a " +
					"status naming the problem. A name that is not one of the seven image " +
					"extensions is `400 {\"error\": \"Only image files are allowed\"}` — the " +
					"reference's own `fileFilter` message. A body past `auth.UploadMaxBytes`, " +
					"five megabytes, is `413 {\"error\": \"File too large\"}`, and so is a " +
					"multipart request whose total exceeds that plus 64 KiB of slack. An " +
					"`UploadStore` that fails is `500` carrying the error's own message, the " +
					"shape `PATCH <admin>/api/settings/ui` already has on this router. The one " +
					"refusal that is the reference's unchanged is `400 {\"error\": \"No file " +
					"uploaded\"}`, which is also where a request that is not `multipart/" +
					"form-data` ends up.",
				Reference: "Configures `multer` with `limits: { fileSize: 5 * 1024 * 1024 }` and a " +
					"`fileFilter` that calls back `new Error('Only image files are allowed')`, " +
					"then mounts `upload.single('file')` between the guard and the handler. " +
					"Both refusals are `next(err)`, the admin router registers no error " +
					"middleware, and neither reaches the handler — so the status and the body " +
					"are whatever the *host application's* error handler produces, which for a " +
					"plain Express app is a `500` carrying an HTML error page. The handler's " +
					"own `if (!req.file)` branch is the only refusal it writes itself. No " +
					"bound is placed on the rest of the request: `limits.fields`, " +
					"`limits.parts` and the non-file field size are all left at their " +
					"defaults, so a body carrying one small image and a gigabyte of text " +
					"fields is read whole.",
				Citations: []string{
					"admin.router.ts:1001-1022",
					"admin.router.ts:1016",
					"admin.router.ts:1018-1022",
					"admin.router.ts:1024-1032",
					"admin.router.ts:1025",
				},
				Why: "There is no Express error pipeline to port. The reference's answer to a " +
					"refused upload is not its own — it is produced by middleware the host " +
					"registered on the application this router was mounted into, so it differs " +
					"between two deployments of the same library and cannot be reproduced by " +
					"anything this package writes. Handing the refusal back to the caller in " +
					"the envelope every other route on this router uses is the only answer " +
					"that is this router's, and the console reads it without changing: " +
					"`admin.js` shows `e.error || res.statusText` on any non-`ok` response. " +
					"The outer bound has no counterpart at all and is not optional. A port " +
					"that streams a client-supplied body into storage has to bound both the " +
					"part and the request, or an anonymous-to-the-network administrator " +
					"session can make the process buffer arbitrarily much — and the " +
					"deployment this seam exists for is a Lambda with a fixed memory " +
					"allocation, where that is a crash rather than a slowdown. The slack is " +
					"64 KiB because the shipped console sends exactly one part.",
				Notes: []DeviationNote{{
					Label: "What is unchanged",
					Text: "The accepted set, exactly: one part named `file` carrying a " +
						"filename, whose name ends in `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, " +
						"`.webp` or `.ico`, compared case-insensitively against the name and " +
						"nothing else — no magic-byte sniffing on either side. A file of " +
						"exactly five megabytes is accepted on both. `svg` is on that list " +
						"here because it is on that list there: an uploaded SVG may carry " +
						"script and is served back from the auth origin, so a deployment that " +
						"would rather not take that trade serves the upload prefix from a " +
						"separate origin or behind a `Content-Security-Policy`.",
				}},
			},
			{
				ID:    "admin-upload-base-url-is-derived-from-the-mount",
				Title: "An upload answers with a usable URL where the reference answers with a bare filename",
				Surface: "the `url` member of `POST <admin>/api/upload/logo` and `…/bg-image`, and " +
					"`uploadBaseUrl` in the console's injected configuration",
				Behaviour: "Resolves `AdminOptions.UploadBaseURL` when it is set, and otherwise — with " +
					"an `auth.UploadStore` configured — derives " +
					"`<AuthAPIPrefix>/ui/assets/uploads`, where `AuthAPIPrefix` falls back to " +
					"the `HTTPConfig.Prefix()` the adapter was mounted with. So a deployment " +
					"that configures neither still answers " +
					"`{\"url\": \"/auth/ui/assets/uploads/<filename>\"}`, and that URL is " +
					"served by this same deployment: `UIHandler` reads the configured " +
					"`UploadStore` back through `UploadFS` at exactly that path. With no " +
					"store there is nothing to derive and the `url` is the bare filename, as " +
					"there.",
				Reference: "`effectiveUploadBaseUrl = options.uploadBaseUrl || ''`, then derives " +
					"`${apiPrefix}/ui/assets/uploads` only when `options.apiPrefix` was " +
					"*passed* and an `uploadDir` is configured. `apiPrefix` is an option of " +
					"the separate admin router and is documented `@default '/auth'`, but the " +
					"code tests it for truthiness rather than defaulting it — so a host that " +
					"omits it gets an empty base, and both upload routes answer " +
					"`url === filename`, a value the browser cannot resolve.",
				Citations: []string{
					"admin.router.ts:136-157",
					"admin.router.ts:638-643",
					"admin.router.ts:1028-1031",
					"admin.router.ts:718",
					"ui.router.ts:185-191",
				},
				Why: "The reference's admin router is a separate Express router that cannot " +
					"know where the auth router was mounted, which is why `apiPrefix` is an " +
					"option at all; here the two are configured from one `HTTPConfig` and the " +
					"mount is known. Resolving it is the identical treatment `authApiPrefix` " +
					"already gets in the injected console configuration, one field further " +
					"along, and it makes the option's own documented default true instead of " +
					"aspirational. The alternative is a deployment whose administrator " +
					"uploads a logo, is handed a string the branding form then stores as a " +
					"`logoUrl`, and serves a broken image — which is the reference's " +
					"out-of-the-box behaviour and is not worth reproducing faithfully. " +
					"A client that parses `url` sees a resolvable path where it would have " +
					"seen a filename; `filename` is sent beside it and is unchanged, and the " +
					"shipped console reads `data.url || data.filename`, so both answers work " +
					"there.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Not available from configuration, and deliberately: every value " +
						"`AdminOptions.UploadBaseURL` can take is a base, so there is no way " +
						"to ask for \"no base\". A host that needs the bare filename reads " +
						"`filename`, which both routes always send.",
				}},
			},
			{
				ID:    "admin-promote-route-comes-from-the-development-line",
				Title: "The console mounts a promote route the published reference does not have",
				Surface: "`POST <admin>/users/{id}/promote`, and `AdminOptions.RateLimiter`, " +
					"the slot that covers it",
				Behaviour: "Mounts a fifty-first admin route. `POST <admin>/users/{id}/promote` takes " +
					"`{method?: 'flag' | 'role'}`, defaulting to `'role'`: `'flag'` writes " +
					"`User.IsAdmin` through the `auth.UserAdminFlagStore` seam and answers " +
					"`501 {\"error\": \"IUserStore.update is required for method=flag\"}` " +
					"without one; `'role'` creates an `admin` role and assigns it, and " +
					"answers `404 {\"error\": \"RBAC store not configured\"}` without an RBAC " +
					"store. Both publish `identity.role.assigned` with " +
					"`data: {role: \"admin\", method}` and answer " +
					"`{\"success\": true, \"method\": <as sent>}`. " +
					"**Note the path**: it is not under `/api`, unlike the other fifty. " +
					"`AdminOptions.RateLimiter` is a second limiter slot, separate from " +
					"`HTTPConfig.RateLimiter`, and it wraps this route and no other — ahead " +
					"of the guard, so a caller over the limit is refused before any " +
					"credential is read.",
				Reference: "Neither exists. At this revision the admin router registers **fifty** " +
					"routes and no promote route is among them: the gap sits between " +
					"`DELETE /api/users/:id/roles/:role` and `GET /api/users/:id/tenants`. " +
					"`AdminOptions` declares no `rateLimiter` either, so nothing on the " +
					"published admin surface can be rate limited through configuration at " +
					"all. A caller that posts to `<admin>/users/<id>/promote` there receives " +
					"the router's `404`.",
				Citations: []string{"admin.router.ts:44-186", "admin.router.ts:917-933"},
				Why: "Both are ported from nik2208/node-auth, the private development line the " +
					"published package is cut from — `node-auth admin.router.ts:1030-1063` " +
					"for the route and `:205-211` for the option — which is the same bet, " +
					"made for the same reason, as the twenty-six publication points of " +
					"`identity-events-are-raised-from-the-development-line`. The promote " +
					"route is where the dev line's own `AuthConfigurator.promoteToAdmin` " +
					"reaches the wire, it is how a deployment bootstraps its first " +
					"administrator without a second tool, and leaving it out would mean a " +
					"host that migrates from the family's next release finding its " +
					"bootstrap gone. It is also the last route of the admin surface: with it " +
					"the mounted set is exactly the dev line's fifty-one, which is an " +
					"assertion a conformance suite can make and " +
					"`adapter/internal/wiretest/admin_promote.go` does.",
				Notes: []DeviationNote{
					{
						Label: "Which tree a citation means",
						Text: "The citations on this entry are the published reference, as every " +
							"entry in this register is, and they locate the *absence*: the " +
							"option set that has no `rateLimiter` and the two routes the " +
							"missing one sits between. The route itself is cited throughout " +
							"the source as `node-auth admin.router.ts:<line>`, which resolves " +
							"against `DevLineRevision`. A reviewer who greps the published " +
							"tree for `promote` finds nothing, and that is the expected " +
							"result rather than a missing port.",
					},
					{
						Label: "The path really has no `/api`",
						Text: "Fifty of the fifty-one routes on this surface are under " +
							"`<admin>/api`; this one is registered as `/users/:id/promote`, " +
							"between two `/api/users` routes. It reads like a slip in the " +
							"source and it is reproduced as written, because the dev line's " +
							"clients will be built against it — `POST " +
							"<admin>/api/users/{id}/promote` is mounted nowhere and answers " +
							"`404` here exactly as it would there.",
					},
					{
						Label: "The two methods are not interchangeable",
						Text: "`method=flag` sets the flag the `'is-admin-flag'` access policy " +
							"reads and assigns no role; `method=role` assigns the `admin` role " +
							"and sets no flag. A deployment guarding the console with " +
							"`AdminIsAdminFlag()` gains nothing from `method=role`, and one " +
							"guarding it with a predicate over the RBAC store gains nothing " +
							"from `method=flag`. Choosing the wrong one is a promotion that " +
							"silently grants no access, on both lines.",
					},
					{
						Label: "What the limiter does not cover",
						Text: "`AdminOptions.RateLimiter` is spread onto this one route in the " +
							"development line and onto nothing else — in particular **not** " +
							"onto `POST <admin>/login`, which is unlimited on both lines " +
							"whatever a host configures. A deployment that wants the console's " +
							"login limited wraps the handler its adapter mounts.",
					},
				},
			},
			{
				ID:      "inbound-webhook-script-runs-out-of-process",
				Title:   "Inbound webhook scripts run through a seam, not an in-process JavaScript sandbox",
				Surface: "`POST <tools>/webhook/{provider}` where the stored `WebhookConfig` carries a `jsScript`",
				Behaviour: "No JavaScript is executed in this process, ever. The route resolves the " +
					"action allowlist — the intersection of `AuthSettings.EnabledWebhookActions` " +
					"with `WebhookConfig.AllowedActions` — and hands the script, the raw request " +
					"body and that resolved list to `ToolsOptions.ScriptRunner`, an " +
					"`InboundScriptRunner` the host implements out of process. What comes back is " +
					"the reference's own `result`, or nothing. " +
					"Three client-visible consequences. **With no runner configured, a webhook " +
					"whose configuration carries a `jsScript` is refused**: " +
					"`400 {\"error\": \"Webhook processing failed\"}`, nothing tracked, and no " +
					"fall-through to `onWebhook` — so the provider's own redelivery is preserved " +
					"instead of the event being acknowledged and lost. A runner that *fails* — " +
					"unreachable, throttled, past its deadline — is refused the same way. A " +
					"script that **throws** is not: a runner reports that as \"no result\", and " +
					"the route acknowledges it and falls through to `onWebhook`, which is what " +
					"the reference does. " +
					"**The five-second timeout bounds the whole run**, not a prefix of it. " +
					"**The body is read under a limit** — `ToolsOptions.WebhookMaxBytes`, 100 KiB " +
					"by default — and must be a JSON object or array, which is what " +
					"`express.json()` enforces one layer up there.",
				Reference: "Executes the script in a `node:vm` sandbox inside the API process. It " +
					"builds the actions object from the same intersection via " +
					"`ActionRegistry.buildContext`, wraps the script in an async IIFE, creates a " +
					"context holding `body`, `actions`, `result` and a `console`, and runs it " +
					"with `{ timeout: 5_000 }`. A script that throws — synchronously or in its " +
					"promise — is logged with `console.error` and treated as no result. The " +
					"timeout applies to *synchronous* execution only: an async IIFE returns at " +
					"its first `await`, and the route then awaits the rest with no deadline at " +
					"all, so a script awaiting a hanging action holds the request open for as " +
					"long as the socket lives. The body is whatever the host's parser left on " +
					"`req.body`.",
				Citations: []string{
					"tools.router.ts:250-326",
					"tools.router.ts:259-292",
					"tools.router.ts:293-306",
					"tools.router.ts:308-322",
					"webhook-action.ts:104-115",
					"webhook-store.interface.ts:35-72",
				},
				Why: "The dependency rule for this package is the standard library plus " +
					"`golang.org/x/crypto`, and a JavaScript engine is not going to be the " +
					"exception. Every option is either `cgo` around a C++ VM or a large pure-Go " +
					"interpreter, and both put script an administrator typed into an admin form " +
					"into the same address space as the signing keys, the session store and the " +
					"password hashes — with a sandbox written by somebody else as the only " +
					"boundary. `node`'s own `vm` documentation says that module is not a " +
					"security mechanism, which is the reference's position on its own sandbox. " +
					"So the sandbox moves to where a real one exists: another process, whose own " +
					"credentials bound what a script can reach. That is also what makes the " +
					"actions declarative rather than a call back into this process. There is " +
					"nothing here to call back into — this package has no action registry, and " +
					"`GET <admin>/api/actions` answers an empty list and says why — and a round " +
					"trip would put the effects back inside the process whose privileges the " +
					"seam exists to escape. None of the reference's script semantics are lost by " +
					"it: there the script and its actions share one address space, and here they " +
					"still do, the runner's. What stays in the core is the half that cannot be " +
					"delegated, which is the administrator's policy: the two lists are " +
					"intersected here, from this package's own settings store, and cross as a " +
					"closed list of ids a runner may narrow and must never widen. " +
					"The refusal when no runner is configured is the same judgement in the " +
					"small. A script is how a deployment reacts to an event it does not " +
					"otherwise see — the cancellation that deprovisions a tenant, the payment " +
					"failure that suspends an account. Acknowledging a webhook whose script " +
					"never ran tells the provider the event was handled, and a provider that has " +
					"been told that does not send it again: the event is gone, silently and " +
					"permanently, and nothing will correct the deployment's own state. A refusal " +
					"costs redeliveries and a red line in someone's provider dashboard, and it " +
					"is recoverable — configure the runner and the backlog arrives.",
				Notes: []DeviationNote{
					{
						Label: "What crosses the seam, and what cannot",
						Text: "`InboundScriptRequest` carries the provider, the webhook id, the " +
							"script, the raw body and the resolved action ids — and has a field " +
							"for nothing else. Not the webhook's `secret`, not the settings " +
							"store, not the request headers, not a callable of any kind. Every " +
							"member is plain data, because the intended implementation encodes " +
							"this struct and sends it elsewhere. The consequence worth stating: " +
							"a runner cannot verify the provider's signature and is not meant " +
							"to. That belongs in `ToolsOptions.OnWebhook`, in this process, " +
							"where the secret is and before the body has gone anywhere.",
					},
					{
						Label: "What an implementation has to get right",
						Text: "One thing above all: report a script's own exception as *no " +
							"result*, and an invocation failure as an *error*. Reporting an " +
							"exception as an error turns every broken script into an endless " +
							"redelivery loop; reporting an invocation failure as no result " +
							"silently drops webhooks the provider believes were delivered and " +
							"will never send again. The second: treat the action list as " +
							"closed — drop an id that is not implemented or whose dependencies " +
							"are unmet, and never expose one the core did not send.",
					},
					{
						Label: "What is unchanged",
						Text: "The route, the statuses and the bodies. `200 {\"ok\": true}` on " +
							"acceptance, `400 {\"error\": \"Webhook processing failed\"}` on " +
							"failure, no guard in front of it, `onWebhook` as the fallback when " +
							"no script declared anything, and " +
							"`InboundWebhookStore.FindByProvider` still not filtering on " +
							"`IsActive` — so a deactivated webhook's inbound script still runs, " +
							"which is the reference's own trap, reproduced rather than " +
							"corrected.",
					},
				},
			},
		},
	}
}
