# awesome-go-auth — Detailed API Reference

Complete reference for every public type, interface, function, and option in the library.

---

## Table of Contents

1. [Core Service](#core-service)
2. [Configuration](#configuration)
3. [Runtime settings](#runtime-settings)
4. [Models](#models)
5. [Store Interfaces](#store-interfaces)
6. [In-Memory Stores](#in-memory-stores)
7. [Auth Functional Options](#auth-functional-options)
8. [Custom Claims](#custom-claims)
9. [OAuth 2.0 + Account Linking](#oauth-20--account-linking)
10. [SSE (Server-Sent Events)](#sse-server-sent-events)
11. [Outgoing webhooks](#outgoing-webhooks)
12. [Telemetry](#telemetry)
13. [Mailer](#mailer)
14. [Delivery](#delivery)
15. [OIDC IDP](#oidc-idp)
16. [Resource server mode](#resource-server-mode)
17. [MCP Server (out of parity scope)](#mcp-server-out-of-parity-scope)
18. [OpenAPI](#openapi)
19. [Embedded UI](#embedded-ui)
20. [API Keys](#api-keys)
21. [Event Bus](#event-bus)
22. [HTTP Adapters](#http-adapters)
23. [Security Helpers](#security-helpers)
24. [Errors](#errors)

---

## Core Service

### `New(opts ...Option) (*Auth, error)`

Creates a fully configured `Auth` instance using functional options. Falls back to in-memory stores if none are provided.

```go
a, err := auth.New(
    auth.WithSecret("32-byte-secret"),
    auth.WithIssuer("https://api.example.com"),
    auth.WithTokenTTLs(15*time.Minute, 7*24*time.Hour),
)
```

### `NewWithConfig(cfg Config, opts ...Option) (*Auth, error)`

Same as `New`, but starting from a `Config` you populate yourself; any options are
applied on top. Use it to reach `Config` fields that have no `With*` option — the
individual TTLs, `EmailVerificationMode`, `BcryptCost`. `cfg` is validated exactly
as `New`'s is, so a partially filled struct is rejected rather than silently
defaulted.

```go
cfg := auth.DefaultConfig("32-byte-secret")
cfg.BcryptCost = 12
cfg.EmailVerificationMode = auth.EmailVerificationModeStrict
a, err := auth.NewWithConfig(cfg, auth.WithUserStore(myStore))
```

### `(*Auth).Service() *Service`

Returns the underlying `*Service` for direct method calls.

### `NewService(cfg Config, users UserStore, sessions SessionStore, opts ...ServiceOption) (*Service, error)`

Low-level constructor. Use `New()` for most cases.

### Service Methods

| Method | Description |
|--------|-------------|
| `Register(ctx, RegisterInput) (User, AuthTokens, error)` | Create a user and return tokens — see [Registration input](#registration-input) |
| `Login(ctx, LoginInput) (User, AuthTokens, error)` | Authenticate and return tokens |
| `Refresh(ctx, refreshToken) (AuthTokens, error)` | Rotate refresh token |
| `Logout(ctx, refreshToken) error` | Revoke session |
| `Authenticate(ctx, accessToken) (User, error)` | Verify an access token and load its user with the stores' enrichment; never runs `BuildTokenClaims` — see [Custom Claims](#custom-claims) |
| `Me(ctx, accessToken) (User, error)` | `Authenticate` plus `CustomClaims` from `BuildTokenClaims`: the `/me` profile |
| `UpdateProfile(ctx, UpdateProfileInput) (User, error)` | Update first/last name |
| `DeleteAccount(ctx, DeleteAccountInput) error` | Delete current account |
| `ForgotPassword(ctx, ForgotPasswordInput) (string, error)` | Generate reset token |
| `ResetPassword(ctx, ResetPasswordInput) error` | Consume reset token |
| `ChangePassword(ctx, ChangePasswordInput) error` | Change password for authenticated user |
| `SendMagicLink(ctx, MagicLinkSendInput) (string, error)` | Generate, store and deliver a magic link — see [Delivery](#delivery) |
| `VerifyMagicLink(ctx, MagicLinkVerifyInput) (User, AuthTokens, error)` | Consume magic link |
| `SendSMSCode(ctx, SMSCodeSendInput) (string, error)` | Generate, store and deliver a 6-digit SMS code — see [Delivery](#delivery) |
| `VerifySMSCode(ctx, SMSCodeVerifyInput) (User, AuthTokens, error)` | Verify SMS code |
| `SetupTOTP(ctx, userID, tenantID) (string, error)` | Generate TOTP secret |
| `VerifyTOTPSetup(ctx, userID, tenantID, secret, code) error` | Enable TOTP |
| `VerifyTOTP(ctx, userID, tenantID, code) (User, AuthTokens, error)` | TOTP second factor |
| `DisableTOTP(ctx, userID, tenantID) error` | Disable TOTP |
| `SendVerificationEmailToken(ctx, EmailVerificationInput) (string, error)` | Generate email verification token |
| `VerifyEmail(ctx, VerifyEmailInput) error` | Mark email verified |
| `RequestEmailChange(ctx, ChangeEmailRequestInput) (string, error)` | Generate email change token |
| `ConfirmEmailChange(ctx, ConfirmEmailChangeInput) error` | Apply email change |
| `GetMetadata(ctx, userID) (map[string]any, error)` | Get user metadata |
| `UpdateMetadata(ctx, userID, map[string]any) error` | Merge user metadata |
| `CreateRole(ctx, role, permissions) error` | Define a role |
| `AssignRole(ctx, userID, role, tenantID) error` | Assign role to user |
| `UserHasPermission(ctx, userID, permission, tenantID) (bool, error)` | Check permission |
| `CreateTenant(ctx, name, config) (Tenant, error)` | Create tenant |
| `AddUserToTenant(ctx, userID, tenantID) error` | Associate user with tenant |
| `ListSessions(ctx, userID, tenantID) ([]Session, error)` | List active sessions |
| `RevokeSessionByID(ctx, sessionID) error` | Revoke a specific session |
| `CleanupExpiredSessions(ctx) (int, error)` | Delete expired sessions |

### Registration input

`Register` requires an email and a password, and refuses a call missing either
one before it touches a store:

```go
_, _, err := svc.Register(ctx, auth.RegisterInput{Email: "", Password: "s3cret!!"})
// err is auth.ErrInvalidInput
```

On the wire that is
`400 {"error":"Email and password are required","code":"INVALID_INPUT"}` on
`POST /auth/register`, on all four adapters and in both delivery modes — the
refusal happens before the branch that chooses between cookies and body tokens,
so a bearer client sees the same answer as a cookie one.

The message and the code are copied from the private dev line `node-auth`
(unreleased, `DevLineRevision`) and **not** from the published reference
`awesome-node-auth@cc01e997` that `ReferenceRevision` pins. The dev line mounts
`POST /register` by default and its default handler throws
`AuthError('Email and password are required', 'INVALID_INPUT', 400)` before
hashing the password or calling `userStore.create`
(`node-auth auth.router.ts:515-525`). The published reference mounts `/register`
only when the host supplies `options.onRegister` (`auth.router.ts:713`), has no
default handler, and therefore has no `INVALID_INPUT` code anywhere — the string
does not occur in its source. Copying an answer from an unreleased tree is a
deliberate bet that the published one will grow the same answer; it is the only
place this port does so, and `DevLineRevision` in `compatibility.go` says which
citations resolve against which tree.

Two things this replaces. An empty password used to reach the length check and
come back as `WEAK_PASSWORD`, which tells a caller who sent no password at all
to choose a stronger one; a missing address used to reach the store and create a
user with a blank email. A password that is *present* but shorter than
`Config.MinPasswordLen` still answers `WEAK_PASSWORD`, unchanged — the two codes
are what tell a client which of the two happened.

The check runs after the email is normalised (trimmed and lowercased), so an
address that is only whitespace is refused here rather than stored as the empty
string. The dev line tests the untrimmed body value and would accept it; this is
the narrower reading, and it can only refuse a request the dev line would have
turned into an account with no usable address.

Note that a successful `POST /auth/register` also opens a session — cookies, or
body tokens under `X-Auth-Strategy: bearer` — where the published reference
returns `201 {"success":true,"userId":…}` and nothing else. There is no knob to
turn that off in this release, and it is **not** a settled decision: a
registration that authenticates bypasses whatever email verification gate the
deployment configured, so under `strict` the new account holds an access token
that `POST /auth/login` would have refused it. That is tracked as a defect in
[#21](https://github.com/nik2208/awesome-go-auth/issues/21) and recorded
provisionally as `register-issues-a-session` in [README.md](README.md) so the
difference is visible on the wire contract while the issue is open; when #21
lands the behaviour changes and the entry is retired.

---

## Configuration

### `Config`

```go
type Config struct {
    Secret                string                        // HMAC secret (min 32 bytes)
    Issuer                string                        // default: "awesome-go-auth"
    AccessTokenTTL        time.Duration                 // default: 15m
    RefreshTokenTTL       time.Duration                 // default: 30d
    SessionCheckOn        string                        // allcalls|refresh|none (default: refresh)
    ResetTokenTTL         time.Duration                 // default: 1h
    MagicLinkTTL          time.Duration                 // default: 15m
    SMSCodeTTL            time.Duration                 // default: 10m
    EmailVerificationTTL  time.Duration                 // default: 24h
    EmailVerificationMode string                        // none|lazy|strict (default: none)
    EmailChangeTTL        time.Duration                 // default: 1h
    TempTokenTTL          time.Duration                 // default: 5m; the step-up token a 2FA challenge hands the client
    ClockSkew             time.Duration                 // default: 30s
    MinPasswordLen        int                           // default: 8
    BcryptCost            int                           // default: bcrypt.DefaultCost (10); 0 means unset
    Require2FA            bool
    TwoFactorAppName      string                        // TOTP issuer shown by authenticator apps; empty = Issuer — see TwoFactorAppName
    BuildTokenClaims      TokenClaimsBuilder            // see Custom Claims
    PasswordVerifier      PasswordVerifier              // optional; accept another provider's password once and adopt it — see Password verifier
    SendMagicLink         MagicLinkSender               // required by POST /auth/magic-link/send
    SendSMSCode           SMSCodeSender                 // required by POST /auth/sms/send
    SendPasswordReset     PasswordResetSender           // optional; POST /auth/forgot-password
    SendEmailVerification EmailVerificationSender       // optional; POST /auth/send-verification-email
    SendEmailChange       EmailChangeSender             // optional; POST /auth/change-email/request
    SendEmailChanged      EmailChangedSender            // optional; the notice POST /auth/change-email/confirm mails to the old address
    Templates             TemplateStore                 // optional; run-time overrides of the built-in mail templates — see Mailer
    Uploads               UploadStore                   // optional; no default — see UploadStore and MemoryUploadStore
    Settings              SettingsStore                 // optional; the admin-flipped runtime settings — see Runtime settings
    Events                *EventBus                     // optional; WithEventBus sets it — see Event Bus
    SiteURLs              []string                      // first = canonical link base; all = origin allowlist — see Delivery
    Logger                func(format string, args ...any)
}
```

### `EmailVerificationMode`

| mode | `Register` | `Login` with an unverified address |
|---|---|---|
| `none` (default) | marks the address verified | refused (`ErrEmailNotVerified`) |
| `lazy` | leaves the address unverified | allowed |
| `strict` | leaves the address unverified | refused (`ErrEmailNotVerified`) |

Under `none` the gate is unobservable through `Register`, because a self-registered
user is already verified. It still applies to users that reach the store another way
(admin provisioning, a data import, a custom `UserStore` whose column defaults to
`false`). `lazy` is the only mode that lets an unverified address log in.

Two limitations apply to `strict`:

- `Register` still returns a usable `AuthTokens` pair, so the mode gates `Login`
  rather than access as a whole ([#21](https://github.com/nik2208/awesome-go-auth/issues/21)).
- `POST /send-verification-email` mints and persists the token and answers
  `{"success": true}`; it mails it only when `Config.SendEmailVerification` is
  wired (`WithEmailVerificationSender`, or
  `NewEmailVerificationMailer(...).Send` for the built-in template). With no
  sender the route still succeeds and sends nothing, which is what a reference
  deployment with no email block does, so a `strict` deployment either wires a
  sender or sends the mail itself from the token `SendVerificationEmailToken`
  returns.

### `TwoFactorAppName` and the TOTP parameters

`TwoFactorAppName` is the reference's `twoFactor.appName`: the issuer an
authenticator app files a TOTP enrolment under. `POST /2fa/setup` returns

```
otpauth://totp/<issuer>:<email>?algorithm=SHA1&digits=6&issuer=<issuer>&period=30&secret=<secret>
```

where `<issuer>` is `TwoFactorAppName`, or `Issuer` when that is empty. The
label takes otplib's `issuer:account` form, which is what the reference emits,
and every piece is escaped as `encodeURIComponent` escapes it (`@` is `%40`, a
space is `%20`). The reference falls back to the literal `'awesome-node-auth'`
instead of `Issuer`; this port keeps `Issuer` so that enrolments made before the
field existed and enrolments made after it sit under one name — registered as
the deviation `totp-issuer-defaults-to-config-issuer` in [README.md](README.md).
`WithTwoFactorAppName("awesome-node-auth")` reproduces the reference's label.

The TOTP parameters are not knobs, in the reference or here. They are exported
as constants, read by both the URI above and the verifier behind
`/2fa/verify-setup` and `/2fa/verify`, so the two cannot drift:

| Constant | Value | |
|---|---|---|
| `TOTPAlgorithm` | `"SHA1"` | otplib's default |
| `TOTPDigits` | `6` | otplib's default |
| `TOTPPeriod` | `30 * time.Second` | otplib's default |
| `TOTPSkew` | `1` | steps either side of now a code is accepted for; this port's tolerance — otplib's `epochTolerance` defaults to `0`, registered as the deviation `totp-accepts-one-step-of-skew` in [README.md](README.md) |

### Password verifier (migration seam)

`Config.PasswordVerifier`, set with `WithPasswordVerifier`, lets a deployment
moving off another identity provider accept that provider's password on the
first login, adopt it as a local bcrypt hash and stop calling the old system.

**This is an additive port extension, not parity.** The reference has no such
hook: its login path verifies the stored bcrypt hash directly
(`local.strategy.ts:19-29` calling `password.service.ts:8-10`, and
`POST /login` is that one call plus the 2FA decision,
`auth.router.ts:541-544`), and nothing in its `AuthConfig` names a verifier, a
legacy hash or a migration. Left unset — the default — the verifier is never
called and `POST /auth/login` answers exactly as the reference does.

It is nonetheless **not** in the deviation register, and the reason is not that
its default matches the reference. That alone is not the register's test:
`oauth-provisioning-is-a-policy-not-a-function` is registered even though a
deployment that configures nothing cannot see any of its three codes — it is
registered because configuring it puts three codes on the wire that the route
could not produce before. This seam puts none. With a verifier configured,
`POST /auth/login` still answers only what it already answered: the ordinary
`200` token body, the `401 INVALID_CREDENTIALS` a wrong local password already
produced, or the generic `500`. No new status, no new code, no new body field,
on this route or any other.

```go
type PasswordVerifier func(ctx context.Context, user User, password string) (ok bool, migrated bool, err error)
```

```go
a, err := auth.New(
    auth.WithPasswordVerifier(func(ctx context.Context, u auth.User, pw string) (bool, bool, error) {
        if u.Metadata["legacyIdP"] != "acme" {
            return false, false, nil // not a migrated account: ordinary 401
        }
        ok, err := acme.CheckPassword(ctx, u.Email, pw)
        return ok, ok, err // adopt the password iff the old system accepted it
    }),
)
```

When it runs, and what each answer means:

| | |
|---|---|
| **When** | Only after the stored hash failed to verify the supplied password. A user whose local hash verifies never reaches the hook, so a finished migration costs nothing per login. A login for an address the store does not hold does not reach it either: the hook takes a `User`, and provisioning an unknown account is a different job. **Everything else does reach it**, which is wider than the imported row the seam was built for: an empty stored hash is a non-match, so *every* account that never had a password — OAuth-only, magic-link-only — has its failed logins handed to the verifier, carrying whatever plaintext the request held. The reference refuses those before it compares anything (`local.strategy.ts:23-25`); this port has no equivalent guard, so a verifier **must** key on its own migration marker and return `(false, false, nil)` before doing anything with the password it is given. |
| `ok=false` | Not the password. `ErrInvalidCredentials` — the same value, and so the same `401 {"error":"Invalid credentials","code":"INVALID_CREDENTIALS"}`, an ordinary wrong password produces. |
| `ok=true, migrated=true` | The password, and adopt it: hashed at `Config.BcryptCost` and written through `UserPasswordStore.UpdatePassword`, the path `ResetPassword` and `ChangePassword` already use, before anything is issued. **The write overwrites whatever hash was stored, not only an absent one** — the hook is reached for any hash that failed to verify, so a verifier that is not gated on a migration marker can answer `ok` for a live account and replace its working local password with the password the request carried. The adopted password deliberately bypasses `Config.MinPasswordLen`: it is an inherited credential rather than one being chosen, and `Register`, `ResetPassword` and `ChangePassword` still enforce the length where a password *is* chosen. The one value never written is the empty string — a bcrypt hash of `""` would make empty-password login succeed forever and would permanently close the passwordless initial-password path that keys on an empty `PasswordHash` — so an empty password behaves as `migrated=false`. |
| `ok=true, migrated=false` | The password, keep nothing. The login proceeds, the stored hash is untouched, and the next login asks again. For a host that means to keep owning the credential. |
| `err != nil` | A failure to *decide*, not a rejection. The login fails closed with the generic `500 {"error":"Internal server error"}` and `ok` is ignored. |

Two properties the tests pin:

- **No new failure a client can see.** Every failure in the seam — the hook
  erroring, the hash not being computable, the store refusing the write or not
  being a `UserPasswordStore` at all — comes back as an opaque error that maps
  through `HTTPErrorFor`'s default to the generic `500`. In particular it is
  *not* wrapped with `%w`, so a store returning `ErrFeatureNotSupported` cannot
  turn one branch into a distinguishable `501 NOT_IMPLEMENTED`. The exception is
  `ctx`: `context.Canceled` and `context.DeadlineExceeded` *are* wrapped with
  `%w`, because `HTTPErrorFor` maps neither — both fall to the same generic
  `500` — so keeping them leaks nothing and lets a caller tell a client that
  hung up from a legacy provider that is down. Since the wire answer names no
  branch, every failure is also passed to `Config.Logger` (user id, never the
  password), which is the only place an operator can read what happened.
- **The write is part of accepting the credential**, so it lands before the
  email-verification gate. An account then refused for an unverified address has
  still stopped depending on the old system; migrating only on a login that
  completes would keep such an account calling it forever.

And one statement of posture that **no test asserts**: timing. The seam adds no
equalisation and removes none — the login path did not equalise before it (an
address the store does not hold returns before any bcrypt work, a known one pays
one bcrypt compare) and does not equalise now. But a configured verifier widens
that pre-existing gap by its own latency: a known address whose hash does not
verify now costs the bcrypt compare *plus* whatever the verifier does, which in
the case this seam exists for is a call to the old provider. A signal that was
milliseconds of key derivation becomes a network round trip. Equalising what is
left is the verifier's job, not this library's.

Two requirements on a verifier, then. The example above shows the first; the
second is the host's to add around whatever call it makes:

- **Gate on a locally-readable marker and return before any network call.** The
  hook sits on an unauthenticated route and is reached for every account whose
  stored hash does not verify, so a verifier that calls the old provider for any
  address it is handed turns `POST /auth/login` into an amplifier aimed at that
  provider — and at its lockout counters — for every address an attacker names.
- **Bound and rate-limit whatever call survives the marker.** The hook runs on
  the request goroutine, so a verifier that talks to the network must honour
  `ctx`, cap its own time, and cap how often it goes out.

### `DefaultConfig(secret string) Config`

Returns a `Config` with sensible defaults.

### `(Config).validate() error`

Called internally; ensures secret length >= 32 and TTLs > 0.

---

## Runtime settings

`Config` is what a deployment decides at start-up. `SettingsStore` is the other
half: the handful of global switches an administrator flips at run time through
the reference's admin Control panel, the reference's `ISettingsStore`
(`src/interfaces/settings-store.interface.ts:28-40`, wired as
`routerOptions.settingsStore`, `src/router/auth.router.ts:92`).

```go
type SettingsStore interface {
    GetSettings(ctx context.Context) (AuthSettings, error)                       // zero value = nothing configured
    UpdateSettings(ctx context.Context, patch AuthSettings) (AuthSettings, error) // shallow merge; returns what is stored
}

type AuthSettings struct {
    RequireEmailVerification             *bool       `json:"requireEmailVerification,omitempty"`
    EmailVerificationMode                *string     `json:"emailVerificationMode,omitempty"`               // none|lazy|strict
    LazyEmailVerificationGracePeriodDays *int        `json:"lazyEmailVerificationGracePeriodDays,omitempty"` // 7 when unset
    Require2FA                           *bool       `json:"require2FA,omitempty"`
    EnabledWebhookActions                []string    `json:"enabledWebhookActions,omitempty"`
    UI                                   *UISettings `json:"ui,omitempty"`
}

type UISettings struct {
    PrimaryColor   *string `json:"primaryColor,omitempty"`
    SecondaryColor *string `json:"secondaryColor,omitempty"`
    LogoURL        *string `json:"logoUrl,omitempty"`
    SiteName       *string `json:"siteName,omitempty"`
    LogoPath       *string `json:"logoPath,omitempty"`
    BgColor        *string `json:"bgColor,omitempty"`
    BgImage        *string `json:"bgImage,omitempty"`
    CardBg         *string `json:"cardBg,omitempty"`
}
```

`MemorySettingsStore` (`NewMemorySettingsStore()`) is the in-memory
implementation: safe for concurrent use, copies in and out.
`WithSettingsStore(store)` wires it (`Config.Settings`); without one nothing
changes, exactly as in the reference, which skips the settings check altogether
when no store is configured (`auth.router.ts:890`).

### What is consulted

One setting, on one route. `Require2FA` is read by `(*Auth).TwoFactorPolicy(ctx)`
and `POST /auth/2fa/disable` refuses on it with
`403 {"error":"Cannot disable 2FA: required by system policy","code":"2FA_REQUIRED"}`
— the reference's answer, from the same check
(`auth.router.ts:890-896`). The route checks the per-user `User.Require2FA` flag
first and answers `403 ... "required for your account"` for that one
(`:884-888`), as the reference does.

```go
store := auth.NewMemorySettingsStore()
required := true
_, _ = store.UpdateSettings(ctx, auth.AuthSettings{Require2FA: &required})
a, err := auth.New(auth.WithSettingsStore(store))
```

`TwoFactorPolicy` is `Config.Require2FA || settings.require2FA`. The static term
is this port's own — the reference has no config-level `require2FA` anywhere,
which is a wire difference, registered as the deviation
`config-require2fa-is-a-system-policy-term` in [README.md](README.md) — and it is
checked first, so a deployment that already requires the factor never
pays for a store read. A store that cannot answer is an error, and the route
answers `500 {"error":"Internal server error"}` with no `code`: failing closed,
and the same status the reference produces when its `getSettings` throws
(`handleError`, `auth.router.ts:899-901` and `:189-195`). The error is logged
through `Config.Logger` before that body goes out, since the body carries none of
it — as the reference logs it in `handleError` (`:193`).

### What is deliberately not consulted

`RequireEmailVerification`, `EmailVerificationMode` and
`LazyEmailVerificationGracePeriodDays` are stored, returned and never read by
login. That is the reference's behaviour, not a gap here: no route that decides a
login reads the store there either — its local strategy reads the static
`config.emailVerificationMode` (`src/strategies/local/local.strategy.ts:32-35`).
The admin UI writes the keys and displays them back; nothing enforces them. It is
catalogued upstream as reference-issues N36, and reproducing it is the point — a
port that quietly enforced these would refuse logins the reference allows, and
the family's clients are pinned to the reference. Use
`Config.EmailVerificationMode` for the knob that does decide a login; see
[`EmailVerificationMode`](#emailverificationmode).

There is no deviation entry for any of this, because there is no wire
difference: every route this port serves answers what the reference answers for
the same stored settings.

`EnabledWebhookActions` and `UI` are stored for surfaces that have not landed yet
and are read by neither today. Both have a reader in the reference, and both sit
outside the login path:

- `GET <prefix>/ui/config` reads the `ui` block for branding
  (`src/router/ui.router.ts:99` and `:126-133`), mounted by `createAuthRouter`
  itself when `config.ui.enabled` (`auth.router.ts:1639-1648`).
- The tools router reads `enabledWebhookActions` as the global allowlist for the
  inbound-webhook sandbox (`src/router/tools.router.ts:261-262`) — and swallows a
  store failure (`.catch(() => ({}))`), i.e. it fails **open**, where this port
  fails closed on `/2fa/disable`. Worth knowing before that router is ported.

### The merge rule

`UpdateSettings` applies the patch as the reference's shallow spread,
`merged = {...current, ...settings}` — the JSDoc example at
`settings-store.interface.ts:20-24` and the interface comment at `:36-38`,
"Settings not present in the input are left untouched". A `nil` field keeps what
is stored; a set field replaces it. `MergeSettings(current, patch)` is that rule,
exported so a database-backed store applies the same one.

The reference's `src/` ships no `ISettingsStore` implementation to compare
against — `src/stores/` holds only `memory-template.store.ts`. The
implementations live beside it and all spread the same way; the closest to this
one is `examples/in-memory-user-store.ts:266-268`,
`this.settings = { ...this.settings, ...updates }`.

Shallow is the operative word, and it bites on `UI`: that is one key of the
spread, so a patch carrying a `UI` replaces the stored block **whole** — the
fields it does not name are dropped, not preserved. The reference depends on
this: its admin `PATCH /admin/api/settings/ui` reads the current settings, merges
the `ui` sub-object itself and writes the merged block back
(`admin.router.ts:979-981`), which it would have no reason to do if the store
merged it. To change one colour, read, merge, write. `EnabledWebhookActions`
follows the same rule as a whole value — `nil` keeps, and a non-`nil` slice
replaces, an empty one included, which is how every action is switched off.

That last distinction has to survive an encoder, and `omitempty` on a `[]string`
would not carry it: it drops the empty slice as well as the `nil` one, so a store
that persists `AuthSettings` as JSON would write the cleared list as an absent
key, read it back as `nil`, and the next merge would put the old list back.
`AuthSettings.MarshalJSON` encodes that one field through a pointer instead, so
`nil` stays absent and a cleared list is written as `[]` — which is what
`JSON.stringify` emits in the reference. Nothing is needed on the way in:
`encoding/json` already decodes `[]` into a non-`nil` empty slice.

The reference's `updateSettings` returns `void` and leaves the caller to read
the result back; this one returns what is stored afterwards, as `TemplateStore`
does.

---

## Models

### `User`

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Unique user ID (format: `usr_<hex>`) |
| `Email` | `string` | Normalized (lowercase, trimmed) email |
| `PasswordHash` | `string` | bcrypt hash |
| `TenantID` | `string` | Owning tenant |
| `PhoneNumber` | `string` | For SMS OTP |
| `FirstName`, `LastName` | `string` | Display name |
| `Role` | `string` | Single role (legacy; prefer Roles slice) |
| `LoginProvider` | `string` | Provider that created the account (set by `OAuthService.HandleCallback`); empty reads as `"local"` on tokens and `/me` |
| `IsEmailVerified` | `bool` | |
| `Require2FA` | `bool` | Per-user 2FA requirement |
| `IsTOTPEnabled` | `bool` | |
| `TOTPSecret` | `string` | Base32 encoded |
| `Metadata` | `map[string]any` | Enriched by MetadataStore |
| `Roles` | `[]string` | Enriched by RBACStore |
| `Permissions` | `[]string` | Enriched by RBACStore |
| `Tenants` | `[]Tenant` | Enriched by TenantStore |
| `CustomClaims` | `map[string]any` | From the BuildTokenClaims hook; filled by `Me`, nil from `Authenticate` |
| `CreatedAt`, `UpdatedAt` | `time.Time` | |

### `Session`

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Session ID (format: `ses_<hex>`) |
| `UserID`, `TenantID` | `string` | |
| `RefreshTokenHash` | `string` | SHA-256 of refresh token |
| `ExpiresAt` | `time.Time` | |
| `RevokedAt` | `*time.Time` | Non-nil = revoked |

### `AuthTokens`

```go
type AuthTokens struct {
    AccessToken  string
    RefreshToken string
    ExpiresIn    time.Duration // access token TTL
}
```

### `Tenant`

```go
type Tenant struct {
    ID, Name  string
    IsActive  bool
    Config    map[string]any
    CreatedAt time.Time
}
```

---

## Store Interfaces

All interfaces are defined in `store.go`. Implement any or all of them against your database.

### `UserStore` (required)

```go
type UserStore interface {
    CreateUser(ctx context.Context, user User) (User, error)
    GetUserByEmail(ctx context.Context, email, tenantID string) (User, error)
    GetUserByID(ctx context.Context, id, tenantID string) (User, error)
}
```

### `SessionStore` (required)

```go
type SessionStore interface {
    CreateSession(ctx context.Context, session Session) (Session, error)
    GetSessionByRefreshTokenHash(ctx context.Context, hash string) (Session, error)
    UpdateSession(ctx context.Context, session Session) error
}
```

### Optional feature stores (type-assert at runtime)

| Interface | Methods | Used by |
|-----------|---------|---------|
| `UserPasswordStore` | `UpdatePassword`, `UpdateResetToken`, `GetUserByResetTokenHash`, `ClearResetToken` | ForgotPassword, ResetPassword, ChangePassword |
| `MagicLinkStore` | `UpdateMagicLinkToken`, `GetUserByMagicLinkTokenHash`, `ClearMagicLinkToken` | SendMagicLink, VerifyMagicLink |
| `SMSStore` | `UpdateSMSCode`, `GetUserBySMSCodeHash`, `ClearSMSCode` | SendSMSCode, VerifySMSCode |
| `TOTPStore` | `UpdateTOTPSecret` | VerifyTOTPSetup, DisableTOTP |
| `EmailVerificationStore` | `UpdateEmailVerificationToken`, `GetUserByEmailVerificationTokenHash`, `MarkEmailVerified`, `ClearEmailVerificationToken` | SendVerificationEmailToken, VerifyEmail |
| `EmailChangeStore` | `UpdateEmailChangeToken`, `GetUserByEmailChangeTokenHash`, `ApplyEmailChange`, `ClearEmailChangeToken` | RequestEmailChange, ConfirmEmailChange |
| `SessionAdminStore` | `ListSessionsForUser`, `RevokeSessionByID`, `DeleteExpiredSessions` | ListSessions, RevokeSessionByID, CleanupExpiredSessions |
| `UserMetadataStore` | `GetMetadata`, `UpdateMetadata`, `ClearMetadata` | GetMetadata, UpdateMetadata |
| `RolesPermissionsStore` | `AddRoleToUser`, `RemoveRoleFromUser`, `GetRolesForUser`, `CreateRole`, `DeleteRole`, `AddPermissionToRole`, `RemovePermissionFromRole`, `GetPermissionsForRole`, `GetPermissionsForUser`, `UserHasPermission` | CreateRole, AssignRole, UserHasPermission |
| `TenantStore` | `CreateTenant`, `GetTenantByID`, `GetAllTenants`, `UpdateTenant`, `DeleteTenant`, `AssociateUserWithTenant`, `DisassociateUserFromTenant`, `GetTenantsForUser`, `GetUsersForTenant` | CreateTenant, AddUserToTenant |
| `UserAccountStore` | `UpdateProfile`, `DeleteUser` | UpdateProfile, DeleteAccount |
| `SessionLookupStore` | `GetSessionByID` | SessionCheckOn=allcalls (`Authenticate`, `Me`) |

---

## In-Memory Stores

All provided in the core package for development, testing, and embedded deployments.

| Type | Implements |
|------|-----------|
| `MemoryUserStore` | UserStore + UserPasswordStore + MagicLinkStore + SMSStore + TOTPStore + EmailVerificationStore + EmailChangeStore |
| `MemorySessionStore` | SessionStore + SessionAdminStore |
| `MemoryMetadataStore` | UserMetadataStore |
| `MemoryRolesPermissionsStore` | RolesPermissionsStore |
| `MemoryTenantStore` | TenantStore |
| `MemoryTelemetryStore` | TelemetryStore |
| `MemoryLinkedAccounts` | LinkedAccountStore |
| `MemoryAPIKeyStore` | APIKeyStore + APIKeyAdminStore + APIKeyServiceIndexStore + APIKeyDeleteStore + APIKeyAuditStore |

---

## Auth Functional Options

Pass to `auth.New(...)`:

| Option | Description |
|--------|-------------|
| `WithSecret(s string)` | JWT signing secret (min 32 bytes) |
| `WithIssuer(s string)` | Token issuer claim |
| `WithTokenTTLs(access, refresh time.Duration)` | Token lifetimes |
| `WithUserStore(UserStore)` | Custom user store |
| `WithSessionStore(SessionStore)` | Custom session store |
| `WithMetadataProvider(UserMetadataStore)` | Enable metadata |
| `WithRBACProvider(RolesPermissionsStore)` | Enable RBAC |
| `WithTenantProvider(TenantStore)` | Enable multi-tenancy |
| `WithBcryptCost(int)` | Password hashing cost, `bcrypt.MinCost`..`bcrypt.MaxCost` |
| `WithRequire2FA(bool)` | Require 2FA for all users |
| `WithTwoFactorAppName(string)` | Issuer of the TOTP provisioning URI, the reference's `twoFactor.appName`; empty keeps `Issuer` — see [TwoFactorAppName](#twofactorappname-and-the-totp-parameters) |
| `WithTokenClaimsBuilder(TokenClaimsBuilder)` | Custom JWT claims — see [Custom Claims](#custom-claims) |
| `WithPasswordVerifier(PasswordVerifier)` | Accept the previous identity provider's password on first login and adopt it locally; a port extension, off unless set — see [Password verifier](#password-verifier-migration-seam) |
| `WithMagicLinkSender(MagicLinkSender)` | Deliver magic links — see [Delivery](#delivery) |
| `WithSMSCodeSender(SMSCodeSender)` | Deliver SMS codes — see [Delivery](#delivery) |
| `WithPasswordResetSender(PasswordResetSender)` | Deliver password-reset tokens — see [Delivery](#delivery) |
| `WithEmailVerificationSender(EmailVerificationSender)` | Deliver email-verification tokens — see [Delivery](#delivery) |
| `WithEmailChangeSender(EmailChangeSender)` | Deliver email-change tokens to the new address — see [Delivery](#delivery) |
| `WithEmailChangedSender(EmailChangedSender)` | Deliver the email-changed notice to the old address — see [The email-changed notice](#the-email-changed-notice) |
| `WithTemplateStore(TemplateStore)` | Run-time overrides of the built-in mail templates — see [`TemplateStore` interface](#templatestore-interface) |
| `WithSettingsStore(SettingsStore)` | Global settings an administrator flips at run time; only `require2FA` is acted on — see [Runtime settings](#runtime-settings) |
| `WithSiteURLs(urls ...string)` | Front-end base URLs: the first is the canonical link base, all are the origin allowlist — see [Per-request link base and language](#per-request-link-base-and-language) |
| `WithLogger(func)` | Logging callback |

Pass to `NewService(...)` as `ServiceOption`:

| Option | Description |
|--------|-------------|
| `WithMetadataStore(UserMetadataStore)` | |
| `WithRolesPermissionsStore(RolesPermissionsStore)` | |
| `WithTenantStore(TenantStore)` | |

---

## Custom Claims

`Config.BuildTokenClaims` — a `TokenClaimsBuilder`, set with `WithTokenClaimsBuilder` —
adds claims to every token minted: access, refresh and the 2FA step-up token. Its
result is spread over the reference's six base claims (`sub`, `email`, `role`,
`loginProvider`, `isEmailVerified`, `isTotpEnabled`) and may override them, exactly as
the reference's `config.buildTokenPayload(user)` may (`auth.router.ts:378-384`). The
session claims `sid`, `tid`, `jti`, `typ`, `iss`, `iat` and `exp` are reserved: they are
written after the merge, so a builder value under one of those names is discarded
rather than minted.

```go
type TokenClaimsBuilder = func(ctx context.Context, user User) (map[string]any, error)
```

A builder error fails the mint: the login, refresh or step-up that needed the token
answers a generic `500` rather than issuing a token carrying fewer claims than the
deployment configured.

### Where the builder runs

| Call | Runs the builder | Why |
|------|------------------|-----|
| Every mint — `Register`, `Login`, `Refresh`, the OAuth callback, the passwordless and 2FA verifies, the step-up token | once per token | The claims go into the token |
| `Me` / `GET /me` | once | The profile mirrors the reference's `/me`, whose body is `buildPayload(user)` (`auth.router.ts:656-680`); the result is rendered under `customClaims`. A failure here is logged and `customClaims` omitted — a read does not go dark because a mint-time hook is down |
| `Authenticate` — the four adapters' `Middleware()`, `POST /link-request`, the IdP `userinfo` endpoint | never | What the builder computed is already inside the token the request carried; `CustomClaims` is nil on the user in context. The reference's `authMiddleware` draws the same line: it verifies the token and hands the route the payload as `req.user`, without `buildTokenPayload` (`auth.middleware.ts:44-61`) |

`Authenticate(ctx, accessToken)` is `Me` without the builder: it verifies the token,
runs the `SessionCheckOn=allcalls` check, loads the user and fills `Metadata`, `Roles`,
`Permissions` and `Tenants` from the optional stores (best effort, as always), and
fails with `Me`'s sentinels. A host route that needs the builder's result can call
`Auth.Me` itself.

### Building the hook from configuration

Three constructors build the hook out of configuration rather than code. They are
this port's own extension — the reference has only the in-process function
(`auth-config.model.ts:316`) — and a token minted through them is indistinguishable
on the wire from one minted through a hand-written closure. Together they decode the
consumer's `security.jwt.extraClaims` table, `{claim: {fromUserField: <field>} | {const: <value>}}`.

| Constructor | Result |
|-------------|--------|
| `StaticClaims(map[string]any) TokenClaimsBuilder` | The same claims on every token, from a copy of the map: neither later edits to the input nor edits to a result change the next token |
| `UserFieldClaims(map[string]string) (TokenClaimsBuilder, error)` | Copies `User` fields into named claims; the map is `claim → field`, the field spelled as it is on `/me` |
| `ChainClaims(...TokenClaimsBuilder) TokenClaimsBuilder` | Runs builders in order and merges: later wins on a shared name, the first error stops the chain, nil builders are skipped |

`UserFieldClaims` reads only these fields, by their `/me` names: `id`, `email`, `role`,
`tenantId`, `firstName`, `lastName`, `phoneNumber`, `isEmailVerified`, `isTotpEnabled`,
`loginProvider` (`"local"` when unset). Any other name — a credential column, a Go
spelling, an enriched collection such as `roles` — is a constructor error, so a typo
in configuration fails at startup and not on every login. So is a claim *name* that is
one of the reserved session claims (`sid`, `tid`, `jti`, `typ`, `iss`, `iat`, `exp`):
the mint would discard the mapping every time, and a mapping that can never reach a
token is a configuration error, not a claim. Mapping over a base claim (`email`,
`role`, ...) stays allowed. `StaticClaims` has no error to return, so a reserved name
there is discarded at mint time like any hook's — check the names before building.
Every mapped claim is emitted on every token, an empty field as an empty value
rather than an absent claim.

```go
fields, err := auth.UserFieldClaims(map[string]string{"tenant": "tenantId", "given": "firstName"})
if err != nil {
    log.Fatal(err) // names the unknown field and lists the allowed ones
}
a, err := auth.New(
    auth.WithTokenClaimsBuilder(auth.ChainClaims(
        fields,
        auth.StaticClaims(map[string]any{"plan": "pro"}),
    )),
)
```

### Claims webhook

`ClaimsWebhook` is a builder that asks an HTTP endpoint for the claims — the consumer's
`security.jwt.claimsWebhook {url, timeoutMs}` knob, for claims that are computed rather
than mapped. Its `Build` method has the builder's signature, so it is wired directly or
as one link of a chain.

```go
hook, err := auth.NewClaimsWebhook("https://hooks.example.com/claims", secret) // 2s timeout
a, err := auth.New(auth.WithTokenClaimsBuilder(hook.Build))
// or, after the mapped claims, with the endpoint having the last word:
a, err = auth.New(auth.WithTokenClaimsBuilder(auth.ChainClaims(fields, hook.Build)))
```

```go
type ClaimsWebhook struct {
    URL     string        // absolute http(s) URL; NewClaimsWebhook validates it
    Secret  string        // signs the body when set; never sent
    Timeout time.Duration // per request, through ctx; NewClaimsWebhook sets 2s
    Client  *http.Client  // nil = http.DefaultClient
}
```

> **This request shape is this port's own.** The reference's `buildTokenPayload` is an
> in-process function that never crosses HTTP, so there is no reference wire to
> reproduce. The envelope — headers and signature — is the family's outbound-webhook
> convention (`src/tools/webhook-sender.ts:24-33`, `54-56`), the same one the delivery
> webhook uses, so one receiver verifies both.

One request per token minted and per `GET /me`, and none for a protected route:
`POST <URL>` with `Content-Type: application/json` and

| Header | Value |
|--------|-------|
| `X-Webhook-Event` | `claims.build` (`ClaimsWebhookEvent`) |
| `X-Webhook-Delivery` | a fresh UUID per request |
| `X-Webhook-Timestamp` | when it was sent: ISO 8601, UTC, milliseconds — `2026-09-11T10:00:00.000Z` |
| `X-Webhook-Signature` | `sha256=<hex HMAC-SHA256 of the raw body, keyed by Secret>` — only when `Secret` is set; `VerifyWebhookSignature` checks it |

The body is `{"user": {…}}`, where `user` is the caller as `GET /me` renders it
(`PublicUser`: credentials omitted, `loginProvider` always present):

```json
{"user":{"sub":"usr_…","id":"usr_…","email":"ada@example.com","loginProvider":"local","tenantId":"t1","isEmailVerified":true,"isTotpEnabled":false,"createdAt":"2026-09-11T10:00:00Z"}}
```

At mint time `user` is the stored row; on `/me` it is the enriched profile, so `roles`,
`permissions`, `tenants` and `metadata` appear there and not at mint time.

The endpoint answers `2xx` with

```json
{"claims": {"plan": "pro", "org": "acme"}}
```

and the `claims` object is merged like any builder's result: it may override the six
base claims and cannot set the reserved session claims, so a compromised endpoint
cannot retype a token or rebind a session. **Anything else fails the mint** — the
route answers the generic `500` any failing builder does, and `/me` logs and omits
`customClaims`: a non-`2xx`, a transport error, the timeout (the caller's context
deadline wins when shorter), a body over 64 KiB, a body that is not JSON, a missing
or `null` `claims`, or a `claims` that is not an object. Errors name the status or
the transport failure and never the response body or the secret. Failing closed is
deliberate: a token minted without the claims the deployment configured would
authorise less, or more, than the deployment decided.

---

## OAuth 2.0 + Account Linking

### `OAuthProvider`

```go
type OAuthProvider struct {
    Name, ClientID, ClientSecret, RedirectURL string
    AuthURL, TokenURL, UserInfoURL            string
    Scopes                                    []string
    AdditionalAuthParams                      map[string]string // extra authorize-query params
    GitHubEmailsURL                           string            // "github" only; "" = UserInfoURL + "/emails"
    MapProfile func(raw map[string]any) (OAuthUserInfo, error)  // replaces the default profile mapping
    ProfileMap map[string]string                                // declarative MapProfile; see Profile mapping
}
```

The reference's `GenericOAuthProviderConfig` (`generic-oauth.strategy.ts:39-78`).
`AdditionalAuthParams` is its `additionalAuthParams`: every entry lands in the
authorization URL's query, with the reference's precedence — an entry overrides
`client_id`, `redirect_uri`, `response_type` and `scope`, while `state` (and
the PKCE `code_challenge`/`code_challenge_method` pair this port adds) always
wins over an entry.

### `NewOAuthService(providers ...OAuthProvider) *OAuthService`

### `NewOAuthServiceWithConfig(providers ...OAuthProvider) (*OAuthService, error)`

`NewOAuthService` with the configuration validated: every provider's
`ProfileMap` is compiled and the errors — one per broken provider, each naming
the provider and the expression — come back joined, with no service, so a
deployment fails at start-up rather than at the first login. `NewOAuthService`
keeps its signature and never panics: a map that does not compile is recorded
against its provider, whose `ExchangeCode` calls return that error before the
token endpoint is contacted (a 500 on the callback — a configuration error,
not a client one) while the other providers keep working.

### `GoogleProvider(clientID, clientSecret, redirectURL) OAuthProvider`
### `GitHubProvider(clientID, clientSecret, redirectURL) OAuthProvider`

The reference's two hard-coded strategies as presets. Google sends scope
`openid email profile` plus `access_type=offline` through
`AdditionalAuthParams` (`google.strategy.ts:28-29`) and maps `sub`, `email`,
`email_verified`, `name`, `picture`. GitHub sends scope `user:email`, maps
`String(id)`, `email`, `name` falling back to `login`, `avatar_url`, and when
the profile carries no email — a GitHub account with a private address — GETs
`GitHubEmailsURL` (`https://api.github.com/user/emails`) with
`Authorization: token <access_token>`, picks the entry that is both `primary`
and `verified`, else the first one, and reports its `verified` flag as
`EmailVerified` (`github.strategy.ts:54-69`). A failing emails call leaves the
email empty; it does not fail the exchange.

### `(*OAuthService).AuthorizeURL(provider, state) (string, error)`

Returns the OAuth2 authorization URL to redirect the user to.

### `(*OAuthService).ExchangeCode(ctx, provider, code) (OAuthUserInfo, error)`

Exchanges an authorization code for normalized user info. For a provider that
is neither `google` nor `github` the subject id is `id`, then `sub` — the
reference's `String(raw.id ?? raw.sub ?? '')` (`generic-oauth.strategy.ts:155`)
— then `user_id`, this port's extra last resort; a numeric id is stringified.
`email_verified` fills `EmailVerified` when it is a boolean. A provider with a
`MapProfile` or a `ProfileMap` (next section) gets that mapping instead.

### Profile mapping: `MapProfile` and `ProfileMap`

The reference's `mapProfile` hook (`generic-oauth.strategy.ts:71-77`) turns the
raw userinfo document into the `{id, email, emailVerified?, name?, picture?}`
profile, and when it is set it is what `getUserProfile` returns, in place of
the default mapping (`:151-153`). This port offers it in two forms on
`OAuthProvider`:

- **`MapProfile func(raw map[string]any) (OAuthUserInfo, error)`** — the hook
  itself. It replaces the whole mapping for that provider, the `github`
  preset's `/user/emails` fallback included. Fill `ProviderID`, `Email`,
  `Name`, `AvatarURL` and `EmailVerified`; the service sets `Provider`, and
  `Raw` when the hook left it nil. An error fails the exchange on the
  profile-failed path: 401 `OAUTH_PROFILE_FAILED` on the callback.
- **`ProfileMap map[string]string`** — the declarative form for a provider
  loaded from configuration, compiled by `NewOAuthService` and validated by
  `NewOAuthServiceWithConfig`. `nil` or empty means the default mapping.

`MapProfile` wins when both are set; the `ProfileMap` is still compiled, so a
broken one is still reported.

#### `ProfileMap` grammar

The keys are `id`, `email`, `emailVerified`, `name` and `picture`; `id` is
required and any other key is an error. Each value is an expression in this
grammar, which is this port's own (the reference takes a function):

```
expr    = alt ("??" alt)*
alt     = path | literal
path    = "$" ("." key | "[" index "]")+
key     = one or more ASCII letters, digits, "_" or "-"
index   = one or more decimal digits
literal = a double-quoted string, allowed only as the last alternative
```

Whitespace around an alternative is ignored. Anything else — `$` alone, a
single-quoted literal, a wildcard (`$.*`, `$[*]`), a filter (`$[?(...)]`), a
slice, a function call, a quoted key — is a compile error naming the
expression. A literal has no escapes, so it cannot contain a double quote.

Evaluation follows JavaScript's `??`: the alternatives are tried in order and
the first path that resolves to a value that is neither missing nor `null`
wins, so an empty string, `false` or `0` is a value and stops the chain; a
literal always resolves. A string is taken as is, a number is rendered as
JavaScript's `String()` renders it (`7001` is `"7001"`, `1.5` is `"1.5"`,
`1e21` is `"1e+21"`), a boolean becomes `"true"` or `"false"`; a value that is
an object or an array is an evaluation error. `emailVerified` must resolve to
a boolean or the strings `"true"`/`"false"` (a literal that is neither is
refused at compile time). `id` must resolve to a non-empty string; the other
four stay empty (`EmailVerified` nil) when nothing resolves. An evaluation
error takes the profile-failed path, 401 `OAUTH_PROFILE_FAILED`.

```go
// Microsoft Graph: /v1.0/me answers {id, displayName, mail, userPrincipalName},
// and mail is null for an account without a mailbox.
microsoft := auth.OAuthProvider{
    Name:         "microsoft",
    ClientID:     os.Getenv("MS_CLIENT_ID"),
    ClientSecret: os.Getenv("MS_CLIENT_SECRET"),
    RedirectURL:  "https://api.example.com/auth/oauth/microsoft/callback",
    AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
    Scopes:       []string{"openid", "email", "profile"},
    ProfileMap: map[string]string{
        "id":    "$.id",
        "email": "$.mail ?? $.userPrincipalName",
        "name":  "$.displayName",
    },
}

// A provider that wraps the profile:
// {"data":{"user":{"id":7001,"mail":null,"userPrincipalName":"…","verified":"true",
//                  "profile":{"displayName":"…","photos":[{"url":"…"}]}}}}
nested := auth.OAuthProvider{
    // …
    ProfileMap: map[string]string{
        "id":            "$.data.user.id", // 7001 becomes "7001"
        "email":         "$.data.user.mail ?? $.data.user.userPrincipalName",
        "emailVerified": `$.data.user.verified ?? "false"`,
        "name":          "$.data.user.profile.displayName",
        "picture":       "$.data.user.profile.photos[0].url",
    },
}

svc, err := auth.NewOAuthServiceWithConfig(microsoft, nested) // a bad expression fails here
```

#### `CompileProfileMap(m map[string]string) (func(map[string]any) (OAuthUserInfo, error), error)`

The compiler behind `ProfileMap`, exported so a deployment can validate a map
it loaded from configuration — or build a `MapProfile` from one — before it
wires anything. The function it returns fills everything but `Provider`.

### `(*OAuthService).HandleCallback(ctx, authSvc, linkedAccounts, info, tenantID, linkToUserID) (User, AuthTokens, error)`

Resolves or creates a user from OAuth user info under the default provisioning
policy. It is `HandleCallbackWithPolicy` with `DefaultOAuthProvisioning()`, so an
address another account already holds is answered with
`*OAuthAccountConflictError`, not linked. Through 0.12.0 it linked the address
and signed that account in; pass `OnEmailMatch: "link"` to
`HandleCallbackWithPolicy` for that.

### `(*OAuthService).HandleCallbackWithPolicy(ctx, authSvc, linkedAccounts, info, tenantID, linkToUserID, policy) (User, AuthTokens, error)`

The same, under an explicit `OAuthProvisioning`:

1. The policy gate — `RequireVerifiedEmail`, then `AllowedEmailDomains` — runs
   before anything is read or written, so a refused identity leaves no trace and
   an account that was linked under a looser policy is refused too.
2. If `linkToUserID` non-empty: links provider to existing account.
3. If an existing `(provider, providerAccountId)` link is found: returns that
   user. This is the only identification the reference's own store
   documentation considers safe (`user-store.interface.ts:105-119`).
4. If an account already holds the profile address: `OnEmailMatch` decides —
   raise an account conflict (the default), link it, or refuse.
5. Otherwise: creates a new user, if `AutoCreate` allows it.

### `OAuthProvisioning`

```go
type OAuthProvisioning struct {
    AutoCreate           bool
    AllowedEmailDomains  []string
    RequireVerifiedEmail bool
    OnEmailMatch         string // "link" | "conflict" | "reject"
    FieldMap             map[string]string
}
```

The declarative replacement for the abstract `findOrCreateUser(profile, state)`
the reference makes every integrator write
(`generic-oauth.strategy.ts:169-172`). Set it on `OAuthWiring.Provisioning`,
which is a **pointer**: `nil` means `DefaultOAuthProvisioning()` —
`AutoCreate: true`, `OnEmailMatch: "conflict"`, no domain list, no verification
demand. That is the `findOrCreateUser` the reference documents for its
integrators (its `README.detailed.md`, "OAuth Strategies"): an existing
provider link signs in, an address another account holds is a conflict, and
anything else is created. A policy given explicitly is taken as written,
`AutoCreate: false` included; the one field whose empty value still means a
default is `OnEmailMatch`, and `""` means `"conflict"`, never `"link"`.

> **Changed after 0.12.0 (issue #36).** Through 0.12.0 the default was
> `OnEmailMatch: "link"`, which signed a provider account into whatever account
> held the address it asserted, whether or not the provider had verified it. A
> deployment that relied on that sets `OnEmailMatch: "link"` explicitly, and
> should add `RequireVerifiedEmail: true` unless every provider it trusts
> verifies addresses.

- **`AutoCreate`** — false answers `403 OAUTH_USER_NOT_PROVISIONED` instead of
  creating an account for an identity nothing here knows.
- **`AllowedEmailDomains`** — empty allows every address. An entry is a bare
  domain (`"example.com"`, or `"@example.com"`), matched case-insensitively
  against the part after the last `@`, with no subdomain matching. A profile
  with no address is refused whenever the list is non-empty. Refusal is
  `403 OAUTH_EMAIL_DOMAIN_NOT_ALLOWED`.
- **`RequireVerifiedEmail`** — refuses `403 OAUTH_EMAIL_NOT_VERIFIED` unless the
  provider positively asserted the address. Most providers assert nothing, so
  turning this on for one of them refuses every login through it.
- **`OnEmailMatch`** — what happens when the provider account is unknown but
  some account already holds the address. `"conflict"` (the default, and what
  `""` means) raises the reference's `OAUTH_ACCOUNT_CONFLICT` and starts the
  account-conflict flow below; `"link"` links it and signs that account in —
  the account-takeover shape the reference's store interface warns about, since
  it applies no check of its own on whether the provider verified the address,
  so pair it with `RequireVerifiedEmail` (which, unlike a check on this branch
  alone, also refuses creation and existing links for an unasserted address);
  `"reject"` answers `403 OAUTH_USER_NOT_PROVISIONED`, the same refusal
  `AutoCreate: false` gives, because both mean the deployment will not
  provision this identity.
- **`FieldMap`** — further `User` fields to fill from the raw profile when the
  callback **creates** an account; an account it only links is never rewritten.
  The keys are the fields it may write — `firstName`, `lastName`,
  `phoneNumber`, `role`, and nothing else — and the values are expressions in
  the `ProfileMap` grammar above, evaluated against the same userinfo document:
  `"$.given_name"`, `"$.name.first ?? $.given_name"`, `"$.roles[0]"`,
  `` `$.dept ?? "unassigned"` ``. The fields the profile itself owns are
  deliberately not targets: `id` and `email` come from `OAuthUserInfo` (map
  them with `ProfileMap`), `tenantId` comes from the wiring, `loginProvider` is
  the provider, and `isEmailVerified` is the policy's business. An expression
  that resolves to nothing leaves its field alone; one that resolves to an
  object or an array fails the callback.

`OAuthProvisioning.Validate()` reports an unknown `OnEmailMatch`, an empty
domain entry, an unknown `FieldMap` target or a `FieldMap` expression that does
not compile. `WithOAuth` runs it, so an invalid policy fails at construction
rather than at the first login; it is exported so a policy loaded from
configuration can be checked before anything is wired.

An account the callback creates records `LoginProvider = <provider>` and takes
`IsEmailVerified` from the provider's claim: true when the provider said
nothing — the common case, and what this port has always done — and false only
when the provider positively said so.

### The account-conflict flow

Under the default `OnEmailMatch: "conflict"`, a provider account asserting an address another
account holds produces `*OAuthAccountConflictError` (it unwraps to
`ErrOAuthAccountConflict` and carries `Provider`, `Email` and
`ProviderAccountID`, the reference's `AuthError` data). On the callback route
that becomes the reference's answer (`auth.router.ts:1988-2003` at 1.10.8):

1. The pair is stashed through `PendingLinkStore.Save` under
   `pending-link:<email>|<provider>`, carrying the provider account id and the
   callback's tenant, for `LinkTokenTTL` (1 hour by default). Like the
   reference's `stash`, this is best effort: a store failure is logged and the
   redirect is sent anyway.
2. The browser gets a `302` to
   `HTTPConfig.AccountConflictLink(siteURL, provider, email)` —
   `<siteURL><prefix>/account-conflict?provider=<p>&code=OAUTH_ACCOUNT_CONFLICT[&email=<e>]`,
   or `<siteURL><prefix>/ui/account-conflict?…` under `HTTPConfig.UIEnabled`,
   with `provider` and `email` escaped as JavaScript's `encodeURIComponent`
   escapes them. `siteURL` is `OAuthCompleteResult.ConflictOrigin`: the origin
   the signed state names when the allowlist admits it, the default site URL
   otherwise, and — unlike the redirect a successful login gets — never the
   state's return path. No session is issued and no link is written.
3. The front-end reads `provider` and `email` off that query and posts them to
   `POST <prefix>/link-request`, which resolves the identity from the stash
   rather than from a credential, and mails a verification link.
4. `POST <prefix>/link-verify` completes the link under the **stashed**
   `providerAccountId` and consumes both the token and the stash. With
   `loginAfterLinking` it issues the session as well.

The stash key has no tenant segment — the reference's shape, reproduced — and
`/link-request` takes the tenant from the entry it finds, so two tenants holding
one address share one slot. A multi-tenant deployment whose tenants share
addresses should not enable the conflict flow across them.

### `OAuthUserInfo`

```go
type OAuthUserInfo struct {
    ProviderID, Provider, Email, Name, AvatarURL string
    EmailVerified *bool // provider's email_verified; nil = not stated
    Raw map[string]any
}
```

`EmailVerified` is the reference profile's `emailVerified?`. The provisioning
policy reads it twice: `RequireVerifiedEmail` refuses a callback with no
positive claim, and an account the callback creates is verified unless the
provider positively said otherwise.

### `LinkedAccountStore` interface

```go
type LinkedAccountStore interface {
    Save(ctx, OAuthLinkedAccount) error
    FindByProvider(ctx, provider, providerID) (OAuthLinkedAccount, error)
    ListForUser(ctx, userID) ([]OAuthLinkedAccount, error)
    Delete(ctx, id) error
}
```

### `MemoryLinkedAccounts`

In-memory `LinkedAccountStore`. Create with `NewMemoryLinkedAccounts()`.

### `PendingLinkStore` interface

The stash. It holds three kinds of single-use entry, all keyed by an opaque
string: the in-flight OAuth state nonce (`oauth-state:`), the account-link token
issued by `/link-request` (`link-token:`, keyed by hash), and the
account-conflict pair the callback parks for the link flow (`pending-link:`).

---

## SSE (Server-Sent Events)

### `SseManager`

The reference's `SseManager` (`src/tools/sse-manager.ts`): connections rather
than channels, a set of server-chosen topics per connection, and `StreamEvent`
frames broadcast to every connection subscribed to a topic.

```go
sse, err := auth.NewSseManager(ctx)

// One handler holds one connection for its whole life. The topics are the
// server's decision — a client never names a channel.
http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
    user, ok := auth.UserFromContext(r.Context())
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    _ = sse.Serve(w, r, []string{"user:" + user.ID, "global"},
        auth.SseConnectionMeta{UserID: user.ID, TenantID: user.TenantID})
})

// Publish from anywhere.
sse.Broadcast(ctx, "user:"+userID, auth.StreamEvent{
    Type: "notification",
    Data: map[string]any{"message": "Hello!"},
})
```

No route is mounted for this yet: `GET <prefix>/tools/stream` arrives with the
tools router.

### `NewSseManager(ctx context.Context, opts ...SseOption) (*SseManager, error)`

With no options: heartbeats every 30 s, deduplication on, no distributor — the
reference's defaults. `ctx` bounds the distributor subscription, and the error
is that subscription failing.

Options: `WithSseHeartbeat(d)` (`0` disables, as the reference's `0` does),
`WithSseDeduplicate(bool)`, `WithSseDistributor(SseDistributor)`,
`WithSseSendBuffer(frames)`.

### `(*SseManager).Serve(w, r, topics []string, meta SseConnectionMeta) error`

Registers a connection, writes the `connected` frame, and streams until the
client goes away or the request context is cancelled. It blocks the request
goroutine for the life of the stream, which is what Go has instead of an
Express `Response` that stays open on its own.

### `(*SseManager).Broadcast(ctx, topic string, ev StreamEvent)`

Fills an empty `ID` and `Timestamp`, overwrites `Topic`, and delivers. Returns
nothing, as the reference's `broadcast` does. Fanning one event across several
topics means building the `StreamEvent` once, with its id, and passing the same
value to each call — that is what the deduplication keys on.

### `(*SseManager).Disconnect(id)`, `ConnectionCount()`, `HeartbeatInterval()`, `Deduplicate()`

### `(*SseManager).BridgeEventBus(ctx, bus *EventBus, topics func(Event) []string) (cancel func())`

Broadcasts every bus event to the topics resolved for it, and returns the
function that stops doing so. The low-level seam only: deciding topics, payload
and the order telemetry, the bus, SSE and webhooks are served in belongs to the
`AuthTools` facade.

### The frame

```
id: <event id>\n
event: <event type>\n
data: {"id":…,"timestamp":…,"topic":…,"type":…,"userId":…,"tenantId":…,"rawData":<payload>}\n
\n
```

Two things to read carefully, both the reference's: the payload arrives under
`rawData`, and there is **no `data` key at all**. The keep-alive is the comment
`: heartbeat\n\n`, with the space the reference's code writes (its own docs say
`:heartbeat`).

### Resume: there is none

Nothing reads the `Last-Event-ID` header a browser sends when its `EventSource`
reconnects, and no delivered event is retained. A reconnect resumes from *now*;
whatever was raised while the client was away is gone. The `id:` line is an
identity and a deduplication key, not a cursor. This matches the reference
exactly — anything that needs delivery across a reconnect is adding a guarantee,
not implementing one.

### `StreamEvent`

```go
type StreamEvent struct {
    ID        string         // `id:` line; filled with a UUIDv4 when empty
    Type      string         // `event:` line
    Timestamp string         // ISO 8601, filled when empty
    Topic     string         // overwritten by Broadcast
    Data      any            // reaches the client as rawData
    UserID    string
    TenantID  string
    Metadata  map[string]any
}
```

Its JSON tags are the shape a **distributor** carries, not the shape of the
frame.

### `SseDistributor` interface

The seam for cross-instance fan-out — and the only thing that makes SSE work at
all where every connection lives in its own process, such as a Lambda Function
URL:

```go
type SseDistributor interface {
    Publish(ctx context.Context, topic string, event StreamEvent) error
    Subscribe(ctx context.Context, fn func(topic string, event StreamEvent)) error
}
```

What it owes: no ordering is required; at-most-once and at-least-once are both
safe (the deduplication absorbs only an *immediate* redelivery); and a `Publish`
that returns an error makes the manager fall back to delivering to its own
connections and no others.

**The fact to design around**: with a distributor configured, `Broadcast` does
not deliver locally. Local connections are served only when the distributor
calls the subscription back, so a distributor that does not echo a publisher's
own events reaches every instance except the one that raised them.

### Slow consumers

Each connection has a bounded queue (`WithSseSendBuffer`, 64 frames by
default). A publisher is never blocked by a reader, and a connection that falls
behind is disconnected rather than buffered without limit — a deliberate
difference from the reference, registered as
`sse-slow-consumer-is-disconnected`.

---

## Outgoing webhooks

The reference's own wire (`src/tools/webhook-sender.ts`). Subscriptions live in a
`WebhookStore` (see the store seams above), not in a list hard-coded at
construction time, and the store is the only filter in the chain: `FindByEvent`
decides who is delivered to and the sender POSTs whatever it is handed, checking
neither `isActive` nor `events` a second time.

### The request

One `POST` to `WebhookConfig.URL` per matching subscription, with
`Content-Type: application/json` and

| Header | Value |
|--------|-------|
| `X-Webhook-Event` | the event name, e.g. `identity.auth.login.success` |
| `X-Webhook-Delivery` | a fresh UUID **per attempt**, not per event — it is minted inside the retry loop, so it cannot be used to deduplicate |
| `X-Webhook-Timestamp` | the *envelope's* timestamp, not the moment of the request: a retry still names the instant the event happened |
| `X-Webhook-Signature` | `sha256=<hex HMAC-SHA256 of the raw body, keyed by Secret>` — only when `Secret` is set; `VerifyWebhookSignature` checks it |

The body is `OutgoingWebhookEvent`:

```json
{"event":"identity.auth.login.success","version":"1","timestamp":"2026-09-12T10:00:00.123Z","data":{"method":"local"},"metadata":{"userId":"usr_…","tenantId":"t1","sessionId":"ses_…","correlationId":"…"}}
```

`timestamp` is a **string**, in exactly the shape JavaScript's `toISOString()`
produces — UTC, always three fractional digits, a literal `Z` — because Go's
RFC 3339 emits as many digits as the value has, and a receiver checking a
signature over the raw body would see a different string for the same instant.
`WebhookTimestamp(t)` produces it. `data` is always present and is `null` when
the event carried none. `metadata` carries only the identifiers that are known;
the client address and user agent are deliberately **not** among them, because a
webhook leaves the deployment.

### Retry

`WebhookConfig.Retries()` (default 3) is a count of *retries*, so the default is
**four** requests. A non-2xx answer and a transport failure are the same failure
and both retry while attempts remain; between them the sender waits
`WebhookConfig.RetryDelay()` (default 1s) doubled once per retry already made —
1s, 2s, 4s — and the last attempt is not followed by a wait. A stored
`maxRetries` of `0` means "deliver once, never retry"; a negative one sends
nothing at all. Exhaustion is silent, as it is in the reference.

Because deliveries retry, **a receiver must be idempotent** — and must not key
that idempotency on `X-Webhook-Delivery`.

### `WebhookDeliverer` — the delivery seam

```go
type WebhookDeliverer interface {
    DeliverWebhook(ctx context.Context, attempt WebhookAttempt) error
}
```

The seam sits below the format and below the policy: a `WebhookAttempt` is a
request that is already built, already signed and already numbered, so a host
replacing the transport reimplements neither the envelope, nor the signature,
nor the back-off. It is self-contained and JSON-serialisable, and carries
`ConfigID` but never the subscription's secret — so it can go straight onto a
queue. The default is `HTTPWebhookDeliverer`, which is the reference's own
behaviour with a per-instance `Timeout` (`DefaultWebhookTimeout`, 10s).

What a host owes when it replaces the default — the full contract is on the
interface's doc comment:

- **Ordering**: none is promised and none is required.
- **Delivery**: this package promises at-most-once and persists nothing. A host
  that needs at-least-once buys it by making `DeliverWebhook` durable before it
  returns `nil`.
- **Retry**: once `DeliverWebhook` returns `nil` this package is finished. A
  queueing deliverer owns the retry policy and the dead-letter queue for the
  real request, and reproduces the reference's schedule by reading
  `WebhookConfig.Retries()` and `RetryDelay()` rather than hard-coding 3 and 1s.
- **Idempotency**: resend the `X-Webhook-Delivery` you were handed; do not mint
  one.
- **Concurrency**: one goroutine per delivery; the call must be safe for
  concurrent use and must bound its own work.

### `WebhookEmitter` — wiring it up

```go
store := auth.NewMemoryWebhookStore()
store.AddWebhook(ctx, auth.WebhookConfig{
    URL:    "https://hooks.example.com/auth",
    Secret: secret,
    Events: []string{auth.EventAuthLoginSuccess}, // or auth.WebhookEventWildcard
})

webhooks := &auth.WebhookEmitter{Store: store}
webhooks.Subscribe(bus) // the whole of the bridge from the event bus
```

`Emit` looks the subscriptions up synchronously, builds one envelope shared by
every delivery, and fires each on its own goroutine; it returns without waiting.
A store failure means "no webhooks for this event", never a failed publish.
Failures are silent by default — set `OnError` to hear about them.

**Nothing subscribes an emitter for you.** Which events reach a webhook is the
host's call; the facade that orders webhooks against telemetry, the bus and SSE
arrives with the `AuthTools` port.

### `VerifyWebhookSignature(secret string, body []byte, sigHeader string) error`

Validates an `X-Webhook-Signature` header against the raw body it should cover,
in constant time. Used by a receiver; it is also what verifies the delivery and
claims webhooks below, which share this envelope.

---

## Telemetry

### `TelemetryStore` interface

```go
type TelemetryStore interface {
    Record(ctx, TelemetryEvent) error
    Query(ctx, TelemetryFilter) ([]TelemetryEvent, error)
}
```

### `TelemetryEvent`

```go
type TelemetryEvent struct {
    ID, EventName, UserID, TenantID string
    IP, UserAgent                    string
    Success                          bool
    Error                            string
    Timestamp                        time.Time
    Meta                             map[string]any
}
```

### `TelemetryFilter`

Filter by `UserID`, `TenantID`, `EventName`, `Since`, `Until`, `Limit`.

### `NewMemoryTelemetryStore() *MemoryTelemetryStore`

---

## Mailer

### `MailerTransport` interface

```go
type MailerTransport interface {
    Send(ctx context.Context, msg MailMessage) error
}

type MailMessage struct {
    To, Subject string
    Body        string // HTML when IsHTML is set, plain text otherwise
    IsHTML      bool
    Text        string // plain-text alternative of an HTML Body; empty → the HTML is sent as the text
}
```

### `NewGatewayMailerTransport(cfg MailerConfig) (MailerTransport, error)`

The transport for the family's mail gateway — the request the reference's built-in
mailer sends. The contract is spelled out under
[Mail gateway contract](#mail-gateway-contract) in the Delivery section.

```go
type MailerConfig struct {
    Endpoint    string       `json:"endpoint"`              // absolute http(s) URL; anything else is a constructor error
    APIKey      string       `json:"apiKey"`                // sent as X-API-Key
    From        string       `json:"from"`
    FromName    string       `json:"fromName,omitempty"`
    Provider    string       `json:"provider,omitempty"`
    DefaultLang string       `json:"defaultLang,omitempty"` // carried, not read: locale is the mailers' knob
    Client      *http.Client `json:"-"`                     // nil → a client with a 10-second timeout
}
```

### `NewHTTPMailerTransport(endpointURL, secret string) *HTTPMailerTransport` — deprecated

POSTs a JSON-encoded `MailMessage` (PascalCase) to any HTTP endpoint with an
`X-Mailer-Secret` header — a request of this port's own that no gateway built for
the reference accepts. Kept unchanged for gateways built against it since 0.3.0 and
scheduled for removal in v1.0.0; use `NewGatewayMailerTransport`.

### `NewMailTemplater(appName string) *MailTemplater`

Returns a templater holding the reference's six built-in templates, in **English**
and **Italian**, transcribed from `awesome-node-auth`
`src/services/mailer.service.ts:19-127` (invitation: `:211-225`) — subject, HTML
and text for each. `appName` is what a template mentioning `{{.appName}}` shows;
the built-ins mention none.

| Constant | Id | Data the ready-made mailer supplies | Reference |
|----------|----|-------------------------------------|-----------|
| `TemplatePasswordReset` | `password-reset` | `link`, `token` | `mailer.service.ts:186` |
| `TemplateMagicLink` | `magic-link` | `link`, `token` | `:191` |
| `TemplateWelcome` | `welcome` | `loginUrl`, `tempPassword` — sent by the reference's `POST /register` (`auth.router.ts:719-724`: `sendWelcome(user.email, {loginUrl: <siteUrl>/login})`, or the deployment's own `config.email.sendWelcome(user.email, data)`); **this port's `POST /register` mails nothing yet**, so the id is reachable only through `RenderMail` | `:196`, `:61-89` |
| `TemplateVerifyEmail` | `verify-email` | `link`, `token` | `:201` |
| `TemplateEmailChanged` | `email-changed` | `newEmail` | `:206` |
| `TemplateInvitation` | `invitation` | `link` — no ready-made mailer, and no route in the reference calls its `sendInvitation` either | `:211` |

The 0.3.x ids `reset_password`, `magic_link`, `verify_email` and `email_change` are
**deprecated aliases**: the first three of the matching constant, `email_change` of
`TemplateVerifyEmail`, because the reference mails its verification template on
`/change-email/request` (`auth.router.ts:1027-1032`) and has no separate one. They
work everywhere an id is accepted and go away in v1.0.0.

### `(*MailTemplater).Register(locale, id, subject, html, text string)`

Adds or replaces the template rendered for `id` in `locale`. The three parts are Go
templates over the keys of `MailTemplateData` — `{{.link}}`, `{{.appName}}` … —
`html/template` for the HTML body (contextual escaping applies), `text/template` for
the subject and the text. This is how a deployment replaces a built-in, adds a
locale, or adds an id of its own without a store; a part that does not parse is
reported by the next render of that `(locale, id)`. An alias id registers under the
id it aliases.

### `(*MailTemplater).RenderMail(ctx, locale, id string, data MailTemplateData) (MailRendered, error)`

The reference's `MailerService.render` (`mailer.service.ts:149-181`), returning
`MailRendered{Subject, HTML, Text}`:

1. A stored template is looked up — through `MailTemplater.Store`, or the store the
   service put on `ctx` (`Config.Templates`) — and used only when both its
   `BaseHTML` and `BaseText` are non-empty (`:158`). A store error is returned.
2. Its translations are those for `locale`, else for `en`, else none (`:159`).
   Every `{{T.key}}` becomes `translations[key]`, or `[key]` when that is missing or
   empty (`:163`); then every remaining `{{key}}` becomes the data value for `key`,
   or `[key]` when there is none (`:165-168`) — the reference's keys per id
   (`link`, `token`; `newEmail`; `loginUrl`, `tempPassword`), plus this port's own
   only when a caller sets them; see `MailTemplateData`. The subject is
   `translations["subject"]`, else the built-in subject for the language, and is
   interpolated the same way (`:172-177`). Values are substituted raw, the HTML
   body included — no escaping, as the reference does none (`:167`). `BaseHTML` is
   your markup, but `newEmail` is what the user typed (lowercased and trimmed,
   nothing more) and `Extra` is whatever the caller passed: a stored template that
   shows them mails them verbatim, exactly as the reference's does; the built-ins,
   rendered by `html/template`, escape them.
3. Otherwise the registered template for `locale` renders — the built-in unless
   `Register` replaced it — falling back to `en`.

`locale` is used as given; the ready-made mailers pass what `resolveLang` picked
(`it`, `en`, or their `Locale`). An id with neither a usable stored template nor a
registered one is an error.

### `(*MailTemplater).Render(locale, id string, data MailTemplateData) (subject, body string, err error)`

`RenderMail` without a context and without the text body: `body` is the HTML. It
sees `MailTemplater.Store` but not a store carried by a service call.

### `MailTemplateData`

```go
type MailTemplateData struct {
    AppName  string         // appName, when non-empty — set by the templater (this port's key)
    UserName string         // name (this port's key)
    Token    string         // token
    URL      string         // link — or loginUrl when the id is welcome, the name its template reads
    Code     string         // code (this port's key)
    NewEmail string         // newEmail
    OldEmail string         // oldEmail (this port's key)
    Extra    map[string]any // any other key, formatted with fmt.Sprint — tempPassword, for instance
}
```

A registered template reads them as `{{.link}}`, `{{.token}}` …; a stored one as
`{{link}}`, `{{token}}` …. An empty field is left out rather than set to `""`, so a
stored template naming a key the mailer did not supply shows `[key]`, as it would in
the reference. The keys marked *this port's* — `appName`, `name`, `code`, `oldEmail`
— and `Extra` are never passed by the reference and are absent here too until set,
so a stored template written for it sees exactly the keys it sees there:
`{link, token}` for `password-reset`, `magic-link` and `verify-email`, `{link}` for
`invitation`, `{newEmail}` for `email-changed`, `{loginUrl, tempPassword}` for
`welcome`. A `{{loginUrl}}` in a password-reset template, or an `{{appName}}` when
the templater has no app name, renders `[loginUrl]` / `[appName]` here as there.

### `TemplateStore` interface

The reference's `ITemplateStore` (`src/interfaces/template-store.interface.ts:13-43`;
`config.templateStore`, `auth-config.model.ts:400`): run-time overrides of the
built-in mail templates, plus the UI translations the reference's UI router reads.

```go
type TemplateStore interface {
    GetMailTemplate(ctx context.Context, id string) (MailTemplate, bool, error)       // false: not stored — the reference's null
    ListMailTemplates(ctx context.Context) ([]MailTemplate, error)
    UpdateMailTemplate(ctx context.Context, id string, patch MailTemplatePatch) (MailTemplate, error) // upsert
    GetUITranslations(ctx context.Context, page string) (UITranslation, bool, error)
    ListUITranslations(ctx context.Context) ([]UITranslation, error)
    UpdateUITranslations(ctx context.Context, page string, translations map[string]map[string]string) (UITranslation, error) // set
}

type MailTemplate struct {
    ID           string                       `json:"id"`
    BaseHTML     string                       `json:"baseHtml"`
    BaseText     string                       `json:"baseText"`
    Translations map[string]map[string]string `json:"translations"` // lang -> key -> value; "subject" is the subject
}

type UITranslation struct {
    Page         string                       `json:"page"`
    Translations map[string]map[string]string `json:"translations"`
}

type MailTemplatePatch struct {
    BaseHTML     *string                      // nil keeps the stored body; a pointer to "" clears it
    BaseText     *string
    Translations map[string]map[string]string // nil keeps every language; non-nil replaces the whole map
}
```

`UpdateMailTemplate` is the reference's upsert: a missing id starts as
`{id, "", "", {}}` and the patch is spread on top (`memory-template.store.ts:16-22`)
— which is why a supplied `Translations` replaces the map rather than merging into
it; read the template and send the map back whole to change one language.
`UpdateUITranslations` sets a page wholesale (`:33-35`). Both return what is stored
afterwards. Placeholders in `BaseHTML` are substituted without HTML escaping — see
step 2 of `RenderMail` for what that means for `newEmail` and `Extra`.

`MemoryTemplateStore` (`NewMemoryTemplateStore()`) is the in-memory implementation:
safe for concurrent use, copies in and out, lists in insertion order.

### `WithTemplateStore(store TemplateStore) Option` / `Config.Templates`

Wires the store once. Every sender the service calls receives a context carrying
it, and a `MailTemplater` whose `Store` is nil — the ready-made mailers' — reads it
from there; a `MailTemplater.Store` set by hand wins, and is the way to render from
a store outside a service call.

```go
store := auth.NewMemoryTemplateStore()
html := `<h1>{{T.title}}</h1><p><a href="{{link}}">{{T.cta}}</a></p>`
text := `{{T.title}}: {{link}}`
_, _ = store.UpdateMailTemplate(ctx, auth.TemplatePasswordReset, auth.MailTemplatePatch{
    BaseHTML: &html,
    BaseText: &text,
    Translations: map[string]map[string]string{
        "en": {"subject": "Reset your {{appName}} password", "title": "Password reset", "cta": "Choose a new password"},
        "it": {"subject": "Reimposta la password", "title": "Reimposta la password", "cta": "Scegli una nuova password"},
    },
})
a, err := auth.New(
    auth.WithTemplateStore(store),
    auth.WithPasswordResetSender(auth.NewPasswordResetMailer(transport, "Example App", "https://app.example.com/auth").Send),
)
```

With that, `POST /auth/forgot-password` mails the stored template; clear either body
and the built-in is back. The UI half of the store is written through the same
interface and served once the UI router lands.

---

## Delivery

`POST /auth/magic-link/send` and `POST /auth/sms/send` answer `{"success": true}` and
nothing else: the credential they mint cannot travel in the response body, because
handing a second factor back to whoever asked for it is no second factor at all.
`SendMagicLink` and `SendSMSCode` therefore pass it to a sender you configure.

**A sender is required to use these routes.** Without one they answer
`500 {"error": "Email not configured", "code": "EMAIL_NOT_CONFIGURED"}` and
`500 {"error": "SMS is not configured", "code": "SMS_NOT_CONFIGURED"}`, matching the
reference. Nothing is stored in that case, and `Config.validate()` does not ask for a
sender — a deployment that never calls these routes needs neither.

### Sender types

```go
type MagicLinkSender func(ctx context.Context, delivery MagicLinkDelivery) error
type SMSCodeSender   func(ctx context.Context, delivery SMSCodeDelivery) error

type MagicLinkDelivery struct {
    UserID, TenantID, Email string
    Token                   string    // plaintext; the store holds only its hash
    ExpiresAt               time.Time
}

type SMSCodeDelivery struct {
    UserID, TenantID, Phone string
    Code                    string    // plaintext; the store holds only its hash
    ExpiresAt               time.Time
}
```

Each delivery carries the one credential it has to transmit and no other user
secret — no password hash, no TOTP secret, no `User`. A sender needing more about
the recipient has `UserID` and `TenantID` to read it back with.

A sender that returns an error fails the route with a generic `500` (no code, no
detail — a transport failure must not describe itself to the caller) and leaves the
stored credential in place, which is what the reference does: an undelivered token
is unguessable and expires on its own.

### Built-in senders

```go
mailer, err := auth.NewGatewayMailerTransport(auth.MailerConfig{
    Endpoint: "https://mail.example.com/send",
    APIKey:   apiKey,
    From:     "noreply@example.com",
    FromName: "Example App",
})
if err != nil {
    log.Fatal(err) // empty or non-absolute endpoint
}

a, err := auth.New(
    auth.WithMagicLinkSender(auth.NewMagicLinkMailer(
        mailer,
        "Example App",                       // greets the recipient in the template
        "https://app.example.com/auth",      // link base; see MagicLinkURL
    ).Send),
    auth.WithSMSCodeSender(auth.SMSTransportSender(
        auth.NewHTTPSMSTransport("https://sms.example.com/send", apiKey, user, pass),
    )),
)
```

| Helper | Purpose |
|--------|---------|
| `NewMagicLinkMailer(MailerTransport, appName, baseURL) *MagicLinkMailer` | Renders the `magic-link` template (built-in or stored) and sends it, HTML and text; `.Locale` selects `en` (default) or `it` |
| `NewPasswordResetMailer(…)`, `NewEmailVerificationMailer(…)`, `NewEmailChangeMailer(…)` | The same shape for `password-reset`, `verify-email` and — as the reference does on `/change-email/request` — `verify-email` again under the confirmation link; use through `.Send` with `WithPasswordResetSender`, `WithEmailVerificationSender`, `WithEmailChangeSender` |
| `NewEmailChangedMailer(MailerTransport, appName) *EmailChangedMailer` | Renders the `email-changed` template with the new address and mails it to the old one; use through `.Send` with `WithEmailChangedSender` — see [The email-changed notice](#the-email-changed-notice) |
| `MagicLinkURL(base, token) string` | The link shape the verify route and every family client expect: `<base>/magic-link/verify?token=<token>` |
| `PasswordResetURL`, `EmailVerificationURL`, `EmailChangeConfirmURL(base, token) string` | Likewise `<base>/reset-password?token=…`, `<base>/verify-email?token=…`, `<base>/change-email/confirm?token=…` |
| `SMSTransportSender(SMSTransport) SMSCodeSender` | Adapts a transport, formatting the code with `SMSCodeMessage` |
| `SMSCodeMessage(code) string` | The family's handset text: `Your verification code is: <code>` |
| `NewGatewayMailerTransport(MailerConfig) (MailerTransport, error)` | `POST` mail gateway with the reference's JSON body and `X-API-Key` — see [Mail gateway contract](#mail-gateway-contract) |
| `NewHTTPSMSTransport(endpoint, apiKey, username, password) *HTTPSMSTransport` | `GET` gateway with credentials as query parameters and `X-API-Key` — see the caveat below |
| `NewDeliveryWebhook(url, secret) (*DeliveryWebhook, error)` | One sender for every seam, over HTTP — see [Delivery webhook](#delivery-webhook) |

```go
type SMSTransport interface {
    Send(ctx context.Context, phone, message string) error
}
```

> **`HTTPSMSTransport` puts the gateway credentials in the URL.** That is the request
> the rest of this family sends, so an existing gateway keeps working, but query
> strings reach access logs and proxies. The fix belongs at the gateway; until then,
> `WithSMSCodeSender` takes any sender, so a deployment whose provider accepts a
> safer shape supplies its own transport and never constructs this one.

### The email-changed notice

`POST /auth/change-email/confirm` applies the pending address, clears the token and
then mails the **old** address a notice — the reference's
`config.email.sendEmailChanged(oldEmail, newEmail)` (`auth.router.ts:1056-1066`,
`auth-config.model.ts:252-257`). The sender is optional and carries no credential:

```go
type EmailChangedSender func(ctx context.Context, delivery EmailChangedDelivery) error

type EmailChangedDelivery struct {
    UserID   string `json:"userId"`
    TenantID string `json:"tenantId"`
    OldEmail string `json:"oldEmail"` // the recipient: the address the account had until now
    NewEmail string `json:"newEmail"` // what the notice reports
    Lang     string `json:"lang"`     // "" from the route — the reference passes no language on confirm
}
```

Two things differ from the token senders above. There is no link, so
`NewEmailChangedMailer(transport, appName)` takes no base URL; and a failing sender
answers the generic `500` **with the change already applied** — the reference's call
sits inside the route's `try` block after `updateEmail`, so a throwing mailer reaches
`handleError` (`:1068-1069`) and nothing is rolled back. That is reproduced, not
softened: the token is spent and the address has moved when the 500 goes out.
Without a sender the route mails nothing and answers `200`, like the three token
routes. `ConfirmEmailChangeInput.Lang` exists for a caller driving the service
directly; the adapters leave it empty, as the reference's route reads only `token`.

### Mail gateway contract

`NewGatewayMailerTransport` sends exactly what the reference's built-in mailer sends
(`awesome-node-auth` `src/services/mailer.service.ts:261-291`; payload
`mailer.service.ts:133-141`; config shape `src/models/auth-config.model.ts:19-36`):

```http
POST {endpoint}
Content-Type: application/json
X-API-Key: {apiKey}

{"to": "…", "subject": "…", "html": "…", "text": "…", "from": "…", "fromName": "…", "provider": "…"}
```

- The endpoint's own path and query are kept, and the header is sent even when the
  key is blank — the reference always sets it.
- `to`, `subject`, `html`, `text` and `from` are always present. `fromName` and
  `provider` are optional in the reference and are absent, not blank, when unset.
- `html` is `MailMessage.Body` when `IsHTML` is set and `text` is `MailMessage.Text`;
  an empty `Text` sends the HTML as the text, as the reference's `sendCustom` does
  (`text ?? html`, `mailer.service.ts:246`). A plain-text `Body` goes out as `text`
  with an empty `html` — the reference has no text-only path.
- Only a `2xx` is delivered (`mailer.service.ts:280-284`). Anything else fails the
  send with an error that names the status and nothing else: the response body is
  discarded unread and the API key never appears in an error.
- The request is bounded by a 10-second client unless `MailerConfig.Client` is set.

`MailerConfig` carries the reference's key names as JSON tags, so a deployment that
already holds an `email.mailer` block for the reference can decode it and hand it
over. `DefaultLang` is carried but not read by the transport: which template set a
mail is rendered from is the mailers' `Locale`.

The older `HTTPMailerTransport` (0.3.0) sends a different body under
`X-Mailer-Secret` and is deprecated; it keeps working for gateways built against it.

### Delivery webhook

`DeliveryWebhook` is one sender for all five seams. Instead of rendering a template
and handing mail to a transport, it `POST`s the delivery itself — credential
included — to a URL you own, and whatever answers there decides how the message
reaches the recipient. It exists for a transport that is neither mail nor SMS, or
that is not reachable from this process; the consumer's `email.deliveryWebhook.url`
knob points at it.

```go
hook, err := auth.NewDeliveryWebhook("https://hooks.example.com/auth-delivery", secret)
a, err := auth.New(
    auth.WithMagicLinkSender(hook.SendMagicLink),
    auth.WithPasswordResetSender(hook.SendPasswordReset),
    auth.WithEmailVerificationSender(hook.SendEmailVerification),
    auth.WithEmailChangeSender(hook.SendEmailChange),
    auth.WithSMSCodeSender(hook.SendSMSCode),
)
```

```go
type DeliveryWebhook struct {
    URL     string        // absolute http(s) URL; NewDeliveryWebhook validates it
    Secret  string        // signs the body when set; never sent
    Timeout time.Duration // per request, through ctx; NewDeliveryWebhook sets 5s
    Client  *http.Client  // nil = http.DefaultClient
}
```

> **This request shape is this port's own.** The reference's send callbacks
> (`config.email.sendMagicLink`, `sendPasswordReset`, …) are in-process functions
> that never cross HTTP, so there is no reference wire to reproduce: the body below
> is an invention of this port. The envelope — headers and signature — is borrowed
> from the family's outbound-webhook convention
> (`src/tools/webhook-sender.ts:24-33`, `54-56`), so a receiver that already
> verifies the tools router's webhooks verifies these the same way.

One request per delivery: `POST <URL>` with `Content-Type: application/json` and

| Header | Value |
|--------|-------|
| `X-Webhook-Event` | `delivery.<kind>` — `delivery.magic-link`, `delivery.sms-code`, … |
| `X-Webhook-Delivery` | a fresh UUID per request |
| `X-Webhook-Timestamp` | when it was sent: ISO 8601, UTC, milliseconds — `2026-09-11T10:00:00.000Z` |
| `X-Webhook-Signature` | `sha256=<hex HMAC-SHA256 of the raw body, keyed by Secret>` — only when `Secret` is set |

The body is `{"kind": "<kind>", "delivery": {…}}`, where `delivery` is the matching
delivery struct in camelCase, fields in this order:

| `kind` | `delivery` |
|--------|------------|
| `magic-link` | `userId`, `tenantId`, `email`, `token`, `expiresAt` |
| `password-reset` | `userId`, `tenantId`, `email`, `token`, `expiresAt` |
| `email-verification` | `userId`, `tenantId`, `email`, `token`, `expiresAt` |
| `email-change` | `userId`, `tenantId`, `newEmail`, `token`, `expiresAt` — addressed to the new mailbox |
| `sms-code` | `userId`, `tenantId`, `phone`, `code`, `expiresAt` |

The four link-carrying kinds also carry `linkBase` and `lang` when the request
resolved them (see "Per-request link base and language" below); both are omitted
when empty, so a receiver must not rely on their presence.

```json
{"kind":"magic-link","delivery":{"userId":"usr_…","tenantId":"t1","email":"ada@example.com","token":"…","expiresAt":"2026-09-11T10:15:00Z"}}
```

`token` and `code` are the plaintext credential — the store holds only its hash — so
the receiver is trusted exactly as a sender callback is: set a `Secret` and verify
the signature before acting, with `VerifyWebhookSignature(secret, rawBody,
r.Header.Get("X-Webhook-Signature"))` in Go. `expiresAt` is RFC 3339. The
`DeliveryKind*` constants and `DeliveryWebhookRequest{Kind string; Delivery
json.RawMessage}` name the same vocabulary for a receiver written in Go: decode the
envelope, switch on `Kind`, unmarshal `Delivery` into the matching struct.

Any `2xx` answer is delivered. Anything else, a transport failure or the timeout is
an error, and the route then behaves per the seam it was wired to — the generic
`500` on `/magic-link/send`, `/sms/send`, `/send-verification-email` and
`/change-email/request`; the unconditional `200` on `/forgot-password`. There is no
retry: a route is waiting on the answer, and the stored credential expires on its
own. The error names the kind, the status and, for mail, the recipient's domain; it
never carries the token, the code, the full address or the secret, because it is
logged and inspected further than the request ever travels.

### Per-request link base and language

The reference builds every emailed link from the request that asked for it, and
so do the four adapters. Each delivery that carries a link — `MagicLinkDelivery`,
`PasswordResetDelivery`, `EmailVerificationDelivery`, `EmailChangeDelivery` —
has two extra members:

```go
LinkBase string // e.g. "https://app.example.com/auth"; "" when no site URL is configured
Lang     string // the request's emailLang body field, untouched; "" when omitted
```

`LinkBase` is resolved in three steps, each a transcription of the reference:

| Step | Export | Reference |
|------|--------|-----------|
| The site URL for the request: the `Origin` header if allowlisted, else the `Referer`'s origin if allowlisted, else the default | `(*Auth).ResolveSiteURL(r *http.Request) string` | `resolveSiteUrl`, `auth.router.ts:233-246` |
| The allowlist: `Config.SiteURLs` then `OAuthWiring.AllowedOrigins`, deduplicated in order; the default: `SiteURLs[0]`, or `OAuthWiring.SiteURL` when that is set | `Config.SiteURLs`, `WithSiteURLs(urls ...string)` | `buildAllowedOrigins` `:213-219`, `getDefaultSiteUrl` `:202-206` |
| The base under that site URL: `<siteURL><prefix>`, or `<siteURL><prefix>/ui` with `HTTPConfig.UIEnabled` | `(HTTPConfig).LinkBase(siteURL) string`; the general form is `(HTTPConfig).UILink(siteURL, path) string` | `buildUiLink` `:261-271`, `magic-link.strategy.ts:25-27` |

```go
a, err := auth.New(
    auth.WithSiteURLs("https://www.example.com", "https://app.example.com"),
    auth.WithPasswordResetSender(auth.NewPasswordResetMailer(transport, "Example App", "https://www.example.com/auth").Send),
)
cfg := auth.DefaultHTTPConfig()
cfg.UIEnabled = true // links point at <site>/auth/ui/… instead of <site>/auth/…
nethttp.MountWithConfig(mux, a, cfg)
```

With that, a `POST /auth/forgot-password` carrying `Origin: https://app.example.com`
mails `https://app.example.com/auth/ui/reset-password?token=…`; one from an origin
that is not in the list, or with no `Origin` at all, mails the link under
`https://www.example.com`. Matching is exact — no trailing-slash or case
normalisation — as the reference's `includes` is. The same allowlist and default
serve the OAuth redirect and the `/link-request` link, so `OAuthWiring.SiteURL`
becomes optional: leave it empty and the OAuth routes fall back to `SiteURLs[0]`.

**Precedence in the built-in mailers.** A delivery's `LinkBase` wins over the
mailer's `BaseURL`; its `Lang` wins over the mailer's `Locale` when it is `it` or
`en`, and anything else — including an omitted `emailLang` — defers to `Locale`
(`resolveLang`, `mailer.service.ts:255-259`). With no `SiteURLs` configured the
adapters set no `LinkBase`, so a deployment built on a static `BaseURL` keeps
mailing exactly the links it did. A custom sender reads the two members directly:
`auth.PasswordResetURL(d.LinkBase, d.Token)` is the reference's link when
`LinkBase` is set.

The service inputs carry the same two members (`ForgotPasswordInput`,
`EmailVerificationInput`, `ChangeEmailRequestInput`, `MagicLinkSendInput`) and
copy them onto the delivery untouched; a caller driving the service directly
supplies them or leaves them empty.

---

## OIDC IDP

The `IDP` type turns awesome-go-auth into a full OIDC Identity Provider.

### `NewIDP(cfg IDPConfig, authSvc *Service, clients ...IDPClient) (*IDP, error)`

Resolves the signing key (`IDPConfig.Signer`, or an ephemeral RSA-2048 key with
a one-time warning), the `kid` and the code store, and refuses a signer whose
public key is not RSA.

### `IDPConfig`

```go
type IDPConfig struct {
    Issuer          string
    AccessTokenTTL  time.Duration // IdP pair: 0 → 30 days
    IDTokenTTL      time.Duration // 0 → 1 hour
    Signer          crypto.Signer // nil → ephemeral RSA-2048 + one warning
    KeyID           string        // "" → DefaultIDPKeyID, "provisioner-key-1"
    PublicKeys      []JWK         // further keys published after Signer's
    RefreshTokenTTL time.Duration // IdP pair: 0 → 90 days
    Logger          func(format string, args ...any) // nil → the Service's
    Codes           AuthCodeStore // nil → NewMemoryAuthCodeStore()
    CodeTTL         time.Duration // 0 → 5 minutes
    JWKSPath        string        // "" → DefaultJWKSPath, "/.well-known/jwks.json"
    JWKSCORSOrigins []string      // nil → "*"
    JWKSURL         string        // "" → Issuer + JWKSPath, for jwks_uri
}
```

### Signing key

`Signer` is any `crypto.Signer` whose public key is RSA. The reference's
configuration is a PEM private key (`idProvider.privateKey`,
`token.service.ts:47`); here that is

```go
key, err := auth.ParseRSAPrivateKeyPEM(os.Getenv("IDP_PRIVATE_KEY")) // PKCS#8 or PKCS#1
idp, err := auth.NewIDP(auth.IDPConfig{Signer: key, KeyID: "prod-2026-09"}, svc, clients...)
```

A signer that keeps the private key elsewhere — AWS KMS, an HSM, another
process — plugs in the same way. `BuildRS256JWT` asks it for exactly one thing
per token: `Sign(rand.Reader, digest, crypto.SHA256)` with the 32-byte SHA-256
of `base64url(header).base64url(claims)`, and uses the bytes it returns as the
signature. RS256 is RSASSA-PKCS1 v1.5 over SHA-256, so the signer must answer
with that (KMS: `RSASSA_PKCS1_V1_5_SHA_256` on a `DIGEST` request), and its
`Public()` must return the matching `*rsa.PublicKey`, which is what the JWKS
document publishes.

With no `Signer` the IDP generates an RSA-2048 key in `NewIDP` and logs, once,
the reference's warning (`token.service.ts:52-57`): `auth: IdP mode: no Signer
configured — auto-generating an ephemeral RSA keypair. All tokens will be
invalidated on restart. Set IDPConfig.Signer in production.` The warning goes
to `IDPConfig.Logger`, else to the `Config.Logger` of the Service. Every token
becomes unverifiable on restart and two processes never share a key:
development only.

`KeyID` is the `kid` in the header of every signed token and in the JWKS entry
for `Signer`; empty means `DefaultIDPKeyID`, the reference's constant
`provisioner-key-1` (`token.service.ts:78`). `PublicKeys` are further `JWK`s
published after the signer's, unchanged — the previous key during a rotation,
so that tokens it signed stay verifiable until they expire. Nothing signs with
them or checks them.

### JWKS types and RS256 builders

```go
type JWK struct {
    Kty string `json:"kty"` // "RSA"
    Use string `json:"use"` // "sig"
    Alg string `json:"alg"` // "RS256"
    Kid string `json:"kid"`
    N   string `json:"n"`   // unpadded base64url, big-endian
    E   string `json:"e"`
}

type JWKS struct {
    Keys []JWK `json:"keys"`
}

func NewRSAJWK(pub *rsa.PublicKey, kid string) (JWK, error)
func (idp *IDP) JWKS() JWKS
func ParseRSAPrivateKeyPEM(pemText string) (*rsa.PrivateKey, error)
func BuildRS256JWT(signer crypto.Signer, kid string, claims map[string]any) (string, error)
```

`JWK` is the reference's interface (`jwks.service.ts:5-12`), `NewRSAJWK` its
`publicKeyToJwk` (`:168-179`; a nil key, or one with no modulus, is an error
rather than a panic, since the key was obtained elsewhere), and `JWKS()` its
`buildJwksDocument` (`:184-186`) followed by `PublicKeys`:
`{"keys":[<signer key>, <PublicKeys>...]}`, which is what the JWKS endpoint
serves. `BuildRS256JWT` is the JWS compact serialisation with header
`{"alg":"RS256","typ":"JWT","kid":<kid>}`, usable on its own by a host that
signs something else with the same key; like `NewIDP`, it refuses a signer
whose `Public()` is not an `*rsa.PublicKey` before asking it to sign.

### The JWKS endpoint — `GET <prefix>/.well-known/jwks.json`

```go
func WithIDP(idp *IDP) Option
func (a *Auth) IDP() *IDP
func (a *Auth) JWKSHandler() http.Handler   // nil without WithIDP
func (idp *IDP) JWKSHandler() http.Handler
func (idp *IDP) JWKSPath() string

const DefaultJWKSPath = "/.well-known/jwks.json"
```

`auth.WithIDP(idp)` registers the IdP on the `Auth`, and that is the whole
switch: every adapter — net/http, chi, gin and echo — then mounts
`GET <prefix><IDPConfig.JWKSPath>`, public and ahead of every middleware. The
reference registers the same route from the same condition, an `idProvider`
block carrying a key or `enabled` (`auth.router.ts:473-475`); without `WithIDP`
the route is not mounted and the path answers 404 like any other.

The same switch mounts the four OIDC endpoints beside it — discovery,
`authorize`, `token` and `userinfo`. Those are this port's own, not the
reference's; see "The OIDC endpoints" below.

Because `NewIDP` wants a `*Service` and `New` is what produces one, build the
IdP with a nil Service and let the `Auth` adopt it:

```go
key, _ := auth.ParseRSAPrivateKeyPEM(os.Getenv("IDP_PRIVATE_KEY"))
idp, _ := auth.NewIDP(auth.IDPConfig{Issuer: "https://api.example.com/auth", Signer: key}, nil)
a, _ := auth.New(auth.WithUserStore(store), auth.WithIDP(idp))
nethttp.Mount(mux, a) // GET /auth/.well-known/jwks.json is now served,
                      // and so are /auth/authorize, /auth/token, /auth/userinfo
                      // and /auth/.well-known/openid-configuration
```

An `IDP` that already carries a different `Service` — one you constructed
yourself, or one a previous `auth.New` already bound — is refused, and `New`
returns `auth: WithIDP: the IDP is already bound to another Service`. Adopting
it would leave `/token` and `/userinfo` answering from that other Service's user
store while this `Auth`'s routes answered from this one, and rebinding an `IDP`
that may already be serving requests is a data race besides. Build a second
`IDP` for a second `Auth`.

**Path.** `IDPConfig.JWKSPath` is the reference's `idProvider.jwksPath`
(`auth.router.ts:475`), relative to the mount prefix; empty means
`DefaultJWKSPath`. `NewIDP` refuses a path the four adapters and
`RegisterHandlers` cannot all route as the same literal path: it must start with
`/` — the value is concatenated onto the prefix, and a relative one would mount
`<prefix>jwks.json` — and must not end with one (a subtree pattern in net/http,
a literal segment in chi), must not contain `{`, `}`, `?`, `#` or `//`, and must
not collide with one of the four OIDC endpoints (`/authorize`, `/token`,
`/userinfo`, `/.well-known/openid-configuration`), which would panic in
`http.ServeMux` at mount time.

**Cache.** Every answer carries `Cache-Control: public, max-age=3600`
(`auth.router.ts:502`). A relying party fetches the document once per key
rotation, not once per token.

**CORS.** `IDPConfig.JWKSCORSOrigins` is the reference's `jwksCorsOrigins`
(`auth.router.ts:492-500`):

| `JWKSCORSOrigins` | Request `Origin` | `Access-Control-Allow-Origin` |
|---|---|---|
| `nil` (default) | anything, or absent | `*` |
| `{"*"}` (exactly one entry) | anything, or absent | `*` |
| `{"https://app.example.com"}` | `https://app.example.com` | `https://app.example.com` |
| `{"https://app.example.com"}` | anything else, or absent | *no header* |
| `{"https://app.example.com", "*"}` | `https://app.example.com` | `https://app.example.com` |
| `{"https://app.example.com", "*"}` | anything else | *no header* |
| `[]string{}` | anything | *no header* |

The document is served in every row: CORS bounds what a browser script may read,
not what the server answers, and the reference refuses nothing on this route.

The reference's type is `string | string[]`, and only its string form is the
wildcard — the test is `corsOrigins === '*'` against the whole value
(`auth.router.ts:493`). Every array there is an allowlist, so an entry `*`
inside one is an ordinary entry matching only an `Origin` header of literally
`*`, which no browser sends. Go has no such union, so the one-element slice
`{"*"}` stands in for the string form; that single value is the only
configuration reading differently from the reference, and it is registered as
the `jwks-cors-wildcard-string-form` deviation in README.md. A deployment that
means the reference's never-matching `['*']` writes the empty slice
`[]string{}`.

Neither the reference nor this port sends `Vary: Origin`, while both send
`Cache-Control: public, max-age=3600` (`auth.router.ts:492-502`). An allowlisted
response therefore must not reach a shared or CDN cache, which would store one
origin's header and replay it to another, or store the header-less variant and
break the allowlisted origin: front an allowlist with a private cache, or leave
`JWKSCORSOrigins` nil so every origin may read the document.

**Methods.** `GET` only, as in the reference (`router.get`,
`auth.router.ts:490`). `HEAD` is served from the same handler, which is
Express's own fallback from `HEAD` to the `GET` handler and net/http's for a
`GET` pattern; chi, gin and echo do not do it themselves, so the adapters
register `HEAD` explicitly there. Any other method misses the route; the status
is the router's own — 405 on net/http, chi and echo, 404 on gin. (Express
answers `OPTIONS` itself with 200 and an `Allow` header when the path has a
route; this port does not, and no CORS preflight reaches the route anyway, since
a JWKS fetch is a simple request.)

**Documenting it.** `GenerateOpenAPISpec` adds the path when
`OpenAPIInfo.IDProvider` is set, at `OpenAPIInfo.JWKSPath` (empty →
`DefaultJWKSPath`); leave the flag false for a deployment with no IdP, or the
document advertises an endpoint that answers 404.

### `(*IDP).IssueIdPTokenPair(ctx context.Context, user User) (AuthTokens, error)`

The reference's `generateIdProviderTokenPair` (`token.service.ts:73-95`): an
RS256 access token and an RS256 refresh token under `KeyID`, both carrying the
same payload — the six base claims (`sub`, `email`, `role`, `loginProvider`,
`isEmailVerified`, `isTotpEnabled`) with `Config.BuildTokenClaims` spread over
them, the hook's `iat`, `exp` and `kid` dropped, `iss` from `IDPConfig.Issuer`
when that is set and otherwise absent — and differing only in lifetime:
`AccessTokenTTL`, 30 days by default; `RefreshTokenTTL`, 90 days by default.
`ExpiresIn` is the access lifetime.

The reference resolves the refresh lifetime in three steps —
`idProvider.refreshTokenExpiry ?? config.refreshTokenExpiresIn ?? '90d'`
(`token.service.ts:91`) — and the middle one is not reproduced:
`IDPConfig.RefreshTokenTTL` never falls back to `Config.RefreshTokenTTL`.
`Config.RefreshTokenTTL` is always set here (`DefaultConfig` fills it and
`validate` requires it), so honouring it would make the 90-day default
unreachable and tie the IdP pair silently to the session lifetime.

It is a host-level API, exactly as in the reference, where nothing calls
`generateIdProviderTokenPair` (reference-issues N35): `/login`, `/refresh` and
the OIDC `token` endpoint keep issuing the HS256 session pair, and constructing
an `IDP` changes nothing about them. Accordingly the `token` endpoint reports
`expires_in` as the lifetime of the access token it returns,
`Config.AccessTokenTTL`; `IDPConfig.AccessTokenTTL` governs only the IdP pair.
No session is created and no `sid` is written, so an IdP pair cannot be revoked
before it expires. Which pair the `token` endpoint returns is a pending design
decision (upstream plan D-15).

### Authorization-code storage

Codes issued by `authorize` and redeemed by `token` live in an `AuthCodeStore`:

```go
type AuthCode struct {
    CodeHash                           string // hashToken of the code the client holds
    UserID, TenantID, ClientID, Nonce  string
    RedirectURI                        string
    CodeChallenge, CodeChallengeMethod string // recorded, not yet verified
    Scope                              string
    ExpiresAt                          time.Time
}

type AuthCodeStore interface {
    SaveCode(ctx context.Context, code AuthCode) error
    ConsumeCode(ctx context.Context, codeHash string) (AuthCode, error)
}
```

The contract, in full in the `AuthCodeStore` doc comment:

- The store never sees the code itself, only `hashToken(code)`; a leaked table
  cannot be replayed at `token`.
- `ConsumeCode` is destructive and single-use: it returns a record exactly once
  and `ErrInvalidCode` on every later call for the same hash, including
  concurrent ones. A shared implementation must make this atomic (conditional
  delete, row lock, `DEL`-and-check), not a read followed by a delete.
- An expired record is absent: `ConsumeCode` returns `ErrInvalidCode` and may
  drop it. `token` re-checks `ExpiresAt` regardless.

`IDPConfig.Codes` left nil selects `NewMemoryAuthCodeStore()`, an in-process
map behind a mutex that sweeps expired entries on each save. That is correct
only while `authorize` and `token` are served by the same process. **A
serverless runtime or any deployment with more than one instance must supply a
shared `AuthCodeStore`** (Redis, a database table, DynamoDB with a conditional
delete) or `token` answers `invalid_grant` for every code minted by a sibling
process.

`token` also refuses a code redeemed by a `client_id` other than the one it was
issued to, and consumes it in the process.

### `IDPClient`

```go
type IDPClient struct {
    ClientID, ClientSecret string
    RedirectURIs           []string
    Name                   string
}
```

### The OIDC endpoints

```go
type OIDCMount struct {
    Path    string       // below the mount prefix, leading "/" included
    Handler http.Handler // serves it, for every method
    // true for /authorize and /token: HTTPConfig.ResourceServer leaves those
    // two unmounted, the way it leaves /login and /refresh unmounted.
    ResourceServerGated bool
}

func (idp *IDP) OIDCMounts() []OIDCMount
func (idp *IDP) RegisterHandlers(mux *http.ServeMux, basePath string)

const (
    OIDCDiscoveryPath = "/.well-known/openid-configuration"
    OIDCAuthorizePath = "/authorize"
    OIDCTokenPath     = "/token"
    OIDCUserInfoPath  = "/userinfo"
)
```

`auth.WithIDP(idp)` is the whole switch for these four as well as for the JWKS
route: every adapter — net/http, chi, gin and echo — mounts them under the
configured prefix, public and ahead of every middleware, and the wiretest
conformance suite replays all four against all four adapters.

| Path | Description |
|------|-------------|
| `<prefix>/.well-known/openid-configuration` | OIDC discovery document, derived from `Issuer` |
| `<prefix>/authorize` | Authorization endpoint (GET = sign-in form, POST = credential check → 302 to the registered `redirect_uri` with `code` and `state`) |
| `<prefix>/token` | Token exchange (`authorization_code` grant, `client_secret_post`) |
| `<prefix>/userinfo` | `Authorization: Bearer` — `sub`, `email`, `name` |

Unlike `IDPConfig.JWKSPath` these paths are not configurable. They have no
counterpart in the reference — it ships no OIDC authorization server — so there
is nothing to track, and the discovery document derives the last three from
`Issuer` itself, so a second spelling would advertise one path and serve
another.

**Methods.** Every method reaches the handler, on all four adapters, because
that is what `RegisterHandlers` has always done with its method-less
`http.ServeMux` patterns and because the handlers discriminate themselves:
`authorize` reads `r.Method` to tell its form from its credential post, `token`
reads `grant_type` out of the form, `userinfo` reads the `Authorization`
header. So `GET <prefix>/token` is `400 unsupported_grant_type` from the
handler, not a 405 from the router. This is the one place the IdP surface
differs from the JWKS route, which is `GET` (and `HEAD`) only because the
reference registers it that way.

**Refusals are plain text.** These endpoints answer with `http.Error` — a
single-line `text/plain` body carrying the OAuth 2.0 error identifier
(`invalid_grant`, `invalid_client`, `unsupported_grant_type`, `unknown
client`, `redirect_uri not allowed`, `unauthorized`) — not the family's JSON
`{"error":…,"code":…}` envelope every other route in this library returns. They
are not routes a family client calls; a relying party is on the other end.

**Resource-server mode gates two of them.** `HTTPConfig.ResourceServer`
unmounts every route that creates or changes a credential, and
`<prefix>/authorize` and `<prefix>/token` are two such routes: `POST` on the
first reads an email, a password and a tenant off the form and hands them to
`Service.Login`, and `POST` on the second spends the resulting code for this
instance's own HS256 session pair. So the adapters skip them in that mode, the
way they skip `/login` and `/refresh`, and a deployment that set the flag to
unmount the credential routes cannot regain a password-accepting endpoint by
also building `WithIDP`. The discovery document and `<prefix>/userinfo` stay:
discovery is metadata like the JWKS document beside it, and `userinfo` reads a
bearer token and returns a profile, which is `GET /me`'s shape and stays for
`GET /me`'s reason (see [Resource server mode](#resource-server-mode)). The
flag travels on the mount as `OIDCMount.ResourceServerGated`, which is also
what `GenerateOpenAPISpec` reads when `OpenAPIInfo.OIDC` and
`OpenAPIInfo.ResourceServer` are set together. `RegisterHandlers` mounts all
four regardless: it is handed a mux with no `HTTPConfig` behind it, so the host
is choosing the surface itself.

**Documenting them.** `GenerateOpenAPISpec` adds the four paths when
`OpenAPIInfo.OIDC` is set, and the JWKS path when `OpenAPIInfo.IDProvider` is —
two flags, because a deployment may well want to publish its keys (the only
route a verifier calls) without advertising an authorization server. Leave them
false for a deployment with no IdP, or the document advertises endpoints that
answer 404.

#### `RegisterHandlers` — mounting them yourself

`(*IDP).RegisterHandlers(mux, basePath)` mounts the same four handlers, plus
the JWKS document at `basePath + JWKSPath()` and the deprecated `basePath/jwks`
alias of it, on a mux you own. Since the adapters mount the four themselves it
is no longer needed by a host that mounts an adapter; it stays for the host
that wants the OIDC endpoints somewhere else — under a different base path,
behind its own middleware — and for the one that uses the `IDP` without
mounting an adapter at all. `examples/gin-mongodb` is that shape.

**Do one or the other, not both.** Mounting an adapter *and* calling
`RegisterHandlers` with the adapter's prefix puts the same endpoints at the
same URLs twice, and what that costs depends on the router.

On a single `http.ServeMux` it is a mount-time panic — both registrations use
the same method-less pattern, so `ServeMux` reports the two as conflicting and
names both registration sites — which is deliberate: a pattern that did *not*
collide (`"GET <path>"` against the method-less one) would be accepted as the
more specific of the two, and the endpoint would end up split, `GET` answered
by one handler and every other method by the other. The JWKS route already
behaved this way; the four OIDC endpoints now do too.

On a chi, gin or echo host there is no such panic, because `RegisterHandlers`
takes a `*http.ServeMux` and the adapter mounted on a router of a different
kind: the two registries never meet, and the endpoints are simply served at two
URLs, each by its own copy. Nothing tells you; the second URL is the symptom.

The discovery document's `jwks_uri` points at the canonical path, not the alias.
It is derived as `Issuer` + `JWKSPath`, the convention every other endpoint in
that document already follows — they are all derived from `Issuer` alone — so
for the advertised URL to resolve, `Issuer` has to carry the mount prefix
(`https://api.example.com/auth`, not `https://api.example.com`).

**That choice is not free.** `IDPConfig.Issuer` is also the `iss` claim of every
token the IdP mints (`token.service.ts:74-77`), and the reference documents
`issuer` as a bare origin — its own example is `'https://auth.myplatform.com'`
(`auth-config.model.ts:77-81`). Moving the prefix into `Issuer` therefore
changes `iss` on every RS256 token and can break resource servers that validate
it. A deployment that must keep a bare `iss` leaves `Issuer` alone and sets
`IDPConfig.JWKSURL` to the absolute JWKS URL instead — that is also the setting
for an IdP reached through a gateway whose external URL is not `Issuer` plus the
mounted path. Note that `JWKSURL` patches `jwks_uri` only: `authorization_endpoint`,
`token_endpoint` and `userinfo_endpoint` have no equivalent override and stay
derived from `Issuer`.

Relying parties that read discovery follow the move on their own; one configured
by hand against `<base>/jwks` keeps working through the 0.x line and stops at
v1.0.0 (upstream plan D-13). Both JWKS patterns are registered `GET`-only, as
the reference registers the route and as the adapters mount it, so the alias's
methods narrow with this change: net/http answers `HEAD` from the `GET` pattern
and 405 to everything else.

ID tokens and IdP token pairs are RS256-signed JWTs built entirely from the
standard library through `BuildRS256JWT`, under `IDPConfig.Signer` and `KeyID`.

---

## Resource server mode

A *resource server* is the other side of the IdP: an API that owns no
credentials, holds no user database, and answers requests by verifying tokens
some other instance issued. It needs three things, and they are independent of
each other — a deployment may take any one without the others.

### 1. `ResourceServerConfig` and `JWKSClient`

```go
type ResourceServerConfig struct {
    JWKSURL      string        // https://auth.example.com/auth/.well-known/jwks.json
    Issuer       string        // expected iss; empty means the claim is not checked
    CacheTTL     time.Duration // 0 → DefaultJWKSCacheTTL (1 hour)
    FetchTimeout time.Duration // 0 → DefaultJWKSFetchTimeout (5 seconds)
    Client       *http.Client  // nil → a plain client of this package

    // 0 → DefaultJWKSMinRefreshInterval (30s); negative turns the limit off.
    MinRefreshInterval time.Duration
}

client := auth.NewJWKSClient(cfg)
key, err := client.GetKey(ctx, "provisioner-key-1") // *rsa.PublicKey
client.Invalidate()
doc, err := client.Document(ctx) // the whole JWKS
```

The cache is **stale-while-revalidate**, transcribed from the reference's
`JwksClient` (`jwks.service.ts:29-141`):

| state | what a read does |
| --- | --- |
| cached, inside the TTL | served from memory, no HTTP |
| a fetch already in flight | joined — a burst on a cold cache is **one** HTTP call |
| cached, past the TTL | the **stale** document is returned immediately and a refresh runs in the background |
| that background refresh fails | nothing changes: the stale document keeps serving |
| no cache at all | the caller waits for the fetch, and a failure is an error |

The last two rows are the point of the design. Once the cache is warm no
request ever waits on the issuer, and an issuer that is briefly unreachable
cannot take the resource server down with it. A fetch is never bound to the
request that triggered it, so cancelling a caller never poisons the cache;
each fetch runs under `FetchTimeout` of its own.

`NewJWKSClient` **panics** when `JWKSURL` is empty or is not an absolute
`http`/`https` URL. A resource server pointed at nothing cannot verify a single
bearer token, so the failure belongs at startup, where it is one line in a log,
rather than at the first request, where it looks like an authentication problem
and stays that way for the life of the process. The reference throws for the
same reason (`jwks-auth.middleware.ts:38-40`).

`JWK.RSAPublicKey()` converts a published key back into an `*rsa.PublicKey` —
the inverse of `NewRSAJWK`, and of the reference's `jwkToPublicKey`
(`jwks.service.ts:199-202`). It accepts only RSA signing keys: `kty` must be
`RSA`, and `alg`, when the document states one, must be `RS256`.

### 2. `VerifyRS256`

```go
claims, err := auth.VerifyRS256(ctx, token, client, cfg.Issuer)
```

The reference's `verifyWithJwks` (`token.service.ts:102-141`), step for step:

1. the header is decoded **without verifying**, only to read `kid`;
2. a token with no `kid` is refused;
3. the header `alg` must be `RS256` — an allow-list, so the `alg` a token
   advertises never selects the verification routine and neither `none` nor an
   HS256 token presented under a published `kid` gets anywhere. The reference
   applies the same pin inside `jwt.verify`, *after* the key lookup; here it
   runs before, so a junk token cannot cost an outbound request;
4. the key is looked up. If the cache does not carry that `kid`, the cache is
   invalidated and the lookup is retried **exactly once** — which is how a key
   rotated inside the TTL is picked up by the first request that needs it. A
   second miss is refused, and so is the first when the cached document is
   younger than `MinRefreshInterval`;
5. the signature is checked, and `exp` and `nbf` are honoured with no clock
   tolerance;
6. when `expectedIssuer` is set, `iss` must equal it, by plain string
   comparison.

**Rate limit on the rotation retry.** The reference invalidates and refetches on
every unknown `kid`, and its `invalidateCache` drops the in-flight fetch handle
too — so anyone who can reach the resource server can make it call the issuer
once per request by sending a random `kid`, uncoalesced, while every legitimate
request in the gap takes the cold path and blocks. This port refuses to re-drop
a document younger than `ResourceServerConfig.MinRefreshInterval`
(`DefaultJWKSMinRefreshInterval`, 30 seconds): the first unknown `kid` may
refetch, the rest are refused from memory. A real rotation is unaffected — the
cached document is typically an hour old by the time a token names a key it does
not carry — and a negative `MinRefreshInterval` restores the reference
behaviour. This is the `jwks-unknown-kid-refetch-is-rate-limited` deviation.

**Which failures are `INVALID_TOKEN`.** Every refusal of the *token* wraps
`ErrInvalidToken` and carries the reference's own message (`Invalid token
format`, `Token missing kid header`, `Unknown signing key`, `Invalid or expired
token`, `Token issuer mismatch`), so `HTTPErrorFor` maps it to 401 and a host
that logs the error logs what the reference logs. A failure to read the JWKS at
all does not: a transport error, a non-200 status and an unparseable document
come back from `GetKey` unwrapped, and `HTTPErrorFor` sends them to
`HTTPErrInternal` — an issuer outage is this server's 5xx, not the caller's bad
credential. `ResourceServerMiddleware` answers 401 either way, as the reference
does (its `catch` does not distinguish them either); only a host calling
`VerifyRS256` directly sees the difference, and it should.

The claims come back as the decoded payload, unchanged: this verifier does not
know what an issuer puts in its tokens, and a resource server is entitled to
read all of it.

### 3. `ResourceServerMiddleware`

```go
// net/http and chi
mux.Handle("GET /reports", nethttp.ResourceServerMiddleware(a, cfg)(reports))
r.With(chiadapter.ResourceServerMiddleware(a, cfg)).Get("/reports", reports)

// gin and echo
r.GET("/reports", ginadapter.ResourceServerMiddleware(a, cfg), reports)
e.GET("/reports", reports, echoadapter.ResourceServerMiddleware(a, cfg))
```

It is the reference's `createJwksAuthMiddleware`
(`jwks-auth.middleware.ts:44-79`):

- `Authorization: Bearer <token>` → verified against the remote JWKS (RS256);
- otherwise the access-token cookie (`__Host-` → `__Secure-` → bare) → verified
  the **local** HS256 way, against this instance's own secret, because a cookie
  session belongs to this instance. The reference keeps this path for the
  dashboard that hosts the resource server;
- neither → `403 {"error":"No access token provided"}`, code-less;
- any verification failure → `401 {"error":"Invalid or expired access token",
  "code":"INVALID_TOKEN"}` — the `HTTPErrInvalidTokenRS` catalog entry.

**Neither path reads a store.** The cookie is checked the way the reference
checks it — `tokenService.verifyAccessToken`, a bare `jwt.verify` against the
HS256 secret (`token.service.ts:143-150`, called at
`jwks-auth.middleware.ts:70-73`) — and *not* through `Auth.Authenticate`, which
the session `Middleware` uses and which reads `users.GetUserByID` and checks the
session for revocation. That difference is the whole point here: a resource
server has no user table for `Authenticate` to read, so routing the cookie
through it would 401 every SSR request on the deployment this mode exists for.
Two consequences, both the reference's:

- a cookie whose subject this instance has no record of is **accepted** — the
  token is the principal;
- a **revoked** session is accepted until its access token expires. This
  middleware cannot emit `SESSION_REVOKED`; a deployment that wants revocation
  checked on every call mounts the session `Middleware`, which is the one with a
  database behind it.

The signature, the `HS256` allow-list, `iss`, `typ` and `exp` are all still
checked, so a refresh token, a token signed with another secret and a tampered
token are refused. (`typ` is checked where the reference relies on a second
secret: it signs refresh tokens with `refreshTokenSecret`, this port signs both
with `Config.Secret` and tells them apart by `typ`.)

**Which credential is used is decided by the header prefix**, not by what
follows it, exactly as the reference decides it (`startsWith('Bearer ')`,
`jwks-auth.middleware.ts:49-59`). So `Authorization: Bearer ` with an empty
token is a bearer request with no token — the code-less 403 — even when a valid
cookie is present; and the scheme match is case-sensitive, so `authorization:
bearer x` falls through to the cookie. `BearerToken` is deliberately not used
here: it trims and matches case-insensitively, which would turn both of those
into different answers.

**What the user context carries.** No store is read on either path: the token
*is* the user record, which is the whole point of the mode. The same mapping
serves both — the bearer claims come from the issuer, the cookie claims from
this instance's own mint, and both carry the same base set.
`UserFromRS256Claims` fills

| `User` field | claim |
| --- | --- |
| `ID` | `sub` |
| `Email` | `email` |
| `Role` | `role` |
| `LoginProvider` | `loginProvider` |
| `IsEmailVerified` | `isEmailVerified` |
| `IsTOTPEnabled` | `isTotpEnabled` |
| `TenantID` | `tid` |

— the reference's six base payload claims (`auth.router.ts:378-384`) plus the
tenant this port writes, and **`CustomClaims` carries the entire verified
payload**, so a scope or permission claim an issuer adds reaches the handler.
Every store-only field is zero: no `PasswordHash`, no `Roles`, no
`Permissions`, no `Tenants`, no `CreatedAt`. A handler that needs those reads
its own store. A mistyped claim reads as absent rather than panicking — the
token comes from another service, and this one does not get to assume its shape.

The principal reaches the handler through the adapter's own `UserFromContext`,
exactly as it does behind `Middleware`. `ResourceServerPrincipal(r, a, client,
issuer)` exposes the same decision for a framework this repository does not
ship.

One `JWKSClient` is built per `ResourceServerMiddleware` call, so the key cache
is shared by every request through that middleware. A host that mounts several
against one issuer and wants a single cache builds the client once with
`NewJWKSClient` and wraps `ResourceServerPrincipal` itself.

### 4. `HTTPConfig.ResourceServer` — unmounting the credential routes

```go
cfg := auth.DefaultHTTPConfig()
cfg.ResourceServer = true
nethttp.MountWithConfig(mux, a, cfg)
```

The adapters then register **none** of the nineteen routes that mint, deliver or
consume a credential, so each answers `404` from the router:

```
POST   /register                   POST   /magic-link/send
POST   /login                      POST   /magic-link/verify
POST   /refresh                    POST   /sms/send
POST   /logout                     POST   /sms/verify
POST   /forgot-password            POST   /2fa/setup
POST   /reset-password             POST   /2fa/verify-setup
POST   /change-password            POST   /2fa/verify
POST   /send-verification-email    POST   /2fa/disable
GET    /verify-email
POST   /change-email/request
POST   /change-email/confirm
```

`ResourceServerGatedRoutes()` returns that list (a fresh map each call).
`OpenAPIInfo.ResourceServer` drops the same nineteen **operations** from
`GenerateOpenAPISpec` — the method, not the whole path item, so a path that ever
gains a second, ungated method keeps it — and the published spec and the mount
then agree. Set the two together.

What stays mounted is `GET /me`, the session routes, `PATCH /profile`,
`POST /add-phone`, `DELETE /account`, and the whole OAuth and account-linking
group. On an `Auth` built `WithIDP`, the JWKS route, `<prefix>/userinfo` and
`<prefix>/.well-known/openid-configuration` stay too — and `<prefix>/authorize`
and `<prefix>/token` do not, because those two take a password and mint a
session pair; see [The OIDC endpoints](#the-oidc-endpoints). They are not in
`ResourceServerGatedRoutes()`, which is the base surface's list and does not
know about an IdP; `OIDCMount.ResourceServerGated` names them instead.

> **Those survivors still need a local user store.** `/me` reads it through
> `Service.Authenticate` → `users.GetUserByID`; `/profile`, `/add-phone` and
> `/account` read *and write* it; and `GET /oauth/{provider}/callback` provisions
> a user and mints a local session, which is a credential this list otherwise
> gates. They stay because the reference mounts them, and because the deployment
> that has both a user store and a remote issuer — the commoner one — uses them.
> **`HTTPConfig.ResourceServer` is about credentials, not about store
> independence.** The store-less deployment is the one that mounts
> `ResourceServerMiddleware` on its own routes, whose two paths read no store at
> all; such a deployment should not be mounting the auth router's account routes
> in the first place, and gating them here would take them away from the
> deployment that can serve them.

> **Deviation.** The reference guards six registrations on `isResourceServer` —
> `/login`, `/logout`, `/refresh`, `/register`, `/forgot-password`,
> `/reset-password` (`auth.router.ts:510`, `:541`, `:590`, `:622`, `:713`,
> `:777`, `:802`) — and leaves the other thirteen mounted over a database it has
> just declared absent. This port gates all nineteen; see
> `resource-server-gates-all-credential-routes` in the README's deviations
> section. To match the reference exactly, leave `ResourceServer` unset and use
> the middleware alone.

---

## MCP Server (out of parity scope)

### `NewMCPServer(authSvc *Service) *MCPServer`

### `(*MCPServer).ServeHTTP(w, r)`

Implements `http.Handler`. Handles JSON-RPC 2.0 POST requests.

**Supported methods:**
- `tools/list` — returns available tool descriptors
- `tools/call` — executes a named tool

**Available tools:**
| Tool | Description |
|------|-------------|
| `auth_get_config` | Returns issuer, TTLs, feature flags. `require_2fa` is the static `Config.Require2FA`; `require_2fa_effective` is the policy `/2fa/disable` enforces (that term OR the stored `require2FA`), omitted when the settings store cannot be read |
| `auth_register` | Registers a new user |
| `auth_login` | Authenticates a user |
| `auth_create_tenant` | Creates a tenant |
| `auth_create_role` | Creates a role with permissions |

---

## OpenAPI

### `GenerateOpenAPISpec(info OpenAPIInfo) map[string]any`

Returns an OpenAPI 3.0.3 spec as a `map[string]any` (JSON-serializable).

```go
type OpenAPIInfo struct {
    Title, Description, Version, ServerURL string
    APIPrefix string // must match the mount; empty means DefaultAPIPrefix ("/auth")
    ResourceServer bool // must match HTTPConfig.ResourceServer
    IDProvider bool     // add the JWKS route     — set it when the Auth was built WithIDP
    JWKSPath   string   // where it is served; must match IDPConfig.JWKSPath
    OIDC       bool     // add the four OIDC ones — set it when the Auth was built WithIDP
    Docs bool // must match HTTPConfig.Docs.Enabled
}
```

Serve as JSON:
```go
spec := auth.GenerateOpenAPISpec(auth.OpenAPIInfo{
    Title:     "My API",
    ServerURL: "https://api.example.com",
    APIPrefix: auth.DefaultAPIPrefix,
})
json.NewEncoder(w).Encode(spec)
```

The spec describes exactly the operations the adapters mount — the current
envelope, the per-route error catalog entries, the `X-Auth-Strategy` and
`X-CSRF-Token` headers, and both the bearer and cookie security schemes. Set
`APIPrefix` to whatever you passed to `MountWithConfig`; a mismatch documents
paths the server does not serve. Set `ResourceServer` to whatever you passed as
`HTTPConfig.ResourceServer`: it drops the nineteen credential operations the adapters
then leave unmounted (see [Resource server mode](#resource-server-mode)). Set
`IDProvider` and `OIDC` when the `Auth` was built `WithIDP`: they add the JWKS
route and the four OIDC endpoints the adapters then mount — `ResourceServer`
alongside `OIDC` drops `/authorize` and `/token` again, because the adapters do
not mount those two in that mode (see
[The OIDC endpoints](#the-oidc-endpoints)). The
wire conformance suite replays every documented operation against every adapter,
so a route added without a spec entry (or a spec entry with no route) fails the
build — and a route the configuration unmounts must vanish from both.

### Serving it — `HTTPConfig.Docs`

The reference's auth router mounts two documentation routes of its own
(`auth.router.ts:1652-1677`), and so do all four adapters, under one flag:

```go
type DocsOptions struct {
    Enabled  bool   // mount GET <prefix>/openapi.json and GET <prefix>/docs
    BasePath string // where the document says they are; empty = the mount prefix
}

cfg := auth.DefaultHTTPConfig()
cfg.Docs.Enabled = os.Getenv("APP_ENV") != "production"
nethttpadapter.MountWithConfig(mux, a, cfg)
```

| Route | Answers |
| --- | --- |
| `GET <prefix>/openapi.json` | `GenerateOpenAPISpec` for this mount, as `application/json` |
| `GET <prefix>/docs` | the reference's Swagger UI page, as `text/html; charset=utf-8` |

Neither has an auth gate — the reference registers both with no guard of their
own — so a reader fetches either with no credential of any kind. Both do sit
behind the CSRF middleware, because in the reference they are registered after
the router-level CSRF auto-init (`auth.router.ts:529-538`) and Express applies
every earlier `router.use` layer to a route registered later. On a `GET` that
middleware rejects nothing: all it does is hand a reader arriving without a
`csrf-token` cookie a fresh one, exactly as the reference does. Both routes are
absent with `Docs.Enabled` unset: a request for either answers `404`.

Enabling `GET <prefix>/docs` is a security decision, not just a convenience: the
page is the reference's, so it loads `swagger-ui-dist@5` from the unpkg CDN with
no subresource integrity, and that script then runs on the auth origin, where
the CSRF cookie is readable from JavaScript by design. Keep the route off in
production, or serve it behind a `Content-Security-Policy` that pins the CDN.

`Docs.Enabled` is a `bool` where the reference's option is `boolean | 'auto'`
and defaults to `'auto'`, meaning enabled unless `NODE_ENV` is `production`.
Resolving an ambient environment is the host's job here — the one line above is
the whole of it — and the resulting difference in default is registered as
`docs-routes-are-opt-in`.

`Docs.BasePath` is the reference's `swaggerBasePath`: it moves the description,
never the mount. The routes are always served at `HTTPConfig.Prefix()`, because
that is where the adapter is; the base path is the prefix the served document
writes its paths under, and the base of the URL the Swagger UI page fetches.
Empty means the mount prefix, which is what you want unless a proxy makes the
API reachable from outside under some other path.

The document a mount serves describes its own two paths, which is
`OpenAPIInfo.Docs` — set for you by the adapter. The wire conformance suite
compares the document to the mounted routes in both directions on all four
adapters, so neither of these can quietly drop out of it.

### `OpenAPIHandler(info OpenAPIInfo) http.Handler`

Serves `GenerateOpenAPISpec(info)` as `application/json`. The document is built
once, at construction: it is a pure function of `info`, and `encoding/json`
writes map keys in sorted order, so every response is the same bytes.

### `SwaggerUIHandler(specURL string) http.Handler`

Serves the reference's Swagger UI page for the document at `specURL`, as
`text/html; charset=utf-8`. The page is `buildSwaggerUiHtml`
(`openapi.ts:1646-1669`) byte for byte: the same markup, and the same
`swagger-ui-dist@5` bundles from the unpkg CDN. That CDN is the reference's
choice, and reproducing it rather than improving on it is the point — a
deployment that cleared the reference's page with its own content policy gets
the same page here. An empty `specURL` means the reference's own default,
`./openapi.json`.

Mounting with `Docs.Enabled` wires both of these for you; call them directly
only when you serve the document from a route of your own.
`(*nethttp.Adapter).OpenAPIHandler` and `.SwaggerUIHandler` build them from the
mount, and `(*nethttp.Adapter).OpenAPIInfo()` returns the `OpenAPIInfo` that
describes it — the value to start from in that case. Its `IDProvider`,
`JWKSPath` and `ResourceServer` are read off the mount and cannot disagree with
it; its `APIPrefix` is the documented base path, which is the mount prefix
unless `Docs.BasePath` moved the description.

---

## Embedded UI

### `GET <prefix>/ui/config`

The document the built-in UI fetches before it renders anything: where the API
is mounted, which features to offer, how to paint itself, which language to
speak, and whether the pages exist at all. It is the reference's
`ui.router.ts:95-170`, and it is mounted by all four adapters when the wire
configuration enables the UI:

```go
cfg := auth.DefaultHTTPConfig()
cfg.UI = auth.UIOptions{
    Enabled:     true,
    DefaultLang: "it",
    CustomCSS:   ":root { --radius: 4px }",
    Branding: auth.UIBranding{
        PrimaryColor: "#4a90d9",
        SiteName:     "Acme",
        CustomLogo:   "https://cdn.acme.test/logo.svg",
    },
}
nethttpadapter.MountWithConfig(mux, a, cfg)
```

That one flag mounts the whole of the reference's UI router at `<prefix>/ui`,
not just this route — the HTML pages with the SSR config injection, the static
assets and the uploaded logos come with it. See
[The hosted UI](#the-hosted-ui-prefixui) below; `UIOptions.Assets` and
`UIOptions.Uploads` are where the last two read from.

The route itself is served by the same handler it has been since v0.7.0, reached
through that mount rather than registered separately, which is where the
reference has it too.

The route is public — the login page fetches it before any session exists — and
answers `200` with these six keys, in this order:

```json
{
  "apiPrefix": "/auth",
  "features": {
    "register": true, "magicLink": true, "sms": false, "google": true,
    "github": false, "forgotPassword": true, "verifyEmail": false, "twoFactor": true
  },
  "ui": {
    "primaryColor": "#4a90d9", "secondaryColor": "#6c757d",
    "logoUrl": "https://cdn.acme.test/logo.svg", "siteName": "Acme",
    "customCss": ":root { --radius: 4px }"
  },
  "translations": { "signIn": "Accedi" },
  "lang": "it",
  "headless": false
}
```

**`features`** says what this deployment can actually do, so it is derived from
the wiring rather than configured:

| Key | True when | Reference |
| --- | --- | --- |
| `register` | always — this port always mounts `POST <prefix>/register`, where the reference mounts it only with an `onRegister` hook and reports that same condition; the route and the flag together are registered as the deviation `register-route-is-always-mounted` in [README.md](README.md) | `ui.router.ts:115`, `auth.router.ts:712-715` |
| `magicLink` | `Config.SendMagicLink` is set | `:116` |
| `sms` | `Config.SendSMSCode` is set | `:117` |
| `google` / `github` | `WithOAuth` wired a provider of that name | `:118-119` |
| `forgotPassword` | `Config.SendPasswordReset` is set | `:120` |
| `verifyEmail` | `Config.SendEmailVerification` is set **and** `Config.EmailVerificationMode` is not `none` | `:121` |
| `twoFactor` | `Config.TwoFactorAppName` is set | `:122` |

The reference reads `config.email.sendX` *or* a configured mailer for the email
ones; this port has no mailer block on `Config`, so the sender is the whole
condition. `verifyEmail` differs in one configuration: the reference asks
`emailVerificationMode !== 'none' || requireEmailVerification`, and an unset mode
passes that test while behaving as `none` everywhere else in its own code. This
port has no `requireEmailVerification` and normalises an unset mode to `none`
throughout, so it answers `false` where the reference answers `true` for a
deployment that wired a verification sender and left the mode alone. That is a
client-visible difference and is registered as the deviation
`ui-config-verify-email-follows-the-effective-mode` in [README.md](README.md),
which carries both answers and the reasoning. `Config.Require2FA` is not read at
all: it makes the second factor mandatory, not available, and the reference has
no equivalent of it.

**`ui`** is `UIOptions.Branding` with the `SettingsStore`'s `ui` block applied on
top, member by member (`:125-134`). `primaryColor`, `secondaryColor` and
`siteName` always carry a value — `#4a90d9`, `#6c757d` and `Awesome Node Auth`
when nothing configured them — and the other five are **absent** rather than
`null` when nothing did, which is what `JSON.stringify` does with the `undefined`
the reference leaves them as. `logoUrl` has three candidates in order: the stored
`logoUrl`, then `UIBranding.CustomLogo`, then the legacy `UIBranding.LogoURL`.
`customCss` is the one member no store can override — the reference reads it from
the static config alone (`:130`) and `UISettings` has no member for it.

**`translations`** is the flat key/value map for `lang`, read from the
`TemplateStore` UI page **`config`** — the reference derives the page from the
request path, which on this route is always `/config` (`:107`), so the login
page's strings are not what this route serves. A language the page does not hold
falls back to `en` and then to `{}`, and the map is never `null`.

**`lang`** is `?lang=`, then `UIOptions.DefaultLang`, then `en` (`:102-103`). The
reference takes its middle term from `config.email.mailer.defaultLang`; this port
has no mailer block on `Config`, so the UI's own default lives in `UIOptions`.

**`headless`** echoes `UIOptions.Headless`. It is the one member the route adds
rather than the config builder (`:166-168`), which is why it is last and why the
error fallback below carries it too.

**When a store fails**, the answer is still `200` and still these six keys, but
`features` is reduced to `register`, `google` and `github` (all `false`), the
branding is the default, `translations` is empty and `lang` is `en` whatever was
asked for (`:143-161`). A client cannot tell that document from a successful one
— which is a bug in the reference, and is reproduced rather than fixed because
the family's clients are written against the document as it is
(reference-issues N32). The error is logged through `Config.Logger` on the way
past, since the client is told nothing.

### The hosted UI (`<prefix>/ui`)

`HTTPConfig.UI.Enabled` mounts the reference's whole `ui.router.ts` — one
handler, `UIHandler`, registered by each adapter on the `<prefix>/ui` subtree.
It answers `GET` (and `HEAD`, for files) and nothing else; every other method
falls through to whatever the router does with an unknown route.

Four layers, in the reference's order, which is behaviour rather than style:

1. **`GET <prefix>/ui/config`** — the document above, served by the handler it
   has always had.
2. **Headless.** With `UIOptions.Headless` set, the handler serves the config
   route and the static assets and stops: no HTML page is served at all, because
   the hosting SPA provides its own login UI. A headless deployment that still
   answered `login.html` would be a different product, so the early return is
   reproduced exactly — and the uploaded assets below are on the far side of it,
   so they are not served either.
3. **Uploaded assets**, when `UIOptions.Uploads` is set *or* a `Config.Uploads`
   store is: the same `fs.FS` under both `<prefix>/ui/assets/logo/` and
   `<prefix>/ui/assets/uploads/`, the legacy path and the unified one. With
   neither — the default — serves neither rather than failing; a file the
   filesystem does not hold falls through to the same `404`, and so does a name
   that is not a valid upload key, so a traversal under either prefix ends
   there too.
4. **The SSR catch-all, then static serving.** A `GET` for a path with no file
   extension is a page: `<page>.html` if it exists, otherwise the first of
   `login.html`, `index.html`, `index.csr.html` that does, so no extensionless
   path under the mount answers `404`. Anything else is looked up as a file in
   `UIOptions.Assets` and served verbatim, or `404`s.

**The SSR injection** is what makes a vendored page usable before `auth.js` has
fetched anything. Into each page it writes: a `<style>:root{…}</style>` block
carrying `--primary-color` and `--input-focus` (both from `primaryColor`),
`--secondary-color`, `--bg-color`, `--card-bg` and `--bg-image` as `url("…")`
with `'`, `"` and `\` percent-encoded; `customCss` in a second `<style>`; the
HTML-escaped `siteName` into `<title>` and into `<h1 class="site-name">`;
`logoUrl` into the logo tag, which the pages ship hidden and which the
substitution reveals; a readiness splash; and
`window.__AUTH_CONFIG__ = <the same document>` before `</head>`. Pages are sent
as `text/html; charset=utf-8` with
`Cache-Control: no-store, no-cache, must-revalidate, max-age=0`; static files
carry express-static's `public, max-age=0`. If the injection fails the page is
sent unmodified, as there.

The config object is serialised with `encoding/json` at its defaults, which
escape `<`, `>` and `&` — a deliberate deviation from the reference's bare
`JSON.stringify`, registered as `ui-ssr-config-json-is-html-escaped`. See the
deviations section of the main README.

#### `(*Auth).UIHandler(cfg HTTPConfig, configRoute http.Handler) http.Handler`

The router as a value, for a host mounting the UI somewhere of its own.
`configRoute` serves the router-relative `/config`; the adapters pass their own
config handler, and passing `nil` leaves that path to the catch-all, which would
render `login.html` at it.

#### `UIOptions.Assets` and `UIOptions.Uploads`

Both are `fs.FS`. `Assets` is the reference's `uiAssetsDir` and defaults to
`UpstreamUIAssetFS()`; a host that supplies its own set replaces the built-in
one outright, with no per-file fallback. `Uploads` is its `uploadDir` and is
read-only — the writing half is `Config.Uploads`, the `UploadStore` the admin
console's upload routes go through.

The two compose so a host wires one thing. `UIOptions.Uploads` wins when it is
set; left nil with an `UploadStore` configured, `UIHandler` serves both asset
mounts from that store through `UploadFS(store)`; with neither, neither path is
mounted. So configuring `WithUploadStore` is enough to make an uploaded logo
appear at the URL `POST <admin>/api/upload/logo` handed back. Set
`UIOptions.Uploads` only to serve the read side from somewhere else — a
read-through cache, a snapshot, an `os.DirFS` over a mounted volume — or when
the read path needs per-request cancellation, which `fs.FS.Open` cannot carry.

#### `UploadStore` and `MemoryUploadStore`

`UploadStore` has four methods — `Put`, `List`, `Open`, `Delete` — and is the
seam over the reference's `uploadDir`, which is a directory on a local disk and
therefore not a portable answer for a host whose only writable path is a
per-execution-environment `/tmp`. Nil is the feature turned off: the four upload
routes are not registered, so they answer `404` rather than `401`, and the
console's `features.upload` is `false`.

Two rules an implementation has to keep. Every key satisfies `ValidUploadKey` —
one path element of ASCII letters, digits, `.`, `_` and `-`, never starting with
`.` — which is what makes `filepath.Join(root, key)` one element below `root` by
construction rather than by check; a filesystem-backed store on Windows must
additionally refuse the reserved device names, since `NUL.png` satisfies that
grammar. And `List` returns newest first, ties broken by key ascending. `Put`
must read its reader to EOF and leave nothing behind if it fails.
`MemoryUploadStore` is the in-process implementation; `UploadContentType(key)`
is the media type an object store should record at write time.

### `(*Auth).UIConfig(ctx, r *http.Request, cfg HTTPConfig) UIConfig`

The document as a value, for a host serving its own UI route. `r` supplies the
`lang` query parameter and nothing else, and may be `nil`. There is no error
return: a failing store produces the reduced document above, exactly as it does
on the route.

### `HTTPConfig.UI` and `HTTPConfig.UIEnabled`

`UIEnabled` is the deprecated spelling of `UI.Enabled`, from when the flag
decided nothing but the shape of an emailed link. It is an alias, not a second
switch: either field enables the UI, `ResolveHTTPConfig` sets both from either,
and a configuration that only ever set `UIEnabled` keeps the links it had and now
serves the config route as well. It is kept through the 0.x line.

> **Upgrading.** That last clause is a behaviour change, not only a rename: a
> deployment that already sets `UIEnabled` begins serving the public,
> unauthenticated `GET <prefix>/ui/config` after upgrading, with no code change
> on its side, and the document names its wired OAuth providers, whether 2FA and
> each delivery path are available, and its branding. Because the two fields are
> OR-ed, setting `UI.Enabled = false` alongside it does not suppress the route —
> the only way back to the previous behaviour is to stop setting `UIEnabled` and
> point the emailed links elsewhere.

### Embedded assets

All files are embedded via `//go:embed` from the `ui/` directory.

`ui/upstream/assets/` is different from the rest of that tree: it holds the
reference's own fourteen browser assets, copied byte for byte from
awesome-node-auth's `src/ui/assets` at `cc01e997` (v1.9.0), and **nothing in it
may be edited in this repository**. Each file's upstream path, size and sha256
are recorded in `upstreamUIAssetTable` (`ui_upstream.go`) and re-hashed by
`TestVendoredUIAssetsHaveNotDrifted` on every `go test ./...`, which also fails
if a file is added to or removed from the set. See `ui/upstream/README.md` for
the re-vendoring recipe and for why the provenance is recorded beside the bytes
rather than as a header inside them.

#### `UpstreamUIAssetFS() fs.FS`

The vendored assets as a filesystem rooted at the asset directory, so a caller
opens `"login.html"` rather than the full embedded path.

#### `ReadUpstreamUIAsset(name string) ([]byte, error)`

One vendored asset by base name, returned as a copy.

#### `UpstreamUIAssets() []UpstreamUIAsset`

The provenance table — name, upstream path, commit, size and sha256 per file —
freshly built on every call.

### `ServeAdminUI() http.Handler`

**Deprecated — removed in v1.0.0.** No replacement until the admin router lands
in M8: the reference's admin SPA is vendored and served under `<prefix>/ui`, but
it calls an admin API no adapter mounts yet.

Serves `ui/admin.html` — this port's own single-page admin dashboard, with
sections for Users, Sessions, Tenants, Roles, API Keys, Telemetry, and OpenAPI
reference. Nothing inside the module serves it.

### `ServeAuthUI() http.Handler`

**Deprecated — removed in v1.0.0.** Set `HTTPConfig.UI.Enabled` instead and the
adapter mounts `<prefix>/ui`, which serves the reference's own login page with
the branding, the site name, the logo and the config already in the document.

Serves `ui/auth.html` — this port's hand-written auth UI, with Login, Register,
Magic Link, Forgot Password and TOTP forms — raw, with no injection of any kind.
The page fetches `<prefix>/ui/config` for itself, so it works, but it flashes
unstyled and it is not the page the family's deployments show.

### `ServeAuthJS() http.Handler`

**Deprecated — removed in v1.0.0.** Use `UpstreamUIAssetFS()` or
`ReadUpstreamUIAsset("auth.js")` instead.

Serves the **vendored** `auth.js` (`ui/upstream/assets/auth.js`, 31,277 bytes) —
the reference's own browser SDK, not this port's hand-written `ui/auth.js`,
which is still embedded for the contract tests but is no longer served or
maintained.

Two differences follow from the swap, and a page that drives the SDK has to know
both:

- **The global changed.** The hand-written client exposed `window.AuthSDK`. The
  reference's client exposes `window.AuthService` and `window.AwesomeNodeAuth`
  (`auth.js:219`, `auth.js:352`) and no `AuthSDK` at all, and its surface is
  different too — it is a page runtime with `init`, `guardPage`, `guardRole` and
  `checkSession`, not a thin method-per-route wrapper.
- **Bearer delivery is no longer requested for you.** The hand-written client
  sent `X-Auth-Strategy: bearer` and exposed the tokens it received; the
  reference's client is cookie-only and never sends that header. The server
  still honours `X-Auth-Strategy` from any caller, so a page that wants bearer
  delivery must send it itself.

This is the point of vendoring: what this port serves is now what the rest of
the family serves, so a page written against the reference's documentation
works here unchanged. A page written against this port's old SDK does not.

**`window.AuthService` methods** (the vendored client's surface; the reference's
own documentation is authoritative, since these are its bytes):
`init`, `login`, `logout`, `register`, `refresh`, `checkSession`, `getUser`,
`isAuthenticated`, `guardPage`, `guardRole`, `forgotPassword`, `resetPassword`,
`setPassword`, `changePassword`, `sendMagicLink`, `verifyMagicLink`,
`sendSmsLogin`, `verifySmsLogin`, `setup2fa`, `verify2faSetup`, `validate2fa`,
`validateSms`, `verifyEmail`, `resendVerificationEmail`, `requestEmailChange`,
`confirmEmailChange`, `getActiveSessions`, `revokeSession`, `getLinkedAccounts`,
`unlinkAccount`, `requestLinkingEmail`, `verifyLinkingToken`,
`verifyConflictLinkingToken`, `deleteAccount`, `applyTranslations`

---

## API Keys

### `NewAPIKeyService(bcryptCost int) *APIKeyService`

Keys are hashed with bcrypt at `bcryptCost`; zero means `bcrypt.DefaultCost`. Pass
the same value as `Config.BcryptCost` to keep both kinds of stored secret at one
cost. `Verify` never hashes — it reads the cost out of the stored hash — so a
verify-only service may pass `0` whatever cost its keys were created at.

### `(*APIKeyService).Create(ctx, store, name, serviceID, scopes, allowedIPs, expiresAt) (rawKey string, record APIKeyRecord, err error)`

Returns the raw key (shown once) and the stored record (key is hashed with bcrypt).

### `(*APIKeyService).Verify(ctx, store, rawKey, ip, requiredScopes) (APIKeyRecord, error)`

Validates key hash, active status, expiry, IP allowlist, and required scopes.

### `APIKeyMiddleware(store APIKeyStore, requiredScopes []string) func(http.Handler) http.Handler`

HTTP middleware that reads `X-Api-Key` or `Authorization: ApiKey <key>` headers.

### `APIKeyStore` interface

The mandatory half, mirroring the reference's `IApiKeyStore`, which makes
`findByPrefix` and `findById` required and everything else optional
(`api-key-store.interface.ts:7-9`):

```go
type APIKeyStore interface {
    Save(ctx, APIKeyRecord) error
    FindByPrefix(ctx, prefix string) (APIKeyRecord, error) // active keys only
    FindByID(ctx, id string) (APIKeyRecord, error)         // any state, incl. revoked
    Revoke(ctx, id string) error
    UpdateLastUsed(ctx, id string, when time.Time) error
}
```

The reference's four optional methods are narrow companion interfaces that a
caller type-asserts the configured store to, one method each, so that the
absence of any one of them is separately observable — which is what lets the
admin surface answer `404 API key store not configured` for "no store" and
`501 IApiKeyStore.listAll is not implemented` for "no listAll":

```go
type APIKeyAdminStore interface {        // listAll?
    ListAll(ctx, limit, offset int) ([]APIKeyRecord, error)
}
type APIKeyServiceIndexStore interface { // listByServiceId?
    ListByServiceID(ctx, serviceID string) ([]APIKeyRecord, error)
}
type APIKeyDeleteStore interface {       // delete?
    Delete(ctx, id string) error
}
type APIKeyAuditStore interface {        // logUsage?
    LogUsage(ctx, entry APIKeyAuditEntry) error
}
```

Both listers return records newest first — `CreatedAt` descending, ties broken
by `ID` ascending. That order is normative for this package; a store that cannot
hold to it registers its own as a deviation. `Revoke`, `UpdateLastUsed` and
`Delete` treat an unknown id as a no-op returning `nil`, not an error, because
the reference's routes await them and answer `200` without a lookup of their
own. `APIKeyAuditStore` is a seam: nothing in the core calls `LogUsage` yet, and
the caller arrives with the admin API-key surface in v0.10.0.

---

## Event Bus

### `NewEventBus() *EventBus`

### `(*EventBus).Subscribe(event string, handler func(Event))`

Subscribe to a specific event name or `"*"` for all events.

### `(*EventBus).Publish(ev Event)`

Delivers the event synchronously to all matching handlers. Panics in handlers are recovered and logged.

### `Event`

```go
type Event struct {
    Name, UserID, TenantID string
    Timestamp              time.Time
    Data                   map[string]any
}
```

---

## HTTP Adapters

Four packages serve the auth router, one per framework. Each takes the
`*auth.Auth` that `auth.New` or `auth.NewWithConfig` returns, not a `*Service`,
and each mounts the **whole** route set in one call. Routes are not wired one
by one. The four mount the same routes and write byte-identical bodies and
cookies through the shared wire helpers. The conformance suite in
`adapter/internal/wiretest` runs every case against all four.

| Package | `Mount` takes | Constructor | `Middleware` shape | Principal read by |
|---|---|---|---|---|
| `adapter/nethttp` | `*http.ServeMux` | `New(a)`, `NewWithConfig(a, cfg)` → `*Adapter` | `func(http.Handler) http.Handler` | `nethttp.UserFromContext(ctx)` |
| `adapter/chi` | `chi.Router` | none: package functions only | `func(http.Handler) http.Handler` | `auth.UserFromContext(ctx)` (chi reuses the net/http handlers and middleware) |
| `adapter/gin` | `gin.IRoutes` | `New(a)`, `NewWithConfig(a, cfg)` → `*Adapter` | `gin.HandlerFunc` | `UserFromContext(c *gin.Context)` |
| `adapter/echo` | `*echo.Group` | `New(a)`, `NewWithConfig(a, cfg)` → `*Adapter` | `echo.MiddlewareFunc` | `UserFromContext(c echo.Context)` |

`nethttp.UserFromContext` is `auth.UserFromContext`; either name works on
net/http and chi.

### `adapter/nethttp`

```go
a, err := auth.New(auth.WithSecret("change-me-in-production-32bytes!!"))
if err != nil {
	log.Fatal(err)
}

mux := http.NewServeMux()
nethttp.Mount(mux, a) // every auth route, under /auth

// A route of the host's own, behind the access-token middleware.
profile := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user, _ := nethttp.UserFromContext(r.Context())
	auth.WriteJSON(w, http.StatusOK, map[string]string{"id": user.ID})
})
mux.Handle("GET /api/profile", nethttp.Middleware(a)(profile))
```

With other wire conventions, build the adapter and mount it. `Middleware()` on
the `*Adapter` returns the middleware; it is not the middleware itself:

```go
cfg := auth.DefaultHTTPConfig()
cfg.APIPrefix = "/api/auth"

mux := http.NewServeMux()
adapt := nethttp.NewWithConfig(a, cfg)
adapt.Mount(mux) // every auth route, under /api/auth
mux.Handle("GET /api/profile", adapt.Middleware()(profile))
```

### `adapter/chi`

There is no `chi.New` and no adapter value. The package is `Mount`,
`MountWithConfig`, `Middleware` and `ResourceServerMiddleware`:

```go
import (
	"github.com/go-chi/chi/v5"
	auth "github.com/nik2208/awesome-go-auth"
	chiAdapter "github.com/nik2208/awesome-go-auth/adapter/chi"
)

r := chi.NewRouter()
chiAdapter.Mount(r, a) // every auth route, under /auth

r.With(chiAdapter.Middleware(a)).Get("/api/profile", func(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.UserFromContext(r.Context())
	auth.WriteJSON(w, http.StatusOK, map[string]string{"id": user.ID})
})
```

### `adapter/gin`

The adapter's package name is also `gin`, so import it under another name.
`gin.Default` below is the framework's constructor:

```go
import (
	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
	ginAdapter "github.com/nik2208/awesome-go-auth/adapter/gin"
)

r := gin.Default()
ginAdapter.Mount(r, a) // every auth route, under /auth

r.GET("/api/profile", ginAdapter.Middleware(a), func(c *gin.Context) {
	user, _ := ginAdapter.UserFromContext(c)
	c.JSON(http.StatusOK, gin.H{"id": user.ID})
})
```

The same through an adapter value:

```go
adapt := ginAdapter.NewWithConfig(a, auth.DefaultHTTPConfig())
adapt.Mount(r)
r.GET("/api/profile", adapt.Middleware(), profile)
```

### `adapter/echo`

The package name `echo` clashes in the same way; `echo.New` below is the
framework's. `Mount` takes an `*echo.Group`, so pass `e.Group("")` to mount at
the root:

```go
import (
	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
	echoAdapter "github.com/nik2208/awesome-go-auth/adapter/echo"
)

e := echo.New()
echoAdapter.Mount(e.Group(""), a) // every auth route, under /auth

e.GET("/api/profile", func(c echo.Context) error {
	user, _ := echoAdapter.UserFromContext(c)
	return c.JSON(http.StatusOK, map[string]string{"id": user.ID})
}, echoAdapter.Middleware(a))
```

The same through an adapter value:

```go
adapt := echoAdapter.NewWithConfig(a, auth.DefaultHTTPConfig())
adapt.Mount(e.Group(""))
e.GET("/api/profile", profile, adapt.Middleware())
```

### What every adapter provides

All four adapters provide the same package-level functions:

- `Mount(router, a)` and `MountWithConfig(router, a, cfg auth.HTTPConfig)`.
  They register the auth routes under `HTTPConfig.Prefix()` (`/auth` by
  default), relative to the router they are given. `Mount` is
  `MountWithConfig` with `auth.DefaultHTTPConfig()`. Some routes depend on the
  configuration:
  - The JWKS document and the four OIDC endpoints are mounted only under
    `auth.WithIDP`.
  - The hosted UI is mounted only under `UI.Enabled`.
  - The OpenAPI document and Swagger UI are mounted only under `Docs.Enabled`.
  - The admin console is mounted only when `AdminMounted()` reports it, at
    `Admin.Path` rather than under the prefix.
  - The tools router is mounted only when `ToolsMounted()` reports it, at
    `Tools.Path`.
  - Under `ResourceServer`, the credential routes are left out
    (`auth.ResourceServerGatedRoutes`).
- `Middleware(a)` verifies this instance's HS256 access token and puts the user
  in the context.
- `ResourceServerMiddleware(a, cfg auth.ResourceServerConfig)` verifies a
  bearer token against a remote JWKS. Without a bearer header, it verifies the local
  access-token cookie. See [Resource server mode](#resource-server-mode).

Both middlewares come in each framework's own shape and put the principal where
the table above reads it. The `*Adapter` of `nethttp`, `gin` and `echo` also
has `Config()`, which returns the resolved `HTTPConfig`, and the methods
`Mount(router)` and `Middleware()`.

Only `nethttp.Adapter` exports the individual route handlers (`Register`,
`Login`, `Refresh`, `Logout`, `Me`, `ForgotPassword`, `MagicLinkSend`,
`TwoFactorSetup`, `Sessions`, …) and the `…Handler()` constructors
(`OAuthAuthorizeHandler`, `UIHandler`, `AdminHandler`, …). The gin and echo
adapters keep theirs unexported. The handler methods are bare. `Mount` wraps
each of their routes in the event-context carrier, the rate-limiter slot and
the CSRF middleware, and adds the access-token middleware where the route needs
it. A handler method mounted by hand gets none of these, so `Mount` is the
supported way to serve the routes.

### `HTTPConfig.RateLimiter` — the rate-limiter slot

The reference declares `RouterOptions.rateLimiter` (`auth.router.ts:46`) and
ships no algorithm behind it: the slot is the whole feature, and a deployment
supplies its own middleware (`express-rate-limit`, a gateway shim, whatever it
already runs). `HTTPConfig.RateLimiter` is that slot in this port's shape.

```go
cfg := auth.DefaultHTTPConfig()
cfg.RateLimiter = func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if overBudget(r) {
            w.Header().Set("Retry-After", "60")
            auth.WriteJSON(w, http.StatusTooManyRequests, map[string]any{
                "error": "Too many requests",
            })
            return
        }
        next.ServeHTTP(w, r)
    })
}
nethttp.MountWithConfig(mux, a, cfg) // chi, gin and echo take the same cfg
```

**Which routes.** Every route of the auth router, on all four adapters — the
reference spreads `...rl` onto each one (`auth.router.ts:541` onwards). The
JWKS document is outside the slot, as it is there: it is registered above the
whole chain and carries no limiter (`:490`).

One pair of routes is inside the slot here and outside it in the reference. When
an OAuth provider is not configured, the reference replaces the real handlers
with bare 404 stubs that carry no limiter (`:1361-1362` for Google,
`:1407-1408` for GitHub); this port mounts one always-guarded handler per OAuth
route and decides on the configuration inside it. Behind a limiter at its limit,
`GET <prefix>/oauth/{provider}` and its callback therefore answer `429` here
where the reference answers `404`, and they consume budget here that they do not
consume there.

**Where in the chain.** Outermost: the limiter runs before the CSRF middleware
and before the auth middleware. That is the reference's order — `rl` is the
first handler on each route, ahead of `authMiddleware` (`GET /me`, `:656`) and
therefore ahead of the double-submit check, which that middleware performs and
which the one route mounted without it repeats by hand inside its handler
(`:1489-1495`). A refusal therefore costs nothing downstream: no CSRF cookie is
minted, no token is verified, no store is read. The wiretest suite pins all
three of those on each adapter.

**One call per route.** The field is a constructor, not a handler: each adapter
calls it once for every route it mounts — some thirty calls — and mounts the
handler it returns. Anything the limiter counts with must therefore be created
*outside* the function and captured by it, as `httprate.LimitByIP` and the
usual `tollbooth` wrappers are written:

```go
limiter := tollbooth.NewLimiter(5, nil)       // one budget, allocated once
cfg.RateLimiter = func(next http.Handler) http.Handler {
    return tollbooth.LimitHandler(limiter, next)
}
```

Allocating the counter inside the function body instead gives every route a
private budget — thirty times the intended allowance — where the reference,
which passes one Express handler *instance* to every route, gets a single
budget shared across the router.

**`nil` means no limiter**, which is the default and the reference's own
behaviour when the option is absent — it collapses to an empty middleware list
(`:468`). Nothing else in the wire contract changes either way.

> **Note for the admin router.** `HTTPConfig.RateLimiter` does not cover the
> admin console. The console has its own separate slot,
> `HTTPConfig.Admin.RateLimiter` (`AdminOptions.RateLimiter`, `admin.go`). It is
> applied to exactly one route, `POST <admin>/users/{id}/promote`, ahead of that
> route's guard. The console's login route and every other admin route carry no
> limiter. The console mounts at `Admin.Path`, `/admin` by default, not under
> `HTTPConfig.APIPrefix`. This mirrors the family's private development line.
> That line declares `AdminOptions.rateLimiter` (`admin.router.ts:205-211`) and
> collapses it to an empty list when it is absent (`:577`). It spreads the slot
> onto the promote route only (`:1030`) and leaves the admin login without one
> (`:614`). Those line numbers are in that private tree, not in
> `auth.ReferenceRevision`, whose admin router has no rate-limiter slot at all.
> The route and the slot are registered together as the deviation
> `admin-promote-route-comes-from-the-development-line` in
> [README.md](README.md). Like `HTTPConfig.RateLimiter`, the field is a
> constructor called at mount time. A host that passes the same limiter to both
> slots gets one shared budget.

---

## Security Helpers

Internal helpers (unexported) available for use within the package:

| Function | Description |
|----------|-------------|
| `newID(prefix) (string, error)` | Generates `prefix_<32hex>` ID |
| `hashPassword(password, cost) (string, error)` | bcrypt at `cost`; a zero cost means `DefaultCost` |
| `verifyPassword(password, hash) bool` | bcrypt compare |
| `hashToken(token) string` | SHA-256 hex |
| `randomToken(byteLen) (string, error)` | Base64URL random bytes |
| `randomNumericCode(length) (string, error)` | Cryptographic numeric code |
| `sign(input, secret) string` | HMAC-SHA256 base64url |
| `secureEqual(a, b) bool` | Constant-time string compare |

---

## Errors

| Error | Description |
|-------|-------------|
| `ErrInvalidCredentials` | Wrong email/password or user not found |
| `ErrUserExists` | Email already registered in tenant |
| `ErrInvalidToken` | Token invalid, expired, or tampered |
| `ErrSessionNotFound` | Refresh token session not found |
| `ErrSessionRevoked` | Session was explicitly revoked |
| `ErrWeakPassword` | Password shorter than MinPasswordLen |
| `ErrInvalidInput` | `Register` called with no email or no password — see [Registration input](#registration-input) |
| `ErrFeatureNotSupported` | Required store interface not implemented |
| `ErrEmailNotVerified` | Login attempted before email verification |
| `ErrInvalidCode` | Wrong SMS code or TOTP code |
| `ErrTwoFactorRequired` | Login requires 2FA step |
| `ErrAlreadyExists` | Resource already exists (e.g., tenant) |
| `ErrTenantNotFound` | Tenant ID not found |
| `ErrRoleNotFound` | Role not found when adding to user |
