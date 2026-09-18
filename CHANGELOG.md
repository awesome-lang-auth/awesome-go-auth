# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`UserLookupStore` — find a user by id alone, whatever tenant it is in**
  (`store.go`). `FindUserByID(ctx, id)` is the reference's `findById(id)`
  (`user-store.interface.ts:5`): no tenant parameter, not even one where `""`
  means "all". It is optional, and a store without it still works everywhere.
  It exists because `GetUserByID` reads `""` as a literal tenant, and has to:
  `/me` and `/refresh` pass it the access token's `tid`, and an empty `tid`
  that matched every tenant would find accounts in any of them. The implementor's
  contract is on the interface. The one rule a store can get wrong is that it
  must never pick between two records sharing an id. It answers an error
  instead. `MemoryUserStore` implements it, and its `CreateUser` already
  refuses an id that another tenant holds.

  A key-value store cannot serve it from the `<tenantID>#<id>` directory index
  that `AdminUserStore.ListUsers` uses, because the id is the sort key's suffix.
  It needs an item keyed on the id alone. The interface doc sets out the two
  ways to have one.

### Fixed
- **`GET <admin>/api/users/{id}` now finds users that `GET <admin>/api/users`
  lists under another tenant.** The listing reads `""` as every tenant; the
  detail route asked `GetUserByID(id, "")`, where `""` is a literal. So a
  deployment that stored users under a tenant got a console whose table linked
  to 404s. The route now uses `UserLookupStore` when the store has it. Without
  it, the route does what it did in 0.11.0. That fallback is recorded as the
  `admin-user-detail-spans-tenants-only-through-a-lookup-store` deviation,
  along with what it still leaves open: `DELETE <admin>/api/users/{id}` and
  `POST <admin>/users/{id}/promote` with `method=flag` still ask for the empty
  tenant. `GET <admin>/api/users/{id}/roles` is unchanged on purpose. Its
  tenant is a role assignment's scope, and the console assigns roles in the
  empty one.

## [0.11.0] - 2026-09-12

The event plane, and the tools router on top of it. **This release carries the
line's breaking removals**; they are listed under Removed, with what a host does
instead.

It starts from a finding: `EventBus.Publish` had existed, documented and
working, with **zero call sites**. Everything downstream subscribed to a bus
that never spoke. So this release lays the `identity.*` vocabulary and the
request context an event carries, then gives the bus its first callers —
sixteen publication points covering nineteen of the twenty-six the family's
private development line raises, with a conformance test that makes
reachability a function of the file a citation names, so a live site that stops
publishing cannot be silenced by reclassifying it.

`WebhookDispatcher` and its invented `X-Signature-SHA256` are replaced by the
reference's format — `X-Webhook-Signature: sha256=<hex>` and its three
companions — with the reference's retry schedule and a `WebhookDeliverer` seam
below the format, so a host can put delivery on a queue without reimplementing
signing or the envelope. `SseHub` is replaced by the reference's `SseManager`:
connections rather than channels, server-chosen topics, per-connection
deduplication, heartbeats, and a distributor seam for the deployments where
in-process fan-out reaches nobody. Resume is reproduced faithfully, which means
it guarantees nothing — the reference reads `Last-Event-ID` nowhere and a
reconnection resumes from now.

`AuthTools` composes the four sinks in the source's order, and the tools router
mounts its five routes. Two postures are worth reading before deploying one: the
router declines the reference's unguarded default and requires an explicit
access decision, because `POST /track` attributes an event to any user it is
told about and fans it out to that user's stream and to outgoing webhooks signed
in the deployment's name; and `GET /stream` reproduces the reference's
credential-in-a-query-string, which is what `EventSource` obliges, with the cost
written where a reader will meet it.

The inbound webhook runs no script in this process and never will. The core
resolves the action allowlist — the intersection the reference computes, with a
failing or absent settings store yielding an empty list rather than a full one —
and hands script, body and that list across an `InboundScriptRunner` seam whose
every field is JSON-encodable. A host's sandbox is its own process and its own
privileges. No JavaScript engine is in this repository, and none will be.

### Added
- **`POST <tools>/webhook/{provider}`, the inbound webhook, and the
  `InboundScriptRunner` seam** (`tools_webhook.go`). The port of
  `tools.router.ts:250-326` — the one route of this router with **no guard at
  all**, there and here: the caller is a third-party provider with no session
  to present, the reference spreads no `protect` onto it (`:251`) and its
  OpenAPI operation carries no `security` entry. **No JavaScript engine enters
  this repository.** The reference runs the administrator's `jsScript` in a
  `node:vm` sandbox in the API process; this package's dependency rule is
  stdlib plus `golang.org/x/crypto`, and an in-process interpreter would put
  script typed into an admin form in the same address space as the signing keys
  and the password hashes. So the core exposes `InboundScriptRunner` —
  `RunInboundScript(ctx, InboundScriptRequest) (InboundScriptResult, bool,
  error)` — and the host implements it out of process, where its own
  credentials are the sandbox. What crosses: the provider, the webhook id, the
  script, the **raw body** and the **resolved action allowlist**. What cannot:
  the webhook's secret, the settings store, the request headers, a callable of
  any kind. The allowlist is the intersection of
  `AuthSettings.EnabledWebhookActions` with `WebhookConfig.AllowedActions`
  (`webhook-action.ts:105`), resolved **in the core** because it is the
  administrator's policy — a runner may narrow it and must never widen it. The
  settings read reproduces the reference's `.catch(() => ({}))`, which fails
  into an *empty* allowlist: a settings store that is down, or absent
  altogether, means no actions rather than all of them. **A configuration with
  a script and no runner is refused** — `400 {"error": "Webhook processing
  failed"}`, nothing tracked — rather than acknowledged, so the provider
  redelivers instead of the event being lost silently; a runner that *fails* is
  refused the same way, while a script that *throws* is reported as "no result"
  and acknowledged, which is what the reference does. `ToolsOptions.OnWebhook`
  is the reference's `onWebhook` fallback (`:63-67`) and is where a host
  verifies the provider's signature — nothing else on this route authenticates
  anything, and the `X-Hub-Signature-256` header the reference's own document
  advertises is read by no line of its code. Two limits the reference leaves to
  its host and this route cannot: `ToolsOptions.WebhookMaxBytes` (100 KiB,
  `express.json()`'s default) and `ToolsOptions.ScriptTimeout` (5s, the
  reference's `vm` timeout — which there bounds only the synchronous prefix
  before the first `await`, and here bounds the whole run). Registered as
  `inbound-webhook-script-runs-out-of-process`.
- **`GET <tools>/telemetry`, the tools router's query endpoint**
  (`tools_telemetry.go`). The port of `tools.router.ts:226-245`, behind the
  same guard as `track` (`:227`) and mounted on the reference's two-part
  condition: the telemetry flag **and** a configured
  `ToolsOptions.TelemetryStore` (`:226`), so without a store the path answers
  404 rather than an empty list. Seven query parameters — `event`, `userId`,
  `tenantId`, `from`, `to`, `limit`, `offset` — become a `TelemetryFilter`;
  `sessionId` is *not* one of them, which is the reference's own destructure
  (`:233`). Nothing is clamped, so `?limit=1000000` is what the store is asked
  for, and an unparseable value is treated as absent — the answer
  `adminQueryInt` already gives, since `parseInt('abc', 10)` is `NaN` and
  `new Date('x')` is an Invalid Date and neither fits in an `int` or a
  `time.Time`. The body is `{"data": [...]}` in the reference's
  `TelemetryEvent` spelling — `event`, `data`, an ISO timestamp — which is this
  package's `trackedRecord` and not its `TelemetryEvent`. **The result is not
  scoped to the caller**: `userId` is a filter and not a claim, so any caller
  the guard admits reads every user's records, IP and user agent included. That
  is the reference's shape, and it is the sharpest illustration of why
  `tools-router-requires-an-explicit-guard-decision` exists.
- **`TelemetryFilter.Offset`** (`telemetry.go`), the reference's `offset`
  (`telemetry-store.interface.ts:38`), which arrived with the route that sends
  it. `MemoryTelemetryStore` applies it after every other filter and before
  `Limit` counts; a store that ignores it does not paginate, and its caller has
  no way to find out.

## [0.10.0] - 2026-09-12

The admin console. Fifty-one routes, split across five pull requests not by
count but by what a reviewer has to check in each: who gets in, then the reads
shape by shape, then the ordinary writes, then the eight routes that hold or
mint a credential, then uploads and the document.

The guard is the release's substance. Four access policies, the legacy bearer
secret, and three deliberate narrowings of the reference, each argued in the
register: a console with no access decision mounts nothing rather than serving
itself to anyone who can reach the port; the unauthenticated-GET branch reaches
the login shell alone, where in the reference it reaches every guarded GET that
accepts `text/html`; and the guard accepts only typed session tokens, where a
bare `jwt.verify` makes every token its secret signs an admin credential — the
2FA step-up token included.

Uploads arrive behind an `UploadStore` seam rather than a directory, composing
with the UI's read-only `Uploads` filesystem so a host wires one thing. The key
a client supplies is never used: it is derived, and the grammar the derivation
produces cannot spell a path separator, so traversal is impossible rather than
checked.

One route comes from the family's private development line rather than the
published reference — `POST <admin>/users/{id}/promote`, registered there
without the `/api` prefix its fifty siblings carry. Reproduced as written and
registered as such, so nobody reads it as an invention of this port.

The conformance suite now holds the mounted console and the development line's
registration list to each other in both directions, and holds the served
document to the mount with the reference's own sixteen omissions named one by
one rather than sampled.

### Added
- **`POST <admin>/users/{id}/promote`, and the admin surface closed at fifty-one
  routes** (`admin_promote.go`). The console's last route, and the one that
  grants the console: `{method?: 'flag' | 'role'}` defaulting to `'role'`.
  `method=flag` writes `User.IsAdmin` through the new `UserAdminFlagStore` seam
  — a narrow interface the core type-asserts, the way `UserTwoFactorPolicyStore`
  is — and answers the reference's
  `501 {"error": "IUserStore.update is required for method=flag"}` without one.
  `method=role` creates an `admin` role and assigns it, `404` without an RBAC
  store. Both answer `{"success": true, "method": <as sent>}` and publish
  `identity.role.assigned`.
  **It comes from the private development line, not the published reference**,
  which registers fifty admin routes and none of them this one — registered as
  `admin.router.ts:1030` there, and **not under `/api`**, unlike its fifty
  siblings. Reproduced as written; `POST <admin>/api/users/{id}/promote` is
  mounted nowhere. See the new
  `admin-promote-route-comes-from-the-development-line` deviation.
  **`AdminOptions.RateLimiter`** arrives with it: a second limiter slot, separate
  from `HTTPConfig.RateLimiter`, wrapping this route and no other and running
  *ahead* of the guard. The console's own login is deliberately unlimited on
  both lines.
  **The conformance set is closed.** `adapter/internal/wiretest/admin_promote.go`
  transcribes the development line's fifty-one route registrations line by line
  and asserts that the mounted set is exactly that — no route mounted that the
  source does not register, none registered that no family table mounts, each
  one probed against a real adapter mount, and the near misses refused.
- **The admin console publishes its four events** (`admin.go`,
  `admin_write.go`). `POST <admin>/api/users/{id}/roles` and
  `DELETE <admin>/api/users/{id}/roles/{role}` — mounted silent by U14 — now
  raise `identity.role.assigned` and `identity.role.revoked` beside the promote
  route's pair, which is all four of the development line's `publishAdminEvent`
  calls. U18's arithmetic moves from 19 + 7 = 26 to **23 + 3 = 26**; the three
  that remain are its `AuthConfigurator`, which this port has no counterpart for.
  **How event context reaches admin routes** — the question U12 left open — is
  answered by `(*Auth).publishAdminEvent`: the console sits outside
  `EventContextMiddleware` on both lines, so the correlation id, client address
  and user agent are read off the request at the publication site, which is
  exactly what the source's own `publishAdminEvent` does. No adapter changed.
- **The admin console's uploads, behind a store seam** (`upload_store.go`,
  `admin_upload.go`). `POST <admin>/api/upload/logo`,
  `POST <admin>/api/upload/bg-image`, `GET <admin>/api/upload/files` and
  `DELETE <admin>/api/upload/:filename` — the port of `admin.router.ts:989-1085`,
  multipart parsed with `mime/multipart` because the dependency rule is stdlib
  plus `golang.org/x/crypto` and `multer` is neither.
  **The seam is the substance.** The reference writes into `uploadDir`, a
  directory on a local disk; `UploadStore` (`Put`, `List`, `Open`, `Delete`) is
  what a host implements instead, with `MemoryUploadStore` shipped and
  `WithUploadStore` / `Config.Uploads` to wire it. **Unconfigured is inert**: no
  store means the four routes are not registered at all, so they answer a plain
  `404` rather than a guarded `401`, the way `GET /api/templates/*` is
  registered only with a `TemplateStore`. `upload` is the last `adminFeatures`
  flag and it now follows the store.
  **One store serves both halves.** `UIOptions.Uploads` — the read-only `fs.FS`
  v0.9.0 added — still wins when set, and left nil `UIHandler` serves
  `<prefix>/ui/assets/logo/` and `<prefix>/ui/assets/uploads/` from the
  configured store through `UploadFS`, so the URL an upload answers with
  resolves against the same deployment with nothing wired twice.
  **Keys are derived, never accepted.** `adminUploadKey` is multer's own
  filename callback (`:1005-1013`) — `path.basename`, the `[^a-z0-9_-]gi`
  sanitiser over UTF-16 code units, forty characters, a millisecond stamp and a
  lowercased extension — and `ValidUploadKey` is the grammar every key satisfies:
  one path element of ASCII letters, digits, `.`, `_` and `-`, never leading `.`.
  No key can contain `/`, `\` or `:`, and none can be `.` or `..`, so traversal
  is not a check that passes but a string a key cannot be. The limits are the
  reference's `limits.fileSize` of 5 MiB and its seven-extension `fileFilter`,
  plus an outer bound on the whole request the reference does not have. Two
  deviations are registered: `admin-upload-refusals-answer-the-admin-envelope`
  and `admin-upload-base-url-is-derived-from-the-mount`.
- **The admin console's OpenAPI document and its Swagger page**
  (`openapi_admin.go`): `GET <admin>/api/openapi.json` and `GET <admin>/api/docs`
  under `AdminOptions.Docs`, and `GenerateAdminOpenAPISpec` — the port of
  `buildAdminOpenApiSpec` (`openapi.ts:672-1362`), the reference's **third**
  generator, beside `GenerateOpenAPISpec` and `GenerateToolsOpenAPISpec`.
  `(*Auth).AdminOpenAPIInfo` fills its eight flags from `adminFeatures`, so the
  document and the console's own tabs cannot disagree.
  **The pair carries no guard**, which is the one exception to a `guard` spread
  onto every other `<admin>/api/*` route (`:1499`, `:1517`). That asymmetry is
  reproduced rather than tidied — guarding it would answer `401` where the
  reference answers `200` — and the decision is put where a host makes it: the
  routes are off until `AdminOptions.Docs.Enabled` is set, the field says what
  enabling them publishes, and the generated document's own `security` blocks
  say it too. `docs-routes-are-opt-in` now covers all three routers. The page is
  `SwaggerUIHandler` unchanged, so its title says "Tools API" here as well —
  the third route this port reproduces that quirk on.
- **`POST <tools>/track/{eventName}` and `POST <tools>/notify/{target}`**
  (`tools_track_notify.go`). The tools router's first two feature routes
  (`tools.router.ts:140-160`, `:165-179`), both behind
  `auth.ToolsProtectMiddleware` where the reference spreads `...protect`, both
  answering `202 {"ok": true}` whatever the fan-out did. `track` takes `data`,
  `userId`, `tenantId`, `sessionId` and `correlationId` off the body — `userId`
  falling back to the authenticated principal on the context — and calls
  `AuthTools.Track`; `notify` takes `data`, `type`, `tenantId`, `userId` and
  `metadata` and calls `AuthTools.Notify`, which broadcasts to the single topic
  `{target}` names and to no other. Neither route re-implements any of the
  fan-out U21 pinned. `DisableTelemetry` and `DisableNotify` unmount their own
  route, so a switched-off group answers the router's `404` and not a handler's
  refusal — as does a name or target that is not exactly one path segment, and
  as does any method but POST.
- **The client address on `track` is a deviation**, and the substantive decision
  of this PR. The reference resolves it at the route as the left-most element of
  `X-Forwarded-For` with the socket as the fallback (`tools.router.ts:144`);
  this port reads `HTTPConfig.ClientIP` — the socket peer with its port stripped
  by default — so that one binary does not hold two address rules and a host's
  stated trust configuration is not overridden by the one route that writes the
  address into a durable record. The header is read nowhere, not even as a
  fallback. See `tools-track-ip-comes-from-the-configured-seam`; a deployment
  behind a proxy it operates sets `cfg.ClientIP` and gets the forwarded address
  here and on the auth router's events alike.
- **The bodies are decoded rather than cast**, which is the second deviation. A
  field of the wrong type — `{"data": 42}` on `track`, where `Track` takes a
  `map[string]any` — is a `400` carrying this router's own `{"error": ...}`
  envelope instead of a `202` that recorded a number or silently dropped it. An
  absent or empty body is still accepted, as `req.body = {}` is there. See
  `tools-request-bodies-are-typed`.
- **`notify` reaches the SSE channel and only that one**, reproduced rather than
  repaired: the route never reads `channels`, so `NotifyOptions.Channels` falls
  to its default `['sse']` on every request and the facade's `email` and `sms`
  channels are unreachable over HTTP (`tools.router.ts:168`, `:171-176`). A host
  that wants those calls the facade, where `Channels` is one field away — and a
  route that took a channel list off the wire would let whoever gets past the
  guard spend the deployment's mail and SMS budget.
- **The document and the mount grew together**: `GenerateToolsOpenAPISpec` gained
  the two path items (`openapi.ts:1385-1416`, `:1456-1490`), each with the `400`
  the reference's own item does not carry, and
  `adapter/internal/wiretest/tools.go` went from 21 cases to 31 — the two-way
  comparison between the served document and the mount now runs over five routes
  instead of three. U22's stop-point survives as `toolsFeatureRoutes`, which is
  down to the telemetry query and the inbound webhook.
- **`GET <tools>/stream`, the tools router's SSE endpoint** (`tools_stream.go`).
  The port of `tools.router.ts:184-221`: `503 {"error": "SSE not enabled"}`
  when the facade was built without a manager (`:193-196`), the authorised
  topics built from the authenticated principal with the client's `?topics=`
  accepted only as a subset (`:203-216`, which is `auth.StreamTopics` — this
  route parses the parameter and calls it), and the response handed to
  `SseManager.Serve` for the life of the connection. **A credential may be
  given in the query string**: `auth.ToolsSseTokenMiddleware` is the port of
  `extractSseToken` (`:185-190`), which copies `?token=` into an
  `Authorization: Bearer` header before the guard runs, because a browser
  `EventSource` cannot set headers. It is reproduced because the family's
  clients depend on it, and it is not a deviation — it is the reference's own
  behaviour — but it is a cost to know: a token in a URL is a token in access
  logs, in `Referer` headers, in browser history and in every proxy that logs
  paths. The copy **overwrites** an Authorization header that was already
  there and takes precedence over the access-token cookie, so a request
  carrying both is authenticated as the query token. A host that will not pay
  that either sets `ToolsOptions.DisableStream` or serves `SseManager.Serve`
  from its own route. There is still **no resume**: `Last-Event-ID` is not
  read, nothing is retained, and a reconnection resumes from *now*.
- **The tools router's skeleton and its authentication posture** (`tools.go`,
  `HTTPConfig.Tools`). The port of `createToolsRouter`'s front half
  (`tools.router.ts:117-135`) and of its two documentation routes (`:332-352`).
  It mounts **beside** `APIPrefix`, at `Tools.Path` — `/tools` by default,
  which is the reference's own `swaggerBasePath` (`:127`) — because
  `createToolsRouter` is a second Express router the host mounts where it likes,
  outside the auth router's CSRF, rate-limiter and event-context layers. It
  carries none of those here either, which is what keeps `POST <tools>/track`
  reachable by a server-to-server caller once U23 mounts it.
  **The posture is a deviation.** The reference's guard slot is
  `authMiddleware ? [authMiddleware] : []` with all four feature flags
  defaulting to `true`, and it says nothing when the slot is left empty, so a
  host that forgets the middleware publishes `track`, `notify` and `stream`
  unauthenticated. This port mounts nothing until `HTTPConfig.ToolsMounted()` —
  `Tools.Enabled`, a `Tools.AuthTools` facade, **and** a `Tools.Access`
  decision. The reference's own default is one named call: `Access:
  auth.ToolsPublic()`. `auth.ToolsProtected(mw)` is the guarded posture, and it
  refuses a nil `mw` rather than degrading to an open router. See the
  `tools-router-requires-an-explicit-guard-decision` entry in the deviation
  register for what an open tools surface costs.
- **The four feature flags**, spelled in the negative —
  `ToolsOptions.DisableTelemetry`, `DisableNotify`, `DisableStream`,
  `DisableWebhook` — so that a zero `ToolsOptions` selects what
  `createToolsRouter(tools, {})` selects: all four groups on
  (`tools.router.ts:121-124`). `ToolsOptions.Features()` resolves the negation
  once, for the router, the document and every route U23 through U25 adds.
- **The tools router's own documentation routes and its own OpenAPI generator**
  (`openapi_tools.go`): `GET <tools>/openapi.json` and `GET <tools>/docs`, both
  under `Tools.Docs` — the reference's second `swagger` / `swaggerBasePath`
  pair (`tools.router.ts:93-101`), `DocsOptions` again because it is the same
  pair of options, and a plain bool for the same reason `HTTPConfig.Docs` is.
  Neither route carries the guard, as neither carries `protect` there (`:333`,
  `:348`). `GenerateToolsOpenAPISpec` is the port of `buildOpenApiSpec`
  (`openapi.ts:1366-1637`), a second generator because the reference has a
  second one and because it describes a router mounted somewhere else entirely.
  The Swagger UI page is `SwaggerUIHandler` unchanged: the reference has one
  builder for all three of its routers, and its title — "Tools API" — is a
  quirk this port already reproduces on the auth router, where it is wrong, and
  which on this one is simply correct.
- **The shape U23 through U25 add a route into**: one `switch` in
  `(*Auth).ToolsHandler`, the way U12 left the admin surface, plus
  `auth.ToolsProtectMiddleware(cfg)` for the routes the reference spreads
  `...protect` onto and the five `Tools*Path` constants. Conformance for all
  four adapters is `adapter/internal/wiretest/tools.go`, which holds the
  document and the mount to each other in both directions; `suite.go` gained one
  line. It is deliberately **not** in that file's `conditionalRoutes` registry,
  which holds every set to `GenerateOpenAPISpec` — the auth router's document,
  whose paths are relative to `HTTPConfig.Prefix()`.
- **The `AuthTools` facade and its fan-out** (`auth_tools.go`). The port of
  `src/tools/auth-tools.ts`: one `Track` call becomes four shapes — a
  `TelemetryEvent` for the store, an `Event` for the bus, a `StreamEvent` for
  the stream and an `OutgoingWebhookEvent` for each matching subscription — in
  the source's own order, **telemetry, bus, SSE, webhooks**
  (`auth-tools.ts:216`, `:221`, `:233`, `:249`). The order is reproduced rather
  than chosen because it is observable: a bus subscriber that reads the
  telemetry store finds the record for the event it is handling only because
  the save already happened. One event id and one instant are generated per
  event and shared by every shape (`auth-tools.ts:200-201`), which is what makes
  the per-connection SSE deduplication work when an event reaches a connection
  on more than one topic.
- **The SSE frame carries the whole telemetry record**, not the tracked payload
  — the question U20 left open on purpose. The reference puts `telemetryEvent`
  on the frame (`auth-tools.ts:240`), so a client reads the payload at
  `rawData.data` and gets the correlation id, session id, IP and user agent
  beside it. The record is spelled on the wire with the reference's key names
  (`event`, `data`) rather than this package's Go field names (`EventName`,
  `Meta`), and the `Success` field, which this port's `TelemetryEvent` has and
  the reference's has not, is left zero and never sent: a tracked event is a
  thing that happened, not a thing that succeeded.
- **`EventTopics` and `StreamTopics`**, the two halves of the topic rule, which
  have to agree or a subscriber never sees an event meant for it. `EventTopics`
  is the reference's `resolveTopics` (`auth-tools.ts:353-359`): `global`, then
  `tenant:<id>`, `user:<id>` and `session:<id>` for each identifier present.
  `StreamTopics` is its stream route's server-authorised list and subset filter
  (`tools.router.ts:207-216`): `global`, `tenant:<id>`, `user:<id>`, and a
  client-requested topic outside that set is dropped rather than refused. The
  two deliberately do **not** agree about `session:<id>`, because the reference
  does not: it is published to and cannot be subscribed to through that route,
  and both halves are reproduced rather than reconciled in either direction. In
  this port the tenant topic is unreachable for a second reason until M8 —
  `Event.TenantID` is empty on everything the library publishes.
- **Failure isolation, sink by sink.** Nothing a sink does fails the call and
  nothing a sink does stops another sink, so `Track` returns no error: the
  telemetry write is awaited and its error discarded (`auth-tools.ts:218`), a
  webhook store lookup that fails is no webhooks rather than a failure
  (`:251`), each delivery is fire-and-forget with its own error discarded
  (`:266`), and a broadcast that reaches nobody is not reported in either tree.
  The one place the reference *can* fail the caller — an unguarded
  `eventBus.publish` (`:231`) — cannot here, because `EventBus.Publish` recovers
  each handler; that is U18's already-registered
  `event-handler-panic-does-not-fail-the-publisher` inherited, not a new
  difference. `AuthToolsOptions.OnError` is how a deployment buys back the
  observability the reference discards, and nil — silence — is the default.
- **`Notify`**, the other public method (`auth-tools.ts:292-342`): one payload
  to one named topic and, optionally, to the user's inbox and handset. It is the
  one broadcast in the package that does not fan out across `EventTopics`,
  because the caller names the channel. The email and SMS channels are reached
  only for a user the store returns who has the contact detail in question, the
  subject falls back to the type and then to `Notification`, and the two default
  bodies encode the same payload differently — indented for email, compact for
  SMS — because the reference passes `null, 2` to one `JSON.stringify` and not
  the other. Both transports are the ones this package already has,
  `MailerTransport` and `SMSTransport`, rather than a second copy of their
  configuration.
- **`AuthTools.Bridge`**, and the decision that it is not automatic. The
  reference's `AuthTools` is fed by a host calling `track` and by nothing else;
  this port additionally raises nineteen `identity.*` events that no `track`
  call produced, so **by default a deployment gets silence from them** and one
  call changes that. Subscribing the bus automatically was rejected mainly
  because it would deliver every *tracked* event twice — `Track` publishes at
  step 2 and then broadcasts and fires webhooks at steps 3 and 4, so a facade
  that also subscribed would hear its own publication and repeat both, with a
  second event id the deduplication cannot collapse — and breaking that loop
  inside the library means a hidden marker on `Event` that exists so one type
  can ignore another's messages. A default that POSTs account events to whatever
  URLs a store happens to hold is also the unrecoverable half of the choice, and
  U19 drew this line first and said why. `Bridge` runs the same fan-out minus
  the bus step, so a bridged event gets the same id, frame and envelope a
  tracked one does.
- **The credential half of the admin API** (`admin_credentials.go`): the eight
  routes of `admin.router.ts` that hold, mint or mask a secret, behind the same
  `AdminGuard.Protect` as the reads and the writes — `GET` and `POST
  /api/api-keys`, `DELETE /api/api-keys/{id}/revoke` and `DELETE
  /api/api-keys/{id}`, `GET` and `POST /api/webhooks`, `PATCH` and `DELETE
  /api/webhooks/{id}`. They are their own PR because their invariant is **secret
  redaction**, and reviewing a mask apart from the write that fills the field it
  hides is how a mask gets missed.
  **What reaches the wire.** The key listing is a hand-picked projection of ten
  fields — `id`, `name`, `keyPrefix`, `serviceId`, `scopes`, `allowedIps`,
  `isActive`, `expiresAt`, `createdAt`, `lastUsedAt` — on a **type that does not
  carry `keyHash` at all**, so the bcrypt hash cannot reach a response through a
  tag someone deletes or a second serialiser; the reference maps the same ten out
  of an object that does carry it (`:1266-1277`), which is the weaker form of the
  same rule. `POST /api/api-keys` answers `{rawKey, record}` and is the **only
  place the raw key exists**: the store holds its bcrypt hash, the nine-field
  `record` beside it does not repeat it, and no later route can produce it. The
  webhook listing masks the signing secret to `***` (`:1381`) where the store
  holds it in the clear, because an HMAC has to be reproducible; `POST
  /api/webhooks` masks the row it echoes the same way (`:1406`), and `PATCH`
  echoes nothing at all — a patch that does not name `secret` leaves the stored
  one untouched, and one that does writes it in the clear. Each of those is
  pinned by a conformance case asserting the secret's **bytes are absent from the
  serialised response**, not that a field is empty.
  **Two absences, two statuses**, which is what v0.8.0 split the optional API-key
  methods one-to-an-interface for: `404 {"error": "API key store not
  configured"}` when no store is configured (`:1254`) against `501 {"error":
  "IApiKeyStore.listAll is not implemented", "keys": [], "total": 0}` when one is
  and cannot enumerate (`:1259-1262`), and the same split on the webhook side per
  method (`listAll`, `add`, `update`, `remove`). `DELETE /api/api-keys/{id}` is
  the other direction of it: with no `APIKeyDeleteStore` it revokes instead and
  says so — `200 {"success": true, "note": "IApiKeyStore.delete not implemented;
  key was revoked instead"}` (`:1348-1354`) — which is only expressible because
  the absence of that one method is observable on a store whose others are
  present.
  The reference's own defaulting stays in the route, as there: `events ?? ['*']`
  and `isActive ?? true` (`:1403-1404`) — nullish and not falsy, so an explicit
  `[]` is stored as a subscription to nothing — `url` required (`:1397`), and
  `limit` clamped to 100 and defaulted to 20 on both listings with the same
  off-by-one `total` the users table has. An unparseable `expiresAt` is a key
  that does not expire rather than a refusal, because `new Date('tomorrow')` is
  an Invalid Date that compares false against every instant (`:1312`).
  Two stores reach the `Auth` for the first time: **`WithAPIKeyStore`** and
  **`WithWebhookStore`**, which are the reference's `AdminOptions.apiKeyStore`
  and `webhookStore` (`:120-131`) and which turn the console's **`apiKeys` and
  `webhooks` feature flags** on — `!!store` there (`:653-654`), so a store that
  cannot enumerate still draws its tab and answers `501` to the listing behind
  it.
  One entry joins the deviation register with these routes:
  `admin-credential-listings-are-ordered`. The reference declares no order for
  either listing and ships no implementation of either `listAll?` to have one;
  this port answers API keys **`CreatedAt` descending, `ID` ascending** and
  webhooks in **first-insertion order**, both stated on the store interfaces
  since v0.8.0 and both client-visible for the first time now. It is
  `admin-listings-are-ordered-by-id`'s argument for the two listings that entry
  deliberately left out, with one addition: a row paged past on these screens is
  a credential nobody revokes.
- **The mutating half of the admin API** (`admin_write.go`): the sixteen routes
  of `admin.router.ts` that change state, behind the same `AdminGuard.Protect`
  as the reads — `DELETE /api/users/{id}`, `POST /api/2fa-policy`,
  `PUT /api/users/{id}/metadata`, `POST /api/users/{id}/roles` and
  `DELETE /api/users/{id}/roles/{role}`, `PUT /api/settings` and
  `PATCH /api/settings/ui`, `DELETE /api/sessions/{handle}`, `POST /api/roles`
  and `DELETE /api/roles/{name}`, the four tenant writes, and the two template
  upserts. Fifteen answer `{"success": true}` and nothing else;
  `POST /api/tenants` answers the row it created and `POST /api/2fa-policy` a
  count beside the flag. The eight credential routes (API keys and webhooks) are
  a separate PR, whose invariant is secret redaction.
  `POST /api/2fa-policy` walks the whole user table in pages of 100 — `listUsers`
  until a page comes back short — and reports `updated` as the number of users
  *listed*, not of rows changed (`admin.router.ts:836-848`). It needs a
  capability this port had no seam for, so one is added:
  **`UserTwoFactorPolicyStore`**, the reference's optional
  `IUserStore.updateRequire2FA` in `store.go`'s style — a narrow interface the
  core type-asserts — with `MemoryUserStore` implementing it. That pair is what
  turns the console's **`twoFAPolicy` feature flag on**, since the reference
  gates the flag on `updateRequire2FA && listUsers` (`:649-650`); the route's own
  two `501`s are asked in that same order, so a store with neither is told about
  the write first. The listing half of its refusal is the third of the three
  distinct answers this codebase gives for one missing `listUsers` — bare, with
  no `users` and no `total` (`:832`) — and it stays distinct from the other two.
  `PUT /api/settings` and `PATCH /api/settings/ui` keep the reference's division
  of labour exactly. `MergeSettings` is a shallow spread and `ui` is one field of
  the patch, so a `PUT` carrying `ui` replaces the branding block whole and drops
  the seven fields it does not name; the `PATCH` route therefore reads the
  current settings, merges the UI sub-object **itself**, and sends the merged
  block back down (`:979-981`). Moving that merge into the store would make one
  field of the patch mean something different from every other and would be a
  different product. That route is also the only one of the sixteen whose `500`
  carries the error's own message rather than the flat `Internal server error`,
  as there (`:984-985`).
  Three reference behaviours are reproduced rather than tidied, and are called
  out because each looks like a bug: `DELETE /api/users/{id}` calls
  `deleteUser` and nothing else, so the deleted user's **sessions, roles, tenant
  memberships, metadata and linked accounts all survive the account** — the same
  codebase cascades on the user's own `DELETE /account`
  (`auth.router.ts:1597-1636`), so the omission is the console's, not an
  oversight to read past. `PUT /api/users/{id}/metadata` is a `PUT` that
  **merges**, because `IUserMetadataStore.updateMetadata` is specified as a
  shallow patch. And `POST /api/templates/mail` is an **upsert whose patch is not
  partial**: the handler rebuilds `{baseHtml, baseText, translations}` out of the
  body with all three keys present whatever it held, so a post naming only an id
  blanks the stored bodies and translations (`:1462`,
  `memory-template.store.ts:22`). All six deletes are unconditional — none looks
  the row up, none answers `404`, none reports what it did.
  The double `decodeURIComponent` U13 found on `GET /api/tenants/{id}/users` is
  on the sibling writes too, and on four more routes: the session handle, the
  role name of both role deletes, and both ids of
  `DELETE /api/tenants/{id}/users/{userId}`. The user id of
  `DELETE /api/users/{id}` and of `POST /api/users/{id}/roles` is not decoded
  twice, which is the reference's own asymmetry.
  No entry joins the deviation register with these routes.
- **The read half of the admin API** (`admin_read.go`): the fourteen `GET`s of
  `admin.router.ts`'s read surface, every one of them behind
  `AdminGuard.Protect` and none behind `ProtectShell` —
  `/api/users`, `/api/users/{id}` and its four sub-resources (`metadata`,
  `linked-accounts`, `roles`, `tenants`), `/api/actions`, `/api/settings`,
  `/api/sessions`, `/api/roles`, `/api/tenants`, `/api/tenants/{id}/users`,
  `/api/templates/mail` and `/api/templates/ui`. Each body is the reference
  handler's field for field, including the parts that are quirks:
  `GET /api/users` clamps `limit` to 100 and defaults it to 20, fetches a
  500-row batch at offset 0 when a `filter` is given and filters it in memory on
  an email-or-id substring, and reports `total` as
  `len(page) + offset + (len(page) == limit ? 1 : 0)` — a best-effort number
  whose only job is the table's "next" button and which is off by one whenever
  the last page is exactly full (`admin.router.ts:782`). Its projection is the
  reference's hand-picked eight (`id`, `email`, `role`, `isEmailVerified`,
  `isTotpEnabled`, `require2FA`, `phoneNumber`, `createdAt`); `isAdmin` is in it
  nowhere, because the reference serialises that field nowhere. The three
  answers the reference gives to one missing capability are kept distinct: `501`
  with an empty page here, the guard's `500` sentence for `'first-user'`, and
  the bare `501` of the 2FA-policy walk. `GET /api/roles` keeps the two absences
  apart the same way the reference does — `404` when no RBAC store is
  configured, `501` when one is and cannot enumerate — by asking whether it was
  given a store rather than by reading an error. `GET /api/actions` answers the
  empty registry: this port has the settings half of the inbound-webhook action
  feature and not the registry, and inventing a registration seam is the tools
  router's work. The two template listings are registered only where a
  `TemplateStore` is, as there.
  One entry joins the deviation register with these routes:
  `admin-listings-are-ordered-by-id`. v0.8.0 declared **ID ascending** as the
  normative order of the three admin listers, and that order only became
  client-visible now that something serves it — the reference's own stores page
  these routes with no `ORDER BY` at all, which makes `offset` paging
  non-deterministic and makes its `'first-user'` access policy read whichever
  row a query planner returned first. The templates and linked-accounts
  listings are *not* covered: those stay in insertion order, matching the
  reference.
- The admin console's skeleton: the access guard, its own login and logout, the
  two static asset routes and the HTML shell, mounted at `HTTPConfig.Admin.Path`
  — `/admin` by default, and a sibling of `APIPrefix` rather than a child of it,
  because the reference's admin router is a second router the host mounts on its
  own. `AdminGuard` ports `buildPolicyGuard` branch for branch: the four access
  policies (`open`, `first-user`, `is-admin-flag`, and a host predicate handed
  the user and the RBAC store), the `Authorization`-then-cookie extraction with
  the `__Host-` / `__Secure-` / bare read order, the three-way unauthenticated
  branch, the `isRoot` bootstrap override, and `first-user`'s `500` for a store
  that cannot enumerate. `POST <admin>/login` accepts a configured root user, the
  legacy `adminSecret` and the ordinary user store, in that order, and sets a
  24-hour session cookie; `POST <admin>/logout` clears it. Everything M8 mounts
  from here sits behind `AdminGuard.Protect`.
- **The reference's outbound webhook wire format** (`webhook_sender.go`,
  `WebhookSender`). The port of `src/tools/webhook-sender.ts`: one `POST` to
  `WebhookConfig.URL` carrying the serialised `OutgoingWebhookEvent` and
  `Content-Type: application/json`, `X-Webhook-Event`, `X-Webhook-Delivery`,
  `X-Webhook-Timestamp` and — only when the subscription holds a secret —
  `X-Webhook-Signature: sha256=<hex HMAC-SHA256 of the body>`
  (`webhook-sender.ts:24-33`, `:54-56`). Three details of it are reproduced
  rather than improved, because a receiver would see each one: the delivery id
  is minted *inside* the retry loop (`:27`), so it identifies an attempt and not
  an event and cannot be used to deduplicate; `X-Webhook-Timestamp` is the
  envelope's own timestamp rather than the moment of the request (`:28`), so a
  retry an hour later still names the instant the event happened; and the body
  is serialised once before the first attempt (`:20`), so every attempt carries
  identical bytes and an identical signature. The timestamp is a string in the
  exact shape `toISOString()` produces — UTC, always three fractional digits, a
  literal `Z` — which is what `OutgoingWebhookEvent.Timestamp` has said since
  v0.8.0 and what the new exported `WebhookTimestamp` produces: Go's RFC 3339
  emits as many fractional digits as the value happens to have, and a receiver
  checking a signature over the raw body would see a different string for the
  same instant. `Event.OutgoingWebhook` builds the envelope from an `Event`,
  taking `metadata` from `Event.WebhookMetadata()` rather than assembling the
  four identifiers a second time.
- **Retry, with the reference's arithmetic** (`WebhookSender.Send`). Stated in
  attempts rather than retries, because the two are off by one:
  `while (attempt <= maxRetries)` runs `WebhookConfig.Retries()+1` times, so the
  default 3 is **four** requests. A non-2xx and a transport failure are the same
  failure and both retry while attempts remain (`webhook-sender.ts:37-43`);
  between them the sender waits `WebhookConfig.RetryDelay()` doubled once per
  retry already made — with the defaults 1s, 2s, 4s — and the last attempt is
  not followed by a wait, because the reference returns out of the loop before
  the delay (`:39`, `:42`). Both defaults are resolved in the sender and not in
  the store, which is why `MaxRetries` and `RetryDelayMs` are `*int`: a stored
  `0` means "deliver once, never retry" and must not decay into four
  deliveries, and a stored negative count sends nothing at all because
  `while (attempt <= -1)` never runs. The exhaustion is silent on the wire and
  in the log, as the reference's is.
- **A pluggable deliverer** (`WebhookDeliverer`, `WebhookAttempt`,
  `HTTPWebhookDeliverer`, `WebhookDelivererFunc`). The seam that replaces the
  reference's bare `fetch` (`webhook-sender.ts:36`), and it sits *below* the
  format and *below* the policy: the sender has already built the envelope,
  signed it, minted the attempt's delivery id and decided how many attempts
  remain, so an implementation POSTs `Body` to `URL` with `Headers` and reports
  what happened. A host moving delivery onto a queue reimplements neither the
  signature, nor the retry policy, nor the envelope. `WebhookAttempt` is
  self-contained and JSON-serialisable, and deliberately carries `ConfigID` but
  never the subscription's secret. The doc comment on `WebhookDeliverer` states
  what a host owes in full — no ordering is promised or required; this package
  promises at-most-once and persists nothing, so at-least-once is the host's to
  buy by making the call durable before returning `nil`; once it returns `nil`
  this package is finished, so a queueing deliverer owns the retry policy and
  the dead-letter queue for the real request, and reproduces the reference's
  schedule from `Retries()` and `RetryDelay()` rather than from hard-coded
  numbers; and the delivery id must be resent rather than re-minted. The
  default is `HTTPWebhookDeliverer`, which is the reference's own behaviour plus
  the request timeout Go needs and the reference does without
  (`DefaultWebhookTimeout`, 10s, per-instance).
- **`WebhookEmitter`** — step 4 of the reference's `AuthTools.track`
  (`auth-tools.ts:263-281`) and exactly that step: look the subscriptions up,
  build one envelope, fan out. The lookup is synchronous on the calling
  goroutine as `track`'s is; a store failure becomes an empty result and never a
  failed publish (`.catch(() => [])`, `:265`); the envelope is built once and
  shared, so two subscriptions receive byte-identical bodies; and every delivery
  runs on its own goroutine with `context.WithoutCancel` of the caller's
  context, because the reference does not await `send` (`:280`) and a delivery
  that died when the response was written would be a retry policy that never
  retried. Failures are silent by default, as the reference's are; the optional
  `OnError` hook is how a deployment buys the observability back.
  `WebhookEmitter.Subscribe(bus)` is the one-line bridge from the event bus,
  and it is a call a host makes — **nothing in this package subscribes an
  emitter for you.** Neither tree ships such a bridge, `AuthTools` is U21, and
  the order webhooks run in relative to telemetry, the bus and SSE is one
  decision that belongs to the facade that owns all four.
- **The reference's `SseManager` protocol** (`sse.go`). `SseManager` is
  `src/tools/sse-manager.ts` ported whole: connections rather than channels, a
  set of server-chosen topics per connection, `StreamEvent` frames with `id`,
  `type`, `timestamp`, `topic`, `data`, `userId`, `tenantId` and `metadata`,
  heartbeat comments, per-connection deduplication by event id, and the
  `SseDistributor` seam for cross-instance fan-out.
  The frame is the reference's byte for byte:
  `id: <id>\n`, `event: <type>\n`, `data: <json>\n\n`. The payload object is the
  event reshaped the way `write` reshapes it (`sse-manager.ts:252`) — the key
  `data` is **absent** and the payload arrives under `rawData` — and it is
  serialised with HTML escaping off, because `JSON.stringify` escapes nothing
  and an event stream has no `<script>` to break out of. There is always exactly
  one `data:` line: the payload is JSON, and JSON never contains a raw newline.
  The keep-alive is `: heartbeat\n\n`, with the space the reference's code
  writes although its own documentation spells the comment `:heartbeat`
  (`sse-manager.ts:159` against `:47`).
  Topics are matched by exact string equality. The hierarchical scheme the
  reference documents (`global`, `tenant:{id}`, `user:{id}`, …) is a naming
  convention and nothing else — no prefix, wildcard or ancestor matching exists
  in either implementation, so a publisher that wants a parent and a child sends
  to both, which is what the deduplication is for. The server decides a
  connection's topics; no client ever names a channel.
  Deduplication is on by default and compares an event's id against the
  **previous** event sent to that connection and nothing older
  (`sse-manager.ts:214`), so it absorbs one event fanned out across several
  topics and is not a general guard against redelivery. Heartbeats default to
  30 s and `WithSseHeartbeat(0)` disables them, exactly as the reference's `0`
  does.
  **There is no resume, in this port or in the reference.** Nothing reads the
  `Last-Event-ID` header a browser sends when its `EventSource` reconnects,
  nothing retains a delivered event, and the per-connection last event id is
  only ever compared against the next event's. A reconnect resumes from *now*
  and what was raised in between is gone. The `id:` line is an identity and a
  deduplication key, not a cursor: anything building delivery across a
  reconnect on top of this is adding a guarantee, not implementing one.
  No route serves this yet — `GET <prefix>/tools/stream` arrives with the tools
  router — and no `AuthTools` facade decides the fan-out order across telemetry,
  the bus, SSE and webhooks.
- **`SseDistributor`**, the reference's `ISseDistributor`
  (`sse-distributor.interface.ts:10-25`): `Publish(ctx, topic, StreamEvent)` and
  `Subscribe(ctx, fn)`. It is what makes the design work where every connection
  lives in its own process — a Lambda Function URL, say — since in-process
  fan-out there reaches nobody. Its contract is written on the interface because
  the reference states none of it: no ordering is required; at-most-once and
  at-least-once are both safe, the latter only because an *immediate*
  redelivery is absorbed by the deduplication; and a `Publish` that errors makes
  the manager fall back to delivering to its own connections and no others
  (`sse-manager.ts:191-194`). The fact to design around is that with a
  distributor configured, `Broadcast` does **not** deliver locally: local
  connections are served only when the distributor calls the subscription back,
  so one that does not echo a publisher's own events back to it reaches every
  instance except the one that raised them.
  `NewSseManager` takes a `context.Context` and returns an error where the
  reference's constructor does neither, and both follow from this seam: the
  reference calls `subscribe` from its constructor without awaiting or catching
  the promise, so a distributor that cannot reach its bus leaves a manager that
  looks healthy and silently receives nothing from the fleet.
- **`StreamEvent`**, the reference's event type. Its JSON tags are the shape a
  *distributor* carries — `publish` takes the whole object — and not the shape
  of the SSE frame, so a TypeScript distributor and a Go one exchange the same
  bytes.

### Changed
- **BREAKING — `WebhookDispatcher` and its wire are removed.** `webhooks.go` is
  gone, and with it `WebhookDispatcher`, `NewWebhookDispatcher`,
  `(*WebhookDispatcher).Dispatch`, `WebhookEndpoint`, `WebhookPayload` and the
  `X-Signature-SHA256` header. None of it was the reference's: the endpoint
  list, the `{id, event, timestamp, data}` envelope and that header name were
  this port's own invention, written before `webhook-sender.ts` was ported, and
  v0.8.0's `WebhookStore` entry named this release as the one that would replace
  them. A deployment on the old type changes three things. **Subscriptions move
  from code into a store**: build a `WebhookStore` — `NewMemoryWebhookStore()`
  is the in-process one — and `AddWebhook` a `WebhookConfig` per endpoint
  instead of passing `WebhookEndpoint` values to a constructor. Note that an
  empty `Events` list now subscribes to **nothing**, where `WebhookEndpoint`
  read the same emptiness as every event: use `auth.WebhookEventWildcard` for
  the old behaviour. **The wiring changes shape**:
  `bus.Subscribe("*", func(e auth.Event) { dispatcher.Dispatch(ctx, e) })`
  becomes `(&auth.WebhookEmitter{Store: store}).Subscribe(bus)`. **And every
  receiver has to be updated**, because both the header and the body changed: a
  receiver reads the signature from `X-Webhook-Signature` rather than
  `X-Signature-SHA256` (`VerifyWebhookSignature` is unchanged, keeps its
  signature and now lives in `webhook_sender.go`), and it decodes an
  `OutgoingWebhookEvent` — `{event, version, timestamp, data, metadata}`, with
  `timestamp` a string and the four identifiers under `metadata` — rather than
  `WebhookPayload`'s `{id, event, timestamp, data}`. Deliveries are also no
  longer a single fire-and-forget POST: they retry, so a receiver must be
  idempotent, and it may not key that idempotency on `X-Webhook-Delivery`, which
  changes per attempt. `examples/chi-postgres` shows the whole migration.
  Nothing else in the package referenced the removed type, no route changed on
  any adapter, and no entry was added to the deviation register — this release
  removes a deviation's worth of difference rather than adding one.
- **BREAKING (API) — `SseHub`, `NewSseHub`, `SseMessage`, `ServeSSE` and the old
  `SseDistributor` are removed.** They spoke a protocol the reference does not
  have: channels instead of connections, a two-method `SseDistributor` shaped as
  `Subscribe(ctx, channel) (<-chan SseMessage, error)`, and a `:ping` keep-alive.
  Nothing in the family's clients speaks it, and keeping it beside the real
  protocol would have meant two SSE surfaces with different frames.
  A host that used them changes three things. `auth.NewSseHub()` becomes
  `auth.NewSseManager(ctx)`, which returns an error. `hub.Publish(ctx, userID,
  auth.SseMessage{Event: name, Data: data})` becomes
  `sse.Broadcast(ctx, "user:"+userID, auth.StreamEvent{Type: name, Data: data})`
  — note the channel becomes a topic, and the topic is a namespaced string
  rather than a bare id. `auth.ServeSSE(hub, channel)` becomes
  `sse.Serve(w, r, topics, auth.SseConnectionMeta{…})` called from inside the
  handler: it blocks for the life of the stream instead of returning a
  `http.HandlerFunc`, because that is what holds a connection open in Go.
  Clients change too, and this is the half that is easy to miss: the frame's
  payload is no longer the bare `Data` map. It is an object carrying the event's
  identity with the payload nested under `rawData`, so a browser doing
  `JSON.parse(e.data)` now reads `.rawData` where it used to read the object
  itself. The `id:` and `event:` lines are unchanged in meaning.
  An implementor of the old `SseDistributor` rewrites it against the new
  interface; the two have no method in common.
- **BREAKING (API) — `EventBus.Subscribe` returns a cancel function.** It is the
  port of the reference's `offEvent` (`auth-event-bus.ts:79-81`), which this bus
  had no counterpart for at all. Go functions are not comparable, so
  `Unsubscribe(name, handler)` cannot be written; the Go shape is the cancel the
  caller already holds. It arrived with the first consumer that needed it — SSE
  subscriptions are the only ones in the plan that end before the process does.
  **Existing call sites compile unchanged**, because Go permits discarding a
  return value; what breaks is code that stored `Subscribe` as a
  `func(string, func(Event))` or satisfied an interface with it.
  The cancel is idempotent, and it does not reach a dispatch already in flight:
  `Publish` copies the handler list before calling anything, exactly as
  `EventEmitter` clones its listener array before emitting, so a handler
  cancelled mid-dispatch may still be called for that event.
- **BREAKING (behaviour) — a slow SSE consumer is disconnected.** Registered as
  `sse-slow-consumer-is-disconnected`. Each connection has a bounded queue
  (`WithSseSendBuffer`, 64 frames by default) and a ten second write deadline; a
  publisher is never blocked by a reader, and a connection that overflows either
  bound is closed. The reference ignores the backpressure signal `res.write`
  returns and queues without limit, which is a Node stream behaviour rather than
  a decision and is not portable — Go's choices are to block the publisher (one
  stalled client would stall every login, since `EventBus.Publish` is
  synchronous on the request goroutine), to drop silently, or to end the
  stream. Ending it is the only one that makes the gap visible at the moment a
  client can act on it, and since neither implementation replays, a silently
  dropped frame is unrecoverable.

## [0.9.0] - 2026-09-12

The hosted UI, and it is the reference's own rather than this port's imitation
of it. All fourteen assets are vendored byte for byte — the git object names are
identical to upstream's, so the identity is by construction and not by a hash
comparison — and a drift check fails on a changed file, an added one, a removed
one, a wrong count, and on CRLF re-mangling, which gets its own message because
its fix is the `.gitattributes` entry rather than a re-vendor.

`UIHandler` serves them the way `ui.router.ts` does: the config document, the
headless short-circuit that serves assets and no HTML at all, the uploaded
assets, the SSR catch-all with its page mapping and its three fallbacks, and
static serving underneath. The injection is reproduced replacement by
replacement, including the CSS variables, the escaped site name, the logo swap
and the readiness splash.

One place this port is deliberately stricter than the reference, and it is in
the register as `ui-ssr-config-json-is-html-escaped`: the injected
`__AUTH_CONFIG__` is serialised with `encoding/json` at its defaults, so a
`</script>` inside a branding string cannot end the block. The two sinks the
reference also has and this release does not close — `customCss` and `logoUrl`,
both unescaped because escaping them changes what renders — are named in that
entry rather than left to be discovered.

The event plane is laid but not yet speaking: the `identity.*` vocabulary, the
payload fields the reference's bus carries, and a request-context carrier the
four adapters install outermost, so that a correlation id, a client address and
a user agent survive from the request to whatever publishes. Nothing publishes
yet — that is the next milestone, and it is the milestone that finally gives
`EventBus.Publish` a caller.

One note for operators reading the gin adapter: `<prefix>/ui/config` is no
longer registered as a route of its own by any adapter. It is served by
`UIHandler`, which is where the reference puts it. The document, its headers and
its CSRF behaviour are unchanged, and the conformance suite holds all four
adapters to the same answer.

### Added
- **The hosted UI is served** (`ui_pages.go`, `UIHandler`).
  `HTTPConfig.UI.Enabled` now mounts the whole of the reference's
  `ui.router.ts` at `<prefix>/ui` on all four adapters, not just its config
  route: the nine vendored HTML pages with the server-side config injection
  they expect, the static assets beside them, the uploaded logos, and headless
  mode.
  The four layers run in the reference's own order, which is behaviour rather
  than style — `/config` answers before the headless short-circuit, the
  short-circuit returns before the uploaded assets are mounted, and the SSR
  catch-all runs before the static serve, which is the only reason
  `<prefix>/ui/login` is a page and `<prefix>/ui/base.css` is a file. A `GET`
  for a path with no extension renders `<page>.html`, or — when there is no
  such file — the first of `login.html`, `index.html`, `index.csr.html` that
  exists, so no extensionless path under the mount answers `404`. A path with
  an extension is served as a file or not at all. Every other method falls
  through.
  The injection is the reference's, replacement by replacement: a `:root` block
  carrying `--primary-color` and `--input-focus` (both from `primaryColor`),
  `--secondary-color`, `--bg-color`, `--card-bg`, and `--bg-image` with `'`,
  `"` and `\` percent-encoded; `customCss` in a second `<style>`; the
  HTML-escaped `siteName` in `<title>` and in `<h1 class="site-name">`; the
  logo tag rewritten without its `hidden` class; the readiness splash; and
  `window.__AUTH_CONFIG__` before `</head>`. Pages go out as
  `text/html; charset=utf-8` with
  `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`; static files
  carry express-static's `public, max-age=0`. On an injection failure the page
  is sent unmodified, as there.
  `UIOptions.Assets` is the reference's `uiAssetsDir` and defaults to the
  vendored set; `UIOptions.Uploads` is its `uploadDir`, served under both
  `<prefix>/ui/assets/logo/` and `<prefix>/ui/assets/uploads/`, and unset — the
  default — mounts neither path rather than failing on a store that is not
  there. Both are `fs.FS`, which is the seam the `UploadStore` will supply when
  it lands in U15.
  One deviation is registered with it, `ui-ssr-config-json-is-html-escaped`.
  The reference writes `JSON.stringify(config)` straight into a `<script>`
  block, where a `</script>` inside `siteName`, `logoUrl` or `customCss` closes
  the element and everything after it is parsed as markup and runs. This port
  serialises with `encoding/json` at its defaults, which escape `<`, `>` and
  `&`, so the sequence stays inside the string. The bytes on the wire differ
  whenever the branding contains one of those three characters; the value
  `JSON.parse` yields does not, so no client can see the difference. It is the
  only entry in the register where this port is stricter than the reference.
  `customCss` into `<style>` and `logoUrl` into `<img src>` are reproduced
  unescaped, as there, and the entry records who can reach them.
  The conformance suite gains a `UIPages` group, run against all four adapters,
  asserting the classification rules on one representative per arm, the
  branding in the rendered page, headless mode, the uploaded assets and the
  CSRF cookie. It is deliberately not a `conditionalRouteSet`: a catch-all is
  not a path list, and an HTML page is not an API operation, so these paths are
  not in the generated document and the set that tracks `<prefix>/ui/config`
  against it is unchanged.
- **The reference's fourteen UI assets, vendored byte for byte**
  (`ui/upstream/assets/`, `ui_upstream.go`). The nine HTML pages, `auth.js`,
  `admin.js`, `admin.css`, `base.css` and `ui-i18n-keys.json` that
  awesome-node-auth serves from `src/ui/assets` at `cc01e997` (v1.9.0) are now
  copies rather than re-implementations — 192,107 bytes, embedded with
  `embed.FS` and reachable as `UpstreamUIAssetFS()` (an `fs.FS` rooted at the
  asset directory), `ReadUpstreamUIAsset(name)` and `UpstreamUIAssets()`, which
  returns the provenance table: upstream path, commit, size and sha256 per file.
  Until now this port served a hand-written UI written by reading the reference
  instead of copying it, and that bet had already been lost once — the header of
  `ui_test.go` is the post-mortem, listing three routes the hand-written SDK
  called that no adapter has ever mounted. A copy cannot drift from a tree it is
  byte-identical to.
  The provenance is recorded *beside* the bytes, never inside them, and that is
  a decision rather than an oversight: a "generated, do not edit" banner is
  itself bytes, so a file carrying one is no longer what the reference ships and
  every one of the fourteen would read as differing from upstream on the first
  hash. (`ui-i18n-keys.json` settles it alone — JSON has no comments, so a
  banner there would have to be a fake key every consumer would then see.) The
  bytes win; the provenance lives in `upstreamUIAssetTable`, in
  `ui/upstream/README.md`, and in the drift check's failure message, which is
  where somebody about to edit an asset in place actually ends up.
  Nothing serves these files yet and no route is mounted. `UIHandler`, the SSR
  config injection the reference's pages expect, the catch-all and headless mode
  are the next change in this milestone; no adapter was touched.
- **A drift check, run by `go test ./...`** (`TestVendoredUIAssetsHaveNotDrifted`).
  It re-hashes every embedded asset and compares it against the checked-in
  sha256 table, and it fails in five distinct ways: an asset's contents differ
  from the table; a file is embedded that the table does not list; the table
  lists a file that is not embedded; the count is no longer the stated fourteen;
  or the bytes were re-mangled to CRLF by a checkout, which gets its own message
  because its fix is a `.gitattributes` entry and not a re-vendor. The second of
  those is why the check walks the embedded filesystem instead of ranging over
  the table — a loop over the table is blind in exactly the direction that
  matters, and can never see a file that was added. Every message names the
  `git cat-file blob` line that restores the file and says plainly that the
  alternative is a deliberate re-vendor. CI already runs `go test -race ./...`,
  so this needed no workflow change and got none.
  `TestVendoredAssetsCallRoutesThatExist` extends `ui_test.go`'s
  `asset paths ⊆ GenerateOpenAPISpec paths` contract to the vendored files: all
  41 auth-route literals across the fourteen assets resolve to a documented
  path. `TestVendoredAssetsSpeakTheCurrentWire` runs the field-shape bans over
  them and they pass clean — the family's UI and this port's wire already agree
  on camelCase, which is the evidence that the `ServeAuthJS` swap below is safe
  rather than merely intended.
- **`ui/upstream/assets/** text eol=lf` in `.gitattributes`.** awesome-node-auth
  ships no `.gitattributes` and publishes these files with LF, so on a host with
  `core.autocrlf=true` an unpinned checkout rewrites all fourteen: `login.html`
  becomes 7,198 bytes hashing to `facd1ced…` where the blob the reference
  actually serves is 7,064 bytes hashing to `f22f3a3d…`. Without the pin the
  drift check fails on a tree nobody edited, and — had those bytes ever been
  normalised into the table — the repository would have pinned a version of the
  reference's UI that no upstream consumer has.
- **The `identity.*` event vocabulary, the payload it travels in, and the
  request context every event carries.** The twenty-six event names the
  reference declares (`auth-event-names.ts:5-40`) as exported string constants,
  with `EventNames()` to enumerate them in the reference's grouping and
  `IsEventName` to test membership — three downstream things need the full set
  rather than the fifteen names anything actually raises, and the reasoning is
  on `EventNames`. `Event` gains the four fields the reference's
  `AuthEventPayload` has and this port did not (`auth-event-bus.ts:6-25`):
  `SessionID`, `CorrelationID`, `IP` and `UserAgent`, each justified by a
  consumer that reads it rather than by symmetry. `Event.WebhookMetadata()`
  projects the four identifiers the reference's outgoing webhook envelope
  carries in `metadata` (`auth-tools.ts:257-262`), so that U19's envelope is
  derived from the event instead of assembled beside it — deliberately without
  `IP` and `UserAgent`, which stay inside the deployment.
- **The `identity.*` events are now published.** `EventBus.Publish` had no call
  site in this library: the bus existed, was documented, worked, and nothing had
  ever raised an event through it, so every downstream consumer of the event
  plane — webhook delivery, the SSE stream, telemetry, the tools router —
  subscribed to a bus that never spoke. Nineteen publication points close that,
  each at the point the private development line publishes and carrying the same
  `data` keys: login success (`method` one of `local`, `totp`, `magic-link`,
  `sms` — five sites, one name, as the source does it), login failure, logout,
  session rotation, registration, the two 2FA transitions, password change,
  email verification, email change, and the OAuth success and conflict. The seam
  is `Config.Events` with `WithEventBus`, beside `Config.Settings`; every
  publication goes through `EventBus.PublishContext`, so the correlation id, IP
  and user agent the request carried reach the subscriber. A deployment that
  configures no bus — the default — publishes nothing and allocates nothing,
  which `TestPublishWithoutABusAllocatesNothing` pins because it is a property
  of escape analysis rather than of the source.
  `event_publication_test.go` is the conformance test: all twenty-six of the
  development line's publication points are in one table, the nineteen this port
  can reach are exercised and their payloads pinned key for key, and the seven it
  cannot each name the surface that is missing and the milestone that will add it
  (four in the admin router, M8; three in the configurator, which has no
  counterpart here). Reachability is not an editorial field — it is checked
  against the development-line *file* each citation names, so a live site cannot
  be reclassified into silence. Eleven declared names stay unraised in both
  trees, including the ones with an obvious call site here, and a test holds them
  that way.
- **`HTTPConfig.ClientIP` — the trust-proxy seam.** The reference reads
  `req.ip || req.socket.remoteAddress`, and Express's `req.ip` is the socket
  peer under the default `trust proxy` setting and a parsed `X-Forwarded-For`
  address under any other — host configuration this port cannot see. Rather than
  pick one silently: unset, the default, resolves the socket peer with its port
  stripped, which is what both halves evaluate to under Express's own default; a
  host behind a load balancer supplies a function and its answer is used as
  given. No `X-Forwarded-For` parser ships, because an untrusted one is a
  spoofable client address in a security log and the trust configuration is the
  host's knowledge.
- **`TelemetryEvent.SessionID` and `TelemetryEvent.CorrelationID`, and
  `TelemetryFilter.SessionID`.** The reference's
  (`telemetry-store.interface.ts:18`, `:20`, `:34`), missing here, and now
  needed: the `Event` that will feed a telemetry record carries both, and a
  store that could not hold them would drop the two identifiers that make a
  record joinable. `MemoryTelemetryStore` honours the new filter.

### Changed
- **`GET <prefix>/ui/config` is mounted inside `UIHandler`** rather than as a
  route of its own. The wire is unchanged — same handler, same document, same
  `Cache-Control: no-store`, same CSRF cookie, and the conformance suite and
  the generated OpenAPI document both still track it — but no adapter registers
  the path any more; the subtree handler delegates it, which is where the
  reference has it too (`ui.router.ts:165` is a route inside the router
  `auth.router.ts:1640` mounts at `/ui`).
  Gin is what decided the shape. Its router will not hold a catch-all beside a
  static sibling: registering `<prefix>/ui/*uipath` while `<prefix>/ui/config`
  exists panics at mount time, in either registration order. Delegating from
  inside the catch-all is the one shape all four routers express, so all four
  now use it and the suite proves the four answer alike.
- **`ServeAuthJS()` now serves the reference's `auth.js`**, not this port's
  hand-written one. The 18 KB `ui/auth.js` is still in the tree and still
  embedded, because `ui_test.go`'s contract tests are written against it, but
  nothing serves it and it is no longer maintained.
  Two things changed with the bytes, and a host that drives the SDK from a page
  needs to know both. The global is different: the hand-written client exposed
  `window.AuthSDK`, the reference's exposes `window.AuthService` and
  `window.AwesomeNodeAuth` (`auth.js:219`, `auth.js:352`) and no `AuthSDK` at
  all — and it is a page runtime with `init`, `guardPage`, `guardRole` and
  `checkSession` rather than a method-per-route wrapper. And bearer delivery is
  no longer requested on the page's behalf: the hand-written client sent
  `X-Auth-Strategy: bearer` and exposed the tokens it got back, while the
  reference's client is cookie-only and never sends that header. The server is unaffected — it still honours
  `X-Auth-Strategy` from any caller (`auth.router.ts:391`), which is how the
  shipped Angular and Flutter clients ask for bearer delivery — but the served
  SDK no longer asks for it on a page's behalf. A page that relied on
  `window.AuthSDK` returning tokens must be rewritten against `AuthService` and
  send the header itself. That is the point of vendoring rather than a cost of
  it: what this port serves is now what the rest of the family serves, so a page
  written against the reference's documentation works here unchanged. The vendored
  client is otherwise a working cookie client against this port, and
  `TestVendoredAuthJSIsAWorkingCookieClient` pins the names both sides have to
  spell identically: the CSRF header, both CSRF cookie prefixes, and
  `SESSION_REVOKED`.
  No entry was added to the deviation register. Vendoring removes a difference
  from the reference rather than introducing one, and the change here is between
  two generations of this port's own SDK — which `compatibility.go` explicitly
  does not track.
- **Deliberate deviation registered:
  `event-handler-panic-does-not-fail-the-publisher`.** `EventBus`'s
  panic-recovering dispatch predates this release and was never recorded. The
  reference's `AuthEventBus` extends Node's `EventEmitter`, so a listener that
  throws propagates out of `publish`, skips every later listener and fails the
  request that published — a `500` for work that already succeeded. This bus
  recovers, logs and runs the rest. The two agree on the other four axes
  compared — publish is synchronous, ordering is registration order, the named
  channel is served before the wildcard, and both dispatch against a snapshot of
  the handler list — and that comparison is now written on `EventBus`.
  `EventBus` gains no `Unsubscribe`: the reference's `offEvent` has no
  line-for-line Go form, and the cancel-function shape that replaces it belongs
  with the first consumer that ends a subscription.
- **Deliberate deviation registered:
  `identity-events-are-raised-from-the-development-line`.** The publishers this
  release adds have no counterpart in the published reference, which raises none
  of the twenty-six names it declares; they are ported from nik2208/node-auth,
  the private line the package is cut from. A consumer comparing the two
  deployments sees events on one and silence on the other, so the asymmetry is a
  fact the register has to carry rather than a detail of the port.
- **Deliberate deviation registered:
  `session-rotated-reports-one-session-id`.** `Service.Refresh` has always
  rotated the refresh token inside the existing session rather than opening a new
  one and revoking the old, which is what the reference's `issueTokens` does. The
  difference predates this release and nothing exposed it until
  `identity.session.rotated` started carrying `data.previousSessionId`, where it
  is now visible as an id equal to the event's own `sessionId`. Rotation is still
  single-use — the stored hash is replaced — and changing the session identity
  across a refresh is a wire change to `GET <prefix>/sessions` that belongs to
  its own PR, so the behaviour is recorded rather than altered here.

### Deprecated
- **`ServeAuthJS()`**, which is now a thin wrapper over the vendored asset kept
  so that existing importers keep compiling. Set `HTTPConfig.UI.Enabled` and
  let the adapter mount `<prefix>/ui`, which serves this file — and the rest of
  the vendored set, with the config injection the reference's pages expect — at
  the path those pages load it from; or read it directly with
  `UpstreamUIAssetFS()` or `ReadUpstreamUIAsset("auth.js")`. **It will be
  removed in v1.0.0.**
- **`ServeAuthUI()` and `ServeAdminUI()`**, the two hand-written pages. Nothing
  inside the module serves them any more, and `ServeAuthUI` serves its page raw
  — no branding, no site name, no logo, no injected config — where
  `HTTPConfig.UI.Enabled` serves the reference's own login page with all four.
  `ServeAdminUI` has no replacement until the admin router lands in M8: the
  reference's admin SPA is vendored and served under `<prefix>/ui`, but it
  calls an admin API no adapter mounts yet. Both still work for a host that
  mounted them on its own mux. **They will be removed in v1.0.0**, together
  with `ui/admin.html`, `ui/auth.html`, `ui/auth.js`, the `uiFS` embed and the
  `ui_test.go` contract tests written against those three files.

## [0.8.0] - 2026-09-12

The store seams the admin surface needs, and nothing that mounts a route: the
admin router itself is the next milestone, and this one exists so that it finds
every interface it needs already designed, implemented in memory, and pinned by
tests.

Three groups. `AdminUserStore`, `SessionLister` and `RoleLister` close the gap
the parity review called the real bottleneck of the admin surface — before them
the library could reach a user only through tenant membership, so a single-tenant
deployment with no membership rows had nothing to paginate. `APIKeyStore` gains
the five methods the reference declares and this port had not ported, and a
memory implementation of all of them. `WebhookStore` arrives whole, subscriptions
included, with the inbound-webhook fields carried as data that no store may
interpret.

One breaking change, to a store interface rather than to the wire:
`APIKeyStore` now requires `FindByID`, which the reference makes mandatory too.

### Added
- **`WebhookStore`, `WebhookConfig` and `MemoryWebhookStore` — the webhook
  subscription seam.** The reference's `IWebhookStore`, `WebhookConfig` and
  `OutgoingWebhookEvent` (`webhook-store.interface.ts:4-150`) as a store seam:
  where webhook subscriptions are held, so that they stop being a list a host
  hard-codes at construction time. `WebhookStore.FindByEvent` is the one
  required method, and it is the only filter in the chain — the reference's emit
  path hands every configuration it returns straight to the sender, which
  re-checks neither `isActive` nor `events` (`auth-tools.ts:250-267`,
  `webhook-sender.ts:17-46`) — so its three rules are stated on the interface
  and implemented once, in the exported `WebhookConfig.Matches`: active
  configurations only; a non-empty `tenantID` returns both the tenant's and the
  global webhooks, an empty one the global webhooks alone; and an `events` entry
  matches literally or is `*`, an empty list matching nothing. `MemoryWebhookStore`
  returns configurations in the order they were added, and that is the normative
  order for this package — a store that cannot reproduce it says so.
  `listAll?`, `add?`, `remove?` and `update?` are `WebhookAdminStore`, and
  `findByProvider?` is `InboundWebhookStore`: narrow interfaces a caller
  type-asserts the configured store to, the way `SessionAdminStore` already
  works. `isActive`, `maxRetries` and `retryDelayMs` are pointers, because the
  reference resolves all three with `??` and a stored `0` means "deliver once,
  never retry" rather than "unset"; `Active`, `Retries` and `RetryDelay` apply
  the documented defaults in one place.
  Three things this deliberately does not do. It does not touch
  `WebhookDispatcher`: that type keeps its `X-Signature-SHA256` header and its
  own envelope until U19 (M9) replaces both, as a BREAKING change, with the
  reference's `X-Webhook-Signature` — so the two shapes coexist for now and
  nothing is wired into `Dispatch`. It mounts no route: the admin Webhooks
  screens are U14 (M8) and the tools router is M9, and no adapter changed. And
  it runs no script: `WebhookConfig` carries `provider`, `allowedActions` and
  `jsScript`, which in the reference feed a `vm` sandbox, as plain data that a
  store must round-trip and never interpret — execution lives out of process
  behind an `InboundScriptRunner` seam (U25), with an IAM role as the real
  sandbox, because a JavaScript engine in this address space would sit beside
  the signing keys. Carrying them now is the bargain `AuthCode.CodeChallenge`
  already strikes: a store written today needs no schema change when M9 arrives.
  Nothing in the library reads a `WebhookStore` yet, no wire surface changed,
  and no entry was added to the deviation register.
- **`AdminUserStore`, `SessionLister` and `RoleLister` — the store seams the
  admin surface needs.** The reference declares three optional methods for it:
  `IUserStore.listUsers` (`user-store.interface.ts:130`),
  `ISessionStore.getAllSessions` (`session-store.interface.ts:91`) and
  `IRolesPermissionsStore.getAllRoles`
  (`roles-permissions-store.interface.ts:155`). All three are now interfaces in
  `store.go`, optional in the way `SessionAdminStore` and `UserMetadataStore`
  already are — a narrow interface the core type-asserts the configured store to
  — with `Service.ListUsers`, `Service.ListAllSessions` and
  `Service.ListAllRoles` resolving them and answering `ErrFeatureNotSupported`
  when the assertion fails. That sentinel is what M8 turns into the reference's
  own `501 {error: 'IUserStore.listUsers is not implemented', users: [], total: 0}`
  (`admin.router.ts:754`, and `:1093`, `:1133` for the other two). **No routes
  are mounted by this change**; the admin router is M8. `MemoryUserStore`,
  `MemorySessionStore` and `MemoryRolesPermissionsStore` implement all three.
- **`User.IsAdmin`.** The reference's `BaseUser.isAdmin` (`user.model.ts:81-90`),
  a stored flag rather than a projection of `Role`: the admin router's
  `'is-admin-flag'` access policy reads it as `granted = user.isAdmin === true`
  (`admin.router.ts:370`) and `buildPolicyGuard` consults no role anywhere, its
  own doc routing anyone wanting role-shaped admin-ness to RBAC and a custom
  predicate instead. Absent is `false` on both sides, so a store that never
  persisted the column needs no migration. It is deliberately not projected onto
  `PublicUser`: the reference serialises it nowhere, the admin users table picks
  its keys one by one and does not pick this one (`admin.router.ts:764-773`), and
  publishing which accounts are admin is not an addition this contract wants.
- **The rest of the reference's `IApiKeyStore`, split into one mandatory
  interface and four narrow companions.** `APIKeyStore` now carries `FindByID`
  (see Changed) beside `Save`, `FindByPrefix`, `Revoke` and `UpdateLastUsed`,
  and the four methods the reference marks optional become an interface each —
  `APIKeyAdminStore` (`ListAll`), `APIKeyServiceIndexStore` (`ListByServiceID`),
  `APIKeyDeleteStore` (`Delete`) and `APIKeyAuditStore` (`LogUsage`) — which a
  caller reaches by type-asserting the configured store, the way
  `SessionAdminStore` and `UserMetadataStore` are reached. One method per
  interface is the load-bearing part, not tidiness: the reference's admin
  surface tells "no store" and "no method" apart, answering
  `404 {"error": "API key store not configured"}` for the first and
  `501 {"error": "IApiKeyStore.listAll is not implemented", "keys": [], "total": 0}`
  for the second (`admin.router.ts:1254`, `:1259-1262`), and
  `DELETE /admin/api/api-keys/:id` falls back to a revoke and says so in the
  body when `delete` alone is missing (`:1348-1354`). A single combined
  interface could not tell those absences apart. No route consumes any of this
  yet — the admin API-key screens are v0.10.0 — so nothing on the wire changes
  in this release.
- **`MemoryAPIKeyStore`**, an in-process store implementing all five of those
  interfaces, built by `NewMemoryAPIKeyStore()`. It is the executable statement
  of the listing order: `ListAll` and `ListByServiceID` return records newest
  first, `CreatedAt` descending with ties broken by `ID` ascending, and that
  order is normative for this package. The reference ships the interface and no
  implementation of it, so there was nothing to reproduce and the choice had to
  be made somewhere; making it here means a store that cannot hold to it — a
  DynamoDB table with no suitable index, say — registers its own order as a
  deviation rather than inventing one in silence. The `ID` tiebreak is what
  makes it a *total* order, without which `limit`/`offset` paging over keys that
  share a timestamp silently repeats some rows and drops others. Records are
  copied in and out, so a caller cannot reach a stored key's scopes or expiry
  through the slices and pointers it passed in or got back.
- **`APIKeyRecord.CreatedAt`**, stamped by `APIKeyService.Create` from
  `time.Now()`, which is where the reference stamps it
  (`api-key.service.ts:64`). The admin listing projects it
  (`admin.router.ts:1275`) and the create route echoes it back beside the
  once-only raw key (`:1325`), and it is the only field that can order a
  listing — `newID` mints random hex, so the IDs carry no time component and
  sorting by one is sorting by noise. It is a value and not a pointer because
  the reference declares it non-optional where `expiresAt` and `lastUsedAt` are
  both nullable. A store that drops it leaves its records sorting last.
- **`APIKeyAuditEntry` and `APIKeyAuditStore`, as a seam.** Nothing in this
  package calls `LogUsage`, and this release wires no caller. In the reference
  the caller is the API-key strategy's audit hook, which is off unless
  `ApiKeyStrategyOptions.auditLog` is set and the store implements the method
  (`api-key.strategy.ts:31`, `:213`); that switch arrives with the admin API-key
  surface in v0.10.0. The type is defined now so that a host writing a store for
  that release writes the table once. It is deliberately not wired early:
  logging every authentication attempt, the failures above all, turns an
  unauthenticated request into a write, and that belongs to the milestone that
  also ships the way to turn it off.
- **`ErrAPIKeyNotFound`**, the sentinel an API-key store answers when no record
  matches. The reference's two finders return `ApiKey | null`
  (`api-key-store.interface.ts:48`, `:54`), which a two-value Go return has no
  room for, so absence is an error here rather than a zero record with a nil
  one. `APIKeyService.Verify` collapses it, and every other store error, into
  `ErrInvalidCredentials`, so the distinction never reaches the wire.

### Changed
- **BREAKING (store interface) — `APIKeyStore` requires `FindByID`.** An
  existing implementation of the previous four-method interface stops compiling
  until it adds
  `FindByID(ctx context.Context, id string) (APIKeyRecord, error)`. The
  reference makes the method mandatory — "All methods are optional except for
  `findByPrefix` and `findById`" (`api-key-store.interface.ts:7-9`) — and
  leaving it optional here would have put an entry in the deviation register
  whose only argument was that this port shipped the interface incomplete
  first. The cost to an implementor is small: `Revoke` and `UpdateLastUsed`
  already take an id, so any store that satisfies them already has the index
  the new method needs, and v0.8.0 is the release the roadmap names as the one
  that completes `APIKeyStore`. `FindByID` is deliberately the opposite of
  `FindByPrefix` — it returns the record whatever its state, where
  `FindByPrefix` returns active keys only (`:46`) — because the admin screens
  address a key by id *after* revoking it, and a management screen that could
  not open a revoked key could not show an operator what they revoked. Nothing
  on the authentication path calls it, so `APIKeyService.Verify` is unchanged.

### Fixed
- **`MemorySessionStore.ListSessionsForUser` now returns a stable order.** It
  ranged over a map, so the device list a user got from `GET /sessions` was
  shuffled on every call. It is now `Session.ID` ascending, the same order
  `SessionLister.GetAllSessions` beside it uses. Nothing could have depended on
  the previous order, because there was not one.

## [0.7.0] - 2026-09-12

The seams a host needs and the surfaces a browser needs. The generated OpenAPI
document is finally served, together with the reference's own Swagger page;
`GET /ui/config` answers the built-in UI with the branding the settings store
holds; the four OIDC endpoints move from a host-owned mux onto the adapters,
which puts them under the conformance suite; a rate-limiter slot sits where the
reference puts its own; and a password-verifier seam lets a deployment migrate
off another provider one login at a time.

Two differences from the reference stop being undocumented: a registration
missing its credentials now answers the dev line's `400 INVALID_INPUT`, and the
session this port issues from `/register`, where the reference issues none, is
in the register as `register-issues-a-session`.

### Added
- **`HTTPConfig.RateLimiter` — the reference's rate-limiter slot.** The
  reference declares `RouterOptions.rateLimiter` (`auth.router.ts:46`) and ships
  no algorithm behind it: the slot is the whole feature. `HTTPConfig.RateLimiter`
  is that slot as a `func(http.Handler) http.Handler`, `nil` (the default)
  meaning no limiter — which is what the reference does with the option absent,
  collapsing it to an empty middleware list (`rl`, `:468`). All four adapters
  apply it to every route of the auth router, the routes the reference spreads
  `...rl` onto (`:541` onwards), and not to the JWKS document, which is
  registered above the chain and carries no limiter there (`:490`) or here. The
  one place the two lines diverge is the OAuth pair when the provider is not
  configured: the reference swaps in bare 404 stubs with no limiter on them
  (`:1361-1362`, `:1407-1408`), where this port keeps its always-mounted guarded
  handler and decides inside it, so behind a limiter at its limit those two
  requests answer `429` here and `404` there.
  The position in the chain is the load-bearing part and is the reference's:
  outermost, ahead of the CSRF middleware and ahead of the auth middleware
  (`GET /me`, `:656`), so a refusal mints no CSRF cookie, verifies no token and
  reads no store. `auth.RateLimitMiddleware(cfg)` is the composable form, a
  pass-through when the slot is empty. A new wiretest group pins all of it on
  net/http, chi, gin and echo: every documented route passes through the slot
  exactly once, a limiter answering `429` short-circuits both middlewares
  (asserted on the body, the absence of any `Set-Cookie`, and a user-store
  lookup counter that stays at zero), and a `nil` slot answers identically to a
  pass-through one on every route, and the JWKS document is still served behind
  a limiter that refuses everything it sees, which is how the route stays
  provably outside the slot. `RateLimiter` is a constructor, called once per
  route at mount time, so a limiter's counter has to be allocated outside it to
  be shared across routes the way the reference's single Express handler
  instance is. No new routes, so the OpenAPI document is unchanged. See
  README_DETAILED.md, "`HTTPConfig.RateLimiter` — the rate-limiter slot".
- **Noted, not implemented:** the family's private development line carries a
  second, separate slot on its admin router (`AdminOptions.rateLimiter`,
  `admin.router.ts:211`, collapsed the same way at `:577`) and spreads it onto
  exactly one route, `POST /users/:id/promote` (`:1030`) — its admin login
  route (`:614`) carries none. That path is relative to the admin router's own
  mount, which the host app chooses and which defaults to `/admin`
  (`admin.router.ts:190`, `openapi.ts:674`), not to `HTTPConfig.APIPrefix`.
  Those line numbers are in that private tree, not in `ReferenceRevision`, whose
  admin router carries no rate-limiter slot at all. No admin route exists in
  this port yet.
- **`Config.PasswordVerifier` and `WithPasswordVerifier` — the migration seam.**
  A deployment moving off another identity provider can now accept that
  provider's password on the first login, adopt it as a local bcrypt hash and
  stop calling the old system. `PasswordVerifier` is
  `func(ctx context.Context, user User, password string) (ok, migrated bool, err error)`
  and is consulted **only** after the stored hash has failed to verify what the
  request carried, so a user whose local hash verifies never reaches it and a
  finished migration costs nothing per login. Everything else does reach it —
  not only the imported row whose hash is empty, but every account that never
  had a password (OAuth-only, magic-link-only), which the reference refuses
  outright (`local.strategy.ts:23-25`) — so **a verifier must key on its own
  migration marker** and refuse before it touches the password it is handed or
  calls anything over the network. `ok=false` is `ErrInvalidCredentials`, the
  same value and therefore the same
  `401 {"error":"Invalid credentials","code":"INVALID_CREDENTIALS"}`
  an ordinary wrong password produces; `ok=true` with `migrated=true` hashes the
  supplied password at `Config.BcryptCost` and writes it through
  `UserPasswordStore.UpdatePassword` — the path `ResetPassword` and
  `ChangePassword` already use — before any token is issued, **overwriting
  whatever hash was stored** rather than only filling in an absent one, and
  bypassing `Config.MinPasswordLen` because the credential is inherited rather
  than chosen (an empty password is never written and behaves as
  `migrated=false`); `ok=true` with `migrated=false` logs the user in and stores
  nothing. A non-nil `err` is a
  failure to decide rather than a rejection and fails the login closed with the
  generic `500 {"error":"Internal server error"}`; so does a failed hash or a
  store that cannot persist the migration, each reported as an opaque error
  wrapped with `%v` and never `%w`, so that a store answering
  `ErrFeatureNotSupported` cannot turn one branch into a distinguishable `501`
  (`context.Canceled` and `context.DeadlineExceeded` are the exception and keep
  `%w`, since `HTTPErrorFor` maps neither and both already answer the same
  generic `500`). Every one of those failures also goes to `Config.Logger`,
  with the user id and never the password, since the wire answer names no
  branch.
  This is an **additive port extension, not parity**: the reference's login path
  verifies bcrypt directly and offers no hook of any kind
  (`local.strategy.ts:19-29` calling `password.service.ts:8-10`, reached by
  `auth.router.ts:541-544`), and its `AuthConfig` names no verifier, legacy hash
  or migration. Unset — the default — nothing is called and `POST /auth/login`
  answers exactly as it did before and exactly as the reference does. The seam
  is not in the deviation register because *configured* it still puts nothing
  new on the wire: no new status, no new code, no new body field, on this route
  or any other. No route, request body or response shape changes. See
  README_DETAILED.md, "Password verifier (migration seam)".
- **`ErrInvalidInput`, `CodeInvalidInput` and `HTTPErrInvalidInput`** — the
  sentinel, the `INVALID_INPUT` code and the catalog entry behind that refusal,
  mapped in `HTTPErrorFor` and documented on `POST /register` in the generated
  OpenAPI document alongside `INVALID_BODY`, `WEAK_PASSWORD` and `USER_EXISTS`.
- **`DevLineRevision`** — the second tree this package cites, `nik2208/node-auth`
  at `e8af923` (unreleased). Nothing in the deviation register resolves against
  it (`Deviation.Citations` is `ReferenceRevision` only, and the register test
  enforces that); it exists so a reader can tell which tree a `file:line` in a
  doc comment means, and so the one fact copied from an unreleased tree — the
  `INVALID_INPUT` refusal above — is recorded as the bet it is instead of being
  attributed to the published reference.
- **`register-issues-a-session` is now in the deviation register, provisionally.**
  This port's `POST /register` has always issued a session alongside its
  `201 {"success":true,"userId":…}` — cookies in cookie mode, top-level
  `accessToken`/`refreshToken` under `X-Auth-Strategy: bearer`, and a refresh
  session row either way — where the published reference returns that body and
  nothing else, and only mounts the route at all when the host supplies
  `options.onRegister`: its register route never reaches `sendTokens` or
  `issueTokens`, so the caller has to `POST /login` next
  (`auth.router.ts:713-730`, `:726`, `:399-406`). The difference was
  undocumented, and it is client-visible, so it is now an entry in
  `CompatibilityNotes()`. **The entry records the difference; it does not bless
  it.** A registration that authenticates bypasses whatever email verification
  gate the deployment configured — under `strict` the new account holds an access
  token `POST /login` would have refused it — which the family already tracks as
  a security-relevant defect in
  [#21](https://github.com/nik2208/awesome-go-auth/issues/21) and pins under
  protest in `awesome-lambda-auth/test/contract/cases_register_test.go`. The
  entry says so in its own text, is marked provisional, and is to be retired
  rather than reworded when #21 lands; "there is no knob" describes this release,
  not a decision that it stays that way. README.md's generated deviations section
  is regenerated from it.
- **The four OIDC endpoints are mounted by all four adapters.** An `Auth` built
  with `auth.WithIDP` already made net/http, chi, gin and echo serve the JWKS
  document; it now mounts the rest of the IdP surface beside it, at the paths
  `(*IDP).RegisterHandlers` has always used and under the configured prefix:
  `<prefix>/.well-known/openid-configuration`, `<prefix>/authorize`,
  `<prefix>/token` and `<prefix>/userinfo`. Public and ahead of every
  middleware, like the JWKS route. No shape changes: the same handlers, the
  same bodies, the same statuses — what changes is that they are inside the
  mount the wiretest conformance suite exercises, so the discovery document's
  shape, `authorize` refusing an unregistered `client_id` and an unregistered
  `redirect_uri`, `token` refusing a code nobody issued and a client nobody
  registered, and `userinfo` refusing a token nobody signed are now pinned on
  all four adapters at once (`adapter/internal/wiretest/oidc.go`). These four
  endpoints have no counterpart in the reference, which ships no OIDC
  authorization server, so nothing here is cited against it and nothing about
  their shapes is settled by it. **This grows the mounted surface by four
  routes**; a deployment that enumerates it will see them.
- **`HTTPConfig.ResourceServer` gates two of the four.** `<prefix>/authorize`
  and `<prefix>/token` are credential routes by this library's own definition —
  `POST <prefix>/authorize` reads an email, a password and a tenant off the form
  and hands them to `Service.Login`, and `POST <prefix>/token` spends the
  resulting code for this instance's HS256 session pair — so resource-server
  mode leaves them unmounted, exactly as it leaves `/login` and `/refresh`
  unmounted, and `OpenAPIInfo.OIDC` drops them from the generated document when
  `OpenAPIInfo.ResourceServer` is set alongside it. Without this a hybrid
  deployment that set the flag to unmount the credential routes and also built
  `WithIDP` would silently regain a password-accepting endpoint and a
  session-minting one. The discovery document and `<prefix>/userinfo` stay
  mounted: discovery is metadata like the JWKS document beside it, and
  `userinfo` reads a bearer token and returns a profile, which is `GET /me`'s
  shape and stays for `GET /me`'s reason. `(*IDP).RegisterHandlers` still mounts
  all four — it is handed a mux with no `HTTPConfig` behind it. See
  `OIDCMount.ResourceServerGated`.
- **`(*IDP).OIDCMounts() []OIDCMount`** and the `OIDCDiscoveryPath`,
  `OIDCAuthorizePath`, `OIDCTokenPath` and `OIDCUserInfoPath` constants — the
  one list the four adapters and `RegisterHandlers` all mount from, so an
  endpoint cannot appear on one mount and not another. Every method reaches the
  handler, which is what `RegisterHandlers`'s method-less `http.ServeMux`
  patterns have always done and what the handlers expect: `authorize` reads
  `r.Method` itself, `token` reads `grant_type` out of the form, `userinfo`
  reads the `Authorization` header.
- **`OpenAPIInfo.OIDC`** adds those four paths to the generated document, at
  the operation each drives the flow with (`GET` discovery, `GET` authorize,
  `POST` token, `GET` userinfo). It is a second flag beside
  `OpenAPIInfo.IDProvider` rather than more of it: publishing a key so that
  somebody else's resource server can verify this IdP's tokens and advertising
  an authorization server a relying party may drive are different statements,
  and a deployment that serves the OIDC endpoints on a mux of its own
  documents them where it mounted them.
- **`GET <prefix>/ui/config`** — the document the built-in UI fetches before it
  renders anything (`ui.router.ts:95-170`), mounted on all four adapters when
  `HTTPConfig.UI.Enabled` is set, as the reference mounts its whole UI router
  under `config.ui.enabled` (`auth.router.ts:1639-1648`). Public: the login page
  fetches it before a session exists, so it asks for no credential and no CSRF
  pair, and like the reference it seeds the CSRF cookie on the way past
  (`auth.router.ts:529-535`). The body carries the reference's six keys in its
  order — `apiPrefix`, `features`, `ui`, `translations`, `lang`, `headless`.
  `features` is derived from the wiring rather than configured: `magicLink`,
  `sms`, `forgotPassword` and `verifyEmail` from the delivery senders (plus, for
  `verifyEmail`, a `Config.EmailVerificationMode` other than `none`), `google`
  and `github` from the providers `WithOAuth` wired, `twoFactor` from
  `Config.TwoFactorAppName`, and `register` always true because this port always
  mounts `POST <prefix>/register` where the reference mounts it only with an
  `onRegister` hook. `ui` is the static branding with the `SettingsStore`'s `ui`
  block applied on top member by member (`:125-134`), defaulting to `#4a90d9`,
  `#6c757d` and `Awesome Node Auth`, with the five members nobody configured
  absent rather than null; `customCss` is static-only, as there. `translations`
  is the `TemplateStore` UI page `config` — the page the reference's own path
  derivation selects on this route (`:107`) — for `lang`, falling back to `en`
  and then to `{}`. `lang` is `?lang=`, then `UIOptions.DefaultLang`, then `en`.
  A store that fails answers `200` with the reference's reduced document:
  `features` collapsed to `register`, `google` and `github`, the default
  branding, no translations and `en` whatever was asked for (`:143-161`) —
  reproduced rather than fixed, because the family's clients are written against
  it (reference-issues N32), and logged through `Config.Logger` since the client
  is told nothing. Covered by the wiretest suite on all four adapters and
  described by `GenerateOpenAPISpec` under the new `OpenAPIInfo.UI`.
  See README_DETAILED.md, "Embedded UI".
- **`HTTPConfig.UI UIOptions`** — the reference's `config.ui` block
  (`auth-config.model.ts:321-381`): `Enabled`, `Headless`, `Branding`
  (`UIBranding`, with the reference's `primaryColor`, `secondaryColor`,
  `logoUrl`, `siteName`, `customLogo`, `bgColor`, `bgImage` and `cardBg`),
  `CustomCSS`, `DefaultLang`, and `Assets`/`Uploads` for the pages and uploads a
  later change serves. **`(*Auth).UIConfig(ctx, r, cfg)`** returns the document
  as a value (`UIConfig`, `UIFeatures`, `UIConfigBranding`) for a host serving
  its own UI route.
- **`GET <prefix>/openapi.json` and `GET <prefix>/docs`** — the reference's two
  documentation routes (`auth.router.ts:1652-1677`), mounted by all four
  adapters when `HTTPConfig.Docs.Enabled` is set and by none of them otherwise.
  Neither has an auth gate, as neither has one in the reference: a reader
  fetches both with no credential of any kind. Both do sit behind the CSRF
  middleware, as every reference route registered after the router-level
  auto-init (`auth.router.ts:529-538`) does — on a `GET` that only writes the
  `csrf-token` cookie to a reader who arrives without one, and rejects nothing.
  The first answers `GenerateOpenAPISpec` for that
  mount as `application/json`; the second answers the reference's Swagger UI
  page, reproduced byte for byte from `buildSwaggerUiHtml`
  (`openapi.ts:1646-1669`) including the `swagger-ui-dist@5` bundles it loads
  from the unpkg CDN, pointed at the document next door. `DocsOptions.BasePath`
  is the reference's `swaggerBasePath` (`auth.router.ts:1657`): it moves the
  description — the paths the served document writes and the URL the page
  fetches — and never the mount, which stays at `HTTPConfig.Prefix()`. Covered
  by the wiretest suite on all four adapters. See README_DETAILED.md, "OpenAPI".
- **`OpenAPIHandler(info OpenAPIInfo)` and `SwaggerUIHandler(specURL string)`** —
  the two `http.Handler`s behind those routes, exported for a host that serves
  the document from a route of its own. `(*nethttp.Adapter).OpenAPIInfo()` is
  the `OpenAPIInfo` describing that adapter's mount: the IdP flag, the JWKS path
  and the resource-server flag are read off the mount and cannot disagree with
  it, and `APIPrefix` is the documented base path — the mount prefix unless
  `DocsOptions.BasePath` moves the description. Enabling the UI route puts the
  reference's unpkg-hosted `swagger-ui-dist@5` bundle on the auth origin; see
  the deviation note before turning it on in production.
- **`OpenAPIInfo.Docs`** — adds those same two paths to the generated document.
  The adapters set it with `HTTPConfig.Docs.Enabled`, so the document and the
  mount agree in both directions; the conformance suite checks that, per
  adapter, through the new `docs` conditional route set.
- **Deviation register: `docs-routes-are-opt-in`.** The reference enables those
  two routes whenever `swagger !== false && NODE_ENV !== 'production'`, so a
  deployment that configures nothing serves them outside production. This port
  takes a plain `bool` and defaults it to off: resolving an ambient environment
  belongs to the host, and `cfg.Docs.Enabled = os.Getenv("APP_ENV") !=
  "production"` is the whole of it. The served document also lists its own two
  paths, which the reference's generator never does. Both halves are in
  `CompatibilityNotes()` and the README's generated deviations section.

### Changed
- **`POST /auth/register` refuses a missing email or password with
  `400 {"error":"Email and password are required","code":"INVALID_INPUT"}`.** The
  message and the code come from the private dev line `node-auth` (unreleased,
  the new `DevLineRevision`) and **not** from the published reference
  `awesome-node-auth@cc01e997` that `ReferenceRevision` pins: the dev line mounts
  `/register` by default and its default handler checks both fields for presence
  and throws `AuthError('Email and password are required', 'INVALID_INPUT', 400)`
  before it hashes the password or calls `userStore.create`
  (`node-auth auth.router.ts:515-525`), while the published reference mounts
  `/register` only when the host supplies `options.onRegister`
  (`auth.router.ts:713`), has no default handler and has no `INVALID_INPUT` code
  anywhere in its source. This port answered `WEAK_PASSWORD` for an empty
  password — telling a caller who sent none to choose a stronger one — and, for a
  missing address, ran the whole registration and stored a user with a blank
  email. Both now stop at the same refusal, before any store is touched. The
  check lives in `Service.Register`, so a direct library caller gets the new
  `ErrInvalidInput` sentinel and all four adapters get the wire answer through
  `HTTPErrorFor`; it runs after email normalisation, so an address that is only
  whitespace is refused here rather than stored as the empty string (the dev
  line tests the untrimmed body value and would accept it — the narrower
  reading, and it can only refuse a request the dev line would have turned into
  an account with no usable address). A password that is present but short still
  answers `WEAK_PASSWORD`, unchanged. Covered by the wiretest suite on all four
  adapters, in cookie and bearer mode.
- **`(*IDP).RegisterHandlers` is no longer needed by a host that mounts an
  adapter**, and keeps working unchanged for one that is not: it still mounts
  all six patterns — the four above, the JWKS document at `basePath +
  JWKSPath()` and the deprecated `<basePath>/jwks` alias — on the mux it is
  given. Mounting an adapter *and* calling it with the adapter's prefix is the
  host's mistake, and what that costs depends on the router. On a single
  `http.ServeMux` it now fails loudly: both registrations use the same
  method-less pattern, so `ServeMux` panics at mount time naming the two
  conflicting registration sites, the way the JWKS route already did. That
  collision is deliberate — a `"GET <path>"` pattern would not conflict, and
  would leave an endpoint split between two handlers with `GET` answered by one
  and every other method by the other. On a chi, gin or echo host the adapter
  mount and the `RegisterHandlers` mux are two different routers, so nothing
  collides and the endpoints simply end up served at two URLs. Do one or the
  other.
- **A deployment that already sets the deprecated `HTTPConfig.UIEnabled` starts
  serving `GET <prefix>/ui/config` on upgrade**, with no code change on its side.
  Until now the flag decided nothing but the shape of an emailed link
  (`HTTPConfig.UILink`); it is now the alias of `HTTPConfig.UI.Enabled`, so
  `ResolveHTTPConfig` switches the route on from it and all four adapters mount
  it. The route is public and unauthenticated, and the document names the OAuth
  providers that are wired, whether 2FA and each of the four delivery paths
  (magic link, SMS, password reset, email verification) are available, and the
  deployment's branding — colours, logo URL, site name and custom CSS. Setting
  `UI.Enabled = false` does **not** suppress it: the two fields are OR-ed, so the
  only way back to the previous behaviour is to stop setting `UIEnabled` and
  point the emailed links elsewhere. The generated OpenAPI document is not
  affected: it lists the route only under the separate `OpenAPIInfo.UI`.
- **`HTTPConfig` gained `Docs DocsOptions`.** Purely additive: a `HTTPConfig`
  built as before has `Docs.Enabled` false and mounts nothing new.

### Deprecated
- **`HTTPConfig.UIEnabled`** — use `HTTPConfig.UI.Enabled`. It is an alias, not a
  second switch: either field enables the UI, `ResolveHTTPConfig` sets both from
  either, and a deployment that only ever set `UIEnabled` keeps the emailed links
  it had and now serves the config route as well — see **Changed** above, which
  is the behaviour change that follows from it. Kept through the 0.x line.

## [0.6.0] - 2026-09-12

The consuming half of identity, and the policies the reference leaves to its
host. A resource server can now verify tokens this port did not issue: the
JWKS document is served at the well-known path on every adapter, and a JWKS
client, an RS256 verifier and a middleware consume one. OAuth gains the
provisioning policy the reference only sketches, and with it the
account-conflict story end to end, from the redirect through link-request to
link-verify. Runtime settings gain their store, so a deployment can require a
second factor without a redeploy.

### Added
- **`SettingsStore`, `AuthSettings` and `MemorySettingsStore`** — the reference's
  `ISettingsStore` (`settings-store.interface.ts:28-40`), the global switches an
  administrator flips at run time through its admin Control panel, wired with
  `WithSettingsStore(store)` (`Config.Settings`). `AuthSettings` carries the
  reference's fields under the reference's JSON names, every one optional:
  `requireEmailVerification`, `emailVerificationMode`,
  `lazyEmailVerificationGracePeriodDays`, `require2FA`, `enabledWebhookActions`
  and `ui` (`UISettings` with `primaryColor`, `secondaryColor`, `logoUrl`,
  `siteName`, `logoPath`, `bgColor`, `bgImage`, `cardBg`), so a stored document
  round-trips between this port and a node-auth deployment unchanged — including
  a *cleared* `enabledWebhookActions`, which `AuthSettings.MarshalJSON` writes as
  `[]` rather than letting `omitempty` drop the key, because an absent key merges
  as "keep" and would silently switch the old allowlist back on.
  `UpdateSettings` applies its patch as the reference's shallow spread,
  `merged = {...current, ...settings}` (`:20-24` is the JSDoc example, `:36-38`
  the interface comment; the reference ships no `ISettingsStore` implementation
  under `src/`, and the closest one beside it is
  `examples/in-memory-user-store.ts:266-268`) — a nil field keeps what is stored,
  a set field replaces it, and `ui` is one key of that spread, so
  a patch carrying it replaces the branding block whole rather than merging into
  it (which is why the reference's own admin route merges the sub-object itself
  before writing it back, `admin.router.ts:979-981`). `MergeSettings(current,
  patch)` is that rule, exported so a database-backed store applies the same one.
  The store is optional: without one nothing changes, as in the reference.
  See README_DETAILED.md, "Runtime settings".
- **`POST /auth/2fa/disable` now refuses on the stored `require2FA` too.** The
  reference's own system-wide term (`auth.router.ts:890-896`): with a settings
  store holding `require2FA: true`, the route answers
  `403 {"error":"Cannot disable 2FA: required by system policy","code":"2FA_REQUIRED"}`
  — the same body `Config.Require2FA` already produced, now reachable the way the
  reference reaches it. The per-user `User.Require2FA` refusal is checked first
  and keeps its own message, as there. A settings store that cannot answer fails
  the route closed with `500 {"error":"Internal server error"}` and no `code`,
  the status the reference produces when its `getSettings` throws
  (`handleError`, `:899-901`, `:189-195`); an unreachable policy store is not
  permission to drop a second factor. The error is logged through `Config.Logger`
  before that body goes out, since the body carries none of it — as the reference
  logs it in `handleError` (`:193`). Covered by the wiretest suite on all four
  adapters.
- **Documented: the email-verification settings are stored and deliberately not
  consulted.** `requireEmailVerification`, `emailVerificationMode` and
  `lazyEmailVerificationGracePeriodDays` written to the store change nothing
  about who may log in, because they change nothing in the reference either: no
  route that decides a login reads the store there, and its local strategy reads
  the static `config.emailVerificationMode` (`src/strategies/local/local.strategy.ts:32-35`).
  Catalogued upstream as reference-issues N36.
  `Config.EmailVerificationMode` is the knob that does decide a login here, as
  `config.emailVerificationMode` is there. No deviation entry, because there is
  no wire difference: every route answers what the reference answers for the same
  stored settings. `enabledWebhookActions` and `ui` are likewise stored and read
  by nothing here yet; the reference's only other readers of the store are
  `GET <prefix>/ui/config`, which reads `ui` for branding
  (`src/router/ui.router.ts:99`, `:126-133`), and the tools router, which reads
  `enabledWebhookActions` and swallows a store failure rather than failing closed
  (`src/router/tools.router.ts:261-262`). Neither is ported yet.
- **Deviation register: `config-require2fa-is-a-system-policy-term`.**
  `Config.Require2FA` is a third term in two decisions the reference makes with
  two — the `/2fa/disable` system-policy refusal and the login 2FA challenge —
  and the reference has no config-level `require2FA` at all
  (`auth.router.ts:880-902`, `:552`). The behaviour predates this release; this
  is the release that made that route's policy term the subject, so it is now in
  `compatibility.go` and the generated README section rather than in prose alone.
- **The JWKS document at `GET <prefix>/.well-known/jwks.json` on every adapter,
  with the reference's headers.** `auth.WithIDP(idp)` registers an `IDP` on the
  `Auth`, and that is what makes net/http, chi, gin and echo mount the route —
  public, ahead of every middleware, exactly where and under the same condition
  as the reference (`auth.router.ts:473-475`). The response carries
  `Cache-Control: public, max-age=3600` (`:502`) and an
  `Access-Control-Allow-Origin` resolved as the reference resolves it
  (`:492-500`): `*` by default, a listed `Origin` echoed back, and no such
  header at all for an unlisted one — the document is served either way, since
  CORS bounds what a browser script may read and not what the server answers.
  `IDPConfig.JWKSPath` moves the route (empty → `DefaultJWKSPath`,
  `/.well-known/jwks.json`; `NewIDP` refuses a path the routers cannot all treat
  as the same literal path — one that does not start with `/`, ends with one,
  contains `{`, `}`, `?`, `#` or `//`, or collides with a path
  `RegisterHandlers` already mounts), `IDPConfig.JWKSCORSOrigins` is the
  allowlist (nil → `*`), and `(*Auth).IDP()`, `(*Auth).JWKSHandler()`,
  `(*IDP).JWKSHandler()` and `(*IDP).JWKSPath()` are the pieces a host mounting
  it itself needs. An `IDP` built with a nil `Service` — the only order a caller
  can write, since `NewIDP` wants one and `New` is what produces it — adopts the
  `Auth`'s Service; one already bound to a different `Service` is refused with
  an error rather than silently left pointing at the other one's user store.
  `OpenAPIInfo.IDProvider` (with `OpenAPIInfo.JWKSPath`) adds the path and the
  `JWK`/`JWKS` schemas it references to the generated document — and only then,
  so a deployment with no IdP ships neither — and the wiretest harness's first
  `conditionalRouteSet`, `jwks`, holds the flag and the four mounts to each
  other in both directions, including the 404 without `WithIDP`. See
  README_DETAILED.md, "OIDC IDP".
- **A deviation entry, `jwks-cors-wildcard-string-form`.** The reference's
  `jwksCorsOrigins` is `string | string[]` and only the *string* `'*'` is the
  wildcard (`corsOrigins === '*'` on the whole value, `auth.router.ts:493`), so
  every array there is an allowlist. Go has no such union: the one-element
  `[]string{"*"}` stands in for the string form, while an entry `*` inside a
  longer slice is an ordinary allowlist entry here exactly as in the reference.
  Registered in `CompatibilityNotes()` and in README.md's generated section.
- **`IDPConfig.JWKSURL`** overrides the `jwks_uri` of the discovery document
  `RegisterHandlers` serves, for an IdP reached through a gateway whose external
  URL is not `Issuer` + the mounted path.
- **Resource-server mode: a JWKS client, an RS256 verifier and a middleware on
  all four adapters.** `ResourceServerConfig{JWKSURL, Issuer, CacheTTL,
  FetchTimeout, Client}` points a deployment at the JWKS of the instance that
  issues its tokens. `NewJWKSClient(cfg)` returns a `*JWKSClient` whose cache is
  stale-while-revalidate, transcribed from the reference's `JwksClient`
  (`jwks.service.ts:29-141`): a document inside its TTL comes from memory; a
  burst on a cold cache is one HTTP call, not one per request; a document past
  its TTL is served immediately while the refresh runs behind it; and a refresh
  that fails changes nothing, so an issuer that is briefly unreachable cannot
  take the resource server down with it. Defaults are the reference's —
  `DefaultJWKSCacheTTL` 1 hour, `DefaultJWKSFetchTimeout` 5 seconds
  (`jwks.service.ts:40-41`). `GetKey(ctx, kid)` and `Invalidate()` are the
  reference's `getKey` and `invalidateCache`; `Document(ctx)` returns the whole
  document, and `JWK.RSAPublicKey()` converts one published key back into an
  `*rsa.PublicKey` (the inverse of `NewRSAJWK`, and of `jwkToPublicKey`,
  `jwks.service.ts:199-202`). `NewJWKSClient` panics on a `JWKSURL` that is
  empty or is not an absolute http/https URL: a resource server that cannot
  reach its issuer fails at startup rather than answering 401 to every bearer
  request for the life of the process, which is how the reference refuses the
  same misconfiguration (`jwks-auth.middleware.ts:38-40`).
- **`VerifyRS256(ctx, token, client, expectedIssuer)`** is `verifyWithJwks`
  (`token.service.ts:102-141`): the `kid` header selects the key, a `kid` the
  cache does not carry invalidates it and is looked up exactly once more — so a
  key rotated inside the TTL is picked up on the first request that needs it —
  `RS256` is pinned as an allow-list rather than read from the token, `exp` and
  `nbf` are honoured with no clock tolerance, and `iss` is compared by string
  equality when `expectedIssuer` is set. Two orderings differ from the reference
  and are the new `jwks-unknown-kid-refetch-is-rate-limited` deviation: the
  `RS256` check runs *before* the key lookup, so an `alg: none` or `alg: HS256`
  token never reaches the issuer; and the rotation retry is rate-limited by
  `ResourceServerConfig.MinRefreshInterval` (`DefaultJWKSMinRefreshInterval`, 30
  seconds), so a flood of tokens naming random `kid`s costs one outbound fetch
  per interval instead of one per request. A negative `MinRefreshInterval`
  restores the reference behaviour. Every refusal of the *token* wraps
  `ErrInvalidToken` and carries the reference's own message (`Invalid token
  format`, `Token missing kid header`, `Unknown signing key`, `Invalid or
  expired token`, `Token issuer mismatch`); a failure to read the JWKS at all —
  transport, non-200, unparseable document — surfaces unwrapped and maps to
  `HTTPErrInternal`, because an issuer outage is this server's 5xx and not the
  caller's bad credential. No new sentinel was added. The claims are returned as
  the decoded payload, unchanged.
- **`ResourceServerMiddleware(a, cfg)`, on net/http, chi, gin and echo.** A
  bearer token is verified against the remote JWKS; an access-token cookie is
  verified against this instance's own HS256 secret, for the dashboard that
  hosts the resource server and may itself be logged in
  (`jwks-auth.middleware.ts:44-79`). **Neither path reads a store** — the cookie
  is checked with the reference's `verifyAccessToken`, a bare `jwt.verify`
  (`token.service.ts:143-150`), not with `Auth.Authenticate`, which would need
  the user table a resource server does not have. Two consequences follow, both
  the reference's: a cookie whose subject this instance has no record of is
  accepted, and a revoked session is accepted until its access token expires —
  `SESSION_REVOKED` is a code of the session `Middleware`, which is the one with
  a database behind it. The path is selected on the `Bearer ` prefix exactly as
  the reference selects it (case-sensitive, and an empty token after the prefix
  is a bearer request with no token, not a fallback to the cookie). No token
  at all — neither header nor cookie — is `403 {"error":"No access token
  provided"}`, code-less; every other failure is `401 {"error":"Invalid or
  expired access token","code":"INVALID_TOKEN"}`, the new `HTTPErrInvalidTokenRS`
  catalog entry. The user in context is built from the verified claims —
  `UserFromRS256Claims` fills `ID`,
  `Email`, `Role`, `LoginProvider`, `IsEmailVerified`, `IsTOTPEnabled` and
  `TenantID` from `sub`, `email`, `role`, `loginProvider`, `isEmailVerified`,
  `isTotpEnabled` and `tid`, leaves every store-only field zero, and carries the
  whole verified payload in `CustomClaims` so a scope or permission claim
  reaches the handler. `ResourceServerPrincipal` exposes the same decision for a
  framework this repository does not ship.
- **`HTTPConfig.ResourceServer`** unmounts the credential routes: with it set,
  the four adapters register none of the nineteen routes in the new
  `ResourceServerGatedRoutes()` — `/register`, `/login`, `/refresh`, `/logout`,
  the five password and email-verification routes, both email-change routes,
  both magic-link routes, both SMS routes and the four 2FA routes — so each
  answers `404`, and `OpenAPIInfo.ResourceServer` drops the same nineteen
  operations from the generated spec. What stays is `/me`, the session routes,
  `/profile`, `/add-phone`, `/account` and the OAuth and linking group — and
  those still need a local user store, so the flag is about credentials, not
  about store independence: the store-less deployment is the one that mounts
  `ResourceServerMiddleware` on its own routes. The reference gates six of the
  nineteen and leaves the rest mounted over a database it has just declared
  absent; gating all of them is the new
  `resource-server-gates-all-credential-routes` deviation. See
  README_DETAILED.md, "Resource server mode".
- **OAuth provisioning policy and the account-conflict flow.**
  `OAuthWiring.Provisioning *OAuthProvisioning` is the declarative stand-in for
  the abstract `findOrCreateUser` the reference makes every integrator write
  (`generic-oauth.strategy.ts:169-172`): `AutoCreate` gates creating an account
  for an unknown identity, `AllowedEmailDomains` restricts which addresses may
  sign in at all, `RequireVerifiedEmail` demands that the provider actually
  asserted the address, `OnEmailMatch` (`"link"`, `"conflict"`, `"reject"`)
  decides what happens when the address already belongs to an account, and
  `FieldMap` fills `firstName`, `lastName`, `phoneNumber` and `role` from the
  raw profile with `ProfileMap` expressions. `nil` means
  `DefaultOAuthProvisioning()` — create, link by address — so a deployment that
  sets nothing is unchanged; `WithOAuth` runs `OAuthProvisioning.Validate()`, so
  an unknown mode or an unknown `FieldMap` target fails at construction rather
  than at the first login. `OAuthService.HandleCallbackWithPolicy` is
  `HandleCallback` with the policy as its last argument; the old signature is
  unchanged and now delegates with the default policy.
- **The reference's account-conflict story, end to end.** Under
  `OnEmailMatch: "conflict"` a provider account asserting an address another
  account holds raises `*OAuthAccountConflictError` (which unwraps to
  `ErrOAuthAccountConflict` and carries the reference's `{email,
  providerAccountId}`), the callback stashes it under the `pending-link:` key
  the linking routes already read, and the browser gets a `302` to
  `HTTPConfig.AccountConflictLink(...)` —
  `<siteUrl><prefix>[/ui]/account-conflict?provider=<p>&code=OAUTH_ACCOUNT_CONFLICT[&email=<e>]`,
  the reference's own query (`auth.router.ts:1346-1355`). `POST /link-request`
  then resolves the identity from that stash and `POST /link-verify` completes
  the link under the stashed `providerAccountId`. Nothing wrote that stash
  before, so the flow the port already had readers for is reachable for the
  first time. `CodeOAuthAccountConflict = "OAUTH_ACCOUNT_CONFLICT"`.
- **Three provisioning refusals on the callback**, all `403` JSON, all
  unreachable without a configured policy, and all registered as deviations:
  `OAUTH_EMAIL_NOT_VERIFIED` (`HTTPErrOAuthEmailNotVerified`),
  `OAUTH_EMAIL_DOMAIN_NOT_ALLOWED` (`HTTPErrOAuthEmailDomainNotAllowed`) and
  `OAUTH_USER_NOT_PROVISIONED` (`HTTPErrOAuthUserNotProvisioned`, answered both
  by `AutoCreate: false` and by `OnEmailMatch: "reject"`).

### Changed
- **BREAKING (minor surface): `(*Auth).TwoFactorPolicy()` is now
  `TwoFactorPolicy(ctx context.Context) (bool, error)`.** It is the OR of
  `Config.Require2FA` and the stored `require2FA`, which is why it needs a
  context to read the store and an error to report the store failing. The static
  term is checked first and short-circuits, so a deployment that already requires
  the factor never pays for a store read. Go has no overloading, so the old
  zero-argument spelling could only have survived under a different name that
  nothing would call; it is dropped instead. The method is used by the adapters'
  `/2fa/disable` handlers, which are in this repository, and by nothing in the
  downstream product — checked by grep over `awesome-lambda-auth`'s 84 Go files,
  which contain no occurrence of `TwoFactorPolicy`.
- **MCP `auth_get_config` reports the effective 2FA policy as well as the
  configured one.** `require_2fa` still carries the static `Config.Require2FA`,
  which is what the field has always meant in a tool that returns configuration;
  the new `require_2fa_effective` carries what `/2fa/disable` actually enforces
  (that term OR the stored `require2FA`), and is omitted when the settings store
  cannot be read, since the route it mirrors answers `500` rather than guessing.
  MCP is out of parity scope; the change is additive.
- **The discovery document's `jwks_uri` now points at the canonical JWKS path**
  (`Issuer` + `IDPConfig.JWKSPath`) instead of `<base>/jwks`. A relying party
  that reads the document follows it automatically; one configured by hand
  against `<base>/jwks` keeps working — see below.
- **The authenticated user now sits under a context key owned by the root
  package** (`auth.ContextWithUser` / `auth.UserFromContext`), so a middleware
  written there can hand a principal to a handler an adapter mounted.
  `nethttp.UserFromContext` is unchanged for callers — same signature, same
  behaviour — and now delegates.
- **An account the OAuth callback creates is verified only when the provider
  did not say otherwise.** `IsEmailVerified` is now
  `EmailVerified == nil || *EmailVerified`: silence still means verified, which
  is what the port has always done and what most providers send, but a provider
  that positively reports `email_verified: false` is believed instead of being
  ignored. `RequireVerifiedEmail` is how a deployment refuses silence as well.

### Deprecated
- **`<base>/jwks`, the alias `(*IDP).RegisterHandlers` mounts alongside the
  canonical path.** It serves the identical bytes and headers and is kept
  through the 0.x line (upstream plan D-13); it is removed in v1.0.0. Point
  relying parties at `<prefix>/.well-known/jwks.json`, or at whatever
  `IDPConfig.JWKSPath` says. Its methods narrow as a side effect: both JWKS
  patterns are now registered `GET`-only, as the reference registers the route
  (`router.get`, `auth.router.ts:490`) and as the four adapters mount it, so
  net/http serves `HEAD` from the `GET` pattern and answers 405 to every other
  method where the alias previously answered the document to all of them.

## [0.5.0] - 2026-09-11

The claims and identity-provider milestone: custom claims can be built from
configuration (StaticClaims, UserFieldClaims, ChainClaims) or from a signed,
bounded, fail-closed claims webhook, the adapters authenticate without
calling the claims hook so a webhook fires on issuance and on /me only, and
the IdP signs with an injected key under a stable kid, publishes a proper
JWKS document, parses PEM keys and mints the reference's RS256 token pair as
a host-level API.

### Added
- **Claim builders — `StaticClaims`, `UserFieldClaims`, `ChainClaims` — and the
  synchronous `ClaimsWebhook`.** `TokenClaimsBuilder` names the type
  `Config.BuildTokenClaims` always had (an alias, so existing literals still
  satisfy it). `StaticClaims(map)` adds the same claims to every token, from a
  copy; `UserFieldClaims(map[claim]field)` copies `User` fields by their `/me`
  names (`id`, `email`, `role`, `tenantId`, `firstName`, `lastName`,
  `phoneNumber`, `isEmailVerified`, `isTotpEnabled`, `loginProvider`) and
  refuses any other field name, or a reserved session claim as the claim
  name, at construction, never at mint time;
  `ChainClaims(...)` merges builders in order, later wins, first error stops.
  `NewClaimsWebhook(url, secret)` builds a `ClaimsWebhook` whose `Build` POSTs
  `{"user": <PublicUser>}` under the family's outbound-webhook headers
  (`X-Webhook-Event: claims.build`, `X-Webhook-Delivery`, `X-Webhook-Timestamp`,
  and `X-Webhook-Signature: sha256=<hex HMAC>` when a secret is set) and expects
  `{"claims": {...}}` — 2 seconds by default, 64 KiB at most. Any other answer fails
  the mint, so a login whose endpoint is down answers `500` exactly as it does
  for any failing hook, and the answered claims cannot set the reserved session
  claims. All four are this port's own extension — the reference has only the
  in-process `buildTokenPayload` function (`auth.router.ts:378-384`) — for
  deployments whose claims are configuration (`security.jwt.extraClaims`,
  `security.jwt.claimsWebhook`) rather than code. See README_DETAILED.md,
  "Custom Claims".
- **`Service.Authenticate(ctx, accessToken)` and `Auth.Authenticate`.** `Me`
  without the custom-claim enrichment: verifies the token, runs the configured
  session check, loads the user and fills the optional stores' metadata, roles,
  permissions and tenants, but never calls `Config.BuildTokenClaims`, so
  `CustomClaims` is nil. `Me` is now `Authenticate` plus the hook.
- **IdP signing key injection, `kid`, and the RS256/JWKS building blocks
  exported.** `IDPConfig.Signer crypto.Signer` is the key every RS256 token is
  signed with and the key the JWKS document publishes: an `*rsa.PrivateKey` —
  `ParseRSAPrivateKeyPEM(pem)` reads the reference's PEM form
  (`idProvider.privateKey`, `token.service.ts:47`), PKCS#8 or PKCS#1 — or a
  KMS/HSM-backed signer, which `BuildRS256JWT(signer, kid, claims)` asks for one
  `Sign(rand, sha256Digest, crypto.SHA256)` per token. `NewIDP` and
  `BuildRS256JWT` both refuse a signer that is not RSA. `IDPConfig.KeyID` is
  the `kid` (empty → `DefaultIDPKeyID`, the reference's `provisioner-key-1`,
  `token.service.ts:78`);
  `IDPConfig.PublicKeys []JWK` are further keys published after the signer's
  for a rotation (structural: nothing signs or verifies with them);
  `IDPConfig.RefreshTokenTTL` and `IDPConfig.Logger` complete the block.
  `JWK{Kty, Use, Alg, Kid, N, E}` and `JWKS{Keys}` are the reference's document
  (`jwks.service.ts:5-16`), `NewRSAJWK(pub, kid) (JWK, error)` its
  `publicKeyToJwk` (`:168-179`; a nil key is an error, not a panic),
  `(*IDP).JWKS()` its `buildJwksDocument` (`:184-186`) followed by
  `PublicKeys`.
- **`(*IDP).IssueIdPTokenPair(ctx, user) (AuthTokens, error)`** — the
  reference's `generateIdProviderTokenPair` (`token.service.ts:73-95`): the six
  base claims with `Config.BuildTokenClaims` spread over them, the hook's
  `iat`/`exp`/`kid` dropped, `iss` only when `IDPConfig.Issuer` is set, access
  token 30 days and refresh token 90 days by default
  (`IDPConfig.AccessTokenTTL`/`RefreshTokenTTL` override), both RS256 under
  `KeyID`, no session and no `sid`. The reference's fallback to the session
  refresh lifetime (`idProvider.refreshTokenExpiry ?? config.refreshTokenExpiresIn
  ?? '90d'`, `token.service.ts:91`) is not reproduced: `IDPConfig.RefreshTokenTTL`
  never falls back to `Config.RefreshTokenTTL`, because that is always set here
  (`DefaultConfig` fills it and `validate` requires it), so honouring it would
  make the 90-day default unreachable and tie the IdP pair silently to the
  session lifetime. A host-level API as in the reference, where nothing calls it
  (reference-issues N35): `/login`, `/refresh` and the OIDC `/token` still issue
  the HS256 session pair.

### Changed
- **The adapters' `Middleware()` no longer runs `Config.BuildTokenClaims`.** All
  four (net/http, chi, gin, echo) authenticate through `Auth.Authenticate`
  instead of `Auth.Me`, so the user a protected route reads from
  `UserFromContext` carries the stores' enrichment as before but `CustomClaims`
  is nil where it used to be the hook's fresh result. The hook is a mint-time
  hook and, with a `ClaimsWebhook` behind it, a network round trip: running it
  on every request would make each protected route pay for a claim set nothing
  reads, when the claims are already inside the token the request carried.
  This is where the reference draws the line too: its `authMiddleware`
  verifies the token and hands the route the payload as `req.user`, without
  `buildTokenPayload` (`auth.middleware.ts:44-61`); only its `/me` calls
  `buildPayload` again.
  `GET /me` still runs it — exactly once per call, and now authenticates itself
  rather than sitting behind the middleware — so `customClaims` on `/me` is
  unchanged. The two other places that verified a token only to read an
  identity off it follow: `POST /link-request` with a credential (the reference
  reads `payload.sub` there without `buildTokenPayload`,
  `auth.router.ts:1502-1510`) and the IdP `userinfo` endpoint, whose body the
  hook never contributed to. Nothing changes on the wire. A host that needs the
  hook's result on its own route can call `Auth.Me` from the handler.
- **The IdP's `kid` defaults to `provisioner-key-1` instead of a random
  per-process value, and `jwks` serves `(*IDP).JWKS()`** — the same JSON shape
  as before for the signer's key, followed by `IDPConfig.PublicKeys`. Leaving
  `IDPConfig.Signer` nil still generates an ephemeral RSA-2048 key per `NewIDP`,
  and now logs the reference's warning once (`token.service.ts:52-57`) through
  `IDPConfig.Logger` or the Service's `Config.Logger`: `auth: IdP mode: no
  Signer configured — auto-generating an ephemeral RSA keypair. All tokens will
  be invalidated on restart. Set IDPConfig.Signer in production.`

### Fixed
- **The OIDC `/token` endpoint reports `expires_in` as the lifetime of the
  access token it returns.** The body carries the HS256 session access token,
  whose lifetime is `Config.AccessTokenTTL`, but `expires_in` was
  `IDPConfig.AccessTokenTTL` raw — `0` when unset, and with that field now the
  IdP pair's 30-day lifetime, a number describing no token in the response. It
  is now `Config.AccessTokenTTL` in seconds; `IDPConfig.AccessTokenTTL` governs
  only `IssueIdPTokenPair`.

## [0.4.0] - 2026-09-11

The email-flows milestone, plus the first steps of the ones after it. Links in
auth mail are now built from the request that asked for them, against a site
URL allowlist, and rendered from a template store with the reference's six
template ids and its en/it built-ins; a gateway transport speaks the
reference's mailer contract and a delivery webhook can replace mail and SMS
altogether. On the way: the session claims can no longer be overridden by a
claims hook (a security fix), loginProvider joins the payload, the TOTP
issuer is configurable with two registered deviations, OAuth providers gain
additional auth params, the GitHub email fallback and a declarative
profileMap, the IdP keeps its authorization codes in a store, and the
wiretest harness can express conditional route sets.

### Added
- **`NewGatewayMailerTransport(MailerConfig)`: a mail transport that speaks the
  reference's gateway contract.** `POST {endpoint}` with an `X-API-Key` header and
  the JSON body `{to, subject, html, text, from, fromName, provider}`, delivered on
  a `2xx` only (`mailer.service.ts:261-291`; config shape
  `auth-config.model.ts:19-36`). `MailerConfig{Endpoint, APIKey, From, FromName,
  Provider, DefaultLang}` mirrors the reference's `email.mailer` block, JSON tags
  included, so a deployment that already holds that block can decode it and hand
  it over; `Client *http.Client` is the one addition (nil → the 10-second timeout
  the other HTTP transports use). The constructor refuses an empty or
  non-absolute endpoint, and a failed send names the status and nothing else —
  the API key never appears in an error. `MailMessage.Text` (additive) carries
  the plain-text alternative; left empty, the HTML is sent as the text, as the
  reference's `sendCustom` does (`text ?? html`). No route changes.
- **`Config.SiteURLs []string` and `WithSiteURLs(urls ...string) Option`** — the
  reference's `config.email.siteUrl`, which is one string or an array of them.
  The first entry is the canonical base for emailed links (`getDefaultSiteUrl`,
  `auth.router.ts:202-206`); every entry, merged with `OAuthWiring.AllowedOrigins`
  in that order and deduplicated, is the origin allowlist a request's `Origin` or
  `Referer` is matched against (`buildAllowedOrigins`, `auth.router.ts:213-219`).
  Matching is exact, as the reference's `includes` is.
- **`(*Auth).ResolveSiteURL(r *http.Request) string`** — the reference's
  `resolveSiteUrl` (`auth.router.ts:233-246`): the allowlisted `Origin`, else the
  allowlisted origin of the `Referer`, else the default site URL. The default is
  `SiteURLs[0]`; `OAuthWiring.SiteURL` stays the override for it, and when that is
  empty `OAuthBegin`, `OAuthComplete` and `LinkRequest` now fall back to
  `SiteURLs[0]` and match against the same merged allowlist — one allowlist and
  one default for links and redirects alike, as the reference has.
- **`HTTPConfig.UIEnabled bool`** and **`(HTTPConfig).UILink(siteURL, path string) string`**
  — the reference's `buildUiLink` (`auth.router.ts:261-271`):
  `<siteURL><prefix>/ui/<path>` with the UI enabled, `<siteURL><prefix>/<path>`
  otherwise, one trailing slash stripped from the prefix and one leading slash
  from the path. **`(HTTPConfig).LinkBase(siteURL string) string`** is
  `UILink(siteURL, "")` with its trailing slash removed — the base
  `MagicLinkURL`, `PasswordResetURL`, `EmailVerificationURL` and
  `EmailChangeConfirmURL` take (`magic-link.strategy.ts:25-27`) — and `""` for an
  empty site URL, so that a mailer's static `BaseURL` still applies.
- **Per-request `LinkBase` and `Lang`** on `ForgotPasswordInput`,
  `EmailVerificationInput`, `ChangeEmailRequestInput` and `MagicLinkSendInput`,
  copied untouched onto `PasswordResetDelivery`, `EmailVerificationDelivery`,
  `EmailChangeDelivery` and `MagicLinkDelivery`. All four adapters fill them from
  the request — `LinkBase` is `cfg.LinkBase(auth.ResolveSiteURL(r))`, `Lang` is
  the `emailLang` body field, which was decoded and dropped before — so a
  deployment serving several front ends mails each one a link back to itself.
  `POST /magic-link/send` now reads `emailLang` in both modes, as the reference
  does (`auth.router.ts:1080`). `LinkTokenDelivery.EmailLang` is unchanged.
- **The ready-made mailers honour the delivery over their static configuration.**
  A non-empty `LinkBase` wins over `BaseURL`; a `Lang` of `it` or `en` wins over
  `Locale` and anything else defers to it (`resolveLang`,
  `mailer.service.ts:255-259`). With no `SiteURLs` configured a delivery carries
  no base, so an existing deployment keeps the links and the language it had.
- `GenerateOpenAPISpec` documents `emailLang` on `POST /magic-link/send` and
  describes what it does on all four routes. No route was added.
- **`loginProvider` on every token and on `GET /me`.** `User.LoginProvider`
  records the provider that created the account: `OAuthService.HandleCallback`
  sets it to the provider's name on the users it creates, and a password
  registration leaves it empty. It reaches the wire as the `loginProvider`
  claim on access, refresh and temp tokens and as the `loginProvider` field of
  `/me`, always present and `"local"` when nothing recorded one — the
  reference's `user.loginProvider ?? 'local'` (`auth.router.ts:379`), which
  its `/me` carries unconditionally. `LoginProviderLocal` names the default.
  The field is additive: a host store that never persists it keeps answering
  `"local"`, and `MemoryUserStore` stores it with the rest of the row.
- **`DeliveryWebhook`: one HTTP sender for every delivery seam.**
  `NewDeliveryWebhook(url, secret)` returns a value whose `SendMagicLink`,
  `SendPasswordReset`, `SendEmailVerification`, `SendEmailChange` and
  `SendSMSCode` methods have the five sender signatures, so a deployment whose
  transport is neither mail nor SMS — or is not reachable from this process —
  wires the one value to `WithMagicLinkSender(hook.SendMagicLink)` and the rest.
  It is what the consumer's `email.deliveryWebhook.url` knob points at. Each
  delivery is `POST`ed once as
  `{"kind": "<magic-link|password-reset|email-verification|email-change|sms-code>",
  "delivery": {…camelCase…}}` with the family's outbound-webhook headers —
  `X-Webhook-Event: delivery.<kind>`, `X-Webhook-Delivery` (a fresh UUID),
  `X-Webhook-Timestamp` (ISO 8601) — and, when a secret is set,
  `X-Webhook-Signature: sha256=<hex HMAC-SHA256 of the body>`, which
  `VerifyWebhookSignature` already checks (`src/tools/webhook-sender.ts:24-33,
  54-56`). A non-2xx answer, a transport failure or the timeout (5 s by default,
  `Timeout` to change it, `Client` to supply your own) is an error, which the
  route it is wired to handles as it already does; the error names the kind, the
  status and the recipient's domain, never the token, the code, the full address
  or the secret. **The body shape is this port's own**: the reference's send
  callbacks never cross HTTP, so there is no wire to reproduce, and
  README_DETAILED.md "Delivery webhook" documents it as such. The five delivery
  structs gained camelCase JSON tags for it (additive; nothing serialised them
  before), and `DeliveryKind*` / `DeliveryWebhookRequest` name the vocabulary for
  a receiver written in Go.
- **`AuthCodeStore` — the OIDC IdP's authorization codes are now a store
  seam.** `AuthCodeStore{SaveCode, ConsumeCode}` persists codes between
  `/authorize` and `/token`; `ConsumeCode` is single-use and treats an expired
  record as absent, answering `ErrInvalidCode` (reused: the sentinel already
  means "unknown, consumed or expired code" and `/token` writes its own
  `invalid_grant`, so no new mapping was needed). `MemoryAuthCodeStore` /
  `NewMemoryAuthCodeStore()` is the in-process implementation. `IDPConfig.Codes`
  selects the store (nil keeps today's in-process behaviour) and
  `IDPConfig.CodeTTL` replaces the hardcoded five minutes (zero keeps it). The
  `AuthCode` record carries `RedirectURI`, `Scope`, `CodeChallenge` and
  `CodeChallengeMethod` as data so a store written now needs no schema change
  when PKCE verification lands; nothing checks them yet.
- **Codes are stored hashed.** The client still receives the 24-byte random
  code; the store is keyed by its SHA-256 (`hashToken`), so a dump of the
  backing table cannot be redeemed at `/token`, the same rule refresh, reset
  and magic-link tokens already follow.
- **`idp_test.go`.** The IdP had no tests. The store is covered for
  save/consume-once, expiry and 32 concurrent consumers under `-race`; the
  endpoints are walked end to end over `httptest` (`/authorize` → `/token` →
  `/userinfo`, replay refused) through an injected `AuthCodeStore`.
- **`OAuthProvider.AdditionalAuthParams map[string]string`** — the reference's
  `additionalAuthParams` (`generic-oauth.strategy.ts:63`): every entry is added
  to the authorization URL's query. Precedence is the reference's spread order
  (`:113-120`): an entry overrides `client_id`, `redirect_uri`, `response_type`
  and `scope`, and `state` overrides an entry; the PKCE pair this port adds is
  written after the entries too, so no configuration can weaken the code
  binding. `GoogleProvider` pre-populates `access_type=offline`, the one extra
  parameter the reference's Google strategy sends (`google.strategy.ts:29`) —
  it sends no `prompt`.
- **`OAuthUserInfo.EmailVerified *bool`** — the reference profile's
  `emailVerified?` (`generic-oauth.strategy.ts:157`, `google.strategy.ts:58`),
  read from the userinfo's `email_verified` boolean; `nil` when the provider
  said nothing. `HandleCallback` does not read it yet: an account the callback
  creates is verified exactly as before.
- **GitHub email fallback.** When GitHub's `/user` answers without an email —
  an account whose address is private — the `github` provider now fetches
  `/user/emails` with `Authorization: token <access_token>` and
  `Accept: application/vnd.github.v3+json`, picks the entry that is both
  `primary` and `verified`, else the first one, and reports its `verified`
  flag as `EmailVerified` (`github.strategy.ts:54-68`). A failing call leaves
  the email empty rather than failing the exchange, as the reference's
  `emailRes.ok` gate does. **`OAuthProvider.GitHubEmailsURL`** overrides the
  endpoint (empty means `UserInfoURL + "/emails"`); `GitHubProvider` sets it to
  `https://api.github.com/user/emails`.
- **`Config.TwoFactorAppName string` and `WithTwoFactorAppName(name string) Option`**
  — the reference's `twoFactor.appName` (`auth-config.model.ts:272-274`, read
  at `auth.router.ts:830`): the issuer an authenticator app files a TOTP
  enrolment under. `POST /2fa/setup` carries it in `otpauthUrl` twice, as the
  label prefix and as the `issuer` parameter. Left empty, the URI keeps
  carrying `Config.Issuer`, as it did before the field existed, so enrolments
  made before and after this release sit under the same name; the reference's
  fallback is the literal `'awesome-node-auth'`, and that difference is
  registered as the deviation `totp-issuer-defaults-to-config-issuer`.
- **`TOTPAlgorithm`, `TOTPDigits`, `TOTPPeriod`, `TOTPSkew`** — the TOTP
  parameters as exported constants (`"SHA1"`, `6`, `30 * time.Second`, `1`),
  read by both the provisioning URI and the verifier so that what an app is
  told at enrolment cannot drift from what a code is later checked against.
  The first three are the reference's otplib defaults, not knobs
  (`totp.strategy.ts:5-8` constructs `TOTP` with only the crypto and base32
  plugins). `TOTPSkew` is this port's existing ±1-step tolerance; otplib's
  `epochTolerance` defaults to `0`, so the reference accepts the current step
  only. No behaviour changed; the values were already these.
- **The deviation `totp-accepts-one-step-of-skew` is registered.**
  `POST /2fa/verify-setup` and `POST /2fa/verify` accept a code from the step
  either side of the current one (`TOTPSkew = 1`); the reference accepts the
  current step only, because `totp.strategy.ts:22-25` calls otplib's `verify`
  with nothing but the secret and `@otplib/totp` 13.4.0 defaults
  `epochTolerance` to `0`. The behaviour is unchanged — it is now recorded in
  `CompatibilityNotes()` and the README's deviations section. There is no knob
  to narrow the window to the reference's and none is planned.
- **`OAuthProvider.MapProfile func(raw map[string]any) (OAuthUserInfo, error)`**
  — the reference's `mapProfile` hook (`generic-oauth.strategy.ts:71-77`): when
  set, it is the profile `ExchangeCode` returns for that provider, in place of
  the default mapping (`:151-153`) — the whole mapping, the `github` preset's
  `/user/emails` fallback included. The service fills `Provider`, and `Raw`
  when the hook left it nil; a hook error fails the exchange on the existing
  profile-failed path (401 `OAUTH_PROFILE_FAILED` on the callback).
- **`OAuthProvider.ProfileMap map[string]string` and
  `CompileProfileMap(map[string]string)`** — the declarative form of the hook
  for a provider loaded from configuration: the keys `id`, `email`,
  `emailVerified`, `name` and `picture` (`id` required, any other key an
  error) mapped to expressions in a grammar that is this port's own — `$.a.b`
  and `$.a[0]` paths, `??` fallback chains and a double-quoted literal as the
  final fallback — e.g. `"$.mail ?? $.userPrincipalName"` for Microsoft Graph
  or `"$.data.user.id"` for a wrapped document. Evaluation follows
  JavaScript's `??`: the first path resolving to a value that is neither
  missing nor `null` wins; a string is taken as is, a number is rendered as
  `String()` renders it (an integer-valued id has no decimal point) and a
  boolean as `true`/`false`. An object or array value, an `emailVerified`
  that is not a boolean or `"true"`/`"false"`, and an `id` that resolves to
  nothing or to the empty string are evaluation errors on the profile-failed
  path. Anything outside the grammar — `$` alone, single quotes, wildcards,
  filters, function calls — is a compile error naming the expression.
  `MapProfile` wins when both are set. `CompileProfileMap` is the compiler,
  exported so a deployment can validate a map before it wires anything.
- **`NewOAuthServiceWithConfig(providers ...OAuthProvider) (*OAuthService, error)`**
  — `NewOAuthService` with every `ProfileMap` validated, so a deployment fails
  at start-up rather than at the first login; the errors name each broken
  provider and expression. `NewOAuthService` keeps its signature and never
  panics: a map that does not compile is recorded against its provider, whose
  exchanges then return that error before the token endpoint is contacted
  (500 on the callback — a configuration error, not a client one) while the
  other providers keep working. No route changes.
- **Template store seam: `TemplateStore`, `MemoryTemplateStore`,
  `WithTemplateStore(TemplateStore) Option` and `Config.Templates`** — the
  reference's `ITemplateStore` (`template-store.interface.ts:13-43`) and its
  `MemoryTemplateStore` (`memory-template.store.ts`), `config.templateStore`
  (`auth-config.model.ts:400`). `MailTemplate{ID, BaseHTML, BaseText,
  Translations}` and `UITranslation{Page, Translations}` carry the reference's
  JSON keys (`id, baseHtml, baseText, translations`; `page, translations`).
  `UpdateMailTemplate(ctx, id, MailTemplatePatch)` upserts from `{id, "", "", {}}`
  and spreads the patch on top — a nil field keeps the stored one, a supplied
  `Translations` replaces the whole map (`memory-template.store.ts:16-22`);
  `UpdateUITranslations` sets a page wholesale (`:33-35`); both return what is
  stored. Lists come back in insertion order. The UI half is stored now and
  read by the UI router when it lands. No route was added.
- **The reference's six template ids and their built-ins.**
  `TemplatePasswordReset` (`password-reset`), `TemplateMagicLink`,
  `TemplateWelcome`, `TemplateVerifyEmail`, `TemplateEmailChanged` and
  `TemplateInvitation` (`mailer.service.ts:186-211`), each with the reference's
  en and it subject, HTML and text transcribed verbatim (`:19-127`, invitation
  `:211-225`). `(*MailTemplater).Register(locale, id, subject, html, text)`
  replaces the unexported `addTemplate`; `(*MailTemplater).RenderMail(ctx,
  locale, id, data) (MailRendered{Subject, HTML, Text}, error)` is the
  reference's `render` (`:149-181`): a stored template is used only when both
  `baseHtml` and `baseText` are non-empty (`:158`), its translations are those
  for the language, else `en`, else none (`:159`), `{{T.key}}` becomes the
  translation or `[key]` (`:163`), then `{{key}}` becomes the data value or
  `[key]` (`:165-168`), and the subject is `translations.subject` or the
  built-in one (`:172`). Values are substituted raw, HTML included, as the
  reference substitutes them (`:167`). The data keys are the reference's per
  id — `link`, `token`; `newEmail`; `loginUrl`, `tempPassword` — and this
  port's own (`appName`, `name`, `code`, `oldEmail`) only when set, so a stored
  template sees the keys it sees in the reference; see `MailTemplateData`,
  which gains `NewEmail` and `OldEmail`. `MailTemplater.Store` names a store; a
  templater whose `Store` is nil finds `Config.Templates` inside a service call.
  `Render(locale, id, data) (subject, body, err)` keeps its signature and
  returns the subject and HTML. The `welcome` id has no sender in this port:
  the reference mails it from `POST /register` (`auth.router.ts:719-724`),
  which this port's register route does not do yet — it renders through
  `RenderMail` only.
- **`Config.SendEmailChanged EmailChangedSender`, `WithEmailChangedSender`,
  `EmailChangedDelivery{UserID, TenantID, OldEmail, NewEmail, Lang}` and
  `NewEmailChangedMailer(transport, appName)`** — the reference's
  `config.email.sendEmailChanged` (`auth-config.model.ts:252-257`): the notice
  `POST /change-email/confirm` mails to the OLD address once the change is
  applied (`auth.router.ts:1056-1066`). `Service.ConfirmEmailChange` fires it
  after the address has moved and the token is cleared; a failing sender is the
  reference's generic 500 with the change already committed — its call sits
  inside the route's `try` (`:1068-1069`) — and a nil sender is silence. The
  route passes no language, as the reference passes none;
  `ConfirmEmailChangeInput.Lang` exists for a caller driving the service
  directly. The wiretest suite records the notice on all four adapters.
- **The ready-made mailers send the text alternative.** `MagicLinkMailer`,
  `PasswordResetMailer`, `EmailVerificationMailer`, `EmailChangeMailer` and the
  new `EmailChangedMailer` fill `MailMessage.Text` with the rendered text body,
  so the gateway payload's `text` is the reference's text template rather than
  a copy of the HTML. Under the deprecated `HTTPMailerTransport` this adds a
  `Text` key to what these mailers send; a caller building its own
  `MailMessage` is unchanged.

### Changed
- **Tests — the wiretest OpenAPI check can express conditional route sets.**
  `documentedRoutes` stays the unconditional base; a `conditionalRouteSet`
  registered in `conditionalRoutes` names the configuration that mounts extra
  routes and the `OpenAPIInfo` flag that documents them, and is checked
  configured (spec and mount agree on base ∪ set), unconfigured (its routes
  answer 404/405) and by name in every failure. The registry is empty until the
  first conditional surface (JWKS, docs, UI, admin, tools) lands.
- **Docs — the README parity snapshot now reflects the shipped surface.** It
  claimed every capability as implemented, including an admin router that does
  not exist; each row now says what is mounted, what is only a building block,
  what is absent, and the milestone release that closes the gap.
- **The IdP no longer keeps authorization codes in a process-local map.**
  `/authorize` saves through `IDPConfig.Codes` and `/token` consumes through
  it; the `sync.Map` is gone. A deployment where the two requests can land on
  different processes — serverless, or more than one instance — must supply a
  shared store or every code minted by a sibling process is `invalid_grant`.
  Single-process callers that never set `Codes` see no change.
- **`/token` binds the code to the client redeeming it.** A code issued to one
  `client_id` redeemed with another client's credentials is now
  `invalid_grant` and the attempt consumes the code (RFC 6749 §4.1.3). The map
  never checked this.
- **Default OAuth subject id is `id`, then `sub`.** The generic userinfo
  mapping probed `sub` → `id` → `user_id`; it now follows the reference's
  `String(raw.id ?? raw.sub ?? '')` (`generic-oauth.strategy.ts:155`) and
  stringifies a numeric `id`. `user_id` stays as this port's extra last
  resort so a provider registered against an earlier version keeps resolving;
  it only widens what is accepted. A profile carrying both `id` and `sub` with
  different values — rare, since OIDC providers send `sub` alone — now links by
  `id`. The `github` mapping prefers `name` and falls back to `login`
  (`github.strategy.ts:69`); it used the login unconditionally.
- **The `otpauthUrl` label is `issuer:account`, as the reference emits it.**
  `POST /2fa/setup` used to label the URI with the bare account
  (`otpauth://totp/user%40example.com?…`); it is now
  `otpauth://totp/<issuer>:user%40example.com?…`, which is what the
  reference's `totp.toURI` (`totp.strategy.ts:17`) has produced all along:
  `@otplib/uri` 13.4.0 (what the reference's package-lock.json pins for `otplib ^13.3.0`) builds the label
  as `${issuer}:${label}` whenever an issuer is given and escapes each
  colon-separated piece with `encodeURIComponent`. Query values are escaped the
  same way — a space in the app name is `%20`, never the `+` of form encoding.
  Authenticator apps read both forms identically; the `secret` is unchanged and
  existing enrolments are unaffected. `algorithm`, `digits` and `period` stay
  spelled out, which otplib omits at its defaults — see `totpProvisioningURI`.
- **The built-in mail templates are the reference's now**
  (`mailer.service.ts:19-127`). Subjects lose the `<appName> - ` prefix and
  read `Reset your password`, `Your magic sign-in link`, `Verify your email
  address` and their Italian counterparts; the bodies are the reference's
  paragraphs, greeting nobody, with the link written out in full and a text
  alternative beside the HTML. `EmailChangeMailer` mails the verify-email
  template under the change-email confirmation link, which is what the
  reference's `/change-email/request` sends (`auth.router.ts:1027-1032`). A
  deployment that wants its previous wording registers it with
  `(*MailTemplater).Register` or stores an override. The wire is untouched:
  only mail bodies differ.
- **`MailTemplater` carries a mutex now**, which is what makes `Register`,
  `RenderMail` and `Render` safe to call concurrently. Use it through the
  pointer `NewMailTemplater` returns, never by value: a copy trips `go vet`'s
  copylocks check.

### Deprecated
- **`HTTPMailerTransport` and `NewHTTPMailerTransport`.** They POST `MailMessage`
  as PascalCase JSON under an `X-Mailer-Secret` header, a request of this port's
  own that no gateway built for the reference accepts. Behaviour is unchanged for
  the gateways built against it since 0.3.0 — `MailMessage.Text` is `omitempty`
  there, so a caller that never sets it sends the same bytes as before. Use
  `NewGatewayMailerTransport` for new deployments; removal is scheduled for
  v1.0.0.
- **The template ids `reset_password`, `magic_link`, `verify_email` and
  `email_change`.** They are aliases — the first three of
  `TemplatePasswordReset`, `TemplateMagicLink` and `TemplateVerifyEmail`;
  `email_change` of `TemplateVerifyEmail` too, since the reference has no
  separate template for that mail. `Render`, `RenderMail` and `Register` accept
  them unchanged, and a store is asked for the id they alias; removal is
  scheduled for v1.0.0.

### Fixed
- **Security — `Config.BuildTokenClaims` can no longer override the session
  claims.** The hook's result was merged over the whole payload, so a custom
  claim named `sid`, `tid`, `jti`, `typ`, `iss`, `iat` or `exp` replaced the
  session binding, tenant scope, token id, type, issuer or lifetime of every
  token minted — and a hook returning `typ: "access"` turned the 2FA step-up
  `tempToken` into a full session credential, reopening the five-minute bypass
  the typed temp token exists to close. Those seven claims are now written
  after the merge, on access, refresh and temp tokens alike. The hook still
  overrides the six base claims (`sub`, `email`, `role`, `loginProvider`,
  `isEmailVerified`, `isTotpEnabled`), which is the reference's own semantics:
  it spreads `buildTokenPayload(user)` over exactly those, assigns `sid`
  afterwards and strips `iat`/`exp` before signing (`auth.router.ts:378-384`,
  `:433`, `token.service.ts:19`).

## [0.3.1] - 2026-09-11

A one-line patch for the shipped clients, cut so that consumers can pin a tag
instead of the pseudo-version they had to use for it.

### Fixed
- **`GET /me` carries `sub` alongside `id`, plus `role` when set.** Both
  official clients cast `sub` non-nullably (Flutter `json['sub'] as String`,
  Angular `sub: string`), so a `/me` body without it crashed the Flutter app on
  a Dart `TypeError` instead of showing a logged-out state. `id` shipped in
  0.2.0 and both clients read it as optional, so emitting both breaks nobody.
  The new test is written against the clients' casts rather than the
  reference's field list. (#46)

## [0.3.0] - 2026-08-15

Makes the 0.2.0 surface actually usable end to end. Two things were missing
rather than wrong: a password login against a 2FA account was a dead end, and
every route that mints a credential to mail or text stored it and answered
success without sending anything. Both are closed, so a client can now complete
a second factor and a deployment can deliver what it issues.

It also adds the deviation register (`CompatibilityNotes()`), whose README
section is generated from it, so a deliberate difference from the reference
cannot quietly stop being documented. Writing it surfaced five differences
nobody had recorded and removed one that turned out not to be a difference at
all.

### Changed
- **BREAKING — `POST /auth/magic-link/send` and `POST /auth/sms/send` require a
  configured sender.** Without one they answer
  `500 {"error": "Email not configured", "code": "EMAIL_NOT_CONFIGURED"}` and
  `500 {"error": "SMS is not configured", "code": "SMS_NOT_CONFIGURED"}` and store
  nothing, matching the reference. Previously they answered
  `200 {"success": true}` having minted and stored a credential that nothing could
  deliver. `Config.validate()` still does not ask for a sender, so a deployment
  that never calls these routes is unaffected. The two checks sit where the
  reference puts them, which is not the same place: `/sms/send` refuses at the top
  of the route, before the body is read, so an unconfigured deployment no longer
  answers `200` to an unknown address; `/magic-link/send` refuses inside the
  service before the address lookup, so the 500 outranks the anti-enumeration
  silence there too, but a bad `tempToken` in `mode: "2fa"` still gets its `401`
  first. A sender that fails leaves the stored credential in place and answers the
  reference's generic code-less `500`.
- **`GenerateOpenAPISpec` now describes the routes that exist.** It had drifted a
  major version behind: it documented `/auth/totp/setup`, `/auth/sessions`,
  `/auth/forgot-password` and `/auth/reset-password` in shapes no adapter ever
  served (`{"user": …, "tokens": …}`, `204`s, snake_case fields), while omitting
  most of the surface 0.2.0 actually mounts. It now covers every mounted operation
  with the current envelope, the real error catalog entries per route, the
  `X-Auth-Strategy` and `X-CSRF-Token` headers, and both the bearer and cookie
  security schemes.
- **The `examples/` programs compile again, and CI compiles them.** All three
  carried `//go:build ignore`, so `go build ./...` never saw them and they had
  rotted onto an adapter API that no longer exists (`adapt.Register`,
  `chiAdapter.New`, per-route registration). They now use `Mount`, drop the routes
  the port does not serve, and wire the delivery senders. The build constraints are
  gone, so they cannot rot again silently.
- **BREAKING — `POST /auth/login` answers a second-factor account with a
  challenge instead of an error.** It was
  `403 {"error": "Two-factor authentication required", "code": "2FA_REQUIRED"}`
  and carried no `tempToken`, so the whole step-up half of the contract
  (`/2fa/verify`, and `/sms/*` + `/magic-link/*` in `mode: "2fa"`) was unreachable
  over HTTP even though those routes were implemented — the tests minted their own
  `tempToken`, which is why it survived. It is now the reference's pair of answers:
  `200 {"requiresTwoFactor": true, "tempToken": "<5-minute token>",
  "available2faMethods": [...]}`, or, when a policy demands a factor the account
  has not enrolled, `403 {"requires2FASetup": true, "tempToken": "…",
  "code": "2FA_SETUP_REQUIRED"}`. Neither body is the error envelope and neither
  sets a cookie, in bearer or cookie mode — nothing has been issued yet. A client
  that branched on `403 2FA_REQUIRED` at `/login` has to branch on
  `requiresTwoFactor` instead; the code itself is unchanged where it is still
  emitted, on `/2fa/disable`. `Service.Login` keeps its signature and still
  reports `ErrTwoFactorRequired`; `Service.LoginWithChallenge` is the form that
  returns the challenge.

### Added
- **`compatibility.go`: `CompatibilityNotes()`, the deviation register as data**,
  closing item 6 of #22. It returns the contract this port targets, the cookie and
  bearer conventions, and every known deviation from `awesome-node-auth` as a
  `[]Deviation` — each with a stable id, the route or surface affected, what this
  port does, what the reference does with a `file:line` citation, and why the
  standing rule (reproduce the reference, quirks included) was set aside.
  `ReferenceRevision` names the revision those citations resolve against.

  **The register is the single source of truth, and the README section is
  generated from it.** The README's "Deliberate deviations from the reference" is
  rendered from `CompatibilityNotes()` by `compatibility_markdown.go` and pinned by
  `TestREADMEIsGeneratedFromCompatibilityNotes`, which re-renders the register and
  compares it to the committed file byte for byte. It fails in both directions: a
  register edit that was not regenerated fails, and a README edit with no register
  edit behind it fails. Regenerate with
  `go test -run TestREADMEIsGeneratedFromCompatibilityNotes -update .`, which the
  section's own header comment says as well. Because the section is generated, the
  register's prose fields are markdown, and `Deviation` gained `Title` (the section
  heading) and optional `Notes` (extra labelled paragraphs) so no README content
  lives outside the register.

  This replaces a mirror test that bound identity only — it asserted that every id
  and citation appeared *somewhere* in the README. That caught a deletion and
  nothing else: an entry could be reworded, weakened, or reversed on either side
  and stay green, and a README line could assert the exact opposite of the data it
  claimed to mirror. `compatibility_test.go` still pins the set of ids, the
  `file:line` shape of every citation, and the wire facts each entry has to keep
  stating — that last one is not redundant with generation, because someone who
  weakens an entry *and* regenerates gets a consistent README; the pinned claims
  are what fails then.

  Nine deviations are registered, and `cookie-max-age-follows-configured-ttl` is
  the newest: this port derives each token cookie's `Max-Age` from the configured
  TTL (`wire.go`), so `DefaultConfig` emits `Max-Age=2592000` on the refresh
  cookie, where the reference hardcodes 7 days — `Max-Age=604800` — regardless of
  its own `refreshTokenExpiresIn` (`token.service.ts:195,199-202`). The access
  cookie matches at the default (both 15 minutes) and diverges on any custom
  `AccessTokenTTL`. Five entries were not written down anywhere before, and two of
  those are wire-visible to any client:
  `password-policy-on-reset-and-change` (the port answers `400 WEAK_PASSWORD` where
  the reference applies no strength check at all and hashes a two-character
  password, `auth.router.ts:801-825, 904-932`) and `totp-setup-omits-qrcode` (no
  `qrCode` data URL, `auth.router.ts:832-835`). The others are
  `one-time-tokens-are-base64url` (43 base64url characters, not 64 hex,
  `token.service.ts:270-272`), `advertised-2fa-methods-require-store-support`, and
  `csrf-cookie-not-reissued-with-tokens`. Nothing here changes behaviour; the
  register describes the port as it already is.
- **`delivery_password_email.go`: the same seam for the three §2 routes that could
  not deliver.** `Config.SendPasswordReset`, `Config.SendEmailVerification` and
  `Config.SendEmailChange` (with `auth.WithPasswordResetSender`,
  `auth.WithEmailVerificationSender` and `auth.WithEmailChangeSender`) receive the
  token minted by `POST /auth/forgot-password`,
  `POST /auth/send-verification-email` and `POST /auth/change-email/request`, which
  until now stored a credential and answered success without sending anything.
  Ready-made mailers `PasswordResetMailer`, `EmailVerificationMailer` and
  `EmailChangeMailer` render the built-in `reset_password`, `verify_email` and
  `email_change` templates — shipped since 0.1.0 and called by nothing — over any
  `MailerTransport`, alongside `PasswordResetURL`, `EmailVerificationURL` and
  `EmailChangeConfirmURL`. `/change-email/request` mails the **new** address: it
  verifies the new mailbox, as in the reference.

  **Not breaking, unlike the passwordless senders.** All three routes still answer
  `200 {"success": true}` and mail nothing when no sender is wired, because the
  reference has no not-configured check on any of them — it prefers a callback,
  falls back to a mailer, and silently succeeds with neither
  (`auth.router.ts:787-792, 956-961, 1027-1032`). A *failing* sender leaves the
  stored token in place and answers the reference's generic code-less `500` on the
  two authenticated routes.
- **`POST /auth/forgot-password` now answers `200 {"success": true}` even when
  delivery fails** — a deliberate divergence, and the only one here. The reference
  lets a throwing mailer reach `handleError` and answer `500`
  (`auth.router.ts:796-798`), which means a known address `500`s while an unknown
  one `200`s: the enumeration oracle the route exists to deny, recorded and marked
  `[UNTESTED]` in the contract, so no client can depend on it. `Auth.ForgotPassword`
  absorbs a delivery failure (`ErrDeliveryFailed`) and nothing else; a store that
  cannot persist the token still answers `500`, exactly as before. `Service.ForgotPassword`
  keeps reporting the failure to a direct library caller, and the swallowed failure
  is logged, so an operator whose mail gateway is down still has a signal.

  Recorded as `forgot-password-succeeds-on-delivery-failure` in
  `CompatibilityNotes()`, and so under **Deliberate deviations from the reference**
  in the README, which is generated from it.
- **`delivery.go`: the mail/SMS delivery seam for the passwordless send routes.**
  `Config.SendMagicLink` and `Config.SendSMSCode` (with `auth.WithMagicLinkSender`
  and `auth.WithSMSCodeSender`) receive the credential the route mints, since it
  cannot travel in the response body. It sits on `Config` beside
  `BuildTokenClaims` rather than behind a store-style optional interface: the
  reference configures delivery the same way, and a missing optional store means
  `NOT_IMPLEMENTED`, which already means something else on these routes.
  `Service.SendMagicLink` and `Service.SendSMSCode` now store the credential and
  then hand it to the sender, wiring up the `MailerTransport` that had been unused
  since 0.1.0.
- Ready-made senders: `MagicLinkMailer` / `NewMagicLinkMailer` (built-in
  `magic_link` template over any `MailerTransport`), `SMSTransport` with
  `HTTPSMSTransport` and `SMSTransportSender`, plus the two family literals
  `MagicLinkURL` (`<base>/magic-link/verify?token=…`) and `SMSCodeMessage`
  (`Your verification code is: …`). `HTTPSMSTransport` reproduces the reference
  gateway contract — `GET` with `username`/`password`/`phone`/`message` query
  parameters and an `X-API-Key` header — credentials-in-URL hazard included, so an
  existing gateway keeps working; the seam is the way out for a deployment whose
  provider accepts something safer.
- `Auth.SMSConfigured`, which `POST /auth/sms/send` prechecks with.
- `OpenAPIInfo.APIPrefix`, so the generated spec follows a non-default mount
  instead of hardcoding `/auth`.
- A conformance case that replays every documented operation against every mounted
  adapter, so the spec cannot describe a route nobody serves.

- **The served browser assets talk to the routes that exist.** `ui/auth.js` was
  calling `/auth/totp/setup`, `/auth/totp/verify`, `/auth/email/verify`,
  `/auth/email/change/*` and `/auth/metadata` — none of which any adapter mounts —
  sending snake_case bodies, and reading tokens out of a `tokens` object the
  server stopped returning in 0.2.0. It never sent `X-Auth-Strategy`, so the
  bearer delivery it assumed never happened.

  It is now a cookie client by default, like the reference: `credentials:
  'include'` on every call, the CSRF cookie mirrored into `X-CSRF-Token` and read
  with the `__Host-` → `__Secure-` → bare priority, and a single-flight
  refresh-and-retry on 401/403 that stops dead on `SESSION_REVOKED` instead of
  looping. `configure({bearer: true})` opts into header/localStorage delivery for
  a cross-origin page, sending the exact `X-Auth-Strategy: bearer` the server
  compares literally. The route and field names now match the router, and the
  surface covers the sessions, account, password, email, OAuth and linking routes
  0.2.0 added. `ui/auth.html` calls the SDK instead of hand-rolling fetches, and
  `ui/admin.html` lists the real endpoints.

  Three tests keep the assets honest: every path literal they contain must name a
  route the OpenAPI spec documents (which the conformance suite ties to the
  mount), none of the retired snake_case or `tokens` shapes may reappear, and
  `auth.js` must keep sending credentials, the CSRF header and the exact bearer
  strategy value.

- **`login_2fa.go`: the login second-factor challenge.**
  `Service.LoginWithChallenge` / `Auth.LoginWithChallenge` return a `LoginResult`
  that is either a session or a `*TwoFactorChallenge`; `WriteTwoFactorChallenge`
  writes it. `available2faMethods` is built from what the account can actually use
  — `TwoFactorMethodTOTP` for an enrolled authenticator, `TwoFactorMethodSMS` for a
  stored number *and* a configured `SendSMSCode`, `TwoFactorMethodMagicLink` for a
  configured `SendMagicLink` — plus, with no counterpart in the reference, the
  store capability each method needs, so a method is never advertised that would
  answer `501 NOT_IMPLEMENTED`. `CodeTwoFactorSetupRequired` is the new code. The
  step-up token is minted below both the password check and the
  email-verification gate, so a failed login hands out nothing.
- Conformance cases that log in over HTTP and drive `/2fa/verify`, `/sms/*` and
  `/magic-link/*` with the `tempToken` taken **out of the login response**, for all
  four adapters. Also pinned: a wrong password, an unknown address and an
  unverified address each carry no `tempToken`; a challenge token is refused by a
  route wanting a real access token (it is typed `temp`, unlike the reference's);
  and the advertised list for a TOTP-only, an SMS-only and a both-factors account.
- `ui/auth.html` presents the TOTP form off the login challenge, and
  `AuthSDK.login` tells a challenge apart from a session, firing
  `auth:2fa-required` instead of `auth:login`.

### Known limitations
- The `tempToken` in the `2FA_SETUP_REQUIRED` answer authenticates nothing here.
  The reference's is an ordinary access token, so there it gets the client into
  `/2fa/setup`; this port types it separately (a documented improvement) and both
  enrolment routes sit behind the access-token gate. Enrolment therefore needs a
  full session, and the served UI reports the situation rather than offering a
  form. Letting `/2fa/setup` accept a step-up token is a security decision of its
  own and has not been made.
- An OAuth login that needs a second factor still completes without one. The
  reference 302-redirects to `<redirectTo>/auth/2fa?tempToken=…&methods=…`
  (auth.router.ts:1298-1313); the port's OAuth callback has no 2FA branch at all.

## [0.2.0] - 2026-08-07

Aligns the HTTP surface with the family wire contract (#22): the full auth-router
surface (~32 routes across all four adapters) now matches the reference in
routes, response envelopes, cookies, error codes and CSRF, so the shipped
Angular, Flutter and `auth.js` clients work against this port with only a
base-URL change. This is a breaking release across the token format, the cookie
names, the response bodies and several constructor signatures — see the BREAKING
entries below. There are no known prior consumers other than the family's own
clients, which this release is what makes compatible.

### Changed
- **BREAKING — `GET /auth/me` returns the user object unwrapped.** It was
  `{"user": {...}}`; it is now the object itself, matching the reference and the
  shipped Angular, Flutter and `auth.js` clients.
- **BREAKING — `login`, `register` and `refresh` no longer return tokens or the
  user in the body by default.** Cookie mode (the default) answers
  `{"success": true}` — plus `"userId"` on register — and sets the cookies.
  Sending `X-Auth-Strategy: bearer` (exact, case-sensitive) switches to
  `{"success": true, "accessToken": "...", "refreshToken": "..."}` with **no**
  `Set-Cookie` at all, including no CSRF cookie.
- **BREAKING — cookies are renamed and prefix-resolved.** `access_token` and
  `refresh_token` become `accessToken` and `refreshToken`, and the written name
  is resolved per the reference rule: insecure → bare, secure + root path + no
  domain → `__Host-<name>`, otherwise `__Secure-<name>`. Because `Secure`
  defaults to true, the default names are now `__Host-accessToken`,
  `__Host-refreshToken` and `__Host-csrf-token`. Existing sessions are logged
  out on upgrade. Every read site tries `__Host-` → `__Secure-` → bare, so a
  client is never locked out by a configuration change; logout expires all three
  variants of each cookie.
- **BREAKING — errors are JSON, not `text/plain`.** Every error is
  `{"error": "<message>", "code": "<CODE>"}`, with `code` omitted where the
  reference emits none. The codes are the reference catalog
  (`INVALID_CREDENTIALS`, `EMAIL_NOT_VERIFIED`, `SESSION_REVOKED`,
  `INVALID_REFRESH_TOKEN`, `CSRF_INVALID`, …) plus `USER_EXISTS`,
  `WEAK_PASSWORD` and `INVALID_BODY`, which have no reference counterpart. A
  revoked session is `401 {"code": "SESSION_REVOKED"}` on both `POST /refresh`
  and, under `SessionCheckOn: allcalls`, on any middleware-protected route.
- **BREAKING — a missing or unusable access token is `403`, not `401`, and
  carries no `code`.** This reproduces the reference middleware exactly. It is
  surprising next to the 401s, and it means a client keying refresh-retry on 401
  will not retry on an expired access token — but that is the behaviour the
  shipped clients were built against, and `SESSION_REVOKED` stays the one coded
  401 on the refresh path.
- **BREAKING — `POST /auth/logout` never fails.** It revokes best-effort,
  expires every cookie variant and answers `200 {"success": true}` even with no
  token at all. It used to answer `400` without one. Revocation goes through the
  new `(*Auth).LogoutRequest`, which tries the refresh token from the body or
  cookie first and then falls back to the access-token cookie — the credential
  the reference logout reads. The fallback is not optional: the refresh cookie is
  scoped to `<prefix>/refresh` in every configuration whose name does not resolve
  to `__Host-`, so a browser sends nothing to `<prefix>/logout` and a
  refresh-token-only logout silently leaves the session live server-side.
- **BREAKING — `POST /auth/refresh` accepts an empty body in cookie mode** and
  answers `401 {"error": "No refresh token provided"}` (was `400`) when no token
  is present anywhere. The body is read first, the cookie second.
- **BREAKING — `CSRFMiddleware` now takes an `HTTPConfig`** and
  `DefaultCSRFConfig` takes no arguments; the cookie attributes moved into
  `HTTPConfig.Cookies`. Enforcement follows the reference matrix: only
  cookie-authenticated unsafe methods on routes that sit behind the auth
  middleware. `logout` is exempt — the reference deliberately leaves it
  unprotected — as are bearer requests and safe methods. Rejection is
  `403 {"error": "CSRF token validation failed", "code": "CSRF_INVALID"}`.
  The exemption table is the contract for every route added later and is pinned
  route by route against the reference: `/2fa/verify` and
  `/change-email/confirm` are exempt (neither has an auth gate), while
  `/link-request` is **not** — it is the one unauthenticated route the reference
  CSRF-checks, via a manual double-submit inside the handler. The mount prefix is
  now located anywhere on a segment boundary in the request path, so an adapter
  mounted on a gin/echo group or a chi `Route` (URL `<base><prefix>/<route>`) is
  still enforced instead of silently unprotected.

  "Cookie-authenticated" is literal: a mutating request that carries no
  `accessToken` cookie is passed through to the access-token gate, which answers
  `403 {"error": "No access token provided"}` with **no** `code`. That is the
  reference's ordering — it extracts the token first and only then reaches its
  CSRF branch (`auth.middleware.ts:29-42`) — and it is what a client with neither
  credential now sees, where an earlier revision of this port answered
  `CSRF_INVALID`. `POST /auth/link-request` is the exception: it has no auth gate
  behind it, so it stays enforced with no credential at all, mirroring the
  reference's hand-written check (`auth.router.ts:1489-1495`). Without that carve-out
  a pure cross-site form post — no cookies, no `Authorization`, no headers —
  would reach the handler and overwrite an in-flight account-link token.
  One term of that route's reference check is **deliberately not reproduced**: the
  reference gates its manual check on `config.csrf.enabled` alone
  (`auth.router.ts:1489`), with no bearer exemption, so it refuses a
  bearer-authenticated `POST /auth/link-request` that carries no double-submit
  pair; this port exempts a real `Authorization: Bearer` credential there as it
  does everywhere else. `Authorization` is not CORS-safelisted, so no cross-site
  page can set it — the exemption costs no CSRF protection — and the family
  contract records the reference's behaviour as a mismatch that breaks native
  bearer clients. A client that sends the pair is accepted by both.

  The carve-out is matched against **every** reading of where the mount prefix
  sits in the request path, not just the leftmost. The middleware is told the
  prefix but never the base a host mounted it under, so it has to search for it —
  and the search is ambiguous when the base ends in the same segment as the prefix.
  A host that groups its API under `/auth` and keeps the default `/auth` prefix
  serves `/auth/auth/link-request`, which resolves at the leftmost occurrence to
  `/auth/link-request`: in neither route table, so it fell through to the
  cookie test, and a forgery carries no cookie. That combination left
  `POST /link-request` unenforced under a supported mount shape — a cross-site form
  post reached the handler, wrote the account-link token and mailed the address.
  Exemptions are still read from the leftmost occurrence only: path parameters are
  part of the path, so honouring a later one would let
  `DELETE /auth/linked-accounts/auth/login` borrow `/login`'s exemption. The
  remaining cost of a colliding base is over-enforcement, not under-enforcement —
  such a deployment also fails to recognise its own exempt routes, so a browser that
  still holds an access cookie is CSRF-checked on `POST /login`. That is
  pre-existing and fail-closed; giving the middleware the base path is the real fix
  and is an API change.
- **BREAKING — gin and echo now agree with net/http on cookie attributes.** Gin
  used to give the refresh cookie an arbitrary lifetime of ten times the access
  token's; both now write through the same serialiser, so the four adapters emit
  identical bytes.
- The CSRF cookie is distributed by router-level auto-init only, as in the
  reference — a request without a readable one gets a fresh 32-hex-character
  token. Unlike the reference, it is not additionally rotated inside
  login/refresh, which would emit two conflicting `Set-Cookie` headers for the
  same name on a first login. The client-visible behaviour is unchanged.

- **BREAKING — `auth.NewAPIKeyService` now takes the bcrypt cost:**
  `NewAPIKeyService(bcryptCost int)`. `Create` stores a bcrypt hash of the key,
  so it carried the same hardcoded cost as passwords and was equally
  unreachable; an operator raising `Config.BcryptCost` would otherwise still get
  key hashes pinned at 10. Pass `0` for the default — including from a
  verify-only call site, since `Verify` reads the cost out of the stored hash
  and never produces one. Existing keys keep verifying at whatever cost they
  were written with. Callers update as
  `auth.NewAPIKeyService()` → `auth.NewAPIKeyService(0)`.

### Added
- `Config.BcryptCost` and `auth.WithBcryptCost`, closing item 2 of #25. This is
  the port's spelling of the reference's `AuthConfig.bcryptSaltRounds`; "cost" is
  what `x/crypto/bcrypt` calls the parameter. The default is unchanged:
  `DefaultConfig` sets `bcrypt.DefaultCost`, and a zero value means "unset",
  which resolves to `bcrypt.DefaultCost` and never to `bcrypt.MinCost`.
  `Config.validate` rejects anything outside `[bcrypt.MinCost, bcrypt.MaxCost]`,
  and a cost explicitly configured *below* `DefaultCost` is reported once
  through `Config.Logger` at construction — legal, since the test suites need
  it, but never silent.
- `auth.NewWithConfig(cfg Config, opts ...Option)`, closing item 3 and the root
  cause of #25. `New` builds its `Config` internally and the exported `Option`
  set has always been narrower than `Config`, so the individual TTLs and
  `EmailVerificationMode` were unreachable from outside the package. Taking the
  struct fixes that class of gap once and cannot drift as `Config` grows.
  Options still apply on top, so the two styles compose. (Item 1, the single
  signing secret, is untouched and #25 stays open for it.)
- `wire.go`: the shared conventions in the root package (stdlib only) —
  `HTTPConfig`, `CookieOptions`, `HTTPError` and the error catalog,
  `WriteJSON`/`WriteHTTPError`/`WriteSuccess`/`WriteTokens`, `CookieValue`,
  `IsBearerRequest`, `AccessTokenFromRequest`, `RefreshTokenFromRequest`. Routes
  added by later PRs call these rather than re-deriving shapes.
- `MountWithConfig` and `NewWithConfig` on all four adapters, so the mount prefix
  and cookie policy are configurable and identical across frameworks.
- `auth.WithSessionCheckOn`, without which the middleware's `SESSION_REVOKED`
  branch was unreachable through `auth.New`.
- `Service.TokenTTLs`, so cookie lifetimes track token lifetimes instead of
  being hardcoded.
- `adapter/internal/wiretest`: one conformance suite asserting status, exact
  body key set, exact `Set-Cookie` attributes and both delivery modes, run
  against all four adapters.

### Known limitations
- `openapi.go` and the served `ui/auth.js` still describe and consume the
  pre-0.2.0 shapes (`{"tokens": …}`, snake_case request fields). Bringing them
  onto the new contract is follow-up work, tracked with the rest of #22.

## [0.1.0] - 2026-08-02

First tagged release. The repository had never been tagged, so this release
carries everything built so far, including the four fixes below. Earlier work is
listed under "Pre-release baseline" and was only ever available as a pseudo-version.

### Added
- **OAuth 2.0 + Account Linking** (`oauth.go`): `OAuthService`, `GoogleProvider`, `GitHubProvider`, `HandleCallback`, `MemoryLinkedAccounts`, `PendingLinkStore`, `LinkedAccountStore`
- **SSE (Server-Sent Events)** (`sse.go`): `SseHub`, `SseDistributor` interface, `ServeSSE` handler with 30-second keepalive pings
- **Outbound Webhooks** (`webhooks.go`): `WebhookDispatcher`, `VerifyWebhookSignature`, HMAC-SHA256 signed delivery
- **Telemetry** (`telemetry.go`): `TelemetryStore` interface, `MemoryTelemetryStore`, `TelemetryFilter`
- **Mail** (`mailer.go`): `MailerTransport` interface, `HTTPMailerTransport`, `MailTemplater` with built-in English and Italian templates (reset_password, magic_link, verify_email, email_change)
- **OIDC IDP** (`idp.go`): `IDP` with Discovery, JWKS, Authorization, Token, UserInfo endpoints; RS256 JWT signing (stdlib only, no external JWT library)
- **MCP Server** (`mcp.go`): JSON-RPC 2.0 MCP tool server exposing auth operations for AI editors (tools/list, tools/call)
- **OpenAPI 3.0** (`openapi.go`): `GenerateOpenAPISpec` returning a complete spec for all auth endpoints
- **Embedded UI** (`ui.go`, `ui/`): `ServeAdminUI`, `ServeAuthUI`, `ServeAuthJS` backed by `embed.FS`
  - `ui/admin.html` — single-page admin dashboard
  - `ui/auth.html` — login/register/magic-link/TOTP UI
  - `ui/auth.js` — vanilla JS browser SDK (~3KB, no dependencies)
- **Examples**: `examples/chi-postgres/`, `examples/gin-mongodb/`, `examples/echo-sqlite/`
- **Community files**: CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, issue templates, PR template
- **Email verification mode** (`config.go`, `service.go`): `Config.EmailVerificationMode`, one of `none`|`lazy`|`strict`, default `none`. Previously `Register` hardcoded `IsEmailVerified: true`, which made the verification flow a no-op for self-registered users. `none` keeps the old behaviour exactly: `Register` marks the address verified, and `Login` still refuses any address that is unverified for another reason. `lazy` registers unverified and allows login; `strict` registers unverified and refuses login until the address is confirmed. `lazy` is the only mode that relaxes the pre-existing `Login` gate, so an embedder that does not set the field sees no behaviour change.

### Known limitations
- `EmailVerificationMode: strict` gates `Login`, not access as a whole: `Register` still returns a usable token pair, so a caller can hold a session without ever verifying (#21).
- `EmailVerificationMode: strict` is not reachable over HTTP: no adapter route exposes `SendVerificationEmailToken` or `VerifyEmail` (#9).
- `EmailVerificationMode: lazy` has no grace deadline; the Node reference expires it via `emailVerificationDeadline`, and the Go `User` has no such field.

### Changed
- **BREAKING — access and refresh tokens are now standard HS256 JWTs** (`token.go`): tokens are emitted as `base64url(header).base64url(claims).base64url(signature)` with a JOSE header of `{"alg":"HS256","typ":"JWT"}`, replacing the previous two-segment `payload.signature` format. Tokens issued before the upgrade will not validate. The signature is HMAC-SHA256 over the RFC 7515 §5.1 signing input — the ASCII string `base64url(header) + "." + base64url(claims)`, both segments unpadded — so the JOSE header is covered by the signature. Verification enforces an explicit `HS256` allow-list keyed on a strictly-named lowercase `alg` member, so `alg: none`, algorithm-confusion tokens and headers that only spell the member `ALG`/`Alg` are all rejected. Access and refresh tokens now also carry `email`, `role`, `isEmailVerified` and `isTotpEnabled` claims

## Pre-release baseline (never tagged)

### Added
- Core auth service: Register, Login, Refresh, Logout, Me
- Password reset flow: ForgotPassword, ResetPassword, ChangePassword
- Magic Link: SendMagicLink, VerifyMagicLink
- SMS OTP: SendSMSCode, VerifySMSCode
- TOTP 2FA: SetupTOTP, VerifyTOTPSetup, VerifyTOTP, DisableTOTP
- Email verification: SendVerificationEmailToken, VerifyEmail
- Email change: RequestEmailChange, ConfirmEmailChange
- Session management: ListSessions, RevokeSessionByID, CleanupExpiredSessions
- User metadata store and service helpers
- RBAC: CreateRole, AssignRole, UserHasPermission
- Multi-tenancy: CreateTenant, AddUserToTenant
- API Keys: APIKeyService, APIKeyMiddleware
- Event Bus: EventBus, Subscribe, Publish
- HTTP adapters: net/http, Chi, Gin, Echo
- In-memory stores: MemoryUserStore, MemorySessionStore, MemoryMetadataStore, MemoryRolesPermissionsStore, MemoryTenantStore
- Custom token claims via BuildTokenClaims hook
