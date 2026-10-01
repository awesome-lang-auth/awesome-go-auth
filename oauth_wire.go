package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// This file is the OAuth and account-linking half of the family wire contract
// (wire-contract.md §4): the signed `state` codec, PKCE S256, the redirect
// allowlist, and the flow methods the HTTP adapters call. The adapters stay
// thin glue; everything that decides an outcome lives here so that net/http,
// chi, gin and echo cannot answer differently.
//
// Two places deliberately exceed the reference, both because the reference is
// unsafe there and issue #10 asks for the fix:
//
//   - The reference packs {nonce, origin, path} into `state` as plain base64url
//     and validates only the origin on callback; the nonce is generated and
//     never read (wire-contract.md §4, gap 4). Here the payload is HMAC-signed
//     with the configured secret and verified on callback, and with a
//     PendingLinkStore configured the nonce is single-use as well.
//   - The reference sends no PKCE at all. Here the authorization URL always
//     carries code_challenge/code_challenge_method=S256 and the exchange
//     carries the verifier.
//
// The open-redirect hole the reference has when the allowlist is empty
// (wire-contract.md §4: "any origin embedded in the state is accepted") closes
// as a side effect: only this server can mint a state that verifies, and it
// only ever embeds an origin it resolved itself.

// Error codes for this route group. The first five are the reference's own
// literals; OAUTH_STATE_INVALID has no counterpart because the reference never
// rejects a state.
const (
	CodeOAuthStateInvalid      = "OAUTH_STATE_INVALID"
	CodeOAuthTokenExchangeFail = "OAUTH_TOKEN_EXCHANGE_FAILED"
	CodeOAuthProfileFailed     = "OAUTH_PROFILE_FAILED"
	CodeEmailRequired          = "EMAIL_REQUIRED"
	CodeTokenRequired          = "TOKEN_REQUIRED"
	CodeInvalidLinkToken       = "INVALID_LINK_TOKEN"
	CodeLinkTokenExpired       = "LINK_TOKEN_EXPIRED"
	CodeUnauthorized           = "UNAUTHORIZED"

	// CodeOAuthAccountConflict is the reference's own literal, and the only one
	// of these four that reaches a client the reference also sends it to: it
	// travels in the query of the /account-conflict redirect rather than in an
	// error body (auth.router.ts:1346-1355).
	CodeOAuthAccountConflict = "OAUTH_ACCOUNT_CONFLICT"

	// The three provisioning refusals. They have no reference counterpart —
	// the reference has no provisioning at all — and are registered in
	// compatibility.go; none of them can be emitted by a deployment that
	// configures no OAuthProvisioning.
	CodeOAuthEmailNotVerified      = "OAUTH_EMAIL_NOT_VERIFIED"
	CodeOAuthEmailDomainNotAllowed = "OAUTH_EMAIL_DOMAIN_NOT_ALLOWED"
	CodeOAuthUserNotProvisioned    = "OAUTH_USER_NOT_PROVISIONED"
)

// The error catalog for this group. Messages are the reference's strings where
// the reference has one.
var (
	// HTTPErrOAuthState is the fix for #10. It is a 401 with a code because a
	// browser mid-flow has to be able to tell a tampered state from a provider
	// failure, and because the reference's own choice on this route is a JSON
	// error rather than a redirect (wire-contract.md §4, gap 5).
	HTTPErrOAuthState = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid or expired OAuth state", Code: CodeOAuthStateInvalid}

	// Coded, unlike its passwordless sibling. The reference throws AuthError with
	// EMAIL_REQUIRED here (auth.router.ts:1498) but answers uncoded on
	// /magic-link/send (auth.router.ts:1111), so the two are not interchangeable.
	// See HTTPErrPasswordlessEmailRequired.
	HTTPErrLinkEmailRequired  = HTTPError{Status: http.StatusBadRequest, Message: "email is required", Code: CodeEmailRequired}
	HTTPErrTokenRequired      = HTTPError{Status: http.StatusBadRequest, Message: "token is required", Code: CodeTokenRequired}
	HTTPErrInvalidLinkToken   = HTTPError{Status: http.StatusBadRequest, Message: "Invalid account-link token", Code: CodeInvalidLinkToken}
	HTTPErrLinkTokenExpired   = HTTPError{Status: http.StatusBadRequest, Message: "Account-link token has expired", Code: CodeLinkTokenExpired}
	HTTPErrTargetUserNotFound = HTTPError{Status: http.StatusNotFound, Message: "Target user not found", Code: CodeUserNotFound}

	// HTTPErrLinkUnauthorized is the reference's second identity-resolution
	// failure. Its first one ("Authentication required", emitted when no pending
	// link store is configured at all) is unreachable here: this port resolves
	// both the stash and the link-token storage through the same
	// PendingLinkStore, so an absent store answers NOT_IMPLEMENTED before
	// identity resolution is ever attempted.
	HTTPErrLinkUnauthorized = HTTPError{Status: http.StatusUnauthorized, Message: "Authentication required or no pending link found", Code: CodeUnauthorized}

	// The provisioning refusals, all on the callback and all JSON rather than a
	// redirect — the reference's own choice for everything on that route that is
	// not the account conflict (wire-contract.md §4, gap 5). 403 rather than 401:
	// the provider did authenticate somebody, and the deployment will not admit
	// them, so repeating the flow cannot help.
	HTTPErrOAuthEmailNotVerified      = HTTPError{Status: http.StatusForbidden, Message: "OAuth email address is not verified", Code: CodeOAuthEmailNotVerified}
	HTTPErrOAuthEmailDomainNotAllowed = HTTPError{Status: http.StatusForbidden, Message: "OAuth email domain is not allowed", Code: CodeOAuthEmailDomainNotAllowed}
	HTTPErrOAuthUserNotProvisioned    = HTTPError{Status: http.StatusForbidden, Message: "No account is provisioned for this OAuth identity", Code: CodeOAuthUserNotProvisioned}
)

// Flow sentinels. They stay unexported: the exported surface a caller needs is
// OAuthHTTPError, and errors.go's sentinel list is pinned by
// TestUnmappedSentinelsAreDeliberate against HTTPErrorFor, which does not and
// must not know about these route-specific literals.
var (
	errOAuthStateInvalid  = errors.New("auth: oauth state is invalid, expired or already used")
	errOAuthTokenExchange = errors.New("auth: oauth token exchange failed")
	errOAuthProfile       = errors.New("auth: oauth profile request failed")
	errStoreNotConfigured = errors.New("auth: required oauth store is not configured")
	errEmailRequired      = errors.New("auth: email is required")
	errTokenRequired      = errors.New("auth: token is required")
	errLinkTokenInvalid   = errors.New("auth: account-link token is invalid")
	errLinkTokenExpired   = errors.New("auth: account-link token has expired")
	errLinkUnauthorized   = errors.New("auth: authentication required or no pending link found")
	errTargetUserNotFound = errors.New("auth: target user not found")

	// The provisioning refusals (oauth_provisioning.go). errOAuthUserNotProvisioned
	// answers both halves of "this deployment will not provision this identity":
	// AutoCreate false, and OnEmailMatch reject.
	errOAuthEmailNotVerified      = errors.New("auth: oauth email address is not verified")
	errOAuthEmailDomainNotAllowed = errors.New("auth: oauth email domain is not allowed")
	errOAuthUserNotProvisioned    = errors.New("auth: no account is provisioned for this oauth identity")
)

// oauthNotConfiguredError names the provider so the 404 stub can carry the
// reference's per-provider message.
type oauthNotConfiguredError struct{ provider string }

func (e oauthNotConfiguredError) Error() string {
	return fmt.Sprintf("auth: oauth provider %q is not configured", e.provider)
}

// OAuthNotConfiguredError is the "<Provider> OAuth not configured" stub as an
// error, so an adapter can answer it without reaching into the flow methods.
func OAuthNotConfiguredError(provider string) error {
	return oauthNotConfiguredError{provider: provider}
}

// providerLabel renders a provider name the way the reference's 404 stubs do.
// Google and GitHub are the two the reference hard-codes; anything else keeps
// the registered name.
func providerLabel(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "google":
		return "Google"
	case "github":
		return "GitHub"
	default:
		return provider
	}
}

// OAuthHTTPError maps a flow failure from this file onto the wire envelope.
// Routes call it instead of WriteServiceError because every literal here is
// route-specific: HTTPErrorFor would turn each of them into a 500.
//
// *OAuthAccountConflictError is deliberately absent: the reference answers that
// one with a 302 to /account-conflict, not with an error body
// (auth.router.ts:1346-1355), so the callback handles it before it gets here
// and anything else that reaches this function with it has lost the redirect.
func OAuthHTTPError(err error) HTTPError {
	var notConfigured oauthNotConfiguredError
	switch {
	case err == nil:
		return HTTPError{}
	case errors.As(err, &notConfigured):
		// 404 with no code, as the reference's absent-strategy stubs emit.
		return HTTPError{Status: http.StatusNotFound, Message: providerLabel(notConfigured.provider) + " OAuth not configured"}
	case errors.Is(err, errOAuthStateInvalid):
		return HTTPErrOAuthState
	case errors.Is(err, errOAuthTokenExchange):
		return HTTPError{Status: http.StatusUnauthorized, Message: "OAuth token exchange failed", Code: CodeOAuthTokenExchangeFail}
	case errors.Is(err, errOAuthProfile):
		return HTTPError{Status: http.StatusUnauthorized, Message: "Failed to get OAuth user profile", Code: CodeOAuthProfileFailed}
	case errors.Is(err, errStoreNotConfigured):
		return HTTPErrNotImplemented
	case errors.Is(err, errEmailRequired):
		return HTTPErrLinkEmailRequired
	case errors.Is(err, errTokenRequired):
		return HTTPErrTokenRequired
	case errors.Is(err, errLinkTokenInvalid):
		return HTTPErrInvalidLinkToken
	case errors.Is(err, errLinkTokenExpired):
		return HTTPErrLinkTokenExpired
	case errors.Is(err, errLinkUnauthorized):
		return HTTPErrLinkUnauthorized
	case errors.Is(err, errTargetUserNotFound):
		return HTTPErrTargetUserNotFound
	case errors.Is(err, errOAuthEmailNotVerified):
		return HTTPErrOAuthEmailNotVerified
	case errors.Is(err, errOAuthEmailDomainNotAllowed):
		return HTTPErrOAuthEmailDomainNotAllowed
	case errors.Is(err, errOAuthUserNotProvisioned):
		return HTTPErrOAuthUserNotProvisioned
	default:
		return HTTPErrorFor(err)
	}
}

// ── wiring ───────────────────────────────────────────────────────────────────

// OAuthWiring is everything the OAuth and account-linking routes need beyond
// the core service. The reference gates each route on the presence of the
// corresponding option; the equivalent here is that an absent member turns its
// routes into NOT_IMPLEMENTED rather than leaving them unmounted, because a
// single dynamic /oauth/{provider} route cannot be registered per provider.
type OAuthWiring struct {
	// Service resolves providers, builds authorization URLs and exchanges codes.
	Service *OAuthService
	// LinkedAccounts persists the provider ↔ user associations the
	// /linked-accounts routes read and write.
	LinkedAccounts LinkedAccountStore
	// PendingLinks is the stash. It carries two kinds of entry, both keyed by an
	// opaque string and both single-use: the in-flight OAuth state (so a nonce
	// cannot be replayed) and the account-link token issued by /link-request.
	PendingLinks PendingLinkStore
	// AllowedOrigins is the port's spelling of the reference's cors.origins for
	// origin resolution: together with Config.SiteURLs — the two lists merged in
	// that order and deduplicated, as buildAllowedOrigins does
	// (auth.router.ts:213-219) — it is the allowlist an initiating request's
	// Origin or Referer is matched against, and the allowlist a state's origin
	// has to be in to be redirected to. It is the same list Auth.ResolveSiteURL
	// uses for emailed links. An empty merged allowlist accepts the origin
	// embedded in the state, matching the reference — safe here only because
	// the state is signed.
	AllowedOrigins []string
	// SiteURL is the fallback redirect target, the reference's first
	// config.email.siteUrl entry. It predates Config.SiteURLs and stays as the
	// override: when set it is the default site URL for the OAuth routes and for
	// Auth.ResolveSiteURL alike; when empty the first Config.SiteURLs entry is.
	// A deployment configuring only SiteURLs may leave it unset.
	SiteURL string
	// TenantID scopes users created or resolved by the callback.
	TenantID string
	// Provisioning is the policy the callback resolves an identity under — the
	// declarative stand-in for the abstract findOrCreateUser the reference makes
	// every integrator write (generic-oauth.strategy.ts:169-172). It is a
	// pointer so that nil means DefaultOAuthProvisioning: a deployment that
	// leaves it unset creates missing accounts and answers an address another
	// account already holds with the reference's account conflict, never a
	// link (it linked through 0.12.0, issue #36), and one that sets it is taken
	// at its word, AutoCreate false included. WithOAuth
	// validates it, so an unknown OnEmailMatch or a FieldMap that does not
	// compile fails at construction.
	Provisioning *OAuthProvisioning
	// StateTTL bounds how long a signed state stays acceptable. Default 10m.
	StateTTL time.Duration
	// LinkTokenTTL bounds the /link-request token. Default 1h, as the reference.
	LinkTokenTTL time.Duration
	// DeliverLinkToken hands the /link-request verification link to the host's
	// mail transport. The route answers success either way, as the reference
	// does when no transport is configured.
	DeliverLinkToken func(ctx context.Context, delivery LinkTokenDelivery) error
}

// LinkTokenDelivery is the payload handed to OAuthWiring.DeliverLinkToken. The
// four members are the reference's sendVerificationEmail(email, token, link,
// emailLang) arguments, plus the provider the link records.
type LinkTokenDelivery struct {
	Email    string
	Provider string
	Token    string
	URL      string
	// EmailLang is the /link-request body's emailLang, passed through untouched so
	// the host's mail transport can localise. Empty when the caller omitted it.
	EmailLang string
}

func (w *OAuthWiring) stateTTL() time.Duration {
	if w.StateTTL > 0 {
		return w.StateTTL
	}
	return 10 * time.Minute
}

func (w *OAuthWiring) linkTokenTTL() time.Duration {
	if w.LinkTokenTTL > 0 {
		return w.LinkTokenTTL
	}
	return time.Hour
}

// provisioning is the policy this wiring resolves callbacks under: the one it
// carries, or the default when it carries none.
func (w *OAuthWiring) provisioning() OAuthProvisioning {
	if w.Provisioning == nil {
		return DefaultOAuthProvisioning()
	}
	return w.Provisioning.normalized()
}

// WithOAuth wires the OAuth service and the linking stores.
//
// A Provisioning policy is validated here, so a deployment whose configuration
// names an unknown OnEmailMatch mode or a FieldMap target that does not exist
// fails at construction rather than at the first login.
func WithOAuth(wiring OAuthWiring) Option {
	return func(b *authBuilder) error {
		clone := wiring
		if wiring.Provisioning != nil {
			if err := wiring.Provisioning.Validate(); err != nil {
				return err
			}
			// The struct is copied so that a caller which goes on editing the
			// policy it passed in cannot change how callbacks resolve; the slice
			// and the map inside it are shared, as every other member of the
			// wiring is.
			policy := *wiring.Provisioning
			clone.Provisioning = &policy
		}
		b.oauth = &clone
		return nil
	}
}

// OAuthConfigured reports whether the OAuth routes have anything to serve. The
// adapters mount the routes unconditionally, so they need this to answer the
// reference's "not configured" stub.
func (a *Auth) OAuthConfigured() bool {
	return a.oauth != nil && a.oauth.Service != nil
}

// Has reports whether a provider is registered.
func (s *OAuthService) Has(name string) bool {
	if s == nil {
		return false
	}
	_, ok := s.providers[name]
	return ok
}

func (a *Auth) requireProvider(provider string) (*OAuthWiring, error) {
	if !a.OAuthConfigured() || !a.oauth.Service.Has(provider) {
		return nil, oauthNotConfiguredError{provider: provider}
	}
	return a.oauth, nil
}

// ── signed state ─────────────────────────────────────────────────────────────

// oauthState is the reference's state payload ({n, o, p}) plus an issued-at.
// The field names are the reference's so that a client or proxy that already
// decodes the payload keeps working; the signature is appended after a dot,
// which a base64url payload can never contain.
type oauthState struct {
	N string `json:"n"`
	O string `json:"o,omitempty"`
	P string `json:"p,omitempty"`
	T int64  `json:"t"`
}

func encodeOAuthState(state oauthState, secret string) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("auth: encode oauth state: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + sign(encoded, secret), nil
}

// decodeOAuthState verifies the signature before it parses anything, so a
// forged payload never reaches the JSON decoder.
func decodeOAuthState(raw, secret string, ttl time.Duration) (oauthState, error) {
	encoded, signature, found := strings.Cut(strings.TrimSpace(raw), ".")
	if !found || encoded == "" || signature == "" {
		return oauthState{}, errOAuthStateInvalid
	}
	if !secureEqual(signature, sign(encoded, secret)) {
		return oauthState{}, errOAuthStateInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return oauthState{}, errOAuthStateInvalid
	}
	var state oauthState
	if err := json.Unmarshal(payload, &state); err != nil || state.N == "" {
		return oauthState{}, errOAuthStateInvalid
	}
	if ttl > 0 {
		issued := time.Unix(state.T, 0)
		if state.T == 0 || time.Since(issued) > ttl || time.Until(issued) > time.Minute {
			return oauthState{}, errOAuthStateInvalid
		}
	}
	return state, nil
}

// ── PKCE ─────────────────────────────────────────────────────────────────────

// pkceVerifier derives the RFC 7636 code_verifier from the state nonce instead
// of storing it. The derivation needs the signing secret, so an attacker who
// intercepts the authorization request — which carries the nonce and the
// challenge, both public by design — still cannot produce the verifier. That
// keeps PKCE working for embedders who configure no PendingLinkStore.
//
// 32 HMAC bytes render as 43 base64url characters, exactly the RFC minimum.
func pkceVerifier(secret, nonce string) string {
	return sign("pkce\x00"+nonce, secret)
}

func pkceChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ── redirect resolution ──────────────────────────────────────────────────────

// resolveSiteURL is the reference's initiation-time origin resolution
// (resolveSiteUrl, auth.router.ts:233-246): match the Origin header against the
// allowlist, then the origin of the Referer, otherwise fall back to the
// configured site URL. The OAuth routes call it with the same allowlist and
// default Auth.ResolveSiteURL uses for emailed links (wire.go), which is how
// the reference arranges it too — one allowedOrigins, one getDefaultSiteUrl.
func resolveSiteURL(origin, referer string, allowed []string, siteURL string) string {
	if len(allowed) > 0 {
		if candidate := strings.TrimSpace(origin); originAllowed(candidate, allowed) {
			return candidate
		}
		if u, err := url.Parse(strings.TrimSpace(referer)); err == nil && u.Scheme != "" && u.Host != "" {
			if candidate := u.Scheme + "://" + u.Host; originAllowed(candidate, allowed) {
				return candidate
			}
		}
	}
	return siteURL
}

// resolveOAuthRedirect is a line-by-line transcription of the reference's
// resolveOAuthRedirect (auth.router.ts:325-351): honour the state's origin when
// the allowlist permits it (an empty allowlist permits everything), append the
// return path, and fall back to the configured site URL.
//
// Three properties of the reference look wrong and are reproduced anyway,
// because three shipped clients are built against this function's output:
//
//   - The return path is honoured ONLY in the accepted-origin branch. The
//     reference appends `p` inside `if (fromState && allowed)` and returns
//     getDefaultSiteUrl(config) bare otherwise, so a state whose origin was
//     rejected contributes nothing at all — not the origin and not the path.
//     `p` comes straight from the caller's `return_path` query param, so
//     appending it to the fallback would let an initiator inject a path into a
//     redirect the allowlist had already refused to trust.
//   - The base-path de-duplication triggers on a LOOSE prefix test
//     (`cleanPath.startsWith(basePath)`, no segment boundary) and, when it
//     triggers, drops the origin's base path entirely in favour of the return
//     path: origin https://ex.com/ex with p=/example resolves to
//     https://ex.com/example, not https://ex.com/ex/example. A segment-boundary
//     test would be tidier and would disagree with the reference on exactly
//     that input.
//   - An origin with a trailing slash is concatenated as-is, so
//     https://ex.com/ + /dash resolves to https://ex.com//dash. The reference
//     only strips the trailing slash inside the de-duplication branch, which
//     that input does not reach (basePath becomes "" and is falsy).
func resolveOAuthRedirect(state oauthState, allowed []string, siteURL string) string {
	fromState := state.O
	if fromState == "" || !originAllowed(fromState, allowed) {
		// getDefaultSiteUrl(config), bare.
		return siteURL
	}
	if state.P == "" {
		return fromState
	}
	cleanPath := state.P
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}
	// `new URL(fromState)` in a try/catch: url.Parse accepts almost anything, so
	// the scheme and host checks stand in for the throw.
	if u, err := url.Parse(fromState); err == nil && u.Scheme != "" && u.Host != "" {
		basePath := strings.TrimSuffix(u.Path, "/")
		if basePath != "" && basePath != "/" && strings.HasPrefix(cleanPath, basePath) {
			return u.Scheme + "://" + u.Host + cleanPath
		}
	}
	return fromState + cleanPath
}

// resolveOAuthConflictOrigin is the reference's conflictOrigin: the state's
// origin when the allowlist admits it (an empty allowlist admits any), the
// default site URL otherwise — and, unlike resolveOAuthRedirect, never the
// state's return path (node-auth auth.router.ts:1992-1995 at 1.10.8, repeated
// at :2072-2075 and :2154-2157). The conflict page lives under the API prefix
// on the site's root, wherever the login was meant to land afterwards.
func resolveOAuthConflictOrigin(state oauthState, allowed []string, siteURL string) string {
	if originAllowed(state.O, allowed) {
		return state.O
	}
	return siteURL
}

// originAllowed mirrors the reference: an empty allowlist allows everything, and
// a non-empty one is an exact `allowedOrigins.includes(origin)` — no trailing
// slash normalisation, no case folding.
func originAllowed(origin string, allowed []string) bool {
	if origin == "" {
		return false
	}
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if candidate == origin {
			return true
		}
	}
	return false
}

// ── stash keys ───────────────────────────────────────────────────────────────

// oauthStateKey namespaces the in-flight state entries. The nonce is the key
// material and is not secret, but keeping the two entry kinds in disjoint
// namespaces stops a link token from ever being read as a state.
func oauthStateKey(nonce string) string { return "oauth-state:" + nonce }

// linkTokenKey stores the hash, never the token: the stash must not hold a
// credential that would let its reader complete somebody else's link.
func linkTokenKey(token string) string { return "link-token:" + hashToken(token) }

// pendingLinkKey is the reference's conflict stash key — (email, provider).
func pendingLinkKey(email, provider string) string {
	return "pending-link:" + normalizeEmail(email) + "|" + strings.ToLower(strings.TrimSpace(provider))
}

// ── begin ────────────────────────────────────────────────────────────────────

// OAuthBeginInput is GET <prefix>/oauth/{provider}.
//
// There is deliberately no "link to the caller's account" field. The reference's
// /oauth/{provider} has no auth gate and reads no credential (wire-contract.md
// §4: "Auth gate: none"); the intent is not carried in the state either, and the
// callback resolves the identity purely through the provider account. Reading the
// initiating request's access token and linking the provider identity to it is an
// account-takeover shape: whoever happened to be signed in when the flow started
// would get the session, and the (provider, providerAccountId) binding would be
// re-pointed at them. Linking an existing account to a provider goes through
// /link-request and /link-verify, where an emailed token proves the address.
type OAuthBeginInput struct {
	Provider   string
	ReturnPath string
	Origin     string
	Referer    string
}

// OAuthBeginResult is what the route redirects to.
type OAuthBeginResult struct {
	AuthorizationURL string
	State            string
}

// OAuthBegin mints a signed state, derives the PKCE challenge and builds the
// provider authorization URL.
func (a *Auth) OAuthBegin(ctx context.Context, in OAuthBeginInput) (OAuthBeginResult, error) {
	wiring, err := a.requireProvider(in.Provider)
	if err != nil {
		return OAuthBeginResult{}, err
	}
	// 16 random bytes as 32 hex characters, the reference's nonce size.
	nonce, err := randomHex(16)
	if err != nil {
		return OAuthBeginResult{}, err
	}
	secret := a.service.cfg.Secret
	origin := resolveSiteURL(in.Origin, in.Referer, a.allowedOrigins(), a.defaultSiteURL())
	state, err := encodeOAuthState(oauthState{
		N: nonce,
		O: origin,
		P: in.ReturnPath,
		T: time.Now().Unix(),
	}, secret)
	if err != nil {
		return OAuthBeginResult{}, err
	}
	authorizationURL, err := wiring.Service.AuthorizeURLPKCE(in.Provider, state, pkceChallengeS256(pkceVerifier(secret, nonce)))
	if err != nil {
		return OAuthBeginResult{}, err
	}
	if wiring.PendingLinks != nil {
		// Recording the nonce is what makes it single-use on callback. Without a
		// stash the state is still signed and time-bounded, just replayable
		// inside its TTL.
		if err := wiring.PendingLinks.Save(ctx, oauthStateKey(nonce), OAuthPendingMeta{
			Provider:    in.Provider,
			RedirectURL: origin,
			TenantID:    wiring.TenantID,
			ExpiresAt:   time.Now().Add(wiring.stateTTL()),
		}, wiring.stateTTL()); err != nil {
			return OAuthBeginResult{}, err
		}
	}
	return OAuthBeginResult{AuthorizationURL: authorizationURL, State: state}, nil
}

// ── complete ─────────────────────────────────────────────────────────────────

// OAuthCompleteInput is GET <prefix>/oauth/{provider}/callback.
type OAuthCompleteInput struct {
	Provider string
	Code     string
	State    string
}

// OAuthCompleteResult carries the issued session and where to send the browser.
type OAuthCompleteResult struct {
	User   User
	Tokens AuthTokens
	// RedirectTo is where a successful callback sends the browser: the
	// reference's resolveOAuthRedirect, the state's origin with its return path
	// appended (node-auth auth.router.ts:671 at 1.10.8).
	RedirectTo string
	// ConflictOrigin is the site URL an account conflict's redirect is built on
	// (AccountConflictLink). It is not RedirectTo: the reference's conflict
	// branch takes the state's bare origin when the allowlist admits it and the
	// default site URL otherwise, and never appends the return path
	// (node-auth auth.router.ts:1992-1995, :2072-2075, :2154-2157 at 1.10.8).
	// It is set on every result whose state verified, conflict or not.
	ConflictOrigin string
}

// OAuthComplete verifies the state, exchanges the code with the PKCE verifier
// and resolves the user.
func (a *Auth) OAuthComplete(ctx context.Context, in OAuthCompleteInput) (OAuthCompleteResult, error) {
	wiring, err := a.requireProvider(in.Provider)
	if err != nil {
		return OAuthCompleteResult{}, err
	}
	if wiring.LinkedAccounts == nil {
		return OAuthCompleteResult{}, errStoreNotConfigured
	}
	secret := a.service.cfg.Secret
	state, err := decodeOAuthState(in.State, secret, wiring.stateTTL())
	if err != nil {
		return OAuthCompleteResult{}, err
	}

	meta := OAuthPendingMeta{TenantID: wiring.TenantID}
	if wiring.PendingLinks != nil {
		stashed, err := wiring.PendingLinks.Get(ctx, oauthStateKey(state.N))
		if err != nil {
			// Unknown or already-consumed nonce. This is the replay defence the
			// reference does not have.
			return OAuthCompleteResult{}, errOAuthStateInvalid
		}
		if stashed.Provider != "" && stashed.Provider != in.Provider {
			// A state minted for one provider must not complete another.
			return OAuthCompleteResult{}, errOAuthStateInvalid
		}
		_ = wiring.PendingLinks.Delete(ctx, oauthStateKey(state.N))
		meta = stashed
		if meta.TenantID == "" {
			meta.TenantID = wiring.TenantID
		}
	}

	redirectTo := resolveOAuthRedirect(state, a.allowedOrigins(), a.defaultSiteURL())
	conflictOrigin := resolveOAuthConflictOrigin(state, a.allowedOrigins(), a.defaultSiteURL())
	info, err := wiring.Service.ExchangeCodePKCE(ctx, in.Provider, in.Code, pkceVerifier(secret, state.N))
	if err != nil {
		return OAuthCompleteResult{RedirectTo: redirectTo, ConflictOrigin: conflictOrigin}, err
	}
	// linkToUserID is deliberately empty: the callback resolves the identity
	// through the provider account, exactly as the reference does. Nothing on the
	// initiating request may influence which account the provider identity lands
	// on — see OAuthBeginInput.
	user, tokens, err := wiring.Service.HandleCallbackWithPolicy(ctx, a.service, wiring.LinkedAccounts, info, meta.TenantID, "", wiring.provisioning())
	if err != nil {
		// Before the stash, as in the dev line, whose catch publishes and then
		// stashes and then redirects (node-auth auth.router.ts:1480 precedes
		// :1486-1488). Nothing downstream depends on the order; keeping it means
		// a subscriber and the pending-link store see the conflict in the same
		// sequence in both trees.
		a.publishOAuthConflict(ctx, in.Provider, err)
		a.stashAccountConflict(ctx, wiring, in.Provider, meta.TenantID, err)
		return OAuthCompleteResult{RedirectTo: redirectTo, ConflictOrigin: conflictOrigin}, err
	}
	// node-auth auth.router.ts:1444, the publish at the end of handleOAuthLogin
	// — one site there serving three callback routes, and one here serving every
	// configured provider. It is a separate name from identity.auth.login.success
	// although an OAuth callback is a login, and it is raised only on the path
	// that issues tokens: a callback that diverts to the 2FA page returns before
	// it (node-auth auth.router.ts:1441).
	//
	// `provider` is the dev line's `user.loginProvider ?? 'oauth'`, read against
	// what the callback route does to the user just before it calls
	// handleOAuthLogin: `user.loginProvider = user.loginProvider ?? <name>`
	// (node-auth auth.router.ts:1476, :1526, :1576). So the value is the
	// provider recorded on the account when there is one and the provider that
	// served this callback otherwise, and the literal 'oauth' is unreachable in
	// both trees. The fallback is deliberately in.Provider and not
	// User.loginProviderOrLocal, which would answer "local" — the one value this
	// key must never carry.
	a.service.publish(ctx, func() Event {
		provider := user.LoginProvider
		if provider == "" {
			provider = in.Provider
		}
		return Event{
			Name:      EventAuthOAuthSuccess,
			UserID:    user.ID,
			SessionID: a.service.sessionIDOf(tokens),
			Data:      map[string]any{"provider": provider, "redirectTo": redirectTo},
		}
	})
	return OAuthCompleteResult{User: user, Tokens: tokens, RedirectTo: redirectTo, ConflictOrigin: conflictOrigin}, nil
}

// publishOAuthConflict raises identity.auth.oauth.conflict for a callback that
// ended in an account conflict: node-auth auth.router.ts:1480, :1530 and :1580.
//
// Three publication points there and one here, and the reason is the shape of
// the two routers rather than a decision. The dev line writes the Google, the
// GitHub and the generic callback as three separate handlers with three copies
// of the same catch, each naming its provider as a literal; this port has one
// OAuthComplete that every provider reaches, and the literal is in.Provider.
// All three dev line payloads are the same three keys.
//
// It is the one reachable name raised on a path that ends in a redirect rather
// than a JSON body, and the one that carries no user id — there is no user yet,
// which is the whole content of a conflict. The two remaining keys are the
// spread of the AuthError's own data (node-auth auth.router.ts:1481); this
// port's OAuthAccountConflictError carries exactly those two fields, and
// populates both whenever it is constructed at all (oauth.go:683), so they are
// written unconditionally rather than omitted when empty.
//
// The address is cut to 320 UTF-16 code units, as the reference's
// oauthConflictEventData does through eventEmail (router-events.ts:13, :46-48,
// :54-67 at 1.10.8). It comes from the provider rather than from a request
// body, so the cap is reached only by a provider asserting a pathological
// address, but the payload is the reference's whatever the address.
//
// A non-conflict failure publishes nothing. The dev line's catch tests the
// error code before it publishes, so a provider that returned a 500, a state
// that did not verify and a refusal from the provisioning policy all pass
// through silently.
func (a *Auth) publishOAuthConflict(ctx context.Context, provider string, err error) {
	var conflict *OAuthAccountConflictError
	if !errors.As(err, &conflict) {
		return
	}
	a.service.publish(ctx, func() Event {
		return Event{
			Name: EventAuthOAuthConflict,
			Data: map[string]any{
				"provider":          provider,
				"email":             eventEmail(conflict.Email),
				"providerAccountId": conflict.ProviderAccountID,
			},
		}
	})
}

// stashAccountConflict parks an account conflict for the link flow to pick up,
// the way the reference's pendingLinkStore.stash(email, provider,
// providerAccountId) does (auth.router.ts:1349-1351). Like the reference it is
// best effort and conditional on the same three things — a store, an address
// and a provider account — because the redirect is sent either way; a front-end
// that lands on /account-conflict with nothing stashed simply finds
// /link-request unwilling to resolve an identity.
//
// The entry is the one the conflict flow already reads (LinkRequest), under the
// key it already uses. It is also the first thing in this port to write that
// namespace, which makes the tenant term real: the key has no tenant segment
// (reference-issues G18), so the entry carries the tenant the callback
// resolved and LinkRequest takes the tenant from the entry. Two tenants holding
// one address therefore share one stash slot — the reference's shape,
// reproduced, and the reason a multi-tenant deployment should not leave the
// conflict flow enabled across tenants that share addresses.
func (a *Auth) stashAccountConflict(ctx context.Context, wiring *OAuthWiring, provider, tenantID string, err error) {
	var conflict *OAuthAccountConflictError
	if !errors.As(err, &conflict) || wiring.PendingLinks == nil {
		return
	}
	if conflict.Email == "" || conflict.ProviderAccountID == "" {
		return
	}
	ttl := wiring.linkTokenTTL()
	if saveErr := wiring.PendingLinks.Save(ctx, pendingLinkKey(conflict.Email, provider), OAuthPendingMeta{
		Provider:          provider,
		TenantID:          tenantID,
		Email:             normalizeEmail(conflict.Email),
		ProviderAccountID: conflict.ProviderAccountID,
		ExpiresAt:         time.Now().Add(ttl),
	}, ttl); saveErr != nil {
		// console.error in the reference, which redirects regardless.
		a.service.logf("auth: oauth conflict stash failed for provider %q: %v", provider, saveErr)
	}
}

// AccountConflictLink is the Location the callback answers an account conflict
// with: the reference's buildUiLink(conflictOrigin, "/account-conflict?…")
// (auth.router.ts:365-375, :2000-2002 at 1.10.8). siteURL is
// OAuthCompleteResult.ConflictOrigin — the state's bare origin or the default
// site URL, never the return path the success redirect appends — and the query
// is the reference's literal one, provider first, then code, then the address
// when there is one.
//
// Both values are escaped as JavaScript's encodeURIComponent escapes them
// (escapeURIComponent), so the Location is the reference's byte for byte: an
// apostrophe, which an address's local part may hold, stays bare, and a space
// is %20 rather than url.QueryEscape's +.
func (c HTTPConfig) AccountConflictLink(siteURL, provider, email string) string {
	path := "/account-conflict?provider=" + escapeURIComponent(provider) + "&code=" + CodeOAuthAccountConflict
	if email != "" {
		path += "&email=" + escapeURIComponent(email)
	}
	return c.UILink(siteURL, path)
}

// ── linked accounts ──────────────────────────────────────────────────────────

// PublicLinkedAccount is the wire projection of a linked account. The field
// names and their optionality are the reference's LinkedAccount interface
// (linked-accounts-store.interface.ts:4-17), which is what the Angular client,
// the served auth.js and the family admin UI read.
//
// Email is populated by every link the library writes, because the reference's
// linkAccount calls always pass `email: user.email` from the callback profile
// (auth.router.ts:1336-1343, :1578-1583). Name and Picture are optional in the
// reference's interface and its own linkAccount calls never set them, so they
// only ever appear when a host-supplied LinkedAccountStore fills them in; the
// admin UI's `a.name || a.email || a.providerAccountId` therefore falls through
// to the email, as it does against the reference.
type PublicLinkedAccount struct {
	Provider          string    `json:"provider"`
	ProviderAccountID string    `json:"providerAccountId"`
	Email             string    `json:"email,omitempty"`
	Name              string    `json:"name,omitempty"`
	Picture           string    `json:"picture,omitempty"`
	LinkedAt          time.Time `json:"linkedAt"`
}

// ListLinkedAccounts returns a user's provider associations, always as a
// non-nil slice so the JSON is [] rather than null.
func (a *Auth) ListLinkedAccounts(ctx context.Context, userID string) ([]PublicLinkedAccount, error) {
	if a.oauth == nil || a.oauth.LinkedAccounts == nil {
		return nil, errStoreNotConfigured
	}
	links, err := a.oauth.LinkedAccounts.ListForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]PublicLinkedAccount, 0, len(links))
	for _, link := range links {
		out = append(out, PublicLinkedAccount{
			Provider:          link.Provider,
			ProviderAccountID: link.ProviderID,
			Email:             link.Email,
			Name:              link.Name,
			Picture:           link.Picture,
			LinkedAt:          link.CreatedAt,
		})
	}
	return out, nil
}

// UnlinkAccount removes one provider association.
//
// The reference performs no existence check and answers success unconditionally
// (wire-contract.md §4, DELETE /linked-accounts). This keeps that, and adds the
// ownership check the reference gets for free by passing the user id into its
// store: a link that belongs to somebody else is left alone.
func (a *Auth) UnlinkAccount(ctx context.Context, userID, provider, providerAccountID string) error {
	if a.oauth == nil || a.oauth.LinkedAccounts == nil {
		return errStoreNotConfigured
	}
	link, err := a.oauth.LinkedAccounts.FindByProvider(ctx, provider, providerAccountID)
	if err != nil || link.UserID != userID {
		return nil
	}
	return a.oauth.LinkedAccounts.Delete(ctx, link.ID)
}

// ── link-request / link-verify ───────────────────────────────────────────────

// LinkRequestInput is POST <prefix>/link-request.
type LinkRequestInput struct {
	Email    string
	Provider string
	// EmailLang is the reference's third body field. It selects the language of
	// the verification mail and is forwarded verbatim to DeliverLinkToken, the way
	// the reference passes it as sendVerificationEmail's fourth argument
	// (auth.router.ts:1530-1535).
	EmailLang   string
	AccessToken string
	// Origin and Referer resolve which origin the verification link points at, as
	// the reference's resolveSiteUrl(req, config, allowedOrigins) does
	// (auth.router.ts:1528). A multi-origin deployment must email a link back to
	// the origin the request came from, not always to the default one.
	Origin  string
	Referer string
	// APIPrefix is the mount prefix, needed to build the verification link.
	APIPrefix string
}

// LinkRequestResult reports what was issued. The token never reaches the HTTP
// response; it is returned so an embedder driving the service directly can send
// it themselves.
type LinkRequestResult struct {
	Token string
	URL   string
}

// LinkRequest issues a single-use account-link token and hands the verification
// link to the configured delivery hook.
func (a *Auth) LinkRequest(ctx context.Context, in LinkRequestInput) (LinkRequestResult, error) {
	if a.oauth == nil || a.oauth.LinkedAccounts == nil || a.oauth.PendingLinks == nil {
		return LinkRequestResult{}, errStoreNotConfigured
	}
	wiring := a.oauth
	email := normalizeEmail(in.Email)
	if email == "" {
		return LinkRequestResult{}, errEmailRequired
	}
	provider := strings.TrimSpace(in.Provider)
	if provider == "" {
		provider = "email"
	}

	// Identity resolution, in the reference's order: a usable access token wins,
	// an unusable one is silently ignored, and the conflict stash is the
	// fallback. Authenticate, not Me: only the identity is read off the user,
	// and the reference reads it off the verified payload without running
	// buildTokenPayload (auth.router.ts:1502-1510), so the claims hook — and a
	// ClaimsWebhook behind it — has no business firing on this route.
	var (
		userID            string
		tenantID          = wiring.TenantID
		providerAccountID string
	)
	if token := strings.TrimSpace(in.AccessToken); token != "" {
		if user, err := a.service.Authenticate(ctx, token); err == nil {
			userID = user.ID
			tenantID = user.TenantID
		}
	}
	if userID == "" {
		stashed, err := wiring.PendingLinks.Get(ctx, pendingLinkKey(email, provider))
		if err != nil {
			return LinkRequestResult{}, errLinkUnauthorized
		}
		providerAccountID = stashed.ProviderAccountID
		if stashed.TenantID != "" {
			tenantID = stashed.TenantID
		}
		user, err := a.service.users.GetUserByEmail(ctx, email, tenantID)
		if err != nil {
			return LinkRequestResult{}, errTargetUserNotFound
		}
		userID = user.ID
	}

	// 32 random bytes as 64 hex characters, the reference's token size.
	token, err := randomHex(32)
	if err != nil {
		return LinkRequestResult{}, err
	}
	ttl := wiring.linkTokenTTL()
	if err := wiring.PendingLinks.Save(ctx, linkTokenKey(token), OAuthPendingMeta{
		Provider:          provider,
		TenantID:          tenantID,
		UserID:            userID,
		Email:             email,
		ProviderAccountID: providerAccountID,
		ExpiresAt:         time.Now().Add(ttl),
	}, ttl); err != nil {
		return LinkRequestResult{}, err
	}

	// The reference resolves the link's origin per request rather than always
	// using the default site url, so a deployment serving several front-ends mails
	// a link back to the one that asked (auth.router.ts:1528).
	siteURL := resolveSiteURL(in.Origin, in.Referer, a.allowedOrigins(), a.defaultSiteURL())
	prefix := strings.TrimSuffix(strings.TrimSpace(in.APIPrefix), "/")
	link := siteURL + prefix + "/link-verify?token=" + url.QueryEscape(token)
	result := LinkRequestResult{Token: token, URL: link}
	if wiring.DeliverLinkToken != nil {
		// Delivery failures do not fail the route: the reference answers success
		// even when no mail transport is configured at all.
		if err := wiring.DeliverLinkToken(ctx, LinkTokenDelivery{
			Email:     email,
			Provider:  provider,
			Token:     token,
			URL:       link,
			EmailLang: in.EmailLang,
		}); err != nil {
			a.service.logf("auth: link token delivery failed for %q: %v", email, err)
		}
	}
	return result, nil
}

// LinkVerifyInput is POST <prefix>/link-verify.
type LinkVerifyInput struct {
	Token             string
	LoginAfterLinking bool
}

// LinkVerifyResult carries the tokens when loginAfterLinking was asked for.
type LinkVerifyResult struct {
	User     User
	Tokens   AuthTokens
	LoggedIn bool
}

// LinkVerify consumes an account-link token and writes the association.
func (a *Auth) LinkVerify(ctx context.Context, in LinkVerifyInput) (LinkVerifyResult, error) {
	if a.oauth == nil || a.oauth.LinkedAccounts == nil || a.oauth.PendingLinks == nil {
		return LinkVerifyResult{}, errStoreNotConfigured
	}
	wiring := a.oauth
	token := strings.TrimSpace(in.Token)
	if token == "" {
		return LinkVerifyResult{}, errTokenRequired
	}
	key := linkTokenKey(token)
	meta, err := wiring.PendingLinks.Get(ctx, key)
	if err != nil {
		return LinkVerifyResult{}, errLinkTokenInvalid
	}
	// Expiry is carried in the entry, not left to the store: a PendingLinkStore
	// that ignores the ttl argument must not turn into an unbounded token.
	if !meta.ExpiresAt.IsZero() && time.Now().After(meta.ExpiresAt) {
		_ = wiring.PendingLinks.Delete(ctx, key)
		return LinkVerifyResult{}, errLinkTokenExpired
	}

	// The reference defaults providerAccountId to the email and overrides it
	// with the stashed OAuth account id when the conflict flow produced one.
	providerAccountID := meta.ProviderAccountID
	if providerAccountID == "" {
		providerAccountID = meta.Email
	}
	linkID, err := newID("lnk")
	if err != nil {
		return LinkVerifyResult{}, err
	}
	// Email is stored, not derived on read: the reference's linkAccount here passes
	// `email` alongside the provider account id (auth.router.ts:1578-1583), and
	// GET /linked-accounts is what renders it.
	if err := wiring.LinkedAccounts.Save(ctx, OAuthLinkedAccount{
		ID:         linkID,
		UserID:     meta.UserID,
		Provider:   meta.Provider,
		ProviderID: providerAccountID,
		Email:      meta.Email,
		CreatedAt:  time.Now(),
	}); err != nil {
		return LinkVerifyResult{}, err
	}
	// Single use: the token dies with the link it created.
	_ = wiring.PendingLinks.Delete(ctx, key)
	_ = wiring.PendingLinks.Delete(ctx, pendingLinkKey(meta.Email, meta.Provider))

	if !in.LoginAfterLinking {
		return LinkVerifyResult{}, nil
	}
	user, tokens, err := a.service.IssueTokensForUser(ctx, meta.UserID, meta.TenantID)
	if err != nil {
		return LinkVerifyResult{}, err
	}
	return LinkVerifyResult{User: user, Tokens: tokens, LoggedIn: true}, nil
}

// IssueTokensForUser starts a session for an identity that has already been
// proven by something other than a password — here, an emailed account-link
// token. It is the one service method this route group needed and the core did
// not have: every other issuance path (Register, Login, VerifyMagicLink,
// VerifySMSCode, VerifyTOTP) reaches newSessionTokens through a credential
// check that does not apply.
func (s *Service) IssueTokensForUser(ctx context.Context, userID, tenantID string) (User, AuthTokens, error) {
	user, err := s.users.GetUserByID(ctx, userID, tenantID)
	if err != nil {
		return User{}, AuthTokens{}, ErrInvalidCredentials
	}
	tokens, err := s.newSessionTokens(ctx, user)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	return user, tokens, nil
}

// IssueTokensForUser delegates to Service.IssueTokensForUser.
func (a *Auth) IssueTokensForUser(ctx context.Context, userID, tenantID string) (User, AuthTokens, error) {
	return a.service.IssueTokensForUser(ctx, userID, tenantID)
}

// ── in-memory stash ──────────────────────────────────────────────────────────

// MemoryPendingLinks is an in-memory PendingLinkStore, the counterpart of
// MemoryLinkedAccounts. It enforces the ttl, which is what makes an OAuth state
// nonce single-use and an account-link token expire.
type MemoryPendingLinks struct {
	mu      sync.Mutex
	entries map[string]memoryPendingEntry
	now     func() time.Time
}

type memoryPendingEntry struct {
	meta      OAuthPendingMeta
	expiresAt time.Time
}

// NewMemoryPendingLinks creates an in-memory PendingLinkStore.
func NewMemoryPendingLinks() *MemoryPendingLinks {
	return &MemoryPendingLinks{entries: make(map[string]memoryPendingEntry), now: time.Now}
}

func (m *MemoryPendingLinks) Save(_ context.Context, key string, meta OAuthPendingMeta, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := memoryPendingEntry{meta: meta}
	if ttl > 0 {
		entry.expiresAt = m.now().Add(ttl)
	}
	m.entries[key] = entry
	return nil
}

func (m *MemoryPendingLinks) Get(_ context.Context, key string) (OAuthPendingMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[key]
	if !ok {
		return OAuthPendingMeta{}, errors.New("auth: pending link not found")
	}
	if !entry.expiresAt.IsZero() && m.now().After(entry.expiresAt) {
		delete(m.entries, key)
		return OAuthPendingMeta{}, errors.New("auth: pending link expired")
	}
	return entry.meta, nil
}

func (m *MemoryPendingLinks) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}

// maxEventEmailLength is the reference's MAX_EVENT_EMAIL_LENGTH
// (router-events.ts:13 at 1.10.8), counted as JavaScript counts a string's
// length: in UTF-16 code units.
const maxEventEmailLength = 320

// eventEmail is the reference's eventEmail for a string: the value cut to
// maxEventEmailLength UTF-16 code units (router-events.ts:46-48). Where the
// cut would fall inside a surrogate pair, JavaScript's slice keeps the lone
// high surrogate, which no Go string can hold; this cuts before the pair
// instead, one code unit shorter.
func eventEmail(email string) string {
	units := 0
	for i, r := range email {
		n := 1
		if r > 0xFFFF {
			n = 2 // a surrogate pair
		}
		if units+n > maxEventEmailLength {
			return email[:i]
		}
		units += n
	}
	return email
}
