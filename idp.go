package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultAuthCodeTTL is how long an authorization code stays redeemable when
// IDPConfig.CodeTTL is unset. Five minutes is the value the process-local map
// hardcoded before the store seam existed, so existing callers see no change.
const defaultAuthCodeTTL = 5 * time.Minute

// DefaultIDPKeyID is the kid the IdP signs with and publishes when
// IDPConfig.KeyID is empty: the constant the reference hardcodes for every
// IdP-issued token and for the JWKS document (token.service.ts:78,
// jwks.service.ts:184).
const DefaultIDPKeyID = "provisioner-key-1"

// DefaultJWKSPath is where the adapters serve the JWKS document, below the
// mount prefix, when IDPConfig.JWKSPath is empty: the reference's
// `idProvider.jwksPath ?? '/.well-known/jwks.json'` (auth.router.ts:475).
const DefaultJWKSPath = "/.well-known/jwks.json"

// The four OIDC endpoints, below the mount prefix. They are constants because
// four places have to spell them identically: RegisterHandlers, the four
// adapters' MountWithConfig, the JWKSPath collision check, and the generated
// OpenAPI document.
//
// Unlike the JWKS route these paths are not configurable. They have no
// counterpart in the reference, which ships no OIDC authorization server, so
// there is nothing to track: the discovery document is the well-known path RFC
// 8414 fixes, and the other three are the names the discovery document this
// package has always served advertises (handleDiscovery below derives them
// from Issuer, so a second spelling would advertise one path and serve
// another).
const (
	OIDCDiscoveryPath = "/.well-known/openid-configuration"
	OIDCAuthorizePath = "/authorize"
	OIDCTokenPath     = "/token"
	OIDCUserInfoPath  = "/userinfo"
)

// jwksCacheControl is the caching directive the reference sets on every JWKS
// response (auth.router.ts:502). A relying party fetches the document once per
// key rotation, not once per token, so an hour of shared caching is what makes
// RS256 verification cheap at the edge.
const jwksCacheControl = "public, max-age=3600"

// jwksWildcardOrigin is the Access-Control-Allow-Origin the reference sends
// when jwksCorsOrigins is absent or is the literal string "*"
// (auth.router.ts:492-494).
const jwksWildcardOrigin = "*"

// The lifetimes of the IdP token pair when IDPConfig leaves them zero: the
// reference's tokenExpiry default of 30d and refreshTokenExpiry default of 90d
// (token.service.ts:80 and :91).
const (
	defaultIDPAccessTokenTTL  = 30 * 24 * time.Hour
	defaultIDPRefreshTokenTTL = 90 * 24 * time.Hour
)

// idpEphemeralKeyWarning is what NewIDP logs, once, when no Signer was
// configured. The sentences are the reference's (token.service.ts:52-57); only
// the two names are this port's.
const idpEphemeralKeyWarning = "auth: IdP mode: no Signer configured — auto-generating an ephemeral RSA keypair. All tokens will be invalidated on restart. Set IDPConfig.Signer in production."

// IDPConfig configures the OIDC Identity Provider.
type IDPConfig struct {
	// Issuer is the iss claim of the ID token and the base of the discovery
	// document. For IssueIdPTokenPair it is optional, as the reference's
	// idProvider.issuer is: left empty, the pair carries no iss claim
	// (token.service.ts:74-77).
	Issuer string
	// AccessTokenTTL is the lifetime of the access token IssueIdPTokenPair
	// mints; zero resolves to 30 days, the reference's tokenExpiry default
	// (token.service.ts:80). It governs only that pair: the OIDC /token
	// endpoint returns the HS256 session access token and reports that
	// token's lifetime, Config.AccessTokenTTL, as expires_in.
	AccessTokenTTL time.Duration
	// IDTokenTTL is the lifetime of the ID token; zero resolves to one hour.
	IDTokenTTL time.Duration

	// Signer signs every RS256 token the IDP issues and is the key the JWKS
	// document publishes first. It must be an RSA key — RS256 is RSASSA-PKCS1
	// v1.5 over SHA-256 (RFC 7518 section 3.3) — and NewIDP refuses a signer
	// whose Public is not an *rsa.PublicKey. An *rsa.PrivateKey qualifies, so
	// the reference's PEM configuration is ParseRSAPrivateKeyPEM(pem) here
	// (idProvider.privateKey, token.service.ts:47); the public key the
	// reference derives when none is given (:67-69) is Signer.Public. A signer
	// that keeps the private key elsewhere — a KMS, an HSM — plugs in the same
	// way; BuildRS256JWT says what it is asked to do.
	//
	// Nil generates an ephemeral RSA-2048 key in NewIDP and logs the
	// reference's warning once (token.service.ts:50-66, auth.router.ts:480-483):
	// every token becomes unverifiable on restart, and two processes never
	// share a key. Development only.
	Signer crypto.Signer
	// KeyID is the kid written into the header of every signed token and
	// published with Signer's key in the JWKS document. Empty resolves to
	// DefaultIDPKeyID, the reference's constant.
	KeyID string
	// PublicKeys are further keys the JWKS document publishes after Signer's,
	// unchanged: the previous key during a rotation, so that the tokens it
	// signed stay verifiable until they expire, or a sibling issuer's. Nothing
	// in the IDP signs with them or checks them; NewRSAJWK builds one from an
	// *rsa.PublicKey. The reference publishes exactly one key
	// (jwks.service.ts:184-186); this is the structural room a rotation needs.
	PublicKeys []JWK
	// RefreshTokenTTL is the lifetime of the refresh token IssueIdPTokenPair
	// mints; zero resolves to 90 days (token.service.ts:91). The reference
	// consults its session refresh lifetime in between (idProvider.refreshTokenExpiry,
	// then refreshTokenExpiresIn, then 90d); that middle step is not
	// reproduced, because Config.RefreshTokenTTL is never unset here —
	// DefaultConfig fills it and validate requires it — so honouring it would
	// make the 90-day default unreachable and tie the IdP pair silently to the
	// session lifetime.
	RefreshTokenTTL time.Duration
	// Logger receives the IDP's diagnostics, today only the ephemeral-key
	// warning. Nil falls back to the Config.Logger of the Service NewIDP was
	// given, and to silence when there is none.
	Logger func(format string, args ...any)

	// Codes holds authorization codes between /authorize and /token. Nil
	// selects NewMemoryAuthCodeStore, which is correct only while both
	// endpoints are served by the same process: a serverless runtime or any
	// deployment with more than one instance must supply a shared
	// implementation, or /token will answer invalid_grant for every code
	// minted by a sibling process. See AuthCodeStore for the contract.
	Codes AuthCodeStore

	// RefreshTokens holds the refresh tokens of the /token endpoint's
	// refresh_token grant: the opaque, single-use tokens /token issues when a code
	// was granted the offline_access scope. Nil selects
	// NewMemoryIDPRefreshTokenStore, which, like the Codes default, is correct
	// only while every /token request reaches the same process. See
	// IDPRefreshTokenStore for the contract. These are not the tokens
	// RefreshTokenTTL above governs: that is the lifetime of the RS256 pair
	// IssueIdPTokenPair mints, and the grant's family lives as long as the
	// session the code opened, Config.RefreshTokenTTL.
	RefreshTokens IDPRefreshTokenStore

	// CodeTTL bounds how long a code issued by /authorize can be redeemed at
	// /token. Zero (or negative) resolves to defaultAuthCodeTTL, five minutes.
	CodeTTL time.Duration

	// JWKSPath is where the JWKS document is served, relative to the adapter's
	// mount prefix: the reference's idProvider.jwksPath (auth.router.ts:475).
	// Empty resolves to DefaultJWKSPath. NewIDP refuses a path that the four
	// adapters and RegisterHandlers cannot all route as the same literal path:
	// it must start with "/" and must not end with one, must not contain "{",
	// "}", "?", "#" or "//", and must not collide with one of the four OIDC
	// endpoints, which the adapters and RegisterHandlers both mount
	// (OIDCAuthorizePath, OIDCTokenPath, OIDCUserInfoPath, OIDCDiscoveryPath).
	//
	// An Auth built WithIDP makes every adapter serve GET <prefix><JWKSPath>,
	// public and ahead of any middleware, exactly where the reference registers
	// it (auth.router.ts:473-475).
	JWKSPath string
	// JWKSCORSOrigins is the allowlist for the Access-Control-Allow-Origin
	// header on the JWKS response: the reference's idProvider.jwksCorsOrigins
	// (auth.router.ts:492-500).
	//
	// Nil is the reference's default, "*". Otherwise the request's Origin is
	// echoed back when it appears in the list, and no Access-Control-Allow-Origin
	// header is sent at all when it does not — not an empty one, and not a
	// refusal: the body is served either way, since CORS bounds what a browser
	// script may read, not what the server answers.
	//
	// The reference's type is `string | string[]`, and only its string form is
	// the wildcard: it compares the whole value against "*" (auth.router.ts:493),
	// so every array is an allowlist and an entry "*" inside one is an ordinary
	// entry, matching only an Origin header of literally "*" — one no browser
	// sends. Go has no such union, so the one-element slice {"*"} stands in for
	// the string form and is the single configuration that reads differently
	// from the reference; see the jwks-cors-wildcard-string-form entry in
	// compatibility.go.
	//
	// Neither the reference nor this port sends Vary: Origin, while both send
	// Cache-Control: public, max-age=3600 (auth.router.ts:492-502). An
	// allowlisted response must therefore not reach a shared cache, which would
	// store one origin's header and replay it to another, or store the
	// header-less variant and break the allowlisted origin: front an allowlist
	// with a private cache, or leave this nil so every origin may read the
	// document.
	JWKSCORSOrigins []string
	// JWKSURL overrides the jwks_uri of the discovery document RegisterHandlers
	// serves. Empty derives it as Issuer + JWKSPath, which is the canonical
	// location whenever Issuer carries the mount prefix — the convention every
	// other endpoint in that document already follows, since they are all
	// derived from Issuer alone. Set it when the IdP is reached through a
	// gateway whose external URL is not Issuer + the mounted path.
	JWKSURL string
}

// IDPClient represents a registered OIDC client application.
type IDPClient struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Name         string
}

// IDP is an OIDC Identity Provider.
type IDP struct {
	cfg     IDPConfig
	authSvc *Service
	// signer is cfg.Signer with the nil default resolved; keyID is cfg.KeyID
	// with the reference's constant as the default; signerJWK is the signer's
	// Public under keyID, checked once at construction to be RSA and built
	// once, the entry JWKS publishes first.
	signer    crypto.Signer
	signerJWK JWK
	keyID     string
	clients   map[string]IDPClient
	// codes is cfg.Codes with the nil default resolved. Every code handed to a
	// client is looked up here by hashToken(code); nothing in the IDP holds a
	// code or its record after the handler returns, which is what lets
	// /authorize and /token run on different processes.
	codes AuthCodeStore
	// refreshTokens is cfg.RefreshTokens with the nil default resolved.
	refreshTokens IDPRefreshTokenStore
	now           func() time.Time
}

// NewIDP creates a new OIDC IDP backed by the given auth service.
//
// A nil cfg.Signer falls back to an ephemeral RSA-2048 key and logs
// idpEphemeralKeyWarning once; a signer that is not RSA is refused. A nil
// cfg.Codes falls back to an in-process MemoryAuthCodeStore; see
// IDPConfig.Codes for when that is not enough.
func NewIDP(cfg IDPConfig, authSvc *Service, clients ...IDPClient) (*IDP, error) {
	if err := validateJWKSPath(cfg.JWKSPath); err != nil {
		return nil, err
	}
	idp := &IDP{cfg: cfg, authSvc: authSvc, now: time.Now}
	signer := cfg.Signer
	if signer == nil {
		// The reference warns on the first call that finds no privateKey and
		// generates once per process (token.service.ts:50-66); here the key is
		// generated once per IDP, at construction, so the warning goes with it.
		idp.logf(idpEphemeralKeyWarning)
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("auth: idp key generation: %w", err)
		}
		signer = key
	}
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok || pub == nil || pub.N == nil {
		return nil, fmt.Errorf("auth: idp: signer public key is %T, want *rsa.PublicKey (RS256 is RSA)", signer.Public())
	}
	idp.signer = signer
	idp.keyID = cfg.KeyID
	if idp.keyID == "" {
		idp.keyID = DefaultIDPKeyID
	}
	signerJWK, err := NewRSAJWK(pub, idp.keyID)
	if err != nil {
		return nil, err
	}
	idp.signerJWK = signerJWK
	idp.clients = make(map[string]IDPClient, len(clients))
	for _, c := range clients {
		idp.clients[c.ClientID] = c
	}
	idp.codes = cfg.Codes
	if idp.codes == nil {
		idp.codes = NewMemoryAuthCodeStore()
	}
	idp.refreshTokens = cfg.RefreshTokens
	if idp.refreshTokens == nil {
		idp.refreshTokens = NewMemoryIDPRefreshTokenStore()
	}
	return idp, nil
}

// logf writes through IDPConfig.Logger, else through the Service's logger.
func (idp *IDP) logf(format string, args ...any) {
	switch {
	case idp.cfg.Logger != nil:
		idp.cfg.Logger(format, args...)
	case idp.authSvc != nil:
		idp.authSvc.logf(format, args...)
	}
}

// codeTTL resolves IDPConfig.CodeTTL, applying the five-minute default.
func (idp *IDP) codeTTL() time.Duration {
	if idp.cfg.CodeTTL <= 0 {
		return defaultAuthCodeTTL
	}
	return idp.cfg.CodeTTL
}

// accessTokenTTL resolves IDPConfig.AccessTokenTTL for the IdP pair.
func (idp *IDP) accessTokenTTL() time.Duration {
	if idp.cfg.AccessTokenTTL <= 0 {
		return defaultIDPAccessTokenTTL
	}
	return idp.cfg.AccessTokenTTL
}

// refreshTokenTTL resolves IDPConfig.RefreshTokenTTL for the IdP pair.
func (idp *IDP) refreshTokenTTL() time.Duration {
	if idp.cfg.RefreshTokenTTL <= 0 {
		return defaultIDPRefreshTokenTTL
	}
	return idp.cfg.RefreshTokenTTL
}

// JWKS is the document the JWKS endpoint serves: the signer's public key under
// KeyID first, then IDPConfig.PublicKeys in the order given. The reference
// builds the same document from its one key (jwks.service.ts:184-186); the
// extra entries are what a rotation publishes so that tokens signed by the
// previous key stay verifiable until they expire.
func (idp *IDP) JWKS() JWKS {
	keys := make([]JWK, 0, 1+len(idp.cfg.PublicKeys))
	keys = append(keys, idp.signerJWK)
	keys = append(keys, idp.cfg.PublicKeys...)
	return JWKS{Keys: keys}
}

// jwksReservedPaths are the suffixes the OIDC endpoints occupy below the mount
// prefix. A JWKSPath equal to one of them would register the same ServeMux
// pattern twice, which panics at mount time — inside the host's own
// initialisation, far from the configuration that caused it.
var jwksReservedPaths = []string{
	OIDCAuthorizePath,
	OIDCTokenPath,
	OIDCUserInfoPath,
	OIDCDiscoveryPath,
}

// validateJWKSPath refuses an IDPConfig.JWKSPath that the four adapters and
// RegisterHandlers cannot all route as the same literal path. Empty is the
// default and is accepted; everything else is checked here, at construction,
// rather than at the first request or at mount time.
//
// The path is concatenated onto the mount prefix, so it must start with "/" — a
// relative one would mount <prefix>jwks.json and be served from nowhere anybody
// looks. It must not end in "/", which is a subtree pattern in net/http and a
// literal trailing segment in chi. It must not contain "{" or "}", which chi,
// gin and echo read as a wildcard parameter, nor "?" or "#", which are not part
// of a path at all, nor "//", which is an empty segment the routers normalise
// differently. And it must not collide with one of the four OIDC endpoints.
func validateJWKSPath(path string) error {
	if path == "" {
		return nil
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("auth: idp: JWKSPath %q must start with %q", path, "/")
	}
	if strings.HasSuffix(path, "/") {
		return fmt.Errorf("auth: idp: JWKSPath %q must not end with %q: a trailing slash is a "+
			"subtree pattern in net/http and a literal segment in chi", path, "/")
	}
	for _, bad := range []string{"{", "}", "?", "#", "//"} {
		if strings.Contains(path, bad) {
			return fmt.Errorf("auth: idp: JWKSPath %q must not contain %q: the routers read it as a "+
				"wildcard or a delimiter rather than as part of a literal path", path, bad)
		}
	}
	for _, reserved := range jwksReservedPaths {
		if path == reserved {
			return fmt.Errorf("auth: idp: JWKSPath %q is one of the four OIDC endpoints: "+
				"registering the same pattern twice panics in http.ServeMux", path)
		}
	}
	return nil
}

// JWKSPath reports where the JWKS document is served relative to the mount
// prefix: IDPConfig.JWKSPath, or DefaultJWKSPath when that is empty. It always
// starts with "/", because NewIDP refuses a path that does not. The adapters
// call it to build the route they mount.
func (idp *IDP) JWKSPath() string {
	if idp.cfg.JWKSPath == "" {
		return DefaultJWKSPath
	}
	return idp.cfg.JWKSPath
}

// jwksURI is the absolute URL the discovery document advertises as jwks_uri:
// IDPConfig.JWKSURL, else Issuer + JWKSPath.
func (idp *IDP) jwksURI() string {
	if idp.cfg.JWKSURL != "" {
		return idp.cfg.JWKSURL
	}
	return strings.TrimSuffix(idp.cfg.Issuer, "/") + idp.JWKSPath()
}

// jwksAllowedOrigin resolves the Access-Control-Allow-Origin header for a
// request carrying this Origin, and reports whether the header is sent at all:
// the transcription of auth.router.ts:492-500.
//
// Nil origins answer "*" whatever the request says, and so does the one-element
// slice {"*"}, which is how this port spells the reference's wildcard string —
// the reference compares the whole value against "*" (auth.router.ts:493), so
// the wildcard is never an entry. Every other slice is an allowlist: the Origin
// is echoed when it is listed and no header is sent when it is not. The
// reference sets none in that branch, which is what makes the browser refuse the
// read while the document is still served to everything that is not a browser.
func (idp *IDP) jwksAllowedOrigin(requestOrigin string) (string, bool) {
	origins := idp.cfg.JWKSCORSOrigins
	if origins == nil {
		return jwksWildcardOrigin, true
	}
	if len(origins) == 1 && origins[0] == jwksWildcardOrigin {
		return jwksWildcardOrigin, true
	}
	for _, origin := range origins {
		if origin == requestOrigin {
			return requestOrigin, true
		}
	}
	return "", false
}

// JWKSHandler serves JWKS() with the headers the reference sets on that route:
// Access-Control-Allow-Origin per JWKSCORSOrigins and
// "Cache-Control: public, max-age=3600" (auth.router.ts:490-503).
//
// The document is built once, here, and not per request: the reference derives
// it at router-creation time and closes over it (auth.router.ts:487), and
// nothing an IDP holds can change it afterwards — the signer and
// IDPConfig.PublicKeys are both fixed at construction.
//
// The handler is public by construction: no auth, no CSRF, no session. Mounting
// it is what an adapter does for an Auth built WithIDP; a host that mounts it
// by hand must keep it ahead of any middleware, as the reference does
// (auth.router.ts:473-474).
func (idp *IDP) JWKSHandler() http.Handler {
	document := idp.JWKS()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin, ok := idp.jwksAllowedOrigin(r.Header.Get("Origin")); ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Cache-Control", jwksCacheControl)
		WriteJSON(w, http.StatusOK, document)
	})
}

// IssueIdPTokenPair mints the reference's RS256 token pair for user: the
// transcription of generateIdProviderTokenPair (token.service.ts:73-95).
//
// The payload is the reference's buildPayload (auth.router.ts:378-384): the
// six base claims sub, email, role, loginProvider, isEmailVerified and
// isTotpEnabled with Config.BuildTokenClaims spread over them, the same object
// the session tokens start from. iat, exp and kid are then dropped from it
// (:73) — the first two are set below, kid is a header parameter — and iss is
// set from IDPConfig.Issuer when that is configured, else left as the hook
// left it (:74-77). Both tokens carry that payload plus iat and exp, both are
// RS256 under KeyID (:81-93); they differ only in lifetime — AccessTokenTTL,
// 30 days by default, and RefreshTokenTTL, 90 days by default. ExpiresIn is
// the access lifetime.
//
// No session is created and no sid, jti or typ claim is written: the reference
// pair has none either, so the refresh token is a longer-lived copy of the
// access token that nothing here can revoke. This is a host-level API exactly
// as in the reference, where nothing in src/ calls generateIdProviderTokenPair
// (reference-issues N35): /login, /refresh and the OIDC /token keep issuing
// the HS256 session pair, and enabling the IDP changes nothing about them.
//
// It lives on IDP rather than Service because everything it needs beyond the
// user is the IDP's — the signer, the kid, the two lifetimes, the issuer — and
// the IDP already holds the Service for the claims hook, while a Service knows
// nothing of any IDP. In the reference all of that is the config.idProvider
// block, which is IDPConfig here.
func (idp *IDP) IssueIdPTokenPair(ctx context.Context, user User) (AuthTokens, error) {
	claims, err := idp.payloadClaims(ctx, user)
	if err != nil {
		return AuthTokens{}, err
	}
	delete(claims, "iat")
	delete(claims, "exp")
	delete(claims, "kid")
	if idp.cfg.Issuer != "" {
		claims["iss"] = idp.cfg.Issuer
	}
	now := idp.now()
	accessTTL := idp.accessTokenTTL()
	accessToken, err := idp.signWithLifetime(claims, now, accessTTL)
	if err != nil {
		return AuthTokens{}, err
	}
	refreshToken, err := idp.signWithLifetime(claims, now, idp.refreshTokenTTL())
	if err != nil {
		return AuthTokens{}, err
	}
	return AuthTokens{AccessToken: accessToken, RefreshToken: refreshToken, ExpiresIn: accessTTL}, nil
}

// payloadClaims is the reference's buildPayload (auth.router.ts:378-384) for
// the IdP pair; issueToken in token.go assembles the same object inline for the
// session pair, and TestIssueIdPTokenPairBaseClaimsMatchSessionTokens keeps
// the two in step. The hook is the Service's, so an IDP built without one
// mints the base claims alone.
func (idp *IDP) payloadClaims(ctx context.Context, user User) (map[string]any, error) {
	claims := map[string]any{
		"sub":             user.ID,
		"email":           user.Email,
		"role":            user.Role,
		"loginProvider":   user.loginProviderOrLocal(),
		"isEmailVerified": user.IsEmailVerified,
		"isTotpEnabled":   user.IsTOTPEnabled,
	}
	if idp.authSvc != nil && idp.authSvc.cfg.BuildTokenClaims != nil {
		custom, err := idp.authSvc.cfg.BuildTokenClaims(ctx, user)
		if err != nil {
			return nil, fmt.Errorf("auth: build token claims: %w", err)
		}
		for key, value := range custom {
			claims[key] = value
		}
	}
	return claims, nil
}

// signWithLifetime signs a copy of claims with iat = now and exp = now + ttl,
// the two members jsonwebtoken manages for the reference (token.service.ts:72).
func (idp *IDP) signWithLifetime(claims map[string]any, now time.Time, ttl time.Duration) (string, error) {
	payload := make(map[string]any, len(claims)+2)
	for key, value := range claims {
		payload[key] = value
	}
	payload["iat"] = now.Unix()
	payload["exp"] = now.Add(ttl).Unix()
	return BuildRS256JWT(idp.signer, idp.keyID, payload)
}

// OIDCMount is one OIDC endpoint as the adapters mount it: Path is below the
// mount prefix and Handler serves it.
//
// The handler is mounted for every method, which is what (*IDP).RegisterHandlers
// has always done with a method-less http.ServeMux pattern, and what the
// handlers expect — /authorize reads r.Method itself to tell its login form
// from its credential post, /token and /userinfo read the form and the
// Authorization header rather than the method. So there is no method to narrow
// to without changing an answer, and the four adapters register the handler for
// all methods rather than for a list they would then have to keep in step.
type OIDCMount struct {
	// Path is the endpoint below the mount prefix, leading "/" included.
	Path string
	// Handler serves it, for every method.
	Handler http.Handler
	// ResourceServerGated reports that this endpoint creates or exchanges a
	// credential, so HTTPConfig.ResourceServer leaves it unmounted the way it
	// leaves /login and /refresh unmounted. Every adapter skips a gated mount
	// under that flag; see oidcResourceServerGated for which two carry it and
	// why. RegisterHandlers ignores the field: it mounts a host's own mux, with
	// no HTTPConfig in sight, so the host decides what goes on it.
	ResourceServerGated bool
}

// oidcResourceServerGated is the OIDC half of ResourceServerGatedRoutes: the
// endpoints HTTPConfig.ResourceServer leaves unmounted, keyed by path.
//
// Two of the four are in it. POST <prefix>/authorize reads an email, a password
// and a tenant off the form and hands them to Service.Login, then mints an
// authorization code for the answer; POST <prefix>/token spends that code and
// returns this instance's own HS256 session pair. Both are routes that create
// or change a credential by the definition at the top of resource_server.go, so
// a deployment that set the flag to unmount /login and /refresh must not regain
// a password-accepting endpoint and a session-minting one by also building
// WithIDP.
//
// The other two are not. The discovery document is metadata, like the JWKS
// route it sits beside and is gated no more than that one is;
// <prefix>/userinfo reads a bearer token and returns a profile, which is the
// same shape as GET /me, and /me stays mounted for the reason that list gives —
// resource-server mode is about credentials, not about store independence.
//
// It is not part of ResourceServerGatedRoutes because that map is the base
// surface's, replayed against an adapter mounted without an IdP, where these
// two paths are not routes at all.
var oidcResourceServerGated = map[string]bool{
	OIDCAuthorizePath: true,
	OIDCTokenPath:     true,
}

// OIDCMounts returns the four OIDC endpoints — discovery, authorize, token and
// userinfo — as the adapters and RegisterHandlers mount them.
//
// It is the one list: every adapter's MountWithConfig walks it, and so does
// RegisterHandlers, so an endpoint cannot appear on one mount and not another.
// The JWKS route is not in it — that one is the reference's, configurable
// through IDPConfig.JWKSPath and GET-only, and the adapters mount it from
// JWKSPath() and JWKSHandler() for that reason.
//
// Two of the four carry ResourceServerGated, which is the adapters' cue to skip
// them under HTTPConfig.ResourceServer; the flag travels on the mount rather
// than splitting the walk in four adapters, so this stays the one list.
//
// These four have no counterpart in the reference, which ships no OIDC
// authorization server; their shapes are described where the handlers are, and
// nothing here changes them.
func (idp *IDP) OIDCMounts() []OIDCMount {
	mounts := []OIDCMount{
		{Path: OIDCDiscoveryPath, Handler: http.HandlerFunc(idp.handleDiscovery)},
		{Path: OIDCAuthorizePath, Handler: http.HandlerFunc(idp.handleAuthorize)},
		{Path: OIDCTokenPath, Handler: http.HandlerFunc(idp.handleToken)},
		{Path: OIDCUserInfoPath, Handler: http.HandlerFunc(idp.handleUserInfo)},
	}
	// Read from the one map rather than spelled twice, so openapi.go and the
	// adapters cannot drift from each other about which two are gated.
	for i := range mounts {
		mounts[i].ResourceServerGated = oidcResourceServerGated[mounts[i].Path]
	}
	return mounts
}

// RegisterHandlers mounts OIDC endpoints on the given mux.
//
// An Auth built with WithIDP makes all four adapters mount the same four
// endpoints under the adapter's own prefix, from the same OIDCMounts list, so a
// host that mounts an adapter no longer needs this at all. It stays for the host
// that serves the OIDC endpoints on a mux of its own — under a different base
// path, or behind its own middleware — and for the one that uses the IdP
// without mounting an adapter.
//
// All four are mounted here whatever OIDCMount.ResourceServerGated says. That
// flag is the adapters' reading of HTTPConfig.ResourceServer, and this method
// is handed a mux with no HTTPConfig behind it: a host mounting the endpoints
// itself is choosing the surface itself.
//
// Calling it with the adapter's own prefix, on the mux the adapter was mounted
// on, is a mistake rather than a way to mount the endpoints twice, and it is a
// loud one: both registrations use the same method-less pattern, so the second
// panics at mount time — ServeMux reports the two patterns as conflicting and
// names both registration sites — the same way the JWKS route already panics
// when a host registers it twice. The panic is the point. A pattern that did
// not collide, "GET <path>" against this method-less one, would be accepted as
// the more specific of the two and would leave the endpoint split between two
// handlers, GET answered by the adapter's mount and every other method by this
// one; that silent split is the failure this shape rules out.
//
// The JWKS document is served at basePath + JWKSPath(), the canonical location
// the adapters mount and the one the discovery document points at.
// <basePath>/jwks is kept as a deprecated alias of it, serving the identical
// bytes and headers, for the relying parties configured against the path this
// package published before v0.6.0; the alias is kept through the 0.x line and
// removed in v1.0.0. The deprecated thing is that URL path, not this method:
// the other four endpoints, and the canonical JWKS path, are current.
//
// Both JWKS patterns are registered for GET alone, as the reference registers
// the route (router.get, auth.router.ts:490) and as the four adapters mount it.
// net/http serves HEAD from a "GET " pattern itself, which is Express's own
// fallback from HEAD to the GET handler; any other method misses the route.
func (idp *IDP) RegisterHandlers(mux *http.ServeMux, basePath string) {
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	jwks := idp.JWKSHandler()
	canonical := basePath + strings.TrimPrefix(idp.JWKSPath(), "/")
	mux.Handle("GET "+canonical, jwks)
	// A JWKSPath of "/jwks" makes the alias the canonical path; registering it
	// twice would panic in ServeMux.
	if alias := basePath + "jwks"; alias != canonical {
		mux.Handle("GET "+alias, jwks)
	}
	for _, mount := range idp.OIDCMounts() {
		mux.Handle(basePath+strings.TrimPrefix(mount.Path, "/"), mount.Handler)
	}
}

func (idp *IDP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	base := strings.TrimSuffix(idp.cfg.Issuer, "/")
	doc := map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + OIDCAuthorizePath,
		"token_endpoint":                        base + OIDCTokenPath,
		"userinfo_endpoint":                     base + OIDCUserInfoPath,
		"jwks_uri":                              idp.jwksURI(),
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile", oidcScopeOfflineAccess},
		"grant_types_supported":                 []string{grantTypeAuthorizationCode, grantTypeRefreshToken},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{pkceMethodS256},
		"claims_supported":                      []string{"sub", "email", "name", "iat", "exp", "iss", "aud", "nonce"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc) //nolint:errcheck
}

func (idp *IDP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	nonce := q.Get("nonce")

	client, ok := idp.clients[clientID]
	if !ok {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	// Look up the canonical (server-controlled) redirect URI from the registered allowlist.
	canonicalRedirect := idpMatchedRedirect(client.RedirectURIs, redirectURI)
	if canonicalRedirect == "" {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	// The PKCE parameters are checked before the form is served or the
	// credentials are, since neither is worth doing for a request whose code
	// could never be redeemed. The client and the redirect_uri are known good by
	// now, so the refusal is the authorization error response of RFC 6749
	// §4.1.2.1 — a redirect back to the client carrying error and state — which
	// is what RFC 7636 §4.4.1 prescribes for a transformation the server does
	// not support.
	if description := pkceAuthorizeError(q.Get("code_challenge"), q.Get("code_challenge_method")); description != "" {
		redirectAuthorizeError(w, r, canonicalRedirect, state, "invalid_request", description)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		email := r.FormValue("email")
		password := r.FormValue("password")
		tenantID := r.FormValue("tenant_id")
		user, _, err := idp.authSvc.Login(r.Context(), LoginInput{Email: email, Password: password, TenantID: tenantID})
		if err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		code, err := randomToken(24)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// The client gets the random code; the store gets only its hash, so
		// a leaked store dump cannot be redeemed at /token. The PKCE pair is
		// what /token verifies the code_verifier against, and the scope is
		// what decides whether it issues a refresh token.
		err = idp.codes.SaveCode(r.Context(), AuthCode{
			CodeHash:            hashToken(code),
			UserID:              user.ID,
			TenantID:            user.TenantID,
			ClientID:            clientID,
			Nonce:               nonce,
			RedirectURI:         canonicalRedirect,
			CodeChallenge:       q.Get("code_challenge"),
			CodeChallengeMethod: q.Get("code_challenge_method"),
			Scope:               q.Get("scope"),
			ExpiresAt:           idp.now().Add(idp.codeTTL()),
		})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Use the canonical (server-controlled) URI, not the raw user input.
		redir, err := url.Parse(canonicalRedirect)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		rq := redir.Query()
		rq.Set("code", code)
		if state != "" {
			rq.Set("state", state)
		}
		redir.RawQuery = rq.Encode()
		http.Redirect(w, r, redir.String(), http.StatusFound)
		return
	}

	// GET: return a minimal login form
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<form method="POST">
<input name="email" placeholder="Email" required>
<input name="password" type="password" placeholder="Password" required>
<input name="tenant_id" placeholder="Tenant ID" value="">
<button type="submit">Sign In</button>
</form></body></html>`)
}

func (idp *IDP) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	// Authenticate, not Me: the body below is sub, email and name, none of
	// which Config.BuildTokenClaims contributes, so running the hook here would
	// cost a relying party a claims round trip per userinfo call for nothing.
	user, err := idp.authSvc.Authenticate(r.Context(), token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"sub":   user.ID,
		"email": user.Email,
		"name":  strings.TrimSpace(user.FirstName + " " + user.LastName),
	})
}

func (idp *IDP) buildIDToken(user User, audience, nonce string) (string, error) {
	now := idp.now()
	ttl := idp.cfg.IDTokenTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	claims := map[string]any{
		"iss":   idp.cfg.Issuer,
		"sub":   user.ID,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
		"email": user.Email,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return BuildRS256JWT(idp.signer, idp.keyID, claims)
}

// idpMatchedRedirect returns the canonical redirect URI from the allowlist that
// exactly matches the requested URI. This ensures the redirect target is always
// a server-controlled value, not a raw user-supplied string.
func idpMatchedRedirect(allowed []string, requested string) string {
	for _, u := range allowed {
		if u == requested {
			return u
		}
	}
	return ""
}
