package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// This file is the other half of the IdP: jwks.go and idp.go mint RS256 tokens
// and publish the key, and this one consumes them. A resource server is a
// deployment with no local user database — it verifies the tokens another
// instance issued against that instance's published JWKS, and mounts none of
// the routes that would create or change a credential.
//
// The three pieces are the reference's three: JwksClient, a cached
// stale-while-revalidate reader of a remote JWKS document
// (jwks.service.ts:29-141); verifyWithJwks, the RS256 verifier that selects the
// key by the token kid header and retries once across a key rotation
// (token.service.ts:102-141); and createJwksAuthMiddleware, which reads a
// bearer token through the first two and a cookie through the local HS256 path
// (jwks-auth.middleware.ts:37-80).

// Defaults for ResourceServerConfig, from the reference JwksClient constructor
// (jwks.service.ts:40-41): cacheTtl 3_600_000 ms and fetchTimeout 5000 ms.
const (
	DefaultJWKSCacheTTL     = time.Hour
	DefaultJWKSFetchTimeout = 5 * time.Second
)

// DefaultJWKSMinRefreshInterval is how long a freshly fetched document is
// trusted to be complete: inside it, a token naming a kid the document does not
// carry is refused without a refetch.
//
// It has no counterpart in the reference, which invalidates and refetches on
// every unknown kid (token.service.ts:116-125). That is an unauthenticated
// request amplifier — anyone who can reach the resource server can make it call
// the issuer once per request by sending a random kid, and because Invalidate
// drops the in-flight handle too, concurrent junk does not even coalesce. See
// the jwks-unknown-kid-refetch-is-rate-limited deviation.
//
// Thirty seconds is picked the way node-jwks-rsa picks its rateLimit default:
// long enough that a flood costs one fetch, short enough that a real rotation
// is picked up in the same breath as it happens.
const DefaultJWKSMinRefreshInterval = 30 * time.Second

// ResourceServerConfig is how a deployment points itself at the JWKS of the
// instance that issues its tokens. It is the reference ResourceServerConfig
// (auth-config.model.ts:112-140) minus the enabled flag: in Go the flag is the
// act of constructing the middleware, and unmounting the credential routes is
// HTTPConfig.ResourceServer.
type ResourceServerConfig struct {
	// JWKSURL is the full URL of the issuer JWKS endpoint, for example
	// https://auth.example.com/auth/.well-known/jwks.json. It is required:
	// NewJWKSClient panics on an empty one, and on one that is not an
	// absolute http or https URL, rather than building a client that refuses
	// every bearer token for the lifetime of the process. The reference refuses
	// the same misconfiguration the same way, by throwing when the mode is
	// wired without its settings (jwks-auth.middleware.ts:38-40).
	JWKSURL string
	// Issuer is the expected iss claim. Empty means the claim is not checked,
	// which is the reference behaviour for an absent issuer
	// (token.service.ts:137).
	Issuer string
	// CacheTTL is how long a fetched document stays fresh. Zero means
	// DefaultJWKSCacheTTL.
	CacheTTL time.Duration
	// FetchTimeout bounds one fetch. Zero means DefaultJWKSFetchTimeout.
	FetchTimeout time.Duration
	// MinRefreshInterval is the shortest interval between two refetches forced
	// by an unknown kid. Zero means DefaultJWKSMinRefreshInterval; a negative
	// value turns the limit off and restores the reference behaviour, which
	// refetches on every unknown kid.
	MinRefreshInterval time.Duration
	// Client is the HTTP client the fetch goes through. Nil means a client of
	// this package, which carries no cookie jar and no redirect policy of its
	// own. A host that needs a proxy, a pinned CA pool or a tracing transport
	// supplies one here.
	Client *http.Client
}

// errJWKSKeyNotFound is what GetKey reports when the fetched document carries
// no key under the requested kid — the reference null return
// (jwks.service.ts:97).
//
// It wraps ErrInvalidToken rather than being a sentinel of its own: on the wire
// an unknown signing key is an unusable token and nothing else, so
// HTTPErrorFor already maps it, and the register of sentinels stays the one
// TestUnmappedSentinelsAreDeliberate walks. VerifyRS256 is the caller that has
// to tell it apart from a fetch failure, and it does so with errors.Is.
var errJWKSKeyNotFound = fmt.Errorf("%w: unknown signing key", ErrInvalidToken)

// jwksFetch is one in-flight fetch. Callers that arrive while it runs wait on
// done and then read doc and err, which are written before it closes.
type jwksFetch struct {
	done chan struct{}
	doc  *JWKS
	err  error
}

// JWKSClient is a cached reader of a remote JWKS document.
//
// The cache is stale-while-revalidate, exactly as the reference
// (jwks.service.ts:49-92):
//
//   - a document inside its TTL is returned from memory;
//   - a fetch already in flight is joined rather than duplicated, so a burst of
//     requests on a cold cache causes one HTTP call;
//   - a document past its TTL is returned anyway, immediately, and a refresh
//     runs in the background;
//   - a refresh that fails changes nothing, so the stale document keeps serving
//     — an issuer that is briefly unreachable does not take the resource server
//     down with it.
//
// The zero value is not usable; construct one with NewJWKSClient. A client is
// safe for concurrent use, and is meant to be long-lived: it is the cache.
type JWKSClient struct {
	url          string
	cacheTTL     time.Duration
	fetchTimeout time.Duration
	minRefresh   time.Duration
	client       *http.Client

	mu        sync.Mutex
	now       func() time.Time
	doc       *JWKS
	expiry    time.Time
	fetchedAt time.Time
	inflight  *jwksFetch
}

// NewJWKSClient returns a client for cfg.JWKSURL. Only the JWKS fields of cfg
// are read; Issuer belongs to the verifier.
//
// It panics when JWKSURL is empty or is not an absolute http or https URL. A
// resource server whose issuer endpoint is misconfigured cannot verify a single
// bearer token, so the failure belongs at startup, where it is one line in a
// log, rather than at the first request, where it is a blanket 401 that looks
// like an authentication problem. The reference throws for the same reason
// (jwks-auth.middleware.ts:38-40).
func NewJWKSClient(cfg ResourceServerConfig) *JWKSClient {
	if err := validateJWKSURL(cfg.JWKSURL); err != nil {
		panic(err.Error())
	}
	c := &JWKSClient{
		url:          cfg.JWKSURL,
		cacheTTL:     cfg.CacheTTL,
		fetchTimeout: cfg.FetchTimeout,
		minRefresh:   cfg.MinRefreshInterval,
		client:       cfg.Client,
		now:          time.Now,
	}
	if c.cacheTTL <= 0 {
		c.cacheTTL = DefaultJWKSCacheTTL
	}
	if c.fetchTimeout <= 0 {
		c.fetchTimeout = DefaultJWKSFetchTimeout
	}
	if c.minRefresh == 0 {
		c.minRefresh = DefaultJWKSMinRefreshInterval
	}
	if c.client == nil {
		c.client = &http.Client{}
	}
	return c
}

// validateJWKSURL is the constructor check, separated so the test can assert on
// the message rather than on the panic alone.
func validateJWKSURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("auth: ResourceServerConfig.JWKSURL is empty; " +
			"resource-server mode needs the issuer JWKS endpoint")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("auth: ResourceServerConfig.JWKSURL %q is not an absolute http or https URL", raw)
	}
	return nil
}

// setClock replaces the clock the TTL is measured against. It exists for the
// tests, which have to make a cache go stale without sleeping for an hour.
func (c *JWKSClient) setClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// URL reports the JWKS endpoint this client reads.
func (c *JWKSClient) URL() string { return c.url }

// Invalidate drops the cached document so the next read fetches fresh keys.
// It is what the verifier calls when a token names a kid the cache does not
// carry, which is how a key rotation is picked up before the TTL expires
// (jwks.service.ts:101-105).
func (c *JWKSClient) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidateLocked()
}

func (c *JWKSClient) invalidateLocked() {
	c.doc = nil
	c.expiry = time.Time{}
	// The in-flight handle is dropped, not cancelled, exactly as the reference
	// nulls fetchPromise (jwks.service.ts:104): a fetch that is already running
	// still completes and still populates the cache, and the next read starts
	// its own rather than joining one that was begun before the invalidation.
	c.inflight = nil
}

// invalidateForRotation is Invalidate with a rate limit, and it is what the
// verifier calls on an unknown kid. It reports whether the cache was actually
// dropped; false means the caller must refuse the token without a refetch.
//
// The limit is the whole of the difference from the reference. Invalidate is
// destructive — it drops the cached document *and* the in-flight handle that
// coalesces concurrent readers — so calling it on every unknown kid hands an
// unauthenticated client a lever: one outbound fetch per request bearing a
// random kid, uncoalesced, with every legitimate request in the gap paying the
// cold path. Refusing to re-drop a document fetched moments ago costs a real
// rotation nothing (the cached document is usually an hour old by the time a
// token names a key it does not carry) and costs a flood everything: the first
// unknown kid may refetch, the rest are refused from memory.
func (c *JWKSClient) invalidateForRotation() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.doc != nil && c.minRefresh > 0 && c.now().Sub(c.fetchedAt) < c.minRefresh {
		return false
	}
	c.invalidateLocked()
	return true
}

// Document returns the cached JWKS, fetching or refreshing as the
// stale-while-revalidate rules require. The returned value is a copy down to
// the key slice, so a caller may sort or filter it freely.
func (c *JWKSClient) Document(ctx context.Context) (JWKS, error) {
	c.mu.Lock()
	if c.doc != nil && c.now().Before(c.expiry) {
		doc := c.doc.clone()
		c.mu.Unlock()
		return doc, nil
	}
	if f := c.inflight; f != nil {
		stale := c.doc
		c.mu.Unlock()
		select {
		case <-f.done:
		case <-ctx.Done():
			return JWKS{}, ctx.Err()
		}
		if f.err != nil {
			// The reference catch returns the stale document rather than the
			// failure (jwks.service.ts:70-73); with no stale document there is
			// nothing to return but the error.
			if stale != nil {
				return stale.clone(), nil
			}
			return JWKS{}, f.err
		}
		return f.doc.clone(), nil
	}

	f := &jwksFetch{done: make(chan struct{})}
	c.inflight = f
	stale := c.doc
	c.mu.Unlock()

	// The fetch is never bound to the calling request: a background refresh
	// outlives the request that triggered it, and even the cold-path caller
	// below only waits for it. Cancelling the caller must not poison the cache
	// for everyone else.
	go c.runFetch(f)

	if stale != nil {
		// Stale-while-revalidate: the caller is served now and the refresh
		// lands whenever it lands (jwks.service.ts:62-75).
		return stale.clone(), nil
	}

	select {
	case <-f.done:
	case <-ctx.Done():
		return JWKS{}, ctx.Err()
	}
	if f.err != nil {
		return JWKS{}, f.err
	}
	return f.doc.clone(), nil
}

func (c *JWKSClient) runFetch(f *jwksFetch) {
	doc, err := c.fetch()

	c.mu.Lock()
	if err == nil {
		stored := doc.clone()
		c.doc = &stored
		c.fetchedAt = c.now()
		c.expiry = c.fetchedAt.Add(c.cacheTTL)
		f.doc = &doc
	}
	f.err = err
	if c.inflight == f {
		c.inflight = nil
	}
	c.mu.Unlock()

	close(f.done)
}

// fetch performs one GET against the JWKS URL, under its own timeout. The
// failures are the reference failures: a non-200 status, a body that is not
// JSON, and a document with no keys array (jwks.service.ts:113-132).
func (c *JWKSClient) fetch() (JWKS, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return JWKS{}, fmt.Errorf("auth: jwks request %s: %w", c.url, err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return JWKS{}, fmt.Errorf("auth: jwks fetch %s: %w", c.url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return JWKS{}, fmt.Errorf("auth: jwks fetch failed with status %d", res.StatusCode)
	}
	// A JWKS document is a handful of public keys. The cap is there so that a
	// misconfigured URL pointing at something large cannot be read into memory
	// on every refresh.
	body, err := io.ReadAll(io.LimitReader(res.Body, maxJWKSBytes))
	if err != nil {
		return JWKS{}, fmt.Errorf("auth: jwks read %s: %w", c.url, err)
	}
	var doc struct {
		Keys *[]JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return JWKS{}, errors.New("auth: invalid JWKS document: failed to parse JSON")
	}
	if doc.Keys == nil {
		return JWKS{}, errors.New(`auth: invalid JWKS document: missing "keys" array`)
	}
	return JWKS{Keys: *doc.Keys}, nil
}

// maxJWKSBytes caps one JWKS response body. An RSA-2048 JWK is around 400
// bytes, so this is room for hundreds of keys.
const maxJWKSBytes = 1 << 20

// clone copies a document down to its key slice.
func (d JWKS) clone() JWKS {
	if d.Keys == nil {
		return JWKS{}
	}
	keys := make([]JWK, len(d.Keys))
	copy(keys, d.Keys)
	return JWKS{Keys: keys}
}

// GetKey returns the RSA public key published under kid, fetching or
// refreshing the document as the cache rules require
// (jwks.service.ts:95-98).
//
// A document that carries no such key is not an error of the transport, and
// the two are told apart by the caller: the error wraps errJWKSKeyNotFound,
// which is what makes VerifyRS256 invalidate and retry once instead of giving
// up. Both forms wrap ErrInvalidToken.
func (c *JWKSClient) GetKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	doc, err := c.Document(ctx)
	if err != nil {
		return nil, err
	}
	for _, key := range doc.Keys {
		if key.Kid != kid {
			continue
		}
		pub, err := key.RSAPublicKey()
		if err != nil {
			return nil, err
		}
		return pub, nil
	}
	return nil, fmt.Errorf("%w %q", errJWKSKeyNotFound, kid)
}

// RSAPublicKey converts a published JWK back into an RSA public key — the
// inverse of NewRSAJWK, and of the reference jwkToPublicKey
// (jwks.service.ts:199-202).
//
// Only RSA signing keys are accepted: kty must be RSA, and alg, when the
// document states one, must be RS256. A key published for another algorithm
// would otherwise be verified as if it were an RS256 key, which is the
// algorithm-confusion the alg allow-list exists to prevent.
func (j JWK) RSAPublicKey() (*rsa.PublicKey, error) {
	if j.Kty != "RSA" {
		return nil, fmt.Errorf("%w: JWK %q has kty %q, want RSA", ErrInvalidToken, j.Kid, j.Kty)
	}
	if j.Alg != "" && j.Alg != rs256Alg {
		return nil, fmt.Errorf("%w: JWK %q has alg %q, want %s", ErrInvalidToken, j.Kid, j.Alg, rs256Alg)
	}
	n, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil || len(n) == 0 {
		return nil, fmt.Errorf("%w: JWK %q has an unreadable modulus", ErrInvalidToken, j.Kid)
	}
	e, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil || len(e) == 0 || len(e) > 8 {
		return nil, fmt.Errorf("%w: JWK %q has an unreadable exponent", ErrInvalidToken, j.Kid)
	}
	exponent := new(big.Int).SetBytes(e)
	if !exponent.IsInt64() || exponent.Int64() > int64(^uint32(0)>>1) || exponent.Int64() < 3 {
		return nil, fmt.Errorf("%w: JWK %q has an out-of-range exponent", ErrInvalidToken, j.Kid)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent.Int64())}, nil
}

// rs256Alg is the only JWS algorithm a resource server accepts. It is an
// allow-list, not a lookup: the alg a token advertises never selects the
// verification routine, so neither "none" nor an HS256 token signed with a
// published modulus can be presented as an RS256 token.
const rs256Alg = "RS256"

// The five failures the reference verifier distinguishes, each an AuthError
// with code INVALID_TOKEN and status 401 (token.service.ts:107, :112, :121,
// :131, :138). The strings are the reference strings, kept so that a host that
// logs the error logs what the reference logs; none of them reaches the wire,
// because the middleware answers with the one fixed body below.
var (
	errRSInvalidTokenFormat = fmt.Errorf("%w: Invalid token format", ErrInvalidToken)
	errRSMissingKid         = fmt.Errorf("%w: Token missing kid header", ErrInvalidToken)
	errRSUnknownKey         = fmt.Errorf("%w: Unknown signing key", ErrInvalidToken)
	errRSInvalidOrExpired   = fmt.Errorf("%w: Invalid or expired token", ErrInvalidToken)
	errRSIssuerMismatch     = fmt.Errorf("%w: Token issuer mismatch", ErrInvalidToken)
)

// VerifyRS256 verifies an RS256 token against the keys client publishes and
// returns its claims — the reference verifyWithJwks (token.service.ts:102-141).
//
// The shape is the reference shape, step for step:
//
//  1. the header is decoded without verifying, only to read kid;
//  2. a token with no kid is refused;
//  3. the header alg must be RS256. This check is the reference's
//     algorithms: ['RS256'] (token.service.ts:136) hoisted above the key
//     lookup: the reference reaches the network first and only then refuses
//     an alg:none or alg:HS256 token, which means a junk token can cost an
//     outbound fetch. Nothing on the wire changes — both refusals are the same
//     401 INVALID_TOKEN — only which of the five messages is logged;
//  4. the key is looked up; if the cache does not carry it, the cache is
//     invalidated and the lookup retried exactly once, which is how a rotation
//     is picked up mid-TTL. A second miss is refused, and so is the first when
//     the cached document is younger than MinRefreshInterval (see
//     invalidateForRotation and the jwks-unknown-kid-refetch-is-rate-limited
//     deviation);
//  5. the signature is checked with RS256 pinned, and exp and nbf are honoured;
//  6. when expectedIssuer is set, iss must equal it — a plain string
//     comparison, as the reference does it (token.service.ts:137).
//
// Every refusal of the token itself wraps ErrInvalidToken, so HTTPErrorFor maps
// it to 401 INVALID_TOKEN. A failure to read the JWKS at all does not: a
// transport error, a non-200 status and an unparseable document surface from
// GetKey unchanged and unwrapped, and HTTPErrorFor sends them to
// HTTPErrInternal, because an issuer outage is this server's 5xx and not the
// caller's bad credential. ResourceServerMiddleware answers 401 either way, as
// the reference does (its catch does not distinguish them either,
// jwks-auth.middleware.ts:76-78); a host calling VerifyRS256 directly sees the
// difference and should.
//
// The claims are returned as the decoded JSON object, unchanged: this verifier
// does not know what an issuer puts in its tokens, and a resource server is
// entitled to read all of it.
func VerifyRS256(ctx context.Context, token string, client *JWKSClient, expectedIssuer string) (map[string]any, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: no JWKS client", ErrInvalidToken)
	}
	header, payload, sig, err := splitToken(token)
	if err != nil {
		return nil, errRSInvalidTokenFormat
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, errRSInvalidTokenFormat
	}
	kid, ok := headerKid(rawHeader)
	if !ok || kid == "" {
		return nil, errRSMissingKid
	}

	// The alg allow-list is checked before the key lookup, so that a token
	// claiming "none" never reaches a verification routine — and never reaches
	// the issuer either.
	if alg, ok := headerAlg(rawHeader); !ok || alg != rs256Alg {
		return nil, errRSInvalidOrExpired
	}

	key, err := client.GetKey(ctx, kid)
	if errors.Is(err, errJWKSKeyNotFound) {
		if !client.invalidateForRotation() {
			return nil, errRSUnknownKey
		}
		key, err = client.GetKey(ctx, kid)
		if errors.Is(err, errJWKSKeyNotFound) {
			return nil, errRSUnknownKey
		}
	}
	if err != nil {
		return nil, err
	}

	rawSig, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, errRSInvalidOrExpired
	}
	digest := sha256.Sum256([]byte(header + "." + payload))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], rawSig); err != nil {
		return nil, errRSInvalidOrExpired
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errRSInvalidOrExpired
	}
	var claims map[string]any
	if err := json.Unmarshal(rawPayload, &claims); err != nil {
		return nil, errRSInvalidOrExpired
	}

	// exp and nbf are what jsonwebtoken checks for the reference by default,
	// with no clock tolerance (token.service.ts:136). A token with neither is
	// accepted, as it is there.
	now := time.Now()
	if exp, ok := numericClaim(claims, "exp"); ok && !now.Before(time.Unix(exp, 0)) {
		return nil, errRSInvalidOrExpired
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok && now.Before(time.Unix(nbf, 0)) {
		return nil, errRSInvalidOrExpired
	}
	if expectedIssuer != "" {
		if iss, _ := claims["iss"].(string); iss != expectedIssuer {
			return nil, errRSIssuerMismatch
		}
	}
	return claims, nil
}

// headerKid reads the kid member of a decoded JOSE header. It decodes into raw
// members for the reason headerAlg does: encoding/json matches struct fields
// case-insensitively, so a struct would read "KID" as kid and select a key the
// signer never named.
func headerKid(rawHeader []byte) (string, bool) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(rawHeader, &members); err != nil {
		return "", false
	}
	raw, ok := members["kid"]
	if !ok {
		return "", false
	}
	var kid string
	if err := json.Unmarshal(raw, &kid); err != nil {
		return "", false
	}
	return kid, true
}

// numericClaim reads a NumericDate claim. JSON numbers decode to float64, and
// a claim that is not a number at all is treated as absent rather than as
// zero — a zero exp would expire every token ever issued.
func numericClaim(claims map[string]any, name string) (int64, bool) {
	switch v := claims[name].(type) {
	case float64:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	default:
		return 0, false
	}
}

// HTTPErrInvalidTokenRS is what the resource-server middleware answers for any
// verification failure: 401 with code INVALID_TOKEN
// (jwks-auth.middleware.ts:77).
//
// It shares its message with HTTPErrInvalidAccessToken and differs in status
// and code, which is the reference difference too: the session middleware
// answers 403 and no code (auth.middleware.ts), and this one answers 401 with
// a code. Both messages are the same string, so a client that only surfaces
// the message reads the same sentence either way.
var HTTPErrInvalidTokenRS = HTTPError{
	Status:  http.StatusUnauthorized,
	Message: "Invalid or expired access token",
	Code:    CodeInvalidToken,
}

// UserFromRS256Claims builds the principal a resource server hands its
// handlers from verified RS256 claims, without reading any store.
//
// This is the whole point of resource-server mode: the instance has no user
// database, so the token is the user record. The six named fields are the
// reference base payload (auth.router.ts:378-384) — sub, email, role,
// loginProvider, isEmailVerified, isTotpEnabled — plus tid, which this port
// writes as the tenant (token.go issueToken) and which a tenant-scoped handler
// cannot do without. Everything in the token, those included, is also left in
// CustomClaims, because the reference assigns the entire payload
// (jwks-auth.middleware.ts:69) and a scope or permission claim an issuer adds
// has to reach the handler somehow.
//
// Fields the token cannot carry are zero: no PasswordHash, no Roles, no
// Permissions, no Tenants, no CreatedAt. A handler that needs them has to read
// its own store.
//
// The name says RS256 because that is the path it was written for, but the
// mapping is the claim set, not the algorithm: the middleware's cookie path
// builds its principal with this same function, from the claims of a locally
// verified HS256 token. Both are the same six base claims plus tid, because
// issueToken writes exactly them (token.go).
func UserFromRS256Claims(claims map[string]any) User {
	str := func(name string) string {
		v, _ := claims[name].(string)
		return v
	}
	boolean := func(name string) bool {
		v, _ := claims[name].(bool)
		return v
	}
	user := User{
		ID:              str("sub"),
		Email:           str("email"),
		TenantID:        str("tid"),
		Role:            str("role"),
		LoginProvider:   str("loginProvider"),
		IsEmailVerified: boolean("isEmailVerified"),
		IsTOTPEnabled:   boolean("isTotpEnabled"),
	}
	if len(claims) > 0 {
		user.CustomClaims = make(map[string]any, len(claims))
		for k, v := range claims {
			user.CustomClaims[k] = v
		}
	}
	return user
}

// ResourceServerMiddleware guards a host route in resource-server mode
// (jwks-auth.middleware.ts:37-80).
//
// A bearer token is verified against the remote JWKS; an access-token cookie is
// verified against this instance own HS256 secret. Neither path reads a store:
// the principal is built from the verified claims in both cases, which is what
// makes the middleware usable on the deployment it is named after — an instance
// with no user database. The reference keeps the cookie path for the dashboard
// that hosts the resource server and may itself be logged in, and verifies it
// with tokenService.verifyAccessToken (jwks-auth.middleware.ts:70-73), a bare
// jwt.verify against the HS256 secret with no store access of any kind
// (token.service.ts:143-150).
//
// The two failures are the reference failures, and they differ:
//
//   - no token at all — neither header nor cookie — is
//     403 {"error":"No access token provided"}, code-less, the same body the
//     session middleware writes (jwks-auth.middleware.ts:56-59);
//   - anything else is 401 {"error":"Invalid or expired access token",
//     "code":"INVALID_TOKEN"} (:76-78).
//
// The cookie path here is deliberately not Auth.VerifyAccess, which the
// adapters' session Middleware uses. VerifyAccess checks the session for
// revocation under SessionCheckOn "allcalls"; verifyAccessToken does not, so
// this middleware does not. Two consequences follow, both the reference's: a
// cookie whose subject is not in this instance store is still accepted, and a
// revoked session is accepted until its access token expires — SESSION_REVOKED
// is a code of the session middleware, and this middleware cannot emit it. A
// deployment that wants revocation checked on every call mounts the session
// Middleware instead; it is the one with a database behind it.
//
// The user reaches the handler through UserFromContext on the request context,
// which is what every adapter UserFromContext reads.
//
// One JWKSClient is built per call, so the key cache is shared by every
// request through the returned middleware and not beyond it. The reference
// caches one client per URL for the whole process
// (jwks-auth.middleware.ts:10-23); a host that mounts two middlewares against
// one issuer and wants one cache builds the client once with NewJWKSClient and
// shares it. Nothing on the wire depends on which it does.
func ResourceServerMiddleware(a *Auth, cfg ResourceServerConfig) func(http.Handler) http.Handler {
	client := NewJWKSClient(cfg)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err, ok := resourceServerPrincipal(r, a, client, cfg.Issuer)
			if !ok {
				WriteHTTPError(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithUser(r.Context(), user)))
		})
	}
}

// bearerPrefix is the Authorization scheme the reference selects the bearer
// path on, matched exactly as it matches it: startsWith('Bearer ')
// (jwks-auth.middleware.ts:49).
const bearerPrefix = "Bearer "

// resourceServerPrincipal is the body of the middleware, shared with the
// framework wrappers so that the four adapters cannot answer differently.
func resourceServerPrincipal(r *http.Request, a *Auth, client *JWKSClient, issuer string) (User, HTTPError, bool) {
	// The bearer header is tried first and the cookie second — the order
	// AccessTokenFromRequest uses — but which one supplied the token decides
	// how it is verified, so the two reads stay apart here.
	//
	// The prefix, not the extracted token, is what selects the path, and it is
	// matched case-sensitively and without trimming, because that is what
	// decides the status code: "Authorization: Bearer " with an empty token
	// is a bearer request with no token, which is the code-less 403, and not a
	// request that falls back to a cookie (jwks-auth.middleware.ts:49-59).
	// BearerToken is deliberately not used here: it trims and it matches the
	// scheme case-insensitively, so "bearer x" would take the bearer path where
	// the reference takes the cookie one.
	header := r.Header.Get("Authorization")
	usingBearer := strings.HasPrefix(header, bearerPrefix)
	var token string
	if usingBearer {
		token = header[len(bearerPrefix):]
	} else {
		token = CookieValue(r, AccessTokenCookieName)
	}
	if token == "" {
		return User{}, HTTPErrNoAccessToken, false
	}

	if usingBearer {
		claims, err := VerifyRS256(r.Context(), token, client, issuer)
		if err != nil {
			return User{}, HTTPErrInvalidTokenRS, false
		}
		return UserFromRS256Claims(claims), HTTPError{}, true
	}

	if a == nil {
		// Nothing to verify a local cookie against. Fail closed rather than
		// panic: a resource server may legitimately be wired with no local
		// Auth at all, and a cookie arriving at one is simply not a credential
		// it can read.
		return User{}, HTTPErrInvalidTokenRS, false
	}
	claims, err := a.service.verifyLocalAccessToken(token)
	if err != nil {
		return User{}, HTTPErrInvalidTokenRS, false
	}
	return UserFromRS256Claims(claims), HTTPError{}, true
}

// verifyLocalAccessToken is the reference's verifyAccessToken
// (token.service.ts:143-150) — jwt.verify against the local HS256 secret and
// nothing more — returning the whole verified payload.
//
// It is parseToken's checks (the HS256 allow-list, the signature, iss, typ and
// exp) with the payload handed back as a claim map instead of the seven-field
// struct, and it reads no store: no GetUserByID, no session lookup, none of
// what Service.Authenticate does on top. That is the difference the
// resource-server cookie path needs, and it is the reference's own division —
// its jwt.verify call cannot reach a database because it is not given one.
//
// typ is kept where the reference relies on a second secret: it signs refresh
// tokens with refreshTokenSecret, so a refresh token cannot pass its
// verifyAccessToken, while this port signs both with Config.Secret and tells
// them apart by typ. Dropping the check would turn every refresh token into an
// access credential here, which the reference never does.
func (s *Service) verifyLocalAccessToken(token string) (map[string]any, error) {
	_, claims, err := s.accessTokenPayload(token)
	return claims, err
}

// accessTokenPayload is parseToken for an access token, returning the
// verified payload twice: as the seven-field struct the session check reads,
// and as the whole claim map a principal is built from. It reads no store.
// verifyLocalAccessToken and Service.VerifyAccess are its two callers.
func (s *Service) accessTokenPayload(token string) (tokenClaims, map[string]any, error) {
	parsed, err := s.parseToken(token, "access")
	if err != nil {
		return tokenClaims{}, nil, err
	}
	_, payload, _, err := splitToken(token)
	if err != nil {
		return tokenClaims{}, nil, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return tokenClaims{}, nil, ErrInvalidToken
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return tokenClaims{}, nil, ErrInvalidToken
	}
	return parsed, claims, nil
}

// ResourceServerPrincipal verifies the credential on r the way
// ResourceServerMiddleware does and returns the principal, the error envelope
// to write when there is none, and whether verification succeeded.
//
// It is exported for the framework adapters, which have to put the user into
// their own context rather than into the request context, and for a host
// writing a middleware for a framework this repository does not ship.
func ResourceServerPrincipal(r *http.Request, a *Auth, client *JWKSClient, issuer string) (User, HTTPError, bool) {
	return resourceServerPrincipal(r, a, client, issuer)
}

// userContextKey is the key every adapter stores the authenticated user under.
// It lives here, rather than once per adapter, so that a middleware written in
// this package can hand a user to a handler an adapter mounted.
type userContextKey struct{}

// ContextWithUser returns ctx carrying user as the authenticated principal.
func ContextWithUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, userContextKey{}, user)
}

// UserFromContext reads the authenticated principal a middleware stored.
func UserFromContext(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(userContextKey{}).(User)
	return user, ok
}

// ResourceServerGatedRoutes is the credential surface HTTPConfig.ResourceServer
// unmounts, as method-keyed paths relative to the mount prefix.
//
// Nineteen routes, and the rule behind the list is one sentence: a route is
// here when it mints, delivers or consumes a credential. Nothing more is
// claimed for it — in particular, this is not the set of routes that need a
// local user database; see below.
//
//	POST   /register                  create an account and a password
//	POST   /login                     exchange a password for a session
//	POST   /refresh                   rotate this instance own session
//	POST   /logout                    revoke this instance own session
//	POST   /forgot-password           mint and mail a reset token
//	POST   /reset-password            spend a reset token
//	POST   /change-password           replace a password
//	POST   /send-verification-email    mint and mail a verification token
//	GET    /verify-email              spend a verification token
//	POST   /change-email/request      mint and mail an email-change token
//	POST   /change-email/confirm      spend an email-change token
//	POST   /magic-link/send           mint and mail a login credential
//	POST   /magic-link/verify         spend it for a session
//	POST   /sms/send                  mint and text a login credential
//	POST   /sms/verify                spend it for a session
//	POST   /2fa/setup                 enrol a TOTP secret
//	POST   /2fa/verify-setup          confirm the enrolment
//	POST   /2fa/verify                spend a second factor for a session
//	POST   /2fa/disable               drop the enrolment
//
// What stays mounted is GET /me, the session routes, PATCH /profile,
// POST /add-phone, DELETE /account, and the whole OAuth and account-linking
// group. On an Auth built WithIDP, the JWKS route, <prefix>/userinfo and
// <prefix>/.well-known/openid-configuration stay too — and <prefix>/authorize
// and <prefix>/token do not.
//
// Those four are not in this map, because this map is the base surface's and
// they are routes only under auth.WithIDP; the two gated ones are named by
// OIDCMount.ResourceServerGated, which every adapter reads from the same walk
// that mounts them, and by OpenAPIInfo.OIDC, which drops them from the spec in
// the same breath. The reason they are gated is the definition at the top of
// this file: POST <prefix>/authorize reads an email, a password and a tenant
// off the form and hands them to Service.Login, and POST <prefix>/token spends
// the resulting code for this instance's own HS256 session pair, so leaving
// them mounted would hand a deployment that set this flag to unmount /login and
// /refresh a password-accepting endpoint and a session-minting one in two hops.
// Discovery is metadata, like the JWKS document beside it, and userinfo reads a
// bearer token and returns a profile, which is GET /me's shape and stays for
// GET /me's reason.
//
// Those still need a local user store, and saying otherwise would be a trap:
// /me goes through Service.Authenticate to users.GetUserByID
// (service.go:236,249-255); /profile, /add-phone and /account read and write
// the user store; and GET /oauth/{provider}/callback provisions a user and
// mints a local session, which is a credential this list otherwise gates. They
// stay because the reference mounts them and because a deployment that does
// have a store — a full instance that also accepts another issuer's bearer
// tokens — uses them. Resource-server mode is about credentials, not about
// store independence: the store-less deployment is the one for
// ResourceServerMiddleware, whose two paths read no store at all, and such a
// deployment should not be mounting the auth router's account routes in the
// first place. Gating them here instead would take routes away from the hybrid
// deployment, which is the commoner one, to protect a deployment that has no
// reason to mount them; that is the decision, and it is why the list is what it
// is rather than "every route that touches the user store".
//
// The reference gates six of these — /login, /logout, /refresh, /register,
// /forgot-password and /reset-password (auth.router.ts:541, :590, :622, :713,
// :777, :802) — and leaves the other thirteen mounted, where they fail at
// runtime against a database that is not there. Gating all nineteen is the
// resource-server-gates-all-credential-routes deviation; see
// CompatibilityNotes.
//
// The returned map is freshly built, so a caller may edit it.
func ResourceServerGatedRoutes() map[string]string {
	return map[string]string{
		"/register": http.MethodPost,
		"/login":    http.MethodPost,
		"/refresh":  http.MethodPost,
		"/logout":   http.MethodPost,

		"/forgot-password":         http.MethodPost,
		"/reset-password":          http.MethodPost,
		"/change-password":         http.MethodPost,
		"/send-verification-email": http.MethodPost,
		"/verify-email":            http.MethodGet,
		"/change-email/request":    http.MethodPost,
		"/change-email/confirm":    http.MethodPost,

		"/magic-link/send":   http.MethodPost,
		"/magic-link/verify": http.MethodPost,
		"/sms/send":          http.MethodPost,
		"/sms/verify":        http.MethodPost,
		"/2fa/setup":         http.MethodPost,
		"/2fa/verify-setup":  http.MethodPost,
		"/2fa/verify":        http.MethodPost,
		"/2fa/disable":       http.MethodPost,
	}
}
