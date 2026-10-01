package wiretest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Conformance cases for the OAuth and account-linking group
// (wire-contract.md §4). Everything asserted here is an exact value: a status,
// a literal error message and code, a cookie attribute set, or the exact set of
// top-level body keys. "Non-empty" is only ever used for values the server
// generates at random, and even those get a length or a derivation check.

const testProvider = "acme"

// RunOAuthLinking executes the OAuth and account-linking suite.
func RunOAuthLinking(t *testing.T, mount Mounter) {
	t.Run("OAuthAuthorize", func(t *testing.T) { testOAuthAuthorize(t, mount) })
	t.Run("OAuthCallback", func(t *testing.T) { testOAuthCallback(t, mount) })
	t.Run("OAuthStateVerification", func(t *testing.T) { testOAuthStateVerification(t, mount) })
	t.Run("LinkedAccountsList", func(t *testing.T) { testLinkedAccountsList(t, mount) })
	t.Run("LinkedAccountsDelete", func(t *testing.T) { testLinkedAccountsDelete(t, mount) })
	t.Run("LinkRequest", func(t *testing.T) { testLinkRequest(t, mount) })
	t.Run("LinkVerify", func(t *testing.T) { testLinkVerify(t, mount) })
}

// ── fixture ──────────────────────────────────────────────────────────────────

// fakeOAuthProvider stands in for the identity provider's token and userinfo
// endpoints. It records the token-exchange form so the PKCE assertions can
// check what actually went over the wire.
type fakeOAuthProvider struct {
	server *httptest.Server

	mu            sync.Mutex
	tokenForm     url.Values
	tokenStatus   int
	profileStatus int
	// profile is the userinfo document; setProfile swaps it for a case that
	// needs another shape.
	profile string
}

// flatProfile is the default userinfo document: sub rather than id, so the
// default mapping's second candidate is what the wire exercises;
// email_verified is what a Google-shaped userinfo carries (google.strategy.ts:57)
// and reaches OAuthUserInfo.EmailVerified.
const flatProfile = `{"sub":"acme-1","email":"oauth@example.com","email_verified":true,"name":"OAuth User"}`

// unverifiedProfile is flatProfile with the email_verified claim taken away —
// the common case, since most providers send nothing. It is what
// RequireVerifiedEmail refuses.
const unverifiedProfile = `{"sub":"acme-1","email":"oauth@example.com","name":"OAuth User"}`

// nestedProfile is a document whose identity is buried the way Microsoft
// Graph or a bespoke identity provider buries it: the id two levels down and
// numeric, the address split over mail (null here) and userPrincipalName, the
// verified flag as text, the picture inside an array. Only a ProfileMap can
// read it.
const nestedProfile = `{"data":{"user":{"id":7001,"mail":null,"userPrincipalName":"nested@example.com","verified":"true","profile":{"displayName":"Nested User","photos":[{"url":"https://img.example.com/n.png"}]}}}}`

func newFakeOAuthProvider(t *testing.T) *fakeOAuthProvider {
	t.Helper()
	p := &fakeOAuthProvider{tokenStatus: http.StatusOK, profileStatus: http.StatusOK, profile: flatProfile}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		p.tokenForm = r.PostForm
		status := p.tokenStatus
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"provider-access-token","token_type":"bearer"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		status := p.profileStatus
		profile := p.profile
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(profile))
	})
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakeOAuthProvider) form() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenForm
}

func (p *fakeOAuthProvider) failProfile() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.profileStatus = http.StatusUnauthorized
}

func (p *fakeOAuthProvider) failToken() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenStatus = http.StatusUnauthorized
}

func (p *fakeOAuthProvider) setProfile(doc string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.profile = doc
}

// expiringPendingLinks is a PendingLinkStore that keeps every entry forever and
// backdates the deadline the caller recorded on it.
//
// It is the only configuration in which LINK_TOKEN_EXPIRED is reachable, and that
// is the point: MemoryPendingLinks honours the ttl it is handed, so an aged
// account-link token disappears from the store and /link-verify answers
// INVALID_LINK_TOKEN instead. A store that ignores the ttl — a SQL table without
// a sweeper, say — hands the aged entry back, and LinkVerify has to enforce the
// deadline carried inside it rather than trusting the store.
type expiringPendingLinks struct{ *auth.MemoryPendingLinks }

func (s expiringPendingLinks) Save(ctx context.Context, key string, meta auth.OAuthPendingMeta, _ time.Duration) error {
	if strings.HasPrefix(key, "link-token:") {
		meta.ExpiresAt = time.Now().Add(-time.Minute)
	}
	return s.MemoryPendingLinks.Save(ctx, key, meta, 0)
}

// oauthFixture is an Env with the OAuth wiring attached.
type oauthFixture struct {
	*Env
	provider *fakeOAuthProvider
	users    *auth.MemoryUserStore
	links    *auth.MemoryLinkedAccounts
	pending  *auth.MemoryPendingLinks

	mu        sync.Mutex
	delivered []auth.LinkTokenDelivery
}

type fixtureOptions struct {
	// omitStores drops the linking stores, the port's analogue of the
	// reference's "route not mounted without linkedAccountsStore".
	omitStores bool
	// omitPending drops only the stash, which is what turns the state nonce from
	// single-use back into merely signed.
	omitPending bool
	// expiringPending swaps in a stash that ignores the ttl and backdates the
	// deadline it was handed, so an account-link token comes back already expired.
	expiringPending bool
	allowed         []string
	// siteURL overrides the fallback redirect target. The reference's redirect
	// resolution has quirks that only show up when the site url carries a base
	// path or a trailing slash.
	siteURL string
	// stateTTL bounds the signed state. Zero means the 10-minute default.
	stateTTL time.Duration
	// profileMap is the provider's declarative profile mapping. nil keeps the
	// default mapping.
	profileMap map[string]string
	// provisioning is the callback's provisioning policy. nil is the wiring's
	// own default — create, and answer an address another account holds with
	// the account conflict (issue #36) — which is what every case runs under
	// unless it says otherwise.
	provisioning *auth.OAuthProvisioning
}

const fixtureSiteURL = "https://app.example.com"

func newOAuthFixture(t *testing.T, mount Mounter, opts fixtureOptions) *oauthFixture {
	t.Helper()
	provider := newFakeOAuthProvider(t)
	fixture := &oauthFixture{
		provider: provider,
		users:    auth.NewMemoryUserStore(),
		links:    auth.NewMemoryLinkedAccounts(),
		pending:  auth.NewMemoryPendingLinks(),
	}
	siteURL := fixtureSiteURL
	if opts.siteURL != "" {
		siteURL = opts.siteURL
	}
	wiring := auth.OAuthWiring{
		Service: auth.NewOAuthService(auth.OAuthProvider{
			Name:         testProvider,
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "https://api.example.com/auth/oauth/acme/callback",
			AuthURL:      "https://provider.example.com/authorize",
			TokenURL:     provider.server.URL + "/token",
			UserInfoURL:  provider.server.URL + "/userinfo",
			Scopes:       []string{"openid", "email"},
			ProfileMap:   opts.profileMap,
		}),
		LinkedAccounts: fixture.links,
		PendingLinks:   fixture.pending,
		AllowedOrigins: opts.allowed,
		SiteURL:        siteURL,
		TenantID:       "t1",
		StateTTL:       opts.stateTTL,
		Provisioning:   opts.provisioning,
		DeliverLinkToken: func(_ context.Context, delivery auth.LinkTokenDelivery) error {
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			fixture.delivered = append(fixture.delivered, delivery)
			return nil
		},
	}
	if opts.omitStores {
		wiring.LinkedAccounts = nil
		wiring.PendingLinks = nil
	}
	if opts.omitPending {
		wiring.PendingLinks = nil
	}
	if opts.expiringPending {
		wiring.PendingLinks = expiringPendingLinks{MemoryPendingLinks: fixture.pending}
	}
	fixture.Env = NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(fixture.users), auth.WithOAuth(wiring))
	return fixture
}

func (f *oauthFixture) lastDelivery(t *testing.T) auth.LinkTokenDelivery {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.delivered) == 0 {
		t.Fatal("no account-link token was delivered")
	}
	return f.delivered[len(f.delivered)-1]
}

// begin drives GET <prefix>/oauth/<provider> and returns the parsed redirect.
func (f *oauthFixture) begin(t *testing.T, query string, headers map[string]string) *url.URL {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/oauth/"+testProvider+query, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := f.Do(req)
	AssertStatus(t, rec, http.StatusFound)
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location %q: %v", rec.Header().Get("Location"), err)
	}
	return location
}

func (f *oauthFixture) callback(t *testing.T, code, state string) *httptest.ResponseRecorder {
	t.Helper()
	target := f.Config.Prefix() + "/oauth/" + testProvider + "/callback?code=" + url.QueryEscape(code)
	if state != "" {
		target += "&state=" + url.QueryEscape(state)
	}
	return f.Do(httptest.NewRequest(http.MethodGet, target, nil))
}

// sessionUser resolves whose session a response's access-token cookie carries.
// Which identity the callback hands out is the whole point of the OAuth login
// route, so it is asserted directly rather than through the token's shape.
func (f *oauthFixture) sessionUser(t *testing.T, rec *httptest.ResponseRecorder) auth.User {
	t.Helper()
	cookie := Cookie(t, rec, hostAccess)
	user, err := f.Auth.Me(context.Background(), cookie.Value)
	if err != nil {
		t.Fatalf("resolve the issued session: %v", err)
	}
	return user
}

// linkedAccountEntries drives GET /linked-accounts as the holder of token.
func (f *oauthFixture) linkedAccountEntries(t *testing.T, token string) []any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/linked-accounts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := f.Do(req)
	AssertStatus(t, rec, http.StatusOK)
	body := Body(t, rec)
	AssertKeys(t, body, "linkedAccounts")
	entries, ok := body["linkedAccounts"].([]any)
	if !ok {
		t.Fatalf("linkedAccounts = %v, want an array", body["linkedAccounts"])
	}
	return entries
}

// decodeStatePayload splits the signed state and decodes the payload half.
func decodeStatePayload(t *testing.T, state string) map[string]any {
	t.Helper()
	encoded, signature, found := strings.Cut(state, ".")
	if !found {
		t.Fatalf("state %q is not signed: expected <payload>.<signature>", state)
	}
	if signature == "" {
		t.Fatalf("state %q carries an empty signature", state)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("state payload is not base64url: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("state payload is not JSON: %v", err)
	}
	return payload
}

// ── GET /oauth/{provider} ────────────────────────────────────────────────────

func testOAuthAuthorize(t *testing.T, mount Mounter) {
	t.Run("redirects to the provider with a signed state and an S256 challenge", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "?return_path=/dashboard", map[string]string{"Origin": fixtureSiteURL})

		if got := location.Scheme + "://" + location.Host + location.Path; got != "https://provider.example.com/authorize" {
			t.Fatalf("authorization endpoint = %q", got)
		}
		query := location.Query()
		for key, want := range map[string]string{
			"client_id":             "test-client-id",
			"redirect_uri":          "https://api.example.com/auth/oauth/acme/callback",
			"response_type":         "code",
			"scope":                 "openid email",
			"code_challenge_method": "S256",
		} {
			if got := query.Get(key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		// 32 bytes of SHA-256 render as 43 base64url characters.
		if challenge := query.Get("code_challenge"); len(challenge) != 43 {
			t.Errorf("code_challenge = %q, want 43 base64url characters", challenge)
		}

		payload := decodeStatePayload(t, query.Get("state"))
		if nonce, _ := payload["n"].(string); len(nonce) != 32 {
			t.Errorf("state nonce = %v, want 32 hex characters", payload["n"])
		}
		if payload["o"] != fixtureSiteURL {
			t.Errorf("state origin = %v, want %q", payload["o"], fixtureSiteURL)
		}
		if payload["p"] != "/dashboard" {
			t.Errorf("state return path = %v, want %q", payload["p"], "/dashboard")
		}
		if issued, _ := payload["t"].(float64); issued <= 0 {
			t.Errorf("state issued-at = %v, want a unix timestamp", payload["t"])
		}
	})

	t.Run("an origin outside the allowlist falls back to the site url", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": "https://evil.example.net"})
		payload := decodeStatePayload(t, location.Query().Get("state"))
		if payload["o"] != fixtureSiteURL {
			t.Fatalf("state origin = %v, want the configured site url %q", payload["o"], fixtureSiteURL)
		}
	})

	// The reference registers a JSON stub only for google and github and lets
	// every other unregistered name fall through to Express's HTML 404. One
	// dynamic route cannot do that, so every unregistered name gets the stub —
	// with the reference's per-provider wording for the two it names. Both the
	// authorize and the callback route answer it.
	t.Run("unregistered provider", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		for name, want := range map[string]string{
			"google": "Google OAuth not configured",
			"github": "GitHub OAuth not configured",
			"nope":   "nope OAuth not configured",
		} {
			rec := f.Do(httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/oauth/"+name, nil))
			AssertError(t, rec, http.StatusNotFound, want, "")

			rec = f.Do(httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/oauth/"+name+"/callback?code=c&state=s", nil))
			AssertError(t, rec, http.StatusNotFound, want, "")
		}
	})

	// The route reads no credential off the initiating request, and nothing on
	// that request may steer which account the provider identity lands on.
	//
	// The reference's /oauth/{provider} has no auth gate (wire-contract.md §4:
	// "Auth gate: none") and does not carry a link intent in the state; the
	// callback resolves the identity purely through the provider account. Treating
	// "somebody is signed in" as "link to that account" is an account-takeover
	// shape, so it is pinned from the outside: whoever holds a session when the
	// flow starts must not change the outcome by one byte.
	t.Run("a signed-in initiator does not capture the provider identity", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		// The fake provider's profile is sub=acme-1 / oauth@example.com, and that
		// account already belongs to the victim.
		victim, _ := f.Seed("victim@example.com")
		if err := f.links.Save(context.Background(), auth.OAuthLinkedAccount{
			ID: "lnk_victim", UserID: victim.ID, Provider: testProvider, ProviderID: "acme-1",
			Email: "oauth@example.com", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed the victim's link: %v", err)
		}
		_, intruderTokens := f.Seed("intruder@example.com")

		// The intruder starts the flow with their own session attached. The
		// callback that follows carries no credential of theirs at all.
		location := f.begin(t, "", map[string]string{
			"Origin":        fixtureSiteURL,
			"Authorization": "Bearer " + intruderTokens.AccessToken,
		})
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertStatus(t, rec, http.StatusFound)

		if got := f.sessionUser(t, rec).Email; got != "victim@example.com" {
			t.Fatalf("the callback issued a session for %q, want the provider account's owner %q", got, "victim@example.com")
		}
		link, err := f.links.FindByProvider(context.Background(), testProvider, "acme-1")
		if err != nil {
			t.Fatalf("the victim's link disappeared: %v", err)
		}
		if link.UserID != victim.ID {
			t.Fatalf("(acme, acme-1) was re-pointed from the victim to %q", link.UserID)
		}
		if entries := f.linkedAccountEntries(t, intruderTokens.AccessToken); len(entries) != 0 {
			t.Fatalf("the initiator gained a link row: %v", entries)
		}
	})

	// The same rule where the provider account is unknown: the callback creates
	// the account the profile describes instead of adopting the initiator's.
	t.Run("a signed-in initiator does not adopt an unknown provider account", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		_, tokens := f.Seed("initiator@example.com")

		location := f.begin(t, "", map[string]string{
			"Origin":        fixtureSiteURL,
			"Authorization": "Bearer " + tokens.AccessToken,
		})
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertStatus(t, rec, http.StatusFound)

		if got := f.sessionUser(t, rec).Email; got != "oauth@example.com" {
			t.Fatalf("the callback issued a session for %q, want the provider profile's address %q", got, "oauth@example.com")
		}
		if entries := f.linkedAccountEntries(t, tokens.AccessToken); len(entries) != 0 {
			t.Fatalf("the initiator gained a link row: %v", entries)
		}
	})
}

// ── GET /oauth/{provider}/callback ───────────────────────────────────────────

func testOAuthCallback(t *testing.T, mount Mounter) {
	t.Run("issues cookies and redirects to the state origin", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "?return_path=/dashboard", map[string]string{"Origin": fixtureSiteURL})
		challenge := location.Query().Get("code_challenge")

		rec := f.callback(t, "auth-code", location.Query().Get("state"))
		AssertStatus(t, rec, http.StatusFound)
		if got := rec.Header().Get("Location"); got != fixtureSiteURL+"/dashboard" {
			t.Fatalf("Location = %q, want %q", got, fixtureSiteURL+"/dashboard")
		}
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())

		// PKCE actually reached the provider, and the verifier matches the
		// challenge the authorization request advertised.
		form := f.provider.form()
		if got := form.Get("grant_type"); got != "authorization_code" {
			t.Errorf("grant_type = %q", got)
		}
		if got := form.Get("code"); got != "auth-code" {
			t.Errorf("code = %q, want %q", got, "auth-code")
		}
		verifier := form.Get("code_verifier")
		if len(verifier) < 43 || len(verifier) > 128 {
			t.Fatalf("code_verifier = %q, want 43..128 characters (RFC 7636)", verifier)
		}
		sum := sha256.Sum256([]byte(verifier))
		if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != challenge {
			t.Fatalf("S256(code_verifier) = %q, want the advertised challenge %q", got, challenge)
		}
	})

	// The reference ignores X-Auth-Strategy on redirect flows: issueTokens with
	// a redirectTo always takes the cookie branch.
	t.Run("the bearer header does not change a redirect flow", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		target := f.Config.Prefix() + "/oauth/" + testProvider + "/callback?code=c&state=" + url.QueryEscape(location.Query().Get("state"))
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := f.Do(req)

		AssertStatus(t, rec, http.StatusFound)
		if got := rec.Header().Get("Location"); got != fixtureSiteURL {
			t.Fatalf("Location = %q, want %q", got, fixtureSiteURL)
		}
		Cookie(t, rec, hostAccess)
		if body := rec.Body.String(); strings.Contains(body, "accessToken") {
			t.Fatalf("redirect body leaked a token: %s", body)
		}
	})

	// The reference appends the state's `p` only inside the accepted-origin
	// branch and returns getDefaultSiteUrl(config) bare otherwise
	// (auth.router.ts:325-351). `p` is the caller's own return_path query param,
	// so a rejected origin must contribute nothing to the redirect. Here SiteURL
	// is deliberately outside the allowlist, which is the configuration the
	// reference cannot express because it derives its allowlist from
	// config.email.siteUrl.
	t.Run("a rejected state origin drops the return path too", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{"https://other.example"}})
		location := f.begin(t, "?return_path=/dashboard", nil)
		if payload := decodeStatePayload(t, location.Query().Get("state")); payload["p"] != "/dashboard" {
			t.Fatalf("state return path = %v, want %q", payload["p"], "/dashboard")
		}
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertStatus(t, rec, http.StatusFound)
		if got := rec.Header().Get("Location"); got != fixtureSiteURL {
			t.Fatalf("Location = %q, want the bare site url %q", got, fixtureSiteURL)
		}
	})

	t.Run("the callback links the provider account to the resolved user", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		AssertStatus(t, f.callback(t, "c", location.Query().Get("state")), http.StatusFound)

		link, err := f.links.FindByProvider(context.Background(), testProvider, "acme-1")
		if err != nil {
			t.Fatalf("provider account was not linked: %v", err)
		}
		if link.Provider != testProvider || link.ProviderID != "acme-1" {
			t.Fatalf("link = %+v", link)
		}
		// The reference's linkAccount always carries the callback profile's email
		// (auth.router.ts:1336-1343), and GET /linked-accounts renders it. A link
		// row that cannot carry an address makes the family admin UI fall all the
		// way through to the raw provider id.
		if link.Email != "oauth@example.com" {
			t.Fatalf("link email = %q, want the callback profile's %q", link.Email, "oauth@example.com")
		}
	})

	// A user the callback creates records the provider that created it, the
	// way the reference's strategies document creating one
	// (`userStore.create({ email, loginProvider: 'microsoft' })`,
	// generic-oauth.strategy.ts:92), and /me reports it under loginProvider —
	// where a password account says "local" (auth.router.ts:379).
	t.Run("a user the callback creates reports the provider as loginProvider", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertStatus(t, rec, http.StatusFound)
		if user := f.sessionUser(t, rec); user.LoginProvider != testProvider {
			t.Fatalf("LoginProvider = %q, want %q", user.LoginProvider, testProvider)
		}
		me := f.Do(Replay(httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/me", nil), rec))
		AssertStatus(t, me, http.StatusOK)
		if got := Body(t, me)["loginProvider"]; got != testProvider {
			t.Fatalf("loginProvider = %v, want %q (body %s)", got, testProvider, me.Body.String())
		}
	})

	// The fake profile carries email_verified, as Google's userinfo does. The
	// claim is mapped onto OAuthUserInfo.EmailVerified and must not disturb the
	// login: the callback still issues the session for the profile's address, and
	// the created account is verified. Under the default policy a claim of false
	// would be believed (D-11) and a missing claim still means verified, which is
	// what this deployment — one that configures no provisioning — always got.
	t.Run("a profile carrying email_verified still logs in", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertStatus(t, rec, http.StatusFound)
		user := f.sessionUser(t, rec)
		if user.Email != "oauth@example.com" {
			t.Fatalf("the callback issued a session for %q, want %q", user.Email, "oauth@example.com")
		}
		if !user.IsEmailVerified {
			t.Fatal("an account the callback creates is verified, as before")
		}
		if _, err := f.links.FindByProvider(context.Background(), testProvider, "acme-1"); err != nil {
			t.Fatalf("provider account was not linked: %v", err)
		}
	})

	// The reference's own resolveOAuthRedirect quirks, reproduced rather than
	// improved on: three shipped clients are built against this Location header.
	t.Run("the redirect reproduces the reference's base-path handling", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			siteURL string
			path    string
			want    string
		}{
			// basePath "/ex", cleanPath "/example": the reference's test is a loose
			// startsWith with no segment boundary, so it fires and the origin's base
			// path is dropped in favour of the return path. A segment-boundary test
			// would answer https://ex.example.com/ex/example instead.
			{"loose prefix drops the base path", "https://ex.example.com/ex", "/example", "https://ex.example.com/example"},
			// The de-duplication the quirk exists for: the base path is not doubled.
			{"a repeated base path is not doubled", "https://ex.example.com/app", "/app/dash", "https://ex.example.com/app/dash"},
			// basePath becomes "" after the trailing slash is stripped, which is
			// falsy in the reference, so it concatenates and the slash doubles.
			{"a trailing-slash origin doubles the slash", "https://ex.example.com/", "/dash", "https://ex.example.com//dash"},
			// No base path at all: plain concatenation.
			{"no base path", "https://ex.example.com", "/dash", "https://ex.example.com/dash"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// An empty allowlist accepts the state's own origin, which is the
				// configuration in which the state's `o` reaches the append branch.
				f := newOAuthFixture(t, mount, fixtureOptions{siteURL: tc.siteURL})
				location := f.begin(t, "?return_path="+url.QueryEscape(tc.path), nil)
				rec := f.callback(t, "c", location.Query().Get("state"))
				AssertStatus(t, rec, http.StatusFound)
				if got := rec.Header().Get("Location"); got != tc.want {
					t.Fatalf("Location = %q, want %q", got, tc.want)
				}
			})
		}
	})

	// The other half of the exchange: the token endpoint refusing the code. Only
	// the profile failure was covered before.
	t.Run("token exchange failure", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		f.provider.failToken()
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertError(t, rec, http.StatusUnauthorized, "OAuth token exchange failed", auth.CodeOAuthTokenExchangeFail)
	})

	// A provider that answers the userinfo call with an error must not produce a
	// user with an empty email. The reference emits OAUTH_PROFILE_FAILED here.
	t.Run("profile failure", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		f.provider.failProfile()
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertError(t, rec, http.StatusUnauthorized, "Failed to get OAuth user profile", auth.CodeOAuthProfileFailed)
	})

	// The declarative counterpart of the reference's mapProfile hook
	// (generic-oauth.strategy.ts:71-77, applied :151-153) over a userinfo
	// document the default mapping cannot read: the session is issued for the
	// address the map resolved, and the provider account is linked under the
	// id it resolved — a JSON number, rendered as JavaScript would.
	t.Run("a ProfileMap maps a nested userinfo document", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{
			allowed: []string{fixtureSiteURL},
			profileMap: map[string]string{
				"id":            "$.data.user.id",
				"email":         "$.data.user.mail ?? $.data.user.userPrincipalName",
				"emailVerified": "$.data.user.verified",
				"name":          "$.data.user.profile.displayName",
				"picture":       "$.data.user.profile.photos[0].url",
			},
		})
		f.provider.setProfile(nestedProfile)
		location := f.begin(t, "?return_path=/dashboard", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertStatus(t, rec, http.StatusFound)
		if got := rec.Header().Get("Location"); got != fixtureSiteURL+"/dashboard" {
			t.Fatalf("Location = %q, want %q", got, fixtureSiteURL+"/dashboard")
		}
		user := f.sessionUser(t, rec)
		if user.Email != "nested@example.com" {
			t.Fatalf("the callback issued a session for %q, want the mapped %q", user.Email, "nested@example.com")
		}
		if user.LoginProvider != testProvider {
			t.Fatalf("LoginProvider = %q, want %q", user.LoginProvider, testProvider)
		}
		link, err := f.links.FindByProvider(context.Background(), testProvider, "7001")
		if err != nil {
			t.Fatalf("provider account 7001 was not linked: %v", err)
		}
		if link.Email != "nested@example.com" {
			t.Fatalf("link email = %q, want the mapped %q", link.Email, "nested@example.com")
		}
		if _, err := f.links.FindByProvider(context.Background(), testProvider, "acme-1"); err == nil {
			t.Fatal("the default mapping's subject was linked as well")
		}
	})

	// The map is the whole mapping: a document it cannot resolve an id from is
	// a profile failure on the wire, the reference's OAUTH_PROFILE_FAILED, and
	// no user is created for it.
	t.Run("a ProfileMap that resolves no id is a profile failure", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{
			allowed:    []string{fixtureSiteURL},
			profileMap: map[string]string{"id": "$.data.user.id", "email": "$.email"},
		})
		// The default flat document has an email but no data.user.id.
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertError(t, rec, http.StatusUnauthorized, "Failed to get OAuth user profile", auth.CodeOAuthProfileFailed)
		if _, err := f.users.GetUserByEmail(context.Background(), "oauth@example.com", "t1"); err == nil {
			t.Fatal("a user was created for a profile that failed to map")
		}
	})

	testOAuthProvisioning(t, mount)
}

// ── the provisioning policy ──────────────────────────────────────────────────

// conflictPolicy is the policy the account-conflict cases run under: the
// reference's outcome for a provider account asserting an address that already
// belongs to somebody.
func conflictPolicy() *auth.OAuthProvisioning {
	policy := auth.DefaultOAuthProvisioning()
	policy.OnEmailMatch = auth.OAuthEmailMatchConflict
	return &policy
}

// conflictStashKey is the reference's (email, provider) stash key, spelled out
// rather than built, so the cases pin the key a host store has to index.
const conflictStashKey = "pending-link:oauth@example.com|acme"

// testOAuthProvisioning covers the callback outcomes the provisioning policy
// adds: the reference's account-conflict redirect, and the three refusals that
// are this port's own (compatibility.go). Everything before this ran under the
// default policy, whose answer to an address another account holds is the
// conflict; the first cases here pin that default, the rest name a policy.
func testOAuthProvisioning(t *testing.T, mount Mounter) {
	// Issue #36: the default policy — a wiring that sets no Provisioning at all
	// — answers an address another account holds with the reference's conflict,
	// as the findOrCreateUser the reference documents does (README.detailed.md
	// "OAuth Strategies" at 1.10.8). Through 0.12.0 this exact request signed
	// the provider account into the holder's account.
	t.Run("the default policy answers an address another account holds with the conflict", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		f.Seed("oauth@example.com")
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))

		AssertStatus(t, rec, http.StatusFound)
		want := fixtureSiteURL + f.Config.Prefix() +
			"/account-conflict?provider=acme&code=OAUTH_ACCOUNT_CONFLICT&email=oauth%40example.com"
		if got := rec.Header().Get("Location"); got != want {
			t.Fatalf("Location = %q, want %q", got, want)
		}
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)
		if _, err := f.links.FindByProvider(context.Background(), testProvider, "acme-1"); err == nil {
			t.Fatal("the default policy linked the provider account by address")
		}
		if _, err := f.pending.Get(context.Background(), conflictStashKey); err != nil {
			t.Fatalf("the default policy stashed nothing under %q: %v", conflictStashKey, err)
		}
	})

	// The old behaviour is still there for a host that asks for it by name.
	t.Run("an explicit link policy still links by address and signs the holder in", func(t *testing.T) {
		policy := auth.DefaultOAuthProvisioning()
		policy.OnEmailMatch = auth.OAuthEmailMatchLink
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}, provisioning: &policy})
		holder, _ := f.Seed("oauth@example.com")
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))

		AssertStatus(t, rec, http.StatusFound)
		if got := rec.Header().Get("Location"); got != fixtureSiteURL {
			t.Fatalf("Location = %q, want the login redirect %q", got, fixtureSiteURL)
		}
		if got := f.sessionUser(t, rec).ID; got != holder.ID {
			t.Fatalf("the callback issued a session for %q, want the holder %q", got, holder.ID)
		}
		link, err := f.links.FindByProvider(context.Background(), testProvider, "acme-1")
		if err != nil || link.UserID != holder.ID {
			t.Fatalf("link = %+v (%v), want one pointing at the holder", link, err)
		}
	})

	// The reference builds the conflict page on the state's bare origin
	// (conflictOrigin, auth.router.ts:1992-1995 at 1.10.8), not on the
	// resolveOAuthRedirect value a successful login is sent to, so the
	// return_path the flow began with is not in the Location.
	t.Run("the conflict page is on the site's origin, not under the return path", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		f.Seed("oauth@example.com")
		location := f.begin(t, "?return_path=/dashboard", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))

		AssertStatus(t, rec, http.StatusFound)
		want := fixtureSiteURL + f.Config.Prefix() +
			"/account-conflict?provider=acme&code=OAUTH_ACCOUNT_CONFLICT&email=oauth%40example.com"
		if got := rec.Header().Get("Location"); got != want {
			t.Fatalf("Location = %q, want %q", got, want)
		}
	})

	// encodeURIComponent, not url.QueryEscape: an apostrophe, which a local
	// part may hold, stays bare (auth.router.ts:2000 at 1.10.8).
	t.Run("the address is escaped as encodeURIComponent escapes it", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		f.provider.setProfile(`{"sub":"acme-1","email":"o'brien+x@example.com","email_verified":true}`)
		f.Seed("o'brien+x@example.com")
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))

		AssertStatus(t, rec, http.StatusFound)
		want := fixtureSiteURL + f.Config.Prefix() +
			"/account-conflict?provider=acme&code=OAUTH_ACCOUNT_CONFLICT&email=o'brien%2Bx%40example.com"
		if got := rec.Header().Get("Location"); got != want {
			t.Fatalf("Location = %q, want %q", got, want)
		}
	})

	// The reference's conflict: stash (email, provider, providerAccountId) and
	// redirect to buildUiLink(siteUrl, "/account-conflict?…")
	// (auth.router.ts:1346-1355). No session, no link row, and the query the
	// front-end reads is the reference's exactly.
	t.Run("an address another account holds redirects to the conflict page", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}, provisioning: conflictPolicy()})
		f.Seed("oauth@example.com")
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))

		AssertStatus(t, rec, http.StatusFound)
		want := fixtureSiteURL + f.Config.Prefix() +
			"/account-conflict?provider=acme&code=OAUTH_ACCOUNT_CONFLICT&email=oauth%40example.com"
		if got := rec.Header().Get("Location"); got != want {
			t.Fatalf("Location = %q, want %q", got, want)
		}
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)
		if _, err := f.links.FindByProvider(context.Background(), testProvider, "acme-1"); err == nil {
			t.Fatal("the conflict linked the provider account it refused to link")
		}

		meta, err := f.pending.Get(context.Background(), conflictStashKey)
		if err != nil {
			t.Fatalf("nothing was stashed under %q: %v", conflictStashKey, err)
		}
		if meta.ProviderAccountID != "acme-1" || meta.Provider != testProvider || meta.TenantID != "t1" {
			t.Fatalf("stash = %+v, want the provider account, the provider and the callback tenant", meta)
		}
	})

	// The whole reference story, end to end and for the first time: the stash
	// the callback parked is what lets an unauthenticated /link-request resolve
	// an identity, and /link-verify then makes the link under the stashed
	// provider account id rather than under the address.
	t.Run("the stash completes through link-request and link-verify", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}, provisioning: conflictPolicy()})
		holder, holderTokens := f.Seed("oauth@example.com")

		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertStatus(t, rec, http.StatusFound)

		// The front-end reads provider and email off the redirect query, which is
		// the only reason they are in it.
		conflictURL, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse the conflict redirect: %v", err)
		}
		query := conflictURL.Query()
		if query.Get("code") != auth.CodeOAuthAccountConflict {
			t.Fatalf("code = %q, want %q", query.Get("code"), auth.CodeOAuthAccountConflict)
		}

		req := csrfPair(f.Request(http.MethodPost, "/link-request", map[string]any{
			"email": query.Get("email"), "provider": query.Get("provider"),
		}))
		AssertStatus(t, f.Do(req), http.StatusOK)
		token := f.lastDelivery(t).Token
		AssertStatus(t, f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token})), http.StatusOK)

		entries := f.linkedAccountEntries(t, holderTokens.AccessToken)
		if len(entries) != 1 {
			t.Fatalf("linkedAccounts = %v, want the one the conflict flow made", entries)
		}
		entry, _ := entries[0].(map[string]any)
		if entry["providerAccountId"] != "acme-1" {
			t.Fatalf("providerAccountId = %v, want the stashed %q", entry["providerAccountId"], "acme-1")
		}

		// The stash is consumed with the token it authorised.
		if _, err := f.pending.Get(context.Background(), conflictStashKey); err == nil {
			t.Fatal("the stash survived the link it authorised")
		}

		// And the provider account is now known, so the same callback is an
		// ordinary login rather than a conflict.
		location = f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		rec = f.callback(t, "c", location.Query().Get("state"))
		AssertStatus(t, rec, http.StatusFound)
		if got := rec.Header().Get("Location"); got != fixtureSiteURL {
			t.Fatalf("Location = %q, want the ordinary login redirect %q", got, fixtureSiteURL)
		}
		if got := f.sessionUser(t, rec).ID; got != holder.ID {
			t.Fatalf("the callback issued a session for %q, want the linked holder %q", got, holder.ID)
		}
	})

	// The three refusals, all JSON on the callback — the reference's own choice
	// for everything on this route that is not the account conflict — and none
	// of them leaving an account or a link behind.
	t.Run("refusals", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			policy  func(*auth.OAuthProvisioning)
			profile string
			seed    bool
			status  int
			message string
			code    string
		}{
			{
				name:    "the provider asserted nothing about the address",
				policy:  func(p *auth.OAuthProvisioning) { p.RequireVerifiedEmail = true },
				profile: unverifiedProfile,
				status:  http.StatusForbidden,
				message: "OAuth email address is not verified",
				code:    auth.CodeOAuthEmailNotVerified,
			},
			{
				name:    "the address is outside the allowed domains",
				policy:  func(p *auth.OAuthProvisioning) { p.AllowedEmailDomains = []string{"acme.example"} },
				status:  http.StatusForbidden,
				message: "OAuth email domain is not allowed",
				code:    auth.CodeOAuthEmailDomainNotAllowed,
			},
			{
				name:    "the deployment does not create accounts",
				policy:  func(p *auth.OAuthProvisioning) { p.AutoCreate = false },
				status:  http.StatusForbidden,
				message: "No account is provisioned for this OAuth identity",
				code:    auth.CodeOAuthUserNotProvisioned,
			},
			{
				name:    "the address belongs to an account and linking is refused",
				policy:  func(p *auth.OAuthProvisioning) { p.OnEmailMatch = auth.OAuthEmailMatchReject },
				seed:    true,
				status:  http.StatusForbidden,
				message: "No account is provisioned for this OAuth identity",
				code:    auth.CodeOAuthUserNotProvisioned,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				policy := auth.DefaultOAuthProvisioning()
				tc.policy(&policy)
				f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}, provisioning: &policy})
				if tc.profile != "" {
					f.provider.setProfile(tc.profile)
				}
				if tc.seed {
					f.Seed("oauth@example.com")
				}
				location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
				rec := f.callback(t, "c", location.Query().Get("state"))

				AssertError(t, rec, tc.status, tc.message, tc.code)
				AssertNoCookie(t, rec, hostAccess)
				if location := rec.Header().Get("Location"); location != "" {
					t.Fatalf("a refusal redirected to %q; the reference answers JSON here", location)
				}
				if _, err := f.links.FindByProvider(context.Background(), testProvider, "acme-1"); err == nil {
					t.Fatal("a refused callback wrote a link row")
				}
				if !tc.seed {
					if _, err := f.users.GetUserByEmail(context.Background(), "oauth@example.com", "t1"); err == nil {
						t.Fatal("a refused callback created the account anyway")
					}
				}
			})
		}
	})

	// The other side of RequireVerifiedEmail: the fake profile does carry
	// email_verified, so a provider that asserts the address is admitted and the
	// account it creates is verified.
	t.Run("an asserted address passes RequireVerifiedEmail", func(t *testing.T) {
		policy := auth.DefaultOAuthProvisioning()
		policy.RequireVerifiedEmail = true
		policy.AllowedEmailDomains = []string{"Example.com"}
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}, provisioning: &policy})
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))

		AssertStatus(t, rec, http.StatusFound)
		user := f.sessionUser(t, rec)
		if user.Email != "oauth@example.com" || !user.IsEmailVerified {
			t.Fatalf("user = %+v, want the profile address, verified", user)
		}
	})
}

// ── the #10 fix ──────────────────────────────────────────────────────────────

// testOAuthStateVerification is the security half of this group. The reference
// generates a state nonce and never reads it (wire-contract.md §4, gap 4);
// every case here fails against that behaviour.
func testOAuthStateVerification(t *testing.T, mount Mounter) {
	newState := func(t *testing.T, f *oauthFixture) string {
		t.Helper()
		return f.begin(t, "", map[string]string{"Origin": fixtureSiteURL}).Query().Get("state")
	}

	t.Run("a missing state is rejected", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		AssertError(t, f.callback(t, "c", ""), http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
	})

	// The nonce is kept intact so the stash lookup would succeed: only the
	// signature can reject this, which is what makes the case a test of the
	// signature rather than of the replay defence behind it.
	t.Run("a tampered payload is rejected", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		state := newState(t, f)
		payload, signature, _ := strings.Cut(state, ".")
		nonce, _ := decodeStatePayload(t, state)["n"].(string)
		// Re-point the redirect origin at an attacker while keeping the original
		// nonce and signature: the classic open redirect through the state.
		forged := base64.RawURLEncoding.EncodeToString([]byte(
			`{"n":"` + nonce + `","o":"https://evil.example.net","t":` + nowUnixString() + `}`))
		if forged == payload {
			t.Fatal("forged payload accidentally equals the real one")
		}
		rec := f.callback(t, "c", forged+"."+signature)
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
		if location := rec.Header().Get("Location"); location != "" {
			t.Fatalf("tampered state produced a redirect to %q", location)
		}
	})

	// This is the shape the reference emits: plain base64url JSON, no signature.
	// Again the real nonce is reused, so the stash cannot be what rejects it.
	t.Run("an unsigned reference-style state is rejected", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		nonce, _ := decodeStatePayload(t, newState(t, f))["n"].(string)
		unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"n":"` + nonce + `","o":"` + fixtureSiteURL + `"}`))
		rec := f.callback(t, "c", unsigned)
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
	})

	t.Run("a signature over a different payload is rejected", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		first := newState(t, f)
		second := newState(t, f)
		payload, _, _ := strings.Cut(first, ".")
		_, signature, _ := strings.Cut(second, ".")
		rec := f.callback(t, "c", payload+"."+signature)
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
	})

	// Single use. With the stash configured the nonce is consumed by the first
	// callback, so an intercepted state cannot be replayed inside its TTL.
	t.Run("a replayed state is rejected", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		state := newState(t, f)
		AssertStatus(t, f.callback(t, "c", state), http.StatusFound)
		AssertError(t, f.callback(t, "c", state), http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
	})

	// The TTL is the other half of "signed and time-bounded". The stash is omitted
	// on purpose so that only the deadline in the `t` claim can reject this: with
	// a stash configured the nonce entry would expire on the same clock and the
	// lookup would be what failed.
	t.Run("a state past its TTL is rejected", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{
			omitPending: true,
			allowed:     []string{fixtureSiteURL},
			stateTTL:    time.Nanosecond,
		})
		state := newState(t, f)
		// The `t` claim has one-second resolution, so the elapsed time has to be
		// unambiguously past a one-nanosecond deadline.
		time.Sleep(5 * time.Millisecond)
		AssertError(t, f.callback(t, "c", state), http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
	})

	// Without a stash the state stays signed and time-bounded but replayable —
	// pinned so the degradation is a documented property, not a surprise.
	t.Run("without a pending-link store the state is signed but replayable", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{omitPending: true, allowed: []string{fixtureSiteURL}})
		state := newState(t, f)
		AssertStatus(t, f.callback(t, "c", state), http.StatusFound)
		AssertStatus(t, f.callback(t, "c", state), http.StatusFound)

		forged := base64.RawURLEncoding.EncodeToString([]byte(`{"n":"x","o":"https://evil.example.net"}`))
		AssertError(t, f.callback(t, "c", forged), http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
	})
}

func nowUnixString() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

// ── GET /linked-accounts ─────────────────────────────────────────────────────

func testLinkedAccountsList(t *testing.T, mount Mounter) {
	linkedAt := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	// The object wrapper is a client-pinned invariant: Angular reads
	// res.linkedAccounts and the served auth.js expects the same. Flutter's
	// helper only accepts a bare array and therefore reads [] here — a known
	// CLIENT bug (wire-contract.md §4, mismatch 1), not a reason to unwrap.
	t.Run("returns the wrapped object", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		user, tokens := f.Seed("linked@example.com")
		if err := f.links.Save(context.Background(), auth.OAuthLinkedAccount{
			ID: "lnk_1", UserID: user.ID, Provider: "acme", ProviderID: "acme-1",
			Email: "linked@provider.example", Name: "Linked User", Picture: "https://provider.example/a.png",
			CreatedAt: linkedAt,
		}); err != nil {
			t.Fatalf("seed link: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/linked-accounts", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := f.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "linkedAccounts")
		accounts, ok := body["linkedAccounts"].([]any)
		if !ok || len(accounts) != 1 {
			t.Fatalf("linkedAccounts = %v, want one entry", body["linkedAccounts"])
		}
		entry, _ := accounts[0].(map[string]any)
		// The reference's LinkedAccount, in full: email, name and picture are
		// optional there and here, and a store that has them must be able to
		// surface them. The family admin UI renders
		// `a.name || a.email || a.providerAccountId`.
		AssertKeys(t, entry, "provider", "providerAccountId", "email", "name", "picture", "linkedAt")
		for key, want := range map[string]string{
			"provider":          "acme",
			"providerAccountId": "acme-1",
			"email":             "linked@provider.example",
			"name":              "Linked User",
			"picture":           "https://provider.example/a.png",
		} {
			if entry[key] != want {
				t.Errorf("%s = %v, want %q", key, entry[key], want)
			}
		}
		if entry["linkedAt"] != linkedAt.Format(time.RFC3339Nano) {
			t.Errorf("linkedAt = %v, want %q", entry["linkedAt"], linkedAt.Format(time.RFC3339Nano))
		}
	})

	// The complaint the optional fields exist for: it is the LINK paths that have
	// to store the address, not just the wire type that has to be able to carry it.
	// The reference's linkAccount always passes the callback profile's email
	// (auth.router.ts:1336-1343) and /link-verify passes the verified address
	// (:1578-1583). Name and picture stay absent, because the reference's own
	// linkAccount calls never set them either.
	t.Run("the callback's auto-link carries the profile email", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertStatus(t, rec, http.StatusFound)

		entries := f.linkedAccountEntries(t, Cookie(t, rec, hostAccess).Value)
		if len(entries) != 1 {
			t.Fatalf("linkedAccounts = %v, want one entry", entries)
		}
		entry, _ := entries[0].(map[string]any)
		AssertKeys(t, entry, "provider", "providerAccountId", "email", "linkedAt")
		if entry["email"] != "oauth@example.com" {
			t.Fatalf("email = %v, want the callback profile's %q", entry["email"], "oauth@example.com")
		}
	})

	t.Run("link-verify carries the verified address", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("verified@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "verified@example.com", "provider": "acme"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertStatus(t, f.Do(req), http.StatusOK)
		token := f.lastDelivery(t).Token
		AssertStatus(t, f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token})), http.StatusOK)

		entries := f.linkedAccountEntries(t, tokens.AccessToken)
		if len(entries) != 1 {
			t.Fatalf("linkedAccounts = %v, want one entry", entries)
		}
		entry, _ := entries[0].(map[string]any)
		AssertKeys(t, entry, "provider", "providerAccountId", "email", "linkedAt")
		if entry["email"] != "verified@example.com" {
			t.Fatalf("email = %v, want %q", entry["email"], "verified@example.com")
		}
	})

	// [] and not null: a client that iterates the value must not have to
	// null-check it.
	t.Run("no links is an empty array", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("nolinks@example.com")
		req := httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/linked-accounts", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := f.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		if got := strings.TrimSpace(rec.Body.String()); got != `{"linkedAccounts":[]}` {
			t.Fatalf("body = %s, want {\"linkedAccounts\":[]}", got)
		}
	})

	// 403 with no code, as the reference's auth middleware emits.
	t.Run("no token", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		rec := f.Do(httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/linked-accounts", nil))
		AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
	})

	t.Run("unusable token", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		req := httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/linked-accounts", nil)
		req.Header.Set("Authorization", "Bearer not-a-token")
		AssertError(t, f.Do(req), http.StatusForbidden, "Invalid or expired access token", "")
	})

	// The reference leaves the route unmounted without a linkedAccountsStore, so
	// a caller gets Express's HTML 404. This port answers the family's
	// NOT_IMPLEMENTED envelope instead.
	t.Run("without a linked-accounts store", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{omitStores: true})
		_, tokens := f.Seed("nostore@example.com")
		req := httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/linked-accounts", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertError(t, f.Do(req), http.StatusNotImplemented, "Feature not supported by the configured stores", auth.CodeNotImplemented)
	})
}

// ── DELETE /linked-accounts/{provider}/{providerAccountId} ───────────────────

func testLinkedAccountsDelete(t *testing.T, mount Mounter) {
	seedLink := func(t *testing.T, f *oauthFixture, userID string) {
		t.Helper()
		if err := f.links.Save(context.Background(), auth.OAuthLinkedAccount{
			ID: "lnk_" + userID, UserID: userID, Provider: "acme", ProviderID: "acme-1", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed link: %v", err)
		}
	}
	del := func(f *oauthFixture, token, provider, accountID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, f.Config.Prefix()+"/linked-accounts/"+provider+"/"+accountID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		return f.Do(req)
	}

	t.Run("removes the link", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		user, tokens := f.Seed("unlink@example.com")
		seedLink(t, f, user.ID)

		rec := del(f, tokens.AccessToken, "acme", "acme-1")
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if _, err := f.links.FindByProvider(context.Background(), "acme", "acme-1"); err == nil {
			t.Fatal("link survived the unlink")
		}
	})

	// An adapter-interchangeability case, which is the class of bug this suite
	// exists for. Express matches its route against the still-encoded path and
	// decodeURIComponent's each captured parameter, so a providerAccountId
	// containing %2F reaches the handler as one parameter holding a slash. The
	// shared handler reads its parameters off r.URL.EscapedPath() for the same
	// reason. Gin, though, routes on the UNESCAPED path, so under a two-parameter
	// pattern this request arrives as three segments and 404s where the other three
	// adapters answer 200 — hence the catch-all registration on that adapter.
	t.Run("a providerAccountId containing an encoded slash", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		user, tokens := f.Seed("encoded@example.com")
		if err := f.links.Save(context.Background(), auth.OAuthLinkedAccount{
			ID: "lnk_encoded", UserID: user.ID, Provider: "acme", ProviderID: "a/b", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed link: %v", err)
		}

		rec := del(f, tokens.AccessToken, "acme", "a%2Fb")
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if _, err := f.links.FindByProvider(context.Background(), "acme", "a/b"); err == nil {
			t.Fatal("the link survived: the %2F never arrived as one parameter")
		}
	})

	// The flip side of the catch-all: widening what reaches the handler must not
	// widen what the route answers. A path that is not exactly
	// <provider>/<providerAccountId> is not this route on any adapter, so all four
	// answer 404 — not the 403 an auth middleware would emit, and not a CSRF
	// failure. Only the status is asserted: the body of an unrouted path belongs to
	// each router and already differs between them.
	t.Run("a path that is not provider and account id is not this route", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("shape@example.com")
		for _, suffix := range []string{"/acme", "/acme/a/b/c"} {
			req := httptest.NewRequest(http.MethodDelete, f.Config.Prefix()+"/linked-accounts"+suffix, nil)
			req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			if rec := f.Do(req); rec.Code != http.StatusNotFound {
				t.Errorf("DELETE %s = %d, want 404 (body %q)", suffix, rec.Code, rec.Body.String())
			}
		}
	})

	// No existence check in the reference: an unknown pair still answers success.
	t.Run("an unknown pair still succeeds", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("unlinkmissing@example.com")
		rec := del(f, tokens.AccessToken, "acme", "does-not-exist")
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
	})

	// Succeeds like every other unlink, but must not touch a link it does not
	// own — the reference scopes the store call by user id.
	t.Run("another user's link is left alone", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		owner, _ := f.Seed("owner@example.com")
		_, intruderTokens := f.Seed("intruder@example.com")
		seedLink(t, f, owner.ID)

		AssertStatus(t, del(f, intruderTokens.AccessToken, "acme", "acme-1"), http.StatusOK)
		if _, err := f.links.FindByProvider(context.Background(), "acme", "acme-1"); err != nil {
			t.Fatal("another user's link was deleted")
		}
	})

	// Unsafe method, cookie-authenticated: double-submit applies.
	//
	// The access-token cookie is what makes this case about CSRF at all.
	// Enforcement is scoped to cookie-authenticated requests, so without it the
	// route would defer to the auth gate and answer "No access token provided" —
	// which is the separate case below, not this one.
	t.Run("cookie mode without the CSRF header", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("unlinkcsrf@example.com")
		req := httptest.NewRequest(http.MethodDelete, f.Config.Prefix()+"/linked-accounts/acme/acme-1", nil)
		req.AddCookie(&http.Cookie{Name: hostAccess, Value: tokens.AccessToken})
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertError(t, f.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
	})

	// No credential of any kind, and no CSRF pair either: this route sits behind the
	// auth middleware, so the auth gate answers with the reference's literal.
	t.Run("no token", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		req := httptest.NewRequest(http.MethodDelete, f.Config.Prefix()+"/linked-accounts/acme/acme-1", nil)
		AssertError(t, f.Do(req), http.StatusForbidden, "No access token provided", "")
	})
}

// ── POST /link-request ───────────────────────────────────────────────────────

func testLinkRequest(t *testing.T, mount Mounter) {
	t.Run("an authenticated caller gets a verification link", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("linkreq@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "linkreq@example.com", "provider": "acme"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := f.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		delivery := f.lastDelivery(t)
		if delivery.Email != "linkreq@example.com" || delivery.Provider != "acme" {
			t.Errorf("delivery = %+v", delivery)
		}
		// 32 random bytes as 64 hex characters, the reference's token size.
		if len(delivery.Token) != 64 {
			t.Errorf("token = %q, want 64 hex characters", delivery.Token)
		}
		wantURL := fixtureSiteURL + f.Config.Prefix() + "/link-verify?token=" + delivery.Token
		if delivery.URL != wantURL {
			t.Errorf("link = %q, want %q", delivery.URL, wantURL)
		}
		// The credential must never appear in the HTTP response.
		if strings.Contains(rec.Body.String(), delivery.Token) {
			t.Errorf("response leaked the account-link token: %s", rec.Body.String())
		}
	})

	// The reference's body is { email, provider?, emailLang? } and emailLang is
	// forwarded to sendVerificationEmail as its fourth argument
	// (auth.router.ts:1496, :1530-1535). Dropping it leaves the host's mail
	// transport unable to localise, which no error surfaces.
	t.Run("emailLang reaches the delivery hook", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("lang@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{
			"email": "lang@example.com", "provider": "acme", "emailLang": "it",
		})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertStatus(t, f.Do(req), http.StatusOK)
		if got := f.lastDelivery(t).EmailLang; got != "it" {
			t.Fatalf("emailLang = %q, want %q", got, "it")
		}
	})

	// The reference resolves the link's origin per request through
	// resolveSiteUrl(req, config, allowedOrigins) (auth.router.ts:1528), so a
	// deployment serving several front-ends mails a link back to the one that
	// asked rather than always to the default site url.
	t.Run("the verification link uses the request origin", func(t *testing.T) {
		const other = "https://admin.example.com"
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL, other}})
		_, tokens := f.Seed("origin@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "origin@example.com", "provider": "acme"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		req.Header.Set("Origin", other)
		AssertStatus(t, f.Do(req), http.StatusOK)

		delivery := f.lastDelivery(t)
		want := other + f.Config.Prefix() + "/link-verify?token=" + delivery.Token
		if delivery.URL != want {
			t.Fatalf("link = %q, want %q", delivery.URL, want)
		}
	})

	// An origin the allowlist refuses falls back to the configured site url, the
	// same resolution the authorize route performs.
	t.Run("an off-allowlist origin falls back to the site url", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		_, tokens := f.Seed("badorigin@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "badorigin@example.com", "provider": "acme"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		req.Header.Set("Origin", "https://evil.example.net")
		AssertStatus(t, f.Do(req), http.StatusOK)

		delivery := f.lastDelivery(t)
		want := fixtureSiteURL + f.Config.Prefix() + "/link-verify?token=" + delivery.Token
		if delivery.URL != want {
			t.Fatalf("link = %q, want %q", delivery.URL, want)
		}
	})

	t.Run("missing email", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("noemail@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertError(t, f.Do(req), http.StatusBadRequest, "email is required", auth.CodeEmailRequired)
	})

	// Unauthenticated and nothing stashed: the conflict flow has nothing to
	// resolve an identity from.
	t.Run("unauthenticated with no pending link", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		f.Seed("nopending@example.com")
		req := csrfPair(f.Request(http.MethodPost, "/link-request", map[string]any{"email": "nopending@example.com"}))
		AssertError(t, f.Do(req), http.StatusUnauthorized, "Authentication required or no pending link found", auth.CodeUnauthorized)
	})

	// The conflict path: a stashed pending link stands in for authentication.
	t.Run("unauthenticated with a stashed pending link", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		f.Seed("conflict@example.com")
		if err := f.pending.Save(context.Background(), "pending-link:conflict@example.com|acme", auth.OAuthPendingMeta{
			Provider: "acme", Email: "conflict@example.com", ProviderAccountID: "acme-9", TenantID: "t1",
		}, time.Hour); err != nil {
			t.Fatalf("stash: %v", err)
		}
		req := csrfPair(f.Request(http.MethodPost, "/link-request", map[string]any{"email": "conflict@example.com", "provider": "acme"}))
		rec := f.Do(req)
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
	})

	t.Run("a stashed link for an unknown address", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		if err := f.pending.Save(context.Background(), "pending-link:ghost@example.com|email", auth.OAuthPendingMeta{
			Provider: "email", Email: "ghost@example.com", ProviderAccountID: "g-1",
		}, time.Hour); err != nil {
			t.Fatalf("stash: %v", err)
		}
		req := csrfPair(f.Request(http.MethodPost, "/link-request", map[string]any{"email": "ghost@example.com"}))
		AssertError(t, f.Do(req), http.StatusNotFound, "Target user not found", auth.CodeUserNotFound)
	})

	t.Run("without the linking stores", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{omitStores: true})
		_, tokens := f.Seed("nostorelink@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "nostorelink@example.com"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertError(t, f.Do(req), http.StatusNotImplemented, "Feature not supported by the configured stores", auth.CodeNotImplemented)
	})

	// Unsafe method with no auth middleware, but the reference CSRF-checks this
	// one by hand, so the exemption table must not list it.
	t.Run("cookie mode without the CSRF header", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "csrf@example.com"})
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertError(t, f.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
	})

	// The pure cross-site forgery, and the reason this route is enforced even
	// though no request to it is ever cookie-authenticated.
	//
	// An auto-submitting form on an attacker's page carries no Authorization, no
	// X-CSRF-Token, and no cookie the attacker chose — and because decodeJSON never
	// inspects Content-Type, <form enctype="text/plain"> is enough to reach the
	// handler. There is no auth gate behind this route to stop it: linkRequest
	// performs no manual check of its own and accepts a stashed pending link in
	// place of authentication for about an hour (auth.router.ts:1513-1524). So the
	// double-submit is the only thing standing between that form and a write which
	// overwrites the in-flight account-link token and mails the victim's address.
	//
	// The refusal is half the case; the other half is that nothing was written.
	t.Run("a forged request is refused and writes nothing", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		f.Seed("forged@example.com")
		if err := f.pending.Save(context.Background(), "pending-link:forged@example.com|acme", auth.OAuthPendingMeta{
			Provider: "acme", Email: "forged@example.com", ProviderAccountID: "acme-7", TenantID: "t1",
		}, time.Hour); err != nil {
			t.Fatalf("stash: %v", err)
		}
		// Establish an in-flight link token the forgery would overwrite.
		legitimate := csrfPair(f.Request(http.MethodPost, "/link-request", map[string]any{"email": "forged@example.com", "provider": "acme"}))
		AssertStatus(t, f.Do(legitimate), http.StatusOK)
		issued := f.lastDelivery(t).Token

		// Now the forgery: nothing on the request at all.
		forged := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "forged@example.com", "provider": "acme"})
		AssertError(t, f.Do(forged), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)

		// No second mail went out, so the victim's token was not rotated.
		if got := f.lastDelivery(t).Token; got != issued {
			t.Fatalf("the refused request still issued a link token: %q, want the earlier %q", got, issued)
		}
		// And the first token still works, which is the user-visible consequence:
		// a forgery must not be able to invalidate an in-flight link.
		AssertStatus(t, f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": issued})), http.StatusOK)
	})

	// A CSRF cookie with no header is the same forgery with one more detail the
	// attacker cannot supply: the cookie is sent by the browser, the header is not.
	t.Run("a forged request with an unmirrored cookie is refused", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		f.Seed("forgedcookie@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "forgedcookie@example.com"})
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: csrfPairValue})
		AssertError(t, f.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
	})
}

// ── POST /link-verify ────────────────────────────────────────────────────────

func testLinkVerify(t *testing.T, mount Mounter) {
	// issueToken drives /link-request and returns the delivered token.
	issueToken := func(t *testing.T, f *oauthFixture, email string) (auth.User, string) {
		t.Helper()
		user, tokens := f.Seed(email)
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": email, "provider": "acme"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertStatus(t, f.Do(req), http.StatusOK)
		return user, f.lastDelivery(t).Token
	}

	t.Run("links the account and issues no session", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		user, token := issueToken(t, f, "verify@example.com")
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)

		links, err := f.links.ListForUser(context.Background(), user.ID)
		if err != nil || len(links) != 1 {
			t.Fatalf("links = %v (%v), want exactly one", links, err)
		}
		if links[0].Provider != "acme" {
			t.Errorf("provider = %q, want %q", links[0].Provider, "acme")
		}
		// With nothing stashed by a conflict, the reference defaults the provider
		// account id to the address.
		if links[0].ProviderID != "verify@example.com" {
			t.Errorf("providerAccountId = %q, want the email", links[0].ProviderID)
		}
	})

	t.Run("the token is single use", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, token := issueToken(t, f, "single@example.com")
		AssertStatus(t, f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token})), http.StatusOK)
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token}))
		AssertError(t, rec, http.StatusBadRequest, "Invalid account-link token", auth.CodeInvalidLinkToken)
	})

	t.Run("missing token", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{}))
		AssertError(t, rec, http.StatusBadRequest, "token is required", auth.CodeTokenRequired)
	})

	t.Run("unknown token", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": "nope"}))
		AssertError(t, rec, http.StatusBadRequest, "Invalid account-link token", auth.CodeInvalidLinkToken)
	})

	// LINK_TOKEN_EXPIRED, the one code in this route group's error table that
	// nothing exercised. It needs a stash that ignores the ttl it was handed —
	// MemoryPendingLinks honours it, drops the aged entry, and the route answers
	// INVALID_LINK_TOKEN instead — which is exactly why LinkVerify enforces the
	// deadline recorded inside the entry rather than trusting the store to have
	// swept it. An expired token is also consumed, so it cannot be retried.
	t.Run("an expired token", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{expiringPending: true})
		_, token := issueToken(t, f, "expired@example.com")

		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token}))
		AssertError(t, rec, http.StatusBadRequest, "Account-link token has expired", auth.CodeLinkTokenExpired)

		rec = f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token}))
		AssertError(t, rec, http.StatusBadRequest, "Invalid account-link token", auth.CodeInvalidLinkToken)
	})

	t.Run("loginAfterLinking in cookie mode", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, token := issueToken(t, f, "login-after@example.com")
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token, "loginAfterLinking": true}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
	})

	// The one route in this group where X-Auth-Strategy matters: it answers with
	// a body, so sendTokens applies.
	t.Run("loginAfterLinking in bearer mode", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, token := issueToken(t, f, "login-bearer@example.com")
		req := f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token, "loginAfterLinking": true})
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := f.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	// Asymmetric with /link-request on purpose: the reference performs no CSRF
	// check here at all, so the emailed link works from a browser with no
	// session and no CSRF cookie.
	t.Run("no CSRF check", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, token := issueToken(t, f, "nocsrf@example.com")
		req := f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token})
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertStatus(t, f.Do(req), http.StatusOK)
	})

	t.Run("without the linking stores", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{omitStores: true})
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": "anything"}))
		AssertError(t, rec, http.StatusNotImplemented, "Feature not supported by the configured stores", auth.CodeNotImplemented)
	})
}
