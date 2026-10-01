package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OAuthProvider holds configuration for a single OAuth 2.0 provider. It is the
// reference's GenericOAuthProviderConfig (generic-oauth.strategy.ts:39-78) with
// the two hard-coded strategies, Google and GitHub, expressed as presets.
type OAuthProvider struct {
	Name         string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
	// AdditionalAuthParams are extra query parameters for the authorization
	// URL — provider-specific knobs such as Google's access_type or prompt. They
	// are the reference's additionalAuthParams (generic-oauth.strategy.ts:63) and
	// keep its precedence exactly (:113-120): an entry overrides client_id,
	// redirect_uri, response_type and scope, and state overrides an entry. The
	// PKCE pair this port adds (code_challenge, code_challenge_method) is written
	// after them as well, so a configuration cannot weaken the code binding.
	AdditionalAuthParams map[string]string
	// GitHubEmailsURL is the endpoint the "github" provider consults when the
	// user profile carries no email — a GitHub account whose address is private
	// (github.strategy.ts:54-68). Empty means UserInfoURL + "/emails", which is
	// https://api.github.com/user/emails for the preset; a test points it at a
	// fake. Only the "github" provider reads it.
	GitHubEmailsURL string
	// MapProfile replaces the default mapping of the userinfo document for
	// this provider — the reference's mapProfile hook
	// (generic-oauth.strategy.ts:71-77), which getUserProfile returns as the
	// profile whenever it is set (:151-153). It replaces the whole mapping,
	// the github preset's /user/emails fallback included. The service fills
	// Provider, and Raw when the hook left it nil; an error fails the exchange
	// on the profile-failed path (401 OAUTH_PROFILE_FAILED on the wire). When
	// both MapProfile and ProfileMap are set, MapProfile wins.
	MapProfile func(raw map[string]any) (OAuthUserInfo, error)
	// ProfileMap is the declarative form of MapProfile for a provider loaded
	// from configuration: the keys id, email, emailVerified, name and picture
	// (id required) mapped to expressions such as "$.data.user.id" or
	// "$.mail ?? $.userPrincipalName". CompileProfileMap documents the grammar.
	// NewOAuthService compiles it: a map that does not compile is recorded
	// against the provider, whose exchanges then fail with that error before
	// contacting the provider (500 on the wire); NewOAuthServiceWithConfig
	// reports it at start-up instead. nil or empty means the default mapping.
	ProfileMap map[string]string
}

// OAuthUserInfo is the normalized profile returned after token exchange — the
// reference's {id, email, emailVerified?, name?, picture?}
// (generic-oauth.strategy.ts:143, :154-160), plus the provider name and the raw
// document.
type OAuthUserInfo struct {
	ProviderID string
	Provider   string
	Email      string
	Name       string
	AvatarURL  string
	// EmailVerified is the provider's email_verified claim, or for GitHub the
	// verified flag of the address picked from /user/emails. nil means the
	// provider said nothing, the reference's `emailVerified: undefined`. The
	// provisioning policy reads it twice: RequireVerifiedEmail refuses a
	// callback that has no positive claim, and an account the callback creates
	// is verified unless the provider positively said otherwise (D-11).
	EmailVerified *bool
	Raw           map[string]any
}

// PendingLinkStore holds temporary OAuth link state.
type PendingLinkStore interface {
	Save(ctx context.Context, state string, meta OAuthPendingMeta, ttl time.Duration) error
	Get(ctx context.Context, state string) (OAuthPendingMeta, error)
	Delete(ctx context.Context, state string) error
}

// OAuthPendingMeta is the metadata stored during OAuth flow.
type OAuthPendingMeta struct {
	Provider    string
	RedirectURL string
	TenantID    string
	UserID      string // non-empty when linking to existing account
	// Email and ProviderAccountID carry the account-linking stash: the address
	// a /link-request token was issued for, and the provider account a callback
	// conflict parked for it.
	Email             string
	ProviderAccountID string
	// ExpiresAt lets a consumer enforce the deadline itself rather than trusting
	// the store to have honoured the ttl argument.
	ExpiresAt time.Time
}

// OAuthLinkedAccount stores a linked provider<->user association.
//
// Email, Name and Picture are the reference's optional LinkedAccount profile
// columns (linked-accounts-store.interface.ts:9-14). GET /linked-accounts
// projects all three, and clients render them: the family admin UI falls back
// through `a.name || a.email || a.providerAccountId`. The library fills Email at
// every link it writes, as the reference's linkAccount calls do; Name and Picture
// are left for a host store that wants to keep them, again as in the reference.
type OAuthLinkedAccount struct {
	ID         string
	UserID     string
	Provider   string
	ProviderID string
	Email      string
	Name       string
	Picture    string
	CreatedAt  time.Time
}

// LinkedAccountStore persists OAuth provider associations per user.
type LinkedAccountStore interface {
	Save(ctx context.Context, link OAuthLinkedAccount) error
	FindByProvider(ctx context.Context, provider, providerID string) (OAuthLinkedAccount, error)
	ListForUser(ctx context.Context, userID string) ([]OAuthLinkedAccount, error)
	Delete(ctx context.Context, id string) error
}

// OAuthService handles OAuth 2.0 authorization code flow.
type OAuthService struct {
	providers map[string]OAuthProvider
	client    *http.Client
	// profileMaps holds each provider's compiled ProfileMap; providerErrs the
	// compile error recorded for a provider whose map did not compile, which
	// ExchangeCodePKCE answers instead of contacting that provider.
	profileMaps  map[string]func(map[string]any) (OAuthUserInfo, error)
	providerErrs map[string]error
}

// NewOAuthService creates an OAuthService for the given providers. A
// ProfileMap that does not compile is not fatal here: the error is recorded
// and every exchange through that provider returns it, while the other
// providers keep working. NewOAuthServiceWithConfig surfaces it at start-up.
func NewOAuthService(providers ...OAuthProvider) *OAuthService {
	s, _ := newOAuthService(providers)
	return s
}

// NewOAuthServiceWithConfig is NewOAuthService with the configuration
// validated: it returns the ProfileMap compile errors of every provider that
// has one — joined, each naming its provider and the expression — and no
// service, so a deployment fails at start-up rather than at the first login.
func NewOAuthServiceWithConfig(providers ...OAuthProvider) (*OAuthService, error) {
	s, err := newOAuthService(providers)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func newOAuthService(providers []OAuthProvider) (*OAuthService, error) {
	s := &OAuthService{
		providers:    make(map[string]OAuthProvider, len(providers)),
		client:       &http.Client{Timeout: 10 * time.Second},
		profileMaps:  make(map[string]func(map[string]any) (OAuthUserInfo, error)),
		providerErrs: make(map[string]error),
	}
	for _, p := range providers {
		// A later provider with the same name replaces an earlier one entirely,
		// its compiled map and any recorded error included.
		s.providers[p.Name] = p
		delete(s.profileMaps, p.Name)
		delete(s.providerErrs, p.Name)
		if len(p.ProfileMap) == 0 {
			continue
		}
		mapper, err := CompileProfileMap(p.ProfileMap)
		if err != nil {
			s.providerErrs[p.Name] = providerConfigError{provider: p.Name, err: err}
			continue
		}
		s.profileMaps[p.Name] = mapper
	}
	// The errors that survived replacement, in name order so the message is
	// stable.
	names := make([]string, 0, len(s.providerErrs))
	for name := range s.providerErrs {
		names = append(names, name)
	}
	sort.Strings(names)
	errs := make([]error, 0, len(names))
	for _, name := range names {
		errs = append(errs, s.providerErrs[name])
	}
	return s, errors.Join(errs...)
}

// providerConfigError is a ProfileMap compile error recorded against the
// provider it belongs to. It unwraps to the CompileProfileMap error.
type providerConfigError struct {
	provider string
	err      error
}

func (e providerConfigError) Error() string {
	return fmt.Sprintf("auth: oauth provider %q: %s", e.provider, strings.TrimPrefix(e.err.Error(), "auth: "))
}

func (e providerConfigError) Unwrap() error { return e.err }

// GoogleProvider builds a pre-configured Google OAuth2 provider — the
// reference's GoogleStrategy (google.strategy.ts:23-33, :53). The authorization
// request carries access_type=offline (:29), the one extra parameter that
// strategy sends; it sends no prompt.
func GoogleProvider(clientID, clientSecret, redirectURL string) OAuthProvider {
	return OAuthProvider{
		Name:                 "google",
		ClientID:             clientID,
		ClientSecret:         clientSecret,
		RedirectURL:          redirectURL,
		AuthURL:              "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:             "https://oauth2.googleapis.com/token",
		UserInfoURL:          "https://www.googleapis.com/oauth2/v3/userinfo",
		Scopes:               []string{"openid", "email", "profile"},
		AdditionalAuthParams: map[string]string{"access_type": "offline"},
	}
}

// GitHubProvider builds a pre-configured GitHub OAuth2 provider — the
// reference's GithubStrategy (github.strategy.ts:23-31, :49-70), including the
// /user/emails fallback for accounts with a private address.
func GitHubProvider(clientID, clientSecret, redirectURL string) OAuthProvider {
	return OAuthProvider{
		Name:            "github",
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		RedirectURL:     redirectURL,
		AuthURL:         "https://github.com/login/oauth/authorize",
		TokenURL:        "https://github.com/login/oauth/access_token",
		UserInfoURL:     "https://api.github.com/user",
		Scopes:          []string{"user:email"},
		GitHubEmailsURL: "https://api.github.com/user/emails",
	}
}

// hasProvider reports whether a provider is configured under this name. It is
// what GET <prefix>/ui/config answers its google and github flags from, where
// the reference asks whether config.oauth.google or config.oauth.github is set
// (ui.router.ts:118-119). A nil service has none, so a deployment that wired no
// OAuth at all answers false rather than panicking.
func (s *OAuthService) hasProvider(name string) bool {
	if s == nil {
		return false
	}
	_, ok := s.providers[name]
	return ok
}

// AuthorizeURL builds the redirect URL for the given provider and state token.
func (s *OAuthService) AuthorizeURL(providerName, state string) (string, error) {
	return s.AuthorizeURLPKCE(providerName, state, "")
}

// AuthorizeURLPKCE builds the redirect URL and, when codeChallenge is non-empty,
// binds the exchange to it with the S256 method (RFC 7636). The HTTP routes
// always pass a challenge; the plain AuthorizeURL stays for embedders driving
// the service themselves.
func (s *OAuthService) AuthorizeURLPKCE(providerName, state, codeChallenge string) (string, error) {
	p, ok := s.providers[providerName]
	if !ok {
		return "", fmt.Errorf("auth: unknown oauth provider %q", providerName)
	}
	u, err := url.Parse(p.AuthURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(p.Scopes, " "))
	// The reference spreads additionalAuthParams over the four standard
	// parameters and then state over it (generic-oauth.strategy.ts:113-120):
	// later keys win, so an entry can replace scope or redirect_uri but never
	// state. The PKCE pair has no reference counterpart and is written last for
	// the same reason.
	for key, value := range p.AdditionalAuthParams {
		q.Set(key, value)
	}
	q.Set("state", state)
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeCode exchanges an authorization code for user info.
func (s *OAuthService) ExchangeCode(ctx context.Context, providerName, code string) (OAuthUserInfo, error) {
	return s.ExchangeCodePKCE(ctx, providerName, code, "")
}

// ExchangeCodePKCE exchanges an authorization code, sending the PKCE verifier
// when one was used to build the authorization URL.
func (s *OAuthService) ExchangeCodePKCE(ctx context.Context, providerName, code, codeVerifier string) (OAuthUserInfo, error) {
	p, ok := s.providers[providerName]
	if !ok {
		return OAuthUserInfo{}, fmt.Errorf("auth: unknown oauth provider %q", providerName)
	}
	// A provider whose ProfileMap did not compile can never produce a profile,
	// so the exchange is refused before the code is spent on the token
	// endpoint. The error is the one NewOAuthServiceWithConfig would have
	// returned at start-up.
	if err := s.providerErrs[providerName]; err != nil {
		return OAuthUserInfo{}, err
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", p.RedirectURL)
	data.Set("client_id", p.ClientID)
	data.Set("client_secret", p.ClientSecret)
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return OAuthUserInfo{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: %v", errOAuthTokenExchange, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: %v", errOAuthTokenExchange, err)
	}
	if resp.StatusCode >= 400 {
		return OAuthUserInfo{}, fmt.Errorf("%w: status %d", errOAuthTokenExchange, resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: parse token response: %v", errOAuthTokenExchange, err)
	}
	if tok.Error != "" || tok.AccessToken == "" {
		return OAuthUserInfo{}, fmt.Errorf("%w: %s", errOAuthTokenExchange, tok.Error)
	}

	uReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserInfoURL, nil)
	if err != nil {
		return OAuthUserInfo{}, err
	}
	uReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uReq.Header.Set("Accept", "application/json")

	uResp, err := s.client.Do(uReq)
	if err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: %v", errOAuthProfile, err)
	}
	defer uResp.Body.Close()
	uBody, err := io.ReadAll(uResp.Body)
	if err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: %v", errOAuthProfile, err)
	}
	// The status check is new: without it a provider's 401 JSON parsed cleanly
	// into an empty profile and the callback went on to create a user with no
	// email and no provider id.
	if uResp.StatusCode >= 400 {
		return OAuthUserInfo{}, fmt.Errorf("%w: status %d", errOAuthProfile, uResp.StatusCode)
	}
	var raw map[string]any
	if err := json.Unmarshal(uBody, &raw); err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: %v", errOAuthProfile, err)
	}
	info, err := s.mapProfile(ctx, p, tok.AccessToken, raw)
	if err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: %v", errOAuthProfile, err)
	}
	return info, nil
}

// mapProfile turns the userinfo document into the normalized profile in the
// order of the reference's getUserProfile (generic-oauth.strategy.ts:151-160):
// the mapProfile hook when the provider has one, else the default mapping.
// This port has two forms of the hook — MapProfile, the function, and
// ProfileMap, the declarative map compiled at construction — and the function
// wins when both are set. Provider is always set here, and Raw when the hook
// left it nil, so a hook only has to produce the five profile fields.
func (s *OAuthService) mapProfile(ctx context.Context, p OAuthProvider, accessToken string, raw map[string]any) (OAuthUserInfo, error) {
	var (
		info OAuthUserInfo
		err  error
	)
	switch {
	case p.MapProfile != nil:
		if info, err = p.MapProfile(raw); err != nil {
			return OAuthUserInfo{}, fmt.Errorf("map profile: %w", err)
		}
	case s.profileMaps[p.Name] != nil:
		if info, err = s.profileMaps[p.Name](raw); err != nil {
			return OAuthUserInfo{}, err
		}
	default:
		info = s.defaultProfile(ctx, p, accessToken, raw)
	}
	info.Provider = p.Name
	if info.Raw == nil {
		info.Raw = raw
	}
	return info, nil
}

// defaultProfile is the mapping a provider without a hook gets: the two
// hard-coded strategies for google and github, the reference's generic
// default for everything else.
func (s *OAuthService) defaultProfile(ctx context.Context, p OAuthProvider, accessToken string, raw map[string]any) OAuthUserInfo {
	providerName := p.Name
	info := OAuthUserInfo{Provider: providerName, Raw: raw}
	switch providerName {
	case "google":
		// GoogleStrategy.getUserProfile (google.strategy.ts:57-58): sub, email,
		// email_verified, name, picture.
		info.ProviderID, _ = raw["sub"].(string)
		info.Email, _ = raw["email"].(string)
		info.EmailVerified = optionalBool(raw["email_verified"])
		info.Name, _ = raw["name"].(string)
		info.AvatarURL, _ = raw["picture"].(string)
	case "github":
		// GithubStrategy.getUserProfile (github.strategy.ts:59-69): String(id),
		// email, name ?? login, avatar_url. emailVerified is only ever known when
		// the address came from /user/emails, which is consulted when the profile
		// has none (:60-68).
		info.ProviderID = subjectID(raw["id"])
		info.Email, _ = raw["email"].(string)
		if info.Name, _ = raw["name"].(string); info.Name == "" {
			info.Name, _ = raw["login"].(string)
		}
		info.AvatarURL, _ = raw["avatar_url"].(string)
		if info.Email == "" {
			info.Email, info.EmailVerified = s.githubEmailFallback(ctx, p, accessToken)
		}
	default:
		// The reference's default mapping, id ?? sub (generic-oauth.strategy.ts:
		// 154-160). user_id is this port's extra last resort, kept because
		// providers registered against earlier versions may rely on it; it only
		// widens what is accepted.
		for _, k := range []string{"id", "sub", "user_id"} {
			if v := subjectID(raw[k]); v != "" {
				info.ProviderID = v
				break
			}
		}
		info.Email, _ = raw["email"].(string)
		info.EmailVerified = optionalBool(raw["email_verified"])
		info.Name, _ = raw["name"].(string)
		info.AvatarURL, _ = raw["avatar_url"].(string)
	}
	return info
}

// subjectID renders a provider's subject the way the reference's
// String(raw.id ?? raw.sub ?? "") does: a string as-is, a JSON number without
// a trailing ".0" (GitHub's id is a number), anything else as "". An empty
// string reads as absent so the next candidate is tried — the one place this is
// looser than the reference, which would keep the empty id.
func subjectID(v any) string {
	switch id := v.(type) {
	case string:
		return id
	case float64:
		return strconv.FormatFloat(id, 'f', -1, 64)
	default:
		return ""
	}
}

// optionalBool reads a JSON boolean claim as the reference's `as boolean |
// undefined` cast does: a boolean is taken, anything else — absent, null, a
// string "true" — is nil.
func optionalBool(v any) *bool {
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

// githubEmailsURL is the endpoint githubEmailFallback calls: the configured
// override, else UserInfoURL + "/emails", which for the real API is
// https://api.github.com/user/emails.
func githubEmailsURL(p OAuthProvider) string {
	if p.GitHubEmailsURL != "" {
		return p.GitHubEmailsURL
	}
	return strings.TrimSuffix(p.UserInfoURL, "/") + "/emails"
}

// githubEmailFallback is github.strategy.ts:54-68 for a profile with no email:
// GET /user/emails with the reference's `Authorization: token` scheme and
// `Accept: application/vnd.github.v3+json` (:55), pick the entry that is both
// primary and verified, else the first one, and report its verified flag. A
// failed call is not an error — the reference gates on `emailRes.ok` and
// otherwise leaves the email empty — so a transport error, a non-2xx or an
// unparsable body all answer ("", nil).
func (s *OAuthService) githubEmailFallback(ctx context.Context, p OAuthProvider, accessToken string) (string, *bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubEmailsURL(p), nil)
	if err != nil {
		return "", nil
	}
	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode >= 400 {
		return "", nil
	}
	var entries []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &entries); err != nil || len(entries) == 0 {
		return "", nil
	}
	chosen := entries[0]
	for _, entry := range entries {
		if entry.Primary && entry.Verified {
			chosen = entry
			break
		}
	}
	verified := chosen.Verified
	return chosen.Email, &verified
}

// ErrOAuthAccountConflict is the sentinel every account conflict unwraps to,
// so a caller can test for the outcome with errors.Is without naming the type.
// The details — which address, which provider account — are on
// OAuthAccountConflictError, which errors.As recovers.
var ErrOAuthAccountConflict = errors.New("auth: oauth account conflict")

// OAuthAccountConflictError is the outcome the reference's
// AuthError("...", "OAUTH_ACCOUNT_CONFLICT") carries, with the same two data
// fields (auth.router.ts:1346-1355): the address the provider asserted and the
// provider account that asserted it. The callback answers it the way the
// reference does — it stashes the pair and redirects the browser to
// /account-conflict — rather than as a JSON error, which is why nothing maps it
// in OAuthHTTPError.
//
// It is raised only under OnEmailMatch = OAuthEmailMatchConflict, which is the
// default: a provider account nobody has linked, asserting an address some
// account already holds.
type OAuthAccountConflictError struct {
	Provider          string
	Email             string
	ProviderAccountID string
}

func (e *OAuthAccountConflictError) Error() string {
	return fmt.Sprintf("auth: oauth account conflict: provider %q account %q claims %q, which belongs to another account",
		e.Provider, e.ProviderAccountID, e.Email)
}

func (e *OAuthAccountConflictError) Unwrap() error { return ErrOAuthAccountConflict }

// HandleCallback resolves/creates a user after OAuth callback under the default
// provisioning policy (DefaultOAuthProvisioning): accounts are created when the
// provider identity is unknown, and an address some account already holds is
// answered with *OAuthAccountConflictError rather than linked. It is
// HandleCallbackWithPolicy with that policy, so it follows the default: through
// 0.12.0 it linked the address and signed that account in (issue #36). An
// embedder that wants the old behaviour calls HandleCallbackWithPolicy with
// OnEmailMatch: OAuthEmailMatchLink.
//
// If linkToUserID is non-empty the provider is linked to that existing account.
func (s *OAuthService) HandleCallback(
	ctx context.Context,
	authSvc *Service,
	linkedAccounts LinkedAccountStore,
	info OAuthUserInfo,
	tenantID string,
	linkToUserID string,
) (User, AuthTokens, error) {
	return s.HandleCallbackWithPolicy(ctx, authSvc, linkedAccounts, info, tenantID, linkToUserID, DefaultOAuthProvisioning())
}

// HandleCallbackWithPolicy is HandleCallback under an explicit provisioning
// policy — the whole of what the reference leaves to the integrator's
// findOrCreateUser (generic-oauth.strategy.ts:169-172). The order is the
// reference's resolution order with the policy's terms in it:
//
//  1. The policy gate: the provider must have asserted the address when
//     RequireVerifiedEmail is set, and the address must be in an admitted
//     domain. Both refuse before anything is read or written, so a refused
//     identity leaves no trace.
//  2. linkToUserID, when the caller named an account to link to.
//  3. The existing (provider, providerAccountId) link, which is the only
//     identification the reference's own store documentation considers safe
//     (user-store.interface.ts:105-119).
//  4. An account already holding the address: linked, refused as a conflict or
//     refused outright, per OnEmailMatch.
//  5. Creation, when AutoCreate allows it.
//
// The conflict outcome is *OAuthAccountConflictError; the three refusals are
// this port's own and reach the wire as 403s with the codes in oauth_wire.go.
func (s *OAuthService) HandleCallbackWithPolicy(
	ctx context.Context,
	authSvc *Service,
	linkedAccounts LinkedAccountStore,
	info OAuthUserInfo,
	tenantID string,
	linkToUserID string,
	policy OAuthProvisioning,
) (User, AuthTokens, error) {
	policy = policy.normalized()
	// Before the identity is resolved, so that a refusal is the same whether or
	// not the deployment already knows this provider account: an unverified or
	// off-domain address must not be able to sign in through a link it made
	// while the policy was looser.
	if err := policy.admit(info); err != nil {
		return User{}, AuthTokens{}, err
	}
	if linkToUserID != "" {
		linkID, err := newID("lnk")
		if err != nil {
			return User{}, AuthTokens{}, err
		}
		link := OAuthLinkedAccount{
			ID:         linkID,
			UserID:     linkToUserID,
			Provider:   info.Provider,
			ProviderID: info.ProviderID,
			Email:      info.Email,
			CreatedAt:  time.Now(),
		}
		if err := linkedAccounts.Save(ctx, link); err != nil {
			return User{}, AuthTokens{}, fmt.Errorf("auth: link account: %w", err)
		}
		user, err := authSvc.users.GetUserByID(ctx, linkToUserID, tenantID)
		if err != nil {
			return User{}, AuthTokens{}, ErrInvalidCredentials
		}
		tokens, err := authSvc.newSessionTokens(ctx, user)
		return user, tokens, err
	}

	// Try existing link
	link, err := linkedAccounts.FindByProvider(ctx, info.Provider, info.ProviderID)
	if err == nil {
		user, err := authSvc.users.GetUserByID(ctx, link.UserID, tenantID)
		if err != nil {
			return User{}, AuthTokens{}, ErrInvalidCredentials
		}
		tokens, err := authSvc.newSessionTokens(ctx, user)
		return user, tokens, err
	}

	// Try by email. Matching an address across providers is the account-takeover
	// shape the reference's own store interface warns about
	// (user-store.interface.ts:105-119), so what happens here is the policy's
	// decision rather than a fixed behaviour.
	if info.Email != "" {
		user, err := authSvc.users.GetUserByEmail(ctx, info.Email, tenantID)
		if err == nil {
			switch policy.OnEmailMatch {
			case OAuthEmailMatchConflict:
				// The reference's AuthError, with its two data fields. The route
				// stashes them and redirects; nothing is written here.
				return User{}, AuthTokens{}, &OAuthAccountConflictError{
					Provider:          info.Provider,
					Email:             info.Email,
					ProviderAccountID: info.ProviderID,
				}
			case OAuthEmailMatchReject:
				return User{}, AuthTokens{}, errOAuthUserNotProvisioned
			}
			linkID, _ := newID("lnk")
			// The reference's linkAccount always carries the callback profile's
			// email (auth.router.ts:1336-1343), which is what GET /linked-accounts
			// renders.
			_ = linkedAccounts.Save(ctx, OAuthLinkedAccount{
				ID: linkID, UserID: user.ID,
				Provider: info.Provider, ProviderID: info.ProviderID,
				Email:     info.Email,
				CreatedAt: time.Now(),
			})
			tokens, err := authSvc.newSessionTokens(ctx, user)
			return user, tokens, err
		}
	}

	// Create new user
	if !policy.AutoCreate {
		return User{}, AuthTokens{}, errOAuthUserNotProvisioned
	}
	setters, err := compileUserFieldMap(policy.FieldMap)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	userID, err := newID("usr")
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	now := time.Now()
	// LoginProvider records which provider created the account, the way the
	// reference's strategy documents creating one
	// (`userStore.create({ email, loginProvider: 'microsoft' })`,
	// generic-oauth.strategy.ts:92; user.model.ts:15). An account the callback
	// only links — found above by provider id or by email — keeps the provider
	// it was created with, as the reference's linkAccount changes no user row.
	//
	// IsEmailVerified follows the provider's claim when it made one and is true
	// when it said nothing (D-11, emailVerifiedOnCreate); RequireVerifiedEmail
	// is what refuses silence, and it has already run.
	draft := User{
		ID:              userID,
		Email:           info.Email,
		TenantID:        tenantID,
		LoginProvider:   info.Provider,
		IsEmailVerified: emailVerifiedOnCreate(info),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := applyUserFieldMap(setters, info.Raw, &draft); err != nil {
		return User{}, AuthTokens{}, err
	}
	newUser, err := authSvc.users.CreateUser(ctx, draft)
	if err != nil {
		return User{}, AuthTokens{}, fmt.Errorf("auth: create oauth user: %w", err)
	}
	linkID, _ := newID("lnk")
	_ = linkedAccounts.Save(ctx, OAuthLinkedAccount{
		ID: linkID, UserID: newUser.ID,
		Provider: info.Provider, ProviderID: info.ProviderID,
		Email:     info.Email,
		CreatedAt: now,
	})
	tokens, err := authSvc.newSessionTokens(ctx, newUser)
	return newUser, tokens, err
}

// MemoryLinkedAccounts is an in-memory implementation of LinkedAccountStore,
// suitable for development, testing, and embedded deployments.
type MemoryLinkedAccounts struct {
	mu    sync.RWMutex
	byID  map[string]OAuthLinkedAccount            // id -> link
	byPrv map[string]map[string]OAuthLinkedAccount // provider -> providerID -> link
	byUsr map[string][]OAuthLinkedAccount          // userID -> links
}

// NewMemoryLinkedAccounts creates an in-memory LinkedAccountStore.
func NewMemoryLinkedAccounts() *MemoryLinkedAccounts {
	return &MemoryLinkedAccounts{
		byID:  make(map[string]OAuthLinkedAccount),
		byPrv: make(map[string]map[string]OAuthLinkedAccount),
		byUsr: make(map[string][]OAuthLinkedAccount),
	}
}

func (m *MemoryLinkedAccounts) Save(_ context.Context, link OAuthLinkedAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[link.ID] = link
	if m.byPrv[link.Provider] == nil {
		m.byPrv[link.Provider] = make(map[string]OAuthLinkedAccount)
	}
	m.byPrv[link.Provider][link.ProviderID] = link
	// Replace existing entry for the same ID to prevent duplicates.
	links := m.byUsr[link.UserID]
	for i, l := range links {
		if l.ID == link.ID {
			links[i] = link
			m.byUsr[link.UserID] = links
			return nil
		}
	}
	m.byUsr[link.UserID] = append(links, link)
	return nil
}

func (m *MemoryLinkedAccounts) FindByProvider(_ context.Context, provider, providerID string) (OAuthLinkedAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if prv, ok := m.byPrv[provider]; ok {
		if link, ok := prv[providerID]; ok {
			return link, nil
		}
	}
	return OAuthLinkedAccount{}, fmt.Errorf("auth: linked account not found")
}

func (m *MemoryLinkedAccounts) ListForUser(_ context.Context, userID string) ([]OAuthLinkedAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]OAuthLinkedAccount, len(m.byUsr[userID]))
	copy(out, m.byUsr[userID])
	return out, nil
}

func (m *MemoryLinkedAccounts) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	link, ok := m.byID[id]
	if !ok {
		return nil
	}
	delete(m.byID, id)
	if prv, ok := m.byPrv[link.Provider]; ok {
		delete(prv, link.ProviderID)
	}
	links := m.byUsr[link.UserID]
	out := links[:0]
	for _, l := range links {
		if l.ID != id {
			out = append(out, l)
		}
	}
	m.byUsr[link.UserID] = out
	return nil
}
