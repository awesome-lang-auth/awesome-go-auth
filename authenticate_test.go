package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingClaims is a Config.BuildTokenClaims hook that counts its calls.
type countingClaims struct {
	mu    sync.Mutex
	calls int
}

func (c *countingClaims) build(_ context.Context, user User) (map[string]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return map[string]any{"plan": "pro", "subjectEmail": user.Email}, nil
}

func (c *countingClaims) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *countingClaims) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = 0
}

// TestAuthenticate_NeverRunsTheClaimsHookAndMeRunsItOnce is the reason
// Authenticate exists. Me used to be what the adapters' middleware called, and
// Me runs Config.BuildTokenClaims to fill CustomClaims — so a ClaimsWebhook
// behind the hook would have fired on every protected request.
func TestAuthenticate_NeverRunsTheClaimsHookAndMeRunsItOnce(t *testing.T) {
	counter := &countingClaims{}
	cfg := testConfig(testSecret)
	cfg.BuildTokenClaims = counter.build
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx := context.Background()
	user, tokens, err := svc.Register(ctx, RegisterInput{Email: "count@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := counter.count(); got != 2 {
		t.Fatalf("Register ran the hook %d times, want 2 (access and refresh)", got)
	}
	counter.reset()

	for i := 0; i < 3; i++ {
		authed, err := svc.Authenticate(ctx, tokens.AccessToken)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if authed.ID != user.ID || authed.Email != "count@example.com" {
			t.Fatalf("Authenticate returned %+v, want the token's user", authed)
		}
		if authed.CustomClaims != nil {
			t.Fatalf("Authenticate filled CustomClaims %+v; it must leave them nil", authed.CustomClaims)
		}
	}
	if got := counter.count(); got != 0 {
		t.Fatalf("Authenticate ran the hook %d times, want 0", got)
	}

	me, err := svc.Me(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if got := counter.count(); got != 1 {
		t.Fatalf("Me ran the hook %d times, want exactly 1", got)
	}
	if me.CustomClaims["plan"] != "pro" || me.CustomClaims["subjectEmail"] != "count@example.com" {
		t.Fatalf("Me.CustomClaims = %+v, want the hook's result", me.CustomClaims)
	}
}

// TestMe_LogsAndSkipsAFailingClaimsHook pins the read-side contract the docs
// promise: a builder failure on Me is logged, leaves CustomClaims nil and does
// not fail the call — /me is a read, and a read does not go dark because a
// mint-time hook is down. The hook succeeds while the user is seeded, so the
// tokens exist, and is swapped for a failing one before Me runs.
func TestMe_LogsAndSkipsAFailingClaimsHook(t *testing.T) {
	var (
		mu     sync.Mutex
		logged []string
	)
	cfg := testConfig(testSecret)
	cfg.Logger = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, fmt.Sprintf(format, args...))
	}
	counter := &countingClaims{}
	cfg.BuildTokenClaims = counter.build
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx := context.Background()
	user, tokens, err := svc.Register(ctx, RegisterInput{Email: "skip@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	boom := errors.New("claims endpoint down")
	svc.cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) { return nil, boom }
	me, err := svc.Me(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Me with a failing hook = %v, want the profile without custom claims", err)
	}
	if me.ID != user.ID || me.Email != "skip@example.com" {
		t.Fatalf("Me returned %+v, want the token's user", me)
	}
	if me.CustomClaims != nil {
		t.Fatalf("Me.CustomClaims = %+v, want nil when the hook fails", me.CustomClaims)
	}
	mu.Lock()
	lines := append([]string(nil), logged...)
	mu.Unlock()
	var saw bool
	for _, line := range lines {
		if strings.Contains(line, "custom claim enrichment skipped") && strings.Contains(line, user.ID) && strings.Contains(line, boom.Error()) {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("the logger did not see the skip line naming the user and the cause; logged %q", lines)
	}

	// Authenticate is unaffected either way: it never ran the hook.
	authed, err := svc.Authenticate(ctx, tokens.AccessToken)
	if err != nil || authed.CustomClaims != nil {
		t.Fatalf("Authenticate = %+v, %v; want the user with nil CustomClaims", authed, err)
	}

	// Once the hook answers again, Me carries its result: nothing was cached.
	svc.cfg.BuildTokenClaims = counter.build
	me, err = svc.Me(ctx, tokens.AccessToken)
	if err != nil || me.CustomClaims["plan"] != "pro" {
		t.Fatalf("Me once the hook recovers = %+v, %v; want the hook's claims", me.CustomClaims, err)
	}
}

// TestAuthenticate_KeepsTheStoresEnrichment pins what the middleware's user
// still carries: everything the optional stores add, because host handlers
// authorise on Roles and Permissions read off the context.
func TestAuthenticate_KeepsTheStoresEnrichment(t *testing.T) {
	ctx := context.Background()
	counter := &countingClaims{}
	cfg := testConfig(testSecret)
	cfg.BuildTokenClaims = counter.build
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore(),
		WithMetadataStore(NewMemoryMetadataStore()), WithRolesPermissionsStore(NewMemoryRolesPermissionsStore()), WithTenantStore(NewMemoryTenantStore()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	user, tokens, err := svc.Register(ctx, RegisterInput{Email: "enriched@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.UpdateMetadata(ctx, user.ID, map[string]any{"theme": "dark"}); err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	if err := svc.CreateRole(ctx, "editor", []string{"posts:write"}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := svc.AssignRole(ctx, user.ID, "editor", user.TenantID); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	tenant, err := svc.CreateTenant(ctx, "Acme", nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if err := svc.AddUserToTenant(ctx, user.ID, tenant.ID); err != nil {
		t.Fatalf("AddUserToTenant: %v", err)
	}
	counter.reset()

	authed, err := svc.Authenticate(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if authed.Metadata["theme"] != "dark" {
		t.Errorf("Metadata = %+v, want the metadata store's row", authed.Metadata)
	}
	if len(authed.Roles) != 1 || authed.Roles[0] != "editor" || len(authed.Permissions) != 1 || authed.Permissions[0] != "posts:write" {
		t.Errorf("Roles/Permissions = %v/%v, want editor/posts:write", authed.Roles, authed.Permissions)
	}
	if len(authed.Tenants) != 1 || authed.Tenants[0].ID != tenant.ID {
		t.Errorf("Tenants = %+v, want the one membership", authed.Tenants)
	}
	if authed.CustomClaims != nil || counter.count() != 0 {
		t.Errorf("Authenticate ran the hook (%d calls, claims %+v)", counter.count(), authed.CustomClaims)
	}
}

// TestAuthenticate_RefusesWhatMeRefuses: the verification half is shared, so
// the sentinels are Me's.
func TestAuthenticate_RefusesWhatMeRefuses(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(testSecret)
	cfg.SessionCheckOn = SessionCheckOnAllCalls
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	_, tokens, err := svc.Register(ctx, RegisterInput{Email: "refuse@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := svc.Authenticate(ctx, "not-a-token"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("garbage = %v, want ErrInvalidToken", err)
	}
	if _, err := svc.Authenticate(ctx, tokens.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a refresh token = %v, want ErrInvalidToken", err)
	}
	if _, err := svc.Authenticate(ctx, tokens.AccessToken); err != nil {
		t.Fatalf("a live access token: %v", err)
	}
	if err := svc.Logout(ctx, tokens.RefreshToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := svc.Authenticate(ctx, tokens.AccessToken); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("after logout under allcalls = %v, want ErrSessionRevoked", err)
	}
	if _, err := svc.Me(ctx, tokens.AccessToken); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("Me after logout under allcalls = %v, want ErrSessionRevoked", err)
	}
}

// userReadCounter counts every UserStore read and write a Service makes, so a
// test can pin that a call made none.
type userReadCounter struct {
	*MemoryUserStore
	mu    sync.Mutex
	reads int
}

func (c *userReadCounter) GetUserByID(ctx context.Context, id, tenantID string) (User, error) {
	c.mu.Lock()
	c.reads++
	c.mu.Unlock()
	return c.MemoryUserStore.GetUserByID(ctx, id, tenantID)
}

func (c *userReadCounter) GetUserByEmail(ctx context.Context, email, tenantID string) (User, error) {
	c.mu.Lock()
	c.reads++
	c.mu.Unlock()
	return c.MemoryUserStore.GetUserByEmail(ctx, email, tenantID)
}

func (c *userReadCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// TestVerifyAccess_ReadsNoUserStore pins #31: the adapters' gate builds the
// principal from the verified claims without a user-store read, as the
// reference's authMiddleware does (auth.middleware.ts:44-61 at v1.10.8), so a
// deleted user's token still verifies — and Me, whose handler looks the user
// up, answers ErrUserNotFound for it. The optional stores' enrichment is kept,
// and the claims hook is not run.
func TestVerifyAccess_ReadsNoUserStore(t *testing.T) {
	ctx := context.Background()
	counter := &countingClaims{}
	store := &userReadCounter{MemoryUserStore: NewMemoryUserStore()}
	cfg := testConfig(testSecret)
	cfg.BuildTokenClaims = counter.build
	svc, err := NewService(cfg, store, NewMemorySessionStore(), WithRolesPermissionsStore(NewMemoryRolesPermissionsStore()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	user, tokens, err := svc.Register(ctx, RegisterInput{Email: "principal@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.CreateRole(ctx, "editor", []string{"posts:write"}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := svc.AssignRole(ctx, user.ID, "editor", user.TenantID); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := store.DeleteUser(ctx, user.ID, user.TenantID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	counter.reset()
	before := store.count()

	principal, err := svc.VerifyAccess(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccess for a deleted user's live token: %v", err)
	}
	if got := store.count() - before; got != 0 {
		t.Errorf("VerifyAccess made %d user-store read(s), want 0", got)
	}
	if principal.ID != user.ID || principal.TenantID != "t1" || principal.Email != "principal@example.com" || !principal.IsEmailVerified {
		t.Errorf("principal = %+v, want the token's claims", principal)
	}
	if principal.PasswordHash != "" {
		t.Error("the principal carries a password hash; it is built from the token")
	}
	if len(principal.Roles) != 1 || principal.Roles[0] != "editor" {
		t.Errorf("Roles = %v, want the RBAC store's enrichment", principal.Roles)
	}
	if principal.CustomClaims != nil || counter.count() != 0 {
		t.Errorf("VerifyAccess ran the hook (%d calls, claims %+v)", counter.count(), principal.CustomClaims)
	}

	if _, err := svc.Me(ctx, tokens.AccessToken); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Me for a deleted user = %v, want ErrUserNotFound", err)
	}
	if _, err := svc.Authenticate(ctx, tokens.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Authenticate for a deleted user = %v, want ErrInvalidToken, unchanged", err)
	}
	if _, err := svc.VerifyAccess(ctx, tokens.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("VerifyAccess(refresh token) = %v, want ErrInvalidToken", err)
	}
}

// Under allcalls the gate still refuses a revoked session with the sentinel
// SESSION_REVOKED is written from.
func TestVerifyAccess_KeepsTheSessionCheck(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(testSecret)
	cfg.SessionCheckOn = SessionCheckOnAllCalls
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	_, tokens, err := svc.Register(ctx, RegisterInput{Email: "revoked-gate@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := svc.Logout(ctx, tokens.RefreshToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := svc.VerifyAccess(ctx, tokens.AccessToken); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("VerifyAccess after logout under allcalls = %v, want ErrSessionRevoked", err)
	}
}

func TestAuthAuthenticateDelegates(t *testing.T) {
	counter := &countingClaims{}
	a, err := newTestAuth(WithTokenClaimsBuilder(counter.build))
	if err != nil {
		t.Fatalf("newTestAuth: %v", err)
	}
	ctx := context.Background()
	user, tokens, err := a.Register(ctx, RegisterInput{Email: "delegate@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	counter.reset()
	authed, err := a.Authenticate(ctx, tokens.AccessToken)
	if err != nil || authed.ID != user.ID || authed.CustomClaims != nil || counter.count() != 0 {
		t.Fatalf("Auth.Authenticate = %+v, %v (hook calls %d)", authed, err, counter.count())
	}
	if _, err := a.Authenticate(ctx, "junk"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Auth.Authenticate(junk) = %v, want ErrInvalidToken", err)
	}
}

// TestLinkRequest_NeverRunsTheClaimsHook: POST /link-request resolves the
// caller's identity from a bearer token and reads nothing but id and tenant
// off the user, so it authenticates rather than building a profile — the
// reference reads the verified payload there without buildTokenPayload
// (auth.router.ts:1502-1510).
func TestLinkRequest_NeverRunsTheClaimsHook(t *testing.T) {
	counter := &countingClaims{}
	a, err := newTestAuth(
		WithTokenClaimsBuilder(counter.build),
		WithOAuth(OAuthWiring{
			Service:        NewOAuthService(),
			LinkedAccounts: NewMemoryLinkedAccounts(),
			PendingLinks:   NewMemoryPendingLinks(),
			SiteURL:        "https://app.example.com",
			TenantID:       "t1",
		}),
	)
	if err != nil {
		t.Fatalf("newTestAuth: %v", err)
	}
	ctx := context.Background()
	user, tokens, err := a.Register(ctx, RegisterInput{Email: "link@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	counter.reset()

	result, err := a.LinkRequest(ctx, LinkRequestInput{Email: "link@example.com", Provider: "acme", AccessToken: tokens.AccessToken})
	if err != nil {
		t.Fatalf("LinkRequest: %v", err)
	}
	if got := counter.count(); got != 0 {
		t.Fatalf("LinkRequest ran Config.BuildTokenClaims %d times, want 0", got)
	}
	// The identity still came from the token: the stash names the caller.
	stashed, err := a.oauth.PendingLinks.Get(ctx, linkTokenKey(result.Token))
	if err != nil {
		t.Fatalf("the link token was not stashed: %v", err)
	}
	if stashed.UserID != user.ID || stashed.TenantID != "t1" {
		t.Fatalf("stash = %+v, want the token's user %s in t1", stashed, user.ID)
	}
}

// TestIDPUserInfo_NeverRunsTheClaimsHook: the IdP's userinfo body is sub, email
// and name, none of which the hook contributes, so it authenticates too.
func TestIDPUserInfo_NeverRunsTheClaimsHook(t *testing.T) {
	counter := &countingClaims{}
	cfg := testConfig(testSecret)
	cfg.BuildTokenClaims = counter.build
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx := context.Background()
	user, tokens, err := svc.Register(ctx, RegisterInput{Email: "userinfo@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	idp, err := NewIDP(IDPConfig{Issuer: "https://idp.example.com", AccessTokenTTL: time.Hour}, svc)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	mux := http.NewServeMux()
	idp.RegisterHandlers(mux, "/oidc")
	counter.reset()

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo = %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	if body["sub"] != user.ID || body["email"] != "userinfo@example.com" {
		t.Fatalf("userinfo body = %v, want the token's user", body)
	}
	if got := counter.count(); got != 0 {
		t.Fatalf("userinfo ran Config.BuildTokenClaims %d times, want 0", got)
	}

	req.Header.Set("Authorization", "Bearer not-a-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo with a garbage token = %d, want 401", rec.Code)
	}
}
