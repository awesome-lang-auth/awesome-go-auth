package wiretest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// The invitation flow (invitation.go in the root package) on every adapter.
//
// The public route, POST <prefix>/invitations/accept, is pinned end to end:
// mounted only with an InvitationStore, under ClosedRegistration too and never
// under ResourceServer; the registration's 201 by default and the session when
// IssueSessionOnRegister allows one; one 401 for every refusal of the token;
// the password and the body checked before the token is spent; the
// 2FA_SETUP_REQUIRED answer and the forced enrolment that opens the session;
// the rate-limiter slot and the CSRF exemption. The three admin routes are
// served by the one AdminHandler on every adapter, and are replayed here only
// to prove each adapter's admin mount reaches them.

// invitationRecorder keeps what the invitation sender was handed.
type invitationRecorder struct {
	mu   sync.Mutex
	sent []auth.InvitationDelivery
}

func (r *invitationRecorder) send(_ context.Context, d auth.InvitationDelivery) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, d)
	return nil
}

// invitationRouteSet is the conditional set for an InvitationStore: it adds
// the accept route, documented by OpenAPIInfo.Invitations.
func invitationRouteSet() conditionalRouteSet {
	return conditionalRouteSet{
		name: "Invitations",
		configure: func(pc *probeConfig) {
			pc.Opts = append(pc.Opts, auth.WithInvitationStore(auth.NewMemoryInvitationStore()))
		},
		routes: map[string]string{auth.InvitationAcceptRoute: http.MethodPost},
		spec:   func() auth.OpenAPIInfo { return auth.OpenAPIInfo{Invitations: true} },
	}
}

// invitationEnv mounts a deployment with the invitation flow on and nothing
// delivered but invitations: no magic-link or SMS sender, so an account under
// a second-factor policy has no method to present and the login — and the
// acceptance — answer 2FA_SETUP_REQUIRED.
func invitationEnv(t *testing.T, mount Mounter, cfg auth.HTTPConfig, opts ...auth.Option) (*Env, *invitationRecorder) {
	t.Helper()
	recorder := &invitationRecorder{}
	opts = append([]auth.Option{
		auth.WithInvitationStore(auth.NewMemoryInvitationStore()),
		auth.WithInvitationSender(recorder.send),
		auth.WithSecret(wiretestAccessSecret),
	}, opts...)
	env := newEnv(t, mount, cfg, opts...)
	env.Delivered = &Deliveries{}
	return env, recorder
}

// invite creates an invitation through the service and returns the token the
// sender was handed.
func invite(t *testing.T, env *Env, email string) auth.InvitationResult {
	t.Helper()
	result, err := env.Auth.InviteUser(context.Background(), auth.InviteUserInput{Email: email, TenantID: testTenant})
	if err != nil {
		t.Fatalf("InviteUser(%s): %v", email, err)
	}
	return result
}

func acceptRequest(env *Env, token, password string) *http.Request {
	return env.Request(http.MethodPost, auth.InvitationAcceptRoute, map[string]string{"token": token, "password": password})
}

func testInvitations(t *testing.T, mount Mounter) {
	t.Run("accepting answers like a registration, and the invitee then logs in", func(t *testing.T) {
		env, recorder := invitationEnv(t, mount, auth.DefaultHTTPConfig())
		result := invite(t, env, "invitee@example.com")
		if len(recorder.sent) != 1 || recorder.sent[0].Token != result.Token {
			t.Fatalf("deliveries = %+v", recorder.sent)
		}
		rec := env.Do(acceptRequest(env, result.Token, "a-new-password"))
		AssertStatus(t, rec, http.StatusCreated)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "userId")
		if body["userId"] != result.User.ID {
			t.Fatalf("userId = %v, want %s", body["userId"], result.User.ID)
		}
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)

		login := env.Do(env.Request(http.MethodPost, "/login", map[string]string{
			"email": "invitee@example.com", "password": "a-new-password", "tenantId": testTenant,
		}))
		AssertStatus(t, login, http.StatusOK)
		Cookie(t, login, hostAccess)
	})

	t.Run("IssueSessionOnRegister: the session, in cookies or in the body", func(t *testing.T) {
		env, _ := invitationEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIssueSessionOnRegister(true))
		cookie := env.Do(acceptRequest(env, invite(t, env, "cookie@example.com").Token, "a-new-password"))
		AssertStatus(t, cookie, http.StatusCreated)
		AssertKeys(t, Body(t, cookie), "success", "userId")
		Cookie(t, cookie, hostAccess)
		Cookie(t, cookie, hostRefresh)

		req := acceptRequest(env, invite(t, env, "bearer@example.com").Token, "a-new-password")
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		bearer := env.Do(req)
		AssertStatus(t, bearer, http.StatusCreated)
		AssertKeys(t, Body(t, bearer), "success", "userId", "accessToken", "refreshToken")
		AssertNoCookies(t, bearer)
	})

	t.Run("every refusal of the token is the same 401", func(t *testing.T) {
		users := auth.NewMemoryUserStore()
		env, _ := invitationEnv(t, mount, auth.DefaultHTTPConfig(),
			auth.WithUserStore(users), auth.WithInvitationStore(expiringStore{auth.NewMemoryInvitationStore()}))
		ctx := context.Background()

		replayed := invite(t, env, "replayed@example.com")
		AssertStatus(t, env.Do(acceptRequest(env, replayed.Token, "a-new-password")), http.StatusCreated)
		revoked := invite(t, env, "revoked@example.com")
		if _, err := env.Auth.RevokeInvitation(ctx, revoked.Invitation.ID, "", ""); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		// An account another route activated: a password reset, say.
		active := invite(t, env, "active@example.com")
		if err := users.UpdatePassword(ctx, active.User.ID, testTenant, "a-hash-set-by-another-route"); err != nil {
			t.Fatalf("activate: %v", err)
		}

		var first string
		for name, token := range map[string]string{
			"unknown":          "not-a-token-anybody-minted",
			"replayed":         replayed.Token,
			"revoked":          revoked.Token,
			"already active":   active.Token,
			"expired":          invite(t, env, "expired@example.com").Token,
			"tampered (1 bit)": flipLast(invite(t, env, "tampered@example.com").Token),
		} {
			rec := env.Do(acceptRequest(env, token, "a-new-password"))
			AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired invitation", auth.CodeInvalidInvitation)
			AssertNoCookie(t, rec, hostAccess)
			AssertNoCookie(t, rec, hostRefresh)
			if first == "" {
				first = rec.Body.String()
			} else if rec.Body.String() != first {
				t.Errorf("%s: body %q differs from %q — a refusal must not say which one it was", name, rec.Body.String(), first)
			}
		}
	})

	t.Run("the body and the password are checked before the token is spent", func(t *testing.T) {
		env, _ := invitationEnv(t, mount, auth.DefaultHTTPConfig())
		result := invite(t, env, "invitee@example.com")
		AssertError(t, env.Do(acceptRequest(env, result.Token, "short")),
			http.StatusBadRequest, "Password is too weak", auth.CodeWeakPassword)
		AssertError(t, env.Do(acceptRequest(env, result.Token, "")),
			http.StatusBadRequest, "Token and password are required", auth.CodeInvalidInput)
		AssertError(t, env.Do(env.Request(http.MethodPost, auth.InvitationAcceptRoute, nil)),
			http.StatusBadRequest, "Token and password are required", auth.CodeInvalidInput)
		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+auth.InvitationAcceptRoute, strings.NewReader("{not json"))
		req.Header.Set("Content-Type", "application/json")
		AssertError(t, env.Do(req), http.StatusBadRequest, auth.HTTPErrInvalidBody.Message, auth.CodeInvalidBody)
		// None of that cost the invitee the invitation.
		AssertStatus(t, env.Do(acceptRequest(env, result.Token, "a-new-password")), http.StatusCreated)
	})

	t.Run("Require2FA: 2FA_SETUP_REQUIRED, and enrolling opens the session", func(t *testing.T) {
		env, _ := invitationEnv(t, mount, auth.DefaultHTTPConfig(),
			auth.WithRequire2FA(true), auth.WithEnrolOnLogin(true), auth.WithIssueSessionOnRegister(true))
		result := invite(t, env, "operator@example.com")
		rec := env.Do(acceptRequest(env, result.Token, "a-new-password"))
		AssertStatus(t, rec, http.StatusForbidden)
		body := Body(t, rec)
		AssertKeys(t, body, "requires2FASetup", "tempToken", "code")
		if body["requires2FASetup"] != true || body["code"] != auth.CodeTwoFactorSetupRequired {
			t.Fatalf("answer = %v", body)
		}
		// No session credential: the CSRF middleware's csrf-token cookie is
		// the only one, as on the login's own challenge.
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)
		token, _ := body["tempToken"].(string)

		// The enrolment token reaches nothing but the two enrolment routes.
		me := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		me.Header.Set("Authorization", "Bearer "+token)
		if got := env.Do(me); got.Code == http.StatusOK {
			t.Fatal("the enrolment token authenticated GET /me")
		}
		_, verify := enrolWithToken(t, env, token, false)
		AssertStatus(t, verify, http.StatusOK)
		Cookie(t, verify, hostAccess)
		Cookie(t, verify, hostRefresh)
	})

	t.Run("mounted under ClosedRegistration, not without a store, not under ResourceServer", func(t *testing.T) {
		closed := auth.DefaultHTTPConfig()
		closed.ClosedRegistration = true
		env, _ := invitationEnv(t, mount, closed)
		AssertStatus(t, env.Do(acceptRequest(env, invite(t, env, "closed@example.com").Token, "a-new-password")), http.StatusCreated)
		if rec := env.Do(env.Request(http.MethodPost, auth.RegisterRoute, credentials("self@example.com"))); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST /register = %d beside the accept route; ClosedRegistration must still close it", rec.Code)
		}

		bare := NewEnv(t, mount, auth.DefaultHTTPConfig())
		if rec := bare.Do(acceptRequest(bare, "t", "a-new-password")); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("accept without an InvitationStore = %d, want 404", rec.Code)
		}

		rs := auth.DefaultHTTPConfig()
		rs.ResourceServer = true
		gated, _ := invitationEnv(t, mount, rs)
		if rec := gated.Do(acceptRequest(gated, invite(t, gated, "rs@example.com").Token, "a-new-password")); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("accept under ResourceServer = %d, want 404", rec.Code)
		}
	})

	t.Run("the rate-limiter slot sees it once, and a refusal spends nothing", func(t *testing.T) {
		recorder := &rateLimitRecorder{}
		cfg := auth.DefaultHTTPConfig()
		cfg.RateLimiter = recorder.middleware
		env, _ := invitationEnv(t, mount, cfg)
		recorder.take()
		AssertStatus(t, env.Do(acceptRequest(env, "unknown", "a-new-password")), http.StatusUnauthorized)
		if seen := recorder.take(); len(seen) != 1 || seen[0] != http.MethodPost+" "+env.Config.Prefix()+auth.InvitationAcceptRoute {
			t.Fatalf("the slot saw %v, want the accept route once", seen)
		}

		refusing := auth.DefaultHTTPConfig()
		refusing.RateLimiter = refusingRateLimiter
		limited, _ := invitationEnv(t, mount, refusing)
		blocked := invite(t, limited, "blocked@example.com")
		rec := limited.Do(acceptRequest(limited, blocked.Token, "a-new-password"))
		AssertStatus(t, rec, http.StatusTooManyRequests)
		if rec.Body.String() != rateLimitRefusedBody {
			t.Fatalf("body = %q, want the limiter's own", rec.Body.String())
		}
		if _, err := limited.Auth.AcceptInvitation(context.Background(), auth.AcceptInvitationInput{Token: blocked.Token, Password: "a-new-password"}); err != nil {
			t.Fatalf("the refused request spent the invitation: %v", err)
		}
	})

	t.Run("CSRF-exempt: another account's cookie and no pair is still accepted", func(t *testing.T) {
		env, _ := invitationEnv(t, mount, auth.DefaultHTTPConfig())
		_, other := env.Seed("other@example.com")
		req := acceptRequest(env, invite(t, env, "invitee@example.com").Token, "a-new-password")
		req.AddCookie(&http.Cookie{Name: hostAccess, Value: other.AccessToken})
		AssertStatus(t, env.Do(req), http.StatusCreated)
	})

	t.Run("the admin mount reaches the three routes", func(t *testing.T) {
		cfg := auth.DefaultHTTPConfig()
		cfg.Admin = machineOptions()
		env, recorder := invitationEnv(t, mount, cfg)
		admin := &adminEnv{Env: env}

		rec := env.Do(admin.machineRequest(http.MethodPost, auth.AdminInvitationsPath, `{"email":"invitee@example.com","tenantId":"t1"}`, "svc:identity"))
		AssertStatus(t, rec, http.StatusCreated)
		created := Body(t, rec)
		AssertKeys(t, created, "success", "invitationId", "userId", "email", "expiresAt")
		if strings.Contains(rec.Body.String(), recorder.sent[0].Token) {
			t.Fatal("the token is in the admin answer")
		}

		rec = env.Do(admin.machineRequest(http.MethodGet, auth.AdminInvitationsPath, "", "svc:identity"))
		AssertStatus(t, rec, http.StatusOK)
		if rows := adminEntries(t, Body(t, rec), "invitations"); len(rows) != 1 {
			t.Fatalf("invitations = %v", rows)
		}

		id, _ := created["invitationId"].(string)
		rec = env.Do(admin.machineRequest(http.MethodDelete, auth.AdminInvitationsPath+"/"+id, "", "svc:identity"))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success", "accountRemoved")
		AssertError(t, env.Do(acceptRequest(env, recorder.sent[0].Token, "a-new-password")),
			http.StatusUnauthorized, "Invalid or expired invitation", auth.CodeInvalidInvitation)

		// Without a store the listing path is the detail route's, as before.
		plain := NewEnv(t, mount, cfg)
		rec = plain.Do((&adminEnv{Env: plain}).machineRequest(http.MethodGet, auth.AdminInvitationsPath, "", "svc:identity"))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s without a store = %d %s, want the detail route's 404", auth.AdminInvitationsPath, rec.Code, rec.Body.String())
		}
	})
}

// expiringStore stores every invitation to an address starting "expired" an
// hour past its expiry: the service's clock is not reachable from here.
type expiringStore struct{ *auth.MemoryInvitationStore }

func (s expiringStore) CreateInvitation(ctx context.Context, invitation auth.Invitation) error {
	if strings.HasPrefix(invitation.Email, "expired") {
		invitation.ExpiresAt = time.Now().Add(-time.Hour)
	}
	return s.MemoryInvitationStore.CreateInvitation(ctx, invitation)
}

// flipLast changes the token's last character, so it is one a holder of the
// real token could guess at, and not it.
func flipLast(token string) string {
	last := token[len(token)-1]
	replacement := byte('A')
	if last == 'A' {
		replacement = 'B'
	}
	return token[:len(token)-1] + string(replacement)
}
