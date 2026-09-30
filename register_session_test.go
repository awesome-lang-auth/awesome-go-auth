package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// Config.IssueSessionOnRegister (#21, the family spec "register may open a
// session"). The wire half — cookies, bearer bodies, GET /me on the issued
// credential — is pinned on all four adapters in adapter/internal/wiretest;
// these pin the service half: the default, the gates that win over the option,
// the session row and the events.

func registerSessionService(t *testing.T, tweak func(*Config)) (*Service, *EventBus, *[]Event) {
	t.Helper()
	cfg := testConfig(testSecret)
	bus := NewEventBus()
	cfg.Events = bus
	if tweak != nil {
		tweak(&cfg)
	}
	var (
		mu  sync.Mutex
		got []Event
	)
	bus.Subscribe(EventBusWildcard, func(ev Event) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, ev)
	})
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, bus, &got
}

func sessionsOf(t *testing.T, svc *Service, user User) []Session {
	t.Helper()
	sessions, err := svc.ListSessions(context.Background(), user.ID, user.TenantID)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	return sessions
}

func TestIssueSessionOnRegister_DefaultsOnInZeroX(t *testing.T) {
	if !DefaultConfig(testSecret).IssueSessionOnRegister {
		t.Fatal("DefaultConfig().IssueSessionOnRegister = false; it stays true until v1.0.0")
	}
	if (Config{}).IssueSessionOnRegister {
		t.Fatal("the zero Config has the option on")
	}
	a, err := newTestAuth()
	if err != nil {
		t.Fatalf("newTestAuth: %v", err)
	}
	if !a.service.cfg.IssueSessionOnRegister {
		t.Fatal("New() has the option off; it is built on DefaultConfig")
	}
	a, err = newTestAuth(WithIssueSessionOnRegister(false))
	if err != nil {
		t.Fatalf("newTestAuth: %v", err)
	}
	if a.service.cfg.IssueSessionOnRegister {
		t.Fatal("WithIssueSessionOnRegister(false) left the option on")
	}
}

// On: the login's session — a usable pair, a session row, and the login's
// event after the registration's own.
func TestRegister_OnOpensTheLoginsSession(t *testing.T) {
	svc, _, events := registerSessionService(t, nil)
	ctx := context.Background()
	user, tokens, err := svc.Register(ctx, RegisterInput{Email: "on@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("tokens = %+v, want a pair", tokens)
	}
	if _, err := svc.Me(ctx, tokens.AccessToken); err != nil {
		t.Fatalf("Me on the issued access token: %v", err)
	}
	sessions := sessionsOf(t, svc, user)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want the one the registration opened", len(sessions))
	}
	if len(*events) != 2 || (*events)[0].Name != EventUserCreated || (*events)[1].Name != EventAuthLoginSuccess {
		t.Fatalf("events = %v, want [%s %s]", eventNamesOf(*events), EventUserCreated, EventAuthLoginSuccess)
	}
	login := (*events)[1]
	if login.UserID != user.ID || login.SessionID != sessions[0].ID || login.Data["method"] != loginMethodLocal {
		t.Fatalf("login event = %+v, want user %s, session %s, method %q", login, user.ID, sessions[0].ID, loginMethodLocal)
	}
}

// Off: the reference's answer — the account and nothing else.
func TestRegister_OffCreatesTheAccountOnly(t *testing.T) {
	svc, _, events := registerSessionService(t, func(c *Config) { c.IssueSessionOnRegister = false })
	user, tokens, err := svc.Register(context.Background(), RegisterInput{Email: "off@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if tokens != (AuthTokens{}) {
		t.Fatalf("tokens = %+v, want none", tokens)
	}
	if n := len(sessionsOf(t, svc, user)); n != 0 {
		t.Fatalf("sessions = %d, want none", n)
	}
	if len(*events) != 1 || (*events)[0].Name != EventUserCreated {
		t.Fatalf("events = %v, want only %s", eventNamesOf(*events), EventUserCreated)
	}
	if _, _, err := svc.Login(context.Background(), LoginInput{Email: "off@example.com", Password: "password1", TenantID: "t1"}); err != nil {
		t.Fatalf("the account cannot log in afterwards: %v", err)
	}
}

// Email verification wins: under strict the new address is unverified, the
// login would refuse it, and so the registration issues nothing — the bypass
// #21 was filed about.
func TestRegister_StrictVerificationWinsOverTheOption(t *testing.T) {
	svc, _, events := registerSessionService(t, func(c *Config) { c.EmailVerificationMode = EmailVerificationModeStrict })
	user, tokens, err := svc.Register(context.Background(), RegisterInput{Email: "strict@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if tokens != (AuthTokens{}) {
		t.Fatalf("tokens = %+v under strict, want none", tokens)
	}
	if n := len(sessionsOf(t, svc, user)); n != 0 {
		t.Fatalf("sessions = %d under strict, want none", n)
	}
	for _, ev := range *events {
		if ev.Name == EventAuthLoginSuccess {
			t.Fatalf("a login was published under strict: %v", eventNamesOf(*events))
		}
	}
}

// Lazy lets an unverified address log in, so it lets the registration open a
// session too: the gate is the login's, not a stricter one of its own.
func TestRegister_LazyVerificationStillIssues(t *testing.T) {
	svc, _, _ := registerSessionService(t, func(c *Config) { c.EmailVerificationMode = EmailVerificationModeLazy })
	user, tokens, err := svc.Register(context.Background(), RegisterInput{Email: "lazy@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.IsEmailVerified || tokens.AccessToken == "" {
		t.Fatalf("user verified = %v, tokens = %+v; want an unverified account with a session", user.IsEmailVerified, tokens)
	}
}

// A required second factor wins too: the login would answer a challenge, so
// the registration does not hand out a full session.
func TestRegister_RequiredSecondFactorWinsOverTheOption(t *testing.T) {
	svc, _, _ := registerSessionService(t, func(c *Config) { c.Require2FA = true })
	user, tokens, err := svc.Register(context.Background(), RegisterInput{Email: "2fa@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if tokens != (AuthTokens{}) || len(sessionsOf(t, svc, user)) != 0 {
		t.Fatalf("tokens = %+v under Require2FA, want none and no session", tokens)
	}
}

// Refusals first: a refused registration issues nothing, whatever the option.
func TestRegister_RefusedIssuesNothing(t *testing.T) {
	svc, _, events := registerSessionService(t, nil)
	ctx := context.Background()
	existing, _, err := svc.Register(ctx, RegisterInput{Email: "dup@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	*events = nil
	for _, in := range []RegisterInput{
		{Email: "dup@example.com", Password: "password1", TenantID: "t1"},
		{Email: "short@example.com", Password: "x", TenantID: "t1"},
		{Email: "", Password: "password1", TenantID: "t1"},
	} {
		_, tokens, err := svc.Register(ctx, in)
		if err == nil || tokens != (AuthTokens{}) {
			t.Fatalf("Register(%+v) = %+v, %v; want a refusal with no tokens", in, tokens, err)
		}
	}
	if len(*events) != 0 {
		t.Fatalf("a refused registration published %v", eventNamesOf(*events))
	}
	if n := len(sessionsOf(t, svc, existing)); n != 1 {
		t.Fatalf("sessions = %d, want only the first registration's", n)
	}
}

// Both configured together is logged once, at construction, so a deployment
// that expected registration to log people in is told why it does not.
func TestIssueSessionOnRegister_StrictIsLoggedOnce(t *testing.T) {
	for _, tc := range []struct {
		name    string
		on      bool
		mode    string
		wantLog bool
	}{
		{"on and strict", true, EmailVerificationModeStrict, true},
		{"off and strict", false, EmailVerificationModeStrict, false},
		{"on and lazy", true, EmailVerificationModeLazy, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lines []string
			cfg := testConfig(testSecret)
			cfg.IssueSessionOnRegister = tc.on
			cfg.EmailVerificationMode = tc.mode
			cfg.Logger = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
			svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
			if err != nil {
				t.Fatalf("NewService: %v", err)
			}
			if _, _, err := svc.Register(context.Background(), RegisterInput{Email: "log@example.com", Password: "password1", TenantID: "t1"}); err != nil {
				t.Fatalf("Register: %v", err)
			}
			n := 0
			for _, line := range lines {
				if strings.Contains(line, "IssueSessionOnRegister") {
					n++
				}
			}
			if tc.wantLog && n != 1 || !tc.wantLog && n != 0 {
				t.Fatalf("logged %d notice(s), want %v: %q", n, tc.wantLog, lines)
			}
		})
	}
}
