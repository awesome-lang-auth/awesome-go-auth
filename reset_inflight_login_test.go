package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Under Config.RevokeSessionsOnPasswordReset, a password login that verified
// the old password before a reset, and opens its session only after the
// reset's revocation has run, keeps nothing: once its session exists the login
// reads the account again, finds another password, revokes the session it just
// opened and answers as a wrong password does. Without that, the session
// missed the revocation — it did not exist when the reset looked — and lived
// on, opened with the password the reset was meant to retire.

// holdingSessionStore is a recordingSessionStore whose CreateSession, once
// armed, stops before it writes: it closes entered and waits for release. A
// login held there has read the account and verified the password, which is
// the moment a reset can fall into.
type holdingSessionStore struct {
	*recordingSessionStore
	mu      sync.Mutex
	armed   bool
	entered chan struct{}
	release chan struct{}
}

func newHoldingSessionStore() *holdingSessionStore {
	return &holdingSessionStore{
		recordingSessionStore: &recordingSessionStore{MemorySessionStore: NewMemorySessionStore(), refuse: map[string]error{}},
		entered:               make(chan struct{}),
		release:               make(chan struct{}),
	}
}

// arm makes the next CreateSession, and only that one, wait for release.
func (s *holdingSessionStore) arm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armed = true
}

func (s *holdingSessionStore) CreateSession(ctx context.Context, session Session) (Session, error) {
	s.mu.Lock()
	hold := s.armed
	s.armed = false
	s.mu.Unlock()
	if hold {
		close(s.entered)
		<-s.release
	}
	return s.recordingSessionStore.CreateSession(ctx, session)
}

// eventLog subscribes to every event a bus raises.
type eventLog struct {
	mu     sync.Mutex
	events []Event
}

func newEventLog(bus *EventBus) *eventLog {
	l := &eventLog{}
	bus.Subscribe(EventBusWildcard, func(ev Event) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.events = append(l.events, ev)
	})
	return l
}

func (l *eventLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = nil
}

func (l *eventLog) named(name string) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, ev := range l.events {
		if ev.Name == name {
			out = append(out, ev)
		}
	}
	return out
}

// passwordLogins are the two entry points of a password login.
var passwordLogins = []struct {
	name  string
	login func(*Service, LoginInput) (AuthTokens, error)
}{
	{"Login", func(svc *Service, in LoginInput) (AuthTokens, error) {
		_, tokens, err := svc.Login(context.Background(), in)
		return tokens, err
	}},
	{"LoginWithChallenge", func(svc *Service, in LoginInput) (AuthTokens, error) {
		result, err := svc.LoginWithChallenge(context.Background(), in)
		return result.Tokens, err
	}},
}

// inFlightLogin runs login while a reset with token completes in the window
// between the login's password check and the session it opens, and returns
// what the login answered.
func inFlightLogin(t *testing.T, svc *Service, store *holdingSessionStore, token string, login func() (AuthTokens, error)) (AuthTokens, error) {
	t.Helper()
	type outcome struct {
		tokens AuthTokens
		err    error
	}
	done := make(chan outcome, 1)
	store.arm()
	go func() {
		tokens, err := login()
		done <- outcome{tokens, err}
	}()
	<-store.entered
	resetErr := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: token, NewPassword: "newpassword1"})
	close(store.release)
	got := <-done
	if resetErr != nil {
		t.Fatalf("reset with a login in flight: %v", resetErr)
	}
	return got.tokens, got.err
}

func newInFlightService(t *testing.T, store SessionStore, users UserStore, opts ...func(*Config)) (*Service, *eventLog) {
	t.Helper()
	cfg := testConfig("resetsessions123456789012345678901")
	bus := NewEventBus()
	cfg.Events = bus
	for _, opt := range opts {
		opt(&cfg)
	}
	svc, err := NewService(cfg, users, store)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, newEventLog(bus)
}

// TestRevokingResetLeavesNoSessionToALoginInFlight is the verification's
// probe: a login with the old password is held after its password check, a
// revoking reset runs to completion, and the login is let go. Before this
// change it answered success and its session refreshed; now it is refused as
// a wrong password is — ErrInvalidCredentials, identity.auth.login.failed with
// the address it was sent, no identity.auth.login.success — and the session it
// opened is revoked, so no session opened with the old password is live.
func TestRevokingResetLeavesNoSessionToALoginInFlight(t *testing.T) {
	for _, entry := range passwordLogins {
		t.Run(entry.name, func(t *testing.T) {
			store := newHoldingSessionStore()
			svc, events := newInFlightService(t, store, NewMemoryUserStore(), revokeOnReset)
			ctx := context.Background()
			user, _ := registerUser(t, svc, "inflight@example.com", "t1")
			token := mintResetToken(t, svc, "inflight@example.com")
			events.reset()

			const submitted = " InFlight@Example.com"
			tokens, err := inFlightLogin(t, svc, store, token, func() (AuthTokens, error) {
				return entry.login(svc, LoginInput{Email: submitted, Password: "password1", TenantID: "t1"})
			})

			if !errors.Is(err, ErrInvalidCredentials) {
				t.Errorf("in-flight login with the old password -> err = %v, want ErrInvalidCredentials", err)
			}
			if tokens != (AuthTokens{}) {
				t.Errorf("in-flight login with the old password handed out tokens")
				if _, err := svc.Refresh(ctx, tokens.RefreshToken); err == nil {
					t.Errorf("the session that login opened after the reset still refreshes")
				}
			}
			sessions, err := store.ListSessionsForUser(ctx, user.ID, "t1")
			if err != nil {
				t.Fatalf("list sessions: %v", err)
			}
			if len(sessions) != 2 {
				t.Errorf("the account has %d sessions, want 2: the registration's and the one the in-flight login opened", len(sessions))
			}
			for _, s := range sessions {
				if s.RevokedAt == nil {
					t.Errorf("session %s, opened with the old password, is live after the revoking reset", s.ID)
				}
			}
			if got := events.named(EventAuthLoginSuccess); len(got) != 0 {
				t.Errorf("identity.auth.login.success raised for the refused login: %+v", got)
			}
			failed := events.named(EventAuthLoginFailed)
			if len(failed) != 1 || failed[0].Data["email"] != submitted {
				t.Errorf("identity.auth.login.failed = %+v, want one carrying the submitted address %q", failed, submitted)
			}

			// The new password works, and its session lives.
			fresh := login(t, svc, "inflight@example.com", "newpassword1")
			if _, err := svc.Refresh(ctx, fresh.RefreshToken); err != nil {
				t.Errorf("a login with the new password after the reset: %v", err)
			}
		})
	}
}

// TestInFlightLoginKeepsItsSessionWithTheOptionOff pins the default: with the
// option off a reset revokes nothing, and the same in-flight login answers
// success with a session that lives, as it always has.
func TestInFlightLoginKeepsItsSessionWithTheOptionOff(t *testing.T) {
	store := newHoldingSessionStore()
	svc, _ := newInFlightService(t, store, NewMemoryUserStore())
	registerUser(t, svc, "inflightoff@example.com", "t1")
	token := mintResetToken(t, svc, "inflightoff@example.com")

	tokens, err := inFlightLogin(t, svc, store, token, func() (AuthTokens, error) {
		_, tokens, err := svc.Login(context.Background(), LoginInput{Email: "inflightoff@example.com", Password: "password1", TenantID: "t1"})
		return tokens, err
	})
	if err != nil {
		t.Fatalf("in-flight login with the option off: %v", err)
	}
	if _, err := svc.Refresh(context.Background(), tokens.RefreshToken); err != nil {
		t.Errorf("its session with the option off: %v, want it alive", err)
	}
}

// byIDUserStore is a MemoryUserStore whose GetUserByID answers err once armed.
type byIDUserStore struct {
	*MemoryUserStore
	mu  sync.Mutex
	err error
}

func (s *byIDUserStore) failWith(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *byIDUserStore) GetUserByID(ctx context.Context, id, tenantID string) (User, error) {
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return User{}, err
	}
	return s.MemoryUserStore.GetUserByID(ctx, id, tenantID)
}

// TestPasswordLoginFailsClosedWhenTheAccountCannotBeReadAgain: under the
// option a password login keeps its session only once it has seen the
// account's password unchanged. A read that fails is not that: the login fails
// with the store's failure — not a credential refusal, so no
// identity.auth.login.failed — and the session it opened is revoked. An account
// gone by then is refused as an unknown one is.
func TestPasswordLoginFailsClosedWhenTheAccountCannotBeReadAgain(t *testing.T) {
	for _, tc := range []struct {
		name      string
		readErr   error
		wantCreds bool
	}{
		{"store failure", errors.New("user table unavailable"), false},
		{"account gone", ErrUserNotFound, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users := &byIDUserStore{MemoryUserStore: NewMemoryUserStore()}
			store := newHoldingSessionStore()
			svc, events := newInFlightService(t, store, users, revokeOnReset)
			ctx := context.Background()
			user, _ := registerUser(t, svc, "reread@example.com", "t1")
			events.reset()
			users.failWith(tc.readErr)

			_, tokens, err := svc.Login(ctx, LoginInput{Email: "reread@example.com", Password: "password1", TenantID: "t1"})
			users.failWith(nil)
			if err == nil || tokens != (AuthTokens{}) {
				t.Fatalf("login whose account could not be read again: tokens handed out = %v, err = %v; want a failure", tokens != (AuthTokens{}), err)
			}
			if got := errors.Is(err, ErrInvalidCredentials); got != tc.wantCreds {
				t.Errorf("err = %v; ErrInvalidCredentials = %v, want %v", err, got, tc.wantCreds)
			}
			if got := len(events.named(EventAuthLoginFailed)); got != map[bool]int{true: 1, false: 0}[tc.wantCreds] {
				t.Errorf("identity.auth.login.failed raised %d times", got)
			}
			sessions, _ := store.ListSessionsForUser(ctx, user.ID, "t1")
			live := 0
			for _, s := range sessions {
				if s.RevokedAt == nil {
					live++
				}
			}
			if live != 1 {
				t.Errorf("%d live sessions, want 1 — the registration's; the refused login's must be revoked", live)
			}
		})
	}
}

// TestPasswordLoginUnderTheOptionKeepsAMigratedHash: a login that adopts the
// password through Config.PasswordVerifier rewrites the stored hash itself.
// The session it opens is kept: the hash it compares the account against is
// the one it wrote, not the marker it read.
func TestPasswordLoginUnderTheOptionKeepsAMigratedHash(t *testing.T) {
	users := NewMemoryUserStore()
	store := newHoldingSessionStore()
	svc, _ := newInFlightService(t, store, users, revokeOnReset, func(c *Config) {
		c.PasswordVerifier = func(_ context.Context, user User, password string) (bool, bool, error) {
			return user.PasswordHash == "legacy:marker" && password == "password1", true, nil
		}
	})
	ctx := context.Background()
	if _, err := users.CreateUser(ctx, User{ID: "usr_legacy", Email: "legacy@example.com", PasswordHash: "legacy:marker", TenantID: "t1", IsEmailVerified: true}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, tokens, err := svc.Login(ctx, LoginInput{Email: "legacy@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("migrating login under the option: %v", err)
	}
	if _, err := svc.Refresh(ctx, tokens.RefreshToken); err != nil {
		t.Errorf("the migrating login's session: %v, want it alive", err)
	}
	if storedUser(t, svc, "usr_legacy").PasswordHash == "legacy:marker" {
		t.Error("precondition: the login did not migrate the hash")
	}
}

// TestRevokingResetLeavesNoSessionToAnEnrolmentInFlight is the same window on
// the one other path that opens a session on the strength of the password:
// the forced enrolment of EnrolOnLogin. Its token is bound to the password,
// but the binding is checked before the factor is stored and the session
// opened, and a reset that lands in between used to leave that session alive.
// Now the completion reads the account again once its session exists, gives
// the session up and answers ErrInvalidToken, as a token minted under another
// password is answered.
func TestRevokingResetLeavesNoSessionToAnEnrolmentInFlight(t *testing.T) {
	store := newHoldingSessionStore()
	svc, events := newInFlightService(t, store, NewMemoryUserStore(), revokeOnReset, func(c *Config) {
		c.Require2FA = true
		c.EnrolOnLogin = true
		c.SendMagicLink, c.SendSMSCode = nil, nil
	})
	ctx := context.Background()
	user, enrolment := setupChallenge(t, svc, "enrolinflight@example.com")
	setup, err := svc.NewForcedTOTPEnrolment(ctx, enrolment)
	if err != nil {
		t.Fatalf("NewForcedTOTPEnrolment: %v", err)
	}
	token := mintResetToken(t, svc, "enrolinflight@example.com")
	events.reset()

	tokens, err := inFlightLogin(t, svc, store, token, func() (AuthTokens, error) {
		_, tokens, err := svc.CompleteTOTPEnrolment(ctx, enrolment, setup.Secret, codeFor(t, setup.Secret, time.Now()))
		return tokens, err
	})

	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("enrolment in flight across the reset -> err = %v, want ErrInvalidToken", err)
	}
	if tokens != (AuthTokens{}) {
		t.Errorf("enrolment in flight across the reset handed out tokens")
		if _, err := svc.Refresh(ctx, tokens.RefreshToken); err == nil {
			t.Errorf("the session that enrolment opened after the reset still refreshes")
		}
	}
	sessions, err := store.ListSessionsForUser(ctx, user.ID, "t1")
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].RevokedAt == nil {
		t.Errorf("sessions = %+v, want the one the enrolment opened, revoked", sessions)
	}
	if got := events.named(EventAuthLoginSuccess); len(got) != 0 {
		t.Errorf("identity.auth.login.success raised for the refused enrolment: %+v", got)
	}
}
