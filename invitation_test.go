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

// The invitation flow at the service: what InviteUser writes, the security
// properties of AcceptInvitation — single use, expiry, the constant-time
// comparison, one refusal for every reason, no token in a log line, an event or
// an error — and what a revocation, a re-invitation and a failed send leave
// behind. The routes are pinned in admin_invitations_test.go and, on all four
// adapters, in adapter/internal/wiretest/invitations.go.

const invitedEmail = "invitee@example.com"

// invitationFixture is an Auth with the invitation flow on: a memory store, a
// recording sender, a recording password-reset sender (the side door the
// pending account has), a metadata store, an event bus and a logger that keeps
// every formatted line.
type invitationFixture struct {
	t        *testing.T
	auth     *Auth
	users    *MemoryUserStore
	store    *MemoryInvitationStore
	metadata *MemoryMetadataStore

	mu         sync.Mutex
	events     []Event
	logs       []string
	deliveries []InvitationDelivery
	resets     []PasswordResetDelivery
	sendErr    error
}

func newInvitationFixture(t *testing.T, opts ...Option) *invitationFixture {
	t.Helper()
	f := &invitationFixture{
		t:        t,
		users:    NewMemoryUserStore(),
		store:    NewMemoryInvitationStore(),
		metadata: NewMemoryMetadataStore(),
	}
	bus := NewEventBus()
	bus.Subscribe(EventBusWildcard, func(ev Event) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.events = append(f.events, ev)
	})
	base := []Option{
		WithUserStore(f.users),
		WithBcryptCost(testBcryptCost),
		WithEventBus(bus),
		WithLogger(func(format string, args ...any) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.logs = append(f.logs, fmt.Sprintf(format, args...))
		}),
		WithInvitationStore(f.store),
		WithInvitationSender(f.send),
		WithPasswordResetSender(func(_ context.Context, d PasswordResetDelivery) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.resets = append(f.resets, d)
			return nil
		}),
		WithMetadataProvider(f.metadata),
	}
	a, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.auth = a
	return f
}

func (f *invitationFixture) send(_ context.Context, d InvitationDelivery) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.deliveries = append(f.deliveries, d)
	return nil
}

func (f *invitationFixture) svc() *Service { return f.auth.service }

func (f *invitationFixture) raised() []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Event(nil), f.events...)
}

func (f *invitationFixture) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events, f.deliveries, f.resets = nil, nil, nil
}

func (f *invitationFixture) invite(email string) InvitationResult {
	f.t.Helper()
	result, err := f.auth.InviteUser(context.Background(), InviteUserInput{
		Email:         email,
		TenantID:      "t1",
		Role:          "operator",
		Metadata:      map[string]any{"team": "ops"},
		InvitedBy:     "svc:identity",
		InvitedByKind: InvitedByMachine,
		LinkBase:      "https://console.example.com/auth",
		Lang:          "it",
	})
	if err != nil {
		f.t.Fatalf("InviteUser(%s): %v", email, err)
	}
	return result
}

func (f *invitationFixture) accept(token, password string) (InvitationAcceptance, error) {
	return f.auth.AcceptInvitation(context.Background(), AcceptInvitationInput{Token: token, Password: password})
}

func TestInviteUserCreatesAPendingAccount(t *testing.T) {
	f := newInvitationFixture(t)
	result := f.invite("  Invitee@Example.COM ")

	if !result.AccountCreated || result.Token == "" {
		t.Fatalf("result = %+v, want a created account and a token", result)
	}
	user, err := f.users.GetUserByID(context.Background(), result.User.ID, "t1")
	if err != nil {
		t.Fatalf("the pending account is not stored: %v", err)
	}
	if user.Email != invitedEmail || user.PasswordHash != "" || user.IsEmailVerified || user.IsTOTPEnabled || user.Role != "operator" {
		t.Fatalf("pending account = %+v, want the normalised address, no password, unverified, no factor, the role", user)
	}
	if !strings.HasPrefix(user.ID, "usr_") {
		t.Errorf("user id %q, want one this package mints", user.ID)
	}
	metadata, _ := f.metadata.GetMetadata(context.Background(), user.ID)
	if metadata["team"] != "ops" {
		t.Errorf("metadata = %v, want the invitation's written to the account", metadata)
	}

	inv := result.Invitation
	switch {
	case !strings.HasPrefix(inv.ID, "inv_"):
		t.Errorf("invitation id %q", inv.ID)
	case inv.TokenHash != hashToken(result.Token) || inv.TokenHash == result.Token:
		t.Errorf("token hash %q is not the SHA-256 of the token", inv.TokenHash)
	case inv.UserID != user.ID || inv.TenantID != "t1" || inv.Email != invitedEmail:
		t.Errorf("invitation = %+v, want it bound to the pending account", inv)
	case inv.InvitedBy != "svc:identity" || inv.InvitedByKind != InvitedByMachine:
		t.Errorf("inviter = %q/%q", inv.InvitedBy, inv.InvitedByKind)
	case inv.ExpiresAt.Sub(inv.CreatedAt) != DefaultInvitationTTL:
		t.Errorf("lifetime = %v, want the 72h default", inv.ExpiresAt.Sub(inv.CreatedAt))
	case !inv.Pending():
		t.Errorf("a new invitation is not pending: %+v", inv)
	}

	if len(f.deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(f.deliveries))
	}
	d := f.deliveries[0]
	if d.Token != result.Token || d.Email != invitedEmail || d.InvitationID != inv.ID || d.UserID != user.ID ||
		d.TenantID != "t1" || d.LinkBase != "https://console.example.com/auth" || d.Lang != "it" ||
		d.Role != "operator" || d.Metadata["team"] != "ops" || !d.ExpiresAt.Equal(inv.ExpiresAt) {
		t.Errorf("delivery = %+v", d)
	}

	events := f.raised()
	if len(events) != 1 || events[0].Name != EventUserInvited {
		t.Fatalf("raised %v, want one %s", eventNamesOf(events), EventUserInvited)
	}
	ev := events[0]
	if ev.UserID != user.ID || ev.TenantID != "t1" {
		t.Errorf("event names %q/%q", ev.UserID, ev.TenantID)
	}
	want := map[string]any{
		"invitationId": inv.ID, "email": invitedEmail, "invitedBy": "svc:identity",
		"invitedByKind": InvitedByMachine, "expiresAt": inv.ExpiresAt.UTC().Format(time.RFC3339),
		"accountCreated": true,
	}
	assertEventData(t, ev, want)
}

func assertEventData(t *testing.T, ev Event, want map[string]any) {
	t.Helper()
	if len(ev.Data) != len(want) {
		t.Errorf("%s data = %v, want exactly %v", ev.Name, ev.Data, want)
	}
	for k, v := range want {
		if ev.Data[k] != v {
			t.Errorf("%s data[%q] = %v, want %v", ev.Name, k, ev.Data[k], v)
		}
	}
}

func TestAcceptInvitation(t *testing.T) {
	t.Run("sets the password, verifies the address, and opens no session by default", func(t *testing.T) {
		f := newInvitationFixture(t)
		result := f.invite(invitedEmail)
		f.reset()

		acceptance, err := f.accept(result.Token, "a-new-password")
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if acceptance.Challenge != nil || acceptance.Tokens.AccessToken != "" {
			t.Fatalf("acceptance = %+v, want neither a challenge nor a session", acceptance)
		}
		if acceptance.User.ID != result.User.ID || acceptance.Invitation.AcceptedAt == nil {
			t.Fatalf("acceptance names %q, accepted at %v", acceptance.User.ID, acceptance.Invitation.AcceptedAt)
		}
		stored, _ := f.users.GetUserByID(context.Background(), result.User.ID, "t1")
		if !stored.IsEmailVerified || !verifyPassword("a-new-password", stored.PasswordHash) {
			t.Fatalf("stored = %+v, want the password set and the address verified", stored)
		}
		// The invitee logs in with the password just set.
		if _, tokens, err := f.auth.Login(context.Background(), LoginInput{Email: invitedEmail, Password: "a-new-password", TenantID: "t1"}); err != nil || tokens.AccessToken == "" {
			t.Fatalf("login after accept: %v", err)
		}
		events := f.raised()
		if len(events) < 1 || events[0].Name != EventUserInvitationAccepted {
			t.Fatalf("raised %v, want %s first", eventNamesOf(events), EventUserInvitationAccepted)
		}
		assertEventData(t, events[0], map[string]any{"invitationId": result.Invitation.ID})
		if events[0].UserID != result.User.ID || events[0].TenantID != "t1" {
			t.Errorf("accepted event names %q/%q", events[0].UserID, events[0].TenantID)
		}
	})

	t.Run("IssueSessionOnRegister opens the session, raising the login after the acceptance", func(t *testing.T) {
		f := newInvitationFixture(t, WithIssueSessionOnRegister(true))
		result := f.invite(invitedEmail)
		f.reset()
		acceptance, err := f.accept(result.Token, "a-new-password")
		if err != nil || acceptance.Tokens.AccessToken == "" || acceptance.Tokens.RefreshToken == "" {
			t.Fatalf("accept = %+v, %v, want a session", acceptance, err)
		}
		if _, err := f.auth.VerifyAccess(context.Background(), acceptance.Tokens.AccessToken); err != nil {
			t.Fatalf("the session's access token does not verify: %v", err)
		}
		names := eventNamesOf(f.raised())
		if strings.Join(names, ",") != EventUserInvitationAccepted+","+EventAuthLoginSuccess {
			t.Fatalf("raised %v, want the acceptance then the login", names)
		}
		if got := f.raised()[1].Data["method"]; got != loginMethodLocal {
			t.Errorf("login method = %v, want %q, as a registration that opens a session raises", got, loginMethodLocal)
		}
	})

	t.Run("a missing field or a short password is refused before the token is spent", func(t *testing.T) {
		f := newInvitationFixture(t)
		result := f.invite(invitedEmail)
		for _, tc := range []struct {
			token, password string
			want            error
		}{
			{"", "a-new-password", ErrInvalidInput},
			{result.Token, "", ErrInvalidInput},
			{result.Token, "short", ErrWeakPassword},
		} {
			if _, err := f.accept(tc.token, tc.password); !errors.Is(err, tc.want) {
				t.Errorf("accept(token present %v, %q) = %v, want %v", tc.token != "", tc.password, err, tc.want)
			}
		}
		if _, err := f.accept(result.Token, "a-new-password"); err != nil {
			t.Fatalf("the invitation was spent by a refused request: %v", err)
		}
	})
}

// TestAcceptInvitationIsSingleUse: a replay is refused, and of many concurrent
// accepts with one token exactly one succeeds — run under -race.
func TestAcceptInvitationIsSingleUse(t *testing.T) {
	t.Run("replay", func(t *testing.T) {
		f := newInvitationFixture(t)
		result := f.invite(invitedEmail)
		if _, err := f.accept(result.Token, "a-new-password"); err != nil {
			t.Fatalf("first accept: %v", err)
		}
		if _, err := f.accept(result.Token, "another-password"); !errors.Is(err, ErrInvalidInvitation) {
			t.Fatalf("replay = %v, want ErrInvalidInvitation", err)
		}
		stored, _ := f.users.GetUserByID(context.Background(), result.User.ID, "t1")
		if !verifyPassword("a-new-password", stored.PasswordHash) {
			t.Fatal("the replay changed the password")
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		f := newInvitationFixture(t)
		result := f.invite(invitedEmail)
		const n = 16
		var wg sync.WaitGroup
		errs := make([]error, n)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = f.accept(result.Token, fmt.Sprintf("password-%02d", i))
			}(i)
		}
		wg.Wait()
		won := -1
		for i, err := range errs {
			switch {
			case err == nil && won >= 0:
				t.Fatalf("accepts %d and %d both succeeded", won, i)
			case err == nil:
				won = i
			case !errors.Is(err, ErrInvalidInvitation):
				t.Fatalf("accept %d = %v, want ErrInvalidInvitation", i, err)
			}
		}
		if won < 0 {
			t.Fatal("no accept succeeded")
		}
		stored, _ := f.users.GetUserByID(context.Background(), result.User.ID, "t1")
		if !verifyPassword(fmt.Sprintf("password-%02d", won), stored.PasswordHash) {
			t.Fatal("the stored password is not the winner's")
		}
	})
}

// TestAcceptInvitationRefusesEveryReasonAlike: unknown, expired, revoked,
// accepted, an account that is gone, an account already active through a side
// door, an account with a factor, an address that moved — one sentinel, and so
// one wire answer.
func TestAcceptInvitationRefusesEveryReasonAlike(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(f *invitationFixture, result InvitationResult) string{
		"unknown": func(*invitationFixture, InvitationResult) string { return "not-a-token-anybody-minted" },
		"expired": func(f *invitationFixture, result InvitationResult) string {
			f.svc().now = func() time.Time { return result.Invitation.ExpiresAt }
			return result.Token
		},
		"revoked": func(f *invitationFixture, result InvitationResult) string {
			if _, err := f.auth.RevokeInvitation(ctx, result.Invitation.ID, "", ""); err != nil {
				t.Fatalf("revoke: %v", err)
			}
			return result.Token
		},
		"account deleted": func(f *invitationFixture, result InvitationResult) string {
			if err := f.users.DeleteUser(ctx, result.User.ID, "t1"); err != nil {
				t.Fatalf("delete: %v", err)
			}
			return result.Token
		},
		// The side door a pending account still has: a magic link to the
		// invited mailbox, then a first password through /change-password.
		"account activated through a magic link and a first password": func(f *invitationFixture, result InvitationResult) string {
			var links []MagicLinkDelivery
			f.svc().cfg.SendMagicLink = func(_ context.Context, d MagicLinkDelivery) error {
				links = append(links, d)
				return nil
			}
			if _, err := f.svc().SendMagicLink(ctx, MagicLinkSendInput{Email: invitedEmail, TenantID: "t1"}); err != nil || len(links) != 1 {
				t.Fatalf("magic link send = %v, %d links", err, len(links))
			}
			user, _, err := f.svc().VerifyMagicLink(ctx, MagicLinkVerifyInput{Token: links[0].Token})
			if err != nil {
				t.Fatalf("magic link login: %v", err)
			}
			if err := f.auth.ChangePassword(ctx, ChangePasswordInput{UserID: user.ID, TenantID: "t1", NewPassword: "first-password"}); err != nil {
				t.Fatalf("first password: %v", err)
			}
			return result.Token
		},
		"account with a factor": func(f *invitationFixture, result InvitationResult) string {
			if err := f.users.UpdateTOTPSecret(ctx, result.User.ID, "t1", "JBSWY3DPEHPK3PXP", true); err != nil {
				t.Fatalf("totp: %v", err)
			}
			return result.Token
		},
		"address moved": func(f *invitationFixture, result InvitationResult) string {
			if err := f.users.UpdateEmailChangeToken(ctx, result.User.ID, "t1", "moved@example.com", "h", time.Now().Add(time.Hour)); err != nil {
				t.Fatalf("email change: %v", err)
			}
			if err := f.users.ApplyEmailChange(ctx, result.User.ID, "t1"); err != nil {
				t.Fatalf("apply: %v", err)
			}
			return result.Token
		},
	}
	var answers []HTTPError
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			f := newInvitationFixture(t)
			result := f.invite(invitedEmail)
			token := prepare(f, result)
			before, _ := f.users.GetUserByID(ctx, result.User.ID, "t1")
			_, err := f.accept(token, "a-new-password")
			if !errors.Is(err, ErrInvalidInvitation) {
				t.Fatalf("accept = %v, want ErrInvalidInvitation", err)
			}
			answers = append(answers, InvitationAcceptHTTPError(err))
			after, _ := f.users.GetUserByID(ctx, result.User.ID, "t1")
			if after.PasswordHash != before.PasswordHash {
				t.Error("a refused accept changed the password")
			}
		})
	}
	t.Run("one wire answer", func(t *testing.T) {
		for _, answer := range answers {
			if answer != HTTPErrInvalidInvitation {
				t.Errorf("answer = %+v, want %+v", answer, HTTPErrInvalidInvitation)
			}
		}
		if HTTPErrInvalidInvitation.Status != http.StatusUnauthorized || HTTPErrInvalidInvitation.Code != CodeInvalidInvitation {
			t.Errorf("HTTPErrInvalidInvitation = %+v", HTTPErrInvalidInvitation)
		}
	})
}

// TestAcceptInvitationExpiresStrictly pins the boundary: honoured a moment
// before ExpiresAt, refused at it.
func TestAcceptInvitationExpiresStrictly(t *testing.T) {
	f := newInvitationFixture(t, WithInvitationTTL(time.Hour))
	result := f.invite(invitedEmail)
	if got := result.Invitation.ExpiresAt.Sub(result.Invitation.CreatedAt); got != time.Hour {
		t.Fatalf("lifetime = %v, want the configured hour", got)
	}
	f.svc().now = func() time.Time { return result.Invitation.ExpiresAt.Add(-time.Nanosecond) }
	if _, err := f.accept(result.Token, "a-new-password"); err != nil {
		t.Fatalf("accept just before expiry: %v", err)
	}

	g := newInvitationFixture(t, WithInvitationTTL(time.Hour))
	expired := g.invite(invitedEmail)
	g.svc().now = func() time.Time { return expired.Invitation.ExpiresAt }
	if _, err := g.accept(expired.Token, "a-new-password"); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatalf("accept at expiry = %v, want ErrInvalidInvitation", err)
	}
}

// mismatchingStore answers every consume with a record for a different token,
// standing in for a store that returns the wrong row.
type mismatchingStore struct{ *MemoryInvitationStore }

func (s mismatchingStore) ConsumeInvitation(ctx context.Context, tokenHash string, now time.Time) (Invitation, error) {
	invitation, err := s.MemoryInvitationStore.ConsumeInvitation(ctx, tokenHash, now)
	invitation.TokenHash = hashToken("some-other-token")
	return invitation, err
}

// TestAcceptInvitationComparesTheStoredHash: the service compares the hash the
// store answered with against the presented one (in constant time, through
// secureEqual), so a store that hands back the wrong row activates nothing.
func TestAcceptInvitationComparesTheStoredHash(t *testing.T) {
	f := newInvitationFixture(t)
	result := f.invite(invitedEmail)
	f.svc().cfg.Invitations = mismatchingStore{f.store}
	if _, err := f.accept(result.Token, "a-new-password"); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatalf("accept = %v, want ErrInvalidInvitation", err)
	}
	stored, _ := f.users.GetUserByID(context.Background(), result.User.ID, "t1")
	if stored.PasswordHash != "" {
		t.Fatal("a mismatching record set the password")
	}
}

// TestAcceptInvitationUnderRequire2FA: the acceptance answers what the login
// would — with EnrolOnLogin, an enrolment token that enrols TOTP and opens the
// session; without it, a setup-required token nothing accepts; and with a
// factor the deployment can deliver, the step-up challenge. No session is
// opened by the acceptance in any of them.
func TestAcceptInvitationUnderRequire2FA(t *testing.T) {
	ctx := context.Background()

	t.Run("EnrolOnLogin: enrol, then the session", func(t *testing.T) {
		f := newInvitationFixture(t, WithRequire2FA(true), WithEnrolOnLogin(true), WithIssueSessionOnRegister(true))
		result := f.invite(invitedEmail)
		acceptance, err := f.accept(result.Token, "a-new-password")
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if acceptance.Tokens.AccessToken != "" {
			t.Fatal("the acceptance opened a session before the second factor")
		}
		challenge := acceptance.Challenge
		if challenge == nil || !challenge.SetupRequired || challenge.TempToken == "" {
			t.Fatalf("challenge = %+v, want 2FA_SETUP_REQUIRED with a token", challenge)
		}
		// The token is an enrolment token bound to the password just set.
		if _, err := f.auth.VerifyEnrolmentToken(ctx, challenge.TempToken); err != nil {
			t.Fatalf("the challenge token is not an honoured enrolment token: %v", err)
		}
		if _, err := f.svc().VerifyTempToken(challenge.TempToken); err == nil {
			t.Error("the enrolment token also passes as a step-up token")
		}
		setup, err := f.auth.NewForcedTOTPEnrolment(ctx, challenge.TempToken)
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		_, tokens, err := f.auth.CompleteTOTPEnrolment(ctx, challenge.TempToken, setup.Secret, codeFor(t, setup.Secret, time.Now()))
		if err != nil || tokens.AccessToken == "" {
			t.Fatalf("enrolment = %v, want the session", err)
		}
	})

	t.Run("without EnrolOnLogin: the token completes nothing", func(t *testing.T) {
		f := newInvitationFixture(t, WithRequire2FA(true))
		result := f.invite(invitedEmail)
		acceptance, err := f.accept(result.Token, "a-new-password")
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if acceptance.Challenge == nil || !acceptance.Challenge.SetupRequired || acceptance.Tokens.AccessToken != "" {
			t.Fatalf("acceptance = %+v, want setup-required and no session", acceptance)
		}
		if _, err := f.auth.VerifyEnrolmentToken(ctx, acceptance.Challenge.TempToken); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("VerifyEnrolmentToken = %v: the enrolment routes accept nothing without EnrolOnLogin", err)
		}
		// The password is set all the same; the login answers the same setup.
		login, err := f.auth.LoginWithChallenge(ctx, LoginInput{Email: invitedEmail, Password: "a-new-password", TenantID: "t1"})
		if err != nil || login.Challenge == nil || !login.Challenge.SetupRequired {
			t.Fatalf("login = %+v, %v, want the same setup-required answer", login, err)
		}
	})

	t.Run("a factor the deployment can deliver: the step-up challenge", func(t *testing.T) {
		f := newInvitationFixture(t, WithRequire2FA(true), WithEnrolOnLogin(true),
			WithMagicLinkSender(func(context.Context, MagicLinkDelivery) error { return nil }))
		result := f.invite(invitedEmail)
		acceptance, err := f.accept(result.Token, "a-new-password")
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		challenge := acceptance.Challenge
		if challenge == nil || challenge.SetupRequired || len(challenge.Methods) != 1 || challenge.Methods[0] != TwoFactorMethodMagicLink {
			t.Fatalf("challenge = %+v, want the magic-link step-up the login gives", challenge)
		}
	})
}

// TestInvitationTokensAreNeverLogged drives every path that logs — the
// startup notice, an undone send whose own undo fails — and every path that
// raises an event, and requires that neither the token nor its hash appears in
// a log line, an event or an error the caller sees.
func TestInvitationTokensAreNeverLogged(t *testing.T) {
	ctx := context.Background()
	f := newInvitationFixture(t)
	f.svc().cfg.SendInvitation = nil // the notice below is a startup line; trigger it too
	if _, err := NewService(f.svc().cfg, f.users, NewMemorySessionStore()); err != nil {
		t.Fatalf("NewService: %v", err)
	}
	f.svc().cfg.SendInvitation = f.send

	var secrets []string
	collect := func(result InvitationResult) {
		secrets = append(secrets, result.Token, result.Invitation.TokenHash)
	}

	// The whole happy path.
	ok := f.invite("happy@example.com")
	collect(ok)
	if _, err := f.accept(ok.Token, "a-new-password"); err != nil {
		t.Fatalf("accept: %v", err)
	}
	// A refusal.
	if _, err := f.accept(ok.Token, "a-new-password"); err == nil {
		t.Fatal("replay accepted")
	}
	// A revocation.
	revoked := f.invite("revoked@example.com")
	collect(revoked)
	if _, err := f.auth.RevokeInvitation(ctx, revoked.Invitation.ID, "usr_admin", InvitedByUser); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// A send that fails through the delivery webhook, whose undo fails too.
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer receiver.Close()
	hook, err := NewDeliveryWebhook(receiver.URL, "s3cret")
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	var minted []string
	f.svc().cfg.SendInvitation = func(ctx context.Context, d InvitationDelivery) error {
		minted = append(minted, d.Token, hashToken(d.Token))
		return hook.SendInvitation(ctx, d)
	}
	f.svc().cfg.Invitations = failingRevokeStore{f.store}
	_, sendErr := f.auth.InviteUser(ctx, InviteUserInput{Email: "undelivered@example.com", TenantID: "t1"})
	if !errors.Is(sendErr, ErrDeliveryFailed) {
		t.Fatalf("InviteUser = %v, want ErrDeliveryFailed", sendErr)
	}
	secrets = append(secrets, minted...)
	if len(minted) != 2 {
		t.Fatalf("the failing sender was not called: %v", minted)
	}

	f.mu.Lock()
	logs := append([]string(nil), f.logs...)
	f.mu.Unlock()
	if len(logs) < 2 {
		t.Fatalf("logs = %q: the paths that log did not run, so this test proves nothing", logs)
	}
	events := f.raised()
	for _, secret := range secrets {
		if secret == "" {
			t.Fatal("an empty secret would match everything")
		}
		for _, line := range logs {
			if strings.Contains(line, secret) {
				t.Errorf("log line %q carries a token or its hash", line)
			}
		}
		for _, ev := range events {
			encoded, _ := json.Marshal(ev)
			if strings.Contains(string(encoded), secret) {
				t.Errorf("event %s carries a token or its hash: %s", ev.Name, encoded)
			}
		}
		if strings.Contains(sendErr.Error(), secret) {
			t.Errorf("the delivery error %q carries a token or its hash", sendErr)
		}
	}
}

// failingRevokeStore cannot revoke, so an undone send has to log that.
type failingRevokeStore struct{ *MemoryInvitationStore }

func (failingRevokeStore) RevokeInvitation(context.Context, string, time.Time) (Invitation, error) {
	return Invitation{}, errors.New("store unavailable")
}

func TestInviteUserReinvite(t *testing.T) {
	ctx := context.Background()

	t.Run("conflict, the default: an existing address is refused", func(t *testing.T) {
		f := newInvitationFixture(t)
		f.invite(invitedEmail)
		if _, err := f.auth.InviteUser(ctx, InviteUserInput{Email: invitedEmail, TenantID: "t1"}); !errors.Is(err, ErrUserExists) {
			t.Fatalf("second invite = %v, want ErrUserExists", err)
		}
	})

	t.Run("reinvite: the same pending account, a fresh token, the old one dead", func(t *testing.T) {
		f := newInvitationFixture(t, WithInvitationReinvite(true))
		first := f.invite(invitedEmail)
		f.reset()
		second := f.invite(invitedEmail)
		if second.AccountCreated || second.User.ID != first.User.ID || second.Invitation.ID == first.Invitation.ID || second.Token == first.Token {
			t.Fatalf("second = %+v, want the same account and a new invitation", second)
		}
		if ev := f.raised(); len(ev) != 1 || ev[0].Data["accountCreated"] != false {
			t.Fatalf("raised %+v, want one invited event saying no account was created", ev)
		}
		pending, _ := f.store.PendingInvitationsForUser(ctx, first.User.ID)
		if len(pending) != 1 || pending[0].ID != second.Invitation.ID {
			t.Fatalf("pending = %+v, want only the new invitation", pending)
		}
		if _, err := f.accept(first.Token, "a-new-password"); !errors.Is(err, ErrInvalidInvitation) {
			t.Fatalf("the replaced token = %v, want ErrInvalidInvitation", err)
		}
		if _, err := f.accept(second.Token, "a-new-password"); err != nil {
			t.Fatalf("the new token: %v", err)
		}
		// An active account is refused even in this mode.
		if _, err := f.auth.InviteUser(ctx, InviteUserInput{Email: invitedEmail, TenantID: "t1"}); !errors.Is(err, ErrUserExists) {
			t.Fatalf("invite of an active account = %v, want ErrUserExists", err)
		}
	})

	t.Run("reinvite never reaches an account no invitation reserved", func(t *testing.T) {
		f := newInvitationFixture(t, WithInvitationReinvite(true))
		// Passwordless, but made by some other route.
		if _, err := f.users.CreateUser(ctx, User{ID: "usr_oauth", Email: "oauth@example.com", TenantID: "t1", LoginProvider: "google"}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := f.auth.InviteUser(ctx, InviteUserInput{Email: "oauth@example.com", TenantID: "t1"}); !errors.Is(err, ErrUserExists) {
			t.Fatalf("invite = %v, want ErrUserExists", err)
		}
	})
}

// TestInviteUserUndoesAFailedSend: a send that fails leaves nothing in the way
// of the retry — in conflict mode the account it created is gone — and a
// re-invitation whose send fails leaves the earlier token working.
func TestInviteUserUndoesAFailedSend(t *testing.T) {
	ctx := context.Background()

	t.Run("conflict mode", func(t *testing.T) {
		f := newInvitationFixture(t)
		f.sendErr = errors.New("gateway down")
		_, err := f.auth.InviteUser(ctx, InviteUserInput{Email: invitedEmail, TenantID: "t1", Metadata: map[string]any{"k": "v"}})
		if !errors.Is(err, ErrDeliveryFailed) {
			t.Fatalf("InviteUser = %v, want ErrDeliveryFailed", err)
		}
		if _, err := f.users.GetUserByEmail(ctx, invitedEmail, "t1"); err == nil {
			t.Fatal("the account of an undelivered invitation is still there")
		}
		if pending, _ := f.store.ListPendingInvitations(ctx, 10, 0); len(pending) != 0 {
			t.Fatalf("pending = %+v, want the undelivered invitation revoked", pending)
		}
		if names := eventNamesOf(f.raised()); len(names) != 0 {
			t.Fatalf("raised %v for an invitation nobody received", names)
		}
		f.sendErr = nil
		retry := f.invite(invitedEmail)
		if !retry.AccountCreated {
			t.Fatal("the retry did not create the account")
		}
	})

	t.Run("reinvite mode keeps the earlier invitation", func(t *testing.T) {
		f := newInvitationFixture(t, WithInvitationReinvite(true))
		first := f.invite(invitedEmail)
		f.sendErr = errors.New("gateway down")
		if _, err := f.auth.InviteUser(ctx, InviteUserInput{Email: invitedEmail, TenantID: "t1"}); !errors.Is(err, ErrDeliveryFailed) {
			t.Fatalf("InviteUser = %v, want ErrDeliveryFailed", err)
		}
		if _, err := f.users.GetUserByID(ctx, first.User.ID, "t1"); err != nil {
			t.Fatal("a failed re-invitation removed an account it did not create")
		}
		f.sendErr = nil
		if _, err := f.accept(first.Token, "a-new-password"); err != nil {
			t.Fatalf("the earlier token after a failed re-invitation: %v", err)
		}
	})
}

// TestRevokeInvitation: the token dies, the pending account goes with it and
// with it the side doors, and an account that is no longer pending stays.
func TestRevokeInvitation(t *testing.T) {
	ctx := context.Background()

	t.Run("removes the pending account and closes the side doors", func(t *testing.T) {
		var links []MagicLinkDelivery
		f := newInvitationFixture(t, WithMagicLinkSender(func(_ context.Context, d MagicLinkDelivery) error {
			links = append(links, d)
			return nil
		}))
		result := f.invite(invitedEmail)
		// Before the revocation the pending account answers a magic link, as
		// any account does: the documented side door. It answers no reset —
		// the invitation still reserves it.
		if _, err := f.svc().SendMagicLink(ctx, MagicLinkSendInput{Email: invitedEmail, TenantID: "t1"}); err != nil || len(links) != 1 {
			t.Fatalf("magic link before revoke = %v, %d links", err, len(links))
		}
		if _, err := f.svc().ForgotPassword(ctx, ForgotPasswordInput{Email: invitedEmail, TenantID: "t1"}); err != nil || len(f.resets) != 0 {
			t.Fatalf("forgot before revoke = %v, %d resets, want none for a reserved account", err, len(f.resets))
		}
		f.reset()
		links = nil

		revocation, err := f.auth.RevokeInvitation(ctx, result.Invitation.ID, "usr_admin", InvitedByUser)
		if err != nil || !revocation.AccountRemoved || revocation.Invitation.RevokedAt == nil {
			t.Fatalf("revoke = %+v, %v", revocation, err)
		}
		if _, err := f.users.GetUserByID(ctx, result.User.ID, "t1"); !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("the pending account survived its revocation: %v", err)
		}
		if metadata, _ := f.metadata.GetMetadata(ctx, result.User.ID); len(metadata) != 0 {
			t.Errorf("metadata = %v, want it cleared with the account", metadata)
		}
		if _, err := f.svc().SendMagicLink(ctx, MagicLinkSendInput{Email: invitedEmail, TenantID: "t1"}); err != nil || len(links) != 0 {
			t.Fatalf("magic link after revoke = %v, %d links: the side door is still open", err, len(links))
		}
		if _, err := f.svc().ForgotPassword(ctx, ForgotPasswordInput{Email: invitedEmail, TenantID: "t1"}); err != nil || len(f.resets) != 0 {
			t.Fatalf("forgot after revoke = %v, %d resets", err, len(f.resets))
		}
		if _, err := f.accept(result.Token, "a-new-password"); !errors.Is(err, ErrInvalidInvitation) {
			t.Fatalf("accept after revoke = %v", err)
		}
		events := f.raised()
		var revokedEvent *Event
		for i := range events {
			if events[i].Name == EventUserInvitationRevoked {
				revokedEvent = &events[i]
			}
		}
		if revokedEvent == nil {
			t.Fatalf("raised %v, want %s", eventNamesOf(events), EventUserInvitationRevoked)
		}
		assertEventData(t, *revokedEvent, map[string]any{
			"invitationId": result.Invitation.ID, "revokedBy": "usr_admin",
			"revokedByKind": InvitedByUser, "accountRemoved": true,
		})
		// The address is free again: a new invitation creates a new account.
		if again := f.invite(invitedEmail); !again.AccountCreated {
			t.Fatal("the address is still taken after the revocation")
		}
	})

	t.Run("an expired invitation is revocable, and takes its account", func(t *testing.T) {
		f := newInvitationFixture(t)
		result := f.invite(invitedEmail)
		f.svc().now = func() time.Time { return result.Invitation.ExpiresAt.Add(time.Hour) }
		revocation, err := f.auth.RevokeInvitation(ctx, result.Invitation.ID, "", "")
		if err != nil || !revocation.AccountRemoved {
			t.Fatalf("revoke of an expired invitation = %+v, %v", revocation, err)
		}
	})

	t.Run("an account activated some other way stays", func(t *testing.T) {
		f := newInvitationFixture(t)
		result := f.invite(invitedEmail)
		if err := f.users.UpdatePassword(ctx, result.User.ID, "t1", "a-hash"); err != nil {
			t.Fatalf("seed password: %v", err)
		}
		revocation, err := f.auth.RevokeInvitation(ctx, result.Invitation.ID, "", "")
		if err != nil || revocation.AccountRemoved {
			t.Fatalf("revoke = %+v, %v, want the active account kept", revocation, err)
		}
		if _, err := f.users.GetUserByID(ctx, result.User.ID, "t1"); err != nil {
			t.Fatal("an active account was deleted by a revocation")
		}
	})

	// The capsule-style flow: magic link is the invitee's way in, so the
	// account is in use while it still has no password. A revocation — after
	// expiry, as a clean-up — must not delete it.
	t.Run("an account signed in to by magic link is kept, even after expiry", func(t *testing.T) {
		var links []MagicLinkDelivery
		f := newInvitationFixture(t, WithMagicLinkSender(func(_ context.Context, d MagicLinkDelivery) error {
			links = append(links, d)
			return nil
		}))
		result := f.invite(invitedEmail)
		if _, err := f.svc().SendMagicLink(ctx, MagicLinkSendInput{Email: invitedEmail, TenantID: "t1"}); err != nil || len(links) != 1 {
			t.Fatalf("magic link send = %v, %d links", err, len(links))
		}
		if _, tokens, err := f.svc().VerifyMagicLink(ctx, MagicLinkVerifyInput{Token: links[0].Token}); err != nil || tokens.AccessToken == "" {
			t.Fatalf("magic link login = %v", err)
		}
		f.svc().now = func() time.Time { return result.Invitation.ExpiresAt.Add(time.Hour) }
		revocation, err := f.auth.RevokeInvitation(ctx, result.Invitation.ID, "", "")
		if err != nil || revocation.AccountRemoved {
			t.Fatalf("revoke = %+v, %v, want the account in use kept", revocation, err)
		}
		if _, err := f.users.GetUserByID(ctx, result.User.ID, "t1"); err != nil {
			t.Fatal("a revocation deleted an account somebody signs in to")
		}
	})

	t.Run("without a listable session store, the row's own markers decide", func(t *testing.T) {
		// A session store that cannot list a user's sessions: only the row
		// says the account was used, here by the verified address a
		// magic-link login leaves.
		f := newInvitationFixture(t, WithSessionStore(opaqueSessions{NewMemorySessionStore()}))
		used := f.invite("used@example.com")
		if err := f.users.MarkEmailVerified(ctx, used.User.ID, "t1", true); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if revocation, err := f.auth.RevokeInvitation(ctx, used.Invitation.ID, "", ""); err != nil || revocation.AccountRemoved {
			t.Fatalf("revoke = %+v, %v, want the verified account kept", revocation, err)
		}
		fresh := f.invite("fresh@example.com")
		if revocation, err := f.auth.RevokeInvitation(ctx, fresh.Invitation.ID, "", ""); err != nil || !revocation.AccountRemoved {
			t.Fatalf("revoke = %+v, %v, want the untouched account removed", revocation, err)
		}
	})

	t.Run("an account with a session is kept, even with its address unverified", func(t *testing.T) {
		f := newInvitationFixture(t)
		result := f.invite(invitedEmail)
		if _, _, err := f.svc().IssueTokensForUser(ctx, result.User.ID, "t1"); err != nil {
			t.Fatalf("session: %v", err)
		}
		if revocation, err := f.auth.RevokeInvitation(ctx, result.Invitation.ID, "", ""); err != nil || revocation.AccountRemoved {
			t.Fatalf("revoke = %+v, %v, want the account kept", revocation, err)
		}
	})

	t.Run("an account with a linked provider is kept by the Auth", func(t *testing.T) {
		linked := NewMemoryLinkedAccounts()
		f := newInvitationFixture(t, WithOAuth(OAuthWiring{LinkedAccounts: linked}))
		result := f.invite(invitedEmail)
		// What /link-verify writes, and nothing on the user row.
		if err := linked.Save(ctx, OAuthLinkedAccount{ID: "lnk_1", UserID: result.User.ID, Provider: "google", ProviderID: "g-1", Email: invitedEmail}); err != nil {
			t.Fatalf("link: %v", err)
		}
		if revocation, err := f.auth.RevokeInvitation(ctx, result.Invitation.ID, "", ""); err != nil || revocation.AccountRemoved {
			t.Fatalf("revoke = %+v, %v, want the linked account kept", revocation, err)
		}
	})

	t.Run("evidence that cannot be read keeps the account, and says so", func(t *testing.T) {
		f := newInvitationFixture(t, WithOAuth(OAuthWiring{LinkedAccounts: failingLinks{NewMemoryLinkedAccounts()}}))
		result := f.invite(invitedEmail)
		if revocation, err := f.auth.RevokeInvitation(ctx, result.Invitation.ID, "", ""); err != nil || revocation.AccountRemoved {
			t.Fatalf("revoke = %+v, %v, want the account kept", revocation, err)
		}
		f.mu.Lock()
		logs := strings.Join(f.logs, "\n")
		f.mu.Unlock()
		if !strings.Contains(logs, "it is kept") {
			t.Errorf("logs = %q, want the kept account explained", logs)
		}
	})

	t.Run("unknown, accepted and revoked twice", func(t *testing.T) {
		f := newInvitationFixture(t)
		if _, err := f.auth.RevokeInvitation(ctx, "inv_nope", "", ""); !errors.Is(err, ErrInvitationNotFound) {
			t.Fatalf("unknown = %v", err)
		}
		accepted := f.invite("accepted@example.com")
		if _, err := f.accept(accepted.Token, "a-new-password"); err != nil {
			t.Fatalf("accept: %v", err)
		}
		if _, err := f.auth.RevokeInvitation(ctx, accepted.Invitation.ID, "", ""); !errors.Is(err, ErrInvitationNotPending) {
			t.Fatalf("revoke of an accepted invitation = %v", err)
		}
		if _, err := f.users.GetUserByID(ctx, accepted.User.ID, "t1"); err != nil {
			t.Fatal("revoking an accepted invitation touched its account")
		}
		revoked := f.invite("revoked@example.com")
		if _, err := f.auth.RevokeInvitation(ctx, revoked.Invitation.ID, "", ""); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if _, err := f.auth.RevokeInvitation(ctx, revoked.Invitation.ID, "", ""); !errors.Is(err, ErrInvitationNotPending) {
			t.Fatalf("second revoke = %v", err)
		}
	})
}

// opaqueSessions is a session store with none of the optional capabilities.
type opaqueSessions struct{ SessionStore }

// failingLinks cannot list a user's linked accounts.
type failingLinks struct{ *MemoryLinkedAccounts }

func (failingLinks) ListForUser(context.Context, string) ([]OAuthLinkedAccount, error) {
	return nil, errors.New("links unavailable")
}

// narrowUserStore hides every optional capability of the store it wraps, so a
// deployment missing the three the flow needs is reachable.
type narrowUserStore struct{ UserStore }

func TestInviteUserRequiresTheStoreCapabilities(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUserStore()
	a, err := New(WithUserStore(narrowUserStore{memory}), WithBcryptCost(testBcryptCost),
		WithInvitationStore(NewMemoryInvitationStore()),
		WithInvitationSender(func(context.Context, InvitationDelivery) error { return nil }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.InviteUser(ctx, InviteUserInput{Email: invitedEmail, TenantID: "t1"}); !errors.Is(err, ErrFeatureNotSupported) {
		t.Fatalf("InviteUser = %v, want ErrFeatureNotSupported", err)
	}
	if gap := a.service.invitationCapabilityGap(); gap != "UserPasswordStore" {
		t.Errorf("gap = %q", gap)
	}
	if _, err := memory.GetUserByEmail(ctx, invitedEmail, "t1"); err == nil {
		t.Fatal("an account was created for an invitation that could never be accepted")
	}
	if _, err := a.AcceptInvitation(ctx, AcceptInvitationInput{Token: "t", Password: "a-new-password"}); !errors.Is(err, ErrFeatureNotSupported) {
		t.Fatalf("AcceptInvitation = %v, want ErrFeatureNotSupported", err)
	}
}

func TestInvitationsAreOffWithoutAStore(t *testing.T) {
	ctx := context.Background()
	a, err := newTestAuth()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.InvitationsEnabled() {
		t.Fatal("InvitationsEnabled without a store")
	}
	if _, err := a.InviteUser(ctx, InviteUserInput{Email: invitedEmail}); !errors.Is(err, ErrFeatureNotSupported) {
		t.Errorf("InviteUser = %v", err)
	}
	if _, err := a.AcceptInvitation(ctx, AcceptInvitationInput{Token: "t", Password: "p"}); !errors.Is(err, ErrFeatureNotSupported) {
		t.Errorf("AcceptInvitation = %v", err)
	}
	if _, err := a.RevokeInvitation(ctx, "inv_x", "", ""); !errors.Is(err, ErrFeatureNotSupported) {
		t.Errorf("RevokeInvitation = %v", err)
	}
	if _, err := a.ListPendingInvitations(ctx, 10, 0); !errors.Is(err, ErrFeatureNotSupported) {
		t.Errorf("ListPendingInvitations = %v", err)
	}
}

func TestInvitationConfig(t *testing.T) {
	cfg := testConfig(testSecret)
	if cfg.InvitationTTL != 0 {
		t.Fatalf("DefaultConfig sets InvitationTTL = %v; zero has to keep meaning the default", cfg.InvitationTTL)
	}
	cfg.InvitationTTL = -time.Second
	if err := cfg.validate(); err == nil {
		t.Error("a negative InvitationTTL validated")
	}
	for name, opt := range map[string]Option{
		"WithInvitationStore(nil)":  WithInvitationStore(nil),
		"WithInvitationSender(nil)": WithInvitationSender(nil),
		"WithInvitationTTL(0)":      WithInvitationTTL(0),
	} {
		if _, err := newTestAuth(opt); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	notices := func(opts ...Option) int {
		var lines []string
		opts = append(opts, WithLogger(func(format string, _ ...any) { lines = append(lines, format) }))
		if _, err := newTestAuth(opts...); err != nil {
			t.Fatalf("New: %v", err)
		}
		n := 0
		for _, line := range lines {
			if strings.Contains(line, "RevealInvitationToken") {
				n++
			}
		}
		return n
	}
	if n := notices(WithInvitationStore(NewMemoryInvitationStore())); n != 1 {
		t.Errorf("a store with no sender logged the notice %d times, want once", n)
	}
	if n := notices(WithInvitationStore(NewMemoryInvitationStore()),
		WithInvitationSender(func(context.Context, InvitationDelivery) error { return nil })); n != 0 {
		t.Errorf("a store with a sender logged the notice %d times", n)
	}
	if n := notices(); n != 0 {
		t.Errorf("no store logged the notice %d times", n)
	}
}

func TestInvitationEventsAreOutsideTheVocabulary(t *testing.T) {
	for _, name := range []string{EventUserInvited, EventUserInvitationAccepted, EventUserInvitationRevoked} {
		if IsEventName(name) {
			t.Errorf("%s is in EventNames, which is the reference's list alone", name)
		}
		if !strings.HasPrefix(name, "identity.user.") {
			t.Errorf("%s is not under identity.user.", name)
		}
	}
}

func TestInvitationAcceptHTTPError(t *testing.T) {
	for err, want := range map[error]HTTPError{
		ErrInvalidInvitation:   HTTPErrInvalidInvitation,
		ErrInvalidInput:        HTTPErrInvitationInputRequired,
		ErrWeakPassword:        HTTPErrWeakPassword,
		ErrFeatureNotSupported: HTTPErrInternal,
		errors.New("store"):    HTTPErrInternal,
	} {
		if got := InvitationAcceptHTTPError(err); got != want {
			t.Errorf("InvitationAcceptHTTPError(%v) = %+v, want %+v", err, got, want)
		}
	}
	if got := HTTPErrorFor(fmt.Errorf("wrapped: %w", ErrInvalidInvitation)); got != HTTPErrInvalidInvitation {
		t.Errorf("HTTPErrorFor = %+v", got)
	}
}

func TestWriteInvitationAcceptance(t *testing.T) {
	cfg := DefaultHTTPConfig()
	t.Run("no session: the registration's 201", func(t *testing.T) {
		rec := httptest.NewRecorder()
		cfg.WriteInvitationAcceptance(rec, httptest.NewRequest(http.MethodPost, "/auth/invitations/accept", nil),
			InvitationAcceptance{User: User{ID: "usr_1"}})
		if rec.Code != http.StatusCreated || strings.TrimSpace(rec.Body.String()) != `{"success":true,"userId":"usr_1"}` {
			t.Fatalf("answer = %d %s", rec.Code, rec.Body.String())
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatal("cookies without a session")
		}
	})
	t.Run("a challenge: the login's 403", func(t *testing.T) {
		rec := httptest.NewRecorder()
		cfg.WriteInvitationAcceptance(rec, httptest.NewRequest(http.MethodPost, "/auth/invitations/accept", nil),
			InvitationAcceptance{User: User{ID: "usr_1"}, Challenge: &TwoFactorChallenge{TempToken: "tt", SetupRequired: true}})
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeTwoFactorSetupRequired) {
			t.Fatalf("answer = %d %s", rec.Code, rec.Body.String())
		}
	})
}

// TestOpenAPIDocumentsTheAcceptRoute: the path item follows
// OpenAPIInfo.Invitations, stays under ClosedRegistration and goes under
// ResourceServer, as the adapters' mount does.
func TestOpenAPIDocumentsTheAcceptRoute(t *testing.T) {
	key := DefaultAPIPrefix + InvitationAcceptRoute
	documented := func(info OpenAPIInfo) bool {
		paths, _ := GenerateOpenAPISpec(info)["paths"].(map[string]any)
		_, ok := paths[key]
		return ok
	}
	if documented(OpenAPIInfo{}) {
		t.Error("documented without the flag")
	}
	if !documented(OpenAPIInfo{Invitations: true}) || !documented(OpenAPIInfo{Invitations: true, ClosedRegistration: true}) {
		t.Error("not documented with the flag")
	}
	if documented(OpenAPIInfo{Invitations: true, ResourceServer: true}) {
		t.Error("documented under resource-server mode, where it is not mounted")
	}
	paths, _ := GenerateOpenAPISpec(OpenAPIInfo{Invitations: true})["paths"].(map[string]any)
	post, _ := paths[key].(map[string]any)["post"].(map[string]any)
	responses, _ := post["responses"].(map[string]any)
	for _, status := range []string{"201", "200", "403", "400", "401", "500"} {
		if _, ok := responses[status]; !ok {
			t.Errorf("no %s response documented", status)
		}
	}
	if !strings.Contains(responses["401"].(map[string]any)["description"].(string), CodeInvalidInvitation) {
		t.Errorf("401 = %v", responses["401"])
	}
}
