package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Regression tests from the review of the invitation flow. Most began as a
// proof of concept that pinned a defect — an invitation spent by a password
// bcrypt cannot hash, an account locked out by /forgot-password, the console
// handed to an invitee under the first-user policy, an accepted account deleted
// by a failed send's undo, an invitation minted by a cross-site form — and now
// pin the fix.

func (f *invitationFixture) logged() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.logs, "\n")
}

// inviteInThePast creates the invitation under a clock two hours back, then
// returns the service to the real clock, so that an invitation with a TTL of
// an hour is expired and everything after it runs on real time.
func (f *invitationFixture) inviteInThePast(email string) InvitationResult {
	f.t.Helper()
	f.svc().now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	result := f.invite(email)
	f.svc().now = time.Now
	return result
}

// TestAcceptInvitationRefusesAnOverlongPasswordBeforeTheConsume: a password
// over bcrypt's 72 bytes used to pass the only check made before the consume,
// spend the token, and fail in hashPassword — a 500, the invitation gone, and
// an account no invitation route could recover. It is now the policy's 400
// while the invitation is still pending.
func TestAcceptInvitationRefusesAnOverlongPasswordBeforeTheConsume(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, password string }{
		{"73 ASCII bytes", strings.Repeat("a", 73)},
		{"25 four-byte runes, 100 bytes", strings.Repeat("\U0001F511", 25)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInvitationFixture(t)
			result := f.invite(invitedEmail)
			_, err := f.accept(result.Token, tc.password)
			if !errors.Is(err, ErrWeakPassword) {
				t.Fatalf("accept(%d bytes) = %v, want ErrWeakPassword", len(tc.password), err)
			}
			if got := InvitationAcceptHTTPError(err); got != HTTPErrWeakPassword {
				t.Fatalf("wire answer = %+v, want %+v", got, HTTPErrWeakPassword)
			}
			if pending, _ := f.store.PendingInvitationsForUser(ctx, result.User.ID); len(pending) != 1 {
				t.Fatalf("pending = %+v: the refused password spent the invitation", pending)
			}
			if _, err := f.accept(result.Token, "a-valid-password"); err != nil {
				t.Fatalf("the corrected retry: %v", err)
			}
			if _, _, err := f.auth.Login(ctx, LoginInput{Email: invitedEmail, Password: "a-valid-password", TenantID: "t1"}); err != nil {
				t.Fatalf("login after the corrected retry: %v", err)
			}
		})
	}

	t.Run("72 bytes is bcrypt's own limit, and is accepted", func(t *testing.T) {
		limit := strings.Repeat("p", bcryptMaxPasswordBytes)
		if _, err := hashPassword(limit, testBcryptCost); err != nil {
			t.Fatalf("hashPassword(%d bytes) = %v: the limit no longer matches bcrypt's", len(limit), err)
		}
		if _, err := hashPassword(limit+"p", testBcryptCost); !errors.Is(err, bcrypt.ErrPasswordTooLong) {
			t.Fatalf("hashPassword(%d bytes) = %v, want bcrypt.ErrPasswordTooLong: the limit no longer matches bcrypt's", len(limit)+1, err)
		}
		f := newInvitationFixture(t)
		result := f.invite(invitedEmail)
		if _, err := f.accept(result.Token, limit); err != nil {
			t.Fatalf("accept(%d bytes): %v", len(limit), err)
		}
	})
}

// faultyUserStore is the fixture's MemoryUserStore with failures on demand,
// each one spent by the first call it fails: the store errors an acceptance
// can meet once the token is spent.
type faultyUserStore struct {
	*MemoryUserStore

	mu           sync.Mutex
	failRead     bool
	failVerify   bool
	failUnverify bool
	failPassword bool
}

var errUserStoreDown = errors.New("user store unavailable")

func (s *faultyUserStore) fail(flag *bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	failing := *flag
	*flag = false
	return failing
}

func (s *faultyUserStore) GetUserByID(ctx context.Context, id, tenantID string) (User, error) {
	if s.fail(&s.failRead) {
		return User{}, errUserStoreDown
	}
	return s.MemoryUserStore.GetUserByID(ctx, id, tenantID)
}

func (s *faultyUserStore) MarkEmailVerified(ctx context.Context, id, tenantID string, verified bool) error {
	flag := &s.failUnverify
	if verified {
		flag = &s.failVerify
	}
	if s.fail(flag) {
		return errUserStoreDown
	}
	return s.MemoryUserStore.MarkEmailVerified(ctx, id, tenantID, verified)
}

func (s *faultyUserStore) UpdatePassword(ctx context.Context, id, tenantID, hash string) error {
	if s.fail(&s.failPassword) {
		return errUserStoreDown
	}
	return s.MemoryUserStore.UpdatePassword(ctx, id, tenantID, hash)
}

// TestAcceptInvitationHandsTheInvitationBackOnAFailure: every failure of the
// acceptance's own after the token is spent — the account read, the hash, the
// challenge, the verification write, the password write — leaves the account
// pending and the invitation pending again, so that the same request, retried,
// completes. It used to leave a spent token and a passwordless account that no
// invitation route could recover.
func TestAcceptInvitationHandsTheInvitationBackOnAFailure(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		opts   []Option
		inject func(f *invitationFixture, users *faultyUserStore)
		// verifiedAfter is what the address is left as by the failure.
		verifiedAfter bool
	}{
		{name: "the account cannot be read", inject: func(_ *invitationFixture, users *faultyUserStore) { users.failRead = true }},
		{name: "the password cannot be hashed", inject: func(f *invitationFixture, _ *faultyUserStore) {
			f.svc().cfg.BcryptCost = bcrypt.MaxCost + 1
		}},
		{
			name: "the challenge cannot be minted",
			opts: []Option{WithRequire2FA(true), WithEnrolOnLogin(true)},
			inject: func(f *invitationFixture, _ *faultyUserStore) {
				failed := false
				f.svc().cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) {
					if !failed {
						failed = true
						return nil, errors.New("claims hook unavailable")
					}
					return nil, nil
				}
			},
		},
		{name: "the address cannot be marked verified", inject: func(_ *invitationFixture, users *faultyUserStore) { users.failVerify = true }},
		{name: "the password cannot be stored", inject: func(_ *invitationFixture, users *faultyUserStore) { users.failPassword = true }},
		{
			// The flag cannot be undone either: the account is left verified
			// and passwordless, which an acceptance still activates.
			name: "the password cannot be stored, nor the flag undone",
			inject: func(_ *invitationFixture, users *faultyUserStore) {
				users.failPassword = true
				users.failUnverify = true
			},
			verifiedAfter: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInvitationFixture(t, tc.opts...)
			result := f.invite(invitedEmail)
			users := &faultyUserStore{MemoryUserStore: f.users}
			f.svc().users = users
			tc.inject(f, users)
			f.reset()

			_, err := f.accept(result.Token, "a-new-password")
			if err == nil || errors.Is(err, ErrInvalidInvitation) {
				t.Fatalf("accept = %v, want the failure itself, not a refusal", err)
			}
			if got := InvitationAcceptHTTPError(err); got != HTTPErrInternal {
				t.Fatalf("wire answer = %+v, want the generic 500", got)
			}
			stored, _ := f.users.GetUserByID(ctx, result.User.ID, "t1")
			if stored.PasswordHash != "" || stored.IsEmailVerified != tc.verifiedAfter {
				t.Fatalf("stored = %+v, want no password and verified=%v", stored, tc.verifiedAfter)
			}
			pending, _ := f.store.PendingInvitationsForUser(ctx, result.User.ID)
			if len(pending) != 1 || pending[0].ID != result.Invitation.ID || pending[0].AcceptedAt != nil {
				t.Fatalf("pending = %+v, want the invitation handed back", pending)
			}
			if names := eventNamesOf(f.raised()); len(names) != 0 {
				t.Fatalf("raised %v for an acceptance that did not happen", names)
			}
			for _, secret := range []string{result.Token, result.Invitation.TokenHash} {
				if strings.Contains(f.logged(), secret) {
					t.Fatalf("a log line carries the token or its hash: %q", f.logged())
				}
			}

			f.svc().cfg.BcryptCost = testBcryptCost
			acceptance, err := f.accept(result.Token, "a-new-password")
			if err != nil {
				t.Fatalf("the retry: %v", err)
			}
			if acceptance.Challenge != nil {
				if _, err := f.auth.VerifyEnrolmentToken(ctx, acceptance.Challenge.TempToken); err != nil {
					t.Fatalf("the retry's challenge does not enrol: %v", err)
				}
				return
			}
			if _, _, err := f.auth.Login(ctx, LoginInput{Email: invitedEmail, Password: "a-new-password", TenantID: "t1"}); err != nil {
				t.Fatalf("login after the retry: %v", err)
			}
		})
	}
}

// contextBoundStore fails every call whose context is done, as a store
// client does.
type contextBoundStore struct{ *MemoryInvitationStore }

func (s contextBoundStore) ReleaseInvitation(ctx context.Context, id string, acceptedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.MemoryInvitationStore.ReleaseInvitation(ctx, id, acceptedAt)
}

// cancellingUsers fails the password write by cancelling the request's
// context: the client that went away mid-acceptance.
type cancellingUsers struct {
	*MemoryUserStore
	cancel context.CancelFunc
}

func (s cancellingUsers) UpdatePassword(ctx context.Context, _, _, _ string) error {
	s.cancel()
	return ctx.Err()
}

// TestAcceptInvitationHandsTheInvitationBackWhenTheClientGoesAway: the
// likeliest failure after the consume is a request whose context is
// cancelled, and the hand-back must not share its fate.
func TestAcceptInvitationHandsTheInvitationBackWhenTheClientGoesAway(t *testing.T) {
	f := newInvitationFixture(t)
	result := f.invite(invitedEmail)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.svc().users = cancellingUsers{MemoryUserStore: f.users, cancel: cancel}
	f.svc().cfg.Invitations = contextBoundStore{f.store}

	if _, err := f.auth.AcceptInvitation(ctx, AcceptInvitationInput{Token: result.Token, Password: "a-new-password"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("accept = %v, want the cancellation", err)
	}
	stored, _ := f.users.GetUserByID(context.Background(), result.User.ID, "t1")
	if stored.PasswordHash != "" || stored.IsEmailVerified {
		t.Fatalf("stored = %+v, want the account still pending", stored)
	}
	f.svc().users = f.users
	if _, err := f.accept(result.Token, "a-new-password"); err != nil {
		t.Fatalf("the retry: %v", err)
	}
}

// failingReleaseStore cannot hand an invitation back.
type failingReleaseStore struct{ *MemoryInvitationStore }

func (failingReleaseStore) ReleaseInvitation(context.Context, string, time.Time) error {
	return errors.New("invitation store unavailable")
}

// TestAcceptInvitationWhenTheHandBackFailsToo: the one case the compensation
// cannot cover — the store fails the write and then the release — is logged
// with both ids and never the token, and the documented way out works.
func TestAcceptInvitationWhenTheHandBackFailsToo(t *testing.T) {
	f := newAdminInvitationFixture(t, nil)
	result := f.invite(invitedEmail)
	f.svc().users = &faultyUserStore{MemoryUserStore: f.users, failPassword: true}
	f.svc().cfg.Invitations = failingReleaseStore{f.store}

	if _, err := f.accept(result.Token, "a-new-password"); err == nil || errors.Is(err, ErrInvalidInvitation) {
		t.Fatalf("accept = %v, want the failure itself", err)
	}
	logs := f.logged()
	for _, want := range []string{result.Invitation.ID, result.User.ID, "pending with no invitation", "DELETE <admin>/api/users/{id}"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs = %q, want %q in them", logs, want)
		}
	}
	for _, secret := range []string{result.Token, result.Invitation.TokenHash} {
		if strings.Contains(logs, secret) {
			t.Fatalf("a log line carries the token or its hash: %q", logs)
		}
	}

	f.svc().users = f.users
	f.svc().cfg.Invitations = f.store
	if rec := f.machine(http.MethodDelete, AdminUsersPath+"/"+result.User.ID, ""); rec.Code != http.StatusOK {
		t.Fatalf("generic delete = %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"`+invitedEmail+`","tenantId":"t1"}`); rec.Code != http.StatusCreated {
		t.Fatalf("a new invitation = %d %s, want 201", rec.Code, rec.Body.String())
	}
}

// failingSessions cannot open a session.
type failingSessions struct{ SessionStore }

func (failingSessions) CreateSession(context.Context, Session) (Session, error) {
	return Session{}, errors.New("session store unavailable")
}

// TestAcceptInvitationKeepsTheActivationWhenNoSessionOpens: once the password
// is stored the account is active, and a session that cannot be opened does
// not turn that into an error that would send the invitee back to a spent
// token: the answer is the registration's without a session, and the login
// works.
func TestAcceptInvitationKeepsTheActivationWhenNoSessionOpens(t *testing.T) {
	ctx := context.Background()
	f := newInvitationFixture(t, WithIssueSessionOnRegister(true))
	result := f.invite(invitedEmail)
	f.reset()
	working := f.svc().sessions
	f.svc().sessions = failingSessions{working}

	acceptance, err := f.accept(result.Token, "a-new-password")
	if err != nil || acceptance.Challenge != nil || acceptance.Tokens.AccessToken != "" {
		t.Fatalf("accept = %+v, %v, want the registration's answer without a session", acceptance, err)
	}
	if names := eventNamesOf(f.raised()); strings.Join(names, ",") != EventUserInvitationAccepted {
		t.Fatalf("raised %v, want the acceptance and no login", names)
	}
	if !strings.Contains(f.logged(), "could not be opened") {
		t.Errorf("logs = %q, want the missing session explained", f.logged())
	}
	f.svc().sessions = working
	if _, tokens, err := f.auth.Login(ctx, LoginInput{Email: invitedEmail, Password: "a-new-password", TenantID: "t1"}); err != nil || tokens.AccessToken == "" {
		t.Fatalf("login after the acceptance: %v", err)
	}
}

// TestForgotPasswordDoesNotReachAReservedAccount: the pending account used to
// answer /forgot-password, and the reset set a password and left the address
// unverified — refused by the login in the default verification mode, while
// the still-live invitation was refused because the account had a password. An
// account an invitation still reserves is now answered as an unknown address.
func TestForgotPasswordDoesNotReachAReservedAccount(t *testing.T) {
	ctx := context.Background()

	t.Run("no reset for a pending invitee, who then accepts and logs in", func(t *testing.T) {
		f := newInvitationFixture(t)
		result := f.invite(invitedEmail)
		for name, forgot := range map[string]func(context.Context, ForgotPasswordInput) (string, error){
			"Service": f.svc().ForgotPassword,
			"Auth":    f.auth.ForgotPassword,
		} {
			if token, err := forgot(ctx, ForgotPasswordInput{Email: invitedEmail, TenantID: "t1"}); err != nil || token != "" {
				t.Fatalf("%s.ForgotPassword = %q, %v, want an unknown address's empty answer", name, token, err)
			}
		}
		if len(f.resets) != 0 {
			t.Fatalf("resets = %d, want none for a reserved account", len(f.resets))
		}
		if stored, _ := f.users.GetUserByID(ctx, result.User.ID, "t1"); stored.ResetTokenHash != "" {
			t.Fatal("a reset token was stored for a reserved account")
		}
		if _, err := f.accept(result.Token, "a-new-password"); err != nil {
			t.Fatalf("accept: %v", err)
		}
		if _, _, err := f.auth.Login(ctx, LoginInput{Email: invitedEmail, Password: "a-new-password", TenantID: "t1"}); err != nil {
			t.Fatalf("login: %v", err)
		}
		// Once active, the account resets like any other.
		if _, err := f.svc().ForgotPassword(ctx, ForgotPasswordInput{Email: invitedEmail, TenantID: "t1"}); err != nil || len(f.resets) != 1 {
			t.Fatalf("forgot after acceptance = %v, %d resets", err, len(f.resets))
		}
		if err := f.svc().ResetPassword(ctx, ResetPasswordInput{Token: f.resets[0].Token, NewPassword: "a-reset-password"}); err != nil {
			t.Fatalf("reset after acceptance: %v", err)
		}
		if _, _, err := f.auth.Login(ctx, LoginInput{Email: invitedEmail, Password: "a-reset-password", TenantID: "t1"}); err != nil {
			t.Fatalf("login after the reset: %v", err)
		}
	})

	t.Run("an expired invitation still reserves the account, and a re-invitation is the way in", func(t *testing.T) {
		f := newInvitationFixture(t, WithInvitationReinvite(true), WithInvitationTTL(time.Hour))
		expired := f.inviteInThePast(invitedEmail)
		if token, err := f.svc().ForgotPassword(ctx, ForgotPasswordInput{Email: invitedEmail, TenantID: "t1"}); err != nil || token != "" || len(f.resets) != 0 {
			t.Fatalf("forgot = %q, %v, %d resets, want nothing for a reserved account", token, err, len(f.resets))
		}
		again := f.invite(invitedEmail)
		if again.AccountCreated || again.User.ID != expired.User.ID {
			t.Fatalf("re-invitation = %+v, want the same pending account", again)
		}
		if _, err := f.accept(again.Token, "a-new-password"); err != nil {
			t.Fatalf("accept: %v", err)
		}
	})

	t.Run("an invitee who signed in by magic link resets as anybody does", func(t *testing.T) {
		var links []MagicLinkDelivery
		f := newInvitationFixture(t, WithMagicLinkSender(func(_ context.Context, d MagicLinkDelivery) error {
			links = append(links, d)
			return nil
		}))
		f.invite(invitedEmail)
		if _, err := f.svc().SendMagicLink(ctx, MagicLinkSendInput{Email: invitedEmail, TenantID: "t1"}); err != nil || len(links) != 1 {
			t.Fatalf("magic link = %v, %d links", err, len(links))
		}
		if _, _, err := f.svc().VerifyMagicLink(ctx, MagicLinkVerifyInput{Token: links[0].Token}); err != nil {
			t.Fatalf("magic link login: %v", err)
		}
		if _, err := f.svc().ForgotPassword(ctx, ForgotPasswordInput{Email: invitedEmail, TenantID: "t1"}); err != nil || len(f.resets) != 1 {
			t.Fatalf("forgot = %v, %d resets, want the reset of a verified account", err, len(f.resets))
		}
		if err := f.svc().ResetPassword(ctx, ResetPasswordInput{Token: f.resets[0].Token, NewPassword: "a-reset-password"}); err != nil {
			t.Fatalf("reset: %v", err)
		}
		if _, _, err := f.auth.Login(ctx, LoginInput{Email: invitedEmail, Password: "a-reset-password", TenantID: "t1"}); err != nil {
			t.Fatalf("login after the reset: %v", err)
		}
	})

	t.Run("a reset token for a reserved account is refused, and the invitation still works", func(t *testing.T) {
		f := newInvitationFixture(t)
		result := f.invite(invitedEmail)
		// A token minted while the account was not reserved — the window in
		// which its only invitation was consumed by an acceptance that then
		// failed and handed it back — stored directly.
		const resetToken = "a-reset-token-minted-in-that-window"
		if err := f.users.UpdateResetToken(ctx, result.User.ID, "t1", hashToken(resetToken), time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := f.svc().ResetPassword(ctx, ResetPasswordInput{Token: resetToken, NewPassword: "a-reset-password"}); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("reset = %v, want ErrInvalidToken", err)
		}
		if stored, _ := f.users.GetUserByID(ctx, result.User.ID, "t1"); stored.PasswordHash != "" {
			t.Fatal("the refused reset set a password")
		}
		if _, err := f.accept(result.Token, "a-new-password"); err != nil {
			t.Fatalf("accept after the refused reset: %v", err)
		}
	})
}

// TestAdminInvitationsAreRefusedUnderTheFirstUserPolicy: under AdminFirstUser
// the console belongs to the lowest user id, and an invitation used to create
// an account at once whose random id could sort first — the inviting admin
// locked out on the spot, the invitee owning the console on acceptance. The
// route now refuses to invite under that policy, whoever calls it.
func TestAdminInvitationsAreRefusedUnderTheFirstUserPolicy(t *testing.T) {
	ctx := context.Background()
	f := newAdminInvitationFixture(t, func(o *AdminOptions) { o.AccessPolicy = AdminFirstUser() })
	const adminID = "usr_ffffffffffffffffffffffffffffffff"
	hash, _ := hashPassword("admin-password", testBcryptCost)
	if _, err := f.users.CreateUser(ctx, User{ID: adminID, Email: "admin@example.com", PasswordHash: hash, IsEmailVerified: true}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, tokens, err := f.auth.Login(ctx, LoginInput{Email: "admin@example.com", Password: "admin-password"})
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	admin := map[string]string{"Authorization": "Bearer " + tokens.AccessToken}

	// The administrator, and a machine caller, whose invitation would move
	// the console just the same.
	body := `{"email":"contractor@example.com","role":"viewer"}`
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"the first user": f.do(http.MethodPost, AdminInvitationsPath, body, admin),
		"a machine":      f.machine(http.MethodPost, AdminInvitationsPath, body),
	} {
		if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), "first-user access policy") {
			t.Errorf("%s: invite = %d %s, want 501 naming the policy", name, rec.Code, rec.Body.String())
		}
	}
	if len(f.deliveries) != 0 {
		t.Fatalf("deliveries = %d, want none", len(f.deliveries))
	}
	if users, _ := f.svc().ListUsers(ctx, "", 10, 0); len(users) != 1 {
		t.Fatalf("users = %d, want the administrator alone", len(users))
	}
	// The console stays the administrator's, and the rest of the invitation
	// surface — listing, revoking — still answers.
	if rec := f.do(http.MethodGet, AdminUsersPath, "", admin); rec.Code != http.StatusOK {
		t.Fatalf("the administrator on the console = %d", rec.Code)
	}
	if rec := f.do(http.MethodGet, AdminInvitationsPath, "", admin); rec.Code != http.StatusOK {
		t.Fatalf("the listing = %d", rec.Code)
	}
}

// TestInviteUserKeepsAnAccountAcceptedDuringAFailedSend: a sender that
// delivers and then reports a failure lets the invitee accept before the undo
// runs. The undo used to delete the account on `created` alone; it now deletes
// it only once the invitation is dead, and here the revocation finds it
// accepted.
func TestInviteUserKeepsAnAccountAcceptedDuringAFailedSend(t *testing.T) {
	ctx := context.Background()
	f := newInvitationFixture(t)
	accepted := errors.New("not attempted")
	f.svc().cfg.SendInvitation = func(_ context.Context, d InvitationDelivery) error {
		// The mail went out, and the invitee was quick.
		_, accepted = f.accept(d.Token, "a-new-password")
		return errors.New("gateway timeout after delivery")
	}
	if _, err := f.auth.InviteUser(ctx, InviteUserInput{Email: invitedEmail, TenantID: "t1"}); !errors.Is(err, ErrDeliveryFailed) {
		t.Fatalf("invite = %v, want ErrDeliveryFailed", err)
	}
	if accepted != nil {
		t.Fatalf("the invitee's accept failed: %v", accepted)
	}
	if _, err := f.users.GetUserByEmail(ctx, invitedEmail, "t1"); err != nil {
		t.Fatalf("the undo deleted the account the invitee activated: %v", err)
	}
	if _, _, err := f.auth.Login(ctx, LoginInput{Email: invitedEmail, Password: "a-new-password", TenantID: "t1"}); err != nil {
		t.Fatalf("login: %v", err)
	}
	if !strings.Contains(f.logged(), "is kept") {
		t.Errorf("logs = %q, want the kept account explained", f.logged())
	}
}

// TestAdminCreateInvitationRequiresJSON: the admin router has no CSRF layer,
// and the create route used to decode any content type, so a cross-site
// text/plain form riding an administrator's cookie minted an invitation to a
// mailbox of the form's choosing. It now refuses everything but JSON, which a
// cross-site form cannot send.
func TestAdminCreateInvitationRequiresJSON(t *testing.T) {
	ctx := context.Background()
	f := newAdminInvitationFixture(t, nil) // the policy admits usr_admin
	hash, _ := hashPassword("admin-password", testBcryptCost)
	if _, err := f.users.CreateUser(ctx, User{ID: "usr_admin", Email: "admin@example.com", PasswordHash: hash, IsEmailVerified: true}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, tokens, err := f.auth.Login(ctx, LoginInput{Email: "admin@example.com", Password: "admin-password"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	cookie := AccessTokenCookieName + "=" + tokens.AccessToken

	// <form enctype="text/plain"> with name `{"email":"attacker@evil.example","role":"admin","pad":"` and value `"}`.
	forged := `{"email":"attacker@evil.example","role":"admin","pad":"="}`
	for _, contentType := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", ""} {
		rec := f.do(http.MethodPost, AdminInvitationsPath, forged, map[string]string{
			"Content-Type":   contentType,
			"Origin":         "https://app.evil.example",
			"Sec-Fetch-Site": "same-site",
			"Cookie":         cookie,
		})
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("Content-Type %q: create = %d %s, want 415", contentType, rec.Code, rec.Body.String())
		}
	}
	if len(f.deliveries) != 0 {
		t.Fatalf("deliveries = %+v, want none", f.deliveries)
	}
	if _, err := f.users.GetUserByEmail(ctx, "attacker@evil.example", ""); err == nil {
		t.Fatal("a refused request created the account")
	}

	rec := f.do(http.MethodPost, AdminInvitationsPath, `{"email":"invitee@example.com"}`, map[string]string{
		"Content-Type": "application/json; charset=utf-8",
		"Cookie":       cookie,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("JSON with a charset = %d %s, want 201", rec.Code, rec.Body.String())
	}
}

// TestInviteUserRefusesAnAddressThatIsNotOneMailbox: an acceptance marks the
// address verified because the token reached it, so the invitation is only
// ever sent to one plain mailbox.
func TestInviteUserRefusesAnAddressThatIsNotOneMailbox(t *testing.T) {
	ctx := context.Background()
	f := newAdminInvitationFixture(t, nil)
	for _, address := range []string{
		"a@example.com, b@example.com",
		"Invitee <invitee@example.com>",
		"<invitee@example.com>",
		"invitee@example.com\r\nBcc: other@example.com",
		"invitee@example.com\nother@example.com",
		"invitee@example.com\x00",
		"invitee @example.com",
		"invitee@example.com (comment)",
		`"invitee"@example.com`,
		"not-an-address",
	} {
		if _, err := f.auth.InviteUser(ctx, InviteUserInput{Email: address, TenantID: "t1"}); !errors.Is(err, ErrInvalidInvitationEmail) {
			t.Errorf("InviteUser(%q) = %v, want ErrInvalidInvitationEmail", address, err)
		}
	}
	if users, _ := f.svc().ListUsers(ctx, "", 10, 0); len(users) != 0 || len(f.deliveries) != 0 {
		t.Fatalf("users = %d, deliveries = %d, want nothing written", len(users), len(f.deliveries))
	}
	rec := f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"a@example.com, b@example.com","tenantId":"t1"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Email is not a valid address") {
		t.Fatalf("route = %d %s, want 400 naming the address", rec.Code, rec.Body.String())
	}
	for _, address := range []string{"  Plus+Tag@Example.COM ", "üser@exämple.com"} {
		if _, err := f.auth.InviteUser(ctx, InviteUserInput{Email: address, TenantID: "t1"}); err != nil {
			t.Errorf("InviteUser(%q) = %v, want it invited", address, err)
		}
	}
}

// tenantBlindUsers finds an address in tenant t1 whatever tenant it is asked
// for: a store that does not scope GetUserByEmail.
type tenantBlindUsers struct{ *MemoryUserStore }

func (s tenantBlindUsers) GetUserByEmail(ctx context.Context, email, _ string) (User, error) {
	return s.MemoryUserStore.GetUserByEmail(ctx, email, "t1")
}

// TestInviteUserReinviteRefusesADifferentRoleOrTenant: a re-invitation reuses
// the pending account as it is, and used to answer 200 for a body whose role
// was silently not applied. A different role or tenant is now refused.
func TestInviteUserReinviteRefusesADifferentRoleOrTenant(t *testing.T) {
	ctx := context.Background()
	f := newAdminInvitationFixture(t, nil, WithInvitationReinvite(true))
	first := f.invite(invitedEmail) // role "operator", tenant t1

	if _, err := f.auth.InviteUser(ctx, InviteUserInput{Email: invitedEmail, TenantID: "t1", Role: "admin"}); !errors.Is(err, ErrInvitationMismatch) {
		t.Fatalf("re-invite with another role = %v, want ErrInvitationMismatch", err)
	}
	rec := f.machine(http.MethodPost, AdminInvitationsPath, `{"email":"`+invitedEmail+`","tenantId":"t1","role":"admin"}`)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "different role or tenant") {
		t.Fatalf("route = %d %s, want 409 naming the mismatch", rec.Code, rec.Body.String())
	}
	if pending, _ := f.store.PendingInvitationsForUser(ctx, first.User.ID); len(pending) != 1 || pending[0].ID != first.Invitation.ID {
		t.Fatalf("pending = %+v, want the first invitation alone", pending)
	}

	f.svc().users = tenantBlindUsers{f.users}
	if _, err := f.auth.InviteUser(ctx, InviteUserInput{Email: invitedEmail, TenantID: "t2"}); !errors.Is(err, ErrInvitationMismatch) {
		t.Fatalf("re-invite into another tenant = %v, want ErrInvitationMismatch", err)
	}
	f.svc().users = f.users

	// The same role, or none at all, re-invites.
	for _, body := range []string{
		`{"email":"` + invitedEmail + `","tenantId":"t1","role":"operator"}`,
		`{"email":"` + invitedEmail + `","tenantId":"t1"}`,
	} {
		if rec := f.machine(http.MethodPost, AdminInvitationsPath, body); rec.Code != http.StatusOK {
			t.Fatalf("re-invite %s = %d %s, want 200", body, rec.Code, rec.Body.String())
		}
	}
	if stored, _ := f.users.GetUserByID(ctx, first.User.ID, "t1"); stored.Role != "operator" {
		t.Fatalf("role = %q, want the account's own", stored.Role)
	}
}

// TestRevokeInvitationClearsWhatTheHostAttached: a revocation that removes
// the pending account used to delete the row and its metadata and leave the
// role assignments and tenant memberships a host gave it behind.
func TestRevokeInvitationClearsWhatTheHostAttached(t *testing.T) {
	ctx := context.Background()
	rbac := NewMemoryRolesPermissionsStore()
	tenants := NewMemoryTenantStore()
	f := newInvitationFixture(t, WithRBACProvider(rbac), WithTenantProvider(tenants))
	result := f.invite(invitedEmail)
	// What a host attaches once the invitation has given it the user id.
	if err := rbac.CreateRole(ctx, "editor", []string{"posts:write"}); err != nil {
		t.Fatalf("role: %v", err)
	}
	if err := rbac.AddRoleToUser(ctx, result.User.ID, "editor", "t1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if _, err := tenants.CreateTenant(ctx, Tenant{ID: "t1", Name: "Acme", IsActive: true}); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	if err := tenants.AssociateUserWithTenant(ctx, result.User.ID, "t1"); err != nil {
		t.Fatalf("membership: %v", err)
	}

	revocation, err := f.auth.RevokeInvitation(ctx, result.Invitation.ID, "", "")
	if err != nil || !revocation.AccountRemoved {
		t.Fatalf("revoke = %+v, %v, want the untouched account removed", revocation, err)
	}
	if roles, _ := rbac.GetRolesForUser(ctx, result.User.ID, "t1"); len(roles) != 0 {
		t.Errorf("roles = %v, want them removed with the account", roles)
	}
	if memberships, _ := tenants.GetTenantsForUser(ctx, result.User.ID); len(memberships) != 0 {
		t.Errorf("tenants = %v, want the membership removed with the account", memberships)
	}
	if metadata, _ := f.metadata.GetMetadata(ctx, result.User.ID); len(metadata) != 0 {
		t.Errorf("metadata = %v, want it cleared with the account", metadata)
	}
}
