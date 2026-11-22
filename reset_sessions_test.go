package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests for Config.RevokeSessionsOnPasswordReset: off, a reset leaves the
// account's sessions alive, as the reference's does; on, a successful reset
// revokes every live session the account holds, and a revocation that fails
// fails the reset rather than claim an end to sessions that are still usable.

// resetSessionsFixture is a service whose session store records revocations
// and can be told to refuse some.
type resetSessionsFixture struct {
	svc      *Service
	sessions *recordingSessionStore
	logged   *[]string
}

func newResetSessionsFixture(t *testing.T, opts ...func(*Config)) resetSessionsFixture {
	t.Helper()
	cfg := testConfig("resetsessions123456789012345678901")
	var logged []string
	var mu sync.Mutex
	cfg.Logger = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, fmt.Sprintf(format, args...))
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	store := &recordingSessionStore{MemorySessionStore: NewMemorySessionStore(), refuse: map[string]error{}}
	svc, err := NewService(cfg, NewMemoryUserStore(), store)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return resetSessionsFixture{svc: svc, sessions: store, logged: &logged}
}

func revokeOnReset(c *Config) { c.RevokeSessionsOnPasswordReset = true }

// recordingSessionStore is a MemorySessionStore that records the ids
// RevokeSessionByID was asked about and refuses those in refuse.
type recordingSessionStore struct {
	*MemorySessionStore
	mu      sync.Mutex
	revoked []string
	refuse  map[string]error
}

func (s *recordingSessionStore) RevokeSessionByID(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	s.revoked = append(s.revoked, sessionID)
	refused := s.refuse[sessionID]
	s.mu.Unlock()
	if refused != nil {
		return refused
	}
	return s.MemorySessionStore.RevokeSessionByID(ctx, sessionID)
}

func (s *recordingSessionStore) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.revoked...)
}

// mintResetToken runs ForgotPassword for email; the fixtures wire no sender,
// so the service hands the token back.
func mintResetToken(t *testing.T, svc *Service, email string) string {
	t.Helper()
	token, err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: email, TenantID: "t1"})
	if err != nil || token == "" {
		t.Fatalf("forgot password: token %q, err %v", token, err)
	}
	return token
}

func login(t *testing.T, svc *Service, email, password string) AuthTokens {
	t.Helper()
	_, tokens, err := svc.Login(context.Background(), LoginInput{Email: email, Password: password, TenantID: "t1"})
	if err != nil {
		t.Fatalf("login %s: %v", email, err)
	}
	return tokens
}

// TestResetPasswordLeavesSessionsAliveByDefault pins the default, which is
// the reference's answer and what every deployment had before the option.
// It passed before the option existed.
func TestResetPasswordLeavesSessionsAliveByDefault(t *testing.T) {
	f := newResetSessionsFixture(t)
	_, registered := registerUser(t, f.svc, "keep@example.com", "t1")
	token := mintResetToken(t, f.svc, "keep@example.com")

	if err := f.svc.ResetPassword(context.Background(), ResetPasswordInput{Token: token, NewPassword: "newpassword1"}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := f.svc.Refresh(context.Background(), registered.RefreshToken); err != nil {
		t.Errorf("refresh after a reset with the option off: %v; the session must stay alive", err)
	}
	if got := f.sessions.asked(); len(got) != 0 {
		t.Errorf("RevokeSessionByID was asked about %q with the option off", got)
	}
}

// TestResetPasswordRevokesTheAccountsSessions: on, every session the account
// held before the reset is revoked — its refresh token answers
// ErrSessionRevoked — and another account's session is not touched. The
// access token already issued is the posture the option documents: valid until
// it expires under SessionCheckOn "refresh", refused at once under "allcalls".
func TestResetPasswordRevokesTheAccountsSessions(t *testing.T) {
	for _, mode := range []string{SessionCheckOnRefresh, SessionCheckOnAllCalls} {
		t.Run("SessionCheckOn "+mode, func(t *testing.T) {
			f := newResetSessionsFixture(t, revokeOnReset, func(c *Config) { c.SessionCheckOn = mode })
			ctx := context.Background()
			_, registered := registerUser(t, f.svc, "reset@example.com", "t1")
			second := login(t, f.svc, "reset@example.com", "password1")
			_, bystander := registerUser(t, f.svc, "bystander@example.com", "t1")
			token := mintResetToken(t, f.svc, "reset@example.com")

			if err := f.svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "newpassword1"}); err != nil {
				t.Fatalf("reset: %v", err)
			}

			for name, tokens := range map[string]AuthTokens{"the registration's": registered, "a later login's": second} {
				if _, err := f.svc.Refresh(ctx, tokens.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
					t.Errorf("refresh with %s session after the reset: err = %v, want ErrSessionRevoked", name, err)
				}
				_, err := f.svc.VerifyAccess(ctx, tokens.AccessToken)
				switch mode {
				case SessionCheckOnAllCalls:
					if !errors.Is(err, ErrSessionRevoked) {
						t.Errorf("%s access token under allcalls: err = %v, want ErrSessionRevoked", name, err)
					}
				default:
					if err != nil {
						t.Errorf("%s access token under %q: err = %v; it is honoured until it expires, as documented", name, mode, err)
					}
				}
			}
			if _, err := f.svc.Refresh(ctx, bystander.RefreshToken); err != nil {
				t.Errorf("another account's session was touched: %v", err)
			}

			// The reset opens no session; the next login does, and it is alive.
			fresh := login(t, f.svc, "reset@example.com", "newpassword1")
			if _, err := f.svc.Refresh(ctx, fresh.RefreshToken); err != nil {
				t.Errorf("a login after the reset: %v", err)
			}
		})
	}
}

// TestResetPasswordRevokesOnlyLiveSessions: a session already revoked or
// already expired is left as it is — revoking it again would relabel an
// earlier revocation on a store that records why — and one that vanished
// between the listing and the revocation is not a failure.
func TestResetPasswordRevokesOnlyLiveSessions(t *testing.T) {
	f := newResetSessionsFixture(t, revokeOnReset)
	ctx := context.Background()
	user, live := registerUser(t, f.svc, "mixed@example.com", "t1")
	gone := login(t, f.svc, "mixed@example.com", "password1")
	now := f.svc.now()
	revokedAt := now.Add(-time.Minute)
	for _, s := range []Session{
		{ID: "ses_already_revoked", UserID: user.ID, TenantID: "t1", RefreshTokenHash: "h1", CreatedAt: now, ExpiresAt: now.Add(time.Hour), RevokedAt: &revokedAt},
		{ID: "ses_expired", UserID: user.ID, TenantID: "t1", RefreshTokenHash: "h2", CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
	} {
		if _, err := f.sessions.CreateSession(ctx, s); err != nil {
			t.Fatalf("seed %s: %v", s.ID, err)
		}
	}
	goneID := f.svc.sessionIDOf(gone)
	f.sessions.refuse[goneID] = ErrSessionNotFound

	token := mintResetToken(t, f.svc, "mixed@example.com")
	if err := f.svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "newpassword1"}); err != nil {
		t.Fatalf("reset: %v; a session that vanished is not a failed revocation", err)
	}
	asked := strings.Join(f.sessions.asked(), ",")
	for _, skipped := range []string{"ses_already_revoked", "ses_expired"} {
		if strings.Contains(asked, skipped) {
			t.Errorf("RevokeSessionByID was asked about %s; asked %q", skipped, asked)
		}
	}
	if !strings.Contains(asked, f.svc.sessionIDOf(live)) {
		t.Errorf("the live session was not revoked; asked %q", asked)
	}
}

// zeroExpiryListing is a session store whose listing leaves ExpiresAt out, as
// a store that projects only some attributes into the listing might.
type zeroExpiryListing struct{ *recordingSessionStore }

func (s zeroExpiryListing) ListSessionsForUser(ctx context.Context, userID, tenantID string) ([]Session, error) {
	sessions, err := s.recordingSessionStore.ListSessionsForUser(ctx, userID, tenantID)
	for i := range sessions {
		sessions[i].ExpiresAt = time.Time{}
	}
	return sessions, err
}

// TestResetPasswordRevokesASessionListedWithoutAnExpiry: an expiry the listing
// does not carry is not an expiry in the past. Reading it as one would skip
// every session such a store lists and answer success with all of them alive.
func TestResetPasswordRevokesASessionListedWithoutAnExpiry(t *testing.T) {
	cfg := testConfig("resetsessions123456789012345678901")
	cfg.RevokeSessionsOnPasswordReset = true
	inner := &recordingSessionStore{MemorySessionStore: NewMemorySessionStore(), refuse: map[string]error{}}
	svc, err := NewService(cfg, NewMemoryUserStore(), zeroExpiryListing{inner})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	_, tokens := registerUser(t, svc, "noexpiry@example.com", "t1")
	token := mintResetToken(t, svc, "noexpiry@example.com")
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: token, NewPassword: "newpassword1"}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := svc.Refresh(context.Background(), tokens.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("refresh after the reset: err = %v, want ErrSessionRevoked", err)
	}
}

// TestResetPasswordFailsWhenARevocationFails: the password has been written
// when the revocation runs, so a store that refuses one revocation leaves a
// changed password and a session that still works. The reset then answers
// the generic 500 rather than a success the caller would read as "every
// other session is gone"; the others are revoked all the same, the failure is
// logged with the user id, and on a store that keeps the token until it is
// cleared the same link completes the revocation once the store recovers.
func TestResetPasswordFailsWhenARevocationFails(t *testing.T) {
	f := newResetSessionsFixture(t, revokeOnReset)
	ctx := context.Background()
	user, first := registerUser(t, f.svc, "partial@example.com", "t1")
	second := login(t, f.svc, "partial@example.com", "password1")
	stuck := f.svc.sessionIDOf(first)
	f.sessions.refuse[stuck] = errors.New("session table throttled")
	token := mintResetToken(t, f.svc, "partial@example.com")

	err := f.svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "newpassword1"})
	if err == nil {
		t.Fatal("a reset whose revocation failed reported success")
	}
	if got := ResetPasswordHTTPError(err); got != HTTPErrInternal {
		t.Errorf("wire answer = %+v, want the generic 500 %+v", got, HTTPErrInternal)
	}
	if _, err := f.svc.Refresh(ctx, second.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("the session the store did revoke: refresh err = %v, want ErrSessionRevoked", err)
	}
	// The refused session still works — which is why the reset did not
	// answer success. Refreshing rotates its token, so the rotated one is what
	// the check after the retry uses.
	rotated, err := f.svc.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatalf("precondition: the refused session should still refresh, got %v", err)
	}
	// The password did change: say so in the log, which is where an operator
	// learns that the 500 was not a failed reset.
	login(t, f.svc, "partial@example.com", "newpassword1")
	var line string
	for _, l := range *f.logged {
		if strings.Contains(l, "could not be revoked") {
			line = l
		}
	}
	if line == "" || !strings.Contains(line, user.ID) || !strings.Contains(line, "session table throttled") {
		t.Errorf("log lines = %q, want one naming the user and the store's error", *f.logged)
	}

	// Same link, store recovered: the reset runs again and revokes the rest.
	delete(f.sessions.refuse, stuck)
	if err := f.svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "newpassword2"}); err != nil {
		t.Fatalf("retry with the same link: %v", err)
	}
	if _, err := f.svc.Refresh(ctx, rotated.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("after the retry: refresh err = %v, want ErrSessionRevoked", err)
	}
	if storedUser(t, f.svc, user.ID).ResetTokenHash != "" {
		t.Error("the token survived a completed reset")
	}
}

// TestResetPasswordRevocationErrorsAreOpaque: whatever a session store
// returns, the reset's answer is the generic 500 — never "Invalid reset
// token" or WEAK_PASSWORD for a request whose token and password were good and
// whose password has been changed.
func TestResetPasswordRevocationErrorsAreOpaque(t *testing.T) {
	for _, sentinel := range []error{ErrInvalidToken, ErrWeakPassword, ErrFeatureNotSupported} {
		t.Run(sentinel.Error(), func(t *testing.T) {
			f := newResetSessionsFixture(t, revokeOnReset)
			_, tokens := registerUser(t, f.svc, "opaque@example.com", "t1")
			f.sessions.refuse[f.svc.sessionIDOf(tokens)] = fmt.Errorf("store: %w", sentinel)
			token := mintResetToken(t, f.svc, "opaque@example.com")

			err := f.svc.ResetPassword(context.Background(), ResetPasswordInput{Token: token, NewPassword: "newpassword1"})
			if err == nil {
				t.Fatal("the reset reported success although a revocation failed")
			}
			if got := ResetPasswordHTTPError(err); got != HTTPErrInternal {
				t.Errorf("a revocation failing with %v answered %+v, want the generic 500", sentinel, got)
			}
		})
	}
}

// TestRevokeSessionsOnPasswordResetNeedsASessionAdminStore: the option is
// refused at construction on a session store that can neither list an
// account's sessions (SessionAdminStore) nor revoke them in one call
// (UserSessionRevoker), rather than accepted and silently left undone.
func TestRevokeSessionsOnPasswordResetNeedsASessionAdminStore(t *testing.T) {
	cfg := testConfig("resetsessions123456789012345678901")
	cfg.RevokeSessionsOnPasswordReset = true
	if _, err := NewService(cfg, NewMemoryUserStore(), bareSessionStore{}); err == nil ||
		!strings.Contains(err.Error(), "SessionAdminStore") {
		t.Errorf("NewService with the option and no SessionAdminStore: err = %v, want a refusal naming SessionAdminStore", err)
	}
	if _, err := New(WithSessionStore(bareSessionStore{}), WithRevokeSessionsOnPasswordReset(true)); err == nil {
		t.Error("New with WithRevokeSessionsOnPasswordReset(true) and no SessionAdminStore must fail")
	}
	cfg.RevokeSessionsOnPasswordReset = false
	if _, err := NewService(cfg, NewMemoryUserStore(), bareSessionStore{}); err != nil {
		t.Errorf("the option off must not require SessionAdminStore: %v", err)
	}
	a, err := New(WithRevokeSessionsOnPasswordReset(true))
	if err != nil {
		t.Fatalf("the default memory session store implements SessionAdminStore: %v", err)
	}
	if !a.Service().cfg.RevokeSessionsOnPasswordReset {
		t.Error("WithRevokeSessionsOnPasswordReset(true) did not set the field")
	}
}

// failingListing is a session store whose listing fails, as one that refuses
// past a cap does (awesome-lambda-auth's DynamoDB store answers
// ErrResultTooLarge past its per-user maximum, revoked sessions counted).
type failingListing struct{ *recordingSessionStore }

var errListingTooLarge = errors.New("session listing: result set exceeds the configured cap")

func (failingListing) ListSessionsForUser(context.Context, string, string) ([]Session, error) {
	return nil, errListingTooLarge
}

// TestResetPasswordFailsWhenTheListingFails: on the listing path a listing
// that fails revokes nothing, so the reset answers the generic 500 — the
// password changed, which the log line says, naming the user — and leaves the
// token, so that on a store that keeps it the same link completes the reset
// once the listing works again.
func TestResetPasswordFailsWhenTheListingFails(t *testing.T) {
	cfg := testConfig("resetsessions123456789012345678901")
	cfg.RevokeSessionsOnPasswordReset = true
	var logged []string
	cfg.Logger = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	inner := &recordingSessionStore{MemorySessionStore: NewMemorySessionStore(), refuse: map[string]error{}}
	svc, err := NewService(cfg, NewMemoryUserStore(), failingListing{inner})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	ctx := context.Background()
	user, tokens := registerUser(t, svc, "overcap@example.com", "t1")
	token := mintResetToken(t, svc, "overcap@example.com")

	err = svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "newpassword1"})
	if err == nil {
		t.Fatal("a reset whose listing failed reported success")
	}
	if got := ResetPasswordHTTPError(err); got != HTTPErrInternal {
		t.Errorf("wire answer = %+v, want the generic 500", got)
	}
	if got := inner.asked(); len(got) != 0 {
		t.Errorf("RevokeSessionByID was asked about %q with no listing", got)
	}
	if _, err := svc.Refresh(ctx, tokens.RefreshToken); err != nil {
		t.Errorf("precondition: with nothing listed the session still works, got %v", err)
	}
	login(t, svc, "overcap@example.com", "newpassword1") // the password did change
	var line string
	for _, l := range logged {
		if strings.Contains(l, "could not be listed") {
			line = l
		}
	}
	if line == "" || !strings.Contains(line, user.ID) || !strings.Contains(line, errListingTooLarge.Error()) {
		t.Errorf("log lines = %q, want one naming the user and the listing's error", logged)
	}
	if storedUser(t, svc, user.ID).ResetTokenHash != hashToken(token) {
		t.Error("the token was cleared by a reset that failed")
	}
}

// bulkRevokingStore is a recordingSessionStore that also implements
// UserSessionRevoker, recording its calls, and notes whether the listing was
// read at all.
type bulkRevokingStore struct {
	*recordingSessionStore
	mu      sync.Mutex
	calls   []string
	listed  bool
	bulkErr error
}

func (s *bulkRevokingStore) RevokeSessionsForUser(ctx context.Context, userID, tenantID string) error {
	s.mu.Lock()
	s.calls = append(s.calls, userID+"/"+tenantID)
	bulkErr := s.bulkErr
	s.mu.Unlock()
	if bulkErr != nil {
		return bulkErr
	}
	return revokeAllInMemory(ctx, s.MemorySessionStore, userID, tenantID)
}

func (s *bulkRevokingStore) ListSessionsForUser(ctx context.Context, userID, tenantID string) ([]Session, error) {
	s.mu.Lock()
	s.listed = true
	s.mu.Unlock()
	return s.recordingSessionStore.ListSessionsForUser(ctx, userID, tenantID)
}

// revokeAllInMemory is a RevokeSessionsForUser over a MemorySessionStore,
// for the test stores below.
func revokeAllInMemory(ctx context.Context, store *MemorySessionStore, userID, tenantID string) error {
	sessions, err := store.ListSessionsForUser(ctx, userID, tenantID)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if session.RevokedAt == nil {
			if err := store.RevokeSessionByID(ctx, session.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func newBulkService(t *testing.T, store SessionStore, logged *[]string) *Service {
	t.Helper()
	cfg := testConfig("resetsessions123456789012345678901")
	cfg.RevokeSessionsOnPasswordReset = true
	cfg.Logger = func(format string, args ...any) { *logged = append(*logged, fmt.Sprintf(format, args...)) }
	svc, err := NewService(cfg, NewMemoryUserStore(), store)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

// TestResetPasswordPrefersTheBulkRevocation: a store that implements
// UserSessionRevoker is asked once, for the account and its tenant, and the
// listing path is not taken — not the listing, not a revocation by id.
func TestResetPasswordPrefersTheBulkRevocation(t *testing.T) {
	store := &bulkRevokingStore{recordingSessionStore: &recordingSessionStore{MemorySessionStore: NewMemorySessionStore(), refuse: map[string]error{}}}
	var logged []string
	svc := newBulkService(t, store, &logged)
	ctx := context.Background()
	user, first := registerUser(t, svc, "bulk@example.com", "t1")
	second := login(t, svc, "bulk@example.com", "password1")
	_, bystander := registerUser(t, svc, "bystander@example.com", "t1")
	token := mintResetToken(t, svc, "bulk@example.com")

	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "newpassword1"}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if want := user.ID + "/t1"; len(store.calls) != 1 || store.calls[0] != want {
		t.Errorf("RevokeSessionsForUser calls = %q, want exactly [%q]", store.calls, want)
	}
	if store.listed || len(store.asked()) != 0 {
		t.Errorf("the listing path ran too: listed %v, revoked by id %q", store.listed, store.asked())
	}
	for name, tokens := range map[string]AuthTokens{"the registration's": first, "a later login's": second} {
		if _, err := svc.Refresh(ctx, tokens.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
			t.Errorf("refresh with %s session after the reset: err = %v, want ErrSessionRevoked", name, err)
		}
	}
	if _, err := svc.Refresh(ctx, bystander.RefreshToken); err != nil {
		t.Errorf("another account's session was touched: %v", err)
	}
}

// TestResetPasswordFailsWhenTheBulkRevocationFails: the bulk call failing is a
// reset that may have left a session working, answered as the listing path
// answers it — the generic 500, a log line naming the user, the token kept.
func TestResetPasswordFailsWhenTheBulkRevocationFails(t *testing.T) {
	store := &bulkRevokingStore{
		recordingSessionStore: &recordingSessionStore{MemorySessionStore: NewMemorySessionStore(), refuse: map[string]error{}},
		bulkErr:               fmt.Errorf("store: %w", ErrInvalidToken), // a sentinel must not leak into the answer
	}
	var logged []string
	svc := newBulkService(t, store, &logged)
	user, _ := registerUser(t, svc, "bulkfail@example.com", "t1")
	token := mintResetToken(t, svc, "bulkfail@example.com")

	err := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: token, NewPassword: "newpassword1"})
	if err == nil {
		t.Fatal("a reset whose bulk revocation failed reported success")
	}
	if got := ResetPasswordHTTPError(err); got != HTTPErrInternal {
		t.Errorf("wire answer = %+v, want the generic 500", got)
	}
	var line string
	for _, l := range logged {
		if strings.Contains(l, "could not be revoked") {
			line = l
		}
	}
	if line == "" || !strings.Contains(line, user.ID) {
		t.Errorf("log lines = %q, want one naming the user", logged)
	}
	if storedUser(t, svc, user.ID).ResetTokenHash != hashToken(token) {
		t.Error("the token was cleared by a reset that failed")
	}
}

// bulkOnlySessionStore implements SessionStore and UserSessionRevoker and
// nothing else: no listing, no revocation by id.
type bulkOnlySessionStore struct {
	SessionStore
	inner *MemorySessionStore
}

func (s bulkOnlySessionStore) RevokeSessionsForUser(ctx context.Context, userID, tenantID string) error {
	return revokeAllInMemory(ctx, s.inner, userID, tenantID)
}

// TestRevokeSessionsOnPasswordResetAcceptsABulkRevoker: a session store with
// UserSessionRevoker and no SessionAdminStore is enough for the option, and
// the reset revokes through it.
func TestRevokeSessionsOnPasswordResetAcceptsABulkRevoker(t *testing.T) {
	inner := NewMemorySessionStore()
	var logged []string
	svc := newBulkService(t, bulkOnlySessionStore{SessionStore: inner, inner: inner}, &logged)
	_, tokens := registerUser(t, svc, "bulkonly@example.com", "t1")
	token := mintResetToken(t, svc, "bulkonly@example.com")
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: token, NewPassword: "newpassword1"}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := svc.Refresh(context.Background(), tokens.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("refresh after the reset: err = %v, want ErrSessionRevoked", err)
	}
}
