package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The password-verifier seam, end to end. Config.PasswordVerifier is an
// additive port extension — the reference's login path verifies bcrypt directly
// and has no hook (local.strategy.ts:19-29) — so nothing here is a parity
// assertion. What it pins instead is the shape of the extension: that it is
// invisible until a host configures it, that it cannot be told apart from an
// ordinary login by a client, and that the migration it exists for really lands
// in the store.

// passwordVerifierSpy is a PasswordVerifier that answers what a test told it to
// and records what it was asked. The mutex is there because -race watches this
// package and a verifier is host code called on the request goroutine.
type passwordVerifierSpy struct {
	mu    sync.Mutex
	calls int
	// lastUser and lastPassword are what the seam handed over on the last call.
	lastUser     User
	lastPassword string

	// The canned answer.
	ok       bool
	migrated bool
	err      error
}

func (v *passwordVerifierSpy) verify(_ context.Context, user User, password string) (bool, bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	v.lastUser = user
	v.lastPassword = password
	return v.ok, v.migrated, v.err
}

func (v *passwordVerifierSpy) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

func (v *passwordVerifierSpy) seen() (User, string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lastUser, v.lastPassword
}

// newVerifierSvc builds a service with verify as the seam. Pass nil to leave it
// unconfigured, which is the default every existing deployment runs.
func newVerifierSvc(t *testing.T, verify PasswordVerifier) *Service {
	t.Helper()
	return newVerifierSvcWithStore(t, verify, NewMemoryUserStore())
}

func newVerifierSvcWithStore(t *testing.T, verify PasswordVerifier, users UserStore) *Service {
	t.Helper()
	cfg := testConfig("verifier123456789012345678901234")
	cfg.PasswordVerifier = verify
	svc, err := NewService(cfg, users, NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

// seedPasswordUser seeds a user holding a real local hash of password. An empty
// password leaves the stored hash empty, which is the imported account the seam
// exists for: the user row arrived from the old system without a bcrypt hash
// this library can verify.
func seedPasswordUser(t *testing.T, svc *Service, email, password string) User {
	t.Helper()
	user := seedUser(t, svc, email)
	if password == "" {
		return user
	}
	hash, err := hashPassword(password, testBcryptCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ps, ok := svc.users.(UserPasswordStore)
	if !ok {
		t.Fatal("seed: the test store cannot update a password")
	}
	if err := ps.UpdatePassword(context.Background(), user.ID, user.TenantID, hash); err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	user.PasswordHash = hash
	return user
}

// userStoreOnly hides every optional capability of the store it wraps, leaving
// the three required UserStore methods. It is how the migration branch is put
// in front of a store that cannot write a password.
type userStoreOnly struct{ inner *MemoryUserStore }

func (s userStoreOnly) CreateUser(ctx context.Context, user User) (User, error) {
	return s.inner.CreateUser(ctx, user)
}

func (s userStoreOnly) GetUserByEmail(ctx context.Context, email, tenantID string) (User, error) {
	return s.inner.GetUserByEmail(ctx, email, tenantID)
}

func (s userStoreOnly) GetUserByID(ctx context.Context, id, tenantID string) (User, error) {
	return s.inner.GetUserByID(ctx, id, tenantID)
}

// TestLoginPrefersAVerifyingLocalHashOverTheVerifier is the first of the four
// outcomes and the one that bounds the cost of the whole seam: a user whose
// stored hash verifies is logged in by it, and the hook is not consulted. Were
// it consulted first, or consulted always, every login in a migrated deployment
// would keep calling the system it migrated away from.
func TestLoginPrefersAVerifyingLocalHashOverTheVerifier(t *testing.T) {
	spy := &passwordVerifierSpy{ok: true, migrated: true}
	svc := newVerifierSvc(t, spy.verify)
	seedPasswordUser(t, svc, "local@example.com", "password1")

	user, tokens, err := svc.Login(context.Background(), LoginInput{
		Email: "local@example.com", Password: "password1", TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if user.Email != "local@example.com" || tokens.AccessToken == "" {
		t.Fatalf("unexpected login result: %+v / %+v", user, tokens)
	}
	if got := spy.callCount(); got != 0 {
		t.Fatalf("verifier was consulted %d times for a user whose local hash verifies; want 0", got)
	}
}

// TestPasswordVerifierMigratesAndIsNotConsultedAgain is the second outcome, and
// the migration itself: the hook accepts the old system's password, the service
// writes it locally through the password-update path, and the next login
// verifies against what was written instead of asking again.
//
// The stored hash is read back out of the store rather than off the returned
// User, so an implementation that updated only the value in hand would fail
// here.
func TestPasswordVerifierMigratesAndIsNotConsultedAgain(t *testing.T) {
	ctx := context.Background()
	const legacyPassword = "old-provider-secret"
	spy := &passwordVerifierSpy{ok: true, migrated: true}
	svc := newVerifierSvc(t, spy.verify)
	user := seedPasswordUser(t, svc, "migrate@example.com", "")

	if before := storedUser(t, svc, user.ID); before.PasswordHash != "" {
		t.Fatalf("fixture should start with no local hash, got %q", before.PasswordHash)
	}

	in := LoginInput{Email: "migrate@example.com", Password: legacyPassword, TenantID: "t1"}
	got, tokens, err := svc.Login(ctx, in)
	if err != nil {
		t.Fatalf("migrating login: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("migrating login issued no session")
	}
	if got.ID != user.ID {
		t.Fatalf("login returned user %q, want %q", got.ID, user.ID)
	}
	if n := spy.callCount(); n != 1 {
		t.Fatalf("verifier called %d times on the first login, want 1", n)
	}
	seenUser, seenPassword := spy.seen()
	if seenUser.ID != user.ID || seenPassword != legacyPassword {
		t.Fatalf("verifier was handed user %q / password %q, want %q / %q",
			seenUser.ID, seenPassword, user.ID, legacyPassword)
	}

	// The migration has to be in the store, and it has to be a usable hash of
	// the password that was proven, at the configured cost.
	after := storedUser(t, svc, user.ID)
	if after.PasswordHash == "" {
		t.Fatal("migration wrote no hash through the store")
	}
	if !verifyPassword(legacyPassword, after.PasswordHash) {
		t.Fatal("the stored hash does not verify the migrated password")
	}
	assertHashCost(t, after.PasswordHash, testBcryptCost)
	if got.PasswordHash != after.PasswordHash {
		t.Fatal("the returned user still carries the pre-migration hash")
	}

	// Second login: the local hash now answers, so the old system is not asked.
	if _, tokens, err = svc.Login(ctx, in); err != nil {
		t.Fatalf("second login: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("second login issued no session")
	}
	if n := spy.callCount(); n != 1 {
		t.Fatalf("verifier called %d times overall; the second login should not have consulted it", n)
	}
}

// TestPasswordVerifierAcceptanceWithoutMigrationLeavesTheStoreAlone pins the
// third documented result: ok with migrated=false logs the user in and writes
// nothing, so a host that means to keep owning the credential is not handed a
// copy of it, and the verifier is consulted again next time.
func TestPasswordVerifierAcceptanceWithoutMigrationLeavesTheStoreAlone(t *testing.T) {
	ctx := context.Background()
	spy := &passwordVerifierSpy{ok: true, migrated: false}
	svc := newVerifierSvc(t, spy.verify)
	user := seedPasswordUser(t, svc, "keep@example.com", "password1")

	in := LoginInput{Email: "keep@example.com", Password: "remote-secret", TenantID: "t1"}
	if _, tokens, err := svc.Login(ctx, in); err != nil {
		t.Fatalf("login: %v", err)
	} else if tokens.AccessToken == "" {
		t.Fatal("login issued no session")
	}
	if after := storedUser(t, svc, user.ID); after.PasswordHash != user.PasswordHash {
		t.Fatal("a verifier that did not ask for migration still had the stored hash rewritten")
	}
	if _, _, err := svc.Login(ctx, in); err != nil {
		t.Fatalf("second login: %v", err)
	}
	if n := spy.callCount(); n != 2 {
		t.Fatalf("verifier called %d times, want 2: without migration each login must ask again", n)
	}
}

// TestPasswordVerifierRejectionIsAnOrdinaryBadPassword is the third outcome and
// the one a client must not be able to detect. The same request is put to a
// service whose verifier says no and to one with no verifier at all, and the two
// answers are compared as the sentinel and as the HTTP envelope the adapters
// write from it.
func TestPasswordVerifierRejectionIsAnOrdinaryBadPassword(t *testing.T) {
	ctx := context.Background()
	in := LoginInput{Email: "reject@example.com", Password: "not-the-password", TenantID: "t1"}

	spy := &passwordVerifierSpy{ok: false}
	withVerifier := newVerifierSvc(t, spy.verify)
	seedPasswordUser(t, withVerifier, "reject@example.com", "password1")
	_, verifierTokens, verifierErr := withVerifier.Login(ctx, in)

	plain := newVerifierSvc(t, nil)
	seedPasswordUser(t, plain, "reject@example.com", "password1")
	_, plainTokens, plainErr := plain.Login(ctx, in)

	if n := spy.callCount(); n != 1 {
		t.Fatalf("verifier called %d times, want 1: a non-verifying hash must reach it", n)
	}
	if !errors.Is(verifierErr, ErrInvalidCredentials) {
		t.Fatalf("rejected login returned %v, want ErrInvalidCredentials", verifierErr)
	}
	if verifierErr != plainErr {
		t.Fatalf("rejected login returned %v; an ordinary bad password returns %v — the two must be the same value", verifierErr, plainErr)
	}
	if got, want := HTTPErrorFor(verifierErr), HTTPErrorFor(plainErr); got != want {
		t.Fatalf("rejected login maps to %+v, an ordinary bad password to %+v", got, want)
	}
	if verifierTokens != (AuthTokens{}) || plainTokens != (AuthTokens{}) {
		t.Fatalf("a refused login issued tokens: %+v / %+v", verifierTokens, plainTokens)
	}
}

// TestPasswordVerifierErrorFailsLoginClosed is the fourth outcome. A verifier
// that cannot decide is not a verifier that said yes, and it is not one that
// said no either: the login fails with the generic 500, no session exists
// afterwards, and nothing the client receives names the branch that ran.
func TestPasswordVerifierErrorFailsLoginClosed(t *testing.T) {
	ctx := context.Background()
	spy := &passwordVerifierSpy{err: errors.New("legacy idp unreachable")}
	svc := newVerifierSvc(t, spy.verify)
	user := seedPasswordUser(t, svc, "closed@example.com", "password1")

	got, tokens, err := svc.Login(ctx, LoginInput{
		Email: "closed@example.com", Password: "old-provider-secret", TenantID: "t1",
	})
	if err == nil {
		t.Fatal("a verifier that errored logged the user in")
	}
	if mapped := HTTPErrorFor(err); mapped != HTTPErrInternal {
		t.Fatalf("verifier failure maps to %+v, want the generic %+v", mapped, HTTPErrInternal)
	}
	// The sentinels a client could tell apart. None of them may be reachable
	// through this error, which is why the seam wraps with %v and not %w.
	for _, sentinel := range []error{
		ErrInvalidCredentials, ErrFeatureNotSupported, ErrEmailNotVerified,
		ErrTwoFactorRequired, ErrWeakPassword, ErrInvalidToken,
	} {
		if errors.Is(err, sentinel) {
			t.Fatalf("verifier failure unwraps to %v, which the wire would tell apart from a 500", sentinel)
		}
	}
	if got.ID != "" || tokens != (AuthTokens{}) {
		t.Fatalf("failed login returned user %+v and tokens %+v", got, tokens)
	}
	sessions, ok := svc.sessions.(*MemorySessionStore)
	if !ok {
		t.Fatal("fixture session store changed type")
	}
	list, err := sessions.ListSessionsForUser(ctx, user.ID, "t1")
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("a failed login left %d session(s) behind", len(list))
	}
	if after := storedUser(t, svc, user.ID); after.PasswordHash != user.PasswordHash {
		t.Fatal("a failed login rewrote the stored hash")
	}
}

// TestPasswordVerifierIsNeverCalledWhenNoneIsConfigured is the promise the whole
// extension rests on: a deployment that did not ask for the seam does not get
// it. The same spy is wired into a second service so that the zero call count
// below is a fact about configuration and not about a hook that never works.
func TestPasswordVerifierIsNeverCalledWhenNoneIsConfigured(t *testing.T) {
	ctx := context.Background()
	in := LoginInput{Email: "off@example.com", Password: "not-the-password", TenantID: "t1"}
	spy := &passwordVerifierSpy{ok: true, migrated: true}

	unconfigured := newVerifierSvc(t, nil)
	user := seedPasswordUser(t, unconfigured, "off@example.com", "password1")
	if _, _, err := unconfigured.Login(ctx, in); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("login without a verifier returned %v, want ErrInvalidCredentials", err)
	}
	if n := spy.callCount(); n != 0 {
		t.Fatalf("verifier called %d times by a service that has none configured", n)
	}
	if after := storedUser(t, unconfigured, user.ID); after.PasswordHash != user.PasswordHash {
		t.Fatal("a login without a verifier rewrote the stored hash")
	}

	// Same spy, same request, a service that did configure it: the hook fires,
	// so the zero above is the configuration and nothing else.
	configured := newVerifierSvc(t, spy.verify)
	seedPasswordUser(t, configured, "off@example.com", "password1")
	if _, _, err := configured.Login(ctx, in); err != nil {
		t.Fatalf("login with the verifier configured: %v", err)
	}
	if n := spy.callCount(); n != 1 {
		t.Fatalf("verifier called %d times once configured, want 1", n)
	}
}

// TestPasswordVerifierMigrationOnAStoreThatCannotWriteIsAGeneric500 covers the
// one failure that would leak loudest if it were mapped: a store that is not a
// UserPasswordStore answers ErrFeatureNotSupported everywhere else in this
// package, and that sentinel is 501 NOT_IMPLEMENTED on the wire. On the login
// path it would announce that a migration was attempted, so the branch reports
// an opaque error instead.
func TestPasswordVerifierMigrationOnAStoreThatCannotWriteIsAGeneric500(t *testing.T) {
	spy := &passwordVerifierSpy{ok: true, migrated: true}
	svc := newVerifierSvcWithStore(t, spy.verify, userStoreOnly{inner: NewMemoryUserStore()})
	seedUser(t, svc, "nostore@example.com")

	_, tokens, err := svc.Login(context.Background(), LoginInput{
		Email: "nostore@example.com", Password: "old-provider-secret", TenantID: "t1",
	})
	if err == nil {
		t.Fatal("a migration the store cannot persist logged the user in")
	}
	if errors.Is(err, ErrFeatureNotSupported) {
		t.Fatalf("migration failure unwraps to ErrFeatureNotSupported, which the wire spells 501: %v", err)
	}
	if mapped := HTTPErrorFor(err); mapped != HTTPErrInternal {
		t.Fatalf("migration failure maps to %+v, want the generic %+v", mapped, HTTPErrInternal)
	}
	if tokens != (AuthTokens{}) {
		t.Fatalf("failed migration issued tokens: %+v", tokens)
	}
}

// TestWithPasswordVerifierOption checks the Option end of the seam: it reaches
// Config, and nil is refused rather than quietly turning the seam off.
func TestWithPasswordVerifierOption(t *testing.T) {
	spy := &passwordVerifierSpy{ok: true}
	a, err := newTestAuth(WithPasswordVerifier(spy.verify))
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	if a.Service().cfg.PasswordVerifier == nil {
		t.Fatal("WithPasswordVerifier did not reach Config")
	}

	if _, err = newTestAuth(WithPasswordVerifier(nil)); err == nil {
		t.Fatal("WithPasswordVerifier(nil) was accepted")
	} else if !strings.Contains(err.Error(), "password verifier") {
		t.Fatalf("unhelpful error for a nil verifier: %v", err)
	}
}

// TestPasswordVerifierAdoptionOverwritesAWorkingLocalPassword pins the sharpest
// edge on the seam, which the empty-hash fixtures above hide: the hook is
// reached for *any* stored hash that failed to verify, not only an absent one,
// so an adopting verifier that is not gated on a migration marker replaces a
// live local credential with whatever the request carried. That is the
// behaviour, and it is the reason the docs make the marker gate a requirement
// rather than an example flourish — so it is asserted here rather than left to
// be discovered.
func TestPasswordVerifierAdoptionOverwritesAWorkingLocalPassword(t *testing.T) {
	ctx := context.Background()
	const (
		localPassword = "the-password-already-stored"
		sentPassword  = "the-password-the-request-carried"
	)
	spy := &passwordVerifierSpy{ok: true, migrated: true}
	svc := newVerifierSvc(t, spy.verify)
	user := seedPasswordUser(t, svc, "overwrite@example.com", localPassword)
	if before := storedUser(t, svc, user.ID); !verifyPassword(localPassword, before.PasswordHash) {
		t.Fatal("fixture should start with a hash that verifies the local password")
	}

	_, tokens, err := svc.Login(ctx, LoginInput{
		Email: "overwrite@example.com", Password: sentPassword, TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("login issued no session")
	}
	if n := spy.callCount(); n != 1 {
		t.Fatalf("verifier called %d times, want 1", n)
	}

	after := storedUser(t, svc, user.ID)
	if !verifyPassword(sentPassword, after.PasswordHash) {
		t.Fatal("adoption did not store the password the request carried")
	}
	if verifyPassword(localPassword, after.PasswordHash) {
		t.Fatal("the previous local password still verifies: adoption replaces the stored hash, it does not merge with it")
	}
}

// TestPasswordVerifierDoesNotAdoptAnEmptyPassword guards the degenerate corner
// of the adoption branch. A verifier that answers ok for an empty password is
// host code being wrong, but hashing "" would be this library being wrong twice
// over: the account would accept an empty password forever, and the passwordless
// initial-password path, which keys on an empty PasswordHash
// (wire_password_email.go:347), would be closed for good. The login is allowed;
// the write is not.
func TestPasswordVerifierDoesNotAdoptAnEmptyPassword(t *testing.T) {
	ctx := context.Background()
	spy := &passwordVerifierSpy{ok: true, migrated: true}
	svc := newVerifierSvc(t, spy.verify)
	user := seedPasswordUser(t, svc, "empty@example.com", "")

	_, tokens, err := svc.Login(ctx, LoginInput{
		Email: "empty@example.com", Password: "", TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("login issued no session")
	}
	if after := storedUser(t, svc, user.ID); after.PasswordHash != "" {
		t.Fatalf("an empty password was adopted as the stored hash %q", after.PasswordHash)
	}
	// Nothing was adopted, so the seam is consulted again, exactly as
	// migrated=false behaves.
	if _, _, err := svc.Login(ctx, LoginInput{
		Email: "empty@example.com", Password: "", TenantID: "t1",
	}); err != nil {
		t.Fatalf("second login: %v", err)
	}
	if n := spy.callCount(); n != 2 {
		t.Fatalf("verifier called %d times, want 2: nothing was written, so the hook must be asked again", n)
	}
}

// TestPasswordVerifierMigratesBeforeTheEmailVerificationGate pins the judgement
// call in verifyThroughPasswordVerifier: the write is part of accepting the
// credential, so it happens before loginPassword refuses an unverified address.
// The account is refused 403 and issued nothing, and it has still stopped
// depending on the old provider — which is the point, since migrating only on a
// login that completes would leave an unverified account calling that provider
// forever.
func TestPasswordVerifierMigratesBeforeTheEmailVerificationGate(t *testing.T) {
	ctx := context.Background()
	const legacyPassword = "old-provider-secret"
	spy := &passwordVerifierSpy{ok: true, migrated: true}

	cfg := testConfig("verifier123456789012345678901234")
	cfg.PasswordVerifier = spy.verify
	cfg.EmailVerificationMode = EmailVerificationModeStrict
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	// The imported row the seam exists for, with the address still unverified:
	// no local hash, so its login reaches the hook.
	user, err := svc.users.CreateUser(ctx, User{
		ID: "usr_imported_unverified", Email: "unverified@example.com",
		TenantID: "t1", IsEmailVerified: false, CreatedAt: svc.now(),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	in := LoginInput{Email: "unverified@example.com", Password: legacyPassword, TenantID: "t1"}
	got, tokens, err := svc.Login(ctx, in)
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("strict-mode login returned %v, want ErrEmailNotVerified", err)
	}
	if got.ID != "" || tokens != (AuthTokens{}) {
		t.Fatalf("a refused login returned user %+v and tokens %+v", got, tokens)
	}

	after := storedUser(t, svc, user.ID)
	if after.PasswordHash == "" {
		t.Fatal("the refused login wrote no hash: the migration must land before the verification gate")
	}
	if !verifyPassword(legacyPassword, after.PasswordHash) {
		t.Fatal("the stored hash does not verify the password that was proven")
	}

	sessions, ok := svc.sessions.(*MemorySessionStore)
	if !ok {
		t.Fatal("fixture session store changed type")
	}
	list, err := sessions.ListSessionsForUser(ctx, user.ID, "t1")
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("a login refused for an unverified address left %d session(s) behind", len(list))
	}

	// The migration is done: the address is still unverified, so the answer is
	// the same 403, but the old provider is not asked a second time.
	if _, _, err := svc.Login(ctx, in); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("second login returned %v, want ErrEmailNotVerified", err)
	}
	if n := spy.callCount(); n != 1 {
		t.Fatalf("verifier called %d times overall, want 1: the adopted hash now answers", n)
	}
}

// TestPasswordVerifierKeepsContextErrors is the one exception to the %v rule.
// A login the client abandoned, or one whose context expired inside the
// verifier, must stay distinguishable from a legacy provider that is broken —
// and it costs nothing to keep, because HTTPErrorFor maps neither context
// sentinel and both already answer the same generic 500.
func TestPasswordVerifierKeepsContextErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"canceled", context.Canceled},
		{"deadline exceeded", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := &passwordVerifierSpy{err: tc.err}
			svc := newVerifierSvc(t, spy.verify)
			seedPasswordUser(t, svc, "ctx@example.com", "password1")

			_, tokens, err := svc.Login(context.Background(), LoginInput{
				Email: "ctx@example.com", Password: "old-provider-secret", TenantID: "t1",
			})
			if !errors.Is(err, tc.err) {
				t.Fatalf("login returned %v, which no longer unwraps to %v", err, tc.err)
			}
			if mapped := HTTPErrorFor(err); mapped != HTTPErrInternal {
				t.Fatalf("a context failure maps to %+v, want the generic %+v", mapped, HTTPErrInternal)
			}
			if tokens != (AuthTokens{}) {
				t.Fatalf("a failed login issued tokens: %+v", tokens)
			}
		})
	}
}

// TestPasswordVerifierFailuresReachTheLogger covers the only channel an operator
// has. The wire answer is HTTPErrInternal, which carries no code and no error
// text (wire.go:127-129), so behind any of the four adapters a failed verifier
// is indistinguishable from any other 500 unless the seam says so through
// Config.Logger — the same hook a failing BuildTokenClaims and a failing
// TwoFactorPolicy already use. What must never be in that line is the password.
func TestPasswordVerifierFailuresReachTheLogger(t *testing.T) {
	const sentPassword = "plaintext-that-must-not-be-logged"
	var (
		mu     sync.Mutex
		logged []string
	)
	cfg := testConfig("verifier123456789012345678901234")
	cfg.Logger = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, fmt.Sprintf(format, args...))
	}
	spy := &passwordVerifierSpy{err: errors.New("legacy idp unreachable")}
	cfg.PasswordVerifier = spy.verify
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	user := seedPasswordUser(t, svc, "logged@example.com", "password1")

	if _, _, err := svc.Login(context.Background(), LoginInput{
		Email: "logged@example.com", Password: sentPassword, TenantID: "t1",
	}); err == nil {
		t.Fatal("a verifier that errored logged the user in")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(logged) == 0 {
		t.Fatal("a failed verifier logged nothing; the generic 500 is all an operator would see")
	}
	joined := strings.Join(logged, "\n")
	if !strings.Contains(joined, user.ID) || !strings.Contains(joined, "legacy idp unreachable") {
		t.Fatalf("the log line names neither the user nor the cause: %q", joined)
	}
	if strings.Contains(joined, sentPassword) {
		t.Fatalf("the password reached the log: %q", joined)
	}
}

// legacyVerifier accepts exactly one password for an account marked as held by
// the old system, and says no to everything else — the marker-gated shape the
// PasswordVerifier doc asks for. Here the marker is the address.
func legacyVerifier(marked, password string, migrated bool) PasswordVerifier {
	return func(_ context.Context, user User, candidate string) (bool, bool, error) {
		if user.Email != marked {
			return false, false, nil
		}
		return candidate == password, migrated, nil
	}
}

// TestChangePasswordConsultsTheVerifierLikeTheLogin pins review finding 1 on
// #30: an account whose password lives behind Config.PasswordVerifier — no
// local hash, or a hash that is only a migration marker — is not passwordless.
// It must present its current password and pass it through the verifier,
// exactly as POST /login does for it; a token alone does not replace it.
func TestChangePasswordConsultsTheVerifierLikeTheLogin(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		migrated bool
		hash     string // what the row holds for the legacy account
	}{
		{"no local hash, verifier keeps the credential", false, ""},
		{"no local hash, verifier migrates", true, ""},
		{"a marker hash that is not bcrypt", false, "legacy:marker"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryUserStore()
			svc := newVerifierSvcWithStore(t, legacyVerifier("legacy@example.com", "old-secret", tc.migrated), store)
			user := seedUser(t, svc, "legacy@example.com")
			if tc.hash != "" {
				if err := store.UpdatePassword(ctx, user.ID, user.TenantID, tc.hash); err != nil {
					t.Fatalf("seed marker: %v", err)
				}
			}

			for _, current := range []string{"", "not-the-old-one"} {
				err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: user.ID, TenantID: "t1", CurrentPassword: current, NewPassword: "attacker1"})
				if !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("currentPassword %q: %v, want ErrInvalidCredentials", current, err)
				}
			}
			if _, _, err := svc.Login(ctx, LoginInput{Email: "legacy@example.com", Password: "attacker1", TenantID: "t1"}); err == nil {
				t.Fatal("a refused change still set the password")
			}

			if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: user.ID, TenantID: "t1", CurrentPassword: "old-secret", NewPassword: "newpassword1"}); err != nil {
				t.Fatalf("change with the verifier-held password: %v", err)
			}
			if _, _, err := svc.Login(ctx, LoginInput{Email: "legacy@example.com", Password: "newpassword1", TenantID: "t1"}); err != nil {
				t.Fatalf("login with the new password: %v", err)
			}
		})
	}
}

// With a verifier configured, an account without a hash that the verifier does
// not hold either cannot be told apart from one it does, so it is refused
// rather than trusted: the fail-closed side of the same rule. With no verifier
// the reference's passwordless path applies unchanged.
func TestChangePasswordWithoutAHashOnlyPasswordlessWithoutAVerifier(t *testing.T) {
	ctx := context.Background()
	withVerifier := newVerifierSvc(t, legacyVerifier("someone-else@example.com", "x", false))
	oauthOnly := seedUser(t, withVerifier, "oauth@example.com")
	if err := withVerifier.ChangePassword(ctx, ChangePasswordInput{UserID: oauthOnly.ID, TenantID: "t1", NewPassword: "initialpw1"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("with a verifier configured: %v, want ErrInvalidCredentials", err)
	}

	without := newVerifierSvc(t, nil)
	plain := seedUser(t, without, "oauth@example.com")
	if err := without.ChangePassword(ctx, ChangePasswordInput{UserID: plain.ID, TenantID: "t1", NewPassword: "initialpw1"}); err != nil {
		t.Fatalf("without a verifier: %v, want the first password set", err)
	}
}
