package auth

import (
	"context"
	"errors"
	"fmt"
)

// This file holds the password-verifier seam: the hook a deployment migrating
// off another identity provider uses to accept that provider's password once,
// turn it into a local hash, and stop depending on it.
//
// It is an additive port extension. The reference has no such hook and no place
// to put one: its login path verifies the stored bcrypt hash directly.
// LocalStrategy.authenticate looks the user up, refuses an account with no
// password, calls passwordService.compare and refuses a false
// (local.strategy.ts:19-29), compare being bcrypt.compare and nothing else
// (password.service.ts:8-10); POST /login is that one call plus the 2FA
// decision (auth.router.ts:541-544). Nothing in AuthConfig names a verifier, a
// legacy hash or a migration.
//
// So this seam is not parity and must never be mistaken for it. It is off
// unless a host turns it on, and a deployment that leaves Config.PasswordVerifier
// nil answers POST /login exactly as it did before the seam existed, which is
// exactly as the reference answers.
//
// Why it is nonetheless not in the deviation register in compatibility.go. The
// test the register applies is not whether the default matches the reference:
// oauth-provisioning-is-a-policy-not-a-function is registered even though "a
// deployment that configures nothing cannot see any of the three codes"
// (compatibility.go:385-388). It is registered because configuring it puts
// three codes on the wire that the route could not produce before. This seam
// puts none. With a verifier configured, POST <prefix>/login still answers only
// what it already answered: the ordinary 200 token body, the 401
// INVALID_CREDENTIALS that a wrong local password produces - the same sentinel,
// so byte for byte the same envelope - or the generic 500. No new status, no
// new code, no new body field, on this route or any other. Keep it that way.
// Anything that lets a client tell a configured verifier apart - a new code, a
// new status, a field in a body - is a wire deviation, and belongs in the
// register with README.md regenerated from it (compatibility.go:14-22).
//
// Why a callback on Config rather than an optional store interface. The
// question a verifier answers - is this the password the old system held - is
// not a question about persistence, which is what every type-asserted interface
// in store.go asks. It is host policy, in practice an HTTP call to the system
// being migrated away from, and it belongs beside Config.BuildTokenClaims and
// the delivery senders for the reasons delivery.go sets out at length.

// PasswordVerifier is the seam itself: a host-supplied check consulted for a
// user whose stored hash did not verify the password a login request carried.
//
// It is handed the user record as the store holds it, so that a migration
// marker the host wrote - a metadata key, a column of its own, a magic
// placeholder in the hash - is what it keys on, and the plaintext password. A
// verifier is host code that may log or forward what it receives, so it
// receives what it needs to answer and nothing else.
//
// Key on that marker first, and answer (false, false, nil) before doing
// anything else when it is absent. That is a requirement of writing a verifier,
// not a stylistic flourish, and it follows from which logins reach the hook:
// every login whose stored hash did not verify does.
//
//   - That is not only the imported row. An account that never had a password -
//     OAuth-only, magic-link-only - carries an empty PasswordHash, so its failed
//     logins reach the hook too, carrying whatever plaintext the request held.
//     The reference refuses those before it compares anything
//     (local.strategy.ts:23-25); this port hands them to host code instead, and
//     the marker is what keeps host code from doing anything with them.
//   - The hook sits on an unauthenticated route. A verifier that calls the old
//     provider for any address it is handed turns POST <prefix>/login into an
//     amplifier aimed at that provider - and at its lockout counters - for every
//     address an attacker cares to name. A marker read out of the user record
//     already in hand costs nothing and cuts that off; whatever call survives
//     the marker must still be bounded and rate-limited by the verifier itself.
//
// The results:
//
//   - ok=false: not the password. The login answers ErrInvalidCredentials, the
//     same value, and therefore the same 401 body, that a wrong local password
//     produces.
//
//   - ok=true, migrated=true: the password, and the service should adopt it.
//     The login hashes it at Config.BcryptCost and writes it through
//     UserPasswordStore.UpdatePassword - the path ResetPassword and
//     ChangePassword already write through - before it issues anything. From
//     then on the local hash verifies and the hook is never reached for this
//     user again, which is how the migration ends. A marker the host keeps in
//     its own data is the host's to clear, and the verifier is the natural
//     place to clear it from.
//
//     Adoption overwrites whatever hash was stored, not only an empty one. The
//     hook is reached for any hash that failed to verify, so a verifier that is
//     not gated on a migration marker can answer ok for a live account and
//     replace its working local password with whatever password the request
//     carried. This is the sharpest edge on the seam and the marker gate is
//     what blunts it.
//
//     The adopted password is deliberately not measured against
//     Config.MinPasswordLen. It is an inherited credential rather than one being
//     chosen here, and refusing it would strand the account on the old system
//     for good; Register, ResetPassword and ChangePassword, where a password is
//     actually chosen, all still enforce the length. The one value refused is
//     the empty string: if a verifier answers ok for an empty password the login
//     proceeds, but nothing is written, because a bcrypt hash of "" would make
//     empty-password login succeed forever. An empty password behaves as
//     migrated=false.
//
//   - ok=true, migrated=false: the password, but keep nothing. The login
//     proceeds and the stored hash is left alone, so the next login consults
//     the verifier again. This is for a host that means to keep owning the
//     credential rather than hand this library a copy of it.
//
// Service.ChangePassword — POST /change-password — consults the verifier too,
// the way the login does: a current password that does not verify against the
// stored hash is handed to the verifier, with the same results (a migration
// included), before the new password is written. And with a verifier
// configured it treats an account with no stored hash as one that may have a
// password behind the verifier, so it must present its current password and
// pass it there; only a deployment with no verifier lets an account with no
// hash set its first password without one. On a deployment with a verifier, an
// OAuth-only or magic-link-only account therefore sets its first password
// through POST /forgot-password rather than /change-password, unless the
// verifier answers ok for it.
//
// A non-nil err is a failure to decide, not a rejection: the old system was
// unreachable, the call timed out, the answer did not parse. The login fails
// closed on it and ok is ignored.
//
// The call is made on the request goroutine, inside the login, so a verifier
// that talks to the network must honour ctx and bound its own time.
type PasswordVerifier func(ctx context.Context, user User, password string) (ok bool, migrated bool, err error)

// verifyThroughPasswordVerifier is the branch loginPassword takes when the
// stored hash did not verify the supplied password. It returns the user to
// carry the login on with, or the error that is the login's answer.
//
// Three properties it holds, each pinned by a test:
//
//   - A user whose local hash verified never gets here. The only caller reaches
//     this after verifyPassword has already said no, so a migrated account stops
//     consulting the old system the moment its new hash lands, and a deployment
//     that has finished migrating pays nothing per login.
//   - A rejection is ErrInvalidCredentials: the identical sentinel, and so the
//     identical 401 body, that an ordinary bad password produces, whether a
//     verifier ran and said no or none was configured at all.
//   - Every failure - the verifier returning an error, the hash not being
//     computable, the store refusing the write or not being a UserPasswordStore
//     at all - comes back as an opaque error, which HTTPErrorFor maps through
//     its default to HTTPErrInternal, the generic 500. The wrapping is %v and
//     not %w on purpose: %w would let a store that returns, say,
//     ErrFeatureNotSupported reach errors.Is inside HTTPErrorFor and turn that
//     one branch into a distinguishable 501 NOT_IMPLEMENTED, which is precisely
//     the leak this promises not to have.
//
// The one exception to the %v rule is ctx: a verifier that comes back with
// context.Canceled or context.DeadlineExceeded is wrapped with %w, because
// neither is a sentinel HTTPErrorFor maps - both fall to its default, the same
// generic 500 - so nothing is leaked by keeping them, and a caller or a log
// that cannot tell "the client hung up" from "the legacy provider is broken"
// is worse off for no gain. Since the wire answer never names a branch, each
// failure is also handed to Config.Logger on the way out, which is the only
// place an operator behind any of the four adapters can learn what went wrong.
//
// On timing, what is true is narrower than "unchanged". The seam adds no
// equalisation and removes none: the login path did not equalise before it - an
// address the store does not hold returns at login_2fa.go:108-110 before any
// bcrypt work, while a known address pays one bcrypt compare - and it does not
// equalise now. But a configured verifier widens that pre-existing gap by its
// own latency. A known address whose hash does not verify now costs the bcrypt
// compare plus whatever the verifier does, which in the case this seam exists
// for is a call to the old provider, so a signal that was milliseconds of key
// derivation becomes a network round trip, on an unauthenticated route. The
// marker gate the PasswordVerifier doc requires is what keeps that cost to the
// accounts actually being migrated; equalising what is left is the verifier's
// own job, not this library's. None of this paragraph is asserted by a test: it
// is a statement of posture, not a pinned property.
//
// Where the write sits. It happens here, as part of accepting the credential,
// and therefore before loginPassword applies the email-verification gate. That
// is deliberate: the credential has been proven at this point, the stored hash
// it becomes is a hash of the very password that was proven, and an account
// that is then refused for an unverified address should still have stopped
// depending on the old system. The alternative - migrating only on a login that
// completes - keeps an unverified account calling the old provider forever,
// which is the dependency this seam exists to end.
func (s *Service) verifyThroughPasswordVerifier(ctx context.Context, user User, password string) (User, error) {
	verify := s.cfg.PasswordVerifier
	if verify == nil {
		return User{}, ErrInvalidCredentials
	}
	ok, migrated, err := verify(ctx, user, password)
	if err != nil {
		s.logf("auth: password verifier failed for user %q; the login answers a generic 500: %v", user.ID, err)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return User{}, fmt.Errorf("auth: password verifier: %w", err)
		}
		return User{}, fmt.Errorf("auth: password verifier: %v", err)
	}
	if !ok {
		return User{}, ErrInvalidCredentials
	}
	// Nothing to adopt: either the verifier means to keep owning the credential,
	// or the credential is the empty string, which is never written. See the
	// migrated=true result on PasswordVerifier for why.
	if !migrated || password == "" {
		return user, nil
	}
	ps, supported := s.users.(UserPasswordStore)
	if !supported {
		s.logf("auth: password verifier asked to migrate the password of user %q, but the "+
			"configured user store is not a UserPasswordStore; the login answers a generic 500", user.ID)
		return User{}, errors.New("auth: password verifier asked to migrate a password, but the configured user store is not a UserPasswordStore")
	}
	hash, err := hashPassword(password, s.cfg.BcryptCost)
	if err != nil {
		s.logf("auth: password verifier migration could not hash the password of user %q; "+
			"the login answers a generic 500: %v", user.ID, err)
		return User{}, fmt.Errorf("auth: password verifier migration: %v", err)
	}
	if err := ps.UpdatePassword(ctx, user.ID, user.TenantID, hash); err != nil {
		s.logf("auth: password verifier migration could not store the password of user %q; "+
			"the login answers a generic 500: %v", user.ID, err)
		return User{}, fmt.Errorf("auth: password verifier migration: %v", err)
	}
	// Carry the new hash on the value the login goes on to use, so that anything
	// downstream reading it sees what the store now holds rather than the marker
	// that was just replaced.
	user.PasswordHash = hash
	return user, nil
}
