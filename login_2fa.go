package auth

import (
	"context"
	"net/http"
	"strings"
)

// This file holds the second-factor branch of POST /login: the answer that hands
// a client the step-up token every route in wire-contract §3 asks for.
//
// Before it, Service.Login answered a 2FA-gated account with
// ErrTwoFactorRequired and nothing else, which HTTPErrorFor spells
// 403 {"error":"Two-factor authentication required","code":"2FA_REQUIRED"}. That
// body carries no tempToken, and /2fa/verify plus /sms/{send,verify} and
// /magic-link/{send,verify} in mode:"2fa" all need one — so the entire step-up
// half of the contract was unreachable over HTTP even though those routes were
// implemented and tested. The tests minted their own tempToken, which is why the
// gap survived (issue #42).
//
// Why the challenge does not travel in the HTTPError envelope. Two reasons, and
// the first settles it on its own:
//
//   - It is not an error. The reference answers the challenge
//     200 {"requiresTwoFactor":true,"tempToken":"<jwt>","available2faMethods":[…]}
//     (auth.router.ts:572-577) — no "error" member, no "code", and the identical
//     body in bearer and cookie mode because no session exists yet. The 403 this
//     port used to send was a deviation, and a recorded one:
//     docs/spec/parity-gap-node-vs-go.md row 1 marks local login "diverges" and
//     names the missing challenge. Its sibling branch is a 403 but is equally not
//     the envelope: {"requires2FASetup":true,"tempToken":"<jwt>",
//     "code":"2FA_SETUP_REQUIRED"} (:568) carries a code and no message.
//   - HTTPError is shared by every route in the package. Widening it would put
//     two more `omitempty` members on all thirty-odd catalog entries for the sake
//     of one branch, and a []string member would make HTTPError non-comparable —
//     wire_test.go keys a map on the value and TestErrorMapping compares entries
//     with ==, so the catalog is comparable by design, not by accident.
//
// So the two bodies are written directly, by WriteTwoFactorChallenge, and
// HTTPErrTwoFactorRequired stays in the catalog for a direct Service.Login caller
// that surfaces the sentinel through WriteServiceError.

// Second-factor method names, exactly as the reference spells them in
// available2faMethods (auth.router.ts:557-559). A client picks its next request
// from this list, so these strings are wire: "magic-link" is hyphenated and
// nothing is capitalised.
const (
	TwoFactorMethodTOTP      = "totp"
	TwoFactorMethodSMS       = "sms"
	TwoFactorMethodMagicLink = "magic-link"
)

// CodeTwoFactorSetupRequired tells a client that a second factor is demanded of
// this account and it has none to present, so enrolment has to come first. It is
// declared here rather than in wire.go's catalog because the body it appears in
// is not the error envelope — see WriteTwoFactorChallenge — and because
// passwordless.go sets the precedent of a feature file owning its own codes.
const CodeTwoFactorSetupRequired = "2FA_SETUP_REQUIRED"

// TwoFactorChallenge is what POST /login answers a user who has a second factor:
// the step-up token, and the factors they can actually present it with.
//
// It carries what goes on the wire and nothing else, for the reason
// MagicLinkDelivery carries so little (delivery.go): the token is a credential,
// and a value that also held the User would hand a password hash and a TOTP
// secret to anything that logs a challenge.
type TwoFactorChallenge struct {
	// TempToken is the step-up credential the §3 routes accept. It is typed
	// tokenTypeTemp, so unlike the reference's it is not also an access token —
	// see the tokenTypeTemp comment for why that deliberate difference is kept.
	TempToken string
	// Methods is available2faMethods: the factors this user can use, in the
	// reference's order. It is empty only when SetupRequired is set.
	Methods []string
	// SetupRequired selects the second of the reference's two branches: a policy
	// demands a second factor and the account has no method at all, so the client
	// must enrol one before it can be challenged.
	SetupRequired bool
}

// LoginResult is the outcome of a password login: either a session, or a
// second-factor challenge.
type LoginResult struct {
	// User is whose password verified. It is populated on both outcomes, because
	// on both outcomes the password did verify and a host that audit-logs a
	// challenge has to know whose it was.
	User User
	// Tokens is the issued session. It is zero when Challenge is set: a challenge
	// is not a login, and no session exists until the second factor lands.
	Tokens AuthTokens
	// Challenge is nil for a login that completed.
	Challenge *TwoFactorChallenge
}

// loginPassword is the part of POST /login the two entry points share: it
// verifies the credentials and reports whether a second factor is demanded. It
// mints nothing.
//
// The split is what makes "a second factor is needed" reachable without a
// token. Service.Login promises that decision as ErrTwoFactorRequired, and if it
// could only learn it from a successfully built challenge then a deployment whose
// Config.BuildTokenClaims hook fails (token.go:66-71 wraps that as an ordinary
// error) would get a generic 500 out of the compatibility wrapper where it used
// to get 403 2FA_REQUIRED — the one thing this PR promised not to change.
func (s *Service) loginPassword(ctx context.Context, in LoginInput) (User, bool, error) {
	// The address as the caller sent it, kept before normalisation because the
	// failure event carries the submitted value rather than the looked-up one:
	// the dev line puts `req.body.email` on the payload untouched (node-auth
	// auth.router.ts:657). A client that sent "  Ada@Example.COM " is reported
	// as having sent that, which is what makes the event useful for spotting a
	// client that is mangling addresses.
	submitted := in.Email
	in.Email = normalizeEmail(in.Email)
	user, err := s.users.GetUserByEmail(ctx, in.Email, in.TenantID)
	if err != nil {
		return User{}, false, s.loginFailed(ctx, submitted, ErrInvalidCredentials)
	}
	// Config.PasswordVerifier, the migration seam, is consulted here and nowhere
	// else: only after the stored hash has failed to verify what the request
	// carried. A user whose local hash verifies never reaches it. A lookup miss
	// does not either — the seam takes a User, and provisioning an account this
	// store has never heard of is a different job from migrating one it has.
	//
	// Everything else does, and that is wider than the imported row the seam was
	// built for. An empty stored hash is a non-match, not a match (verifyPassword
	// of anything against "" is a bcrypt error), so every account that never had
	// a password — OAuth-only, magic-link-only — reaches the hook as well, with
	// whatever plaintext the request carried; the reference refuses those before
	// it compares anything (local.strategy.ts:23-25). A verifier must therefore
	// key on its own migration marker before it does anything with the password
	// it is handed, and a rewritten hash here replaces whatever was stored, not
	// only an absent one.
	//
	// With no verifier configured this collapses back to ErrInvalidCredentials,
	// the answer the line above always gave. See password_verifier.go for the
	// whole seam, including why a failure here is a generic 500 rather than
	// anything a client could tell apart.
	if !verifyPassword(in.Password, user.PasswordHash) {
		user, err = s.verifyThroughPasswordVerifier(ctx, user, in.Password)
		if err != nil {
			return User{}, false, s.loginFailed(ctx, submitted, err)
		}
	}
	if s.emailVerificationBlocksLogin(user) {
		return User{}, false, s.loginFailed(ctx, submitted, ErrEmailNotVerified)
	}
	return user, s.requiresTwoFactor(user), nil
}

// loginFailed raises identity.auth.login.failed for a refused password login
// and returns err unchanged, so that each refusal above stays one line and none
// of them can be added later without it.
//
// It is the dev line's only publication inside a catch, and the only one with a
// condition attached: `if (err instanceof AuthError && err.statusCode === 401)`
// (node-auth auth.router.ts:655). What throws a 401 there is
// LocalStrategy.authenticate, for an unknown address, an account with no stored
// password, and a password that does not verify (node-auth
// local.strategy.ts:20-29). What does not is its unverified-address refusal,
// which is a 403 (node-auth local.strategy.ts:40) — and neither is a store that
// is simply broken, which reaches handleError as a 500. A publication that
// fired for those would be saying something else entirely: an infrastructure
// outage would read as a wave of credential-stuffing.
//
// The gate is asked of HTTPErrorFor rather than written out as a list of
// sentinels, because HTTPErrorFor is already this port's answer to "what status
// is this error" and a list here could disagree with it. ErrInvalidCredentials
// is the 401; ErrEmailNotVerified maps to 403; a Config.PasswordVerifier that
// failed is an ordinary error and falls through to HTTPErrInternal. Each of
// those is then exactly the dev line's treatment of the same case.
//
// No user id, even where one is in hand — the lookup may well have succeeded
// and only the password failed. The dev line passes none (node-auth
// auth.router.ts:657-659), and the reason survives the port: the event reports
// that an address was refused, and naming the account behind it would turn any
// subscriber's log into an oracle for which addresses are registered.
func (s *Service) loginFailed(ctx context.Context, submittedEmail string, err error) error {
	if HTTPErrorFor(err).Status != http.StatusUnauthorized {
		return err
	}
	s.publish(ctx, func() Event {
		return Event{
			Name: EventAuthLoginFailed,
			Data: map[string]any{"method": loginMethodLocal, "email": submittedEmail},
		}
	})
	return err
}

// LoginWithChallenge is the full POST /login path: it verifies the password and
// then either issues a session or mints the step-up challenge.
//
// Service.Login is the narrower form of the same call, kept for direct callers:
// it collapses a challenge back into ErrTwoFactorRequired, which says a second
// factor is needed and cannot say anything more.
//
// A challenge that cannot be minted is returned as the error, not as a challenge
// with an empty TempToken and not as ErrTwoFactorRequired. This call's whole
// point is the token: a client handed a challenge without one would believe it
// had a step-up credential and be refused by every §3 route, and the sentinel
// would spell the 403 2FA_REQUIRED body this PR removed from /login — a wire
// answer no longer served on this route, telling the client to step up with a
// token it was never given. So the failure surfaces: HTTPErrorFor maps it to
// HTTPErrInternal (wire.go:172-173), which is what a broken host hook is.
func (s *Service) LoginWithChallenge(ctx context.Context, in LoginInput) (LoginResult, error) {
	var zero LoginResult
	user, secondFactor, err := s.loginPassword(ctx, in)
	if err != nil {
		return zero, err
	}
	// Only here, below both gates, is a step-up token minted. Anywhere earlier —
	// on a lookup hit, or before verifyPassword returns — and /login becomes an
	// oracle that hands a step-up credential to whoever guesses an address, and
	// that credential stands in for the password on every route in §3.
	if secondFactor {
		challenge, err := s.twoFactorChallenge(ctx, user)
		if err != nil {
			return zero, err
		}
		return LoginResult{User: user, Challenge: challenge}, nil
	}
	tokens, err := s.completeLocalLogin(ctx, user)
	if err != nil {
		return zero, err
	}
	return LoginResult{User: user, Tokens: tokens}, nil
}

// twoFactorChallenge mints the challenge for a user whose password has already
// verified. It is unexported because it takes no password: the only correct
// caller is the one above it.
func (s *Service) twoFactorChallenge(ctx context.Context, user User) (*TwoFactorChallenge, error) {
	methods := s.availableTwoFactorMethods(user)
	// Both reference branches mint the same token with the same overridden
	// expiries (auth.router.ts:564-567 and :572-575), so it is minted once here.
	token, err := s.IssueTempToken(ctx, user)
	if err != nil {
		return nil, err
	}
	return &TwoFactorChallenge{TempToken: token, Methods: methods, SetupRequired: len(methods) == 0}, nil
}

// availableTwoFactorMethods lists the factors this user can present, in the
// reference's order (auth.router.ts:556-559).
//
// Note what each entry is conditioned on there. TOTP is per-user; SMS is
// per-user (a stored number) and per-deployment (config.sms); magic-link is
// per-deployment only (config.email.sendMagicLink || config.email.mailer). So a
// deployment that can send mail offers magic-link to every challenged user, and
// the port keeps that: it is the sender on Config that decides, exactly as
// Auth.SMSConfigured decides for /sms/send.
//
// Two things this deliberately does not check:
//
//   - A verified address is not required for magic-link. The reference does not
//     check one (:559), the step-up branch of /magic-link/verify does not either
//     (Service.VerifyMagicLink applies the verification side effect only on the
//     login path), and login has already refused an unverified user above unless
//     the deployment runs in lazy mode. Requiring one here would advertise fewer
//     methods than the routes accept.
//   - Config.Require2FA is not consulted. It is the trigger for a challenge, not
//     a method, and asking it here would advertise a factor nobody enrolled.
//
// The store-capability assertions have no counterpart in the reference, whose
// user store is one interface. They are this port's version of the same
// question — is this method wired up at all — and they only ever narrow the
// list: without them a deployment whose store cannot hold a magic-link token
// would advertise magic-link and answer 501 NOT_IMPLEMENTED when the client took
// it up.
func (s *Service) availableTwoFactorMethods(user User) []string {
	methods := make([]string, 0, 3)
	if user.IsTOTPEnabled && strings.TrimSpace(user.TOTPSecret) != "" {
		methods = append(methods, TwoFactorMethodTOTP)
	}
	// Untrimmed, as the reference tests it (`if (user.phoneNumber && config.sms)`,
	// auth.router.ts:1015 at v1.10.8), and as /sms/send and Service.SendSMSCode do.
	if _, ok := s.users.(SMSStore); ok && s.cfg.SendSMSCode != nil && user.PhoneNumber != "" {
		methods = append(methods, TwoFactorMethodSMS)
	}
	if _, ok := s.users.(MagicLinkStore); ok && s.cfg.SendMagicLink != nil {
		methods = append(methods, TwoFactorMethodMagicLink)
	}
	return methods
}

// LoginWithChallenge delegates to Service.LoginWithChallenge. It is what the
// adapters call, so that a 2FA-gated account is answered with the challenge
// rather than with the bare sentinel.
func (a *Auth) LoginWithChallenge(ctx context.Context, in LoginInput) (LoginResult, error) {
	return a.service.LoginWithChallenge(ctx, in)
}

// The two challenge bodies. They are structs rather than maps so the member set
// is fixed at compile time: a client keys on requiresTwoFactor / requires2FASetup
// to tell the branches apart, and the two share only tempToken.
type twoFactorChallengeBody struct {
	RequiresTwoFactor bool     `json:"requiresTwoFactor"`
	TempToken         string   `json:"tempToken"`
	Methods           []string `json:"available2faMethods"`
}

type twoFactorSetupBody struct {
	Requires2FASetup bool   `json:"requires2FASetup"`
	TempToken        string `json:"tempToken"`
	Code             string `json:"code"`
}

// WriteTwoFactorChallenge writes the login challenge as the entire response body.
//
// No cookie is set on either branch, in either delivery mode: nothing has been
// issued yet, so there is nothing to deliver. That is the reference's behaviour
// too — the 2FA branch returns before issueTokens is ever reached
// (auth.router.ts:571-578 precedes :580-581).
func WriteTwoFactorChallenge(w http.ResponseWriter, challenge TwoFactorChallenge) {
	if challenge.SetupRequired {
		WriteJSON(w, http.StatusForbidden, twoFactorSetupBody{
			Requires2FASetup: true,
			TempToken:        challenge.TempToken,
			Code:             CodeTwoFactorSetupRequired,
		})
		return
	}
	methods := challenge.Methods
	if methods == nil {
		// encoding/json renders a nil slice as null, and a client iterating
		// available2faMethods must never be handed one.
		methods = []string{}
	}
	WriteJSON(w, http.StatusOK, twoFactorChallengeBody{
		RequiresTwoFactor: true,
		TempToken:         challenge.TempToken,
		Methods:           methods,
	})
}
