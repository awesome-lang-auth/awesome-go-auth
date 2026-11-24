package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The lifetime of the enrolment token a 2FA_SETUP_REQUIRED answer carries
// under EnrolOnLogin: Config.EnrolmentTokenTTL (WithEnrolmentTokenTTL) when it
// is set, Config.TempTokenTTL otherwise. What is pinned here: the token's own
// exp carries the lifetime, so a client reading exp - iat shows the right
// window; every use honours it until exp plus ClockSkew and refuses it after;
// a forced enrolment whose secret was answered at the start completes late in
// the window, and not a second past it; zero keeps the earlier lifetime; the
// bounds are refused when the service is built; and the step-up token keeps
// TempTokenTTL whatever the option says.

// enrolmentClock is a service clock held at a whole second and moved by hand.
// A token's iat and exp are whole seconds, so a clock with a fraction would
// move the edge the tests measure.
type enrolmentClock struct{ at time.Time }

func (c *enrolmentClock) now() time.Time { return c.at }

func newEnrolmentClock() (*enrolmentClock, time.Time) {
	start := time.Now().Truncate(time.Second)
	return &enrolmentClock{at: start}, start
}

// enrolmentTTLAuth is New with a mandatory second factor that no account can
// be challenged with — DefaultConfig wires no magic-link or SMS sender — and
// EnrolOnLogin on, so every login of an account without TOTP is answered
// 2FA_SETUP_REQUIRED with an enrolment token. The service reads clock.
func enrolmentTTLAuth(t *testing.T, clock *enrolmentClock, opts ...Option) *Auth {
	t.Helper()
	base := []Option{WithBcryptCost(testBcryptCost), WithRequire2FA(true), WithEnrolOnLogin(true)}
	a, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.service.now = clock.now
	return a
}

// tokenWindow is what a client reads off a token to show how long it has
// left: exp - iat.
func tokenWindow(t *testing.T, token string) time.Duration {
	t.Helper()
	claims := decodeJWTPayload(t, token)
	iat, iatOK := claims["iat"].(float64)
	exp, expOK := claims["exp"].(float64)
	if !iatOK || !expOK {
		t.Fatalf("token carries iat %v and exp %v, want two numbers", claims["iat"], claims["exp"])
	}
	return time.Duration(exp-iat) * time.Second
}

// enrolmentGateRequest is a POST /2fa/setup carrying nothing but what the
// test hands TOTPEnrolmentCaller as the body's tempToken.
func enrolmentGateRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/auth/2fa/setup", nil)
}

// TestEnrolmentTokenTTL_LengthensTheTokenAndItsWindow: with the option the
// token is minted with the lifetime asked for, and every use honours it until
// exp plus ClockSkew — the service call and the gate in front of the two
// enrolment routes alike — and refuses it one second later.
func TestEnrolmentTokenTTL_LengthensTheTokenAndItsWindow(t *testing.T) {
	ctx := context.Background()
	clock, start := newEnrolmentClock()
	a := enrolmentTTLAuth(t, clock, WithEnrolmentTokenTTL(15*time.Minute))
	_, token := setupChallenge(t, a.service, "window@example.com")

	if got := tokenWindow(t, token); got != 15*time.Minute {
		t.Fatalf("enrolment token exp - iat = %s, want 15m0s: the token itself must carry the window a client shows", got)
	}
	if iat := decodeJWTPayload(t, token)["iat"]; iat != float64(start.Unix()) {
		t.Fatalf("iat = %v, want %d: the token was not minted on the test clock", iat, start.Unix())
	}

	skew := a.service.cfg.ClockSkew
	for _, tc := range []struct {
		name    string
		after   time.Duration
		honours bool
	}{
		{"at minute 14", 14 * time.Minute, true},
		{"at exp", 15 * time.Minute, true},
		{"at exp plus ClockSkew", 15*time.Minute + skew, true},
		{"a second past exp plus ClockSkew", 15*time.Minute + skew + time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock.at = start.Add(tc.after)
			_, err := a.VerifyEnrolmentToken(ctx, token)
			caller, herr, ok := a.TOTPEnrolmentCaller(ctx, enrolmentGateRequest(), token)
			if tc.honours {
				if err != nil {
					t.Fatalf("VerifyEnrolmentToken %s after the login = %v, want the token honoured", tc.after, err)
				}
				if !ok || !caller.Forced {
					t.Fatalf("TOTPEnrolmentCaller %s after the login = %+v, %+v, %v, want the forced enrolment", tc.after, caller, herr, ok)
				}
				return
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("VerifyEnrolmentToken %s after the login = %v, want ErrInvalidToken", tc.after, err)
			}
			if ok || herr != HTTPErrInvalidTempToken {
				t.Fatalf("TOTPEnrolmentCaller %s after the login = %+v, %+v, %v, want 401 INVALID_TEMP_TOKEN", tc.after, caller, herr, ok)
			}
		})
	}
}

// TestEnrolmentTokenTTL_ShorterThanTempTokenTTL: a lifetime set below
// TempTokenTTL is the token's lifetime as well. A deployment that shortens
// the enrolment window, two minutes under the default five, gets two minutes:
// the token carries them, every use honours it until exp plus ClockSkew and
// refuses it one second later, the service call and the gate alike, and it
// is refused long before TempTokenTTL. The step-up token keeps its five.
func TestEnrolmentTokenTTL_ShorterThanTempTokenTTL(t *testing.T) {
	ctx := context.Background()
	clock, start := newEnrolmentClock()
	a := enrolmentTTLAuth(t, clock, WithEnrolmentTokenTTL(2*time.Minute))
	if got := a.service.cfg.TempTokenTTL; got != 5*time.Minute {
		t.Fatalf("TempTokenTTL = %s, want the default 5m0s: the case is a lifetime below it", got)
	}
	_, token := setupChallenge(t, a.service, "short@example.com")

	if got := tokenWindow(t, token); got != 2*time.Minute {
		t.Fatalf("enrolment token exp - iat = %s, want 2m0s: a lifetime below TempTokenTTL is the token's too", got)
	}

	skew := a.service.cfg.ClockSkew
	for _, tc := range []struct {
		name    string
		after   time.Duration
		honours bool
	}{
		{"at minute 1", time.Minute, true},
		{"at exp", 2 * time.Minute, true},
		{"at exp plus ClockSkew", 2*time.Minute + skew, true},
		{"a second past exp plus ClockSkew", 2*time.Minute + skew + time.Second, false},
		{"at TempTokenTTL", 5 * time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock.at = start.Add(tc.after)
			_, err := a.VerifyEnrolmentToken(ctx, token)
			caller, herr, ok := a.TOTPEnrolmentCaller(ctx, enrolmentGateRequest(), token)
			if tc.honours {
				if err != nil {
					t.Fatalf("VerifyEnrolmentToken %s after the login = %v, want the token honoured", tc.after, err)
				}
				if !ok || !caller.Forced {
					t.Fatalf("TOTPEnrolmentCaller %s after the login = %+v, %+v, %v, want the forced enrolment", tc.after, caller, herr, ok)
				}
				return
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("VerifyEnrolmentToken %s after the login = %v, want ErrInvalidToken: the token lives 2 minutes, not TempTokenTTL", tc.after, err)
			}
			if ok || herr != HTTPErrInvalidTempToken {
				t.Fatalf("TOTPEnrolmentCaller %s after the login = %+v, %+v, %v, want 401 INVALID_TEMP_TOKEN", tc.after, caller, herr, ok)
			}
		})
	}

	t.Run("the step-up token keeps TempTokenTTL", func(t *testing.T) {
		clock.at = start
		stepUp, err := a.IssueTempToken(ctx, User{ID: "u1", TenantID: "t1", Email: "direct@example.com"})
		if err != nil {
			t.Fatalf("IssueTempToken: %v", err)
		}
		if got := tokenWindow(t, stepUp); got != 5*time.Minute {
			t.Fatalf("IssueTempToken exp - iat = %s, want 5m0s: a shorter enrolment window is not a shorter step-up", got)
		}
	})
}

// TestEnrolmentTokenTTL_ForcedEnrolmentCompletesUntilTheTokenExpires: the
// secret is answered at the start of the window, as an enrolment page asks for
// it before the authenticator app is installed, and the enrolment is
// completed late with that same secret. Nothing the completion depends on
// lapses before the token: at minute 14 of 15 it stores the factor and opens
// the session; a second past 15 minutes plus ClockSkew, with a code that is
// right at that instant, it is refused as an expired token and stores nothing.
func TestEnrolmentTokenTTL_ForcedEnrolmentCompletesUntilTheTokenExpires(t *testing.T) {
	ctx := context.Background()

	t.Run("completed at minute 14 of 15", func(t *testing.T) {
		clock, start := newEnrolmentClock()
		a := enrolmentTTLAuth(t, clock, WithEnrolmentTokenTTL(15*time.Minute))
		user, token := setupChallenge(t, a.service, "minute14@example.com")
		setup, err := a.NewForcedTOTPEnrolment(ctx, token)
		if err != nil {
			t.Fatalf("NewForcedTOTPEnrolment at the start of the window: %v", err)
		}

		clock.at = start.Add(14 * time.Minute)
		_, tokens, err := a.CompleteTOTPEnrolment(ctx, token, setup.Secret, codeFor(t, setup.Secret, clock.at))
		if err != nil {
			t.Fatalf("CompleteTOTPEnrolment at minute 14 of 15 = %v, want the session", err)
		}
		if tokens.AccessToken == "" || tokens.RefreshToken == "" {
			t.Fatalf("tokens = %+v, want a session", tokens)
		}
		stored, err := a.service.users.GetUserByID(ctx, user.ID, user.TenantID)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if !stored.IsTOTPEnabled || stored.TOTPSecret != setup.Secret {
			t.Fatalf("stored TOTP = %v %q, want the secret /2fa/setup answered at minute 0", stored.IsTOTPEnabled, stored.TOTPSecret)
		}
	})

	t.Run("a second past 15 minutes plus ClockSkew", func(t *testing.T) {
		clock, start := newEnrolmentClock()
		a := enrolmentTTLAuth(t, clock, WithEnrolmentTokenTTL(15*time.Minute))
		user, token := setupChallenge(t, a.service, "late@example.com")
		setup, err := a.NewForcedTOTPEnrolment(ctx, token)
		if err != nil {
			t.Fatalf("NewForcedTOTPEnrolment at the start of the window: %v", err)
		}

		clock.at = start.Add(15*time.Minute + a.service.cfg.ClockSkew + time.Second)
		_, tokens, err := a.CompleteTOTPEnrolment(ctx, token, setup.Secret, codeFor(t, setup.Secret, clock.at))
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("CompleteTOTPEnrolment past the window = %v, want ErrInvalidToken (an expired token, not a wrong code)", err)
		}
		if herr := TOTPEnrolmentHTTPError(err); herr != HTTPErrInvalidTempToken {
			t.Fatalf("the route would answer %+v, want 401 INVALID_TEMP_TOKEN", herr)
		}
		if tokens.AccessToken != "" || tokens.RefreshToken != "" {
			t.Fatalf("tokens = %+v, want none", tokens)
		}
		stored, err := a.service.users.GetUserByID(ctx, user.ID, user.TenantID)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if stored.IsTOTPEnabled || stored.TOTPSecret != "" {
			t.Fatalf("stored TOTP = %v %q, want nothing enrolled by an expired token", stored.IsTOTPEnabled, stored.TOTPSecret)
		}
		if _, err := a.NewForcedTOTPEnrolment(ctx, token); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("NewForcedTOTPEnrolment past the window = %v, want ErrInvalidToken", err)
		}
	})
}

// TestEnrolmentTokenTTL_InvitationAcceptance: the acceptance of an invitation
// under a mandatory second factor answers 2FA_SETUP_REQUIRED with the same
// enrolment token the login mints, so the option reaches it too — the case of
// an invitee who chooses a password and then installs an authenticator app.
func TestEnrolmentTokenTTL_InvitationAcceptance(t *testing.T) {
	ctx := context.Background()
	f := newInvitationFixture(t, WithRequire2FA(true), WithEnrolOnLogin(true), WithEnrolmentTokenTTL(15*time.Minute))
	clock, start := newEnrolmentClock()
	f.svc().now = clock.now

	result := f.invite(invitedEmail)
	acceptance, err := f.accept(result.Token, "a-new-password")
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	challenge := acceptance.Challenge
	if challenge == nil || !challenge.SetupRequired || challenge.TempToken == "" {
		t.Fatalf("challenge = %+v, want 2FA_SETUP_REQUIRED with a token", challenge)
	}
	if got := tokenWindow(t, challenge.TempToken); got != 15*time.Minute {
		t.Fatalf("the acceptance's enrolment token exp - iat = %s, want 15m0s", got)
	}

	clock.at = start.Add(time.Minute)
	setup, err := f.auth.NewForcedTOTPEnrolment(ctx, challenge.TempToken)
	if err != nil {
		t.Fatalf("NewForcedTOTPEnrolment at minute 1: %v", err)
	}
	clock.at = start.Add(14 * time.Minute)
	if _, tokens, err := f.auth.CompleteTOTPEnrolment(ctx, challenge.TempToken, setup.Secret, codeFor(t, setup.Secret, clock.at)); err != nil || tokens.AccessToken == "" {
		t.Fatalf("CompleteTOTPEnrolment at minute 14 = %+v, %v, want the session", tokens, err)
	}
}

// TestEnrolmentTokenTTL_ZeroKeepsTempTokenTTL: unset — DefaultConfig's zero,
// or WithEnrolmentTokenTTL(0) — the enrolment token lives TempTokenTTL, as it
// did before the option existed: 5 minutes by default, and whatever
// TempTokenTTL a deployment set otherwise.
func TestEnrolmentTokenTTL_ZeroKeepsTempTokenTTL(t *testing.T) {
	ctx := context.Background()
	if got := DefaultConfig(testSecret).EnrolmentTokenTTL; got != 0 {
		t.Fatalf("DefaultConfig EnrolmentTokenTTL = %s, want 0: unset is TempTokenTTL", got)
	}

	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{"unset", nil},
		{"WithEnrolmentTokenTTL(0)", []Option{WithEnrolmentTokenTTL(0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock, start := newEnrolmentClock()
			a := enrolmentTTLAuth(t, clock, tc.opts...)
			_, token := setupChallenge(t, a.service, "default@example.com")
			if got := tokenWindow(t, token); got != 5*time.Minute {
				t.Fatalf("enrolment token exp - iat = %s, want 5m0s, TempTokenTTL's default", got)
			}
			skew := a.service.cfg.ClockSkew
			clock.at = start.Add(5*time.Minute + skew)
			if _, err := a.VerifyEnrolmentToken(ctx, token); err != nil {
				t.Fatalf("VerifyEnrolmentToken at exp plus ClockSkew = %v, want the token honoured", err)
			}
			clock.at = start.Add(5*time.Minute + skew + time.Second)
			if _, err := a.VerifyEnrolmentToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("VerifyEnrolmentToken a second past 5 minutes plus ClockSkew = %v, want ErrInvalidToken", err)
			}
		})
	}

	t.Run("a TempTokenTTL of the deployment's own", func(t *testing.T) {
		cfg := DefaultConfig(testSecret)
		cfg.BcryptCost = testBcryptCost
		cfg.Require2FA = true
		cfg.EnrolOnLogin = true
		cfg.TempTokenTTL = 7 * time.Minute
		a, err := NewWithConfig(cfg)
		if err != nil {
			t.Fatalf("NewWithConfig: %v", err)
		}
		_, token := setupChallenge(t, a.service, "custom@example.com")
		if got := tokenWindow(t, token); got != 7*time.Minute {
			t.Fatalf("enrolment token exp - iat = %s, want 7m0s, the deployment's TempTokenTTL", got)
		}
	})
}

// TestEnrolmentTokenTTL_BoundsAreRefusedAtNew: a lifetime under a minute or
// over thirty, a negative one included, makes New, NewWithConfig and
// NewService refuse the configuration with an error that names the field's
// bounds; zero and both bounds themselves are accepted.
func TestEnrolmentTokenTTL_BoundsAreRefusedAtNew(t *testing.T) {
	for _, d := range []time.Duration{
		-time.Minute, time.Nanosecond, 59 * time.Second, time.Minute - time.Nanosecond,
		30*time.Minute + time.Nanosecond, 31 * time.Minute, time.Hour,
	} {
		t.Run("refused "+d.String(), func(t *testing.T) {
			_, err := New(WithEnrolmentTokenTTL(d))
			if err == nil {
				t.Fatalf("New(WithEnrolmentTokenTTL(%s)) = nil error, want the configuration refused", d)
			}
			for _, want := range []string{"enrolment token ttl", "1m0s", "30m0s", d.String()} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("New(WithEnrolmentTokenTTL(%s)) error %q does not name %q", d, err, want)
				}
			}
			cfg := DefaultConfig(testSecret)
			cfg.EnrolmentTokenTTL = d
			if _, err := NewWithConfig(cfg); err == nil {
				t.Errorf("NewWithConfig with EnrolmentTokenTTL %s = nil error, want the configuration refused", d)
			}
			if _, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore()); err == nil {
				t.Errorf("NewService with EnrolmentTokenTTL %s = nil error, want the configuration refused", d)
			}
		})
	}
	for _, d := range []time.Duration{0, time.Minute, 15 * time.Minute, 30 * time.Minute} {
		if _, err := New(WithEnrolmentTokenTTL(d)); err != nil {
			t.Errorf("New(WithEnrolmentTokenTTL(%s)) = %v, want it accepted", d, err)
		}
	}
}

// TestEnrolmentTokenTTL_LeavesTheStepUpTokenAlone: the option is the
// enrolment token's alone. The step-up token of an account with a factor, the
// one IssueTempToken mints, and the setup-required token without EnrolOnLogin
// — which is the step-up token — all keep TempTokenTTL, and are refused once
// it and ClockSkew have passed.
func TestEnrolmentTokenTTL_LeavesTheStepUpTokenAlone(t *testing.T) {
	ctx := context.Background()

	t.Run("the challenge of an account with a factor", func(t *testing.T) {
		clock, start := newEnrolmentClock()
		a := enrolmentTTLAuth(t, clock, WithEnrolmentTokenTTL(15*time.Minute))
		user, _, err := a.service.Register(ctx, RegisterInput{Email: "stepup@example.com", Password: "password1", TenantID: "t1"})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		secret := mustSecret(t)
		if err := a.service.VerifyTOTPSetup(ctx, user.ID, user.TenantID, secret, codeFor(t, secret, clock.at)); err != nil {
			t.Fatalf("enrol TOTP: %v", err)
		}
		result, err := a.LoginWithChallenge(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: "t1"})
		if err != nil || result.Challenge == nil || result.Challenge.SetupRequired {
			t.Fatalf("login = %+v, %v, want a step-up challenge", result, err)
		}
		stepUp := result.Challenge.TempToken
		if got := tokenWindow(t, stepUp); got != 5*time.Minute {
			t.Fatalf("step-up token exp - iat = %s, want 5m0s, TempTokenTTL: the option is the enrolment token's alone", got)
		}
		clock.at = start.Add(5*time.Minute + a.service.cfg.ClockSkew + time.Second)
		if _, err := a.service.VerifyTempToken(stepUp); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("VerifyTempToken a second past 5 minutes plus ClockSkew = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("IssueTempToken", func(t *testing.T) {
		clock, _ := newEnrolmentClock()
		a := enrolmentTTLAuth(t, clock, WithEnrolmentTokenTTL(30*time.Minute))
		token, err := a.IssueTempToken(ctx, User{ID: "u1", TenantID: "t1", Email: "direct@example.com"})
		if err != nil {
			t.Fatalf("IssueTempToken: %v", err)
		}
		if got := tokenWindow(t, token); got != 5*time.Minute {
			t.Fatalf("IssueTempToken exp - iat = %s, want 5m0s", got)
		}
	})

	t.Run("the setup-required token without EnrolOnLogin", func(t *testing.T) {
		a, err := New(WithBcryptCost(testBcryptCost), WithRequire2FA(true), WithEnrolmentTokenTTL(15*time.Minute))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, token := setupChallenge(t, a.service, "noenrol@example.com")
		if got := tokenWindow(t, token); got != 5*time.Minute {
			t.Fatalf("setup-required token without EnrolOnLogin exp - iat = %s, want 5m0s: it is the step-up token", got)
		}
		if _, err := a.service.VerifyTempToken(token); err != nil {
			t.Fatalf("VerifyTempToken = %v, want the step-up token it always was", err)
		}
	})
}
