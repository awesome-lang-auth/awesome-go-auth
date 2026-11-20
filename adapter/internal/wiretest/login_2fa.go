package wiretest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// errClaimsHookDown is what a host's Config.BuildTokenClaims returns in the mint
// failure cases below. Its identity never reaches the wire — HTTPErrInternal
// carries neither a code nor the underlying error (wire.go) — so the cases match
// on the envelope, not on this text.
var errClaimsHookDown = errors.New("claims hook down")

// Conformance cases for the second-factor branch of POST /login: wire-contract
// §3.1, the challenge that hands a client the tempToken every step-up route
// needs.
//
// These cases exist because the ones in passwordless.go could not have caught
// issue #42. They mint their tempToken with tempTokenFor, which calls
// Auth.IssueTempToken directly — so every step-up route was pinned against a
// token no HTTP client could ever have obtained, and /login answering
// 403 2FA_REQUIRED with an empty-handed body passed the whole suite. Nothing
// below mints a token: each case logs in over HTTP and reads the tempToken out of
// the login response, so the path a real client walks is the path under test.

// challengeOpts is the delivery configuration of a challenge env.
//
// available2faMethods is per-deployment for two of its three entries — sms needs
// a configured sender as well as a stored number, magic-link needs only the
// sender — so a case that asserts the list exactly has to control which senders
// exist. NewEnv wires both, which is right for the send routes and wrong here.
type challengeOpts struct {
	sms  bool
	mail bool
}

// challengeEnv builds an env with exactly the senders challengeOpts names, plus
// whatever opts add. Env.Delivered records what those senders received, so the
// step-up drive below can read the SMS code and the magic-link token out of it.
func challengeEnv(t *testing.T, mount Mounter, which challengeOpts, opts ...auth.Option) *Env {
	t.Helper()
	delivered := &Deliveries{}
	var senders []auth.Option
	if which.mail {
		senders = append(senders, auth.WithMagicLinkSender(func(_ context.Context, d auth.MagicLinkDelivery) error {
			delivered.MagicLinks = append(delivered.MagicLinks, d)
			return nil
		}))
	}
	if which.sms {
		senders = append(senders, auth.WithSMSCodeSender(func(_ context.Context, d auth.SMSCodeDelivery) error {
			delivered.SMSCodes = append(delivered.SMSCodes, d)
			return nil
		}))
	}
	env := newEnv(t, mount, auth.DefaultHTTPConfig(), append(senders, opts...)...)
	env.Delivered = delivered
	return env
}

// loginChallenge logs in over HTTP and returns the challenge body, asserting the
// wire shape of it: 200, exactly the three members the reference sends, and no
// auth cookie — nothing has been issued yet, so there is nothing to deliver.
//
// The returned tempToken is the only one any case below uses.
func loginChallenge(t *testing.T, env *Env, email string) (string, []string) {
	t.Helper()
	rec := env.Do(env.Request(http.MethodPost, "/login", credentials(email)))

	AssertStatus(t, rec, http.StatusOK)
	body := Body(t, rec)
	AssertKeys(t, body, "requiresTwoFactor", "tempToken", "available2faMethods")
	if body["requiresTwoFactor"] != true {
		t.Fatalf("requiresTwoFactor = %v", body["requiresTwoFactor"])
	}
	// No session was created, so no session credential may be delivered — in
	// either mode. The CSRF cookie is a different thing and the middleware
	// distributes it on every response.
	AssertNoCookie(t, rec, hostAccess)
	AssertNoCookie(t, rec, hostRefresh)

	tempToken, _ := body["tempToken"].(string)
	if strings.TrimSpace(tempToken) == "" {
		t.Fatal("the challenge carried no tempToken: no client can complete the second factor")
	}
	raw, ok := body["available2faMethods"].([]any)
	if !ok {
		t.Fatalf("available2faMethods = %#v, want an array", body["available2faMethods"])
	}
	methods := make([]string, 0, len(raw))
	for _, m := range raw {
		s, _ := m.(string)
		methods = append(methods, s)
	}
	return tempToken, methods
}

func assertMethods(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("available2faMethods = %v, want %v", got, want)
	}
}

// enrolledTOTPEnv seeds a user, enrols TOTP over HTTP and returns the secret.
//
// Enrolment goes through Seed's tokens rather than through a login, because after
// the first enrolment — and always, under a system-wide policy — /login no longer
// completes. Register is not gated on a second factor in either implementation.
func enrolledTOTPEnv(t *testing.T, env *Env, email string) string {
	t.Helper()
	_, tokens := env.Seed(email)
	return enrolTOTP(t, env, tokens.AccessToken)
}

func testLoginTwoFactor(t *testing.T, mount Mounter) {
	// ── the end-to-end paths ────────────────────────────────────────────────────

	t.Run("a TOTP account completes /2fa/verify with the token login gave it", func(t *testing.T) {
		env := challengeEnv(t, mount, challengeOpts{})
		secret := enrolledTOTPEnv(t, env, "e2etotp@example.com")

		tempToken, methods := loginChallenge(t, env, "e2etotp@example.com")
		assertMethods(t, methods, auth.TwoFactorMethodTOTP)

		rec := env.Do(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": tempToken, "totpCode": totpCode(t, secret, time.Now()),
		}))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
	})

	t.Run("a bearer client completes the same challenge and is handed tokens", func(t *testing.T) {
		env := challengeEnv(t, mount, challengeOpts{})
		secret := enrolledTOTPEnv(t, env, "e2ebearer@example.com")

		// The challenge itself is identical in bearer mode: no session exists, so
		// there is nothing for the delivery switch to switch on.
		req := env.Request(http.MethodPost, "/login", credentials("e2ebearer@example.com"))
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		login := env.Do(req)
		AssertStatus(t, login, http.StatusOK)
		body := Body(t, login)
		AssertKeys(t, body, "requiresTwoFactor", "tempToken", "available2faMethods")
		AssertNoCookies(t, login)
		tempToken, _ := body["tempToken"].(string)

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": tempToken, "totpCode": totpCode(t, secret, time.Now()),
		}), ""))
		AssertStatus(t, rec, http.StatusOK)
		verified := Body(t, rec)
		AssertKeys(t, verified, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, verified, "accessToken")
		AssertNoCookies(t, rec)
	})

	t.Run("an SMS account completes /sms/send and /sms/verify in mode 2fa", func(t *testing.T) {
		store := phoneUserStore{MemoryUserStore: auth.NewMemoryUserStore(), phone: "+15555550142"}
		env := challengeEnv(t, mount, challengeOpts{sms: true},
			auth.WithUserStore(store), auth.WithRequire2FA(true))
		env.Seed("e2esms@example.com")

		tempToken, methods := loginChallenge(t, env, "e2esms@example.com")
		assertMethods(t, methods, auth.TwoFactorMethodSMS)

		send := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"mode": auth.StepUpMode, "tempToken": tempToken,
		}))
		AssertStatus(t, send, http.StatusOK)
		AssertKeys(t, Body(t, send), "success")
		if len(env.Delivered.SMSCodes) != 1 {
			t.Fatalf("deliveries = %d, want 1", len(env.Delivered.SMSCodes))
		}

		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"mode": auth.StepUpMode, "tempToken": tempToken, "code": env.Delivered.SMSCodes[0].Code,
		}))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
	})

	t.Run("a magic-link account completes /magic-link/send and /magic-link/verify in mode 2fa", func(t *testing.T) {
		env := challengeEnv(t, mount, challengeOpts{mail: true}, auth.WithRequire2FA(true))
		env.Seed("e2emagic@example.com")

		tempToken, methods := loginChallenge(t, env, "e2emagic@example.com")
		assertMethods(t, methods, auth.TwoFactorMethodMagicLink)

		send := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"mode": auth.StepUpMode, "tempToken": tempToken,
		}))
		AssertStatus(t, send, http.StatusOK)
		AssertKeys(t, Body(t, send), "success")
		if len(env.Delivered.MagicLinks) != 1 {
			t.Fatalf("deliveries = %d, want 1", len(env.Delivered.MagicLinks))
		}
		// The link went to the address on the account, not to anything the caller
		// could name: /magic-link/send in 2fa mode derives it from the tempToken.
		if env.Delivered.MagicLinks[0].Email != "e2emagic@example.com" {
			t.Fatalf("link addressed to %q", env.Delivered.MagicLinks[0].Email)
		}

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"token": env.Delivered.MagicLinks[0].Token, "mode": auth.StepUpMode, "tempToken": tempToken,
		}))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
	})

	// ── the advertised list matches what the account can actually do ────────────

	t.Run("available2faMethods is the enrolled factors and nothing more", func(t *testing.T) {
		t.Run("TOTP only", func(t *testing.T) {
			env := challengeEnv(t, mount, challengeOpts{})
			enrolledTOTPEnv(t, env, "mtotp@example.com")
			_, methods := loginChallenge(t, env, "mtotp@example.com")
			assertMethods(t, methods, auth.TwoFactorMethodTOTP)
		})

		// A phone number with no SMS sender is not a method: the reference gates
		// 'sms' on config.sms as well as on the stored number (auth.router.ts:558).
		t.Run("a phone number without a configured sender is not advertised", func(t *testing.T) {
			store := phoneUserStore{MemoryUserStore: auth.NewMemoryUserStore(), phone: "+15555550143"}
			env := challengeEnv(t, mount, challengeOpts{}, auth.WithUserStore(store))
			enrolledTOTPEnv(t, env, "mphonenosender@example.com")
			_, methods := loginChallenge(t, env, "mphonenosender@example.com")
			assertMethods(t, methods, auth.TwoFactorMethodTOTP)
		})

		t.Run("SMS only", func(t *testing.T) {
			store := phoneUserStore{MemoryUserStore: auth.NewMemoryUserStore(), phone: "+15555550144"}
			env := challengeEnv(t, mount, challengeOpts{sms: true},
				auth.WithUserStore(store), auth.WithRequire2FA(true))
			env.Seed("msms@example.com")
			_, methods := loginChallenge(t, env, "msms@example.com")
			assertMethods(t, methods, auth.TwoFactorMethodSMS)
		})

		// The stored number is tested untrimmed, as the reference tests it
		// (`if (user.phoneNumber && config.sms)`, auth.router.ts:1015 at
		// v1.10.8): a number of only spaces, which /add-phone stores as sent
		// since #35, is advertised.
		t.Run("a number of only spaces is advertised", func(t *testing.T) {
			store := phoneUserStore{MemoryUserStore: auth.NewMemoryUserStore(), phone: " "}
			env := challengeEnv(t, mount, challengeOpts{sms: true},
				auth.WithUserStore(store), auth.WithRequire2FA(true))
			env.Seed("mspace@example.com")
			_, methods := loginChallenge(t, env, "mspace@example.com")
			assertMethods(t, methods, auth.TwoFactorMethodSMS)
		})

		// A sender but no stored number is not a method either. With nothing else
		// enrolled that leaves no method at all, so the answer is the setup branch —
		// which is itself the assertion that 'sms' was not advertised: a challenge
		// listing it would have been a 200.
		t.Run("a configured sender without a phone number is not advertised", func(t *testing.T) {
			env := challengeEnv(t, mount, challengeOpts{sms: true}, auth.WithRequire2FA(true))
			env.Seed("mnosms@example.com")
			rec := env.Do(env.Request(http.MethodPost, "/login", credentials("mnosms@example.com")))
			AssertStatus(t, rec, http.StatusForbidden)
			AssertKeys(t, Body(t, rec), "requires2FASetup", "tempToken", "code")
		})

		t.Run("TOTP and SMS", func(t *testing.T) {
			store := phoneUserStore{MemoryUserStore: auth.NewMemoryUserStore(), phone: "+15555550145"}
			env := challengeEnv(t, mount, challengeOpts{sms: true}, auth.WithUserStore(store))
			enrolledTOTPEnv(t, env, "mboth@example.com")
			_, methods := loginChallenge(t, env, "mboth@example.com")
			// The reference's order, not the enrolment order.
			assertMethods(t, methods, auth.TwoFactorMethodTOTP, auth.TwoFactorMethodSMS)
		})

		// magic-link is per-deployment only in the reference: it is offered to every
		// challenged user as soon as mail can be sent, with no per-user precondition
		// (auth.router.ts:559 checks config.email alone).
		t.Run("magic-link follows the mail sender, not the account", func(t *testing.T) {
			store := phoneUserStore{MemoryUserStore: auth.NewMemoryUserStore(), phone: "+15555550146"}
			env := challengeEnv(t, mount, challengeOpts{sms: true, mail: true}, auth.WithUserStore(store))
			enrolledTOTPEnv(t, env, "mall@example.com")
			_, methods := loginChallenge(t, env, "mall@example.com")
			assertMethods(t, methods, auth.TwoFactorMethodTOTP, auth.TwoFactorMethodSMS, auth.TwoFactorMethodMagicLink)
		})
	})

	// ── the second branch: a policy demands a factor nobody enrolled ────────────

	// 403, and a body that is not the error envelope: requires2FASetup and a code,
	// no message. The tempToken is minted here too, exactly as in the reference
	// (auth.router.ts:564-568).
	//
	// [KNOWN GAP] no route in this port accepts that token. The reference's
	// tempToken is an ordinary access token, so there it authenticates /2fa/setup
	// and the client can enrol on the spot; this port types it tokenTypeTemp and the
	// two enrolment routes sit behind the access-token middleware. The token is
	// therefore currently informational. Widening /2fa/setup to accept a step-up
	// token is a security-relevant decision of its own and is not made here.
	t.Run("a policy with no enrolled factor answers 2FA_SETUP_REQUIRED", func(t *testing.T) {
		env := challengeEnv(t, mount, challengeOpts{}, auth.WithRequire2FA(true))
		env.Seed("setupreq@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/login", credentials("setupreq@example.com")))

		AssertStatus(t, rec, http.StatusForbidden)
		body := Body(t, rec)
		AssertKeys(t, body, "requires2FASetup", "tempToken", "code")
		if body["requires2FASetup"] != true {
			t.Fatalf("requires2FASetup = %v", body["requires2FASetup"])
		}
		if body["code"] != auth.CodeTwoFactorSetupRequired {
			t.Fatalf("code = %v, want %q", body["code"], auth.CodeTwoFactorSetupRequired)
		}
		if tempToken, _ := body["tempToken"].(string); strings.TrimSpace(tempToken) == "" {
			t.Fatal("the setup answer carried no tempToken")
		}
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)
	})

	// The literals themselves, so a rename of the constants cannot move the wire.
	t.Run("the challenge literals", func(t *testing.T) {
		if auth.CodeTwoFactorSetupRequired != "2FA_SETUP_REQUIRED" {
			t.Errorf("setup code = %q", auth.CodeTwoFactorSetupRequired)
		}
		if auth.TwoFactorMethodTOTP != "totp" || auth.TwoFactorMethodSMS != "sms" || auth.TwoFactorMethodMagicLink != "magic-link" {
			t.Errorf("method names drifted: %q %q %q",
				auth.TwoFactorMethodTOTP, auth.TwoFactorMethodSMS, auth.TwoFactorMethodMagicLink)
		}
	})

	// ── the token is not handed out before the password verifies ────────────────

	// The whole point of the ordering. A tempToken stands in for the password on
	// every route in §3, so a /login that minted one before verifyPassword returned
	// would be an oracle: guess an address, collect a step-up credential. Each case
	// asserts the exact member set of the body, which is what makes "no tempToken"
	// checkable rather than a claim about a field nobody looked at.
	t.Run("a failed login carries no tempToken", func(t *testing.T) {
		t.Run("wrong password against a 2FA account", func(t *testing.T) {
			env := challengeEnv(t, mount, challengeOpts{sms: true, mail: true})
			enrolledTOTPEnv(t, env, "oracle@example.com")

			rec := env.Do(env.Request(http.MethodPost, "/login", map[string]string{
				"email": "oracle@example.com", "password": "wrong", "tenantId": testTenant,
			}))
			AssertError(t, rec, http.StatusUnauthorized, "Invalid credentials", auth.CodeInvalidCredentials)
			assertNoTempToken(t, rec)
		})

		t.Run("an address nobody registered", func(t *testing.T) {
			env := challengeEnv(t, mount, challengeOpts{sms: true, mail: true}, auth.WithRequire2FA(true))
			rec := env.Do(env.Request(http.MethodPost, "/login", credentials("ghost@example.com")))
			AssertError(t, rec, http.StatusUnauthorized, "Invalid credentials", auth.CodeInvalidCredentials)
			assertNoTempToken(t, rec)
		})

		// The email gate sits above the challenge in both implementations, so an
		// unverified address is refused rather than challenged — even for an account
		// that has a factor enrolled and would otherwise be handed a token.
		t.Run("an unverified address on a 2FA account", func(t *testing.T) {
			backing := auth.NewMemoryUserStore()
			env := challengeEnv(t, mount, challengeOpts{}, auth.WithUserStore(backing))
			user, tokens := env.Seed("unverified2fa@example.com")
			enrolTOTP(t, env, tokens.AccessToken)
			unverify(t, backing, user)

			rec := env.Do(env.Request(http.MethodPost, "/login", credentials("unverified2fa@example.com")))
			AssertError(t, rec, http.StatusForbidden, "Email address is not verified", auth.CodeEmailNotVerified)
			assertNoTempToken(t, rec)
		})
	})

	// ── the challenge cannot be minted ──────────────────────────────────────────

	// A host whose Config.BuildTokenClaims hook fails breaks token minting from
	// outside the package (issueToken wraps a hook error as an ordinary error), so
	// /login reaches the challenge branch and cannot produce the token it exists to
	// hand over.
	//
	// The route answers 500, not a challenge with an empty tempToken and not the
	// 403 2FA_REQUIRED this PR removed from /login: a client told to step up with a
	// token it was never given would be refused by every §3 route. The two cases
	// together pin that the answer is the deployment's broken minting either way —
	// the second factor does not change it. Service.Login, whose contract is the
	// sentinel rather than the token, still reports ErrTwoFactorRequired here; that
	// is a Go-API guarantee with no wire counterpart and is pinned in the root
	// package (login_2fa_test.go).
	t.Run("a login whose token cannot be minted answers 500", func(t *testing.T) {
		mintFailure := func(t *testing.T, email string, enrol bool) *httptest.ResponseRecorder {
			t.Helper()
			// The hook has to work while the account is seeded and enrolled — both go
			// through it — and fail only for the login under test.
			broken := false
			env := challengeEnv(t, mount, challengeOpts{},
				auth.WithTokenClaimsBuilder(func(context.Context, auth.User) (map[string]any, error) {
					if broken {
						return nil, errClaimsHookDown
					}
					return nil, nil
				}))
			if enrol {
				enrolledTOTPEnv(t, env, email)
			} else {
				env.Seed(email)
			}
			broken = true
			return env.Do(env.Request(http.MethodPost, "/login", credentials(email)))
		}

		t.Run("a 2FA account", func(t *testing.T) {
			rec := mintFailure(t, "mintfail2fa@example.com", true)
			AssertError(t, rec, http.StatusInternalServerError, "Internal server error", "")
			assertNoTempToken(t, rec)
		})

		t.Run("an account with no second factor", func(t *testing.T) {
			rec := mintFailure(t, "mintfailplain@example.com", false)
			AssertError(t, rec, http.StatusInternalServerError, "Internal server error", "")
			AssertNoCookie(t, rec, hostAccess)
			AssertNoCookie(t, rec, hostRefresh)
		})
	})

	// ── the token is typed, and only the step-up routes accept it ───────────────

	// The port's one deliberate difference from the reference here: its tempToken is
	// an ordinary access token, so there a login challenge doubles as a session
	// credential for five minutes. This one is tokenTypeTemp and a route wanting a
	// real access token refuses it — which is only worth asserting now that a client
	// can actually obtain one from /login.
	t.Run("a token from a login challenge is not an access token", func(t *testing.T) {
		env := challengeEnv(t, mount, challengeOpts{})
		enrolledTOTPEnv(t, env, "typed@example.com")
		tempToken, _ := loginChallenge(t, env, "typed@example.com")

		rec := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tempToken))
		AssertError(t, rec, http.StatusForbidden, "Invalid or expired access token", "")
	})
}

// assertNoTempToken fails when a response body mentions a step-up token under
// that name, at any nesting depth: it matches the raw body rather than a decoded
// top-level member.
//
// It does not, on its own, rule out a token handed over under some other name —
// a substring check cannot. What rules that out is the AssertError beside every
// call, which pins the body to exactly the error envelope's members, so any
// extra member fails whatever it is called.
func assertNoTempToken(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(rec.Body.String(), "tempToken") {
		t.Fatalf("a failed login handed out a step-up token: %s", rec.Body.String())
	}
}
