package wiretest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Forced enrolment: the 2FA_SETUP_REQUIRED branch of POST /login, made
// completable (enrolment.go in the root package).
//
// A second factor is demanded — Config.Require2FA or the user's own Require2FA
// flag — and the account has none to present. The login opens no session and
// answers 403 with an enrolment token; POST /2fa/setup and POST
// /2fa/verify-setup accept that token (as the body's tempToken, or as a bearer
// credential, which is how a client written against the reference presents
// it), and a verify-setup that completes with it opens the session exactly as
// POST /2fa/verify does.
//
// Every case here logs in over HTTP and reads the token out of the 403, for the
// reason login_2fa.go gives: a token minted by the test is a token no client
// could have obtained.

// enrolmentEnv is a deployment that demands a second factor and can deliver
// none: no SMS sender, no mail sender, so an account without TOTP has no method
// at all and the login answers 2FA_SETUP_REQUIRED. The secret is fixed so the
// expiry case can sign a token the deployment accepts.
func enrolmentEnv(t *testing.T, mount Mounter, cfg auth.HTTPConfig, opts ...auth.Option) *Env {
	t.Helper()
	opts = append([]auth.Option{auth.WithRequire2FA(true), auth.WithSecret(wiretestAccessSecret)}, opts...)
	env := newEnv(t, mount, cfg, opts...)
	env.Delivered = &Deliveries{}
	return env
}

// require2FAOnEveryLookup flags Require2FA on both lookups, so the per-user
// policy reaches the login (which reads by email) as well as the enrolment
// routes (which read by id). require2FAUserStore flags the id lookup alone,
// which is a different case: a flag set after the login.
type require2FAOnEveryLookup struct {
	*auth.MemoryUserStore
}

func (s require2FAOnEveryLookup) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	user, err := s.MemoryUserStore.GetUserByID(ctx, id, tenantID)
	if err == nil {
		user.Require2FA = true
	}
	return user, err
}

func (s require2FAOnEveryLookup) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) {
	user, err := s.MemoryUserStore.GetUserByEmail(ctx, email, tenantID)
	if err == nil {
		user.Require2FA = true
	}
	return user, err
}

// setupRequiredToken logs in over HTTP and returns the enrolment token of the
// 2FA_SETUP_REQUIRED answer, asserting the answer's wire shape: 403, exactly
// the reference's three members, and no session credential.
func setupRequiredToken(t *testing.T, env *Env, email string) string {
	t.Helper()
	rec := env.Do(env.Request(http.MethodPost, "/login", credentials(email)))
	AssertStatus(t, rec, http.StatusForbidden)
	body := Body(t, rec)
	AssertKeys(t, body, "requires2FASetup", "tempToken", "code")
	if body["requires2FASetup"] != true || body["code"] != auth.CodeTwoFactorSetupRequired {
		t.Fatalf("setup answer = %v", body)
	}
	AssertNoCookie(t, rec, hostAccess)
	AssertNoCookie(t, rec, hostRefresh)
	token, _ := body["tempToken"].(string)
	if strings.TrimSpace(token) == "" {
		t.Fatal("the setup answer carried no tempToken")
	}
	return token
}

// enrolWithToken walks the forced enrolment with the token in the body and
// returns the secret and the verify-setup response.
func enrolWithToken(t *testing.T, env *Env, token string, bearer bool) (string, *httptest.ResponseRecorder) {
	t.Helper()
	setup := env.Do(env.Request(http.MethodPost, "/2fa/setup", map[string]any{"tempToken": token}))
	AssertStatus(t, setup, http.StatusOK)
	setupBody := Body(t, setup)
	AssertKeys(t, setupBody, "secret", "otpauthUrl")
	// Enrolment material is not a session.
	AssertNoCookie(t, setup, hostAccess)
	AssertNoCookie(t, setup, hostRefresh)
	secret, _ := setupBody["secret"].(string)

	req := env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
		"tempToken": token, "secret": secret, "token": totpCode(t, secret, time.Now()),
	})
	if bearer {
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	}
	return secret, env.Do(req)
}

// expiredCopy re-signs token's payload with exp an hour in the past, which is
// beyond any clock skew: the same token, on the far side of its lifetime.
func expiredCopy(t *testing.T, token, secret string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	claims["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return resignHS256(t, parts[0]+"."+base64.RawURLEncoding.EncodeToString(payload)+".x", secret)
}

func testForcedEnrolment(t *testing.T, mount Mounter) {
	// ── the login ───────────────────────────────────────────────────────────────

	t.Run("an enforced login without a factor opens no session", func(t *testing.T) {
		t.Run("Config.Require2FA", func(t *testing.T) {
			env := enrolmentEnv(t, mount, auth.DefaultHTTPConfig())
			env.Seed("cfgpolicy@example.com")
			setupRequiredToken(t, env, "cfgpolicy@example.com")
		})
		t.Run("the per-user flag", func(t *testing.T) {
			store := require2FAOnEveryLookup{auth.NewMemoryUserStore()}
			env := newEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
			env.Seed("userpolicy@example.com")
			setupRequiredToken(t, env, "userpolicy@example.com")
		})
	})

	// ── completing it ──────────────────────────────────────────────────────────

	t.Run("full enrolment opens the session", func(t *testing.T) {
		t.Run("cookie mode", func(t *testing.T) {
			env := enrolmentEnv(t, mount, auth.DefaultHTTPConfig())
			env.Seed("forcedcookie@example.com")
			token := setupRequiredToken(t, env, "forcedcookie@example.com")

			_, verify := enrolWithToken(t, env, token, false)
			AssertStatus(t, verify, http.StatusOK)
			AssertKeys(t, Body(t, verify), "success")
			AssertCookieAttrs(t, Cookie(t, verify, hostAccess), accessCookieSpec())
			AssertCookieAttrs(t, Cookie(t, verify, hostRefresh), refreshCookieSpec())

			// The session is a real one, and it says the factor is there.
			me := env.Do(Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), verify))
			AssertStatus(t, me, http.StatusOK)
			if got := Body(t, me)["isTotpEnabled"]; got != true {
				t.Errorf("isTotpEnabled = %v after a forced enrolment, want true", got)
			}
			// And the next login is a TOTP challenge, not another setup answer.
			_, methods := loginChallenge(t, env, "forcedcookie@example.com")
			assertMethods(t, methods, auth.TwoFactorMethodTOTP)
		})

		t.Run("bearer mode", func(t *testing.T) {
			env := enrolmentEnv(t, mount, auth.DefaultHTTPConfig())
			env.Seed("forcedbearer@example.com")
			token := setupRequiredToken(t, env, "forcedbearer@example.com")

			_, verify := enrolWithToken(t, env, token, true)
			AssertStatus(t, verify, http.StatusOK)
			body := Body(t, verify)
			AssertKeys(t, body, "success", "accessToken", "refreshToken")
			AssertNoCookie(t, verify, hostAccess)
			AssertNoCookie(t, verify, hostRefresh)
			access, _ := body["accessToken"].(string)
			AssertStatus(t, env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", access)), http.StatusOK)
		})

		t.Run("the token as a bearer credential", func(t *testing.T) {
			// A client written against the reference sends the tempToken as an
			// access token, because there it is one.
			env := enrolmentEnv(t, mount, auth.DefaultHTTPConfig())
			env.Seed("forcedheader@example.com")
			token := setupRequiredToken(t, env, "forcedheader@example.com")

			setup := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/setup", nil), token))
			AssertStatus(t, setup, http.StatusOK)
			secret, _ := Body(t, setup)["secret"].(string)

			verify := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
				"secret": secret, "token": totpCode(t, secret, time.Now()),
			}), token))
			AssertStatus(t, verify, http.StatusOK)
			AssertKeys(t, Body(t, verify), "success", "accessToken", "refreshToken")
		})

		t.Run("a bad code enrols nothing and opens nothing", func(t *testing.T) {
			env := enrolmentEnv(t, mount, auth.DefaultHTTPConfig())
			env.Seed("forcedbadcode@example.com")
			token := setupRequiredToken(t, env, "forcedbadcode@example.com")
			setup := env.Do(env.Request(http.MethodPost, "/2fa/setup", map[string]any{"tempToken": token}))
			secret, _ := Body(t, setup)["secret"].(string)

			rec := env.Do(env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
				"tempToken": token, "secret": secret, "token": wrongTOTPCode(t, secret),
			}))
			AssertError(t, rec, http.StatusBadRequest, "Invalid TOTP code", "")
			AssertNoCookie(t, rec, hostAccess)
			// Still nothing enrolled, so the token is still good and the login
			// still asks for setup.
			setupRequiredToken(t, env, "forcedbadcode@example.com")
			AssertStatus(t, env.Do(env.Request(http.MethodPost, "/2fa/setup", map[string]any{"tempToken": token})), http.StatusOK)
		})
	})

	t.Run("an empty secret is no factor", func(t *testing.T) {
		// An empty secret is an empty HMAC key: its code verifies, and anybody
		// can compute it. The forced path refuses it before anything is stored.
		env := enrolmentEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("emptysecret@example.com")
		token := setupRequiredToken(t, env, "emptysecret@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
			"tempToken": token, "secret": "", "token": totpCode(t, "", time.Now()),
		}))
		AssertError(t, rec, http.StatusBadRequest, "Invalid TOTP code", "")
		AssertNoCookie(t, rec, hostAccess)
		// Nothing enrolled: the login still asks for setup, and the token works.
		setupRequiredToken(t, env, "emptysecret@example.com")
		AssertStatus(t, env.Do(env.Request(http.MethodPost, "/2fa/setup", map[string]any{"tempToken": token})), http.StatusOK)
	})

	t.Run("a voluntary enrolment still opens nothing", func(t *testing.T) {
		// The access-token path is unchanged: {"success":true} and no session,
		// in cookie mode too.
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("voluntary@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("voluntary@example.com")))
		AssertStatus(t, login, http.StatusOK)

		setup := env.Do(csrfMirror(env.Request(http.MethodPost, "/2fa/setup", nil), login))
		AssertStatus(t, setup, http.StatusOK)
		secret, _ := Body(t, setup)["secret"].(string)
		verify := env.Do(csrfMirror(env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
			"secret": secret, "token": totpCode(t, secret, time.Now()),
		}), login))
		AssertStatus(t, verify, http.StatusOK)
		AssertKeys(t, Body(t, verify), "success")
		AssertNoCookie(t, verify, hostAccess)
		AssertNoCookie(t, verify, hostRefresh)
	})

	// ── the token does one thing ────────────────────────────────────────────────

	t.Run("the enrolment token is refused everywhere else", func(t *testing.T) {
		cfg := auth.DefaultHTTPConfig()
		cfg.Admin = auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()}
		env := enrolmentEnv(t, mount, cfg)
		env.Seed("elsewhere@example.com")
		token := setupRequiredToken(t, env, "elsewhere@example.com")
		prefix := env.Config.Prefix()

		// As an access token: the gate's own answer for a token that is not one.
		for _, route := range []struct{ method, path string }{
			{http.MethodGet, "/me"},
			{http.MethodGet, "/sessions"},
			{http.MethodPost, "/2fa/disable"},
			{http.MethodPost, "/change-password"},
		} {
			rec := env.Do(bearerRequest(route.method, prefix+route.path, token))
			AssertError(t, rec, http.StatusForbidden, "Invalid or expired access token", "")
		}
		// As a step-up token: each route's own answer for a bad tempToken.
		rec := env.Do(env.Request(http.MethodPost, "/2fa/verify", map[string]any{"tempToken": token, "totpCode": "000000"}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired access token", auth.CodeInvalidAccessToken)
		rec = env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{"mode": "2fa", "tempToken": token, "code": "000000"}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
		rec = env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"mode": "2fa", "tempToken": token, "token": "x"}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
		// As a refresh token.
		rec = env.Do(env.Request(http.MethodPost, "/refresh", map[string]any{"refreshToken": token}))
		AssertStatus(t, rec, http.StatusUnauthorized)
		AssertNoCookie(t, rec, hostAccess)
		// As an admin credential.
		rec = env.Do(bearerRequest(http.MethodGet, env.Config.AdminPath()+auth.AdminPingPath, token))
		AssertError(t, rec, http.StatusUnauthorized, "Unauthorized", "")
	})

	t.Run("the other token types do not enrol", func(t *testing.T) {
		// The step-up token is the one that matters: a user with a factor holds
		// one after the password alone, and an enrolment route that took it
		// would let that password replace the factor.
		env := challengeEnv(t, mount, challengeOpts{})
		secret := enrolledTOTPEnv(t, env, "hasfactor@example.com")
		stepUp, _ := loginChallenge(t, env, "hasfactor@example.com")
		_, tokens := env.Seed("plain@example.com")

		for name, candidate := range map[string]string{
			"a step-up token": stepUp,
			"an access token": tokens.AccessToken,
			"a refresh token": tokens.RefreshToken,
		} {
			t.Run(name, func(t *testing.T) {
				rec := env.Do(env.Request(http.MethodPost, "/2fa/setup", map[string]any{"tempToken": candidate}))
				AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
				rec = env.Do(env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
					"tempToken": candidate, "secret": "JBSWY3DPEHPK3PXP", "token": totpCode(t, "JBSWY3DPEHPK3PXP", time.Now()),
				}))
				AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
				AssertNoCookie(t, rec, hostAccess)
			})
		}
		// The step-up token as a bearer credential is the access gate's refusal.
		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/setup", nil), stepUp))
		AssertError(t, rec, http.StatusForbidden, "Invalid or expired access token", "")

		// And the factor the step-up token's owner holds is the one it held.
		fresh, _ := loginChallenge(t, env, "hasfactor@example.com")
		rec = env.Do(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": fresh, "totpCode": totpCode(t, secret, time.Now()),
		}))
		AssertStatus(t, rec, http.StatusOK)
	})

	t.Run("a replayed enrolment token is refused", func(t *testing.T) {
		env := enrolmentEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("replay@example.com")
		token := setupRequiredToken(t, env, "replay@example.com")
		_, verify := enrolWithToken(t, env, token, false)
		AssertStatus(t, verify, http.StatusOK)

		rec := env.Do(env.Request(http.MethodPost, "/2fa/setup", map[string]any{"tempToken": token}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
		rec = env.Do(env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
			"tempToken": token, "secret": "JBSWY3DPEHPK3PXP", "token": totpCode(t, "JBSWY3DPEHPK3PXP", time.Now()),
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
		AssertNoCookie(t, rec, hostAccess)
		rec = env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/setup", nil), token))
		AssertError(t, rec, http.StatusForbidden, "Invalid or expired access token", "")
	})

	t.Run("an enrolment through one token retires the others", func(t *testing.T) {
		env := enrolmentEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("twotokens@example.com")
		first := setupRequiredToken(t, env, "twotokens@example.com")
		second := setupRequiredToken(t, env, "twotokens@example.com")
		_, verify := enrolWithToken(t, env, second, false)
		AssertStatus(t, verify, http.StatusOK)

		rec := env.Do(env.Request(http.MethodPost, "/2fa/setup", map[string]any{"tempToken": first}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
	})

	t.Run("an expired enrolment token is refused", func(t *testing.T) {
		env := enrolmentEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("expired@example.com")
		token := setupRequiredToken(t, env, "expired@example.com")
		expired := expiredCopy(t, token, wiretestAccessSecret)

		rec := env.Do(env.Request(http.MethodPost, "/2fa/setup", map[string]any{"tempToken": expired}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
		rec = env.Do(env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
			"tempToken": expired, "secret": "JBSWY3DPEHPK3PXP", "token": totpCode(t, "JBSWY3DPEHPK3PXP", time.Now()),
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
		// The copy differs from the original only in its lifetime: the original
		// is still accepted, so it is the expiry being refused.
		AssertStatus(t, env.Do(env.Request(http.MethodPost, "/2fa/setup", map[string]any{"tempToken": token})), http.StatusOK)
	})

	// ── everything else answers as it did ──────────────────────────────────────

	t.Run("a request with no enrolment token answers as before", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionCheckOn(auth.SessionCheckOnAllCalls))
		_, tokens := env.Seed("asbefore@example.com")

		for _, route := range []string{"/2fa/setup", "/2fa/verify-setup"} {
			rec := env.Do(env.Request(http.MethodPost, route, nil))
			AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
			rec = env.Do(passwordlessBearer(env.Request(http.MethodPost, route, nil), "not-a-token"))
			AssertError(t, rec, http.StatusForbidden, "Invalid or expired access token", "")
		}
		// The credential is answered before the body, as the middleware and the
		// decoder behind it answered.
		malformed := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/2fa/verify-setup", strings.NewReader("{not json"))
		malformed.Header.Set("Content-Type", "application/json")
		AssertError(t, env.Do(malformed), http.StatusForbidden, "No access token provided", "")
		authed := passwordlessBearer(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/2fa/verify-setup", strings.NewReader("{not json")), tokens.AccessToken)
		authed.Header.Set("Content-Type", "application/json")
		rec := env.Do(authed)
		AssertStatus(t, rec, http.StatusBadRequest)
		// /2fa/setup reads no body in the reference, so an unparsable one is
		// still a voluntary enrolment.
		setup := passwordlessBearer(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/2fa/setup", strings.NewReader("{not json")), tokens.AccessToken)
		AssertStatus(t, env.Do(setup), http.StatusOK)

		// A cookie-authenticated call is still CSRF-checked.
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("asbefore@example.com")))
		rec = env.Do(Replay(env.Request(http.MethodPost, "/2fa/setup", nil), login))
		AssertError(t, rec, http.StatusForbidden, auth.HTTPErrCSRFInvalid.Message, auth.CodeCSRFInvalid)

		// A revoked session is still SESSION_REVOKED under allcalls.
		if err := env.Auth.Service().RevokeSessionByID(context.Background(), sessionIDOf(t, tokens.AccessToken)); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		rec = env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/setup", nil), tokens.AccessToken))
		AssertStatus(t, rec, http.StatusUnauthorized)
		if got := Body(t, rec)["code"]; got != auth.CodeSessionRevoked {
			t.Errorf("code = %v, want %s", got, auth.CodeSessionRevoked)
		}
	})
}

// wrongTOTPCode is a six-digit code that does not verify against secret now or
// at the adjacent steps the verifier tolerates.
func wrongTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	now := time.Now()
	valid := map[string]bool{}
	for _, at := range []time.Time{now.Add(-30 * time.Second), now, now.Add(30 * time.Second)} {
		valid[totpCode(t, secret, at)] = true
	}
	for _, candidate := range []string{"000000", "111111", "222222", "333333"} {
		if !valid[candidate] {
			return candidate
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

// sessionIDOf reads the sid claim out of an access token without verifying it.
func sessionIDOf(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		Sid string `json:"sid"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims.Sid
}
