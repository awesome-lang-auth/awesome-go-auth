package wiretest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// The authentication context on the wire: the amr, auth_time and mfa_at claims
// every access token carries (authentication_context.go in the root package),
// and POST <prefix>/2fa/step-up, the one route that moves mfa_at for an
// existing session.
//
// The claims are read straight out of the token the response delivered —
// cookie or body — because that is what a resource server reads.

// tokenClaims decodes a compact JWT's payload without verifying it.
func tokenClaims(t *testing.T, token string) map[string]any {
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
	return claims
}

func claimAMR(t *testing.T, claims map[string]any) []string {
	t.Helper()
	raw, ok := claims[auth.ClaimAMR].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

// assertAuthContext checks the three claims of the access token a response
// delivered, in either mode, and returns its claims.
func assertAuthContext(t *testing.T, rec *httptest.ResponseRecorder, wantAMR []string, wantMFA bool) map[string]any {
	t.Helper()
	token, _ := Body(t, rec)["accessToken"].(string)
	if token == "" {
		token = Cookie(t, rec, hostAccess).Value
	}
	claims := tokenClaims(t, token)
	if got := claimAMR(t, claims); !slices.Equal(got, wantAMR) {
		t.Errorf("amr = %v, want %v", got, wantAMR)
	}
	if _, ok := claims[auth.ClaimAuthTime].(float64); !ok {
		t.Errorf("auth_time = %#v, want a NumericDate", claims[auth.ClaimAuthTime])
	}
	_, hasMFA := claims[auth.ClaimMFAAt].(float64)
	if hasMFA != wantMFA {
		t.Errorf("mfa_at present = %v, want %v (claims %v)", hasMFA, wantMFA, claims)
	}
	return claims
}

func testStepUp(t *testing.T, mount Mounter) {
	// ── the claims, path by path ────────────────────────────────────────────────

	t.Run("a password login records pwd and no second factor", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("ctxpwd@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/login", credentials("ctxpwd@example.com")))
		AssertStatus(t, rec, http.StatusOK)
		assertAuthContext(t, rec, []string{auth.AMRPassword}, false)
	})

	t.Run("a TOTP login records the second factor, and refresh carries it", func(t *testing.T) {
		env := challengeEnv(t, mount, challengeOpts{})
		secret := enrolledTOTPEnv(t, env, "ctxtotp@example.com")
		tempToken, _ := loginChallenge(t, env, "ctxtotp@example.com")
		verify := env.Do(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": tempToken, "totpCode": totpCode(t, secret, time.Now()),
		}))
		AssertStatus(t, verify, http.StatusOK)
		before := assertAuthContext(t, verify, []string{auth.AMRPassword, auth.AMROTP, auth.AMRMFA}, true)

		refreshed := env.Do(Replay(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/refresh", nil), verify))
		AssertStatus(t, refreshed, http.StatusOK)
		after := assertAuthContext(t, refreshed, []string{auth.AMRPassword, auth.AMROTP, auth.AMRMFA}, true)
		for _, name := range []string{auth.ClaimAuthTime, auth.ClaimMFAAt} {
			if before[name] != after[name] {
				t.Errorf("%s moved on refresh: %v → %v", name, before[name], after[name])
			}
		}
	})

	t.Run("the SMS and magic-link step-up record their factor", func(t *testing.T) {
		store := phoneUserStore{MemoryUserStore: auth.NewMemoryUserStore(), phone: "+15555550177"}
		// A policy, so that the login challenges: the stored phone number and
		// the mail sender are the account's two factors.
		env := challengeEnv(t, mount, challengeOpts{sms: true, mail: true}, auth.WithUserStore(store), auth.WithRequire2FA(true))
		user, _ := env.Seed("ctxstep@example.com")

		temp, _ := loginChallenge(t, env, "ctxstep@example.com")
		AssertStatus(t, env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{"mode": "2fa", "tempToken": temp})), http.StatusOK)
		code := env.Delivered.SMSCodes[len(env.Delivered.SMSCodes)-1].Code
		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{"mode": "2fa", "tempToken": temp, "code": code}))
		AssertStatus(t, rec, http.StatusOK)
		assertAuthContext(t, rec, []string{auth.AMRPassword, auth.AMRSMS, auth.AMRMFA}, true)

		temp, _ = loginChallenge(t, env, "ctxstep@example.com")
		AssertStatus(t, env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{"mode": "2fa", "tempToken": temp})), http.StatusOK)
		link := env.Delivered.MagicLinks[len(env.Delivered.MagicLinks)-1].Token
		rec = env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"mode": "2fa", "tempToken": temp, "token": link}))
		AssertStatus(t, rec, http.StatusOK)
		assertAuthContext(t, rec, []string{auth.AMRPassword, auth.AMREmail, auth.AMRMFA}, true)

		// The same two routes as a login of their own record one factor.
		AssertStatus(t, env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{"userId": user.ID, "tenantId": testTenant})), http.StatusOK)
		code = env.Delivered.SMSCodes[len(env.Delivered.SMSCodes)-1].Code
		rec = env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{"userId": user.ID, "tenantId": testTenant, "code": code}))
		AssertStatus(t, rec, http.StatusOK)
		assertAuthContext(t, rec, []string{auth.AMRSMS}, false)

		AssertStatus(t, env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{"email": "ctxstep@example.com", "tenantId": testTenant})), http.StatusOK)
		link = env.Delivered.MagicLinks[len(env.Delivered.MagicLinks)-1].Token
		rec = env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": link}))
		AssertStatus(t, rec, http.StatusOK)
		assertAuthContext(t, rec, []string{auth.AMREmail}, false)
	})

	// ── POST /2fa/step-up ──────────────────────────────────────────────────────

	// stepUpSession is a one-factor session — a magic-link login — of an
	// account that already holds TOTP: the factor predates the session, so the
	// session may step up with it, and having presented no second factor yet,
	// the step-up's effect is visible in a single second. bearer selects the
	// delivery; the returned access token is the one the session's response
	// carried, cookie or body.
	stepUpSession := func(t *testing.T, env *Env, email string, bearer bool) (*httptest.ResponseRecorder, string, string) {
		t.Helper()
		_, seeded := env.Seed(email)
		secret := enrolTOTP(t, env, seeded.AccessToken)
		AssertStatus(t, env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{"email": email, "tenantId": testTenant})), http.StatusOK)
		link := env.Delivered.MagicLinks[len(env.Delivered.MagicLinks)-1].Token
		req := env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": link})
		if bearer {
			req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		}
		login := env.Do(req)
		AssertStatus(t, login, http.StatusOK)
		access, _ := Body(t, login)["accessToken"].(string)
		if access == "" {
			access = Cookie(t, login, hostAccess).Value
		}
		return login, secret, access
	}
	stepBearer := func(env *Env, token, code string) *httptest.ResponseRecorder {
		req := env.Request(http.MethodPost, auth.StepUpRoute, map[string]any{"totpCode": code})
		if token != "" {
			req = passwordlessBearer(req, token)
		}
		return env.Do(req)
	}

	t.Run("step-up in cookie mode delivers the access cookie alone", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, secret, _ := stepUpSession(t, env, "stepcookie@example.com", false)
		assertAuthContext(t, login, []string{auth.AMREmail}, false)

		rec := env.Do(csrfMirror(env.Request(http.MethodPost, auth.StepUpRoute, map[string]any{
			"totpCode": totpCode(t, secret, time.Now()),
		}), login))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		// The refresh token is not rotated, so its cookie is not touched.
		AssertNoCookie(t, rec, hostRefresh)
		claims := assertAuthContext(t, rec, []string{auth.AMREmail, auth.AMROTP, auth.AMRMFA}, true)
		if claims["sid"] != tokenClaims(t, Cookie(t, login, hostAccess).Value)["sid"] {
			t.Error("the step-up token belongs to another session")
		}

		// The next refresh carries the new mfa_at forward.
		refreshed := env.Do(Replay(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/refresh", nil), login))
		AssertStatus(t, refreshed, http.StatusOK)
		after := assertAuthContext(t, refreshed, []string{auth.AMREmail, auth.AMROTP, auth.AMRMFA}, true)
		if after[auth.ClaimMFAAt] != claims[auth.ClaimMFAAt] {
			t.Errorf("mfa_at after refresh = %v, want the step-up's %v", after[auth.ClaimMFAAt], claims[auth.ClaimMFAAt])
		}
	})

	t.Run("step-up in bearer mode answers the access token in the body", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, secret, access := stepUpSession(t, env, "stepbearer@example.com", true)
		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, auth.StepUpRoute, map[string]any{
			"totpCode": totpCode(t, secret, time.Now()),
		}), access))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success", "accessToken")
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)
		assertAuthContext(t, rec, []string{auth.AMREmail, auth.AMROTP, auth.AMRMFA}, true)
	})

	t.Run("a cookie step-up without the CSRF header is refused", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, secret, _ := stepUpSession(t, env, "stepcsrf@example.com", false)
		rec := env.Do(Replay(env.Request(http.MethodPost, auth.StepUpRoute, map[string]any{
			"totpCode": totpCode(t, secret, time.Now()),
		}), login))
		AssertError(t, rec, http.StatusForbidden, auth.HTTPErrCSRFInvalid.Message, auth.CodeCSRFInvalid)
	})

	t.Run("step-up refusals", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, secret, access := stepUpSession(t, env, "steprefuse@example.com", true)
		refresh, _ := Body(t, login)["refreshToken"].(string)
		_, plain := env.Seed("stepplain@example.com")

		AssertError(t, stepBearer(env, "", "123456"), http.StatusForbidden, "No access token provided", "")
		AssertError(t, stepBearer(env, "not-a-token", "123456"), http.StatusForbidden, "Invalid or expired access token", "")
		AssertError(t, stepBearer(env, access, stepUpWrongCode(t, secret)), http.StatusUnauthorized, "Invalid TOTP code", "")
		AssertError(t, stepBearer(env, plain.AccessToken, "123456"), http.StatusBadRequest, "User not found or 2FA not set up", "")

		// A logged-out session is refused even though the default session-check
		// mode lets its access token through the gate: the route writes to the
		// session, so it always checks it.
		logout := env.Do(env.Request(http.MethodPost, "/logout", map[string]any{"refreshToken": refresh}))
		AssertStatus(t, logout, http.StatusOK)
		AssertError(t, stepBearer(env, access, totpCode(t, secret, time.Now())), http.StatusUnauthorized,
			auth.HTTPErrSessionRevoked.Message, auth.CodeSessionRevoked)
	})

	// ── a factor the session is not bound to ───────────────────────────────────

	// Whoever holds a session's access token can enrol a factor through the
	// voluntary /2fa/setup and /2fa/verify-setup. A code of that factor proves
	// nothing the token did not, so it never moves the session's mfa_at.
	t.Run("a factor enrolled after the session opened cannot step up", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("stepfirst@example.com") // a password session, no factor yet
		secret := enrolTOTP(t, env, tokens.AccessToken)
		AssertError(t, stepBearer(env, tokens.AccessToken, totpCode(t, secret, time.Now())), http.StatusForbidden,
			auth.HTTPErrReauthenticationRequired.Message, auth.CodeReauthenticationRequired)
	})

	t.Run("a factor swapped in through the session cannot step up", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, original, access := stepUpSession(t, env, "stepswap@example.com", true)
		swapped := enrolTOTP(t, env, access)
		for name, secret := range map[string]string{"the swapped-in factor": swapped, "the replaced factor": original} {
			rec := stepBearer(env, access, totpCode(t, secret, time.Now()))
			if rec.Code != http.StatusForbidden || Body(t, rec)["code"] != auth.CodeReauthenticationRequired {
				t.Errorf("%s: %d %s, want 403 %s", name, rec.Code, rec.Body.String(), auth.CodeReauthenticationRequired)
			}
		}
	})

	// ── the failure budget ─────────────────────────────────────────────────────

	t.Run("the last wrong code of the budget ends the session", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, secret, access := stepUpSession(t, env, "stepbudget@example.com", true)
		refresh, _ := Body(t, login)["refreshToken"].(string)
		wrong := stepUpWrongCode(t, secret)
		for i := 1; i < auth.StepUpFailureLimit; i++ {
			AssertError(t, stepBearer(env, access, wrong), http.StatusUnauthorized, "Invalid TOTP code", "")
		}
		AssertError(t, stepBearer(env, access, wrong), http.StatusUnauthorized, auth.HTTPErrSessionRevoked.Message, auth.CodeSessionRevoked)
		// The right code no longer helps, and the session's refresh token is dead.
		AssertError(t, stepBearer(env, access, totpCode(t, secret, time.Now())), http.StatusUnauthorized,
			auth.HTTPErrSessionRevoked.Message, auth.CodeSessionRevoked)
		rec := env.Do(env.Request(http.MethodPost, "/refresh", map[string]any{"refreshToken": refresh}))
		if rec.Code == http.StatusOK {
			t.Fatalf("refresh after the budget = %d %s, want a refusal", rec.Code, rec.Body.String())
		}
	})
}

// stepUpWrongCode is a six-digit code that does not verify against secret now
// or at the adjacent steps the verifier tolerates.
func stepUpWrongCode(t *testing.T, secret string) string {
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
