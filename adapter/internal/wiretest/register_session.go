package wiretest

// POST <prefix>/register under Config.IssueSessionOnRegister (#21): the
// family spec "register may open a session, when the instance admin says so"
// (.tools/plan/spec-register-session.md in the workspace).
//
// Off, the answer is the reference's: 201 {"success":true,"userId":"…"}, no
// access or refresh cookie, no token, no session row (auth.router.ts:1259 at
// v1.10.8). On — the 0.x default — the same status and fields plus a session
// delivered exactly as POST /login delivers one. A refused registration never
// issues anything, and a login gate the new account would not pass — strict
// email verification — wins over the option.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
	"golang.org/x/crypto/bcrypt"
)

// registerSessionEnv builds an env from a whole Config, which is the only way
// to reach EmailVerificationMode from outside the package: it has no Option.
func registerSessionEnv(t *testing.T, mount Mounter, tweak func(*auth.Config)) *Env {
	t.Helper()
	cfg := auth.DefaultConfig("01234567890123456789012345678901")
	cfg.BcryptCost = bcrypt.MinCost
	if tweak != nil {
		tweak(&cfg)
	}
	a, err := auth.NewWithConfig(cfg,
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()))
	if err != nil {
		t.Fatalf("auth.NewWithConfig: %v", err)
	}
	httpCfg := auth.DefaultHTTPConfig()
	return &Env{T: t, Auth: a, Handler: mount(t, a, httpCfg), Config: httpCfg, Delivered: &Deliveries{}}
}

// assertRegisteredWithoutSession pins the reference's answer: the two fields
// and nothing else in the body, no credential cookie, and no session row for
// the account it names.
func assertRegisteredWithoutSession(t *testing.T, env *Env, rec *httptest.ResponseRecorder, bearerMode bool) {
	t.Helper()
	AssertStatus(t, rec, http.StatusCreated)
	body := Body(t, rec)
	AssertKeys(t, body, "success", "userId")
	if body["success"] != true {
		t.Fatalf("success = %v", body["success"])
	}
	AssertNoCookie(t, rec, hostAccess)
	AssertNoCookie(t, rec, hostRefresh)
	if bearerMode {
		AssertNoCookies(t, rec)
	}
	userID, _ := body["userId"].(string)
	sessions, err := env.Auth.ListSessions(context.Background(), userID, "t1")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("the registration opened %d session(s), want none", len(sessions))
	}
}

func testRegisterSession(t *testing.T, mount Mounter) {
	bearerModes := []struct {
		name   string
		bearer bool
	}{{"cookie mode", false}, {"bearer mode", true}}

	for _, mode := range bearerModes {
		t.Run("off answers the reference's 201 and nothing else, "+mode.name, func(t *testing.T) {
			env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIssueSessionOnRegister(false))
			req := env.Request(http.MethodPost, "/register", credentials("off@example.com"))
			if mode.bearer {
				req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
			}
			assertRegisteredWithoutSession(t, env, env.Do(req), mode.bearer)

			// And the client logs in afterwards, as with the reference.
			login := env.Do(env.Request(http.MethodPost, "/login", credentials("off@example.com")))
			AssertStatus(t, login, http.StatusOK)
		})
	}

	t.Run("on, cookie mode: GET /me answers on the cookies it set", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIssueSessionOnRegister(true))
		rec := env.Do(env.Request(http.MethodPost, "/register", credentials("oncookie@example.com")))
		AssertStatus(t, rec, http.StatusCreated)
		AssertKeys(t, Body(t, rec), "success", "userId")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())

		me := env.Do(Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), rec))
		AssertStatus(t, me, http.StatusOK)
		if got := Body(t, me)["email"]; got != "oncookie@example.com" {
			t.Fatalf("GET /me email = %v, want the registered account", got)
		}
	})

	t.Run("on, bearer mode: GET /me answers on the token it returned", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIssueSessionOnRegister(true))
		req := env.Request(http.MethodPost, "/register", credentials("onbearer@example.com"))
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := env.Do(req)
		AssertStatus(t, rec, http.StatusCreated)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "userId", "accessToken", "refreshToken")
		AssertNoCookies(t, rec)

		access, _ := body["accessToken"].(string)
		me := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", access))
		AssertStatus(t, me, http.StatusOK)
		if got := Body(t, me)["email"]; got != "onbearer@example.com" {
			t.Fatalf("GET /me email = %v, want the registered account", got)
		}
	})

	// Refusals first: nothing is issued for a registration that is refused.
	t.Run("on, a refused registration issues nothing", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIssueSessionOnRegister(true))
		env.Seed("taken@example.com")
		for _, mode := range bearerModes {
			req := env.Request(http.MethodPost, "/register", credentials("taken@example.com"))
			if mode.bearer {
				req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
			}
			rec := env.Do(req)
			AssertError(t, rec, http.StatusConflict, "User already exists", auth.CodeUserExists)
			AssertNoCookie(t, rec, hostAccess)
			AssertNoCookie(t, rec, hostRefresh)
		}
	})

	// Email verification wins: under strict the login would refuse the new,
	// unverified account with 403 EMAIL_NOT_VERIFIED, so the registration must
	// not hand it the credential the gate withholds — the bypass #21 was filed
	// about.
	for _, mode := range bearerModes {
		t.Run("on, strict email verification issues nothing, "+mode.name, func(t *testing.T) {
			env := registerSessionEnv(t, mount, func(c *auth.Config) {
				c.IssueSessionOnRegister = true
				c.EmailVerificationMode = auth.EmailVerificationModeStrict
			})
			req := env.Request(http.MethodPost, "/register", credentials("strict@example.com"))
			if mode.bearer {
				req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
			}
			assertRegisteredWithoutSession(t, env, env.Do(req), mode.bearer)

			login := env.Do(env.Request(http.MethodPost, "/login", credentials("strict@example.com")))
			AssertStatus(t, login, http.StatusForbidden)
		})
	}
}
