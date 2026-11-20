package wiretest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// The RefreshSecret group: auth.WithRefreshSecret gives refresh tokens a key of
// their own, the reference's refreshTokenSecret (token.service.ts:67-71, :237
// at 1.10.8), while access tokens stay on WithSecret, its accessTokenSecret.
// What the wire shows is that the whole session flow still works across the
// two keys, and that /refresh refuses a refresh token signed with the access
// key with the same 401 INVALID_REFRESH_TOKEN any unusable refresh token gets
// (auth.router.ts:1121-1130 and token.service.ts:236-240 at 1.10.8; wire.go
// CodeInvalidRefreshToken).

const (
	wiretestAccessSecret  = "wiretest-access-secret-0123456789ab"
	wiretestRefreshSecret = "wiretest-refresh-secret-0123456789a"
)

// resignHS256 re-signs a compact HS256 JWT's header and payload with secret:
// the refresh token a component holding only that secret could mint.
func resignHS256(t *testing.T, token, secret string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", token)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func testRefreshSecret(t *testing.T, mount Mounter) {
	newSplitEnv := func(t *testing.T) *Env {
		return NewEnv(t, mount, auth.DefaultHTTPConfig(),
			auth.WithSecret(wiretestAccessSecret), auth.WithRefreshSecret(wiretestRefreshSecret))
	}

	t.Run("the session flow works across the two keys", func(t *testing.T) {
		env := newSplitEnv(t)
		env.Seed("split@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("split@example.com")))
		AssertStatus(t, login, http.StatusOK)

		refreshed := env.Do(Replay(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/refresh", nil), login))
		AssertStatus(t, refreshed, http.StatusOK)
		AssertKeys(t, Body(t, refreshed), "success")

		me := env.Do(Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), refreshed))
		AssertStatus(t, me, http.StatusOK)
	})

	t.Run("bearer refresh returns a token signed with the refresh key", func(t *testing.T) {
		env := newSplitEnv(t)
		_, tokens := env.Seed("splitbearer@example.com")
		if resignHS256(t, tokens.RefreshToken, wiretestRefreshSecret) != tokens.RefreshToken {
			t.Fatal("the seeded refresh token is not signed with WithRefreshSecret's key")
		}
		if resignHS256(t, tokens.AccessToken, wiretestAccessSecret) != tokens.AccessToken {
			t.Fatal("the seeded access token is not signed with WithSecret's key")
		}

		req := env.Request(http.MethodPost, "/refresh", map[string]string{"refreshToken": tokens.RefreshToken})
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := env.Do(req)
		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		rotated, _ := body["refreshToken"].(string)
		if resignHS256(t, rotated, wiretestRefreshSecret) != rotated {
			t.Error("the rotated refresh token is not signed with WithRefreshSecret's key")
		}
		access, _ := body["accessToken"].(string)
		if resignHS256(t, access, wiretestAccessSecret) != access {
			t.Error("the new access token is not signed with WithSecret's key")
		}
	})

	t.Run("a refresh token signed with the access key is refused", func(t *testing.T) {
		env := newSplitEnv(t)
		_, tokens := env.Seed("splitforged@example.com")
		forged := resignHS256(t, tokens.RefreshToken, wiretestAccessSecret)
		if forged == tokens.RefreshToken {
			t.Fatal("the two keys produced the same signature")
		}
		rec := env.Do(env.Request(http.MethodPost, "/refresh", map[string]string{"refreshToken": forged}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired refresh token", auth.CodeInvalidRefreshToken)
	})

	t.Run("without WithRefreshSecret the access key signs refresh tokens", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSecret(wiretestAccessSecret))
		_, tokens := env.Seed("single@example.com")
		if resignHS256(t, tokens.RefreshToken, wiretestAccessSecret) != tokens.RefreshToken {
			t.Fatal("with no refresh secret, the refresh token must be signed with WithSecret's key")
		}
		rec := env.Do(env.Request(http.MethodPost, "/refresh", map[string]string{"refreshToken": tokens.RefreshToken}))
		AssertStatus(t, rec, http.StatusOK)
	})
}
