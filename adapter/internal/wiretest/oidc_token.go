package wiretest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// The token endpoint's flows, on all four adapters: PKCE verification (RFC
// 7636), client_secret_basic beside client_secret_post (RFC 6749 §2.3.1), and
// the refresh_token grant (RFC 6749 §6) with rotation and reuse detection
// (RFC 9700 §4.14.2), issued only for offline_access (OIDC Core §11).
//
// As for the rest of the OIDC group nothing here is cited to the reference,
// which ships no authorization server (auth.router.ts:473-503 is its whole IdP
// surface: the JWKS route). Every refusal is the RFC 6749 §5.2 body.

// A code_verifier and its S256 code_challenge, computed independently of the
// package: printf %s "$v" | openssl dgst -sha256 -binary | base64 | tr "+/" "-_" | tr -d "=".
const (
	testPKCEVerifier  = "dBjftJeZ4CVP-mJ92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testPKCEChallenge = "ngF5GsXcbwljx6u133FFr3Xht9xooA_DuaX_3QwODtc"
)

// assertTokenRefusal holds one refusal of the token endpoint: the status, the
// RFC 6749 §5.2 JSON body with its error code, the two cache headers §5.2
// requires, no cookie, and nothing of the tokens it declined to issue.
func assertTokenRefusal(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	AssertStatus(t, rec, status)
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json — the token endpoint refuses with the RFC 6749 §5.2 body", got)
	}
	for header, want := range map[string]string{"Cache-Control": "no-store", "Pragma": "no-cache"} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	AssertNoCookies(t, rec)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode refusal %q: %v", rec.Body.String(), err)
	}
	if body["error"] != code {
		t.Errorf("error = %v, want %q (body %s)", body["error"], code, rec.Body.String())
	}
	for key := range body {
		if key != "error" && key != "error_description" {
			t.Errorf("a refusal carries %q: %s", key, rec.Body.String())
		}
	}
}

// oidcToken posts a token request with client_secret_post for client.
func oidcToken(env *Env, form url.Values, clientID, secret string) *httptest.ResponseRecorder {
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)
	return env.Do(oidcForm(env, auth.OIDCTokenPath, form))
}

// oidcIssueCode seeds a user once per env and signs it in at POST /authorize
// with the extra query parameters, returning the code from the redirect.
func oidcIssueCode(t *testing.T, env *Env, email string, extra url.Values) string {
	t.Helper()
	q := url.Values{
		"client_id":    {testOIDCClientID},
		"redirect_uri": {testOIDCRedirectURI},
		"state":        {"opaque-state"},
	}
	for k, v := range extra {
		q[k] = v
	}
	form := url.Values{"email": {email}, "password": {"password1"}, "tenant_id": {"t1"}}
	req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+auth.OIDCAuthorizePath+"?"+q.Encode(),
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := env.Do(req)
	AssertStatus(t, rec, http.StatusFound)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in the redirect: %q", loc.RawQuery)
	}
	return code
}

// assertTokenSuccess holds a 200 of the token endpoint and returns its body.
func assertTokenSuccess(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	AssertStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (RFC 6749 §5.1)", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache (RFC 6749 §5.1)", got)
	}
	AssertNoCookies(t, rec)
	body := Body(t, rec)
	assertNonEmptyString(t, body, "access_token")
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", body["token_type"])
	}
	return body
}

func codeGrant(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testOIDCRedirectURI}}
}

func refreshGrant(token string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
}

func testOIDCToken(t *testing.T, mount Mounter) {
	pkce := url.Values{"code_challenge": {testPKCEChallenge}, "code_challenge_method": {"S256"}}

	t.Run("PKCE", func(t *testing.T) {
		env := newOIDCEnv(t, mount)
		env.Seed("pkce@example.com")

		t.Run("the matching verifier redeems the code", func(t *testing.T) {
			form := codeGrant(oidcIssueCode(t, env, "pkce@example.com", pkce))
			form.Set("code_verifier", testPKCEVerifier)
			assertTokenSuccess(t, oidcToken(env, form, testOIDCClientID, testOIDCClientSecret))
		})
		t.Run("a mismatched verifier is invalid_grant", func(t *testing.T) {
			form := codeGrant(oidcIssueCode(t, env, "pkce@example.com", pkce))
			form.Set("code_verifier", strings.Repeat("x", 43))
			assertTokenRefusal(t, oidcToken(env, form, testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_grant")
		})
		t.Run("a missing verifier is invalid_grant", func(t *testing.T) {
			form := codeGrant(oidcIssueCode(t, env, "pkce@example.com", pkce))
			assertTokenRefusal(t, oidcToken(env, form, testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_grant")
		})
		t.Run("a code without a challenge needs no verifier", func(t *testing.T) {
			form := codeGrant(oidcIssueCode(t, env, "pkce@example.com", nil))
			assertTokenSuccess(t, oidcToken(env, form, testOIDCClientID, testOIDCClientSecret))
		})
		t.Run("authorize refuses plain with a redirect", func(t *testing.T) {
			q := url.Values{
				"client_id":             {testOIDCClientID},
				"redirect_uri":          {testOIDCRedirectURI},
				"state":                 {"opaque-state"},
				"code_challenge":        {testPKCEVerifier},
				"code_challenge_method": {"plain"},
			}
			rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.OIDCAuthorizePath+"?"+q.Encode(), nil))
			AssertStatus(t, rec, http.StatusFound)
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if got := loc.Scheme + "://" + loc.Host + loc.Path; got != testOIDCRedirectURI {
				t.Fatalf("redirected to %s, want the registered redirect_uri", got)
			}
			if lq := loc.Query(); lq.Get("error") != "invalid_request" || lq.Get("state") != "opaque-state" || lq.Get("code") != "" {
				t.Fatalf("redirect query = %q, want error=invalid_request with the state and no code", loc.RawQuery)
			}
		})
	})

	t.Run("client_secret_basic", func(t *testing.T) {
		env := newOIDCEnv(t, mount)
		env.Seed("basic@example.com")
		basic := func(form url.Values, id, secret string) *httptest.ResponseRecorder {
			req := oidcForm(env, auth.OIDCTokenPath, form)
			req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
			return env.Do(req)
		}

		t.Run("authenticates the client", func(t *testing.T) {
			assertTokenSuccess(t, basic(codeGrant(oidcIssueCode(t, env, "basic@example.com", nil)),
				testOIDCClientID, testOIDCClientSecret))
		})
		t.Run("a wrong secret is a 401 with a Basic challenge", func(t *testing.T) {
			rec := basic(codeGrant(oidcIssueCode(t, env, "basic@example.com", nil)), testOIDCClientID, "not-the-secret")
			assertTokenRefusal(t, rec, http.StatusUnauthorized, "invalid_client")
			if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
				t.Errorf("WWW-Authenticate = %q, want a Basic challenge (RFC 6749 §5.2)", got)
			}
		})
		t.Run("both methods at once are invalid_request", func(t *testing.T) {
			form := codeGrant(oidcIssueCode(t, env, "basic@example.com", nil))
			form.Set("client_id", testOIDCClientID)
			form.Set("client_secret", testOIDCClientSecret)
			assertTokenRefusal(t, basic(form, testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_request")
		})
		t.Run("a different client_id beside it is invalid_request", func(t *testing.T) {
			form := codeGrant(oidcIssueCode(t, env, "basic@example.com", nil))
			form.Set("client_id", testOIDCOtherClientID)
			assertTokenRefusal(t, basic(form, testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_request")
		})
		t.Run("a wrong post secret stays a 401 without a challenge", func(t *testing.T) {
			rec := oidcToken(env, codeGrant(oidcIssueCode(t, env, "basic@example.com", nil)), testOIDCClientID, "nope")
			assertTokenRefusal(t, rec, http.StatusUnauthorized, "invalid_client")
			if got := rec.Header().Get("WWW-Authenticate"); got != "" {
				t.Errorf("WWW-Authenticate = %q on a client_secret_post attempt", got)
			}
		})
	})

	t.Run("refresh_token grant", func(t *testing.T) {
		env := newOIDCEnv(t, mount)
		env.Seed("offline@example.com")
		offline := func(t *testing.T, scope string) map[string]any {
			t.Helper()
			code := oidcIssueCode(t, env, "offline@example.com", url.Values{"scope": {scope}})
			return assertTokenSuccess(t, oidcToken(env, codeGrant(code), testOIDCClientID, testOIDCClientSecret))
		}
		refreshToken := func(t *testing.T, body map[string]any) string {
			t.Helper()
			token, _ := body["refresh_token"].(string)
			if token == "" {
				t.Fatalf("no refresh_token in %v", body)
			}
			return token
		}

		t.Run("no refresh token without offline_access", func(t *testing.T) {
			body := offline(t, "openid email")
			if _, ok := body["refresh_token"]; ok {
				t.Fatalf("a refresh token was issued without offline_access: %v", body)
			}
		})
		t.Run("issue and rotate", func(t *testing.T) {
			first := refreshToken(t, offline(t, "openid offline_access"))
			rec := oidcToken(env, refreshGrant(first), testOIDCClientID, testOIDCClientSecret)
			body := assertTokenSuccess(t, rec)
			second := refreshToken(t, body)
			if second == first {
				t.Fatal("the refresh token was not rotated")
			}
			if body["scope"] != "openid offline_access" {
				t.Errorf("scope = %v, want the granted scope", body["scope"])
			}
			assertNonEmptyString(t, body, "id_token")
			// The refreshed access token is a working bearer credential.
			me := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.OIDCUserInfoPath, nil)
			me.Header.Set("Authorization", "Bearer "+body["access_token"].(string))
			AssertStatus(t, env.Do(me), http.StatusOK)
			// And the rotated token rotates in turn.
			assertTokenSuccess(t, oidcToken(env, refreshGrant(second), testOIDCClientID, testOIDCClientSecret))
		})
		t.Run("over client_secret_basic", func(t *testing.T) {
			token := refreshToken(t, offline(t, "openid offline_access"))
			req := oidcForm(env, auth.OIDCTokenPath, refreshGrant(token))
			req.SetBasicAuth(testOIDCClientID, testOIDCClientSecret)
			assertTokenSuccess(t, env.Do(req))
		})
		t.Run("reuse revokes the family", func(t *testing.T) {
			first := refreshToken(t, offline(t, "openid offline_access"))
			second := refreshToken(t, assertTokenSuccess(t,
				oidcToken(env, refreshGrant(first), testOIDCClientID, testOIDCClientSecret)))
			assertTokenRefusal(t, oidcToken(env, refreshGrant(first), testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_grant")
			assertTokenRefusal(t, oidcToken(env, refreshGrant(second), testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_grant")
		})
		t.Run("another client is invalid_grant and revokes the family", func(t *testing.T) {
			token := refreshToken(t, offline(t, "openid offline_access"))
			assertTokenRefusal(t, oidcToken(env, refreshGrant(token), testOIDCOtherClientID, testOIDCOtherClientSecret),
				http.StatusBadRequest, "invalid_grant")
			assertTokenRefusal(t, oidcToken(env, refreshGrant(token), testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_grant")
		})
		t.Run("scope narrows and does not widen", func(t *testing.T) {
			token := refreshToken(t, offline(t, "openid email offline_access"))
			form := refreshGrant(token)
			form.Set("scope", "email")
			body := assertTokenSuccess(t, oidcToken(env, form, testOIDCClientID, testOIDCClientSecret))
			if body["scope"] != "email" {
				t.Errorf("scope = %v, want the narrowed %q", body["scope"], "email")
			}
			if _, ok := body["id_token"]; ok {
				t.Errorf("an id_token was issued for a scope without openid: %v", body)
			}
			form = refreshGrant(refreshToken(t, body))
			form.Set("scope", "openid profile")
			assertTokenRefusal(t, oidcToken(env, form, testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_scope")
		})
		t.Run("an unknown token is invalid_grant", func(t *testing.T) {
			assertTokenRefusal(t, oidcToken(env, refreshGrant("never-issued"), testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_grant")
		})
	})

	t.Run("hardening", func(t *testing.T) {
		env := newOIDCEnv(t, mount)
		env.Seed("hard@example.com")

		t.Run("a verifier for a code without a challenge is a downgrade", func(t *testing.T) {
			// RFC 9700 §2.1.1.
			form := codeGrant(oidcIssueCode(t, env, "hard@example.com", nil))
			form.Set("code_verifier", testPKCEVerifier)
			assertTokenRefusal(t, oidcToken(env, form, testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_grant")
		})
		t.Run("redirect_uri must match the authorization request", func(t *testing.T) {
			// RFC 6749 §4.1.3.
			form := codeGrant(oidcIssueCode(t, env, "hard@example.com", nil))
			form.Del("redirect_uri")
			assertTokenRefusal(t, oidcToken(env, form, testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_grant")
			form = codeGrant(oidcIssueCode(t, env, "hard@example.com", nil))
			form.Set("redirect_uri", "https://rp.example.com/elsewhere")
			assertTokenRefusal(t, oidcToken(env, form, testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_grant")
		})
		t.Run("credentials in the query string are refused", func(t *testing.T) {
			// RFC 6749 §2.3.1 and §3.2: body parameters only.
			form := codeGrant(oidcIssueCode(t, env, "hard@example.com", nil))
			form.Set("client_id", testOIDCClientID)
			req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+auth.OIDCTokenPath+"?"+
				url.Values{"client_secret": {testOIDCClientSecret}}.Encode(), strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			assertTokenRefusal(t, env.Do(req), http.StatusBadRequest, "invalid_request")
		})
		t.Run("a replayed code revokes the grant it produced", func(t *testing.T) {
			// RFC 6749 §4.1.2.
			code := oidcIssueCode(t, env, "hard@example.com", url.Values{"scope": {"openid offline_access"}})
			body := assertTokenSuccess(t, oidcToken(env, codeGrant(code), testOIDCClientID, testOIDCClientSecret))
			refresh, _ := body["refresh_token"].(string)
			assertTokenRefusal(t, oidcToken(env, codeGrant(code), testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_grant")
			assertTokenRefusal(t, oidcToken(env, refreshGrant(refresh), testOIDCClientID, testOIDCClientSecret),
				http.StatusBadRequest, "invalid_grant")
		})
	})

	t.Run("public client", func(t *testing.T) {
		idp, err := auth.NewIDP(
			auth.IDPConfig{Issuer: testIDPIssuer, Signer: testIDPKey(), KeyID: testIDPKeyID},
			nil,
			auth.IDPClient{ClientID: "wiretest-spa", RedirectURIs: []string{testOIDCRedirectURI}},
		)
		if err != nil {
			t.Fatal(err)
		}
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIDP(idp))
		env.Seed("spa@example.com")
		issue := func(t *testing.T, extra url.Values) string {
			t.Helper()
			q := url.Values{"client_id": {"wiretest-spa"}, "redirect_uri": {testOIDCRedirectURI}, "state": {"s"}}
			for k, v := range extra {
				q[k] = v
			}
			form := url.Values{"email": {"spa@example.com"}, "password": {"password1"}, "tenant_id": {"t1"}}
			req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+auth.OIDCAuthorizePath+"?"+q.Encode(),
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := env.Do(req)
			AssertStatus(t, rec, http.StatusFound)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			return loc.Query().Get("code")
		}

		t.Run("authorize requires PKCE", func(t *testing.T) {
			if code := issue(t, nil); code != "" {
				t.Fatalf("a public client got a code without a code_challenge")
			}
		})
		t.Run("client_id alone with PKCE authenticates", func(t *testing.T) {
			form := codeGrant(issue(t, pkce))
			form.Set("client_id", "wiretest-spa")
			form.Set("code_verifier", testPKCEVerifier)
			assertTokenSuccess(t, env.Do(oidcForm(env, auth.OIDCTokenPath, form)))
		})
		t.Run("an empty secret is not a credential", func(t *testing.T) {
			form := codeGrant(issue(t, pkce))
			form.Set("code_verifier", testPKCEVerifier)
			assertTokenRefusal(t, oidcToken(env, form, "wiretest-spa", ""), http.StatusUnauthorized, "invalid_client")
		})
		t.Run("discovery advertises none", func(t *testing.T) {
			doc := assertOIDCDiscoveryDocument(t,
				env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.OIDCDiscoveryPath, nil)))
			assertOIDCStringList(t, doc, "token_endpoint_auth_methods_supported",
				"client_secret_basic", "client_secret_post", "none")
		})
	})

	t.Run("the refresh grant can be switched off", func(t *testing.T) {
		idp, err := auth.NewIDP(
			auth.IDPConfig{Issuer: testIDPIssuer, Signer: testIDPKey(), KeyID: testIDPKeyID, DisableRefreshTokenGrant: true},
			nil,
			auth.IDPClient{ClientID: testOIDCClientID, ClientSecret: testOIDCClientSecret, RedirectURIs: []string{testOIDCRedirectURI}},
		)
		if err != nil {
			t.Fatal(err)
		}
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIDP(idp))
		env.Seed("off@example.com")
		body := assertTokenSuccess(t, oidcToken(env,
			codeGrant(oidcIssueCode(t, env, "off@example.com", url.Values{"scope": {"openid offline_access"}})),
			testOIDCClientID, testOIDCClientSecret))
		if _, ok := body["refresh_token"]; ok {
			t.Fatalf("a refresh token was issued with the grant off: %v", body)
		}
		assertTokenRefusal(t, oidcToken(env, refreshGrant("x"), testOIDCClientID, testOIDCClientSecret),
			http.StatusBadRequest, "unsupported_grant_type")
		doc := assertOIDCDiscoveryDocument(t,
			env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.OIDCDiscoveryPath, nil)))
		assertOIDCStringList(t, doc, "grant_types_supported", "authorization_code")
		assertOIDCStringList(t, doc, "scopes_supported", "openid", "email", "profile")
	})
}
