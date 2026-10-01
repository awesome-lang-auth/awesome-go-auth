package wiretest

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Conformance cases for the passwordless entry points and the TOTP second
// factor: wire-contract §3.
//
// The credential the send routes mint never reaches the response, so the
// assertions come at it from three sides: the body is pinned to exactly
// {"success":true}, the store is read directly to prove the route really did
// mint and persist something, and Env.Delivered is read to prove it was handed
// to the delivery seam. A handler that returned 200 without calling the service
// passes the first and fails the others; one that stored a credential nobody
// could receive passes the first two and fails the third.

const testTenant = "t1"

// phoneUserStore gives every user a phone number on the id and email lookups.
// The port has no add-phone route yet (that is item 4 of the umbrella issue),
// and /sms/send branches on the stored number, so the store is where the fact
// has to come from.
type phoneUserStore struct {
	*auth.MemoryUserStore
	phone string
}

func (s phoneUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	user, err := s.MemoryUserStore.GetUserByID(ctx, id, tenantID)
	if err == nil {
		user.PhoneNumber = s.phone
	}
	return user, err
}

func (s phoneUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) {
	user, err := s.MemoryUserStore.GetUserByEmail(ctx, email, tenantID)
	if err == nil {
		user.PhoneNumber = s.phone
	}
	return user, err
}

// require2FAUserStore flags require2FA on the id lookup only. Login reads the
// user by email and therefore still succeeds, which is exactly the case
// /2fa/disable has to handle: a flag set after the caller's token was issued.
// A handler that trusted the token's user instead of re-reading would let the
// disable through.
type require2FAUserStore struct {
	*auth.MemoryUserStore
}

func (s require2FAUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	user, err := s.MemoryUserStore.GetUserByID(ctx, id, tenantID)
	if err == nil {
		user.Require2FA = true
	}
	return user, err
}

// failingSettingsStore is a settings store that is never reachable, which is
// what the /2fa/disable fail-closed case needs: the route has to answer 500
// rather than read the failure as permission to turn the second factor off.
type failingSettingsStore struct{}

func (failingSettingsStore) GetSettings(context.Context) (auth.AuthSettings, error) {
	return auth.AuthSettings{}, errors.New("settings store unavailable")
}

func (failingSettingsStore) UpdateSettings(context.Context, auth.AuthSettings) (auth.AuthSettings, error) {
	return auth.AuthSettings{}, errors.New("settings store unavailable")
}

// seedSettings returns a memory settings store already holding settings, the
// state an administrator leaves behind after using the Control panel.
func seedSettings(t *testing.T, settings auth.AuthSettings) auth.SettingsStore {
	t.Helper()
	store := auth.NewMemorySettingsStore()
	if _, err := store.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatalf("seeding the settings store: %v", err)
	}
	return store
}

func boolPtr(b bool) *bool { return &b }

// totpCode is an independent RFC 6238 implementation. Generating the code with
// the library's own helper would make every TOTP assertion here tautological.
func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("decode totp secret %q: %v", secret, err)
	}
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		uint32(sum[offset+3])&0xff
	return fmt.Sprintf("%06d", truncated%1000000)
}

// bearer marks a request as a bearer client and, when a token is given,
// authenticates it.
func passwordlessBearer(req *http.Request, accessToken string) *http.Request {
	req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	return req
}

// csrfMirror replays a response's cookies and mirrors the CSRF one into the
// double-submit header, the way a browser client does.
func csrfMirror(req *http.Request, rec *httptest.ResponseRecorder) *http.Request {
	Replay(req, rec)
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, auth.CSRFTokenCookieName) && c.Value != "" {
			req.Header.Set(auth.CSRFHeaderName, c.Value)
		}
	}
	return req
}

func passwordlessStoredUser(t *testing.T, store *auth.MemoryUserStore, id string) auth.User {
	t.Helper()
	user, err := store.GetUserByID(context.Background(), id, testTenant)
	if err != nil {
		t.Fatalf("read back user %q: %v", id, err)
	}
	return user
}

func tempTokenFor(t *testing.T, env *Env, user auth.User) string {
	t.Helper()
	token, err := env.Auth.IssueTempToken(context.Background(), user)
	if err != nil {
		t.Fatalf("issue temp token: %v", err)
	}
	return token
}

// -----------------------------------------------------------------------------
// magic link
// -----------------------------------------------------------------------------

func testMagicLink(t *testing.T, mount Mounter) {
	t.Run("send stores a link, delivers it, and answers with nothing else", func(t *testing.T) {
		store := auth.NewMemoryUserStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
		user, _ := env.Seed("magic@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"email": "magic@example.com", "tenantId": testTenant,
		}))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success")
		if body["success"] != true {
			t.Fatalf("success = %v", body["success"])
		}
		stored := passwordlessStoredUser(t, store, user.ID).MagicLinkTokenHash
		if stored == "" {
			t.Fatal("no magic-link token was stored: the route answered without doing anything")
		}
		// The link has to have gone somewhere, and it has to be the link the
		// store will accept — a token delivered to the recipient that the store
		// never learned about verifies as invalid.
		if len(env.Delivered.MagicLinks) != 1 {
			t.Fatalf("delivered %d links, want 1: the route stored a credential nobody received", len(env.Delivered.MagicLinks))
		}
		delivered := env.Delivered.MagicLinks[0]
		if delivered.Email != "magic@example.com" {
			t.Errorf("delivered to %q", delivered.Email)
		}
		if delivered.Token == "" || delivered.Token == stored {
			t.Errorf("delivered token %q: want the plaintext, not the stored hash", delivered.Token)
		}
		// The credential must still not be on the wire.
		if strings.Contains(rec.Body.String(), delivered.Token) {
			t.Errorf("the response body carries the magic-link token: %s", rec.Body.String())
		}
	})

	t.Run("send is silent about an unknown address", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"email": "nobody@example.com", "tenantId": testTenant,
		}))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if len(env.Delivered.MagicLinks) != 0 {
			t.Errorf("something was mailed for an address the store does not have: %+v", env.Delivered.MagicLinks)
		}
	})

	// A deployment with nothing to mail the link with answers 500, and it answers
	// it before the lookup: an address the store does not have gets the same 500,
	// not the 200 the anti-enumeration path would otherwise give
	// (magic-link.strategy.ts:12-14 precedes :15).
	t.Run("send without email delivery configured", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			email string
		}{
			{name: "known address", email: "magicunconfigured@example.com"},
			{name: "unknown address", email: "nobody@example.com"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				store := auth.NewMemoryUserStore()
				env := NewEnvWithoutDelivery(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
				user, _ := env.Seed("magicunconfigured@example.com")

				rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
					"email": tc.email, "tenantId": testTenant,
				}))

				AssertError(t, rec, http.StatusInternalServerError, "Email not configured", auth.CodeEmailNotConfigured)
				if hash := passwordlessStoredUser(t, store, user.ID).MagicLinkTokenHash; hash != "" {
					t.Errorf("a token was stored for a deployment that cannot send it: %q", hash)
				}
			})
		}
	})

	// The 2fa branch reaches the same check, but only after the step-up token has
	// been resolved: an unusable tempToken still answers 401, because the
	// reference's email check lives in the strategy behind the route.
	t.Run("send in 2fa mode without email delivery configured", func(t *testing.T) {
		env := NewEnvWithoutDelivery(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("magicstepupunconfigured@example.com")

		bad := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"mode": auth.StepUpMode, "tempToken": "not-a-token",
		}))
		AssertError(t, bad, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)

		good := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"mode": auth.StepUpMode, "tempToken": tempTokenFor(t, env, user),
		}))
		AssertError(t, good, http.StatusInternalServerError, "Email not configured", auth.CodeEmailNotConfigured)
	})

	// Code-less on purpose: the reference answers this one inline.
	t.Run("send without an address", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{"tenantId": testTenant}))
		AssertError(t, rec, http.StatusBadRequest, "email is required", "")
	})

	t.Run("send in 2fa mode without a tempToken", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{"mode": auth.StepUpMode}))
		AssertError(t, rec, http.StatusBadRequest, "tempToken is required for 2FA mode", auth.CodeTempTokenRequired)
	})

	t.Run("send in 2fa mode with an unusable tempToken", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"mode": auth.StepUpMode, "tempToken": "not-a-token",
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
	})

	// The address is the tempToken's, not the body's: otherwise anyone holding a
	// step-up token could have the link mailed somewhere else.
	t.Run("send in 2fa mode ignores the body address", func(t *testing.T) {
		store := auth.NewMemoryUserStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
		subject, _ := env.Seed("subject@example.com")
		other, _ := env.Seed("other@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"mode":      auth.StepUpMode,
			"tempToken": tempTokenFor(t, env, subject),
			"email":     "other@example.com",
			"tenantId":  testTenant,
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if passwordlessStoredUser(t, store, subject.ID).MagicLinkTokenHash == "" {
			t.Error("the step-up subject got no magic link")
		}
		if passwordlessStoredUser(t, store, other.ID).MagicLinkTokenHash != "" {
			t.Error("the body address got a magic link: the 2fa branch must ignore it")
		}
	})

	// The link base and the language are resolved from the request exactly as
	// on the three §2 mailing routes — the same table, the same probe shape (see
	// runLinkResolutionCases). The reference passes
	// buildUiLink(resolveSiteUrl(req, …), '') and emailLang to the strategy on
	// both branches (auth.router.ts:1104, 1114).
	t.Run("link resolution", func(t *testing.T) {
		runLinkResolutionCases(t, mount, magicLinkSendProbe)
	})

	// The 2fa branch resolves the same way, so a step-up link points back at the
	// front end that asked for it (auth.router.ts:1104).
	t.Run("send in 2fa mode resolves the link base and forwards emailLang too", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSiteURLs("https://www.example.com", "https://app.example.com"))
		subject, _ := env.Seed("magicstepuplink@example.com")

		req := env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"mode": auth.StepUpMode, "tempToken": tempTokenFor(t, env, subject), "emailLang": "it",
		})
		req.Header.Set("Origin", "https://app.example.com")
		AssertStatus(t, env.Do(req), http.StatusOK)

		if len(env.Delivered.MagicLinks) != 1 {
			t.Fatalf("delivered %d links, want 1", len(env.Delivered.MagicLinks))
		}
		got := env.Delivered.MagicLinks[0]
		if got.LinkBase != "https://app.example.com/auth" || got.Lang != "it" {
			t.Errorf("delivered LinkBase/Lang = %q/%q, want https://app.example.com/auth/it", got.LinkBase, got.Lang)
		}
	})

	t.Run("verify in cookie mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("magicverify@example.com")
		token := magicLinkToken(t, env, user)

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": token}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
	})

	t.Run("verify in bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("magicbearer@example.com")
		token := magicLinkToken(t, env, user)

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": token}), ""))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	t.Run("verify with an unusable token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": "bogus"}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid magic link token", auth.CodeInvalidMagicLink)
	})

	t.Run("verify burns the link", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("magiconce@example.com")
		token := magicLinkToken(t, env, user)

		AssertStatus(t, env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": token})), http.StatusOK)
		replay := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": token}))
		AssertError(t, replay, http.StatusUnauthorized, "Invalid magic link token", auth.CodeInvalidMagicLink)
	})

	t.Run("verify in 2fa mode without a tempToken", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"mode": auth.StepUpMode, "token": "irrelevant",
		}))
		AssertError(t, rec, http.StatusBadRequest, "tempToken is required for 2FA mode", auth.CodeTempTokenRequired)
	})

	t.Run("verify in 2fa mode with an unusable tempToken", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"mode": auth.StepUpMode, "tempToken": "not-a-token", "token": "irrelevant",
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
	})

	t.Run("verify in 2fa mode issues tokens", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("magicstepup@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"mode":      auth.StepUpMode,
			"tempToken": tempTokenFor(t, env, user),
			"token":     magicLinkToken(t, env, user),
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
	})

	// A link that belongs to somebody else must not complete the challenge, and
	// must not issue anything.
	t.Run("verify in 2fa mode refuses another user's link", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		subject, _ := env.Seed("stepupsubject@example.com")
		stranger, _ := env.Seed("stranger@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"mode":      auth.StepUpMode,
			"tempToken": tempTokenFor(t, env, subject),
			"token":     magicLinkToken(t, env, stranger),
		}))

		AssertError(t, rec, http.StatusUnauthorized, "Token mismatch", auth.CodeTokenMismatch)
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)
	})

	// "Issues nothing" has to mean nothing in the store either. A refusal that
	// still creates a session hands the link's owner a login they never
	// performed — visible in their session list and revocable only by them —
	// which is worse than the 401 suggests. The reference reaches issueTokens
	// only after the id comparison (auth.router.ts:1150-1154).
	t.Run("verify in 2fa mode creates no session on a mismatch", func(t *testing.T) {
		sessions := auth.NewMemorySessionStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(sessions))
		subject, _ := env.Seed("nosessionsubject@example.com")
		stranger, _ := env.Seed("nosessionstranger@example.com")
		before := sessionCount(t, sessions, stranger)
		token := magicLinkToken(t, env, stranger)

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"mode":      auth.StepUpMode,
			"tempToken": tempTokenFor(t, env, subject),
			"token":     token,
		}))

		AssertError(t, rec, http.StatusUnauthorized, "Token mismatch", auth.CodeTokenMismatch)
		if after := sessionCount(t, sessions, stranger); after != before {
			t.Errorf("the refused request left the link's owner with %d sessions, was %d", after, before)
		}
		// The link is still burned, as in the reference: the strategy clears it
		// before the router compares ids (magic-link.strategy.ts:50).
		replay := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": token}))
		AssertError(t, replay, http.StatusUnauthorized, "Invalid magic link token", auth.CodeInvalidMagicLink)
	})

	// The email-verification side effect belongs to the login branch only
	// (auth.router.ts:1158-1164; the 2fa branch at :1134-1156 has no such call).
	// A second factor is not a proof of address ownership in the reference's
	// model, and an emailVerificationMode gate elsewhere reads the flag.
	t.Run("verify in login mode marks the email verified", func(t *testing.T) {
		store := auth.NewMemoryUserStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
		user := seedUnverified(t, store, "unverifiedlogin@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"token": magicLinkToken(t, env, user),
		}))

		AssertStatus(t, rec, http.StatusOK)
		if !passwordlessStoredUser(t, store, user.ID).IsEmailVerified {
			t.Error("a login-mode magic link did not verify the address")
		}
	})

	t.Run("verify in 2fa mode leaves the email unverified", func(t *testing.T) {
		store := auth.NewMemoryUserStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
		user := seedUnverified(t, store, "unverifiedstepup@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"mode":      auth.StepUpMode,
			"tempToken": tempTokenFor(t, env, user),
			"token":     magicLinkToken(t, env, user),
		}))

		AssertStatus(t, rec, http.StatusOK)
		if passwordlessStoredUser(t, store, user.ID).IsEmailVerified {
			t.Error("the step-up branch verified the address: that side effect is login-mode only")
		}
	})
}

// sessionCount reports how many sessions a user holds. It is the store-side half
// of "the refusal issued nothing": the wire half (no cookies, no tokens in the
// body) can pass while a session row exists.
func sessionCount(t *testing.T, sessions *auth.MemorySessionStore, user auth.User) int {
	t.Helper()
	list, err := sessions.ListSessionsForUser(context.Background(), user.ID, user.TenantID)
	if err != nil {
		t.Fatalf("list sessions for %s: %v", user.ID, err)
	}
	return len(list)
}

// seedUnverified puts an unverified user straight into the store. Register
// cannot produce one: the default EmailVerificationMode is "none", which marks
// every new account verified, and there is no exported option to change it.
func seedUnverified(t *testing.T, store *auth.MemoryUserStore, email string) auth.User {
	t.Helper()
	user, err := store.CreateUser(context.Background(), auth.User{
		ID: "usr_" + strings.ReplaceAll(strings.Split(email, "@")[0], ".", ""),
		// No password hash: nothing in these cases logs in.
		Email: email, TenantID: testTenant, IsEmailVerified: false, CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("seed unverified %s: %v", email, err)
	}
	return user
}

// magicLinkToken mints a link through the service. The send route delivers the
// token rather than returning it, so a test that wants to verify a link asks for
// one directly instead of digging it out of Env.Delivered.
// magicLinkSendProbe is the /magic-link/send probe for runLinkResolutionCases:
// one login-mode send, reporting the LinkBase and Lang the recording sender
// NewEnv wires was handed.
func magicLinkSendProbe(t *testing.T, mount Mounter, cfg auth.HTTPConfig, site []auth.Option, headers map[string]string, emailLang string) (string, string) {
	t.Helper()
	env := NewEnv(t, mount, cfg, site...)
	env.Seed("linkmagic@example.com")

	body := map[string]any{"email": "linkmagic@example.com", "tenantId": testTenant}
	if emailLang != "" {
		body["emailLang"] = emailLang
	}
	rec := env.Do(withHeaders(env.Request(http.MethodPost, "/magic-link/send", body), headers))
	AssertStatus(t, rec, http.StatusOK)
	if len(env.Delivered.MagicLinks) != 1 {
		t.Fatalf("delivered %d links, want 1", len(env.Delivered.MagicLinks))
	}
	return env.Delivered.MagicLinks[0].LinkBase, env.Delivered.MagicLinks[0].Lang
}

func magicLinkToken(t *testing.T, env *Env, user auth.User) string {
	t.Helper()
	token, err := env.Auth.SendMagicLink(context.Background(), auth.MagicLinkSendInput{Email: user.Email, TenantID: user.TenantID})
	if err != nil {
		t.Fatalf("send magic link: %v", err)
	}
	if token == "" {
		t.Fatal("send magic link returned no token")
	}
	return token
}

// -----------------------------------------------------------------------------
// SMS OTP
// -----------------------------------------------------------------------------

func newPhoneEnv(t *testing.T, mount Mounter) (*Env, *auth.MemoryUserStore) {
	t.Helper()
	backing := auth.NewMemoryUserStore()
	store := phoneUserStore{MemoryUserStore: backing, phone: "+15555550100"}
	return NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store)), backing
}

func testSMSOTP(t *testing.T, mount Mounter) {
	t.Run("send by address stores a code, delivers it, and answers with nothing else", func(t *testing.T) {
		env, store := newPhoneEnv(t, mount)
		user, _ := env.Seed("sms@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"email": "sms@example.com", "tenantId": testTenant,
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		stored := passwordlessStoredUser(t, store, user.ID).SMSCodeHash
		if stored == "" {
			t.Fatal("no SMS code was stored: the route answered without doing anything")
		}
		if len(env.Delivered.SMSCodes) != 1 {
			t.Fatalf("delivered %d codes, want 1: the route stored a credential nobody received", len(env.Delivered.SMSCodes))
		}
		delivered := env.Delivered.SMSCodes[0]
		if delivered.Phone != "+15555550100" {
			t.Errorf("texted %q, want the stored number", delivered.Phone)
		}
		if len(delivered.Code) != 6 || delivered.Code == stored {
			t.Errorf("delivered code %q: want the six-digit plaintext, not the stored hash", delivered.Code)
		}
		if strings.Contains(rec.Body.String(), delivered.Code) {
			t.Errorf("the response body carries the SMS code: %s", rec.Body.String())
		}
	})

	// config.sms is checked at the very top of the reference's route
	// (auth.router.ts:1178-1181), before the body is even destructured, so every
	// one of these answers the same 500. The unknown-address case is the one that
	// matters: with the check any lower it would answer 200 "sent" from a
	// deployment that cannot text anybody.
	t.Run("send without SMS delivery configured", func(t *testing.T) {
		cases := []struct {
			name string
			body map[string]any
		}{
			{name: "by address", body: map[string]any{"email": "smsunconfigured@example.com", "tenantId": testTenant}},
			{name: "by unknown address", body: map[string]any{"email": "nobody@example.com", "tenantId": testTenant}},
			{name: "by unknown id", body: map[string]any{"userId": "usr_missing", "tenantId": testTenant}},
			{name: "with no id or address", body: map[string]any{"tenantId": testTenant}},
			{name: "in 2fa mode with no tempToken", body: map[string]any{"mode": auth.StepUpMode}},
			{name: "in 2fa mode with an unusable tempToken", body: map[string]any{"mode": auth.StepUpMode, "tempToken": "not-a-token"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				backing := auth.NewMemoryUserStore()
				store := phoneUserStore{MemoryUserStore: backing, phone: "+15555550100"}
				env := NewEnvWithoutDelivery(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
				user, _ := env.Seed("smsunconfigured@example.com")

				rec := env.Do(env.Request(http.MethodPost, "/sms/send", tc.body))

				AssertError(t, rec, http.StatusInternalServerError, "SMS is not configured", auth.CodeSMSNotConfigured)
				if hash := passwordlessStoredUser(t, backing, user.ID).SMSCodeHash; hash != "" {
					t.Errorf("a code was stored for a deployment that cannot send it: %q", hash)
				}
			})
		}

		// Also with a body the route would otherwise have accepted outright.
		t.Run("by id", func(t *testing.T) {
			backing := auth.NewMemoryUserStore()
			store := phoneUserStore{MemoryUserStore: backing, phone: "+15555550100"}
			env := NewEnvWithoutDelivery(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
			user, _ := env.Seed("smsunconfiguredid@example.com")

			rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
				"userId": user.ID, "tenantId": testTenant,
			}))

			AssertError(t, rec, http.StatusInternalServerError, "SMS is not configured", auth.CodeSMSNotConfigured)
			if hash := passwordlessStoredUser(t, backing, user.ID).SMSCodeHash; hash != "" {
				t.Errorf("a code was stored for a deployment that cannot send it: %q", hash)
			}
		})
	})

	// Magic-link delivery is a separate half of the seam: an SMS-only deployment
	// still texts codes, and a mail-only one still mails links.
	t.Run("send needs only the SMS half of the seam", func(t *testing.T) {
		backing := auth.NewMemoryUserStore()
		store := phoneUserStore{MemoryUserStore: backing, phone: "+15555550100"}
		env := NewEnvWithoutDelivery(t, mount, auth.DefaultHTTPConfig(),
			auth.WithUserStore(store),
			auth.WithSMSCodeSender(func(context.Context, auth.SMSCodeDelivery) error { return nil }),
		)
		user, _ := env.Seed("smsonly@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"userId": user.ID, "tenantId": testTenant,
		}))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")

		// ...and the mail half is still missing, which only /magic-link/send cares about.
		mail := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"email": "smsonly@example.com", "tenantId": testTenant,
		}))
		AssertError(t, mail, http.StatusInternalServerError, "Email not configured", auth.CodeEmailNotConfigured)
	})

	t.Run("send by id", func(t *testing.T) {
		env, store := newPhoneEnv(t, mount)
		user, _ := env.Seed("smsid@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"userId": user.ID, "tenantId": testTenant,
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if passwordlessStoredUser(t, store, user.ID).SMSCodeHash == "" {
			t.Fatal("no SMS code was stored")
		}
	})

	// The asymmetry is the reference's: an unknown address is answered with
	// silence, an unknown id with a 404.
	t.Run("send to an unknown address is silent", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"email": "nobody@example.com", "tenantId": testTenant,
		}))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
	})

	t.Run("send to an unknown id", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"userId": "usr_missing", "tenantId": testTenant,
		}))
		AssertError(t, rec, http.StatusNotFound, "User not found", "")
	})

	t.Run("send without an id or an address", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{"tenantId": testTenant}))
		AssertError(t, rec, http.StatusBadRequest, "userId or email is required", "")
	})

	t.Run("send to a user with no phone number", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("nophone@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"userId": user.ID, "tenantId": testTenant,
		}))
		AssertError(t, rec, http.StatusBadRequest, "User does not have a phone number configured", auth.CodePhoneNotSet)
	})

	// A number stored as sent (#35) is tested as the reference tests it,
	// untrimmed (`if (!user.phoneNumber)`, auth.router.ts:1830 at v1.10.8): one
	// of only spaces is a number, and the code is sent to it.
	t.Run("send to a user whose number is only spaces", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("spacephone@example.com")
		add := env.Request(http.MethodPost, "/add-phone", map[string]string{"phoneNumber": " "})
		add.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertStatus(t, env.Do(add), http.StatusOK)

		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"userId": user.ID, "tenantId": testTenant,
		}))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if n := len(env.Delivered.SMSCodes); n != 1 {
			t.Fatalf("%d SMS code(s) delivered, want 1", n)
		}
	})

	t.Run("send in 2fa mode without a tempToken", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{"mode": auth.StepUpMode}))
		AssertError(t, rec, http.StatusBadRequest, "tempToken is required for 2FA mode", auth.CodeTempTokenRequired)
	})

	t.Run("send in 2fa mode with an unusable tempToken", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"mode": auth.StepUpMode, "tempToken": "not-a-token",
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
	})

	t.Run("send in 2fa mode", func(t *testing.T) {
		env, store := newPhoneEnv(t, mount)
		user, _ := env.Seed("smsstepup@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"mode": auth.StepUpMode, "tempToken": tempTokenFor(t, env, user),
		}))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if passwordlessStoredUser(t, store, user.ID).SMSCodeHash == "" {
			t.Fatal("no SMS code was stored for the step-up subject")
		}
	})

	t.Run("verify in cookie mode", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		user, _ := env.Seed("smsverify@example.com")
		code := smsCode(t, env, user)

		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"userId": user.ID, "code": code, "tenantId": testTenant,
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
	})

	t.Run("verify in bearer mode", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		user, _ := env.Seed("smsbearer@example.com")
		code := smsCode(t, env, user)

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"userId": user.ID, "code": code, "tenantId": testTenant,
		}), ""))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	t.Run("verify with the wrong code", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		user, _ := env.Seed("smswrong@example.com")
		smsCode(t, env, user)

		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"userId": user.ID, "code": "000000", "tenantId": testTenant,
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired SMS code", "")
	})

	// An id nobody has is a credential failure, not a 404. The reference resolves
	// the user inside the strategy, where an unknown id and a wrong code are the
	// same `return false` (sms.strategy.ts:24-25 -> auth.router.ts:1277); its 404
	// sits after that check and only fires if the user vanished mid-request. A 404
	// here would also make this unauthenticated route a user-existence oracle.
	t.Run("verify with an unknown id", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"userId": "usr_nobody", "code": "123456", "tenantId": testTenant,
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired SMS code", "")
	})

	// Same in the step-up branch: the tempToken names a user the store lost.
	t.Run("verify in 2fa mode for a user the store lost", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		token := tempTokenFor(t, env, auth.User{ID: "usr_nobody", TenantID: testTenant, Email: "gone@example.com"})
		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"mode": auth.StepUpMode, "tempToken": token, "code": "123456",
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired SMS code", "")
	})

	t.Run("verify without an id", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{"code": "123456"}))
		AssertError(t, rec, http.StatusBadRequest, "userId is required", "")
	})

	t.Run("verify in 2fa mode without a tempToken", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"mode": auth.StepUpMode, "code": "123456",
		}))
		AssertError(t, rec, http.StatusBadRequest, "tempToken is required for 2FA mode", auth.CodeTempTokenRequired)
	})

	t.Run("verify in 2fa mode with an unusable tempToken", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"mode": auth.StepUpMode, "tempToken": "not-a-token", "code": "123456",
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
	})

	t.Run("verify in 2fa mode issues tokens", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		user, _ := env.Seed("smsstepupverify@example.com")
		code := smsCode(t, env, user)

		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"mode": auth.StepUpMode, "tempToken": tempTokenFor(t, env, user), "code": code,
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
	})
}

// smsCode mints a code through the service: the send route delivers it rather
// than returning it. See magicLinkToken.
func smsCode(t *testing.T, env *Env, user auth.User) string {
	t.Helper()
	code, err := env.Auth.SendSMSCode(context.Background(), auth.SMSCodeSendInput{UserID: user.ID, TenantID: user.TenantID})
	if err != nil {
		t.Fatalf("send sms code: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("sms code = %q, want six digits", code)
	}
	return code
}

// -----------------------------------------------------------------------------
// TOTP
// -----------------------------------------------------------------------------

func testTwoFactor(t *testing.T, mount Mounter) {
	t.Run("setup returns the enrolment material and nothing else", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("setup2fa@example.com")

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/setup", nil), tokens.AccessToken))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		// No success envelope, and no qrCode: the reference's PNG data URL needs
		// a QR encoder this port does not carry.
		AssertKeys(t, body, "secret", "otpauthUrl")
		secret, _ := body["secret"].(string)
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil || secret == "" {
			t.Fatalf("secret = %q, want base32", secret)
		}
		// The label is otplib's issuer:account, percent-escaped as
		// encodeURIComponent does it, which is what the reference's otplib emits:
		// the @ is %40, the separating colon is bare. With no app name configured
		// the issuer is Config.Issuer, awesome-go-auth on the defaults (deviation
		// totp-issuer-defaults-to-config-issuer).
		want := "otpauth://totp/awesome-go-auth:setup2fa%40example.com?algorithm=SHA1&digits=6&issuer=awesome-go-auth&period=30&secret=" + secret
		if body["otpauthUrl"] != want {
			t.Fatalf("otpauthUrl = %v, want %q", body["otpauthUrl"], want)
		}
	})

	// The reference's twoFactor.appName (auth.router.ts:830). It is the issuer
	// the authenticator app displays, so it reaches the wire twice — as the label
	// prefix and as the issuer parameter — and a space in it is %20 in both, as
	// encodeURIComponent renders it; never the "+" of form encoding.
	t.Run("setup labels the URI with the configured app name", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithTwoFactorAppName("Example App"))
		_, tokens := env.Seed("appname@example.com")

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/setup", nil), tokens.AccessToken))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		secret, _ := body["secret"].(string)
		want := "otpauth://totp/Example%20App:appname%40example.com?algorithm=SHA1&digits=6&issuer=Example%20App&period=30&secret=" + secret
		if body["otpauthUrl"] != want {
			t.Fatalf("otpauthUrl = %v, want %q", body["otpauthUrl"], want)
		}
	})

	t.Run("setup is a fresh secret every call", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("setuptwice@example.com")
		first := Body(t, env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/setup", nil), tokens.AccessToken)))["secret"]
		second := Body(t, env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/setup", nil), tokens.AccessToken)))["secret"]
		if first == second {
			t.Fatal("two setups returned the same secret")
		}
	})

	// 403 with no code, as everywhere else behind the access-token middleware.
	// No CSRF pair is needed to get here: enforcement is scoped to requests that
	// carry an access-token cookie, so a credential-less request is passed through
	// to the auth gate exactly as in the reference.
	t.Run("setup without a credential", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/2fa/setup", nil))
		AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
	})

	// The ordering, stated as its own case. The reference checks the access token
	// first and the CSRF header second (auth.middleware.ts:29-32 then :33-42), so a
	// cookie client with neither hears "No access token provided" — not
	// CSRF_INVALID, which is what this port answered while its CSRF middleware
	// judged every unsafe method in front of the auth gate. The three enrolment
	// routes are the first unsafe authenticated routes in the port, which is why the
	// difference first became visible here.
	t.Run("a cookie client with no credential is answered by the auth gate", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/2fa/setup", nil))
		// The empty code argument asserts that no "code" field is present at all,
		// which is what tells this answer apart from a CSRF refusal.
		AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
	})

	t.Run("verify-setup enables the factor", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("enrol@example.com")
		enrolTOTP(t, env, tokens.AccessToken)

		me := env.Do(passwordlessBearer(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), tokens.AccessToken))
		AssertStatus(t, me, http.StatusOK)
		if Body(t, me)["isTotpEnabled"] != true {
			t.Fatalf("isTotpEnabled = %v after enrolment", Body(t, me)["isTotpEnabled"])
		}
	})

	// 400 here, 401 on /2fa/verify, both code-less: the two routes disagree in
	// the reference.
	t.Run("verify-setup with the wrong code", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("enrolbad@example.com")
		secret, _ := Body(t, env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/setup", nil), tokens.AccessToken)))["secret"].(string)

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
			"token": "000000", "secret": secret,
		}), tokens.AccessToken))
		AssertError(t, rec, http.StatusBadRequest, "Invalid TOTP code", "")
	})

	t.Run("verify in cookie mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("stepuptotp@example.com")
		secret := enrolTOTP(t, env, tokens.AccessToken)

		rec := env.Do(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": tempTokenFor(t, env, user), "totpCode": totpCode(t, secret, time.Now()),
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
	})

	t.Run("verify in bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("stepuptotpbearer@example.com")
		secret := enrolTOTP(t, env, tokens.AccessToken)

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": tempTokenFor(t, env, user), "totpCode": totpCode(t, secret, time.Now()),
		}), ""))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	// The documented inconsistency: the same failure the magic-link and SMS
	// routes report as INVALID_TEMP_TOKEN is INVALID_ACCESS_TOKEN here, and an
	// absent tempToken lands in the same place because this route has no
	// missing-token branch at all.
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{name: "an unusable tempToken", body: map[string]any{"tempToken": "not-a-token", "totpCode": "123456"}},
		{name: "no tempToken at all", body: map[string]any{"totpCode": "123456"}},
	} {
		t.Run("verify with "+tc.name, func(t *testing.T) {
			env := NewEnv(t, mount, auth.DefaultHTTPConfig())
			rec := env.Do(env.Request(http.MethodPost, "/2fa/verify", tc.body))
			AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired access token", auth.CodeInvalidAccessToken)
		})
	}

	t.Run("verify with the wrong code", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("stepupbadcode@example.com")
		enrolTOTP(t, env, tokens.AccessToken)

		rec := env.Do(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": tempTokenFor(t, env, user), "totpCode": "000000",
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid TOTP code", "")
		AssertNoCookie(t, rec, hostAccess)
	})

	t.Run("verify for a user who never enrolled", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("neverenrolled@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": tempTokenFor(t, env, user), "totpCode": "123456",
		}))
		AssertError(t, rec, http.StatusBadRequest, "User not found or 2FA not set up", "")
	})

	t.Run("disable", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("disable2fa@example.com")
		enrolTOTP(t, env, tokens.AccessToken)

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")

		me := env.Do(passwordlessBearer(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), tokens.AccessToken))
		if Body(t, me)["isTotpEnabled"] != false {
			t.Fatal("the factor survived /2fa/disable")
		}
	})

	t.Run("disable refuses a user who must keep 2FA", func(t *testing.T) {
		store := require2FAUserStore{MemoryUserStore: auth.NewMemoryUserStore()}
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
		_, tokens := env.Seed("mustkeep@example.com")

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens.AccessToken))
		AssertError(t, rec, http.StatusForbidden, "Cannot disable 2FA: required for your account", auth.CodeTwoFactorRequired)
	})

	t.Run("disable refuses under a system-wide policy", func(t *testing.T) {
		// The account is seeded, and its session opened, by an instance without
		// the policy: under Require2FA registration issues no session (the
		// login would answer a challenge instead, #21). The instance under test
		// shares its stores and its secret, so the token is a live one there.
		users, sessions := auth.NewMemoryUserStore(), auth.NewMemorySessionStore()
		seeder := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(users), auth.WithSessionStore(sessions))
		_, tokens := seeder.Seed("policy@example.com")
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(users), auth.WithSessionStore(sessions), auth.WithRequire2FA(true))

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens.AccessToken))
		AssertError(t, rec, http.StatusForbidden, "Cannot disable 2FA: required by system policy", auth.CodeTwoFactorRequired)
	})

	// The reference's own term for the same refusal: require2FA read from the
	// settings store an administrator writes through the Control panel, checked
	// after the per-user flag (auth.router.ts:890-896). The two refusals share
	// the 2FA_REQUIRED code and differ only in the message.
	t.Run("disable refuses under a seeded settings store", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(),
			auth.WithSettingsStore(seedSettings(t, auth.AuthSettings{Require2FA: boolPtr(true)})))
		_, tokens := env.Seed("settingspolicy@example.com")
		// Enrolled first, so the refusal is protecting a factor that exists: the
		// same 403 would come back for a user who never set one up, and that case
		// would prove nothing about the policy.
		enrolTOTP(t, env, tokens.AccessToken)

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens.AccessToken))
		AssertError(t, rec, http.StatusForbidden, "Cannot disable 2FA: required by system policy", auth.CodeTwoFactorRequired)

		me := env.Do(passwordlessBearer(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), tokens.AccessToken))
		if Body(t, me)["isTotpEnabled"] != true {
			t.Fatal("the factor was disabled despite the stored require2FA")
		}
	})

	// The order of the two refusals, which is the only thing that decides which
	// message a client sees when both terms hold: the reference checks the
	// per-user flag first (:884-888) and the stored setting second (:890-896), so
	// a user carrying require2FA on a deployment whose store also requires it is
	// told it is required for their account, not by system policy. Without this
	// case the two checks could be swapped and every other assertion here would
	// still pass.
	t.Run("disable reports the per-user reason when both terms hold", func(t *testing.T) {
		store := require2FAUserStore{MemoryUserStore: auth.NewMemoryUserStore()}
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store),
			auth.WithSettingsStore(seedSettings(t, auth.AuthSettings{Require2FA: boolPtr(true)})))
		_, tokens := env.Seed("bothterms@example.com")

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens.AccessToken))
		AssertError(t, rec, http.StatusForbidden, "Cannot disable 2FA: required for your account", auth.CodeTwoFactorRequired)
	})

	// A store that holds settings but not this one changes nothing: the
	// email-verification settings are stored and never consulted, here or at
	// login (reference-issues N36, reproduced deliberately).
	t.Run("disable succeeds when the settings store does not require 2FA", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(),
			auth.WithSettingsStore(seedSettings(t, auth.AuthSettings{
				Require2FA:               boolPtr(false),
				RequireEmailVerification: boolPtr(true),
			})))
		_, tokens := env.Seed("settingsallows@example.com")
		enrolTOTP(t, env, tokens.AccessToken)

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
	})

	// Fail closed. A settings store that cannot answer must not be read as
	// permission to drop the factor, and the status is the reference's: its
	// getSettings throw leaves the route through handleError, which answers 500
	// {"error":"Internal server error"} with no code (auth.router.ts:899-901,
	// :189-195).
	t.Run("disable answers 500 when the settings store fails", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(),
			auth.WithSettingsStore(failingSettingsStore{}))
		_, tokens := env.Seed("settingsdown@example.com")
		enrolTOTP(t, env, tokens.AccessToken)

		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens.AccessToken))
		AssertError(t, rec, http.StatusInternalServerError, "Internal server error", "")

		// And the factor is still on: the refusal is a refusal, not a 500 after
		// the disable went through.
		me := env.Do(passwordlessBearer(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), tokens.AccessToken))
		if Body(t, me)["isTotpEnabled"] != true {
			t.Fatal("the factor was disabled behind a failing settings store")
		}
	})

	// The enrolment routes are the only three in this section behind the auth
	// middleware, so they are the only three a cookie client must double-submit
	// for. The four send/verify routes are unauthenticated and exempt, which the
	// cases above rely on by never sending a CSRF header.
	t.Run("setup is CSRF-protected for cookie clients", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("csrf2fa@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("csrf2fa@example.com")))

		bare := env.Do(Replay(env.Request(http.MethodPost, "/2fa/setup", nil), login))
		AssertError(t, bare, http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)

		mirrored := env.Do(csrfMirror(env.Request(http.MethodPost, "/2fa/setup", nil), login))
		AssertStatus(t, mirrored, http.StatusOK)
		AssertKeys(t, Body(t, mirrored), "secret", "otpauthUrl")
	})
}

// enrolTOTP walks the stateless enrolment: /2fa/setup hands out a secret, the
// client proves it can generate a code from it, and only then is it stored.
func enrolTOTP(t *testing.T, env *Env, accessToken string) string {
	t.Helper()
	setup := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/setup", nil), accessToken))
	AssertStatus(t, setup, http.StatusOK)
	secret, _ := Body(t, setup)["secret"].(string)
	if secret == "" {
		t.Fatal("setup returned no secret")
	}
	verify := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
		"token": totpCode(t, secret, time.Now()), "secret": secret,
	}), accessToken))
	AssertStatus(t, verify, http.StatusOK)
	AssertKeys(t, Body(t, verify), "success")
	return secret
}

// -----------------------------------------------------------------------------
// the mode switch
// -----------------------------------------------------------------------------

// testStepUpModeDefault pins the client-pinned invariant from issue #22: `mode`
// is optional and only the exact string "2fa" selects the step-up branch. One
// shipped client sends mode:"login" and another omits the field, so every value
// that is not "2fa" — absent, "login", empty, wrongly cased, garbage — has to
// reach the identical branch.
//
// Each route is probed with a body that fails differently in the two branches:
// the login branch gets far enough to answer for the credential it was given,
// while the step-up branch stops at the missing tempToken. A handler that
// mistook any of these values for "2fa" answers 400 TEMP_TOKEN_REQUIRED and
// fails here.
// testStepUpEmptyBody pins that a request with no body at all is answered as a
// request whose fields are simply absent, route by route.
//
// The reference has no body validation of its own: express.json() leaves
// req.body as {} when there is nothing to parse, so each route reaches its own
// per-field check and answers `email is required`, `userId is required`,
// INVALID_MAGIC_LINK, INVALID_ACCESS_TOKEN. Answering `400 Invalid request body`
// instead collapses four distinct, actionable failures into one a client cannot
// route on — and the four adapters did not even agree, because echo's binder
// tolerates a zero-length body where the other three refused it.
//
// Malformed JSON is a different case and is still 400 INVALID_BODY (pinned for
// /register in testRegister); only emptiness is tolerated. The bodies asserted
// here are exactly the ones the same route gives for a JSON body that omits the
// same fields, which is what makes "an empty body means every field omitted"
// checkable rather than a claim about each route in isolation.
func testStepUpEmptyBody(t *testing.T, mount Mounter) {
	cases := []struct {
		route   string
		status  int
		message string
		code    string
	}{
		{route: "/magic-link/send", status: http.StatusBadRequest, message: "email is required"},
		{route: "/magic-link/verify", status: http.StatusUnauthorized, message: "Invalid magic link token", code: auth.CodeInvalidMagicLink},
		{route: "/sms/send", status: http.StatusBadRequest, message: "userId or email is required"},
		{route: "/sms/verify", status: http.StatusBadRequest, message: "userId is required"},
		// No missing-tempToken branch on this one, by contract: an absent token
		// fails verification and lands on INVALID_ACCESS_TOKEN.
		{route: "/2fa/verify", status: http.StatusUnauthorized, message: "Invalid or expired access token", code: auth.CodeInvalidAccessToken},
	}
	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			env := NewEnv(t, mount, auth.DefaultHTTPConfig())
			// Content-Type is set and the body is empty, which is what a client
			// sending no payload actually puts on the wire.
			AssertError(t, env.Do(env.Request(http.MethodPost, tc.route, nil)), tc.status, tc.message, tc.code)
		})
	}

	// The one body-reading route behind the access-token middleware. Its answer to
	// an omitted code is a 400 and an empty body has to reach the same place.
	t.Run("/2fa/verify-setup", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("emptybodyenrol@example.com")
		rec := env.Do(passwordlessBearer(env.Request(http.MethodPost, "/2fa/verify-setup", nil), tokens.AccessToken))
		AssertError(t, rec, http.StatusBadRequest, "Invalid TOTP code", "")
	})

	// Malformed JSON is still refused as malformed, on every one of them.
	t.Run("malformed bodies are still refused", func(t *testing.T) {
		for _, route := range []string{"/magic-link/send", "/magic-link/verify", "/sms/send", "/sms/verify", "/2fa/verify"} {
			t.Run(route, func(t *testing.T) {
				env := NewEnv(t, mount, auth.DefaultHTTPConfig())
				req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+route, stringReader("{not json"))
				req.Header.Set("Content-Type", "application/json")
				AssertError(t, env.Do(req), http.StatusBadRequest, "Invalid request body", auth.CodeInvalidBody)
			})
		}
	})
}

func testStepUpModeDefault(t *testing.T, mount Mounter) {
	loginModes := []struct {
		name string
		mode any
	}{
		{name: "absent", mode: nil},
		{name: "login", mode: "login"},
		{name: "empty", mode: ""},
		{name: "wrongly cased", mode: "2FA"},
		{name: "garbage", mode: "banana"},
	}

	routes := []struct {
		name  string
		route string
		body  func(env *Env) map[string]any
		// login is the answer the login branch gives this body.
		status  int
		message string
		code    string
	}{
		{
			name:  "magic-link/send",
			route: "/magic-link/send",
			body: func(*Env) map[string]any {
				return map[string]any{"tenantId": testTenant}
			},
			status: http.StatusBadRequest, message: "email is required",
		},
		{
			name:  "magic-link/verify",
			route: "/magic-link/verify",
			body: func(*Env) map[string]any {
				return map[string]any{"token": "bogus"}
			},
			status: http.StatusUnauthorized, message: "Invalid magic link token", code: auth.CodeInvalidMagicLink,
		},
		{
			name:  "sms/send",
			route: "/sms/send",
			body: func(*Env) map[string]any {
				return map[string]any{"tenantId": testTenant}
			},
			status: http.StatusBadRequest, message: "userId or email is required",
		},
		{
			name:  "sms/verify",
			route: "/sms/verify",
			body: func(*Env) map[string]any {
				return map[string]any{"code": "123456"}
			},
			status: http.StatusBadRequest, message: "userId is required",
		},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			for _, mode := range loginModes {
				t.Run(mode.name, func(t *testing.T) {
					env := NewEnv(t, mount, auth.DefaultHTTPConfig())
					body := route.body(env)
					if mode.mode != nil {
						body["mode"] = mode.mode
					}
					AssertError(t, env.Do(env.Request(http.MethodPost, route.route, body)), route.status, route.message, route.code)
				})
			}

			t.Run("2fa selects the step-up branch", func(t *testing.T) {
				env := NewEnv(t, mount, auth.DefaultHTTPConfig())
				body := route.body(env)
				body["mode"] = auth.StepUpMode
				AssertError(t, env.Do(env.Request(http.MethodPost, route.route, body)),
					http.StatusBadRequest, "tempToken is required for 2FA mode", auth.CodeTempTokenRequired)
			})
		})
	}
}
