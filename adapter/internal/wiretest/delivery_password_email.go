package wiretest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// Conformance cases for the delivery seam of the three §2 routes that mint a
// credential: POST /forgot-password, POST /send-verification-email and
// POST /change-email/request.
//
// The credential never appears in a response, so "the route sent the right thing"
// cannot be asserted from the body and is not worth asserting from the store
// either — a stored hash cannot tell a delivered token from one dropped on the
// floor. Each flow is therefore driven end to end: the recorded delivery is
// handed straight back to the route that spends the token, and only that route's
// answer decides whether the sender got the real thing. Nothing here compares
// against a value the test computed itself.
//
// Three behaviours are pinned per sender — the round trip, the store-then-send
// order, and a stored credential surviving a failed send — plus the answer an
// unconfigured deployment gets, which is a 200 with no mail on all three routes
// because the reference sends nothing and still succeeds there (auth.router.ts:
// 787-792, 956-961, 1027-1032).

// senderEnv mounts an adapter whose seam carries only the senders the case under
// test asks for. It starts from NewEnvWithoutDelivery on purpose: these three
// senders are independent of each other and of the magic-link and SMS halves, and
// starting from "nothing wired" is what proves it.
func senderEnv(t *testing.T, mount Mounter, opts ...auth.Option) (*Env, *auth.MemoryUserStore) {
	t.Helper()
	store := auth.NewMemoryUserStore()
	env := NewEnvWithoutDelivery(t, mount, auth.DefaultHTTPConfig(),
		append([]auth.Option{auth.WithUserStore(store)}, opts...)...)
	return env, store
}

// errTransportDown stands in for a mail gateway that is not answering.
var errTransportDown = errors.New("mail gateway unreachable")

// assertBodyHidesToken fails when the response leaked the credential the sender
// was given. Every one of these routes answers {"success":true} and nothing else.
func assertBodyHidesToken(t *testing.T, rec *httptest.ResponseRecorder, token string) {
	t.Helper()
	if token != "" && strings.Contains(rec.Body.String(), token) {
		t.Errorf("the response body carries the token: %s", rec.Body.String())
	}
}

func testPasswordEmailDelivery(t *testing.T, mount Mounter) {
	t.Run("PasswordReset", func(t *testing.T) { testPasswordResetDelivery(t, mount) })
	t.Run("EmailVerification", func(t *testing.T) { testEmailVerificationDelivery(t, mount) })
	t.Run("EmailChange", func(t *testing.T) { testEmailChangeDelivery(t, mount) })
	t.Run("LinkResolution", func(t *testing.T) {
		t.Run("forgot-password", func(t *testing.T) { runLinkResolutionCases(t, mount, forgotPasswordProbe) })
		t.Run("send-verification-email", func(t *testing.T) { runLinkResolutionCases(t, mount, sendVerificationEmailProbe) })
		t.Run("change-email-request", func(t *testing.T) { runLinkResolutionCases(t, mount, changeEmailRequestProbe) })
	})
}

// -----------------------------------------------------------------------------
// per-request link base and language
// -----------------------------------------------------------------------------

// The reference builds every emailed link from the request that asked for it:
// the Origin — or the Referer's origin — matched against the site URL
// allowlist, else the first site URL, then the mount prefix and, with the
// static UI enabled, /ui (resolveSiteUrl and buildUiLink, auth.router.ts:233-246
// and 261-271, applied at :785-786, :954-955, :1025-1026 and :1104/:1114). The
// emailLang body field travels to the sender as given (:788, :957, :1028,
// :1104/:1114). The four routes that mail something are probed identically: a
// probe mounts an env, fires one request and reports what its sender was
// handed, and runLinkResolutionCases asserts the same table against each.
//
// What the sender receives is the whole assertion. The body is {"success":true}
// either way, and nothing here pins the shape of the link a mailer builds from
// the base — that is the root package's — only that every adapter resolves the
// same base and forwards the same language for the same request.

// linkProbe fires one request at a mailing route and reports the LinkBase and
// Lang the recording sender received. site configures the site URLs, headers go
// on the request, and emailLang goes in the body when non-empty.
type linkProbe func(t *testing.T, mount Mounter, cfg auth.HTTPConfig, site []auth.Option, headers map[string]string, emailLang string) (linkBase, lang string)

func withHeaders(req *http.Request, headers map[string]string) *http.Request {
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return req
}

func runLinkResolutionCases(t *testing.T, mount Mounter, probe linkProbe) {
	const (
		www = "https://www.example.com"
		app = "https://app.example.com"
	)
	site := []auth.Option{auth.WithSiteURLs(www, app)}

	check := func(t *testing.T, cfg auth.HTTPConfig, opts []auth.Option, headers map[string]string, emailLang, wantBase, wantLang string) {
		t.Helper()
		gotBase, gotLang := probe(t, mount, cfg, opts, headers, emailLang)
		if gotBase != wantBase {
			t.Errorf("delivered LinkBase = %q, want %q", gotBase, wantBase)
		}
		if gotLang != wantLang {
			t.Errorf("delivered Lang = %q, want %q", gotLang, wantLang)
		}
	}

	t.Run("an allowlisted Origin is the link base", func(t *testing.T) {
		check(t, auth.DefaultHTTPConfig(), site, map[string]string{"Origin": app}, "", app+"/auth", "")
	})

	t.Run("an allowlisted Referer origin is the link base when there is no Origin", func(t *testing.T) {
		check(t, auth.DefaultHTTPConfig(), site, map[string]string{"Referer": app + "/account/settings?tab=security"}, "", app+"/auth", "")
	})

	// The allowlist is what keeps a caller from steering somebody's link at an
	// origin of its choosing: an unlisted Origin contributes nothing.
	t.Run("an unlisted Origin falls back to the first site URL", func(t *testing.T) {
		check(t, auth.DefaultHTTPConfig(), site, map[string]string{"Origin": "https://evil.example", "Referer": "https://evil.example/login"}, "", www+"/auth", "")
	})

	t.Run("no Origin and no Referer fall back to the first site URL", func(t *testing.T) {
		check(t, auth.DefaultHTTPConfig(), site, nil, "", www+"/auth", "")
	})

	t.Run("the base follows the mount prefix", func(t *testing.T) {
		cfg := auth.DefaultHTTPConfig()
		cfg.APIPrefix = "/api/auth/"
		check(t, cfg, site, map[string]string{"Origin": app}, "", app+"/api/auth", "")
	})

	t.Run("UI.Enabled points the base at the static UI", func(t *testing.T) {
		cfg := auth.DefaultHTTPConfig()
		cfg.UI.Enabled = true
		check(t, cfg, site, map[string]string{"Origin": app}, "", app+"/auth/ui", "")
	})

	t.Run("emailLang reaches the sender as given", func(t *testing.T) {
		check(t, auth.DefaultHTTPConfig(), site, map[string]string{"Origin": app}, "it", app+"/auth", "it")
	})

	// With no site URL configured the delivery carries no base at all, which is
	// what leaves a ready-made mailer on the static BaseURL it was built with —
	// the arrangement every deployment had before Config.SiteURLs existed.
	t.Run("without site URLs the base is empty", func(t *testing.T) {
		check(t, auth.DefaultHTTPConfig(), nil, map[string]string{"Origin": app}, "", "", "")
	})
}

// The three §2 probes. Each starts from NewEnvWithoutDelivery and wires only
// the sender it records, as senderEnv does.

func forgotPasswordProbe(t *testing.T, mount Mounter, cfg auth.HTTPConfig, site []auth.Option, headers map[string]string, emailLang string) (string, string) {
	t.Helper()
	var delivered []auth.PasswordResetDelivery
	opts := append([]auth.Option{auth.WithPasswordResetSender(func(_ context.Context, d auth.PasswordResetDelivery) error {
		delivered = append(delivered, d)
		return nil
	})}, site...)
	env := NewEnvWithoutDelivery(t, mount, cfg, opts...)
	env.Seed("linkreset@example.com")

	body := map[string]string{"email": "linkreset@example.com", "tenantId": testTenant}
	if emailLang != "" {
		body["emailLang"] = emailLang
	}
	assertSuccessBody(t, env.Do(withHeaders(env.Request(http.MethodPost, "/forgot-password", body), headers)))
	if len(delivered) != 1 {
		t.Fatalf("delivered %d resets, want 1", len(delivered))
	}
	return delivered[0].LinkBase, delivered[0].Lang
}

func sendVerificationEmailProbe(t *testing.T, mount Mounter, cfg auth.HTTPConfig, site []auth.Option, headers map[string]string, emailLang string) (string, string) {
	t.Helper()
	var delivered []auth.EmailVerificationDelivery
	store := auth.NewMemoryUserStore()
	opts := append([]auth.Option{
		auth.WithUserStore(store),
		auth.WithEmailVerificationSender(func(_ context.Context, d auth.EmailVerificationDelivery) error {
			delivered = append(delivered, d)
			return nil
		}),
	}, site...)
	env := NewEnvWithoutDelivery(t, mount, cfg, opts...)
	user, tokens := env.Seed("linkverify@example.com")
	unverify(t, store, user)

	// An empty body is valid on this route, so the language is the only field.
	var body any
	if emailLang != "" {
		body = map[string]string{"emailLang": emailLang}
	}
	assertSuccessBody(t, env.Do(bearer(withHeaders(env.Request(http.MethodPost, "/send-verification-email", body), headers), tokens)))
	if len(delivered) != 1 {
		t.Fatalf("delivered %d verifications, want 1", len(delivered))
	}
	return delivered[0].LinkBase, delivered[0].Lang
}

func changeEmailRequestProbe(t *testing.T, mount Mounter, cfg auth.HTTPConfig, site []auth.Option, headers map[string]string, emailLang string) (string, string) {
	t.Helper()
	var delivered []auth.EmailChangeDelivery
	opts := append([]auth.Option{auth.WithEmailChangeSender(func(_ context.Context, d auth.EmailChangeDelivery) error {
		delivered = append(delivered, d)
		return nil
	})}, site...)
	env := NewEnvWithoutDelivery(t, mount, cfg, opts...)
	_, tokens := env.Seed("linkchange@example.com")

	body := map[string]string{"newEmail": "linkchanged@example.com"}
	if emailLang != "" {
		body["emailLang"] = emailLang
	}
	assertSuccessBody(t, env.Do(bearer(withHeaders(env.Request(http.MethodPost, "/change-email/request", body), headers), tokens)))
	if len(delivered) != 1 {
		t.Fatalf("delivered %d changes, want 1", len(delivered))
	}
	return delivered[0].LinkBase, delivered[0].Lang
}

// -----------------------------------------------------------------------------
// POST /forgot-password
// -----------------------------------------------------------------------------

func testPasswordResetDelivery(t *testing.T, mount Mounter) {
	// The round trip. The delivered token is spent on /reset-password, and the
	// new password is then used to log in — so the assertion is that the
	// recipient of the mail can actually reset the password, not that two strings
	// match.
	t.Run("delivers the token /reset-password accepts", func(t *testing.T) {
		delivered := &Deliveries{}
		env, store := senderEnv(t, mount, auth.WithPasswordResetSender(func(_ context.Context, d auth.PasswordResetDelivery) error {
			delivered.PasswordResets = append(delivered.PasswordResets, d)
			return nil
		}))
		user, _ := env.Seed("resetdelivery@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/forgot-password", map[string]string{
			"email": "resetdelivery@example.com", "tenantId": testTenant,
		}))
		assertSuccessBody(t, rec)

		if len(delivered.PasswordResets) != 1 {
			t.Fatalf("delivered %d resets, want 1: the route stored a credential nobody received", len(delivered.PasswordResets))
		}
		got := delivered.PasswordResets[0]
		if got.Email != user.Email || got.UserID != user.ID || got.TenantID != testTenant {
			t.Errorf("delivery = %+v, want %s/%s/%s", got, user.Email, user.ID, testTenant)
		}
		assertOneTimeToken(t, "delivered reset token", got.Token)
		assertTTL(t, "delivered reset token", &got.ExpiresAt, resetTokenTTL)
		assertBodyHidesToken(t, rec, got.Token)

		spend := env.Do(env.Request(http.MethodPost, "/reset-password", map[string]string{
			"token": got.Token, "password": "deliveredpw1",
		}))
		assertSuccessBody(t, spend)
		login := env.Do(env.Request(http.MethodPost, "/login", map[string]string{
			"email": "resetdelivery@example.com", "password": "deliveredpw1", "tenantId": testTenant,
		}))
		AssertStatus(t, login, http.StatusOK)
		if storedUser(t, store, user).ResetTokenHash != "" {
			t.Error("the reset token survived being spent")
		}
	})

	// Store first, then send. The sender reads the row while the request is still
	// in flight: the hash has to be there already, because a sender that mails a
	// token the store has not learned about yet sends a credential that may never
	// become valid.
	t.Run("stores the token before it sends it", func(t *testing.T) {
		var sawHash string
		store := auth.NewMemoryUserStore()
		env := NewEnvWithoutDelivery(t, mount, auth.DefaultHTTPConfig(),
			auth.WithUserStore(store),
			auth.WithPasswordResetSender(func(ctx context.Context, d auth.PasswordResetDelivery) error {
				stored, err := store.GetUserByID(ctx, d.UserID, d.TenantID)
				if err != nil {
					t.Errorf("read back the user from inside the sender: %v", err)
					return nil
				}
				sawHash = stored.ResetTokenHash
				return nil
			}))
		env.Seed("resetorder@example.com")

		assertSuccessBody(t, env.Do(env.Request(http.MethodPost, "/forgot-password", map[string]string{
			"email": "resetorder@example.com", "tenantId": testTenant,
		})))
		if sawHash == "" {
			t.Error("the sender was called before the token was stored")
		}
	})

	// The case that matters most, and the one that pins the *reason* for the
	// deviation the README registers as "forgot-password: unconditional 200 on
	// delivery failure". A failing sender must not change the answer: a 500 here
	// would be a 500 only for an address that exists, which is the enumeration
	// oracle the route exists to deny. The reference does answer 500
	// (auth.router.ts:796-798) and its own spec marks that an [UNTESTED] oracle;
	// this is the port's deliberate divergence, and the credential still survives.
	//
	// The known/unknown comparison at the end is the assertion that makes the
	// reason true rather than merely intended: with the same broken sender wired,
	// the two addresses must be indistinguishable. Do not weaken it to a bare
	// "status is 200" — a 200 whose body differed would still be an oracle.
	t.Run("a failing sender still gets 200 and keeps the stored token", func(t *testing.T) {
		env, store := senderEnv(t, mount, auth.WithPasswordResetSender(
			func(context.Context, auth.PasswordResetDelivery) error { return errTransportDown },
		))
		user, _ := env.Seed("resetfailed@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/forgot-password", map[string]string{
			"email": "resetfailed@example.com", "tenantId": testTenant,
		}))
		assertSuccessBody(t, rec)
		// No session is issued on this route, whatever delivery did. The CSRF
		// cookie the guard distributes is the only Set-Cookie a caller may see.
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)

		stored := storedUser(t, store, user)
		if stored.ResetTokenHash == "" {
			t.Error("the stored token was rolled back; an undelivered token is harmless and stays")
		}
		assertTTL(t, "reset token", stored.ResetTokenExpiresAt, resetTokenTTL)

		// And the answer is byte-identical to the unknown-address answer, which is
		// what "no oracle" actually means.
		unknown := env.Do(env.Request(http.MethodPost, "/forgot-password", map[string]string{
			"email": "nobody@example.com", "tenantId": testTenant,
		}))
		assertSuccessBody(t, unknown)
		if rec.Body.String() != unknown.Body.String() {
			t.Errorf("failed delivery answered %q, unknown address answered %q", rec.Body.String(), unknown.Body.String())
		}
	})

	// The other half of the same rule: no sender at all. The reference has no
	// not-configured check on this route, so an unconfigured deployment answers
	// 200 and mails nothing (wire-contract §2 "Mailer dispatch order"). This is
	// also what pins the seam as additive — the route behaves exactly as it did
	// before the sender existed.
	t.Run("no sender at all still gets 200 and stores the token", func(t *testing.T) {
		env, store := senderEnv(t, mount)
		user, _ := env.Seed("resetunconfigured@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/forgot-password", map[string]string{
			"email": "resetunconfigured@example.com", "tenantId": testTenant,
		}))
		assertSuccessBody(t, rec)
		if storedUser(t, store, user).ResetTokenHash == "" {
			t.Error("no reset token was persisted")
		}
		if len(env.Delivered.PasswordResets) != 0 {
			t.Errorf("an unconfigured deployment delivered something: %+v", env.Delivered.PasswordResets)
		}
	})
}

// -----------------------------------------------------------------------------
// POST /send-verification-email
// -----------------------------------------------------------------------------

func testEmailVerificationDelivery(t *testing.T, mount Mounter) {
	// The round trip, ending at GET /verify-email — which is the only proof that
	// the delivered token is the one the store will accept. The route is
	// authenticated, and the bearer token is the only gate this case adds.
	t.Run("delivers the token /verify-email accepts", func(t *testing.T) {
		delivered := &Deliveries{}
		env, store := senderEnv(t, mount, auth.WithEmailVerificationSender(func(_ context.Context, d auth.EmailVerificationDelivery) error {
			delivered.EmailVerifications = append(delivered.EmailVerifications, d)
			return nil
		}))
		user, tokens := env.Seed("verifydelivery@example.com")
		unverify(t, store, user)

		rec := env.Do(bearer(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/send-verification-email", nil), tokens))
		assertSuccessBody(t, rec)

		if len(delivered.EmailVerifications) != 1 {
			t.Fatalf("delivered %d verifications, want 1", len(delivered.EmailVerifications))
		}
		got := delivered.EmailVerifications[0]
		if got.Email != user.Email || got.UserID != user.ID || got.TenantID != testTenant {
			t.Errorf("delivery = %+v, want %s/%s/%s", got, user.Email, user.ID, testTenant)
		}
		assertOneTimeToken(t, "delivered verification token", got.Token)
		assertTTL(t, "delivered verification token", &got.ExpiresAt, verifyTokenTTL)
		assertBodyHidesToken(t, rec, got.Token)

		spend := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/verify-email?token="+got.Token, nil))
		assertSuccessBody(t, spend)
		if !storedUser(t, store, user).IsEmailVerified {
			t.Error("the address is still unverified after the delivered token was spent")
		}
	})

	t.Run("stores the token before it sends it", func(t *testing.T) {
		var sawHash string
		store := auth.NewMemoryUserStore()
		env := NewEnvWithoutDelivery(t, mount, auth.DefaultHTTPConfig(),
			auth.WithUserStore(store),
			auth.WithEmailVerificationSender(func(ctx context.Context, d auth.EmailVerificationDelivery) error {
				stored, err := store.GetUserByID(ctx, d.UserID, d.TenantID)
				if err != nil {
					t.Errorf("read back the user from inside the sender: %v", err)
					return nil
				}
				sawHash = stored.EmailVerificationTokenHash
				return nil
			}))
		user, tokens := env.Seed("verifyorder@example.com")
		unverify(t, store, user)

		assertSuccessBody(t, env.Do(bearer(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/send-verification-email", nil), tokens)))
		if sawHash == "" {
			t.Error("the sender was called before the token was stored")
		}
	})

	// This route is authenticated and has no anti-enumeration duty, so the
	// reference's answer to a throwing mailer is reproduced as-is: the generic
	// code-less 500. The token stays stored, exactly as on /magic-link/send.
	t.Run("a failing sender gets the generic 500 and keeps the stored token", func(t *testing.T) {
		env, store := senderEnv(t, mount, auth.WithEmailVerificationSender(
			func(context.Context, auth.EmailVerificationDelivery) error { return errTransportDown },
		))
		user, tokens := env.Seed("verifyfailed@example.com")
		unverify(t, store, user)

		rec := env.Do(bearer(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/send-verification-email", nil), tokens))
		AssertError(t, rec, http.StatusInternalServerError, "Internal server error", "")

		stored := storedUser(t, store, user)
		if stored.EmailVerificationTokenHash == "" {
			t.Error("the stored token was rolled back")
		}
		assertTTL(t, "verification token", stored.EmailVerificationTokenExpiry, verifyTokenTTL)
	})

	t.Run("no sender at all still gets 200 and stores the token", func(t *testing.T) {
		env, store := senderEnv(t, mount)
		user, tokens := env.Seed("verifyunconfigured@example.com")
		unverify(t, store, user)

		rec := env.Do(bearer(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/send-verification-email", nil), tokens))
		assertSuccessBody(t, rec)
		if storedUser(t, store, user).EmailVerificationTokenHash == "" {
			t.Error("no verification token was persisted")
		}
		if len(env.Delivered.EmailVerifications) != 0 {
			t.Errorf("an unconfigured deployment delivered something: %+v", env.Delivered.EmailVerifications)
		}
	})
}

// -----------------------------------------------------------------------------
// POST /change-email/request
// -----------------------------------------------------------------------------

func testEmailChangeDelivery(t *testing.T, mount Mounter) {
	// The round trip, ending at /change-email/confirm. It also pins the recipient
	// of each mail: the request's goes to the NEW address, because it is a
	// verification of the new mailbox (auth.router.ts:1027-1032); the confirm's
	// is the notice to the OLD address, sent once the change is applied
	// (:1060-1066), with no language — the reference's route passes none
	// (:1062, :1065).
	t.Run("delivers the token /change-email/confirm accepts, to the new address", func(t *testing.T) {
		delivered := &Deliveries{}
		env, store := senderEnv(t, mount,
			auth.WithEmailChangeSender(func(_ context.Context, d auth.EmailChangeDelivery) error {
				delivered.EmailChanges = append(delivered.EmailChanges, d)
				return nil
			}),
			auth.WithEmailChangedSender(func(_ context.Context, d auth.EmailChangedDelivery) error {
				delivered.EmailChanged = append(delivered.EmailChanged, d)
				return nil
			}),
		)
		user, tokens := env.Seed("changedelivery@example.com")

		rec := env.Do(bearer(env.Request(http.MethodPost, "/change-email/request", map[string]string{
			"newEmail": "changedelivered@example.com",
		}), tokens))
		assertSuccessBody(t, rec)

		if len(delivered.EmailChanges) != 1 {
			t.Fatalf("delivered %d changes, want 1", len(delivered.EmailChanges))
		}
		got := delivered.EmailChanges[0]
		if got.NewEmail != "changedelivered@example.com" {
			t.Errorf("mailed %q, want the new address changedelivered@example.com", got.NewEmail)
		}
		if strings.Contains(strings.ToLower(got.NewEmail), "changedelivery@") {
			t.Error("mailed the current address; this message verifies the new mailbox")
		}
		if got.UserID != user.ID || got.TenantID != testTenant {
			t.Errorf("delivery = %+v, want %s/%s", got, user.ID, testTenant)
		}
		assertOneTimeToken(t, "delivered email-change token", got.Token)
		assertTTL(t, "delivered email-change token", &got.ExpiresAt, emailChangeTokenTTL)
		assertBodyHidesToken(t, rec, got.Token)

		if len(delivered.EmailChanged) != 0 {
			t.Fatalf("the notice went out before the change was confirmed: %+v", delivered.EmailChanged)
		}
		spend := env.Do(env.Request(http.MethodPost, "/change-email/confirm", map[string]string{"token": got.Token}))
		assertSuccessBody(t, spend)
		if stored := storedUser(t, store, user); stored.Email != "changedelivered@example.com" {
			t.Errorf("address = %q, want changedelivered@example.com", stored.Email)
		}

		if len(delivered.EmailChanged) != 1 {
			t.Fatalf("delivered %d notices, want 1", len(delivered.EmailChanged))
		}
		notice := delivered.EmailChanged[0]
		if notice.OldEmail != "changedelivery@example.com" {
			t.Errorf("notice mailed to %q, want the old address changedelivery@example.com", notice.OldEmail)
		}
		if notice.NewEmail != "changedelivered@example.com" {
			t.Errorf("notice reports %q, want the new address changedelivered@example.com", notice.NewEmail)
		}
		if notice.UserID != user.ID || notice.TenantID != testTenant {
			t.Errorf("notice = %+v, want %s/%s", notice, user.ID, testTenant)
		}
		if notice.Lang != "" {
			t.Errorf("notice Lang = %q, want none: the reference passes no language on confirm", notice.Lang)
		}
	})

	// The reference writes the new address and clears the token before it mails
	// the notice (auth.router.ts:1058-1059 then :1061-1066), so a sender that
	// reads the account back sees the change already in place.
	t.Run("the notice goes out after the change is applied", func(t *testing.T) {
		var sawEmail, sawHash string
		store := auth.NewMemoryUserStore()
		env := NewEnvWithoutDelivery(t, mount, auth.DefaultHTTPConfig(),
			auth.WithUserStore(store),
			auth.WithEmailChangedSender(func(ctx context.Context, d auth.EmailChangedDelivery) error {
				stored, err := store.GetUserByID(ctx, d.UserID, d.TenantID)
				if err != nil {
					t.Errorf("read back the user from inside the sender: %v", err)
					return nil
				}
				sawEmail, sawHash = stored.Email, stored.EmailChangeTokenHash
				return nil
			}))
		user, _ := env.Seed("noticeorder@example.com")
		token, err := env.Auth.Service().RequestEmailChange(context.Background(), auth.ChangeEmailRequestInput{
			UserID: user.ID, TenantID: testTenant, NewEmail: "noticeordered@example.com",
		})
		if err != nil {
			t.Fatalf("mint a token to spend: %v", err)
		}
		assertSuccessBody(t, env.Do(env.Request(http.MethodPost, "/change-email/confirm", map[string]string{"token": token})))
		if sawEmail != "noticeordered@example.com" {
			t.Errorf("address at notice time = %q, want the new one already applied", sawEmail)
		}
		if sawHash != "" {
			t.Error("the token was still stored when the notice went out; the reference clears it first")
		}
	})

	// sendEmailChanged sits inside the route's try block after the change is
	// written (auth.router.ts:1058-1066), so a throwing mailer reaches
	// handleError (:1068-1069): the generic 500, for a change that stays
	// applied. Reproduced rather than softened — rolling the address back
	// would be an invention, and so would a 200.
	t.Run("a failing notice sender gets the generic 500 with the change already applied", func(t *testing.T) {
		env, store := senderEnv(t, mount, auth.WithEmailChangedSender(
			func(context.Context, auth.EmailChangedDelivery) error { return errTransportDown },
		))
		user, _ := env.Seed("noticefailed@example.com")
		token, err := env.Auth.Service().RequestEmailChange(context.Background(), auth.ChangeEmailRequestInput{
			UserID: user.ID, TenantID: testTenant, NewEmail: "noticefaileddelivery@example.com",
		})
		if err != nil {
			t.Fatalf("mint a token to spend: %v", err)
		}
		rec := env.Do(env.Request(http.MethodPost, "/change-email/confirm", map[string]string{"token": token}))
		AssertError(t, rec, http.StatusInternalServerError, "Internal server error", "")

		stored := storedUser(t, store, user)
		if stored.Email != "noticefaileddelivery@example.com" {
			t.Errorf("address = %q, want the new one: the change is committed before the notice", stored.Email)
		}
		if stored.EmailChangeTokenHash != "" || stored.PendingEmail != "" {
			t.Error("the spent token or the pending address survived the failed notice")
		}
		// The token is spent: a retry cannot re-apply or re-notify.
		AssertError(t, env.Do(env.Request(http.MethodPost, "/change-email/confirm", map[string]string{"token": token})),
			http.StatusBadRequest, "Invalid email-change token", "")
	})

	t.Run("no notice sender still gets 200 and applies the change", func(t *testing.T) {
		env, store := senderEnv(t, mount)
		user, _ := env.Seed("noticeunconfigured@example.com")
		token, err := env.Auth.Service().RequestEmailChange(context.Background(), auth.ChangeEmailRequestInput{
			UserID: user.ID, TenantID: testTenant, NewEmail: "noticeunconfigured2@example.com",
		})
		if err != nil {
			t.Fatalf("mint a token to spend: %v", err)
		}
		assertSuccessBody(t, env.Do(env.Request(http.MethodPost, "/change-email/confirm", map[string]string{"token": token})))
		if stored := storedUser(t, store, user); stored.Email != "noticeunconfigured2@example.com" {
			t.Errorf("address = %q, want noticeunconfigured2@example.com", stored.Email)
		}
		if len(env.Delivered.EmailChanged) != 0 {
			t.Errorf("an unconfigured deployment delivered something: %+v", env.Delivered.EmailChanged)
		}
	})

	t.Run("stores the token before it sends it", func(t *testing.T) {
		var sawHash, sawPending string
		store := auth.NewMemoryUserStore()
		env := NewEnvWithoutDelivery(t, mount, auth.DefaultHTTPConfig(),
			auth.WithUserStore(store),
			auth.WithEmailChangeSender(func(ctx context.Context, d auth.EmailChangeDelivery) error {
				stored, err := store.GetUserByID(ctx, d.UserID, d.TenantID)
				if err != nil {
					t.Errorf("read back the user from inside the sender: %v", err)
					return nil
				}
				sawHash, sawPending = stored.EmailChangeTokenHash, stored.PendingEmail
				return nil
			}))
		_, tokens := env.Seed("changeorder@example.com")

		assertSuccessBody(t, env.Do(bearer(env.Request(http.MethodPost, "/change-email/request", map[string]string{
			"newEmail": "changeordered@example.com",
		}), tokens)))
		if sawHash == "" {
			t.Error("the sender was called before the token was stored")
		}
		// The pending address is part of the same write, and the mail is useless
		// without it: confirming resolves the pending column, not the token.
		if sawPending != "changeordered@example.com" {
			t.Errorf("pending address at send time = %q, want changeordered@example.com", sawPending)
		}
	})

	t.Run("a failing sender gets the generic 500 and keeps the stored token", func(t *testing.T) {
		env, store := senderEnv(t, mount, auth.WithEmailChangeSender(
			func(context.Context, auth.EmailChangeDelivery) error { return errTransportDown },
		))
		user, tokens := env.Seed("changefailed@example.com")

		rec := env.Do(bearer(env.Request(http.MethodPost, "/change-email/request", map[string]string{
			"newEmail": "changefaileddelivery@example.com",
		}), tokens))
		AssertError(t, rec, http.StatusInternalServerError, "Internal server error", "")

		stored := storedUser(t, store, user)
		if stored.EmailChangeTokenHash == "" {
			t.Error("the stored token was rolled back")
		}
		if stored.PendingEmail != "changefaileddelivery@example.com" {
			t.Errorf("pending address = %q, want it to survive the failed send", stored.PendingEmail)
		}
		// The address itself must not move: only /change-email/confirm applies it.
		if stored.Email != "changefailed@example.com" {
			t.Errorf("address = %q, want the unchanged one", stored.Email)
		}
	})

	t.Run("no sender at all still gets 200 and stores the token", func(t *testing.T) {
		env, store := senderEnv(t, mount)
		user, tokens := env.Seed("changeunconfigured@example.com")

		rec := env.Do(bearer(env.Request(http.MethodPost, "/change-email/request", map[string]string{
			"newEmail": "changeunconfigured2@example.com",
		}), tokens))
		assertSuccessBody(t, rec)
		stored := storedUser(t, store, user)
		if stored.EmailChangeTokenHash == "" || stored.PendingEmail != "changeunconfigured2@example.com" {
			t.Error("no email-change token was persisted")
		}
		if len(env.Delivered.EmailChanges) != 0 {
			t.Errorf("an unconfigured deployment delivered something: %+v", env.Delivered.EmailChanges)
		}
	})
}
