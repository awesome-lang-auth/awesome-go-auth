package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The provisioning policy is the one place in the OAuth group where the port
// decides something the reference leaves to the integrator, so the matrix is
// pinned here rather than only through the adapters: every branch of
// HandleCallbackWithPolicy, what each refusal answers, and — as important —
// what a refusal leaves behind, which is nothing.

const provisioningTenant = "t1"

// provisioningFixture is an Auth with its memory stores plus a linked-accounts
// store, which is all HandleCallbackWithPolicy touches.
type provisioningFixture struct {
	auth  *Auth
	users UserStore
	links *MemoryLinkedAccounts
}

func newProvisioningFixture(t *testing.T) *provisioningFixture {
	t.Helper()
	users := NewMemoryUserStore()
	a, err := newTestAuth(WithUserStore(users), WithSessionStore(NewMemorySessionStore()))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return &provisioningFixture{auth: a, users: users, links: NewMemoryLinkedAccounts()}
}

// seed creates an account the way a password registration would: no provider,
// no link row.
func (f *provisioningFixture) seed(t *testing.T, email string) User {
	t.Helper()
	user, err := f.users.CreateUser(context.Background(), User{
		ID: "usr_" + email, Email: email, TenantID: provisioningTenant,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("seed %q: %v", email, err)
	}
	return user
}

func (f *provisioningFixture) callback(info OAuthUserInfo, policy OAuthProvisioning) (User, error) {
	user, _, err := NewOAuthService().HandleCallbackWithPolicy(
		context.Background(), f.auth.service, f.links, info, provisioningTenant, "", policy)
	return user, err
}

func acmeProfile(email string, verified *bool) OAuthUserInfo {
	return OAuthUserInfo{
		ProviderID:    "acme-1",
		Provider:      "acme",
		Email:         email,
		Name:          "OAuth User",
		EmailVerified: verified,
		Raw:           map[string]any{"sub": "acme-1", "email": email},
	}
}

// ── the resolution matrix ────────────────────────────────────────────────────

// An unknown provider account with an unknown address is a new account, and the
// policy decides whether it may be created at all.
func TestOAuthProvisioningCreateBranch(t *testing.T) {
	t.Run("AutoCreate creates the account and links it", func(t *testing.T) {
		f := newProvisioningFixture(t)
		user, err := f.callback(acmeProfile("new@example.com", nil), DefaultOAuthProvisioning())
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		if user.Email != "new@example.com" || user.LoginProvider != "acme" {
			t.Fatalf("user = %+v, want the profile address under loginProvider acme", user)
		}
		if _, err := f.links.FindByProvider(context.Background(), "acme", "acme-1"); err != nil {
			t.Fatalf("provider account was not linked: %v", err)
		}
	})

	t.Run("AutoCreate false refuses and writes nothing", func(t *testing.T) {
		f := newProvisioningFixture(t)
		policy := DefaultOAuthProvisioning()
		policy.AutoCreate = false
		if _, err := f.callback(acmeProfile("new@example.com", nil), policy); !errors.Is(err, errOAuthUserNotProvisioned) {
			t.Fatalf("callback = %v, want errOAuthUserNotProvisioned", err)
		}
		if _, err := f.users.GetUserByEmail(context.Background(), "new@example.com", provisioningTenant); err == nil {
			t.Fatal("a refused callback created the account anyway")
		}
		if _, err := f.links.FindByProvider(context.Background(), "acme", "acme-1"); err == nil {
			t.Fatal("a refused callback wrote a link row")
		}
	})
}

// Decision D-11: the provider's claim decides, and silence means verified —
// which is what this port did before the claim was read at all.
func TestOAuthProvisioningEmailVerifiedOnCreate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verified *bool
		want     bool
	}{
		{"the provider said nothing", nil, true},
		{"the provider said true", boolPtr(true), true},
		{"the provider said false", boolPtr(false), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProvisioningFixture(t)
			user, err := f.callback(acmeProfile("verified@example.com", tc.verified), DefaultOAuthProvisioning())
			if err != nil {
				t.Fatalf("callback: %v", err)
			}
			if user.IsEmailVerified != tc.want {
				t.Fatalf("IsEmailVerified = %v, want %v", user.IsEmailVerified, tc.want)
			}
		})
	}
}

// The address is held by an account nobody linked this provider to: the
// takeover-shaped case the reference's store documentation warns about
// (user-store.interface.ts:105-119), and the one OnEmailMatch exists for.
func TestOAuthProvisioningOnEmailMatch(t *testing.T) {
	t.Run("link signs the holder in and links the provider account", func(t *testing.T) {
		f := newProvisioningFixture(t)
		held := f.seed(t, "held@example.com")
		policy := DefaultOAuthProvisioning()
		policy.OnEmailMatch = OAuthEmailMatchLink
		user, err := f.callback(acmeProfile("held@example.com", nil), policy)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		if user.ID != held.ID {
			t.Fatalf("session user = %q, want the address holder %q", user.ID, held.ID)
		}
		link, err := f.links.FindByProvider(context.Background(), "acme", "acme-1")
		if err != nil || link.UserID != held.ID {
			t.Fatalf("link = %+v (%v), want one pointing at the holder", link, err)
		}
	})

	t.Run("conflict raises the reference error and writes nothing", func(t *testing.T) {
		f := newProvisioningFixture(t)
		f.seed(t, "held@example.com")
		policy := DefaultOAuthProvisioning()
		policy.OnEmailMatch = OAuthEmailMatchConflict

		_, err := f.callback(acmeProfile("held@example.com", nil), policy)
		var conflict *OAuthAccountConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("callback = %v, want *OAuthAccountConflictError", err)
		}
		if !errors.Is(err, ErrOAuthAccountConflict) {
			t.Fatal("the conflict does not unwrap to ErrOAuthAccountConflict")
		}
		if conflict.Email != "held@example.com" || conflict.ProviderAccountID != "acme-1" || conflict.Provider != "acme" {
			t.Fatalf("conflict = %+v, want the reference's {email, providerAccountId} plus the provider", conflict)
		}
		if _, err := f.links.FindByProvider(context.Background(), "acme", "acme-1"); err == nil {
			t.Fatal("the conflict linked the account it refused to link")
		}
	})

	t.Run("reject refuses with the not-provisioned code and writes nothing", func(t *testing.T) {
		f := newProvisioningFixture(t)
		f.seed(t, "held@example.com")
		policy := DefaultOAuthProvisioning()
		policy.OnEmailMatch = OAuthEmailMatchReject

		_, err := f.callback(acmeProfile("held@example.com", nil), policy)
		if !errors.Is(err, errOAuthUserNotProvisioned) {
			t.Fatalf("callback = %v, want errOAuthUserNotProvisioned", err)
		}
		if _, err := f.links.FindByProvider(context.Background(), "acme", "acme-1"); err == nil {
			t.Fatal("a rejected callback wrote a link row")
		}
	})

	// The link is the identification the reference considers safe, so it is
	// resolved before the address is looked at at all: a provider account that
	// is already linked cannot be turned into a conflict by a later policy
	// change.
	t.Run("an existing link is resolved before the address", func(t *testing.T) {
		f := newProvisioningFixture(t)
		owner := f.seed(t, "owner@example.com")
		f.seed(t, "held@example.com")
		if err := f.links.Save(context.Background(), OAuthLinkedAccount{
			ID: "lnk_1", UserID: owner.ID, Provider: "acme", ProviderID: "acme-1", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed link: %v", err)
		}
		policy := DefaultOAuthProvisioning()
		policy.OnEmailMatch = OAuthEmailMatchConflict

		user, err := f.callback(acmeProfile("held@example.com", nil), policy)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		if user.ID != owner.ID {
			t.Fatalf("session user = %q, want the linked owner %q", user.ID, owner.ID)
		}
	})
}

// RequireVerifiedEmail and AllowedEmailDomains gate the whole callback, before
// anything is resolved or written.
func TestOAuthProvisioningGate(t *testing.T) {
	t.Run("RequireVerifiedEmail", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			verified *bool
			wantErr  error
		}{
			{"the provider said nothing", nil, errOAuthEmailNotVerified},
			{"the provider said false", boolPtr(false), errOAuthEmailNotVerified},
			{"the provider said true", boolPtr(true), nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newProvisioningFixture(t)
				policy := DefaultOAuthProvisioning()
				policy.RequireVerifiedEmail = true
				_, err := f.callback(acmeProfile("gate@example.com", tc.verified), policy)
				if tc.wantErr == nil {
					if err != nil {
						t.Fatalf("callback: %v", err)
					}
					return
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("callback = %v, want %v", err, tc.wantErr)
				}
				if _, err := f.users.GetUserByEmail(context.Background(), "gate@example.com", provisioningTenant); err == nil {
					t.Fatal("a refused callback created the account anyway")
				}
			})
		}
	})

	t.Run("AllowedEmailDomains", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			domains []string
			email   string
			allowed bool
		}{
			{"empty allows everything", nil, "anyone@anywhere.example", true},
			{"an allowed domain", []string{"acme.example"}, "user@acme.example", true},
			{"the @ spelling", []string{"@acme.example"}, "user@acme.example", true},
			{"case folding on both sides", []string{"ACME.example"}, "User@Acme.EXAMPLE", true},
			{"another domain", []string{"acme.example"}, "user@evil.example", false},
			{"a subdomain is not the domain", []string{"acme.example"}, "user@mail.acme.example", false},
			{"no address at all", []string{"acme.example"}, "", false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newProvisioningFixture(t)
				policy := DefaultOAuthProvisioning()
				policy.AllowedEmailDomains = tc.domains
				_, err := f.callback(acmeProfile(tc.email, nil), policy)
				switch {
				case tc.allowed && err != nil:
					t.Fatalf("callback = %v, want the address admitted", err)
				case !tc.allowed && !errors.Is(err, errOAuthEmailDomainNotAllowed):
					t.Fatalf("callback = %v, want errOAuthEmailDomainNotAllowed", err)
				}
			})
		}
	})

	// The gate is not only a provisioning check: an identity that is already
	// linked is refused too, so tightening the policy locks out the accounts it
	// now refuses rather than only the new ones.
	t.Run("an already-linked identity is gated too", func(t *testing.T) {
		f := newProvisioningFixture(t)
		owner := f.seed(t, "owner@evil.example")
		if err := f.links.Save(context.Background(), OAuthLinkedAccount{
			ID: "lnk_1", UserID: owner.ID, Provider: "acme", ProviderID: "acme-1", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed link: %v", err)
		}
		policy := DefaultOAuthProvisioning()
		policy.AllowedEmailDomains = []string{"acme.example"}
		if _, err := f.callback(acmeProfile("owner@evil.example", nil), policy); !errors.Is(err, errOAuthEmailDomainNotAllowed) {
			t.Fatalf("callback = %v, want errOAuthEmailDomainNotAllowed", err)
		}
	})
}

// ── FieldMap ─────────────────────────────────────────────────────────────────

func TestOAuthProvisioningFieldMap(t *testing.T) {
	raw := map[string]any{
		"sub":         "acme-1",
		"email":       "mapped@example.com",
		"given_name":  "Ada",
		"family_name": "Lovelace",
		"roles":       []any{"admin", "member"},
		"profile":     map[string]any{"phones": []any{map[string]any{"e164": "+15550000"}}},
		"group":       map[string]any{"nested": true},
	}
	info := OAuthUserInfo{ProviderID: "acme-1", Provider: "acme", Email: "mapped@example.com", Raw: raw}

	t.Run("fills the mapped fields on creation", func(t *testing.T) {
		f := newProvisioningFixture(t)
		policy := DefaultOAuthProvisioning()
		policy.FieldMap = map[string]string{
			"firstName":   "$.name.first ?? $.given_name",
			"lastName":    "$.family_name",
			"phoneNumber": "$.profile.phones[0].e164",
			"role":        "$.roles[0]",
		}
		user, err := f.callback(info, policy)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		for name, got := range map[string]string{
			"FirstName": user.FirstName, "LastName": user.LastName,
			"PhoneNumber": user.PhoneNumber, "Role": user.Role,
		} {
			want := map[string]string{
				"FirstName": "Ada", "LastName": "Lovelace",
				"PhoneNumber": "+15550000", "Role": "admin",
			}[name]
			if got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
	})

	// A mapping says where a value would come from, not that the provider must
	// send one.
	t.Run("an expression that resolves to nothing leaves the field alone", func(t *testing.T) {
		f := newProvisioningFixture(t)
		policy := DefaultOAuthProvisioning()
		policy.FieldMap = map[string]string{"firstName": "$.missing"}
		user, err := f.callback(info, policy)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		if user.FirstName != "" {
			t.Fatalf("FirstName = %q, want it left empty", user.FirstName)
		}
	})

	// A value with no scalar form is a configuration or provider mismatch, and
	// guessing at a rendering would put "[object Object]" in a user column.
	t.Run("an expression that resolves to an object fails the callback", func(t *testing.T) {
		f := newProvisioningFixture(t)
		policy := DefaultOAuthProvisioning()
		policy.FieldMap = map[string]string{"firstName": "$.group"}
		_, err := f.callback(info, policy)
		if err == nil || !strings.Contains(err.Error(), "not a scalar") {
			t.Fatalf("callback = %v, want an object-valued field map error", err)
		}
		if _, err := f.users.GetUserByEmail(context.Background(), "mapped@example.com", provisioningTenant); err == nil {
			t.Fatal("the account was created despite the field map failing")
		}
	})

	// The map only fills an account being created: an existing one keeps what
	// it has, as the reference's linkAccount changes no user row.
	t.Run("an account the callback only links is not rewritten", func(t *testing.T) {
		f := newProvisioningFixture(t)
		f.seed(t, "mapped@example.com")
		policy := DefaultOAuthProvisioning()
		policy.OnEmailMatch = OAuthEmailMatchLink
		policy.FieldMap = map[string]string{"firstName": "$.given_name"}
		user, err := f.callback(info, policy)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		if user.FirstName != "" {
			t.Fatalf("FirstName = %q, want the stored row untouched", user.FirstName)
		}
	})
}

// ── validation ───────────────────────────────────────────────────────────────

func TestOAuthProvisioningValidate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy OAuthProvisioning
		want   string // a substring of the error; empty means the policy is valid
	}{
		{"the zero policy", OAuthProvisioning{}, ""},
		{"the default policy", DefaultOAuthProvisioning(), ""},
		{"every mode", OAuthProvisioning{OnEmailMatch: OAuthEmailMatchConflict}, ""},
		{"an unknown mode", OAuthProvisioning{OnEmailMatch: "ignore"}, `unknown OnEmailMatch "ignore"`},
		{"an empty domain entry", OAuthProvisioning{AllowedEmailDomains: []string{"acme.example", " "}}, "empty entry"},
		{
			"an unknown field map target",
			OAuthProvisioning{FieldMap: map[string]string{"isAdmin": "$.admin"}},
			`unknown target "isAdmin"`,
		},
		{
			"a field map expression that does not compile",
			OAuthProvisioning{FieldMap: map[string]string{"role": "$.roles[0"}},
			"expected ] after the index",
		},
		{
			"a valid field map",
			OAuthProvisioning{FieldMap: map[string]string{"role": `$.roles[0] ?? "member"`}},
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want an error containing %q", err, tc.want)
			}
		})
	}

	// The error has to name the allowlist: a target is configuration, and a
	// typo is only fixable if the message says what the choices are.
	t.Run("the unknown-target error names every target", func(t *testing.T) {
		err := OAuthProvisioning{FieldMap: map[string]string{"nope": "$.x"}}.Validate()
		if err == nil {
			t.Fatal("Validate accepted an unknown target")
		}
		for _, field := range []string{"firstName", "lastName", "phoneNumber", "role"} {
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error %q does not name the target %q", err, field)
			}
		}
	})
}

// A policy is configuration, so an invalid one fails at construction rather
// than at the first login.
func TestWithOAuthValidatesTheProvisioningPolicy(t *testing.T) {
	_, err := newTestAuth(WithOAuth(OAuthWiring{
		Service:      NewOAuthService(),
		Provisioning: &OAuthProvisioning{OnEmailMatch: "ignore"},
	}))
	if err == nil || !strings.Contains(err.Error(), "unknown OnEmailMatch") {
		t.Fatalf("New = %v, want the policy refused at construction", err)
	}
}

// nil means the default, and an explicit policy is taken as written except for
// OnEmailMatch, which has no empty mode: "" is the conflict, never the link
// (issue #36), so a policy that leaves the mode out cannot link by address.
func TestOAuthWiringProvisioningDefaults(t *testing.T) {
	if got := DefaultOAuthProvisioning(); got.AutoCreate != true || got.OnEmailMatch != OAuthEmailMatchConflict {
		t.Fatalf("DefaultOAuthProvisioning = %+v, want AutoCreate and the conflict mode", got)
	}
	if got := (&OAuthWiring{}).provisioning(); got.AutoCreate != true || got.OnEmailMatch != OAuthEmailMatchConflict {
		t.Fatalf("an unset policy = %+v, want DefaultOAuthProvisioning", got)
	}
	explicit := &OAuthWiring{Provisioning: &OAuthProvisioning{}}
	if got := explicit.provisioning(); got.AutoCreate != false || got.OnEmailMatch != OAuthEmailMatchConflict {
		t.Fatalf("an explicit zero policy = %+v, want AutoCreate false and the conflict mode", got)
	}
	link := &OAuthWiring{Provisioning: &OAuthProvisioning{OnEmailMatch: OAuthEmailMatchLink}}
	if got := link.provisioning(); got.OnEmailMatch != OAuthEmailMatchLink {
		t.Fatalf("an explicit link policy = %+v, want the link mode kept", got)
	}
}

// The policy-less signature follows the default, and so changed with it
// (issue #36): an address another account holds is the reference's conflict,
// not a link, and nothing is written. The old behaviour is one explicit
// policy away.
func TestHandleCallbackFollowsTheDefaultPolicy(t *testing.T) {
	f := newProvisioningFixture(t)
	held := f.seed(t, "old@example.com")
	_, _, err := NewOAuthService().HandleCallback(
		context.Background(), f.auth.service, f.links, acmeProfile("old@example.com", nil), provisioningTenant, "")
	var conflict *OAuthAccountConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("HandleCallback = %v, want *OAuthAccountConflictError", err)
	}
	if _, err := f.links.FindByProvider(context.Background(), "acme", "acme-1"); err == nil {
		t.Fatal("the default policy linked the provider account by address")
	}

	link := DefaultOAuthProvisioning()
	link.OnEmailMatch = OAuthEmailMatchLink
	user, _, err := NewOAuthService().HandleCallbackWithPolicy(
		context.Background(), f.auth.service, f.links, acmeProfile("old@example.com", nil), provisioningTenant, "", link)
	if err != nil {
		t.Fatalf("HandleCallbackWithPolicy(link): %v", err)
	}
	if user.ID != held.ID {
		t.Fatalf("session user = %q, want the address holder %q", user.ID, held.ID)
	}
}

// ── the conflict redirect ────────────────────────────────────────────────────

// The Location a conflict answers with, in both branches of buildUiLink
// (auth.router.ts:365-375 at 1.10.8), with the reference's parameter order and
// its encodeURIComponent escaping (:2000-2001).
func TestAccountConflictLink(t *testing.T) {
	const site = "https://app.example.com"
	for _, tc := range []struct {
		name     string
		cfg      HTTPConfig
		provider string
		email    string
		want     string
	}{
		{
			"default prefix", HTTPConfig{}, "acme", "held@example.com",
			site + "/auth/account-conflict?provider=acme&code=OAUTH_ACCOUNT_CONFLICT&email=held%40example.com",
		},
		{
			"static UI", HTTPConfig{UIEnabled: true}, "acme", "held@example.com",
			site + "/auth/ui/account-conflict?provider=acme&code=OAUTH_ACCOUNT_CONFLICT&email=held%40example.com",
		},
		{
			"custom prefix", HTTPConfig{APIPrefix: "/api/auth/"}, "acme", "held@example.com",
			site + "/api/auth/account-conflict?provider=acme&code=OAUTH_ACCOUNT_CONFLICT&email=held%40example.com",
		},
		{
			"no address", HTTPConfig{}, "acme", "",
			site + "/auth/account-conflict?provider=acme&code=OAUTH_ACCOUNT_CONFLICT",
		},
		{
			"an escaped provider name", HTTPConfig{}, "acme corp", "",
			site + "/auth/account-conflict?provider=acme%20corp&code=OAUTH_ACCOUNT_CONFLICT",
		},
		// encodeURIComponent leaves !'()*~ bare and escapes everything else
		// outside the unreserved set, + and @ included; url.QueryEscape would
		// have written %27 for the apostrophe a local part may hold.
		{
			"an address only encodeURIComponent spells this way", HTTPConfig{}, "acme", "o'brien+x(1)~*!@example.com",
			site + "/auth/account-conflict?provider=acme&code=OAUTH_ACCOUNT_CONFLICT&email=o'brien%2Bx(1)~*!%40example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.AccountConflictLink(site, tc.provider, tc.email); got != tc.want {
				t.Fatalf("AccountConflictLink = %q, want %q", got, tc.want)
			}
		})
	}
}

// The three refusals have to reach the wire as themselves rather than as the
// 500 an unmapped sentinel becomes.
func TestOAuthHTTPErrorMapsTheProvisioningRefusals(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want HTTPError
	}{
		{errOAuthEmailNotVerified, HTTPErrOAuthEmailNotVerified},
		{errOAuthEmailDomainNotAllowed, HTTPErrOAuthEmailDomainNotAllowed},
		{errOAuthUserNotProvisioned, HTTPErrOAuthUserNotProvisioned},
	} {
		if got := OAuthHTTPError(tc.err); got != tc.want {
			t.Errorf("OAuthHTTPError(%v) = %+v, want %+v", tc.err, got, tc.want)
		}
	}
}

// The conflict event's address is the reference's eventEmail: cut to 320
// UTF-16 code units (router-events.ts:13, :46-48 at 1.10.8), which is
// JavaScript's string length, not Go's byte length.
func TestEventEmailCapsAtTheReferenceLength(t *testing.T) {
	short := "held@example.com"
	if got := eventEmail(short); got != short {
		t.Fatalf("eventEmail(%q) = %q, want it untouched", short, got)
	}
	long := strings.Repeat("a", 400) + "@example.com"
	if got := eventEmail(long); got != long[:320] {
		t.Fatalf("eventEmail(400+ ASCII) has length %d, want the first 320", len(got))
	}
	// "é" is one UTF-16 unit and two UTF-8 bytes: 320 of them are kept whole.
	accented := strings.Repeat("é", 330)
	if got := eventEmail(accented); got != strings.Repeat("é", 320) {
		t.Fatalf("eventEmail(330 x é) kept %d runes, want 320", len([]rune(got)))
	}
	// An astral character is two units. 319 ASCII units leave room for one
	// unit only, so the pair is dropped rather than split.
	astral := strings.Repeat("a", 319) + "\U0001F600" + "b"
	if got := eventEmail(astral); got != strings.Repeat("a", 319) {
		t.Fatalf("eventEmail(319 a + emoji) = %d bytes, want the 319 a before the pair", len(got))
	}
	exact := strings.Repeat("a", 318) + "\U0001F600" + "b"
	if got := eventEmail(exact); got != strings.Repeat("a", 318)+"\U0001F600" {
		t.Fatalf("eventEmail(318 a + emoji + b) = %q, want the pair kept at exactly 320 units", got)
	}
}
