package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The wire shape of GET <prefix>/ui/config is pinned by the wiretest suite, on
// all four adapters. What is pinned here is the derivation behind it: which
// wiring turns which feature flag on, how the three branding candidates are
// ordered, and the JSON the two features objects encode as — including the
// reduced one, whose whole point is that it is shorter.

// uiTestAuth builds an Auth from a Config, which is the only way to reach
// EmailVerificationMode: it has no Option, deliberately (see NewWithConfig).
func uiTestAuth(t *testing.T, cfg Config, opts ...Option) *Auth {
	t.Helper()
	a, err := NewWithConfig(cfg, opts...)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	return a
}

// uiTestConfig is a valid Config with the delivery seam empty.
func uiTestConfig() Config { return DefaultConfig(testSecret) }

func uiTestOAuth(names ...string) Option {
	providers := make([]OAuthProvider, 0, len(names))
	for _, name := range names {
		providers = append(providers, OAuthProvider{
			Name:         name,
			ClientID:     "client",
			ClientSecret: "secret",
			RedirectURL:  "https://api.example.com/auth/oauth/" + name + "/callback",
			AuthURL:      "https://provider.example.com/authorize",
			TokenURL:     "https://provider.example.com/token",
			UserInfoURL:  "https://provider.example.com/userinfo",
		})
	}
	return WithOAuth(OAuthWiring{
		Service:        NewOAuthService(providers...),
		LinkedAccounts: NewMemoryLinkedAccounts(),
		PendingLinks:   NewMemoryPendingLinks(),
	})
}

func TestUIConfigFeaturesFollowTheWiring(t *testing.T) {
	senders := func(cfg *Config) {
		cfg.SendMagicLink = func(context.Context, MagicLinkDelivery) error { return nil }
		cfg.SendSMSCode = func(context.Context, SMSCodeDelivery) error { return nil }
		cfg.SendPasswordReset = func(context.Context, PasswordResetDelivery) error { return nil }
		cfg.SendEmailVerification = func(context.Context, EmailVerificationDelivery) error { return nil }
	}

	for _, tc := range []struct {
		name string
		cfg  func(*Config)
		opts []Option
		want UIFeatures
	}{
		{
			// register is the one flag this port cannot turn off: it always
			// mounts POST <prefix>/register, where the reference mounts it only
			// with an onRegister hook (auth.router.ts:712-715) and reports that
			// same condition (ui.router.ts:115).
			name: "nothing wired",
			cfg:  func(*Config) {},
			want: UIFeatures{Register: true},
		},
		{
			name: "the delivery seam",
			cfg:  senders,
			want: UIFeatures{Register: true, MagicLink: true, SMS: true, ForgotPassword: true},
		},
		{
			// The verification sender is not enough: the deployment also has to
			// want verification, which the default mode says it does not.
			name: "verification sender under the default mode",
			cfg: func(cfg *Config) {
				cfg.SendEmailVerification = func(context.Context, EmailVerificationDelivery) error { return nil }
			},
			want: UIFeatures{Register: true},
		},
		{
			name: "verification sender under strict",
			cfg: func(cfg *Config) {
				cfg.SendEmailVerification = func(context.Context, EmailVerificationDelivery) error { return nil }
				cfg.EmailVerificationMode = EmailVerificationModeStrict
			},
			want: UIFeatures{Register: true, VerifyEmail: true},
		},
		{
			name: "verification sender under lazy",
			cfg: func(cfg *Config) {
				cfg.SendEmailVerification = func(context.Context, EmailVerificationDelivery) error { return nil }
				cfg.EmailVerificationMode = EmailVerificationModeLazy
			},
			want: UIFeatures{Register: true, VerifyEmail: true},
		},
		{
			// A mode left empty is none throughout this port (Service
			// emailVerificationMode), so it is none here too. The reference's
			// undefined passes its !== 'none' test and reports true; see
			// UIFeatures.
			name: "verification sender under an unset mode",
			cfg: func(cfg *Config) {
				cfg.SendEmailVerification = func(context.Context, EmailVerificationDelivery) error { return nil }
				cfg.EmailVerificationMode = ""
			},
			want: UIFeatures{Register: true},
		},
		{
			// Without the sender the mode decides nothing, exactly as the
			// reference's && puts it.
			name: "strict with no sender",
			cfg: func(cfg *Config) {
				cfg.EmailVerificationMode = EmailVerificationModeStrict
			},
			want: UIFeatures{Register: true},
		},
		{
			name: "two factor is the app name",
			cfg: func(cfg *Config) {
				cfg.TwoFactorAppName = "Acme"
			},
			want: UIFeatures{Register: true, TwoFactor: true},
		},
		{
			// Require2FA makes the factor mandatory, not available. The reference
			// has no equivalent of it and reads only its twoFactor block.
			name: "require2FA alone does not advertise the factor",
			cfg: func(cfg *Config) {
				cfg.Require2FA = true
			},
			want: UIFeatures{Register: true},
		},
		{
			name: "the OAuth providers",
			cfg:  func(*Config) {},
			opts: []Option{uiTestOAuth("google", "github")},
			want: UIFeatures{Register: true, Google: true, GitHub: true},
		},
		{
			// Only these two names are reported: the reference reads
			// config.oauth.google and config.oauth.github and nothing else.
			name: "an unrelated provider is not advertised",
			cfg:  func(*Config) {},
			opts: []Option{uiTestOAuth("gitlab")},
			want: UIFeatures{Register: true},
		},
		{
			name: "one of the two",
			cfg:  func(*Config) {},
			opts: []Option{uiTestOAuth("google")},
			want: UIFeatures{Register: true, Google: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := uiTestConfig()
			tc.cfg(&cfg)
			a := uiTestAuth(t, cfg, tc.opts...)
			if got := a.UIConfig(context.Background(), nil, DefaultHTTPConfig()).Features; got != tc.want {
				t.Errorf("features = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestUIConfigBrandingPrecedence(t *testing.T) {
	a := uiTestAuth(t, uiTestConfig())

	static := UIBranding{
		PrimaryColor:   "#static-primary",
		SecondaryColor: "#static-secondary",
		LogoURL:        "https://example.com/legacy.svg",
		SiteName:       "Static Name",
		CustomLogo:     "https://example.com/custom.svg",
		BgColor:        "#static-bg",
		BgImage:        "https://example.com/bg.jpg",
		CardBg:         "#static-card",
	}

	t.Run("nothing configured gives the reference defaults", func(t *testing.T) {
		got := a.UIConfig(context.Background(), nil, DefaultHTTPConfig()).UI
		want := UIConfigBranding{
			PrimaryColor:   UIDefaultPrimaryColor,
			SecondaryColor: UIDefaultSecondaryColor,
			SiteName:       UIDefaultSiteName,
		}
		if got != want {
			t.Errorf("ui = %+v, want %+v", got, want)
		}
	})

	t.Run("the static branding wins over the defaults", func(t *testing.T) {
		cfg := DefaultHTTPConfig()
		cfg.UI.Branding = static
		cfg.UI.CustomCSS = "body{}"
		got := a.UIConfig(context.Background(), nil, cfg).UI
		want := UIConfigBranding{
			PrimaryColor:   static.PrimaryColor,
			SecondaryColor: static.SecondaryColor,
			// customLogo beats the legacy logoUrl (ui.router.ts:128).
			LogoURL:   static.CustomLogo,
			SiteName:  static.SiteName,
			CustomCSS: "body{}",
			BgColor:   static.BgColor,
			BgImage:   static.BgImage,
			CardBg:    static.CardBg,
		}
		if got != want {
			t.Errorf("ui = %+v, want %+v", got, want)
		}
	})

	t.Run("the legacy logoUrl is the last candidate", func(t *testing.T) {
		cfg := DefaultHTTPConfig()
		cfg.UI.Branding = UIBranding{LogoURL: static.LogoURL}
		if got := a.UIConfig(context.Background(), nil, cfg).UI.LogoURL; got != static.LogoURL {
			t.Errorf("logoUrl = %q, want %q", got, static.LogoURL)
		}
	})

	t.Run("the settings store wins over everything", func(t *testing.T) {
		stored := UISettings{
			PrimaryColor:   strPtr("#stored-primary"),
			SecondaryColor: strPtr("#stored-secondary"),
			LogoURL:        strPtr("https://example.com/stored.svg"),
			SiteName:       strPtr("Stored Name"),
			BgColor:        strPtr("#stored-bg"),
			BgImage:        strPtr("https://example.com/stored-bg.jpg"),
			CardBg:         strPtr("#stored-card"),
		}
		store := NewMemorySettingsStore()
		if _, err := store.UpdateSettings(context.Background(), AuthSettings{UI: &stored}); err != nil {
			t.Fatalf("seed settings: %v", err)
		}
		withStore := uiTestAuth(t, uiTestConfig(), WithSettingsStore(store))

		cfg := DefaultHTTPConfig()
		cfg.UI.Branding = static
		cfg.UI.CustomCSS = "body{}"
		got := withStore.UIConfig(context.Background(), nil, cfg).UI
		want := UIConfigBranding{
			PrimaryColor:   *stored.PrimaryColor,
			SecondaryColor: *stored.SecondaryColor,
			LogoURL:        *stored.LogoURL,
			SiteName:       *stored.SiteName,
			// customCss is the one member no store can override: the reference
			// reads it from the static config alone (ui.router.ts:130), and
			// UISettings has no member for it.
			CustomCSS: "body{}",
			BgColor:   *stored.BgColor,
			BgImage:   *stored.BgImage,
			CardBg:    *stored.CardBg,
		}
		if got != want {
			t.Errorf("ui = %+v, want %+v", got, want)
		}
	})

	t.Run("a stored member left empty falls through", func(t *testing.T) {
		// The reference's chain is a chain of ||, which an empty string does not
		// stop any more than a missing key does.
		store := NewMemorySettingsStore()
		if _, err := store.UpdateSettings(context.Background(), AuthSettings{UI: &UISettings{
			PrimaryColor: strPtr(""),
			SiteName:     strPtr(""),
		}}); err != nil {
			t.Fatalf("seed settings: %v", err)
		}
		withStore := uiTestAuth(t, uiTestConfig(), WithSettingsStore(store))

		cfg := DefaultHTTPConfig()
		cfg.UI.Branding = UIBranding{PrimaryColor: static.PrimaryColor}
		got := withStore.UIConfig(context.Background(), nil, cfg).UI
		if got.PrimaryColor != static.PrimaryColor {
			t.Errorf("primaryColor = %q, want the static %q", got.PrimaryColor, static.PrimaryColor)
		}
		if got.SiteName != UIDefaultSiteName {
			t.Errorf("siteName = %q, want the default %q", got.SiteName, UIDefaultSiteName)
		}
	})
}

func TestUIConfigLanguage(t *testing.T) {
	a := uiTestAuth(t, uiTestConfig())

	for _, tc := range []struct {
		name        string
		target      string
		defaultLang string
		want        string
	}{
		{"no request at all", "", "", UIDefaultLang},
		{"no parameter", "/auth/ui/config", "", UIDefaultLang},
		{"a parameter", "/auth/ui/config?lang=it", "", "it"},
		{"an empty parameter is no parameter", "/auth/ui/config?lang=", "", UIDefaultLang},
		{"the configured default", "/auth/ui/config", "fr", "fr"},
		{"the parameter beats the default", "/auth/ui/config?lang=it", "fr", "it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultHTTPConfig()
			cfg.UI.DefaultLang = tc.defaultLang
			var req *http.Request
			if tc.target != "" {
				req = httptest.NewRequest(http.MethodGet, tc.target, nil)
			}
			if got := a.UIConfig(context.Background(), req, cfg).Lang; got != tc.want {
				t.Errorf("lang = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUIConfigTranslations(t *testing.T) {
	store := NewMemoryTemplateStore()
	if _, err := store.UpdateUITranslations(context.Background(), "config", map[string]map[string]string{
		"en": {"signIn": "Sign in"},
		"it": {"signIn": "Accedi"},
	}); err != nil {
		t.Fatalf("seed translations: %v", err)
	}
	// The login page's strings are not what this route serves: the page is taken
	// from the request path, which is always /config here (ui.router.ts:107).
	if _, err := store.UpdateUITranslations(context.Background(), "login", map[string]map[string]string{
		"en": {"signIn": "Wrong page"},
	}); err != nil {
		t.Fatalf("seed translations: %v", err)
	}
	a := uiTestAuth(t, uiTestConfig(), WithTemplateStore(store))

	for _, tc := range []struct {
		name, lang, want string
	}{
		{"the requested language", "it", "Accedi"},
		{"english", "en", "Sign in"},
		{"an unknown language falls back to english", "de", "Sign in"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/auth/ui/config?lang="+tc.lang, nil)
			got := a.UIConfig(context.Background(), req, DefaultHTTPConfig())
			if got.Translations["signIn"] != tc.want {
				t.Errorf("translations = %#v, want signIn %q", got.Translations, tc.want)
			}
			if got.Lang != tc.lang {
				t.Errorf("lang = %q, want the requested %q", got.Lang, tc.lang)
			}
		})
	}

	t.Run("a page the store does not hold is an empty object, not null", func(t *testing.T) {
		bare := uiTestAuth(t, uiTestConfig(), WithTemplateStore(NewMemoryTemplateStore()))
		got := bare.UIConfig(context.Background(), nil, DefaultHTTPConfig())
		if got.Translations == nil {
			t.Fatal("translations is nil, which encodes as null")
		}
		if len(got.Translations) != 0 {
			t.Errorf("translations = %#v, want empty", got.Translations)
		}
	})

	t.Run("the returned map is the caller's own", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/auth/ui/config?lang=it", nil)
		first := a.UIConfig(context.Background(), req, DefaultHTTPConfig()).Translations
		first["signIn"] = "clobbered"
		if second := a.UIConfig(context.Background(), req, DefaultHTTPConfig()).Translations; second["signIn"] != "Accedi" {
			t.Errorf("the stored translations were mutated through a served document: %#v", second)
		}
	})
}

// uiFailingStore fails both halves of the seam, one instance at a time.
type uiFailingStore struct {
	*MemoryTemplateStore
	err error
}

func (s uiFailingStore) GetSettings(context.Context) (AuthSettings, error) {
	return AuthSettings{}, s.err
}

func (s uiFailingStore) UpdateSettings(context.Context, AuthSettings) (AuthSettings, error) {
	return AuthSettings{}, s.err
}

func (s uiFailingStore) GetUITranslations(context.Context, string) (UITranslation, bool, error) {
	return UITranslation{}, false, s.err
}

func TestUIConfigFallsBackWhenAStoreFails(t *testing.T) {
	failing := uiFailingStore{MemoryTemplateStore: NewMemoryTemplateStore(), err: errors.New("store is down")}

	cfg := DefaultHTTPConfig()
	cfg.APIPrefix = "/api/auth"
	cfg.UI.Enabled = true
	cfg.UI.Headless = true
	cfg.UI.Branding = UIBranding{PrimaryColor: "#ignored", SiteName: "Ignored"}
	cfg.UI.CustomCSS = "body{}"
	cfg.UI.DefaultLang = "it"

	for _, tc := range []struct {
		name string
		opt  Option
	}{
		{"settings", WithSettingsStore(failing)},
		{"templates", WithTemplateStore(failing)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged int
			a := uiTestAuth(t, uiTestConfig(), tc.opt, WithLogger(func(string, ...any) { logged++ }))

			req := httptest.NewRequest("GET", "/api/auth/ui/config?lang=de", nil)
			got := a.UIConfig(context.Background(), req, cfg)

			// Everything configured is discarded; the prefix and the headless
			// flag are not, because the reference's catch rebuilds the one and
			// the route sets the other afterwards (ui.router.ts:144, :166-168).
			want := UIConfig{
				APIPrefix: "/api/auth",
				Features:  UIFeatures{collapsed: true},
				UI: UIConfigBranding{
					PrimaryColor:   UIDefaultPrimaryColor,
					SecondaryColor: UIDefaultSecondaryColor,
					SiteName:       UIDefaultSiteName,
				},
				Translations: map[string]string{},
				Lang:         UIDefaultLang,
				Headless:     true,
			}
			if got.APIPrefix != want.APIPrefix || got.UI != want.UI || got.Lang != want.Lang ||
				got.Headless != want.Headless || got.Features != want.Features || len(got.Translations) != 0 {
				t.Errorf("document = %+v,\nwant        %+v", got, want)
			}
			// The client is told nothing, so the operator has to be.
			if logged == 0 {
				t.Error("the store failure was not logged through Config.Logger")
			}
		})
	}
}

func TestUIConfigEncodesTheReferenceShape(t *testing.T) {
	t.Run("the full document", func(t *testing.T) {
		cfg := DefaultHTTPConfig()
		cfg.UI.Branding = UIBranding{
			PrimaryColor: "#111111", SecondaryColor: "#222222", CustomLogo: "logo.svg",
			SiteName: "Acme", BgColor: "#333333", BgImage: "bg.jpg", CardBg: "#444444",
		}
		cfg.UI.CustomCSS = "body{}"
		cfg.UI.Headless = true
		a := uiTestAuth(t, uiTestConfig())

		encoded, err := json.Marshal(a.UIConfig(context.Background(), nil, cfg))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		// Byte for byte, in the reference's key order (ui.router.ts:136-142,
		// :114-123, :125-134, :168).
		want := `{"apiPrefix":"/auth",` +
			`"features":{"register":true,"magicLink":false,"sms":false,"google":false,` +
			`"github":false,"forgotPassword":false,"verifyEmail":false,"twoFactor":false},` +
			`"ui":{"primaryColor":"#111111","secondaryColor":"#222222","logoUrl":"logo.svg",` +
			`"siteName":"Acme","customCss":"body{}","bgColor":"#333333","bgImage":"bg.jpg",` +
			`"cardBg":"#444444"},` +
			`"translations":{},"lang":"en","headless":true}`
		if string(encoded) != want {
			t.Errorf("encoded = %s\nwant       %s", encoded, want)
		}
	})

	t.Run("the unconfigured document omits what nobody set", func(t *testing.T) {
		a := uiTestAuth(t, uiTestConfig())
		encoded, err := json.Marshal(a.UIConfig(context.Background(), nil, DefaultHTTPConfig()))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		want := `{"apiPrefix":"/auth",` +
			`"features":{"register":true,"magicLink":false,"sms":false,"google":false,` +
			`"github":false,"forgotPassword":false,"verifyEmail":false,"twoFactor":false},` +
			`"ui":{"primaryColor":"` + UIDefaultPrimaryColor + `","secondaryColor":"` +
			UIDefaultSecondaryColor + `","siteName":"` + UIDefaultSiteName + `"},` +
			`"translations":{},"lang":"en","headless":false}`
		if string(encoded) != want {
			t.Errorf("encoded = %s\nwant       %s", encoded, want)
		}
	})

	t.Run("the reduced features object really is three keys", func(t *testing.T) {
		encoded, err := json.Marshal(fallbackUIConfig(DefaultHTTPConfig()).Features)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if want := `{"register":false,"google":false,"github":false}`; string(encoded) != want {
			t.Errorf("encoded = %s, want %s", encoded, want)
		}
	})

	t.Run("a features value a caller built is never reduced", func(t *testing.T) {
		encoded, err := json.Marshal(UIFeatures{Register: true})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(decoded) != 8 {
			t.Errorf("encoded = %s, want all eight flags", encoded)
		}
	})
}
