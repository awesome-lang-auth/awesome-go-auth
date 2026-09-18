package wiretest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	auth "github.com/nik2208/awesome-go-auth"
)

// The built-in UI group: GET <prefix>/ui/config, the document the UI fetches
// before it renders anything (ui.router.ts:95-170).
//
// It is the second route the adapters mount conditionally — on
// HTTPConfig.UI.Enabled, which is the reference's config.ui.enabled
// (auth.router.ts:1639-1648) — so the other half of the contract, that it is
// absent without the flag and tracked by the generated document in both
// directions, is the "ui" conditional set at the bottom of this file.
//
// What is asserted here is the shape: the exact key set of the document and of
// its two nested objects, the settings store winning over the static branding,
// the language selection, the echoed headless flag, and the reduced document a
// store failure produces.

// The static branding the cases configure. The values are deliberately not the
// defaults, so an assertion on them cannot pass on a document that ignored the
// configuration.
const (
	testUIPrimaryColor   = "#112233"
	testUISecondaryColor = "#445566"
	testUISiteName       = "Wiretest Auth"
	testUICustomLogo     = "https://cdn.example.com/custom-logo.svg"
	testUILogoURL        = "https://cdn.example.com/legacy-logo.svg"
	testUIBgColor        = "#f0f4ff"
	testUIBgImage        = "https://cdn.example.com/bg.jpg"
	testUICardBg         = "#ffffff"
	testUICustomCSS      = ":root { --radius: 4px }"
)

// The stored branding an administrator would have written through the admin
// panel, which has to win over every static value above.
const (
	testUIStoredPrimaryColor = "#aabbcc"
	testUIStoredSiteName     = "Stored Name"
	testUIStoredLogoURL      = "https://cdn.example.com/stored-logo.svg"
	testUIStoredBgColor      = "#001122"
)

// The reference's defaults (ui.router.ts:126-129), spelled out rather than read
// from the package constants: this is the wire, and a test that quoted the
// implementation would follow it wherever it went.
const (
	testUIDefaultPrimaryColor   = "#4a90d9"
	testUIDefaultSecondaryColor = "#6c757d"
	testUIDefaultSiteName       = "Awesome Node Auth"
)

// testUITwoFactorAppName switches the twoFactor feature flag on: it is this
// port's spelling of the reference's twoFactor block.
const testUITwoFactorAppName = "Wiretest"

// errUIStore is what the failing stores answer with. The document must not
// carry it — the client is told nothing at all, which is the reference's
// behaviour and the reason the reduced features object is worth pinning.
var errUIStore = errors.New("wiretest: store is unreachable")

// uiFailingSettings is a settings store that cannot answer, the first half of
// the reference's try block (ui.router.ts:99).
type uiFailingSettings struct{}

func (uiFailingSettings) GetSettings(context.Context) (auth.AuthSettings, error) {
	return auth.AuthSettings{}, errUIStore
}

func (uiFailingSettings) UpdateSettings(context.Context, auth.AuthSettings) (auth.AuthSettings, error) {
	return auth.AuthSettings{}, errUIStore
}

// uiFailingTemplates is a template store whose UI half cannot answer, the other
// half of the same try block (:108). The mail half is a working memory store, so
// the failure is the one the case is about.
type uiFailingTemplates struct {
	*auth.MemoryTemplateStore
}

func (uiFailingTemplates) GetUITranslations(context.Context, string) (auth.UITranslation, bool, error) {
	return auth.UITranslation{}, false, errUIStore
}

// uiHTTPConfig is the wire configuration with the UI switched on and nothing
// else changed.
func uiHTTPConfig() auth.HTTPConfig {
	cfg := auth.DefaultHTTPConfig()
	cfg.UI.Enabled = true
	return cfg
}

// uiBrandedConfig is uiHTTPConfig with every static member of the branding set.
func uiBrandedConfig() auth.HTTPConfig {
	cfg := uiHTTPConfig()
	cfg.UI.Branding = auth.UIBranding{
		PrimaryColor:   testUIPrimaryColor,
		SecondaryColor: testUISecondaryColor,
		LogoURL:        testUILogoURL,
		SiteName:       testUISiteName,
		CustomLogo:     testUICustomLogo,
		BgColor:        testUIBgColor,
		BgImage:        testUIBgImage,
		CardBg:         testUICardBg,
	}
	cfg.UI.CustomCSS = testUICustomCSS
	return cfg
}

// uiTranslationStore is a template store holding the config page in two
// languages. The page is "config" and not "login": the reference derives the
// page from the request path, and on this route that path is always /config
// (ui.router.ts:107).
func uiTranslationStore(t *testing.T) auth.TemplateStore {
	t.Helper()
	store := auth.NewMemoryTemplateStore()
	if _, err := store.UpdateUITranslations(context.Background(), "config", map[string]map[string]string{
		"en": {"signIn": "Sign in"},
		"it": {"signIn": "Accedi"},
	}); err != nil {
		t.Fatalf("seed ui translations: %v", err)
	}
	return store
}

// uiConfigRequest builds a request for the config route, with query appended
// when it is not empty.
func uiConfigRequest(env *Env, query string) *http.Request {
	target := env.Config.Prefix() + auth.UIConfigRoute
	if query != "" {
		target += "?" + query
	}
	return httptest.NewRequest(http.MethodGet, target, nil)
}

// uiDocument issues the request and returns the decoded document, holding it to
// the top-level key set on the way past. Both the success and the failure paths
// answer 200 with these six keys — that is what makes the failure path
// invisible to a client that does not look at features.
func uiDocument(t *testing.T, env *Env, query string) map[string]any {
	t.Helper()
	rec := env.Do(uiConfigRequest(env, query))
	AssertStatus(t, rec, http.StatusOK)
	body := Body(t, rec)
	AssertKeys(t, body, "apiPrefix", "features", "ui", "translations", "lang", "headless")
	return body
}

// uiObject reads one nested object out of the document.
func uiObject(t *testing.T, body map[string]any, key string) map[string]any {
	t.Helper()
	object, ok := body[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want an object", key, body[key])
	}
	return object
}

// assertUIValues fails unless each named member holds this value.
func assertUIValues(t *testing.T, object map[string]any, want map[string]any) {
	t.Helper()
	for member, value := range want {
		if object[member] != value {
			t.Errorf("%s = %#v, want %#v", member, object[member], value)
		}
	}
}

// assertUIUnrouted fails unless the request missed the route entirely. The Go
// routers disagree among themselves on 404 versus 405, so both are accepted;
// what matters is that no document came back.
func assertUIUnrouted(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	switch rec.Code {
	case http.StatusNotFound, http.StatusMethodNotAllowed:
	default:
		t.Fatalf("status = %d, want 404 or 405 (body %q)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "apiPrefix") {
		t.Errorf("an unrouted request was served the UI config document: %s", body)
	}
}

func testUIConfig(t *testing.T, mount Mounter) {
	t.Run("the document carries the reference keys and the configured branding", func(t *testing.T) {
		// NewEnv wires all six senders, so the four delivery-derived flags are on.
		env := NewEnv(t, mount, uiBrandedConfig(),
			auth.WithTwoFactorAppName(testUITwoFactorAppName),
			auth.WithOAuth(auth.OAuthWiring{
				Service: auth.NewOAuthService(
					auth.GoogleProvider("google-client", "google-secret", "https://api.example.com/auth/oauth/google/callback"),
					auth.GitHubProvider("github-client", "github-secret", "https://api.example.com/auth/oauth/github/callback"),
				),
				LinkedAccounts: auth.NewMemoryLinkedAccounts(),
				PendingLinks:   auth.NewMemoryPendingLinks(),
			}),
		)
		body := uiDocument(t, env, "")

		if body["apiPrefix"] != env.Config.Prefix() {
			t.Errorf("apiPrefix = %#v, want %q", body["apiPrefix"], env.Config.Prefix())
		}
		if body["lang"] != "en" {
			t.Errorf("lang = %#v, want %q", body["lang"], "en")
		}
		if body["headless"] != false {
			t.Errorf("headless = %#v, want false", body["headless"])
		}

		features := uiObject(t, body, "features")
		AssertKeys(t, features, "register", "magicLink", "sms", "google", "github",
			"forgotPassword", "verifyEmail", "twoFactor")
		assertUIValues(t, features, map[string]any{
			// register is unconditional here: this port always mounts
			// POST <prefix>/register, where the reference mounts it only with an
			// onRegister hook and reports that same condition (:115).
			"register":       true,
			"magicLink":      true,
			"sms":            true,
			"google":         true,
			"github":         true,
			"forgotPassword": true,
			// The verification sender is wired, but the mode is the default none,
			// so the deployment does not want verification and the flag is off.
			"verifyEmail": false,
			"twoFactor":   true,
		})

		ui := uiObject(t, body, "ui")
		AssertKeys(t, ui, "primaryColor", "secondaryColor", "logoUrl", "siteName",
			"customCss", "bgColor", "bgImage", "cardBg")
		assertUIValues(t, ui, map[string]any{
			"primaryColor":   testUIPrimaryColor,
			"secondaryColor": testUISecondaryColor,
			// customLogo wins over the legacy logoUrl (:128).
			"logoUrl":   testUICustomLogo,
			"siteName":  testUISiteName,
			"customCss": testUICustomCSS,
			"bgColor":   testUIBgColor,
			"bgImage":   testUIBgImage,
			"cardBg":    testUICardBg,
		})

		translations := uiObject(t, body, "translations")
		if len(translations) != 0 {
			t.Errorf("translations = %#v, want an empty object with no template store", translations)
		}
	})

	t.Run("an unconfigured deployment gets the reference defaults and nothing else", func(t *testing.T) {
		// No senders, no providers, no branding: the document a deployment that
		// only switched the UI on receives.
		env := NewEnvWithoutDelivery(t, mount, uiHTTPConfig())
		body := uiDocument(t, env, "")

		features := uiObject(t, body, "features")
		AssertKeys(t, features, "register", "magicLink", "sms", "google", "github",
			"forgotPassword", "verifyEmail", "twoFactor")
		assertUIValues(t, features, map[string]any{
			"register": true, "magicLink": false, "sms": false, "google": false,
			"github": false, "forgotPassword": false, "verifyEmail": false, "twoFactor": false,
		})

		// The five optional members are absent rather than null, which is what
		// JSON.stringify does with the undefined the reference leaves them as.
		ui := uiObject(t, body, "ui")
		AssertKeys(t, ui, "primaryColor", "secondaryColor", "siteName")
		assertUIValues(t, ui, map[string]any{
			"primaryColor":   testUIDefaultPrimaryColor,
			"secondaryColor": testUIDefaultSecondaryColor,
			"siteName":       testUIDefaultSiteName,
		})
	})

	t.Run("the settings store wins over the static branding", func(t *testing.T) {
		store := seedSettings(t, auth.AuthSettings{UI: &auth.UISettings{
			PrimaryColor: stringPtr(testUIStoredPrimaryColor),
			SiteName:     stringPtr(testUIStoredSiteName),
			LogoURL:      stringPtr(testUIStoredLogoURL),
			BgColor:      stringPtr(testUIStoredBgColor),
		}})

		env := NewEnv(t, mount, uiBrandedConfig(), auth.WithSettingsStore(store))
		ui := uiObject(t, uiDocument(t, env, ""), "ui")
		assertUIValues(t, ui, map[string]any{
			"primaryColor": testUIStoredPrimaryColor,
			"siteName":     testUIStoredSiteName,
			// The stored logo beats config.ui.customLogo, which beats the legacy
			// config.ui.logoUrl (:128).
			"logoUrl": testUIStoredLogoURL,
			"bgColor": testUIStoredBgColor,
			// Members the store did not carry keep the static value…
			"secondaryColor": testUISecondaryColor,
			"bgImage":        testUIBgImage,
			"cardBg":         testUICardBg,
			// …and customCss is static-only: there is no stored member for it and
			// the reference reads it from the config alone (:130).
			"customCss": testUICustomCSS,
		})
	})

	t.Run("lang selects the translations", func(t *testing.T) {
		env := NewEnv(t, mount, uiHTTPConfig(), auth.WithTemplateStore(uiTranslationStore(t)))

		for _, tc := range []struct {
			name  string
			query string
			lang  string
			want  string
		}{
			// No parameter and no configured default: English (:103).
			{"default", "", "en", "Sign in"},
			{"query", "lang=it", "it", "Accedi"},
			// A language the page does not hold falls back to English, while the
			// document still reports the language that was asked for (:110).
			{"unknown language falls back to en", "lang=de", "de", "Sign in"},
			// An empty parameter is no parameter, as the empty string is falsy there.
			{"empty parameter", "lang=", "en", "Sign in"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				body := uiDocument(t, env, tc.query)
				if body["lang"] != tc.lang {
					t.Errorf("lang = %#v, want %q", body["lang"], tc.lang)
				}
				translations := uiObject(t, body, "translations")
				AssertKeys(t, translations, "signIn")
				if translations["signIn"] != tc.want {
					t.Errorf("translations.signIn = %#v, want %q", translations["signIn"], tc.want)
				}
			})
		}
	})

	t.Run("UIOptions.DefaultLang is the fallback the request overrides", func(t *testing.T) {
		cfg := uiHTTPConfig()
		cfg.UI.DefaultLang = "it"
		env := NewEnv(t, mount, cfg, auth.WithTemplateStore(uiTranslationStore(t)))

		body := uiDocument(t, env, "")
		if body["lang"] != "it" {
			t.Errorf("lang = %#v, want the configured default %q", body["lang"], "it")
		}
		if got := uiObject(t, body, "translations")["signIn"]; got != "Accedi" {
			t.Errorf("translations.signIn = %#v, want %q", got, "Accedi")
		}

		body = uiDocument(t, env, "lang=en")
		if body["lang"] != "en" {
			t.Errorf("lang = %#v, want the requested %q", body["lang"], "en")
		}
	})

	t.Run("a template store holding no config page answers an empty object", func(t *testing.T) {
		env := NewEnv(t, mount, uiHTTPConfig(), auth.WithTemplateStore(auth.NewMemoryTemplateStore()))
		if translations := uiObject(t, uiDocument(t, env, "lang=it"), "translations"); len(translations) != 0 {
			t.Errorf("translations = %#v, want an empty object", translations)
		}
	})

	t.Run("headless is echoed", func(t *testing.T) {
		// The flag auth.js reads to stop redirecting on session loss. It is added
		// by the route rather than by getUiConfig (:166-168).
		cfg := uiHTTPConfig()
		cfg.UI.Headless = true
		env := NewEnv(t, mount, cfg)
		if body := uiDocument(t, env, ""); body["headless"] != true {
			t.Errorf("headless = %#v, want true", body["headless"])
		}
	})

	t.Run("a failing store answers the reduced document", func(t *testing.T) {
		// The reference's catch (:143-161): still 200, still the same six keys,
		// but three feature flags instead of eight, the default branding whatever
		// was configured, no translations, and English whatever was asked for.
		// This is reproduced rather than fixed — a client cannot tell it from a
		// success, which is the bug, and the family's clients are written against
		// it (reference-issues N32).
		for _, tc := range []struct {
			name string
			opt  auth.Option
		}{
			{"settings store", auth.WithSettingsStore(uiFailingSettings{})},
			{"template store", auth.WithTemplateStore(uiFailingTemplates{auth.NewMemoryTemplateStore()})},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cfg := uiBrandedConfig()
				cfg.UI.Headless = true
				env := NewEnv(t, mount, cfg, tc.opt)
				body := uiDocument(t, env, "lang=it")

				features := uiObject(t, body, "features")
				AssertKeys(t, features, "register", "google", "github")
				assertUIValues(t, features, map[string]any{
					"register": false, "google": false, "github": false,
				})

				ui := uiObject(t, body, "ui")
				AssertKeys(t, ui, "primaryColor", "secondaryColor", "siteName")
				assertUIValues(t, ui, map[string]any{
					"primaryColor":   testUIDefaultPrimaryColor,
					"secondaryColor": testUIDefaultSecondaryColor,
					"siteName":       testUIDefaultSiteName,
				})

				if translations := uiObject(t, body, "translations"); len(translations) != 0 {
					t.Errorf("translations = %#v, want an empty object", translations)
				}
				if body["lang"] != "en" {
					t.Errorf("lang = %#v, want %q whatever the request asked for", body["lang"], "en")
				}
				if body["apiPrefix"] != env.Config.Prefix() {
					t.Errorf("apiPrefix = %#v, want %q", body["apiPrefix"], env.Config.Prefix())
				}
				// headless is set outside getUiConfig, so the fallback carries it.
				if body["headless"] != true {
					t.Errorf("headless = %#v, want true on the fallback too", body["headless"])
				}
				if raw := env.Do(uiConfigRequest(env, "")).Body.String(); strings.Contains(raw, errUIStore.Error()) {
					t.Errorf("the store error reached the client: %s", raw)
				}
			})
		}
	})

	t.Run("no credential is required and the CSRF cookie is seeded", func(t *testing.T) {
		// The login page fetches this before any session exists, so the route
		// asks for nothing. It sits behind the CSRF middleware only for the
		// cookie that middleware hands out, which the reference seeds from a
		// router-level middleware registered ahead of its UI router
		// (auth.router.ts:529-535).
		env := NewEnv(t, mount, uiHTTPConfig())
		rec := env.Do(uiConfigRequest(env, ""))
		AssertStatus(t, rec, http.StatusOK)
		if cookie := Cookie(t, rec, hostCSRF); cookie.Value == "" {
			t.Error("the CSRF cookie was seeded with an empty value")
		}
		// And because that cookie is per-client, the document must not be
		// storable by a shared cache. The header is this port's addition to a
		// route the reference leaves uncached; see the handler comment.
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want %q on a response that seeds a CSRF cookie", got, "no-store")
		}
	})

	t.Run("the route is GET-only", func(t *testing.T) {
		env := NewEnv(t, mount, uiHTTPConfig())
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(method, func(t *testing.T) {
				assertUIUnrouted(t, env.Do(httptest.NewRequest(method, env.Config.Prefix()+auth.UIConfigRoute, nil)))
			})
		}
	})

	t.Run("without UI.Enabled there is no route", func(t *testing.T) {
		// The reference mounts its whole ui router only under config.ui.enabled
		// (auth.router.ts:1639-1648). testOpenAPI asserts the same thing through
		// the conditional set; this is the group saying it in its own terms.
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		assertUIUnrouted(t, env.Do(uiConfigRequest(env, "")))
	})
}

// stringPtr is the pointer every optional UISettings member is.
func stringPtr(value string) *string { return &value }

// uiRouteSet is the conditional set testOpenAPI replays: configured, the adapter
// serves GET <prefix>/ui/config and the document generated with OpenAPIInfo.UI
// describes it; unconfigured, neither does.
func uiRouteSet() conditionalRouteSet {
	return conditionalRouteSet{
		name:      "ui",
		configure: func(pc *probeConfig) { pc.HTTP.UI.Enabled = true },
		routes:    map[string]string{auth.UIConfigRoute: http.MethodGet},
		spec:      func() auth.OpenAPIInfo { return auth.OpenAPIInfo{UI: true} },
	}
}

// The UI pages group: everything under <prefix>/ui that is not the config
// document — the SSR-rendered HTML, the static assets, the uploaded ones and
// headless mode (ui.router.ts:172-332).
//
// # What this group can assert, and what it cannot
//
// The other conditional groups in this suite are lists of paths, and testOpenAPI
// holds each of them to the generated document in both directions. This one is
// not, twice over.
//
// It is not a path list. The reference's last two layers are catch-alls: every
// extensionless path under the mount renders *some* page, because a path with no
// file of its own falls back to login.html. There is no finite set of paths to
// enumerate and no extensionless path that can be asserted absent, so what is
// pinned here is the *classification* — which arm of the router a representative
// path reaches — on one representative per arm. A case that passes proves the
// rule for its representative and for nothing else; the exhaustive half is in
// the root package (ui_pages_test.go), which can call the classifier directly.
//
// And it is not in the OpenAPI document. GenerateOpenAPISpec describes the API
// operations a client calls, and an HTML page is not one: it has no request
// body, no response schema and no status code a generated client would branch
// on. So these paths are deliberately absent from the spec, and this group is
// deliberately not a conditionalRouteSet — registering one would require the
// generator to grow paths for them, which would be describing the UI to the
// wrong audience. uiRouteSet stays what it is: GET <prefix>/ui/config, the one
// route under this mount that *is* an operation, tracked in both directions.
//
// What the four adapters can disagree about, and therefore what this group is
// really for, is routing. A catch-all sibling of a fixed path is the one shape
// the four Go routers do not agree on — gin refuses it outright — so the config
// route reaches its handler through a different registration on gin than on the
// other three. That is exactly the kind of difference this suite exists to
// catch, and it is caught here by asserting the same responses on all four.
func testUIPages(t *testing.T, mount Mounter) {
	t.Run("an extensionless path is rendered as a page", func(t *testing.T) {
		env := NewEnv(t, mount, uiHTTPConfig())
		for _, page := range []string{"", "/", "/login", "/register", "/forgot-password"} {
			t.Run(uiPageName(page), func(t *testing.T) {
				rec := uiPageRequest(t, env, page)
				AssertStatus(t, rec, http.StatusOK)
				if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
					t.Errorf("Content-Type = %q, want text/html; charset=utf-8", got)
				}
				// The injected object is what makes it a rendered page rather
				// than a file that happens to be HTML (ui.router.ts:272).
				if body := rec.Body.String(); !strings.Contains(body, "window.__AUTH_CONFIG__") {
					t.Errorf("the page carries no injected config: %.200q", body)
				}
			})
		}
	})

	t.Run("a rendered page is uncacheable", func(t *testing.T) {
		// ui.router.ts:284. The page embeds a per-request config object and is
		// served behind the CSRF middleware, so a shared cache holding one would
		// hand one visitor's document to the next.
		env := NewEnv(t, mount, uiHTTPConfig())
		rec := uiPageRequest(t, env, "/login")
		const want = "no-store, no-cache, must-revalidate, max-age=0"
		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("Cache-Control = %q, want %q", got, want)
		}
	})

	t.Run("an unknown page falls back rather than 404ing", func(t *testing.T) {
		// ui.router.ts:316-325. This is the half of the catch-all a path list
		// could never express: there is no extensionless path under the mount
		// that answers 404.
		env := NewEnv(t, mount, uiHTTPConfig())
		rec := uiPageRequest(t, env, "/no-such-page")
		AssertStatus(t, rec, http.StatusOK)
		if !strings.Contains(rec.Body.String(), `id="login-form"`) {
			t.Error("the fallback did not render login.html")
		}
	})

	t.Run("a path with an extension is served as a file", func(t *testing.T) {
		// The classification that makes the two layers work at all
		// (ui.router.ts:300-303): the same mount answers /login with a rendered
		// page and /base.css with bytes.
		env := NewEnv(t, mount, uiHTTPConfig())
		rec := uiPageRequest(t, env, "/base.css")
		AssertStatus(t, rec, http.StatusOK)
		want, err := auth.ReadUpstreamUIAsset("base.css")
		if err != nil {
			t.Fatal(err)
		}
		if rec.Body.String() != string(want) {
			t.Error("the static asset was not served verbatim")
		}
		if strings.Contains(rec.Body.String(), "window.__AUTH_CONFIG__") {
			t.Error("a static file was put through the SSR injection")
		}
	})

	t.Run("a file that does not exist is a 404", func(t *testing.T) {
		// It has an extension, so it never reaches the catch-all and is never
		// answered with the login page — which is what keeps a missing
		// stylesheet from arriving as HTML.
		env := NewEnv(t, mount, uiHTTPConfig())
		if rec := uiPageRequest(t, env, "/nothing.css"); rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404 (body %.120q)", rec.Code, rec.Body.String())
		}
	})

	t.Run("the branding reaches the page", func(t *testing.T) {
		// The SSR injection reads the same document GET /ui/config serves, so
		// the branding a client fetches and the branding the page is painted
		// with cannot disagree (ui.router.ts:201-229).
		env := NewEnv(t, mount, uiBrandedConfig())
		body := uiPageRequest(t, env, "/login").Body.String()
		for _, want := range []string{
			"--primary-color: " + testUIPrimaryColor + ";",
			"--input-focus: " + testUIPrimaryColor + ";",
			"--secondary-color: " + testUISecondaryColor + ";",
			"<style>" + testUICustomCSS + "</style>",
			"<title>" + testUISiteName + "</title>",
			// customLogo wins over the legacy logoUrl, as it does in the
			// document (ui.router.ts:128).
			`<img src="` + testUICustomLogo + `" alt="Logo" class="logo">`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("the rendered page does not carry %q", want)
			}
		}
	})

	t.Run("the config route is served under the same mount", func(t *testing.T) {
		// The one assertion that is really about routing rather than about the
		// UI: three adapters register <prefix>/ui/config as a route of its own
		// and gin cannot, so gin answers it from inside the catch-all. Both have
		// to produce the document.
		env := NewEnv(t, mount, uiHTTPConfig())
		uiDocument(t, env, "")
	})

	t.Run("headless mode serves assets and no pages", func(t *testing.T) {
		// ui.router.ts:172-183. The early return is the behaviour: the hosting
		// SPA provides its own login UI, and a headless deployment that still
		// answered login.html would be a different product.
		cfg := uiHTTPConfig()
		cfg.UI.Headless = true
		env := NewEnv(t, mount, cfg)

		for _, page := range []string{"", "/", "/login", "/register"} {
			if rec := uiPageRequest(t, env, page); rec.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d in headless mode, want 404 (body %.120q)",
					uiPageName(page), rec.Code, rec.Body.String())
			}
		}
		// auth.js is why the mode exists: the SPA loads it with a <script> tag.
		if rec := uiPageRequest(t, env, "/auth.js"); rec.Code != http.StatusOK {
			t.Errorf("GET /auth.js = %d in headless mode, want 200", rec.Code)
		}
		// And the document, which is how auth.js learns it is headless.
		if body := uiDocument(t, env, ""); body["headless"] != true {
			t.Errorf("headless = %#v, want true", body["headless"])
		}
	})

	t.Run("uploaded assets are served under both paths", func(t *testing.T) {
		// The legacy /assets/logo and the unified /assets/uploads, from one
		// directory (ui.router.ts:185-191). The seam is an fs.FS until the
		// UploadStore lands.
		cfg := uiHTTPConfig()
		cfg.UI.Uploads = fstest.MapFS{
			"company.png": &fstest.MapFile{Data: []byte("PNGDATA")},
		}
		env := NewEnv(t, mount, cfg)
		for _, page := range []string{"/assets/logo/company.png", "/assets/uploads/company.png"} {
			rec := uiPageRequest(t, env, page)
			AssertStatus(t, rec, http.StatusOK)
			if rec.Body.String() != "PNGDATA" {
				t.Errorf("GET %s served %q, want the uploaded bytes", page, rec.Body.String())
			}
		}
	})

	t.Run("without an upload directory neither path is served", func(t *testing.T) {
		// The reference leaves both mounts unregistered under `if (uploadDir)`,
		// so an unconfigured deployment 404s rather than failing on a store it
		// does not have.
		env := NewEnv(t, mount, uiHTTPConfig())
		for _, page := range []string{"/assets/logo/company.png", "/assets/uploads/company.png"} {
			if rec := uiPageRequest(t, env, page); rec.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d with no upload directory, want 404", page, rec.Code)
			}
		}
	})

	t.Run("a page request seeds the CSRF cookie", func(t *testing.T) {
		// The login page is fetched before any session exists and then posts to
		// /login with the double-submit pair, so it has to arrive with the
		// cookie. The reference's CSRF auto-init is a router.use registered
		// ahead of its UI router (auth.router.ts:529-538) and runs for every
		// route mounted after it, pages included.
		env := NewEnv(t, mount, uiHTTPConfig())
		rec := uiPageRequest(t, env, "/login")
		if cookie := Cookie(t, rec, hostCSRF); cookie.Value == "" {
			t.Error("the CSRF cookie was seeded with an empty value")
		}
	})

	t.Run("a mutating method is unrouted", func(t *testing.T) {
		// req.method !== 'GET' → next(), and express.static does not answer a
		// POST either (ui.router.ts:296-298).
		env := NewEnv(t, mount, uiHTTPConfig())
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(method, func(t *testing.T) {
				target := env.Config.Prefix() + auth.UIRoute + "/login"
				assertUIUnrouted(t, env.Do(httptest.NewRequest(method, target, nil)))
			})
		}
	})

	t.Run("without UI.Enabled nothing under the mount is served", func(t *testing.T) {
		// The reference mounts its whole ui router only under config.ui.enabled
		// (auth.router.ts:1639-1648), and "whole" now means the pages and the
		// assets as well as the document.
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		for _, page := range []string{"", "/", "/login", "/base.css"} {
			t.Run(uiPageName(page), func(t *testing.T) {
				assertUIUnrouted(t, uiPageRequest(t, env, page))
			})
		}
	})
}

// uiPageRequest issues a GET for one path below the UI mount. An empty page is
// the bare mount, which Express serves as the login page.
func uiPageRequest(t *testing.T, env *Env, page string) *httptest.ResponseRecorder {
	t.Helper()
	return env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.UIRoute+page, nil))
}

// uiPageName labels a subtest for a path that may be empty.
func uiPageName(page string) string {
	if page == "" {
		return "(mount root)"
	}
	return page
}
