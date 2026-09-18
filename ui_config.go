package auth

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
)

// This file is GET <prefix>/ui/config: the document the built-in UI fetches
// before it renders anything — where the API is mounted, which features to
// offer, how to paint itself, which language to speak, and whether the pages
// exist at all.
//
// It is the reference's ui.router.ts:95-170 — the getUiConfig closure and the
// one route that serves it — and the configuration it reads is the reference's
// config.ui block (auth-config.model.ts:321-381), which arrives here as
// HTTPConfig.UI.
//
// Only the config route is mounted. The HTML pages, the static assets and the
// uploaded logos the same reference router serves (ui.router.ts:177-190) come
// later; UIOptions.Assets and UIOptions.Uploads are where they will read from.

// The branding defaults. They are the reference's literals
// (ui.router.ts:126-129, repeated in its error fallback at :149-151) and are
// wire values rather than a claim about who wrote the server: the family's
// clients render siteName as the page heading, so a port that substituted a
// default of its own would show a different login page for the same
// configuration.
const (
	UIDefaultPrimaryColor   = "#4a90d9"
	UIDefaultSecondaryColor = "#6c757d"
	UIDefaultSiteName       = "Awesome Node Auth"
	// UIDefaultLang is the language the document falls back to when the request
	// asks for none and none is configured, and the language whose translations
	// stand in for a language the template store does not hold
	// (ui.router.ts:103, :110).
	UIDefaultLang = "en"
)

// UIConfigRoute is where the document is served below the mount prefix. The
// reference mounts its whole ui router at <prefix>/ui (auth.router.ts:1640) and
// the config endpoint at /config within it (ui.router.ts:165).
//
// It is exported because openapi.go describes the route and the conformance
// suite replays it, and one constant is what keeps the description and the
// mount from parting company — the way ResourceServerGatedRoutes is shared
// already.
//
// Since v0.9.0 no adapter registers this path on its own router. UIHandler
// serves the whole of <prefix>/ui, this route included, and delegates it to the
// same handler the adapters used to mount here — which is where the reference
// has it too (ui.router.ts:165 is a route inside the router auth.router.ts:1640
// mounts at /ui). The constant is built from UIRoute so that the two cannot
// drift.
const UIConfigRoute = UIRoute + "/config"

// uiConfigPage is the template store page the translations are read from.
//
// The reference derives it from the request path — page = req.path without its
// leading slash, or "login" when the path is empty (ui.router.ts:107) — and on
// this route that path is always /config. So the document serves the page named
// "config" and never the login page's strings, whatever the UI is about to
// render. That is what its code does, so it is what this does; a store that
// wants the config route to carry the login strings has to file them under
// "config".
const uiConfigPage = "config"

// UIOptions is the reference's config.ui block (auth-config.model.ts:321-381):
// everything the built-in UI is configured with. It reaches the route as
// HTTPConfig.UI.
type UIOptions struct {
	// Enabled mounts the UI. The reference gates its whole ui router on
	// config.ui.enabled (auth.router.ts:1639-1648); this port gates
	// GET <prefix>/ui/config on the same flag, so with it false the route is not
	// registered and the router answers whatever it answers for an unknown path.
	//
	// It is also what points an emailed link at a UI page rather than at the API
	// route itself — see HTTPConfig.UILink.
	Enabled bool
	// Headless is the reference's config.ui.headless (auth-config.model.ts:343):
	// the SPA case, in which the hosting application provides its own pages and
	// the router serves only this document and the static assets.
	//
	// It decides two things. UIHandler short-circuits on it and serves no HTML
	// page at all (ui.router.ts:172-183), and it is echoed in this document,
	// which is where auth.js reads it from to stop redirecting on an expired
	// session (:334-336, ui.router.ts:168).
	Headless bool
	// Branding is the static half of the served ui object: the deployment's
	// colours, logo and site name, each of which a settings store may override
	// per request. See UIBranding.
	Branding UIBranding
	// CustomCSS is the reference's config.ui.customCss
	// (auth-config.model.ts:348-353), served as the ui object's customCss. It is
	// the one member of that object a settings store cannot override, because
	// the reference reads it from the static config alone (ui.router.ts:130).
	CustomCSS string
	// DefaultLang is the language the document falls back to when the request
	// carries no lang query parameter. The reference reads that fallback from
	// config.email.mailer.defaultLang (ui.router.ts:103); this port has no
	// mailer block on Config — MailerConfig belongs to the transport a host
	// builds — so the UI's own default lives here. Empty means UIDefaultLang.
	DefaultLang string
	// Assets is the reference's uiAssetsDir (ui.router.ts:11-14): the built-in
	// pages and scripts UIHandler serves and renders. nil — the default — is the
	// vendored copy of the reference's own assets, UpstreamUIAssetFS(), which is
	// that option's "if not provided, the internal Vanilla JS UI will be
	// served". A host supplying its own set is taken at its word: the pages are
	// looked up in it and nothing falls back to the vendored ones, because a
	// half-replaced UI is worse than a missing one.
	//
	// It is an fs.FS rather than a directory path so that a host can serve a
	// built SPA from its own embed.FS without unpacking it, and os.DirFS is the
	// one-line spelling of the reference's directory.
	Assets fs.FS
	// Uploads is the reference's uploadDir (:16-20): the logos and backgrounds
	// an administrator uploaded, served under both <prefix>/ui/assets/logo/ and
	// <prefix>/ui/assets/uploads/ (ui.router.ts:185-191).
	//
	// It is read-only on purpose, and U15 is where the other half arrived:
	// Config.Uploads is the UploadStore the admin console writes through, and
	// UploadFS presents one as exactly this fs.FS. UIHandler composes the two
	// so that a host wires one thing:
	//
	//   - Uploads set wins, always. A host that wants the read side served from
	//     somewhere else — a read-through cache, a snapshot, an os.DirFS over a
	//     mounted volume — says so here and the store is not consulted.
	//   - Uploads nil with an UploadStore configured serves that store's
	//     objects, through UploadFS. This is the ordinary arrangement and is
	//     what makes the URL the upload routes hand back resolve against this
	//     same deployment.
	//   - Neither mounts neither path, exactly as the reference's
	//     `if (uploadDir)` leaves them unmounted, so an unconfigured deployment
	//     answers 404 there rather than failing on a store it does not have.
	//
	// The one thing UploadFS cannot carry is a request context: fs.FS.Open takes
	// none. A host that needs per-request cancellation on the read path sets
	// this field to its own fs.FS. See UploadFS.
	Uploads fs.FS
}

// UIBranding is the static branding block, under the reference's field names
// (auth-config.model.ts:353-380). Every member is optional, and the empty
// string means unset: the reference's chain of `||` treats an empty string and
// an absent key alike, so a value configured empty falls through to the next
// candidate exactly as a missing one does.
//
// CustomLogo and LogoURL are both here because the reference has both, and
// because it prefers the first: the served logoUrl is the stored
// settings.ui.logoUrl, then config.ui.customLogo, then config.ui.logoUrl
// (ui.router.ts:128). customLogo is the documented field
// (auth-config.model.ts:354-355) and logoUrl is kept there as a legacy one
// (:357-361).
type UIBranding struct {
	PrimaryColor   string
	SecondaryColor string
	LogoURL        string
	SiteName       string
	CustomLogo     string
	BgColor        string
	BgImage        string
	CardBg         string
}

// UIConfig is the body of GET <prefix>/ui/config, with the reference's keys in
// the reference's order (ui.router.ts:136-142 plus :168).
//
// apiPrefix is where the API routes are mounted, which is what lets the UI be
// served from one path and call the API at another. The reference derives it
// from the mounted router's baseUrl with a trailing /ui removed (:98); here it
// is HTTPConfig.Prefix, which is the same value by construction.
//
// translations is the flat key -> value map for lang, never null: a deployment
// with no template store, a store holding no config page, or a page holding
// neither the requested language nor English all yield the empty object
// (:105-112).
type UIConfig struct {
	APIPrefix    string            `json:"apiPrefix"`
	Features     UIFeatures        `json:"features"`
	UI           UIConfigBranding  `json:"ui"`
	Translations map[string]string `json:"translations"`
	Lang         string            `json:"lang"`
	// Headless echoes UIOptions.Headless. It is the one member the route adds
	// rather than getUiConfig (ui.router.ts:166-168), which is why it is last
	// and why the error fallback carries it too.
	Headless bool `json:"headless"`
}

// UIConfigBranding is the served ui object (ui.router.ts:125-134): the static
// branding with the stored settings applied on top.
//
// The five optional members are omitted rather than sent null, which is what
// JSON.stringify does with the undefined the reference leaves them as. The
// three that are always present have defaults behind them and can never be
// empty.
//
// customCss is here and customLogo is not: the logo is resolved into logoUrl,
// and the CSS is passed through from the static configuration.
type UIConfigBranding struct {
	PrimaryColor   string `json:"primaryColor"`
	SecondaryColor string `json:"secondaryColor"`
	LogoURL        string `json:"logoUrl,omitempty"`
	SiteName       string `json:"siteName"`
	CustomCSS      string `json:"customCss,omitempty"`
	BgColor        string `json:"bgColor,omitempty"`
	BgImage        string `json:"bgImage,omitempty"`
	CardBg         string `json:"cardBg,omitempty"`
}

// UIFeatures is the served features object (ui.router.ts:114-123): which login
// affordances the UI should offer. Each flag says that this deployment can
// actually perform the thing, which is why they are derived from the wiring
// rather than configured.
//
//   - register is always true. The reference mounts POST /register only when
//     routerOptions.onRegister is supplied and reports that same condition here
//     (auth.router.ts:712-715, ui.router.ts:115); this port always mounts the
//     route, so the honest answer about the routes it serves is always true.
//     Registered as the deviation register-route-is-always-mounted.
//   - magicLink, sms, forgotPassword and verifyEmail follow the delivery seam:
//     Config.SendMagicLink, Config.SendSMSCode, Config.SendPasswordReset and
//     Config.SendEmailVerification. The reference reads config.email.sendX or a
//     configured mailer for the three email ones and config.sms for the other
//     (:116-121); this port has no mailer block on Config, so the sender is the
//     whole condition.
//   - verifyEmail additionally requires the deployment to want verification at
//     all: Config.EmailVerificationMode other than none, as normalised by the
//     service. The reference asks emailVerificationMode !== 'none' ||
//     requireEmailVerification (:121), and an unset mode passes that test while
//     behaving as none everywhere else in its own code
//     (auth-config.model.ts:286-289). This port has no requireEmailVerification
//     and normalises an unset mode to none throughout, so it answers false where
//     the reference answers true for a deployment that configured a verification
//     sender and left the mode alone. Registered as the deviation
//     ui-config-verify-email-follows-the-effective-mode, which is where the
//     reasoning lives.
//   - google and github report a configured OAuth provider of that name
//     (:118-119, WithOAuth here).
//   - twoFactor is Config.TwoFactorAppName, this port's spelling of the
//     reference's twoFactor block, which holds nothing but appName
//     (auth-config.model.ts:272-274, ui.router.ts:122). Config.Require2FA is not
//     read: it makes the factor mandatory, not available, and the reference has
//     no equivalent of it.
type UIFeatures struct {
	Register       bool `json:"register"`
	MagicLink      bool `json:"magicLink"`
	SMS            bool `json:"sms"`
	Google         bool `json:"google"`
	GitHub         bool `json:"github"`
	ForgotPassword bool `json:"forgotPassword"`
	VerifyEmail    bool `json:"verifyEmail"`
	TwoFactor      bool `json:"twoFactor"`
	// collapsed marks the value built by the error fallback, which carries three
	// of the eight flags and not the other five. See MarshalJSON; a UIFeatures a
	// caller builds is never collapsed.
	collapsed bool
}

// MarshalJSON writes the eight flags, or the three the error fallback writes.
//
// The fallback object really is shorter (ui.router.ts:147): a client that keyed
// on features.magicLink gets undefined from a deployment whose settings store is
// down, rather than false. That is a bug in the reference — it drops five flags
// on an error path the client cannot distinguish from success — and it is
// reproduced rather than fixed (reference-issues N32), because the family's
// clients are written against the document as it is and a port that filled the
// five in would be answering something no node-auth server ever answers.
//
// The flag is unexported and set in one place, so the type stays a plain
// collection of booleans for anyone building or reading one. Round-tripping a
// collapsed value through an encoder and a decoder yields an uncollapsed one.
func (f UIFeatures) MarshalJSON() ([]byte, error) {
	if f.collapsed {
		return json.Marshal(struct {
			Register bool `json:"register"`
			Google   bool `json:"google"`
			GitHub   bool `json:"github"`
		}{Register: f.Register, Google: f.Google, GitHub: f.GitHub})
	}
	// A defined type with no methods of its own, so this does not recurse.
	type features UIFeatures
	return json.Marshal(features(f))
}

// UIConfig builds the document GET <prefix>/ui/config serves (ui.router.ts:
// 95-170). The adapters call it; a host serving its own UI route may call it
// too.
//
// r supplies the lang query parameter and nothing else, and may be nil. cfg is
// the wire configuration the adapter was mounted with: its Prefix is the
// document's apiPrefix and its UI block is the branding, the language default
// and the headless flag.
//
// There is no error return, because the route has no error path: a settings
// store or template store that fails is caught and answered with the fallback
// document (:143-161), exactly as the reference's catch does. A store failure is
// therefore invisible to the client beyond the shorter features object, which is
// why it is logged through Config.Logger on the way past.
func (a *Auth) UIConfig(ctx context.Context, r *http.Request, cfg HTTPConfig) UIConfig {
	out, err := a.uiConfig(ctx, r, cfg)
	if err != nil {
		a.service.logf("auth: ui config: a store failed and the reduced fallback "+
			"document was served instead: %v", err)
		out = fallbackUIConfig(cfg)
	}
	// headless is set by the route on whichever object getUiConfig returned
	// (:166-168), so the fallback carries it as well.
	out.Headless = cfg.UI.Headless
	return out
}

// uiConfig is the body of getUiConfig up to its catch: everything that can fail
// returns the error instead, and UIConfig turns that into the fallback.
func (a *Auth) uiConfig(ctx context.Context, r *http.Request, cfg HTTPConfig) (UIConfig, error) {
	// The settings store is read first, as there (:99), so its failure decides
	// the whole document rather than half of it.
	settings, err := a.uiSettings(ctx)
	if err != nil {
		return UIConfig{}, err
	}
	lang := uiLang(r, cfg)
	translations, err := a.uiTranslations(ctx, lang)
	if err != nil {
		return UIConfig{}, err
	}
	return UIConfig{
		APIPrefix:    cfg.Prefix(),
		Features:     a.uiFeatures(),
		UI:           uiBranding(cfg.UI, settings),
		Translations: translations,
		Lang:         lang,
	}, nil
}

// fallbackUIConfig is the reference's catch block (:144-160): the default
// branding, three feature flags, no translations and English, whatever the
// request asked for and whatever the deployment configured.
func fallbackUIConfig(cfg HTTPConfig) UIConfig {
	return UIConfig{
		APIPrefix: cfg.Prefix(),
		Features:  UIFeatures{collapsed: true},
		UI: UIConfigBranding{
			PrimaryColor:   UIDefaultPrimaryColor,
			SecondaryColor: UIDefaultSecondaryColor,
			SiteName:       UIDefaultSiteName,
		},
		Translations: map[string]string{},
		Lang:         UIDefaultLang,
	}
}

// uiSettings reads the stored branding, or nil when no settings store is
// configured — the reference's empty settings object (:99).
func (a *Auth) uiSettings(ctx context.Context) (*UISettings, error) {
	store := a.service.cfg.Settings
	if store == nil {
		return nil, nil
	}
	settings, err := store.GetSettings(ctx)
	if err != nil {
		return nil, err
	}
	return settings.UI, nil
}

// uiLang resolves the document language: the lang query parameter, then
// UIOptions.DefaultLang, then UIDefaultLang (:102-103). An empty parameter is
// no parameter, as an empty string is falsy there.
func uiLang(r *http.Request, cfg HTTPConfig) string {
	if r != nil && r.URL != nil {
		if lang := r.URL.Query().Get("lang"); lang != "" {
			return lang
		}
	}
	if cfg.UI.DefaultLang != "" {
		return cfg.UI.DefaultLang
	}
	return UIDefaultLang
}

// uiTranslations reads the config page from the template store and picks the
// language: the requested one, then English, then nothing (:105-112). The map
// is always non-nil, so the document carries an object and never null.
func (a *Auth) uiTranslations(ctx context.Context, lang string) (map[string]string, error) {
	store := a.service.cfg.Templates
	if store == nil {
		return map[string]string{}, nil
	}
	page, ok, err := store.GetUITranslations(ctx, uiConfigPage)
	if err != nil {
		return nil, err
	}
	if !ok {
		return map[string]string{}, nil
	}
	for _, candidate := range []string{lang, UIDefaultLang} {
		if values, found := page.Translations[candidate]; found {
			return copyStrings(values), nil
		}
	}
	return map[string]string{}, nil
}

// uiFeatures derives the features object from the wiring. See UIFeatures for
// what each flag means and where the reference reads it.
func (a *Auth) uiFeatures() UIFeatures {
	cfg := a.service.cfg
	return UIFeatures{
		Register:       true,
		MagicLink:      cfg.SendMagicLink != nil,
		SMS:            cfg.SendSMSCode != nil,
		Google:         a.oauthProviderConfigured("google"),
		GitHub:         a.oauthProviderConfigured("github"),
		ForgotPassword: cfg.SendPasswordReset != nil,
		VerifyEmail: cfg.SendEmailVerification != nil &&
			a.service.emailVerificationMode() != EmailVerificationModeNone,
		TwoFactor: cfg.TwoFactorAppName != "",
	}
}

// oauthProviderConfigured reports whether WithOAuth wired a provider under this
// name, which is what the reference's config.oauth.google and .github are
// (auth-config.model.ts:260-270).
func (a *Auth) oauthProviderConfigured(name string) bool {
	if a.oauth == nil || a.oauth.Service == nil {
		return false
	}
	return a.oauth.Service.hasProvider(name)
}

// uiBranding applies the stored settings over the static configuration, member
// by member, in the reference's order of preference (:126-133).
func uiBranding(opts UIOptions, settings *UISettings) UIConfigBranding {
	if settings == nil {
		settings = &UISettings{}
	}
	static := opts.Branding
	return UIConfigBranding{
		PrimaryColor:   uiFirstNonEmpty(uiSetting(settings.PrimaryColor), static.PrimaryColor, UIDefaultPrimaryColor),
		SecondaryColor: uiFirstNonEmpty(uiSetting(settings.SecondaryColor), static.SecondaryColor, UIDefaultSecondaryColor),
		LogoURL:        uiFirstNonEmpty(uiSetting(settings.LogoURL), static.CustomLogo, static.LogoURL),
		SiteName:       uiFirstNonEmpty(uiSetting(settings.SiteName), static.SiteName, UIDefaultSiteName),
		// customCss is static-only: the reference reads it from the config and
		// never from the store (:130), and UISettings has no member for it.
		CustomCSS: opts.CustomCSS,
		BgColor:   uiFirstNonEmpty(uiSetting(settings.BgColor), static.BgColor),
		BgImage:   uiFirstNonEmpty(uiSetting(settings.BgImage), static.BgImage),
		CardBg:    uiFirstNonEmpty(uiSetting(settings.CardBg), static.CardBg),
	}
}

// uiFirstNonEmpty is the reference's chain of `||` over strings: the first
// candidate that is not empty, or the empty string when none is.
func uiFirstNonEmpty(candidates ...string) string {
	for _, candidate := range candidates {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

// uiSetting reads one optional stored branding member. UISettings fields are
// pointers so a patch can carry one without blanking the rest; an absent one is
// the empty string here, which the chain above skips.
func uiSetting(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
