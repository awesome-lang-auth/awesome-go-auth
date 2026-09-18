package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	texttemplate "text/template"
	"time"
)

// MailMessage is a single email to be sent.
type MailMessage struct {
	To      string
	Subject string
	// Body is the message: HTML when IsHTML is set, plain text otherwise.
	Body   string
	IsHTML bool
	// Text is the plain-text alternative of an HTML Body — the reference's
	// `text` payload field (mailer.service.ts:133-141). It is read only when
	// IsHTML is set; a plain-text Body already is the text. Left empty, the
	// gateway transport sends the HTML in its place, as the reference's
	// sendCustom does (`text ?? html`, mailer.service.ts:246).
	//
	// omitempty dates from the HTTPMailerTransport removed in v1.0.0, whose
	// PascalCase body it kept byte-identical for the callers that never set
	// Text. It stays because the tag is part of the type: a host that encodes a
	// MailMessage itself, to a queue or a transport of its own, sees the same
	// bytes it saw before.
	Text string `json:",omitempty"`
}

// MailerTransport delivers email messages.
type MailerTransport interface {
	Send(ctx context.Context, msg MailMessage) error
}

// MailerConfig is the reference's email.mailer block (awesome-node-auth
// src/models/auth-config.model.ts:19-36): the settings of the mail gateway
// NewGatewayMailerTransport talks to. The JSON tags are the reference's key
// names, so a deployment that already holds that block for the reference can
// decode it and hand it over as is.
type MailerConfig struct {
	// Endpoint is the full URL the gateway accepts a POST at
	// (auth-config.model.ts:20-21). It must be an absolute http or https URL;
	// NewGatewayMailerTransport refuses anything else.
	Endpoint string `json:"endpoint"`
	// APIKey travels in the X-API-Key header (auth-config.model.ts:22-23).
	APIKey string `json:"apiKey"`
	// From is the sender address, sent as `from` (auth-config.model.ts:24-25).
	From string `json:"from"`
	// FromName is the sender's display name, sent as `fromName` when set
	// (auth-config.model.ts:26-27).
	FromName string `json:"fromName,omitempty"`
	// Provider names the gateway-side provider, sent as `provider` when set
	// (auth-config.model.ts:28-29).
	Provider string `json:"provider,omitempty"`
	// DefaultLang is the reference's default template language, "en" or "it"
	// (auth-config.model.ts:30-35; read by resolveLang, mailer.service.ts:255-259).
	// The transport does not read it: which template set a mail is rendered
	// from is the mailers' decision (MagicLinkMailer.Locale and its siblings).
	// It is carried so the block decodes as one unit and can be passed on.
	DefaultLang string `json:"defaultLang,omitempty"`
	// Client makes the request. Nil means a client with a 10-second timeout,
	// the same bound HTTPSMSTransport uses.
	Client *http.Client `json:"-"`
}

// NewGatewayMailerTransport builds the transport for the family's mail gateway,
// the contract the reference's built-in mailer speaks (awesome-node-auth
// src/services/mailer.service.ts:261-291):
//
//	POST {endpoint}
//	Content-Type: application/json
//	X-API-Key: {apiKey}
//
//	{"to": …, "subject": …, "html": …, "text": …, "from": …, "fromName": …, "provider": …}
//
// Any status outside 2xx is a failure (mailer.service.ts:280-284). The
// endpoint's own path and query are kept, as the reference keeps them
// (mailer.service.ts:269).
//
// It fails when cfg.Endpoint is empty or not an absolute http(s) URL, so that a
// misconfiguration surfaces at start-up rather than as a 500 on the first send.
// The reference has no such check — `new URL(endpoint)` throws inside send — so
// the constructor is the port's only addition, and it adds no request.
func NewGatewayMailerTransport(cfg MailerConfig) (MailerTransport, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("auth: mailer gateway endpoint is required")
	}
	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("auth: mailer gateway endpoint: %w", err)
	}
	if (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" {
		return nil, fmt.Errorf("auth: mailer gateway endpoint %q must be an absolute http or https URL", cfg.Endpoint)
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &gatewayMailerTransport{cfg: cfg, client: client}, nil
}

// gatewayMailerTransport is what NewGatewayMailerTransport returns. It is not
// exported: the constructor is the only way to obtain one because it is where
// the endpoint is validated.
type gatewayMailerTransport struct {
	cfg    MailerConfig
	client *http.Client
}

// gatewayMailPayload is the reference's MailPayload (mailer.service.ts:133-141),
// key for key. fromName and provider are optional there and JSON.stringify
// drops an undefined value, so they are omitted when empty rather than sent
// blank.
type gatewayMailPayload struct {
	To       string `json:"to"`
	Subject  string `json:"subject"`
	HTML     string `json:"html"`
	Text     string `json:"text"`
	From     string `json:"from"`
	FromName string `json:"fromName,omitempty"`
	Provider string `json:"provider,omitempty"`
}

func (t *gatewayMailerTransport) Send(ctx context.Context, msg MailMessage) error {
	payload := gatewayMailPayload{
		To:       msg.To,
		Subject:  msg.Subject,
		From:     t.cfg.From,
		FromName: t.cfg.FromName,
		Provider: t.cfg.Provider,
	}
	if msg.IsHTML {
		payload.HTML = msg.Body
		payload.Text = msg.Text
	} else {
		// A plain-text message has no HTML to offer. The reference has no
		// text-only path, so html goes out empty rather than filled with a
		// body that is not HTML.
		payload.Text = msg.Body
	}
	if payload.Text == "" {
		// text ?? html: the reference sends the HTML as the text when none was
		// supplied (mailer.service.ts:246).
		payload.Text = payload.HTML
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// Set unconditionally, empty value included, as HTTPSMSTransport does and
	// for the same reason: the reference always sends the header
	// (mailer.service.ts:274).
	req.Header.Set("X-API-Key", t.cfg.APIKey)

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth: mailer gateway send: %w", err)
	}
	resp.Body.Close()
	// 2xx only (mailer.service.ts:280-284). The status is all the error carries:
	// the response body is discarded unread, as the reference's res.resume()
	// discards it, and nothing the request was sent with — the key least of
	// all — is repeated back.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("auth: mailer gateway status %d", resp.StatusCode)
	}
	return nil
}

// -----------------------------------------------------------------------------
// templates
// -----------------------------------------------------------------------------

// The six template ids the reference renders, as its MailerService names them
// (mailer.service.ts:186, 191, 196, 201, 206, 211). They are the ids a
// TemplateStore is asked for and the ids Register, RenderMail and Render take —
// as given. The ids this port used before it adopted the reference's
// (reset_password, magic_link, verify_email, email_change) were aliases of the
// first four through the 0.x line and are not resolved any more: an id is
// looked up under its own spelling, in the store and among the registered
// templates alike, so a stored row under an old id is not the row a mailer
// asks for. There is no email_change template of its own in the reference
// either: /change-email/request mails the verification template
// (auth.router.ts:1027-1032, calling sendVerificationEmail), and so does
// EmailChangeMailer.
const (
	TemplatePasswordReset = "password-reset"
	TemplateMagicLink     = "magic-link"
	TemplateWelcome       = "welcome"
	TemplateVerifyEmail   = "verify-email"
	TemplateEmailChanged  = "email-changed"
	TemplateInvitation    = "invitation"
)

// MailTemplateData holds the variables a template is rendered with.
//
// A built-in template, or one added with Register, reads them as Go template
// fields — {{.link}}, {{.token}} … — and a stored template reads the same keys
// as {{link}}, {{token}} … (see RenderMail). The keys are the reference's, so a
// stored template written for it renders here unchanged:
//
//	token     Token                  (mailer.service.ts:186, 191, 201)
//	link      URL, for every id but welcome           (:186, 191, 201, 211)
//	loginUrl  URL, for welcome only — the name its template reads (:62); the
//	          reference's router passes {loginUrl} there (auth.router.ts:724)
//	newEmail  NewEmail               (:206)
//	…         every Extra entry under its own key, formatted with fmt.Sprint;
//	          the welcome template's tempPassword (:63) travels here
//	appName   AppName, the templater's, when it has one  (a key of this port's)
//	name      UserName                                   (a key of this port's)
//	code      Code                                       (a key of this port's)
//	oldEmail  OldEmail                                   (a key of this port's)
//
// An empty field is left out rather than set to "", so a stored template naming
// a key the caller did not supply shows the reference's "[key]" placeholder.
// The reference never passes appName, name, code or oldEmail, and they are
// absent here too until set, so a stored template written for it sees exactly
// the keys it sees there: {link, token} for password-reset, magic-link and
// verify-email (:186, :191, :201), {link} for invitation (:211), {newEmail} for
// email-changed (:206), {loginUrl, tempPassword} for welcome
// (auth.router.ts:724). The ready-made mailers supply what the reference's
// senders do and nothing else. A field set on the struct wins over an Extra
// entry of the same key.
type MailTemplateData struct {
	AppName  string
	UserName string
	Token    string
	URL      string
	Code     string
	// NewEmail and OldEmail are the two addresses of the email-changed notice.
	NewEmail string
	OldEmail string
	Extra    map[string]any
}

// values is the key -> value map both template kinds render from. id is the
// canonical template id: it decides which name URL travels under.
func (d MailTemplateData) values(id string) map[string]string {
	out := make(map[string]string, len(d.Extra)+8)
	for k, v := range d.Extra {
		if v == nil {
			// `data[key] ?? '[KEY]'`: a null value is as absent (mailer.service.ts:167).
			continue
		}
		out[k] = fmt.Sprint(v)
	}
	set := func(key, value string) {
		if value != "" {
			out[key] = value
		}
	}
	set("appName", d.AppName)
	set("name", d.UserName)
	set("token", d.Token)
	if id == TemplateWelcome {
		// The welcome data is {loginUrl, tempPassword?} (auth.router.ts:724,
		// mailer.service.ts:62-63): the sign-in URL under the name the
		// template reads, and no link.
		set("loginUrl", d.URL)
	} else {
		set("link", d.URL)
	}
	set("code", d.Code)
	set("newEmail", d.NewEmail)
	set("oldEmail", d.OldEmail)
	return out
}

// MailRendered is a rendered mail: what RenderMail returns and what a
// ready-made mailer hands its transport as Subject, Body (the HTML) and Text.
type MailRendered struct {
	Subject string
	HTML    string
	Text    string
}

// MailTemplater renders localized mail templates: the reference's six
// built-ins in en and it, any the host registers over them, and — when a
// TemplateStore is reachable — the stored override for an id.
//
// It is the port's MailerService.render (mailer.service.ts:149-181): the store
// is consulted first and used when it holds both bodies; otherwise the
// registered template renders. Register is meant for set-up time; RenderMail
// and Render are safe to call concurrently, with each other and with Register.
type MailTemplater struct {
	// Store is the template store RenderMail consults. Nil means the one the
	// service put on the context — Config.Templates, set with WithTemplateStore,
	// which reaches every sender the service calls — and, when there is none
	// there either, the built-ins only. Set it to render from a store outside a
	// service call, or from a store other than the configured one.
	Store TemplateStore

	appName string
	mu      sync.RWMutex
	tmpls   map[string]*mailTemplate
}

// mailTemplate is one registered (locale, id) pair. All three parts are Go
// templates, so a registered subject can carry {{.appName}}: text/template for
// the subject and the text body, html/template — contextual escaping included
// — for the HTML body. err is a parse failure, reported on render rather than
// at Register, which has no error return.
type mailTemplate struct {
	subject *texttemplate.Template
	html    *htmltemplate.Template
	text    *texttemplate.Template
	err     error
}

// NewMailTemplater creates a templater with the built-in en and it templates
// for the six reference ids. appName is what a template mentioning
// {{.appName}} shows; the built-ins mention none, as the reference's do not,
// and it is carried as the appName data key for stored and registered ones.
func NewMailTemplater(appName string) *MailTemplater {
	t := &MailTemplater{appName: appName, tmpls: make(map[string]*mailTemplate)}
	for _, b := range builtinMailTemplates {
		t.Register(b.locale, b.id, b.subject, b.html, b.text)
	}
	return t
}

// Register adds or replaces the template rendered for id in locale. The three
// parts are Go templates over the keys MailTemplateData lists — {{.link}},
// {{.appName}} … — html/template for html, text/template for subject and text.
// It is what NewMailTemplater fills the built-ins in with, and the way a host
// replaces one, or adds a locale or an id of its own, without a TemplateStore.
//
// A part that does not parse is kept and reported by RenderMail for that
// (locale, id) rather than dropped: a typo must surface, and Register has no
// error return to surface it through.
func (t *MailTemplater) Register(locale, id, subject, html, text string) {
	entry := &mailTemplate{}
	var err error
	if entry.subject, err = texttemplate.New(id + "/subject").Option("missingkey=zero").Parse(subject); err != nil {
		entry.err = fmt.Errorf("auth: mail template %s/%s subject: %w", locale, id, err)
	} else if entry.html, err = htmltemplate.New(id + "/html").Option("missingkey=zero").Parse(html); err != nil {
		entry.err = fmt.Errorf("auth: mail template %s/%s html: %w", locale, id, err)
	} else if entry.text, err = texttemplate.New(id + "/text").Option("missingkey=zero").Parse(text); err != nil {
		entry.err = fmt.Errorf("auth: mail template %s/%s text: %w", locale, id, err)
	}
	t.mu.Lock()
	if t.tmpls == nil {
		// A zero-value MailTemplater has no built-ins and no map; Register on
		// it must add, not panic.
		t.tmpls = make(map[string]*mailTemplate)
	}
	t.tmpls[locale+"/"+id] = entry
	t.mu.Unlock()
}

// lookup finds the registered template for id in locale, falling back to en.
func (t *MailTemplater) lookup(locale, id string) *mailTemplate {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if entry, ok := t.tmpls[locale+"/"+id]; ok {
		return entry
	}
	return t.tmpls["en/"+id]
}

// storeFor is the store RenderMail consults: Store, else the one the service
// put on ctx, else none.
func (t *MailTemplater) storeFor(ctx context.Context) TemplateStore {
	if t.Store != nil {
		return t.Store
	}
	return templateStoreFromContext(ctx)
}

// RenderMail renders template id in locale: subject, HTML body and text body.
//
// It is the reference's MailerService.render (mailer.service.ts:149-181):
//
//   - A stored template is looked up first — through Store, or the store the
//     service put on ctx (Config.Templates) — and used only when both its
//     BaseHTML and BaseText are non-empty (:158). A store error is returned.
//   - Its translations are those for locale, else for "en", else none (:159).
//     Every {{T.key}} becomes translations[key], or "[key]" when that is
//     missing or empty (:163); then every remaining {{key}} becomes the data
//     value for key — the keys MailTemplateData lists, which for a template
//     written against the reference are exactly the ones it passes — or
//     "[key]" when there is none (:165-168). The subject is
//     translations["subject"], else the registered subject for the language,
//     interpolated the same way (:172-177). Values are substituted as they
//     are, in the HTML body included — no HTML escaping, because the
//     reference does none (:167). A stored BaseHTML is the deployment's own
//     markup, but not every value is: newEmail is the address the user typed
//     on /change-email/request, lowercased and trimmed and nothing more, and
//     an Extra entry is whatever the caller put there. A stored template that
//     shows them mails them verbatim, as the reference's does; the built-ins,
//     rendered by html/template, escape them.
//   - Otherwise the registered template for locale renders — the built-in one
//     unless Register replaced it — falling back to "en" when locale has none,
//     with html/template's contextual escaping in the HTML body.
//
// locale is used as given; the ready-made mailers pass what resolveLang
// picked, and id is used as given too (see the template constants). An id
// with neither a usable stored template nor a registered one is an error.
func (t *MailTemplater) RenderMail(ctx context.Context, locale, id string, data MailTemplateData) (MailRendered, error) {
	if t == nil {
		return MailRendered{}, errors.New("auth: nil mail templater")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	data.AppName = t.appName
	values := data.values(id)
	registered := t.lookup(locale, id)

	if store := t.storeFor(ctx); store != nil {
		stored, ok, err := store.GetMailTemplate(ctx, id)
		if err != nil {
			return MailRendered{}, fmt.Errorf("auth: mail template %q: %w", id, err)
		}
		if ok && stored.BaseHTML != "" && stored.BaseText != "" {
			return renderStoredTemplate(id, stored, locale, values, registered)
		}
	}
	if registered == nil {
		return MailRendered{}, fmt.Errorf("auth: mail template %q not found", id)
	}
	return registered.render(id, values)
}

// Render produces the subject and HTML body for the given locale and template
// id: RenderMail without a context and without the text body, kept for the
// callers that want exactly that. The store the service configured is only
// reachable through the context, so a Render outside a service call sees
// Store and the built-ins.
func (t *MailTemplater) Render(locale, name string, data MailTemplateData) (subject, body string, err error) {
	rendered, err := t.RenderMail(context.Background(), locale, name, data)
	if err != nil {
		return "", "", err
	}
	return rendered.Subject, rendered.HTML, nil
}

func (m *mailTemplate) render(id string, values map[string]string) (MailRendered, error) {
	if m.err != nil {
		return MailRendered{}, m.err
	}
	subject, err := executeTemplate(m.subject, values)
	if err != nil {
		return MailRendered{}, fmt.Errorf("auth: render mail template %q subject: %w", id, err)
	}
	html, err := executeTemplate(m.html, values)
	if err != nil {
		return MailRendered{}, fmt.Errorf("auth: render mail template %q: %w", id, err)
	}
	text, err := executeTemplate(m.text, values)
	if err != nil {
		return MailRendered{}, fmt.Errorf("auth: render mail template %q text: %w", id, err)
	}
	return MailRendered{Subject: subject, HTML: html, Text: text}, nil
}

// templateExecutor is what html/template and text/template have in common.
type templateExecutor interface {
	Execute(w io.Writer, data any) error
}

func executeTemplate(tmpl templateExecutor, values map[string]string) (string, error) {
	var buf strings.Builder
	if err := tmpl.Execute(&buf, values); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// renderStoredTemplate is the store branch of RenderMail (mailer.service.ts:
// 158-177). registered supplies the fallback subject and may be nil.
func renderStoredTemplate(id string, stored MailTemplate, locale string, values map[string]string, registered *mailTemplate) (MailRendered, error) {
	translations := pickTranslations(stored.Translations, locale)
	subject := translations["subject"]
	if subject == "" && registered != nil {
		if registered.err != nil {
			return MailRendered{}, registered.err
		}
		fallback, err := executeTemplate(registered.subject, values)
		if err != nil {
			return MailRendered{}, fmt.Errorf("auth: render mail template %q subject: %w", id, err)
		}
		subject = fallback
	}
	return MailRendered{
		Subject: interpolateStored(subject, translations, values),
		HTML:    interpolateStored(stored.BaseHTML, translations, values),
		Text:    interpolateStored(stored.BaseText, translations, values),
	}, nil
}

// pickTranslations is `translations[lang] || translations['en'] || {}`
// (mailer.service.ts:159). Presence decides, as JavaScript's || does on an
// object: a language whose map is empty is still that language's map.
func pickTranslations(all map[string]map[string]string, locale string) map[string]string {
	if m, ok := all[locale]; ok && m != nil {
		return m
	}
	if m, ok := all["en"]; ok && m != nil {
		return m
	}
	return map[string]string{}
}

// The two placeholder shapes of a stored template, the reference's regular
// expressions verbatim (mailer.service.ts:163, 165).
var (
	storedTranslationPattern = regexp.MustCompile(`\{\{T\.([^}]+)\}\}`)
	storedDataPattern        = regexp.MustCompile(`\{\{([^}]+)\}\}`)
)

// interpolateStored is the reference's interpolate (mailer.service.ts:161-170):
// translations first, data second, each missing one left as its bracketed key.
// A translation that is present but empty counts as missing (`||`, :163); a
// data value that is present but empty does not (`??`, :167).
func interpolateStored(s string, translations, values map[string]string) string {
	s = storedTranslationPattern.ReplaceAllStringFunc(s, func(match string) string {
		key := match[len("{{T.") : len(match)-len("}}")]
		if v := translations[key]; v != "" {
			return v
		}
		return "[" + key + "]"
	})
	return storedDataPattern.ReplaceAllStringFunc(s, func(match string) string {
		key := match[len("{{") : len(match)-len("}}")]
		if strings.HasPrefix(key, "T.") {
			// Already handled above (:166): a translation that itself reads
			// {{T.x}} is left as it is, not resolved twice.
			return match
		}
		if v, ok := values[key]; ok {
			return v
		}
		return "[" + key + "]"
	})
}

// builtinMailTemplates are the reference's built-in templates — subject, html
// and text for each of the six ids in en and it (mailer.service.ts:19-127; the
// invitation fallback :211-225) — with its ${…} interpolations as the Go
// template fields MailTemplateData lists. The wording is the reference's,
// which is what keeps a mailbox from telling the two ports apart.
var builtinMailTemplates = []struct {
	locale, id, subject, html, text string
}{
	// password-reset (:19-38)
	{"en", TemplatePasswordReset, "Reset your password",
		`<p>You requested a password reset.</p>
<p>Click the link below to proceed (valid for 1 hour):</p>
<p><a href="{{.link}}">{{.link}}</a></p>
<p>If you did not request this, please ignore this email.</p>`,
		`You requested a password reset.

Click the link below (valid for 1 hour):
{{.link}}

If you did not request this, please ignore this email.`},
	{"it", TemplatePasswordReset, "Reimposta la tua password",
		`<p>Hai richiesto di reimpostare la tua password.</p>
<p>Clicca sul link seguente per procedere (valido 1 ora):</p>
<p><a href="{{.link}}">{{.link}}</a></p>
<p>Se non hai richiesto questo, ignora questa email.</p>`,
		`Hai richiesto di reimpostare la tua password.

Clicca sul link seguente (valido 1 ora):
{{.link}}

Se non hai richiesto questo, ignora questa email.`},

	// magic-link (:40-59)
	{"en", TemplateMagicLink, "Your magic sign-in link",
		`<p>You requested a sign-in link.</p>
<p>Click the link below to sign in (valid for 15 minutes):</p>
<p><a href="{{.link}}">{{.link}}</a></p>
<p>If you did not request this, please ignore this email.</p>`,
		`You requested a sign-in link.

Click the link below (valid for 15 minutes):
{{.link}}

If you did not request this, please ignore this email.`},
	{"it", TemplateMagicLink, "Il tuo link di accesso",
		`<p>Hai richiesto un link di accesso.</p>
<p>Clicca sul link seguente per accedere (valido 15 minuti):</p>
<p><a href="{{.link}}">{{.link}}</a></p>
<p>Se non hai richiesto questo, ignora questa email.</p>`,
		`Hai richiesto un link di accesso.

Clicca sul link seguente (valido 15 minuti):
{{.link}}

Se non hai richiesto questo, ignora questa email.`},

	// welcome (:61-89): the temporary-password line appears only when one is
	// supplied, as the reference's passwordLine / passwordText do (:66-69, 78-81).
	{"en", TemplateWelcome, "Welcome! Your account has been created",
		`<p>Your account has been created successfully.</p>
{{if .tempPassword}}<p>Temporary password: <strong>{{.tempPassword}}</strong></p>{{end}}
<p>Sign in here: <a href="{{.loginUrl}}">{{.loginUrl}}</a></p>`,
		`Your account has been created successfully.
{{if .tempPassword}}Temporary password: {{.tempPassword}}
{{end}}Sign in here: {{.loginUrl}}`},
	{"it", TemplateWelcome, "Benvenuto! Il tuo account è stato creato",
		`<p>Il tuo account è stato creato con successo.</p>
{{if .tempPassword}}<p>Password temporanea: <strong>{{.tempPassword}}</strong></p>{{end}}
<p>Accedi qui: <a href="{{.loginUrl}}">{{.loginUrl}}</a></p>`,
		`Il tuo account è stato creato con successo.
{{if .tempPassword}}Password temporanea: {{.tempPassword}}
{{end}}Accedi qui: {{.loginUrl}}`},

	// verify-email (:91-110)
	{"en", TemplateVerifyEmail, "Verify your email address",
		`<p>Thank you for signing up.</p>
<p>Click the link below to verify your email address (valid for 24 hours):</p>
<p><a href="{{.link}}">{{.link}}</a></p>
<p>If you did not create an account, please ignore this email.</p>`,
		`Thank you for signing up.

Click the link below to verify your email address (valid for 24 hours):
{{.link}}

If you did not create an account, please ignore this email.`},
	{"it", TemplateVerifyEmail, "Verifica il tuo indirizzo email",
		`<p>Grazie per esserti registrato.</p>
<p>Clicca sul link seguente per verificare il tuo indirizzo email (valido 24 ore):</p>
<p><a href="{{.link}}">{{.link}}</a></p>
<p>Se non hai creato un account, ignora questa email.</p>`,
		`Grazie per esserti registrato.

Clicca sul link seguente per verificare il tuo indirizzo email (valido 24 ore):
{{.link}}

Se non hai creato un account, ignora questa email.`},

	// email-changed (:112-127)
	{"en", TemplateEmailChanged, "Your email address has been updated",
		`<p>This is a notice that your email address has been updated to <strong>{{.newEmail}}</strong>.</p>
<p>If you did not request this change, please contact support immediately.</p>`,
		`Your email address has been updated to {{.newEmail}}.

If you did not request this change, please contact support immediately.`},
	{"it", TemplateEmailChanged, "Il tuo indirizzo email è stato aggiornato",
		`<p>Questo è un avviso che il tuo indirizzo email è stato aggiornato a <strong>{{.newEmail}}</strong>.</p>
<p>Se non hai richiesto questa modifica, contatta immediatamente il supporto.</p>`,
		`Il tuo indirizzo email è stato aggiornato a {{.newEmail}}.

Se non hai richiesto questa modifica, contatta immediatamente il supporto.`},

	// invitation (:211-225)
	{"en", TemplateInvitation, "Invitation to join",
		`<p>You have been invited.</p><p><a href="{{.link}}">{{.link}}</a></p>`,
		`You have been invited.

{{.link}}`},
	{"it", TemplateInvitation, "Invito ad unirsi",
		`<p>Sei stato invitato.</p><p><a href="{{.link}}">{{.link}}</a></p>`,
		`Sei stato invitato.

{{.link}}`},
}
