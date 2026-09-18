package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// Tests for the templater half of mailer.go: the six built-ins are the
// reference's, the deprecated ids still work, Register overrides and adds, and
// a TemplateStore is consulted under the reference's rule
// (mailer.service.ts:149-181). The transport half is in mailer_test.go.

const (
	testMailLink     = "https://app.example.com/auth/reset-password?token=tok123"
	testMailNewEmail = "new@example.com"
)

// builtInMailSnapshot is what the reference's built-in templates produce
// (mailer.service.ts:19-127; invitation :211-225) with ${link}, ${newEmail},
// ${loginUrl} and ${tempPassword} substituted — the six ids in en and it,
// subject, html and text, verbatim. A mailbox must not be able to tell the two
// ports apart.
var builtInMailSnapshot = []struct {
	name, locale, id string
	data             MailTemplateData
	want             MailRendered
}{
	{"password-reset/en", "en", TemplatePasswordReset, MailTemplateData{URL: testMailLink}, MailRendered{
		Subject: "Reset your password",
		HTML:    "<p>You requested a password reset.</p>\n<p>Click the link below to proceed (valid for 1 hour):</p>\n<p><a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>\n<p>If you did not request this, please ignore this email.</p>",
		Text:    "You requested a password reset.\n\nClick the link below (valid for 1 hour):\n" + testMailLink + "\n\nIf you did not request this, please ignore this email.",
	}},
	{"password-reset/it", "it", TemplatePasswordReset, MailTemplateData{URL: testMailLink}, MailRendered{
		Subject: "Reimposta la tua password",
		HTML:    "<p>Hai richiesto di reimpostare la tua password.</p>\n<p>Clicca sul link seguente per procedere (valido 1 ora):</p>\n<p><a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>\n<p>Se non hai richiesto questo, ignora questa email.</p>",
		Text:    "Hai richiesto di reimpostare la tua password.\n\nClicca sul link seguente (valido 1 ora):\n" + testMailLink + "\n\nSe non hai richiesto questo, ignora questa email.",
	}},
	{"magic-link/en", "en", TemplateMagicLink, MailTemplateData{URL: testMailLink}, MailRendered{
		Subject: "Your magic sign-in link",
		HTML:    "<p>You requested a sign-in link.</p>\n<p>Click the link below to sign in (valid for 15 minutes):</p>\n<p><a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>\n<p>If you did not request this, please ignore this email.</p>",
		Text:    "You requested a sign-in link.\n\nClick the link below (valid for 15 minutes):\n" + testMailLink + "\n\nIf you did not request this, please ignore this email.",
	}},
	{"magic-link/it", "it", TemplateMagicLink, MailTemplateData{URL: testMailLink}, MailRendered{
		Subject: "Il tuo link di accesso",
		HTML:    "<p>Hai richiesto un link di accesso.</p>\n<p>Clicca sul link seguente per accedere (valido 15 minuti):</p>\n<p><a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>\n<p>Se non hai richiesto questo, ignora questa email.</p>",
		Text:    "Hai richiesto un link di accesso.\n\nClicca sul link seguente (valido 15 minuti):\n" + testMailLink + "\n\nSe non hai richiesto questo, ignora questa email.",
	}},
	// welcome: the temporary-password line appears only when one is supplied
	// (mailer.service.ts:66-69, 78-81), which leaves the reference's blank line
	// in the HTML when it is not.
	{"welcome/en", "en", TemplateWelcome, MailTemplateData{URL: testMailLink}, MailRendered{
		Subject: "Welcome! Your account has been created",
		HTML:    "<p>Your account has been created successfully.</p>\n\n<p>Sign in here: <a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>",
		Text:    "Your account has been created successfully.\nSign in here: " + testMailLink,
	}},
	{"welcome/en with a temporary password", "en", TemplateWelcome, MailTemplateData{URL: testMailLink, Extra: map[string]any{"tempPassword": "Tmp-1234"}}, MailRendered{
		Subject: "Welcome! Your account has been created",
		HTML:    "<p>Your account has been created successfully.</p>\n<p>Temporary password: <strong>Tmp-1234</strong></p>\n<p>Sign in here: <a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>",
		Text:    "Your account has been created successfully.\nTemporary password: Tmp-1234\nSign in here: " + testMailLink,
	}},
	{"welcome/it", "it", TemplateWelcome, MailTemplateData{URL: testMailLink}, MailRendered{
		Subject: "Benvenuto! Il tuo account è stato creato",
		HTML:    "<p>Il tuo account è stato creato con successo.</p>\n\n<p>Accedi qui: <a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>",
		Text:    "Il tuo account è stato creato con successo.\nAccedi qui: " + testMailLink,
	}},
	{"welcome/it with a temporary password", "it", TemplateWelcome, MailTemplateData{URL: testMailLink, Extra: map[string]any{"tempPassword": "Tmp-1234"}}, MailRendered{
		Subject: "Benvenuto! Il tuo account è stato creato",
		HTML:    "<p>Il tuo account è stato creato con successo.</p>\n<p>Password temporanea: <strong>Tmp-1234</strong></p>\n<p>Accedi qui: <a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>",
		Text:    "Il tuo account è stato creato con successo.\nPassword temporanea: Tmp-1234\nAccedi qui: " + testMailLink,
	}},
	{"verify-email/en", "en", TemplateVerifyEmail, MailTemplateData{URL: testMailLink}, MailRendered{
		Subject: "Verify your email address",
		HTML:    "<p>Thank you for signing up.</p>\n<p>Click the link below to verify your email address (valid for 24 hours):</p>\n<p><a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>\n<p>If you did not create an account, please ignore this email.</p>",
		Text:    "Thank you for signing up.\n\nClick the link below to verify your email address (valid for 24 hours):\n" + testMailLink + "\n\nIf you did not create an account, please ignore this email.",
	}},
	{"verify-email/it", "it", TemplateVerifyEmail, MailTemplateData{URL: testMailLink}, MailRendered{
		Subject: "Verifica il tuo indirizzo email",
		HTML:    "<p>Grazie per esserti registrato.</p>\n<p>Clicca sul link seguente per verificare il tuo indirizzo email (valido 24 ore):</p>\n<p><a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>\n<p>Se non hai creato un account, ignora questa email.</p>",
		Text:    "Grazie per esserti registrato.\n\nClicca sul link seguente per verificare il tuo indirizzo email (valido 24 ore):\n" + testMailLink + "\n\nSe non hai creato un account, ignora questa email.",
	}},
	{"email-changed/en", "en", TemplateEmailChanged, MailTemplateData{NewEmail: testMailNewEmail}, MailRendered{
		Subject: "Your email address has been updated",
		HTML:    "<p>This is a notice that your email address has been updated to <strong>" + testMailNewEmail + "</strong>.</p>\n<p>If you did not request this change, please contact support immediately.</p>",
		Text:    "Your email address has been updated to " + testMailNewEmail + ".\n\nIf you did not request this change, please contact support immediately.",
	}},
	{"email-changed/it", "it", TemplateEmailChanged, MailTemplateData{NewEmail: testMailNewEmail}, MailRendered{
		Subject: "Il tuo indirizzo email è stato aggiornato",
		HTML:    "<p>Questo è un avviso che il tuo indirizzo email è stato aggiornato a <strong>" + testMailNewEmail + "</strong>.</p>\n<p>Se non hai richiesto questa modifica, contatta immediatamente il supporto.</p>",
		Text:    "Il tuo indirizzo email è stato aggiornato a " + testMailNewEmail + ".\n\nSe non hai richiesto questa modifica, contatta immediatamente il supporto.",
	}},
	{"invitation/en", "en", TemplateInvitation, MailTemplateData{URL: testMailLink}, MailRendered{
		Subject: "Invitation to join",
		HTML:    "<p>You have been invited.</p><p><a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>",
		Text:    "You have been invited.\n\n" + testMailLink,
	}},
	{"invitation/it", "it", TemplateInvitation, MailTemplateData{URL: testMailLink}, MailRendered{
		Subject: "Invito ad unirsi",
		HTML:    "<p>Sei stato invitato.</p><p><a href=\"" + testMailLink + "\">" + testMailLink + "</a></p>",
		Text:    "Sei stato invitato.\n\n" + testMailLink,
	}},
}

func TestMailTemplaterBuiltInsAreTheReferenceTemplates(t *testing.T) {
	tm := NewMailTemplater("Example App")
	seen := map[string]bool{}
	for _, tc := range builtInMailSnapshot {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tm.RenderMail(context.Background(), tc.locale, tc.id, tc.data)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if got != tc.want {
				t.Errorf("rendered\n%#v\nwant\n%#v", got, tc.want)
			}
			if strings.Contains(got.Text, "<") {
				t.Errorf("Text carries markup: %q", got.Text)
			}
			// Render is RenderMail without the text body, for the callers that
			// want exactly that.
			subject, body, err := tm.Render(tc.locale, tc.id, tc.data)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if subject != tc.want.Subject || body != tc.want.HTML {
				t.Errorf("Render = %q / %q, want the subject and HTML of RenderMail", subject, body)
			}
			seen[tc.locale+"/"+tc.id] = true
		})
	}
	// Every one of the six ids, in both languages, is pinned above.
	for _, id := range []string{TemplatePasswordReset, TemplateMagicLink, TemplateWelcome, TemplateVerifyEmail, TemplateEmailChanged, TemplateInvitation} {
		for _, locale := range []string{"en", "it"} {
			if !seen[locale+"/"+id] {
				t.Errorf("no snapshot for %s/%s", locale, id)
			}
		}
	}
}

// The four 0.3.x ids were aliases of the reference's through the 0.x line and
// are plain ids now, resolved nowhere: RenderMail on one finds no built-in, and
// a stored row under one is not the row TemplatePasswordReset is asked for.
// That second half is the migration this pins — a deployment whose template
// store holds "reset_password" renames the row to the constant, because
// nothing here will read it for the password-reset mail any more.
func TestMailTemplaterNoLongerResolvesTheOldIDs(t *testing.T) {
	ctx := context.Background()
	tm := NewMailTemplater("Example App")
	data := MailTemplateData{Token: "tok123", URL: testMailLink}
	for _, old := range []string{"reset_password", "magic_link", "verify_email", "email_change"} {
		if got, err := tm.RenderMail(ctx, "en", old, data); err == nil {
			t.Errorf("RenderMail(%q) rendered %+v; the old id is not an alias any more and has no built-in", old, got)
		}
	}

	// Register under an old id registers exactly that id — it neither replaces
	// the constant's built-in nor becomes reachable through it.
	tm.Register("en", "magic_link", "Registered under the old id", "<p>{{.link}}</p>", "{{.link}}")
	if got, err := tm.RenderMail(ctx, "en", TemplateMagicLink, data); err != nil || got.Subject == "Registered under the old id" {
		t.Errorf("Register(magic_link) reached the magic-link id: %+v, %v", got, err)
	}
	if got, err := tm.RenderMail(ctx, "en", "magic_link", data); err != nil || got.Subject != "Registered under the old id" {
		t.Errorf("Register(magic_link) did not register magic_link itself: %+v, %v", got, err)
	}

	// A stored row under the old id is not consulted for the constant.
	store := NewMemoryTemplateStore()
	if _, err := store.UpdateMailTemplate(ctx, "reset_password", MailTemplatePatch{
		BaseHTML: strPtr("<p>stored {{link}}</p>"), BaseText: strPtr("stored {{link}}"),
	}); err != nil {
		t.Fatal(err)
	}
	tm.Store = store
	got, err := tm.RenderMail(ctx, "en", TemplatePasswordReset, data)
	if err != nil {
		t.Fatalf("%s: %v", TemplatePasswordReset, err)
	}
	if got.HTML == "<p>stored "+testMailLink+"</p>" {
		t.Errorf("the row stored under reset_password served %s: the old id is still being resolved", TemplatePasswordReset)
	}
}

// A locale with no template set falls back to English, as the reference's
// resolveLang ends in 'en' (mailer.service.ts:258).
func TestMailTemplaterFallsBackToEnglish(t *testing.T) {
	ctx := context.Background()
	tm := NewMailTemplater("")
	data := MailTemplateData{URL: testMailLink}
	en, err := tm.RenderMail(ctx, "en", TemplatePasswordReset, data)
	if err != nil {
		t.Fatal(err)
	}
	for _, locale := range []string{"", "de", "EN", "en-US"} {
		got, err := tm.RenderMail(ctx, locale, TemplatePasswordReset, data)
		if err != nil {
			t.Fatalf("locale %q: %v", locale, err)
		}
		if got != en {
			t.Errorf("locale %q rendered %+v, want the English set", locale, got)
		}
	}
	it, err := tm.RenderMail(ctx, "it", TemplatePasswordReset, data)
	if err != nil {
		t.Fatal(err)
	}
	if it == en {
		t.Error("it rendered the English set")
	}
	if _, err := tm.RenderMail(ctx, "en", "no-such-template", data); err == nil {
		t.Error("an unknown id must be an error")
	}
}

func TestMailTemplaterRegisterOverridesAndAdds(t *testing.T) {
	ctx := context.Background()
	tm := NewMailTemplater("Example App")
	data := MailTemplateData{URL: testMailLink}

	t.Run("replaces a built-in in one locale only", func(t *testing.T) {
		tm.Register("en", TemplatePasswordReset, "{{.appName}}: reset your password", `<p>Reset: <a href="{{.link}}">{{.link}}</a></p>`, "Reset: {{.link}}")
		got, err := tm.RenderMail(ctx, "en", TemplatePasswordReset, data)
		if err != nil {
			t.Fatal(err)
		}
		want := MailRendered{
			Subject: "Example App: reset your password",
			HTML:    `<p>Reset: <a href="` + testMailLink + `">` + testMailLink + `</a></p>`,
			Text:    "Reset: " + testMailLink,
		}
		if got != want {
			t.Errorf("rendered %+v, want %+v", got, want)
		}
		it, err := tm.RenderMail(ctx, "it", TemplatePasswordReset, data)
		if err != nil || it.Subject != "Reimposta la tua password" {
			t.Errorf("the Italian set was touched: %+v, %v", it, err)
		}
	})

	t.Run("adds a locale, which falls back to en for the other ids", func(t *testing.T) {
		tm.Register("fr", TemplateMagicLink, "Votre lien de connexion", "<p>{{.link}}</p>", "{{.link}}")
		fr, err := tm.RenderMail(ctx, "fr", TemplateMagicLink, data)
		if err != nil || fr.Subject != "Votre lien de connexion" {
			t.Errorf("fr magic-link = %+v, %v", fr, err)
		}
		reset, err := tm.RenderMail(ctx, "fr", TemplatePasswordReset, data)
		if err != nil || reset.Subject != "Example App: reset your password" {
			t.Errorf("fr password-reset = %+v, %v; want the en set", reset, err)
		}
	})

	t.Run("adds an id of the deployment's own", func(t *testing.T) {
		tm.Register("en", "account-locked", "Account locked", "<p>Sorry, {{.name}}.</p>", "Sorry, {{.name}}.")
		got, err := tm.RenderMail(ctx, "en", "account-locked", MailTemplateData{UserName: "Ada"})
		if err != nil {
			t.Fatal(err)
		}
		if got.HTML != "<p>Sorry, Ada.</p>" || got.Text != "Sorry, Ada." || got.Subject != "Account locked" {
			t.Errorf("rendered %+v", got)
		}
	})

	t.Run("the HTML body is contextually escaped, the text body is not", func(t *testing.T) {
		tm.Register("en", "escaped", "s", "<p>{{.name}}</p>", "{{.name}}")
		got, err := tm.RenderMail(ctx, "en", "escaped", MailTemplateData{UserName: "<b>"})
		if err != nil {
			t.Fatal(err)
		}
		if got.HTML != "<p>&lt;b&gt;</p>" || got.Text != "<b>" {
			t.Errorf("rendered %+v", got)
		}
	})

	t.Run("a part that does not parse is reported on render", func(t *testing.T) {
		tm.Register("en", "broken", "s", "<p>{{.link</p>", "x")
		_, err := tm.RenderMail(ctx, "en", "broken", data)
		if err == nil || !strings.Contains(err.Error(), "broken") {
			t.Errorf("err = %v, want a parse failure naming the template", err)
		}
	})

	t.Run("a zero-value templater has no built-ins and accepts Register", func(t *testing.T) {
		var zero MailTemplater
		if _, err := zero.RenderMail(ctx, "en", TemplatePasswordReset, data); err == nil {
			t.Error("a zero-value templater rendered a built-in")
		}
		zero.Register("en", "only", "Only", "<p>only</p>", "only")
		got, err := zero.RenderMail(ctx, "en", "only", MailTemplateData{})
		if err != nil || got.Subject != "Only" {
			t.Errorf("rendered %+v, %v", got, err)
		}
		var nilTemplater *MailTemplater
		if _, err := nilTemplater.RenderMail(ctx, "en", "only", MailTemplateData{}); err == nil {
			t.Error("a nil templater must fail, not panic")
		}
	})
}

// brokenTemplateStore fails every lookup. The methods the templater never
// calls are left to the embedded nil interface.
type brokenTemplateStore struct {
	TemplateStore
	err error
}

func (s brokenTemplateStore) GetMailTemplate(context.Context, string) (MailTemplate, bool, error) {
	return MailTemplate{}, false, s.err
}

// A stored template is used only when both bodies are non-empty
// (mailer.service.ts:158); otherwise the built-in renders as if the store held
// nothing.
func TestMailTemplaterStorePrecedence(t *testing.T) {
	ctx := context.Background()
	data := MailTemplateData{Token: "tok123", URL: testMailLink}
	builtIn, err := NewMailTemplater("").RenderMail(ctx, "en", TemplatePasswordReset, data)
	if err != nil {
		t.Fatal(err)
	}
	stored := MailRendered{
		Subject: "Reset your password", // no translations: the built-in subject (:172)
		HTML:    "<p>stored " + testMailLink + "</p>",
		Text:    "stored " + testMailLink,
	}
	html, text := strPtr("<p>stored {{link}}</p>"), strPtr("stored {{link}}")

	cases := []struct {
		name  string
		patch MailTemplatePatch
		want  MailRendered
	}{
		{"both bodies: the stored template renders", MailTemplatePatch{BaseHTML: html, BaseText: text}, stored},
		{"html only: the built-in renders", MailTemplatePatch{BaseHTML: html}, builtIn},
		{"text only: the built-in renders", MailTemplatePatch{BaseText: text}, builtIn},
		{"both empty: the built-in renders", MailTemplatePatch{BaseHTML: strPtr(""), BaseText: strPtr("")}, builtIn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryTemplateStore()
			if _, err := store.UpdateMailTemplate(ctx, TemplatePasswordReset, tc.patch); err != nil {
				t.Fatal(err)
			}
			tm := NewMailTemplater("")
			tm.Store = store
			got, err := tm.RenderMail(ctx, "en", TemplatePasswordReset, data)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("rendered %+v, want %+v", got, tc.want)
			}
		})
	}

	t.Run("an id the store does not hold renders the built-in", func(t *testing.T) {
		tm := NewMailTemplater("")
		tm.Store = NewMemoryTemplateStore()
		got, err := tm.RenderMail(ctx, "en", TemplatePasswordReset, data)
		if err != nil || got != builtIn {
			t.Errorf("rendered %+v, %v", got, err)
		}
	})

	full := NewMemoryTemplateStore()
	if _, err := full.UpdateMailTemplate(ctx, TemplatePasswordReset, MailTemplatePatch{BaseHTML: html, BaseText: text}); err != nil {
		t.Fatal(err)
	}

	t.Run("the store the service put on the context is consulted when Store is nil", func(t *testing.T) {
		tm := NewMailTemplater("")
		got, err := tm.RenderMail(withTemplateStore(ctx, full), "en", TemplatePasswordReset, data)
		if err != nil || got != stored {
			t.Errorf("rendered %+v, %v; want the stored template", got, err)
		}
		plain, err := tm.RenderMail(ctx, "en", TemplatePasswordReset, data)
		if err != nil || plain != builtIn {
			t.Errorf("without a store on the context rendered %+v, %v; want the built-in", plain, err)
		}
	})

	t.Run("Store wins over the context store", func(t *testing.T) {
		own := NewMemoryTemplateStore()
		if _, err := own.UpdateMailTemplate(ctx, TemplatePasswordReset, MailTemplatePatch{
			BaseHTML: strPtr("<p>own</p>"), BaseText: strPtr("own"),
		}); err != nil {
			t.Fatal(err)
		}
		tm := NewMailTemplater("")
		tm.Store = own
		got, err := tm.RenderMail(withTemplateStore(ctx, full), "en", TemplatePasswordReset, data)
		if err != nil || got.HTML != "<p>own</p>" {
			t.Errorf("rendered %+v, %v; want the templater's own store", got, err)
		}
	})

	t.Run("Render sees Store and nothing else", func(t *testing.T) {
		tm := NewMailTemplater("")
		subject, body, err := tm.Render("en", TemplatePasswordReset, data)
		if err != nil || subject != builtIn.Subject || body != builtIn.HTML {
			t.Errorf("Render = %q / %q, %v; want the built-in", subject, body, err)
		}
		tm.Store = full
		_, body, err = tm.Render("en", TemplatePasswordReset, data)
		if err != nil || body != stored.HTML {
			t.Errorf("Render with Store = %q, %v; want the stored HTML", body, err)
		}
	})

	t.Run("a store error is returned", func(t *testing.T) {
		down := errors.New("template table unreachable")
		tm := NewMailTemplater("")
		tm.Store = brokenTemplateStore{err: down}
		if _, err := tm.RenderMail(ctx, "en", TemplatePasswordReset, data); !errors.Is(err, down) {
			t.Errorf("err = %v, want it to wrap the store's", err)
		}
	})
}

// The interpolation of a stored template is the reference's interpolate
// (mailer.service.ts:161-170): {{T.key}} from the translations, or [key] when
// missing or empty (||); then {{key}} from the data, or [key] when absent (??,
// so a present empty value stays empty); a {{T.x}} produced by the first pass
// is left alone by the second. The subject is translations.subject, else the
// built-in one, interpolated the same way (:172-174).
func TestMailTemplaterStoredTemplateInterpolation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTemplateStore()
	if _, err := store.UpdateMailTemplate(ctx, TemplatePasswordReset, MailTemplatePatch{
		BaseHTML: strPtr(`<h1>{{T.title}}</h1><p>{{T.body}}</p><p>{{T.missing}} {{T.empty}}</p>` +
			`<p><a href="{{link}}">{{link}}</a> {{token}} {{unknown}} [{{note}}] {{nilled}} {{appName}}</p><p>{{T.nested}}</p>`),
		BaseText: strPtr(`{{T.title}}: {{link}}`),
		Translations: map[string]map[string]string{
			"en": {
				"subject": "{{T.title}} for {{name}}",
				"title":   "Reset",
				"body":    "Use the link",
				"empty":   "",
				"nested":  "see {{link}} and {{T.title}}",
			},
			"it": {"subject": "Reimposta", "title": "Reimposta", "body": "Usa il link"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	tm := NewMailTemplater("Example App")
	tm.Store = store
	data := MailTemplateData{Token: "tok123", URL: testMailLink, Extra: map[string]any{"note": "", "nilled": nil}}

	en, err := tm.RenderMail(ctx, "en", TemplatePasswordReset, data)
	if err != nil {
		t.Fatal(err)
	}
	wantEN := MailRendered{
		Subject: "Reset for [name]",
		HTML: `<h1>Reset</h1><p>Use the link</p><p>[missing] [empty]</p>` +
			`<p><a href="` + testMailLink + `">` + testMailLink + `</a> tok123 [unknown] [] [nilled] Example App</p><p>see ` + testMailLink + ` and {{T.title}}</p>`,
		Text: "Reset: " + testMailLink,
	}
	if en != wantEN {
		t.Errorf("en rendered\n%#v\nwant\n%#v", en, wantEN)
	}

	it, err := tm.RenderMail(ctx, "it", TemplatePasswordReset, data)
	if err != nil {
		t.Fatal(err)
	}
	wantIT := MailRendered{
		Subject: "Reimposta",
		HTML: `<h1>Reimposta</h1><p>Usa il link</p><p>[missing] [empty]</p>` +
			`<p><a href="` + testMailLink + `">` + testMailLink + `</a> tok123 [unknown] [] [nilled] Example App</p><p>[nested]</p>`,
		Text: "Reimposta: " + testMailLink,
	}
	if it != wantIT {
		t.Errorf("it rendered\n%#v\nwant\n%#v", it, wantIT)
	}

	// translations[lang] || translations['en'] (:159): a language the template
	// has no translations for reads the English ones.
	de, err := tm.RenderMail(ctx, "de", TemplatePasswordReset, data)
	if err != nil || de != wantEN {
		t.Errorf("de rendered %+v, %v; want the en translations", de, err)
	}
}

// A stored template sees the keys the reference passes for its id and nothing
// more unless a caller sets it: URL is link everywhere but welcome, where it is
// loginUrl and there is no link (auth.router.ts:724, mailer.service.ts:62), and
// appName — a key of this port's — is absent when the templater has none. A
// template written against the reference renders the same [key] placeholders
// here.
func TestMailTemplaterStoredTemplateSeesTheReferenceKeys(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTemplateStore()
	for _, id := range []string{TemplatePasswordReset, TemplateWelcome} {
		if _, err := store.UpdateMailTemplate(ctx, id, MailTemplatePatch{
			BaseHTML: strPtr("{{link}}|{{loginUrl}}|{{appName}}"),
			BaseText: strPtr("{{link}}|{{loginUrl}}|{{appName}}"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	data := MailTemplateData{URL: testMailLink}

	unnamed := NewMailTemplater("")
	unnamed.Store = store
	if got, err := unnamed.RenderMail(ctx, "en", TemplatePasswordReset, data); err != nil || got.HTML != testMailLink+"|[loginUrl]|[appName]" {
		t.Errorf("password-reset rendered %q, %v; want link and the two placeholders", got.HTML, err)
	}
	if got, err := unnamed.RenderMail(ctx, "en", TemplateWelcome, data); err != nil || got.HTML != "[link]|"+testMailLink+"|[appName]" {
		t.Errorf("welcome rendered %q, %v; want loginUrl and the two placeholders", got.HTML, err)
	}

	named := NewMailTemplater("Example App")
	named.Store = store
	if got, err := named.RenderMail(ctx, "en", TemplatePasswordReset, data); err != nil || got.HTML != testMailLink+"|[loginUrl]|Example App" {
		t.Errorf("password-reset with an app name rendered %q, %v", got.HTML, err)
	}
}

// The fallback chain of a stored template's subject and translations, language
// by language: a language whose map is present but empty is still that
// language's map (an empty object is truthy), a language with no map reads en,
// and no en either means no translations at all and the built-in subject.
func TestMailTemplaterStoredTemplateLangFallbackChain(t *testing.T) {
	ctx := context.Background()
	tm := NewMailTemplater("")
	data := MailTemplateData{URL: testMailLink}
	render := func(t *testing.T, translations map[string]map[string]string, locale string) MailRendered {
		t.Helper()
		store := NewMemoryTemplateStore()
		if _, err := store.UpdateMailTemplate(ctx, TemplateMagicLink, MailTemplatePatch{
			BaseHTML: strPtr("<p>{{T.title}}</p>"), BaseText: strPtr("{{T.title}}"), Translations: translations,
		}); err != nil {
			t.Fatal(err)
		}
		tm.Store = store
		got, err := tm.RenderMail(ctx, locale, TemplateMagicLink, data)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	t.Run("no translations at all: [key] and the built-in subject for the language", func(t *testing.T) {
		if got := render(t, nil, "it"); got.Subject != "Il tuo link di accesso" || got.HTML != "<p>[title]</p>" {
			t.Errorf("rendered %+v", got)
		}
		if got := render(t, nil, "en"); got.Subject != "Your magic sign-in link" || got.HTML != "<p>[title]</p>" {
			t.Errorf("rendered %+v", got)
		}
	})

	t.Run("only en: it reads en", func(t *testing.T) {
		en := map[string]map[string]string{"en": {"subject": "S", "title": "T"}}
		if got := render(t, en, "it"); got.Subject != "S" || got.HTML != "<p>T</p>" {
			t.Errorf("rendered %+v", got)
		}
	})

	t.Run("a present but empty it map is used as it is", func(t *testing.T) {
		both := map[string]map[string]string{"en": {"subject": "S", "title": "T"}, "it": {}}
		if got := render(t, both, "it"); got.Subject != "Il tuo link di accesso" || got.HTML != "<p>[title]</p>" {
			t.Errorf("rendered %+v; an empty map must not fall through to en", got)
		}
	})

	t.Run("a language without a subject keeps its other keys and takes the built-in subject", func(t *testing.T) {
		it := map[string]map[string]string{"it": {"title": "Titolo"}}
		if got := render(t, it, "it"); got.Subject != "Il tuo link di accesso" || got.HTML != "<p>Titolo</p>" {
			t.Errorf("rendered %+v", got)
		}
	})
}

// Register is for set-up time but must not race a render in flight: the race
// detector is the assertion here.
func TestMailTemplaterConcurrentUse(t *testing.T) {
	ctx := context.Background()
	tm := NewMailTemplater("")
	tm.Store = NewMemoryTemplateStore()
	data := MailTemplateData{URL: testMailLink}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				tm.Register("en", TemplateMagicLink, "s", "<p>{{.link}}</p>", "{{.link}}")
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := tm.RenderMail(ctx, "en", TemplateMagicLink, data); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
