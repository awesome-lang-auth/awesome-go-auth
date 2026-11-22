package auth

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// Tests for Config.EmailLangs: with it set, the emailLang a request carries
// reaches a sender only as one of the configured languages, or as "" — the
// sender's own default — for anything else; with it unset, untouched, as
// before. No value is ever refused, so the answer cannot depend on it.

// emailLangCases are the vectors under EmailLangs {"it", "en"}: the listed
// languages in any case and with a region, and everything that is not one of
// them — an unlisted language, a value that is not a language tag, one far
// too long.
var emailLangCases = []struct{ name, sent, want string }{
	{"a listed language", "it", "it"},
	{"another listed language", "en", "en"},
	{"case is not significant", "EN", "en"},
	{"surrounding spaces are not either", " en ", "en"},
	{"a region falls back to its language", "it-IT", "it"},
	{"so does an underscore region", "it_it", "it"},
	{"and an English region", "en-GB", "en"},
	{"an unlisted language", "de", ""},
	{"an unlisted two letters", "xx", ""},
	{"a word that is not a tag of a listed language", "english", ""},
	{"one letter is not a language", "e", ""},
	{"markup", "en<script>", ""},
	{"an empty subtag", "it--IT", ""},
	{"a leading separator", "-it", ""},
	{"4096 bytes", strings.Repeat("a", 4096), ""},
	{"past 35 characters", "it-" + strings.Repeat("x", 8) + "-" + strings.Repeat("y", 8) + "-" + strings.Repeat("z", 8) + "-abcdefgh", ""},
	{"nothing", "", ""},
}

// langSpy records the Lang of every delivery a service hands its senders.
type langSpy struct {
	mu    sync.Mutex
	langs map[string]string
}

func (s *langSpy) record(kind, lang string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.langs == nil {
		s.langs = map[string]string{}
	}
	s.langs[kind] = lang
}

func (s *langSpy) options() []Option {
	return []Option{
		WithPasswordResetSender(func(_ context.Context, d PasswordResetDelivery) error {
			s.record("password-reset", d.Lang)
			return nil
		}),
		WithEmailVerificationSender(func(_ context.Context, d EmailVerificationDelivery) error {
			s.record("email-verification", d.Lang)
			return nil
		}),
		WithEmailChangeSender(func(_ context.Context, d EmailChangeDelivery) error {
			s.record("email-change", d.Lang)
			return nil
		}),
		WithEmailChangedSender(func(_ context.Context, d EmailChangedDelivery) error {
			s.record("email-changed", d.Lang)
			return nil
		}),
		WithMagicLinkSender(func(_ context.Context, d MagicLinkDelivery) error {
			s.record("magic-link", d.Lang)
			return nil
		}),
		WithInvitationSender(func(_ context.Context, d InvitationDelivery) error {
			s.record("invitation", d.Lang)
			return nil
		}),
	}
}

// deliverEveryKind sends one of each mail that carries a request's language,
// all asking for lang, and returns what each sender was handed.
func deliverEveryKind(t *testing.T, lang string, opts ...Option) map[string]string {
	t.Helper()
	spy := &langSpy{}
	var linkLang string
	base := append(spy.options(),
		WithUserStore(NewMemoryUserStore()),
		WithInvitationStore(NewMemoryInvitationStore()),
		WithOAuth(OAuthWiring{
			Service:        NewOAuthService(),
			LinkedAccounts: NewMemoryLinkedAccounts(),
			PendingLinks:   NewMemoryPendingLinks(),
			SiteURL:        "https://app.example.com",
			TenantID:       "t1",
			DeliverLinkToken: func(_ context.Context, d LinkTokenDelivery) error {
				linkLang = d.EmailLang
				return nil
			},
		}),
	)
	a, err := newTestAuth(append(base, opts...)...)
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	ctx := context.Background()
	user, tokens, err := a.Register(ctx, RegisterInput{Email: "lang@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := a.ForgotPassword(ctx, ForgotPasswordInput{Email: user.Email, TenantID: "t1", Lang: lang}); err != nil {
		t.Fatalf("forgot password: %v", err)
	}
	if err := a.Service().users.(*MemoryUserStore).MarkEmailVerified(ctx, user.ID, "t1", false); err != nil {
		t.Fatalf("unverify: %v", err)
	}
	if _, err := a.SendVerificationEmailToken(ctx, EmailVerificationInput{UserID: user.ID, TenantID: "t1", Lang: lang}); err != nil {
		t.Fatalf("send verification email: %v", err)
	}
	// Through the service, which hands the token back for the confirm step.
	changeToken, err := a.Service().RequestEmailChange(ctx, ChangeEmailRequestInput{UserID: user.ID, TenantID: "t1", NewEmail: "lang2@example.com", Lang: lang})
	if err != nil || changeToken == "" {
		t.Fatalf("request email change: token %q, err %v", changeToken, err)
	}
	if err := a.Service().ConfirmEmailChange(ctx, ConfirmEmailChangeInput{Token: changeToken, Lang: lang}); err != nil {
		t.Fatalf("confirm email change: %v", err)
	}
	if _, err := a.SendMagicLink(ctx, MagicLinkSendInput{Email: "lang2@example.com", TenantID: "t1", Lang: lang}); err != nil {
		t.Fatalf("send magic link: %v", err)
	}
	if _, err := a.InviteUser(ctx, InviteUserInput{Email: "invitee@example.com", TenantID: "t1", Lang: lang}); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if _, err := a.LinkRequest(ctx, LinkRequestInput{Email: "lang2@example.com", Provider: "acme", AccessToken: tokens.AccessToken, EmailLang: lang}); err != nil {
		t.Fatalf("link request: %v", err)
	}
	spy.mu.Lock()
	defer spy.mu.Unlock()
	got := map[string]string{"link-request": linkLang}
	for k, v := range spy.langs {
		got[k] = v
	}
	return got
}

var everyLangKind = []string{
	"password-reset", "email-verification", "email-change", "email-changed",
	"magic-link", "invitation", "link-request",
}

// TestEmailLangsBoundWhatReachesTheSenders: every mail that carries a
// request's language — the five link mails, the email-changed notice for a
// direct caller, the invitation — reaches its sender with one of the
// configured languages or nothing.
func TestEmailLangsBoundWhatReachesTheSenders(t *testing.T) {
	for _, tc := range emailLangCases {
		t.Run(tc.name, func(t *testing.T) {
			got := deliverEveryKind(t, tc.sent, WithEmailLangs("it", "en"))
			for _, kind := range everyLangKind {
				if got[kind] != tc.want {
					shown := got[kind]
					if len(shown) > 40 {
						shown = shown[:40] + "…"
					}
					t.Errorf("%s: emailLang %.40q reached the sender as %q, want %q", kind, tc.sent, shown, tc.want)
				}
			}
		})
	}
}

// TestEmailLangsUnsetPassEmailLangThrough pins the default, which is what
// every deployment had before the field: the value reaches the sender as it
// was sent, and a sender of the deployment's own is free to honour it. It
// passed before EmailLangs existed.
func TestEmailLangsUnsetPassEmailLangThrough(t *testing.T) {
	for _, sent := range []string{"it", "de", "EN", "it-IT", strings.Repeat("a", 64)} {
		got := deliverEveryKind(t, sent)
		for _, kind := range everyLangKind {
			if got[kind] != sent {
				t.Errorf("%s: emailLang %q reached the sender as %q with EmailLangs unset", kind, sent, got[kind])
			}
		}
	}
}

// TestEmailLangsAreValidated: a configured entry has to be a language tag a
// request could match, or NewService refuses the configuration.
func TestEmailLangsAreValidated(t *testing.T) {
	for _, tc := range []struct {
		langs []string
		ok    bool
	}{
		{[]string{"it", "en"}, true},
		{[]string{"pt-BR", "zh_Hant"}, true},
		{nil, true},
		{[]string{"it", ""}, false},
		{[]string{"e n"}, false},
		{[]string{" it"}, false},
		{[]string{strings.Repeat("a", 36)}, false},
	} {
		_, err := New(WithEmailLangs(tc.langs...))
		if (err == nil) != tc.ok {
			t.Errorf("WithEmailLangs(%q): err = %v, want ok=%v", tc.langs, err, tc.ok)
		}
	}
}
