package auth

import (
	"context"
	"strings"
	"testing"
)

// InvitationMailer renders the reference's invitation template — the built-in
// fallback of mailer.service.ts:210-227, or a stored override — with the link
// and nothing else the library supplies, and mails it to the invited address.

func TestInvitationURL(t *testing.T) {
	for base, want := range map[string]string{
		"https://console.example.com/auth":  "https://console.example.com/auth/invitations/accept?token=tok",
		"https://console.example.com/auth/": "https://console.example.com/auth/invitations/accept?token=tok",
		"":                                  "/invitations/accept?token=tok",
	} {
		if got := InvitationURL(base, "tok"); got != want {
			t.Errorf("InvitationURL(%q) = %q, want %q", base, got, want)
		}
	}
}

func TestInvitationMailerRendersTheReferenceTemplate(t *testing.T) {
	for _, tc := range []struct {
		locale, lang, wantSubject, wantText string
	}{
		{"en", "", "Invitation to join", "You have been invited."},
		{"it", "", "Invito ad unirsi", "Sei stato invitato."},
		{"en", "it", "Invito ad unirsi", "Sei stato invitato."},
		{"it", "en", "Invitation to join", "You have been invited."},
	} {
		transport := &recordingMailer{}
		mailer := NewInvitationMailer(transport, "Example App", "https://static.example.com/auth")
		mailer.Locale = tc.locale
		err := mailer.Send(context.Background(), InvitationDelivery{
			Email: "invitee@example.com", Token: "tok123", LinkBase: "https://console.example.com/auth", Lang: tc.lang,
			Metadata: map[string]any{"team": "<b>ops</b>"},
		})
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		msg := transport.sent[0]
		link := "https://console.example.com/auth/invitations/accept?token=tok123"
		if msg.To != "invitee@example.com" || !msg.IsHTML || msg.Subject != tc.wantSubject {
			t.Errorf("%s/%s: message = %+v", tc.locale, tc.lang, msg)
		}
		if want := "<p>" + tc.wantText + "</p><p><a href=\"" + link + "\">" + link + "</a></p>"; msg.Body != want {
			t.Errorf("%s/%s: html = %q, want %q", tc.locale, tc.lang, msg.Body, want)
		}
		if want := tc.wantText + "\n\n" + link; msg.Text != want {
			t.Errorf("%s/%s: text = %q, want %q", tc.locale, tc.lang, msg.Text, want)
		}
		if strings.Contains(msg.Body+msg.Text, "ops") {
			t.Errorf("the metadata was rendered into the mail: %q", msg.Body)
		}
	}
}

func TestInvitationMailerFallsBackToItsBaseURL(t *testing.T) {
	transport := &recordingMailer{}
	mailer := NewInvitationMailer(transport, "Example App", "https://static.example.com/auth")
	if err := mailer.Send(context.Background(), InvitationDelivery{Email: "i@example.com", Token: "t"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !strings.Contains(transport.sent[0].Text, "https://static.example.com/auth/invitations/accept?token=t") {
		t.Errorf("text = %q, want the static base", transport.sent[0].Text)
	}
}

// A stored template sees {link} and not {token}: the reference passes its
// caller's data and the link, never the raw token (mailer.service.ts:211).
func TestInvitationMailerRendersAStoredTemplate(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryTemplateStore()
	if _, err := store.UpdateMailTemplate(ctx, TemplateInvitation, MailTemplatePatch{
		BaseHTML: strPtr(`<p>join {{link}} {{token}}</p>`), BaseText: strPtr(`join {{link}} {{token}}`),
	}); err != nil {
		t.Fatal(err)
	}
	transport := &recordingMailer{}
	mailer := NewInvitationMailer(transport, "Example App", "https://console.example.com/auth")
	mailer.Templates.Store = store
	if err := mailer.Send(ctx, InvitationDelivery{Email: "i@example.com", Token: "tok"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	link := "https://console.example.com/auth/invitations/accept?token=tok"
	if got := transport.sent[0]; got.Text != "join "+link+" [token]" || got.Subject != "Invitation to join" {
		t.Errorf("mailed %+v", got)
	}
}

func TestInvitationMailerWithoutATransport(t *testing.T) {
	var mailer InvitationMailer
	if err := mailer.Send(context.Background(), InvitationDelivery{Email: "x@example.com"}); err == nil {
		t.Error("a mailer with no transport must fail rather than silently succeed")
	}
	var nilMailer *InvitationMailer
	if err := nilMailer.Send(context.Background(), InvitationDelivery{Email: "x@example.com"}); err == nil {
		t.Error("a nil mailer must fail")
	}
	var _ InvitationSender = (&InvitationMailer{}).Send
}
