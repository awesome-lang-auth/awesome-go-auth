package auth

import (
	"context"
	"errors"
	"time"
)

// The invitation's half of the delivery seam (delivery.go,
// delivery_password_email.go): what a sender is handed, the link it mails, and
// the ready-made mailer that renders the reference's own invitation template.
//
// It follows the other five senders in every respect that matters — a func
// type on Config rather than a store capability, a delivery carrying the
// plaintext token and nothing else that is credential material, store first
// and send second — and differs in one: a failed send is undone rather than
// left to expire. The other routes are the user's own and can simply be asked
// again; this one is an administrator's, and in conflict mode a retry would
// otherwise meet the account the failed call left behind.

// InvitationDelivery is what an InvitationSender is handed. Like
// MagicLinkDelivery it carries the plaintext token — the store holds only its
// hash — and no User: a sender is host code that may log what it receives.
//
// The JSON tags are the shape DeliveryWebhook posts under the kind
// DeliveryKindInvitation.
type InvitationDelivery struct {
	InvitationID string `json:"invitationId"`
	UserID       string `json:"userId"`
	TenantID     string `json:"tenantId"`
	// Email is the invited address, normalised, and the recipient.
	Email string `json:"email"`
	// Role and Metadata are what the invitation was created with, for a sender
	// whose message mentions them. Neither is rendered by InvitationMailer.
	Role     string         `json:"role,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
	// Token is the plaintext token POST <prefix>/invitations/accept accepts.
	Token string `json:"token"`
	// ExpiresAt is the end of the invitation's lifetime, Config.InvitationTTL
	// after it was created. The token is honoured strictly before it.
	ExpiresAt time.Time `json:"expiresAt"`
	// LinkBase and Lang are what PasswordResetDelivery's are. The admin route
	// resolves LinkBase from the request as every emailed link is resolved
	// (Auth.ResolveSiteURL, then HTTPConfig.LinkBase) — for a machine caller,
	// which sends no Origin, that is the default site URL — and passes the
	// body's emailLang as Lang.
	LinkBase string `json:"linkBase,omitempty"`
	Lang     string `json:"lang,omitempty"`
}

// InvitationSender delivers an invitation. An error undoes the invitation —
// see Service.InviteUser — and the admin route answers 502.
type InvitationSender func(ctx context.Context, delivery InvitationDelivery) error

// InvitationURL builds the link an invitation mails: the base with any
// trailing slash removed, then "/invitations/accept?token=<token>", the shape
// of every other emailed link here (MagicLinkURL, PasswordResetURL).
//
// The path is the accept route's, which is POST-only, and no page ships for
// it: neither the built-in UI nor the reference has an accept form. So base is
// the front end that owns the form, and that front end serves GET on the path
// — the same arrangement the reference's /reset-password link relies on (see
// PasswordResetURL). A deployment whose form lives elsewhere writes its own
// sender; the delivery carries the token and the base.
func InvitationURL(base, token string) string {
	return tokenLink(base, InvitationAcceptRoute, token)
}

// InvitationMailer is the ready-made InvitationSender: it renders the
// invitation template (TemplateInvitation — the built-in, or a TemplateStore's
// override) and hands the result to a MailerTransport, as the reference's
// sendInvitation does (mailer.service.ts:210-227).
//
// The template is rendered with link and nothing else from the library, which
// is what the reference passes it on top of its caller's data: a stored
// template written for the reference sees {link} here too. Metadata is not
// spread into it, because the reference's data argument is its caller's to
// fill and the admin route is not that caller.
//
//	auth.WithInvitationSender(auth.NewInvitationMailer(
//		mailer,
//		"Example App",
//		"https://console.example.com/auth",
//	).Send)
type InvitationMailer struct{ TokenMailer }

// NewInvitationMailer builds an InvitationMailer with the built-in templates.
// baseURL is the static fallback for a delivery that carries no LinkBase, as
// TokenMailer.BaseURL is.
func NewInvitationMailer(transport MailerTransport, appName, baseURL string) *InvitationMailer {
	return &InvitationMailer{newTokenMailer(transport, appName, baseURL)}
}

// Send renders and delivers the invitation. Its signature is
// InvitationSender's.
func (m *InvitationMailer) Send(ctx context.Context, delivery InvitationDelivery) error {
	if m == nil || m.Transport == nil {
		return errors.New("auth: invitation mailer has no transport")
	}
	templates := m.Templates
	if templates == nil {
		templates = NewMailTemplater("")
	}
	rendered, err := templates.RenderMail(ctx, resolveLang(delivery.Lang, m.Locale), TemplateInvitation, MailTemplateData{
		URL: m.link(InvitationURL, delivery.LinkBase, delivery.Token),
	})
	if err != nil {
		return err
	}
	return m.Transport.Send(ctx, MailMessage{
		To:      delivery.Email,
		Subject: rendered.Subject,
		Body:    rendered.HTML,
		IsHTML:  true,
		Text:    rendered.Text,
	})
}
