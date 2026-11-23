package auth

import (
	"context"
	"errors"
	"strings"
	"time"
)

// This file holds the delivery seam: how a minted magic link or SMS code
// reaches the person it was minted for.
//
// The two routes that need it — POST <prefix>/magic-link/send and POST
// <prefix>/sms/send — answer {"success":true} and nothing else, so the
// credential cannot travel in the response body: handing a second factor back
// to whoever asked for it is no second factor at all. Service.SendMagicLink and
// Service.SendSMSCode give it to a host-supplied sender instead.
//
// Why the sender sits on Config and not behind a store-style optional
// interface. The other optional capabilities in this package are type
// assertions on the UserStore — MagicLinkStore, SMSStore, EmailVerificationStore
// — because each asks a question about persistence: can this store keep that
// column. Delivery is not that question. Whether a deployment can send mail has
// nothing to do with which database it chose, and a UserStore that also spoke
// SMTP would be a layering mistake. Two consequences settle it:
//
//   - A missing optional store means ErrFeatureNotSupported, which the wire
//     spells NOT_IMPLEMENTED. That code already means something else on these
//     very routes — the reference emits it when the store cannot look a
//     magic-link token up (wire-contract §3) — and the spec wants
//     EMAIL_NOT_CONFIGURED and SMS_NOT_CONFIGURED here. Different cause,
//     different code; reusing the store seam would collapse them.
//   - The reference puts delivery on its config too: config.email.sendMagicLink
//     (a callback) or config.email.mailer (a transport) for mail, and the
//     config.sms block for SMS. Config.BuildTokenClaims is this package's
//     existing precedent for a host-supplied callback and these two are its
//     siblings.
//
// Neither sender is required to construct a Service: Config.validate does not
// ask for them, exactly as the reference starts fine without an email or sms
// block. A deployment that never calls the passwordless routes never needs one.
// The absence is reported when a route is actually used, as the 500 the spec
// documents.

// MagicLinkDelivery is what a MagicLinkSender is handed.
//
// It carries the plaintext magic-link token — the store only ever sees its hash
// — and deliberately nothing else that is credential material. A sender is host
// code that may log or forward what it receives, so it is given the one secret
// it has to transmit and no other: no password hash, no TOTP secret, no User.
// A sender that needs more about the recipient has UserID and TenantID to read
// it back with.
//
// The JSON tags — on this struct and on the four others a sender is handed — are
// the shape DeliveryWebhook posts (delivery_webhook.go). Nothing else in this
// package serialises a delivery.
type MagicLinkDelivery struct {
	UserID   string `json:"userId"`
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
	// Token is the plaintext token the matching verify route accepts.
	Token string `json:"token"`
	// ExpiresAt is the stored expiry, Config.MagicLinkTTL from now. Verification
	// additionally allows Config.ClockSkew past it, so a message that quotes this
	// value understates the window slightly rather than overstating it.
	ExpiresAt time.Time `json:"expiresAt"`
	// LinkBase is the base the link is built under for this request —
	// "https://app.example.com/auth" — resolved by the adapter from the request's
	// Origin or Referer against Config.SiteURLs (Auth.ResolveSiteURL, then
	// HTTPConfig.LinkBase), which is the reference's siteUrlOverride argument
	// (auth.router.ts:1104/1114 → magic-link.strategy.ts:25). It wins over
	// MagicLinkMailer.BaseURL when set; empty when no site URL is configured or
	// the service was called directly, in which case that static base applies.
	LinkBase string `json:"linkBase,omitempty"`
	// Lang is the request's emailLang body field, passed through untouched
	// (auth.router.ts:1080, 1104/1114) unless Config.EmailLangs lists the
	// deployment's languages, under which it is one of those or empty. "it"
	// and "en" select the built-in template set over MagicLinkMailer.Locale;
	// anything else, the empty string included, defers to it (resolveLang,
	// mailer.service.ts:255-259). The other deliveries' Lang is the same.
	Lang string `json:"lang,omitempty"`
}

// resolveLang is the reference's MailerService.resolveLang
// (mailer.service.ts:255-259): "it" and "en" are honoured as given, anything
// else — including the empty string a request without emailLang produces — is
// the configured default. fallback stands in for config.defaultLang; an unknown
// fallback then renders as English in MailTemplater.RenderMail, which is the
// reference's `?? 'en'`.
func resolveLang(lang, fallback string) string {
	switch lang {
	case "it", "en":
		return lang
	}
	return fallback
}

// linkBaseOr is the precedence between the two bases a ready-made mailer knows:
// the one the delivery carries for this request, then the mailer's static one.
func linkBaseOr(perRequest, static string) string {
	if perRequest != "" {
		return perRequest
	}
	return static
}

// SMSCodeDelivery is what an SMSCodeSender is handed. See MagicLinkDelivery for
// why it carries so little.
type SMSCodeDelivery struct {
	UserID   string `json:"userId"`
	TenantID string `json:"tenantId"`
	// Phone is the recipient's stored number. The send route refuses a user
	// without one before it gets this far (PHONE_NOT_SET), so it is never empty.
	Phone string `json:"phone"`
	// Code is the plaintext one-time code; the store holds only its hash.
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// MagicLinkSender delivers a magic link. An error fails the route with the
// reference's generic 500 — a transport failure must not describe itself to the
// caller — and leaves the stored token in place, which is what the reference
// does too: an undelivered token is unguessable and expires on its own.
type MagicLinkSender func(ctx context.Context, delivery MagicLinkDelivery) error

// SMSCodeSender delivers an SMS one-time code. See MagicLinkSender for the
// failure contract.
type SMSCodeSender func(ctx context.Context, delivery SMSCodeDelivery) error

// MagicLinkVerifyPath is the route a magic link points at, relative to the
// mount prefix.
const MagicLinkVerifyPath = "/magic-link/verify"

// MagicLinkURL builds the link the reference mails: the base with any trailing
// slash removed, then "/magic-link/verify?token=<token>"
// (magic-link.strategy.ts:23-27). Reproduced here so that a deployment writing
// its own sender does not have to guess the shape the verify route and the
// shipped clients expect.
//
// base is the address the auth routes are reachable at from a mailbox —
// "https://app.example.com/auth". The reference derives it per request from
// email.siteUrl and the request Origin (resolveSiteUrl / buildUiLink,
// wire-contract §4), and so do the adapters here: MagicLinkDelivery.LinkBase is
// that value (Auth.ResolveSiteURL, HTTPConfig.LinkBase), and a custom sender
// passes it straight in. An empty base yields a relative link, which the
// reference also produces when siteUrl is unset — it is a misconfiguration in
// both, not a special case handled here.
//
// The token is interpolated raw. randomToken emits base64url, whose alphabet
// needs no query escaping, and the reference interpolates its hex token raw for
// the same reason.
func MagicLinkURL(base, token string) string {
	return tokenLink(base, MagicLinkVerifyPath, token)
}

// tokenLink is the shape every emailed link in this package has. It is shared
// with the three builders in delivery_password_email.go so that one of them
// cannot start escaping the token, or keeping the trailing slash, on its own.
func tokenLink(base, path, token string) string {
	return strings.TrimSuffix(base, "/") + path + "?token=" + token
}

// SMSCodeMessage is the text the reference texts (sms.strategy.ts:20). It is on
// a wire of its own — a real handset — so the literal is reproduced rather than
// reworded, and it lives here so a custom SMSCodeSender can reuse it instead of
// drifting from the rest of the family.
func SMSCodeMessage(code string) string {
	return "Your verification code is: " + code
}

// MagicLinkMailer is the ready-made MagicLinkSender: it renders the magic-link
// template (TemplateMagicLink — the built-in, or a TemplateStore's override)
// and hands the result to a MailerTransport, text alternative included. It is
// the port's equivalent of the reference's config.email.mailer path, where a
// deployment configures a transport instead of writing a callback
// (mailer.service.ts:190-193).
//
// Use it as a sender through its Send method:
//
//	mailer, err := auth.NewGatewayMailerTransport(auth.MailerConfig{
//		Endpoint: endpoint, APIKey: apiKey, From: "noreply@example.com",
//	})
//	// handle err
//	auth.WithMagicLinkSender(auth.NewMagicLinkMailer(
//		mailer,
//		"Example App",
//		"https://app.example.com/auth",
//	).Send)
type MagicLinkMailer struct {
	// Transport delivers the rendered message. Required.
	Transport MailerTransport
	// BaseURL is what MagicLinkURL builds the link under when the delivery
	// carries no LinkBase of its own: the static fallback for a deployment with
	// no Config.SiteURLs, or for a service called directly. A delivery's
	// LinkBase — the base the adapter resolved for the request — wins over it.
	BaseURL string
	// Locale selects the built-in template set: "en" (the default) or "it". An
	// unknown locale falls back to English, as MailTemplater.Render does.
	//
	// It is the default, not the rule: a delivery whose Lang is "it" or "en" —
	// the request's emailLang body field — renders in that language instead,
	// and any other Lang defers to this (resolveLang, mailer.service.ts:255-259,
	// where Locale plays config.defaultLang).
	Locale string
	// Templates renders subject and bodies. NewMagicLinkMailer fills this in;
	// set Templates.Store to render from a TemplateStore outside a service call
	// (inside one, Config.Templates is found on its own).
	Templates *MailTemplater
}

// NewMagicLinkMailer builds a MagicLinkMailer with the built-in templates.
// appName is what a template mentioning {{.appName}} shows; the built-ins
// mention none.
func NewMagicLinkMailer(transport MailerTransport, appName, baseURL string) *MagicLinkMailer {
	return &MagicLinkMailer{
		Transport: transport,
		BaseURL:   baseURL,
		Templates: NewMailTemplater(appName),
	}
}

// Send renders and delivers the magic-link mail. Its signature is
// MagicLinkSender's.
func (m *MagicLinkMailer) Send(ctx context.Context, delivery MagicLinkDelivery) error {
	if m == nil || m.Transport == nil {
		return errors.New("auth: magic link mailer has no transport")
	}
	templates := m.Templates
	if templates == nil {
		templates = NewMailTemplater("")
	}
	// link and token are the data the reference's sendMagicLink renders with
	// (mailer.service.ts:191); a stored template sees exactly those keys.
	rendered, err := templates.RenderMail(ctx, resolveLang(delivery.Lang, m.Locale), TemplateMagicLink, MailTemplateData{
		Token: delivery.Token,
		URL:   MagicLinkURL(linkBaseOr(delivery.LinkBase, m.BaseURL), delivery.Token),
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

// SMSTransportSender adapts an SMSTransport into an SMSCodeSender, formatting
// the code with SMSCodeMessage. It is the SMS counterpart of MagicLinkMailer.
func SMSTransportSender(transport SMSTransport) SMSCodeSender {
	return func(ctx context.Context, delivery SMSCodeDelivery) error {
		if transport == nil {
			return errors.New("auth: sms sender has no transport")
		}
		return transport.Send(ctx, delivery.Phone, SMSCodeMessage(delivery.Code))
	}
}
