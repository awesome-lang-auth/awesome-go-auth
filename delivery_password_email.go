package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// This file extends the delivery seam of delivery.go to the three §2 routes that
// mint a credential and, until now, had nowhere to send it, plus the one notice
// the reference mails without a credential in it:
//
//	POST <prefix>/forgot-password        → PasswordResetSender
//	POST <prefix>/send-verification-email → EmailVerificationSender
//	POST <prefix>/change-email/request   → EmailChangeSender
//	POST <prefix>/change-email/confirm   → EmailChangedSender (to the OLD address)
//
// The shape is delivery.go's, for delivery.go's reasons: func types rather than
// interfaces, a delivery struct carrying the plaintext token and nothing else
// that is credential material, the sender on Config rather than behind a
// UserStore assertion, no sender required by Config.validate, and store-first-
// then-send so a failed send leaves an unguessable token that expires on its own.
//
// What differs from magic-link and SMS is what an *unconfigured* deployment sees,
// and the difference is the reference's, not a simplification:
//
//   - /magic-link/send checks its config before the lookup and throws
//     EMAIL_NOT_CONFIGURED (magic-link.strategy.ts:12-14), so the port answers
//     500 there.
//   - These three routes check nothing. Each one prefers a config callback,
//     falls back to config.email.mailer, and when neither exists sends no mail
//     and still answers 200 {"success":true} (auth.router.ts:787-792, 956-961,
//     1027-1032; wire-contract §2 "Mailer dispatch order": "if neither exists, no
//     email is sent and the route still succeeds").
//
// So none of the three has a NOT_CONFIGURED sentinel: a nil sender is silence,
// not an error, and wiring one is purely additive for an existing deployment.
// The three routes behave exactly as they did before this file existed until a
// sender is supplied.
//
// A *failing* sender is a different matter. The reference's send calls sit inside
// the route's try block, so a throwing mailer reaches handleError and produces
// the generic code-less 500 (auth.router.ts:796-798). That is reproduced on
// /send-verification-email and /change-email/request, which are authenticated and
// have no anti-enumeration duty. It is deliberately *not* reproduced on
// /forgot-password — see ErrDeliveryFailed and Auth.ForgotPassword.

// ErrDeliveryFailed marks a send that failed after the credential was already
// stored. It is joined to the transport's own error rather than replacing it, so
// a caller can still read the cause, and it exists for exactly one reason:
// /forgot-password has to tell a delivery failure apart from a store failure in
// order to swallow the first and report the second (Auth.ForgotPassword).
//
// It maps to no catalog entry of its own. HTTPErrorFor does not know it, so it
// falls through to the generic 500 — which is what the reference answers for a
// throwing mailer, and what the two authenticated routes therefore answer.
var ErrDeliveryFailed = errors.New("auth: delivery failed after the credential was stored")

// PasswordResetDelivery is what a PasswordResetSender is handed.
//
// Like MagicLinkDelivery it carries the plaintext token — the store holds only
// its hash — plus the address the mail goes to and the ids a sender needs to read
// anything else back with. No User, no password hash: a sender is host code that
// may log what it receives.
type PasswordResetDelivery struct {
	UserID   string `json:"userId"`
	TenantID string `json:"tenantId"`
	// Email is the stored address of the account the reset was requested for,
	// not the address as the request spelled it. An unknown address never
	// reaches a sender at all: the route is silent about who is registered.
	Email string `json:"email"`
	// Token is the plaintext token POST <prefix>/reset-password accepts.
	Token string `json:"token"`
	// ExpiresAt is the stored expiry, Config.ResetTokenTTL from now (1 hour, as
	// in the reference). Verification allows Config.ClockSkew past it, so a
	// message quoting this value understates the window rather than overstating
	// it.
	ExpiresAt time.Time `json:"expiresAt"`
	// LinkBase and Lang are what MagicLinkDelivery's are: the base the adapter
	// resolved for this request (auth.router.ts:785-786) and the request's
	// emailLang (:779, :788). LinkBase wins over PasswordResetMailer.BaseURL when
	// set; a Lang of "it" or "en" wins over its Locale.
	LinkBase string `json:"linkBase,omitempty"`
	Lang     string `json:"lang,omitempty"`
}

// EmailVerificationDelivery is what an EmailVerificationSender is handed. The
// route behind it is authenticated, so Email is the caller's own stored address.
type EmailVerificationDelivery struct {
	UserID   string `json:"userId"`
	TenantID string `json:"tenantId"`
	Email    string `json:"email"`
	// Token is the plaintext token GET <prefix>/verify-email accepts.
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	// LinkBase and Lang are what PasswordResetDelivery's are
	// (auth.router.ts:941, 954-957).
	LinkBase string `json:"linkBase,omitempty"`
	Lang     string `json:"lang,omitempty"`
}

// EmailChangeDelivery is what an EmailChangeSender is handed.
//
// NewEmail is the only address here, and it is the recipient: this message
// verifies that the new mailbox exists, so it goes to the new mailbox
// (auth.router.ts:1027-1032 mails newEmail; wire-contract §2 "sent to the new
// address"). The current address is deliberately absent — the delivery carries
// only what the message needs, and a sender that wants the old address has
// UserID to read it back with.
//
// The notice the reference mails the *old* address once the change is applied
// (config.email.sendEmailChanged from /change-email/confirm,
// auth.router.ts:1060-1066) is a different delivery: EmailChangedDelivery, handed
// to Config.SendEmailChanged.
type EmailChangeDelivery struct {
	UserID   string `json:"userId"`
	TenantID string `json:"tenantId"`
	// NewEmail is the pending address the message goes to.
	NewEmail string `json:"newEmail"`
	// Token is the plaintext token POST <prefix>/change-email/confirm accepts.
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	// LinkBase and Lang are what PasswordResetDelivery's are
	// (auth.router.ts:1025-1028).
	LinkBase string `json:"linkBase,omitempty"`
	Lang     string `json:"lang,omitempty"`
}

// PasswordResetSender delivers a password-reset token.
//
// An error does NOT fail POST <prefix>/forgot-password: that route answers 200
// {"success":true} whatever happens. See Auth.ForgotPassword.
type PasswordResetSender func(ctx context.Context, delivery PasswordResetDelivery) error

// EmailVerificationSender delivers an email-verification token. An error fails
// the route with the reference's generic 500 and leaves the stored token in
// place, as MagicLinkSender does.
type EmailVerificationSender func(ctx context.Context, delivery EmailVerificationDelivery) error

// EmailChangeSender delivers an email-change token to the pending address. See
// EmailVerificationSender for the failure contract.
type EmailChangeSender func(ctx context.Context, delivery EmailChangeDelivery) error

// EmailChangedDelivery is what an EmailChangedSender is handed: the notice that
// POST <prefix>/change-email/confirm sends to the address an account just moved
// away from (auth.router.ts:1060-1066, "Send notification to old address").
//
// OldEmail is the recipient; NewEmail is what the notice reports. There is no
// token and no link — this mail confirms nothing, it informs — which is why it
// carries neither. The JSON tags are the reference's argument names in
// camelCase, so a sender that forwards the delivery as JSON does so in the
// family's spelling.
type EmailChangedDelivery struct {
	UserID   string `json:"userId"`
	TenantID string `json:"tenantId"`
	// OldEmail is the address the notice goes to: the one the account had
	// until the change was applied (auth.router.ts:1056, 1062).
	OldEmail string `json:"oldEmail"`
	// NewEmail is the address the account has now (:1057, 1062).
	NewEmail string `json:"newEmail"`
	// Lang is ConfirmEmailChangeInput.Lang, copied through untouched. The
	// routes leave it empty — the reference calls sendEmailChanged with no
	// language (:1062, 1065) — so EmailChangedMailer renders in its Locale.
	Lang string `json:"lang"`
}

// EmailChangedSender delivers the email-changed notice to the old address.
//
// An error fails POST <prefix>/change-email/confirm with the reference's generic
// 500 — its sendEmailChanged call sits inside the route's try block, after the
// change has been written (auth.router.ts:1058-1066, handleError at :1068-1069)
// — so the address has moved even though the response says 500. The failure
// contract is EmailVerificationSender's; the difference is what has already
// happened when it fires.
type EmailChangedSender func(ctx context.Context, delivery EmailChangedDelivery) error

// The routes the three tokens are spent on, relative to the mount prefix.
const (
	PasswordResetPath      = "/reset-password"
	EmailVerificationPath  = "/verify-email"
	EmailChangeConfirmPath = "/change-email/confirm"
)

// PasswordResetURL, EmailVerificationURL and EmailChangeConfirmURL build the
// links the reference mails, so a deployment writing its own sender does not have
// to guess the shape.
//
// base is the address the auth routes are reachable at from a mailbox. The
// reference derives it per request (resolveSiteUrl / buildUiLink, wire-contract
// §4) and so do the adapters here — each delivery's LinkBase is that value, see
// MagicLinkURL — so a custom sender passes delivery.LinkBase in, falling back to
// a base of its own when it is empty.
//
// One caveat carries over from the reference and is worth knowing before these
// links reach a real mailbox: /reset-password and /change-email/confirm are
// POST-only routes, so a browser following either link lands on something it
// cannot GET (wire-contract §2 notes the same about the reference with its UI
// disabled). A deployment points base at the front end that owns those two pages;
// /verify-email is a GET and works directly.
func PasswordResetURL(base, token string) string {
	return tokenLink(base, PasswordResetPath, token)
}

// EmailVerificationURL builds the verify-email link.
func EmailVerificationURL(base, token string) string {
	return tokenLink(base, EmailVerificationPath, token)
}

// EmailChangeConfirmURL builds the change-email confirmation link.
func EmailChangeConfirmURL(base, token string) string {
	return tokenLink(base, EmailChangeConfirmPath, token)
}

// -----------------------------------------------------------------------------
// service side
// -----------------------------------------------------------------------------

// deliverPasswordReset, deliverEmailVerification and deliverEmailChange are the
// three send steps, called after the token hash is stored.
//
// A nil sender returns nil: on these routes an unconfigured deployment sends
// nothing and still succeeds. A failing sender returns an error joining
// ErrDeliveryFailed and the transport's own, which is what lets /forgot-password
// swallow one failure mode without swallowing store failures too.
//
// linkBase and lang are the request's, copied from the service input onto the
// delivery untouched: the service neither resolves nor validates them, exactly
// as the reference's routes hand `link` and `emailLang` to the sender as built
// and as received (auth.router.ts:788, 957, 1028).
//
// Every sender is called with senderContext(ctx), which is how Config.Templates
// reaches a ready-made mailer.
func (s *Service) deliverPasswordReset(ctx context.Context, user User, token string, expiresAt time.Time, linkBase, lang string) error {
	if s.cfg.SendPasswordReset == nil {
		return nil
	}
	err := s.cfg.SendPasswordReset(s.senderContext(ctx), PasswordResetDelivery{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Email:     user.Email,
		Token:     token,
		ExpiresAt: expiresAt,
		LinkBase:  linkBase,
		Lang:      lang,
	})
	if err != nil {
		return fmt.Errorf("auth: deliver password reset: %w: %w", ErrDeliveryFailed, err)
	}
	return nil
}

func (s *Service) deliverEmailVerification(ctx context.Context, user User, token string, expiresAt time.Time, linkBase, lang string) error {
	if s.cfg.SendEmailVerification == nil {
		return nil
	}
	err := s.cfg.SendEmailVerification(s.senderContext(ctx), EmailVerificationDelivery{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Email:     user.Email,
		Token:     token,
		ExpiresAt: expiresAt,
		LinkBase:  linkBase,
		Lang:      lang,
	})
	if err != nil {
		return fmt.Errorf("auth: deliver email verification: %w: %w", ErrDeliveryFailed, err)
	}
	return nil
}

func (s *Service) deliverEmailChange(ctx context.Context, user User, newEmail, token string, expiresAt time.Time, linkBase, lang string) error {
	if s.cfg.SendEmailChange == nil {
		return nil
	}
	err := s.cfg.SendEmailChange(s.senderContext(ctx), EmailChangeDelivery{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		NewEmail:  newEmail,
		Token:     token,
		ExpiresAt: expiresAt,
		LinkBase:  linkBase,
		Lang:      lang,
	})
	if err != nil {
		return fmt.Errorf("auth: deliver email change: %w: %w", ErrDeliveryFailed, err)
	}
	return nil
}

// deliverEmailChanged is the notice step of ConfirmEmailChange, called after
// the change is applied. The nil-sender silence and the ErrDeliveryFailed join
// are the three siblings'.
func (s *Service) deliverEmailChanged(ctx context.Context, user User, oldEmail, newEmail, lang string) error {
	if s.cfg.SendEmailChanged == nil {
		return nil
	}
	err := s.cfg.SendEmailChanged(s.senderContext(ctx), EmailChangedDelivery{
		UserID:   user.ID,
		TenantID: user.TenantID,
		OldEmail: oldEmail,
		NewEmail: newEmail,
		Lang:     lang,
	})
	if err != nil {
		return fmt.Errorf("auth: deliver email changed: %w: %w", ErrDeliveryFailed, err)
	}
	return nil
}

// senderContext is the context every sender is called with: the caller's,
// carrying Config.Templates for a MailTemplater whose Store is nil (see
// MailTemplater.RenderMail). With no store configured it is ctx itself.
func (s *Service) senderContext(ctx context.Context) context.Context {
	return withTemplateStore(ctx, s.cfg.Templates)
}

// -----------------------------------------------------------------------------
// ready-made mailers
// -----------------------------------------------------------------------------

// TokenMailer is the shared body of the three ready-made senders below and the
// port's equivalent of the reference's config.email.mailer path, where a
// deployment configures a transport instead of writing a callback. It is
// MagicLinkMailer's shape, factored out because three copies of it would be three
// places for a template name or a Content-Type to drift.
type TokenMailer struct {
	// Transport delivers the rendered message. Required.
	Transport MailerTransport
	// BaseURL is what the URL builders above build the link under when the
	// delivery carries no LinkBase of its own — the static fallback, as
	// MagicLinkMailer.BaseURL is. A delivery's LinkBase wins over it.
	BaseURL string
	// Locale selects the built-in template set: "en" (the default) or "it". An
	// unknown locale falls back to English, as MailTemplater.RenderMail does.
	//
	// It is the default, as MagicLinkMailer.Locale is: a delivery whose Lang is
	// "it" or "en" — the request's emailLang body field — renders in that
	// language instead, and any other Lang defers to this (resolveLang).
	Locale string
	// Templates renders subject and bodies. The constructors fill this in; set
	// Templates.Store to render from a TemplateStore outside a service call
	// (inside one, Config.Templates is found on its own).
	Templates *MailTemplater
}

func newTokenMailer(transport MailerTransport, appName, baseURL string) TokenMailer {
	return TokenMailer{Transport: transport, BaseURL: baseURL, Templates: NewMailTemplater(appName)}
}

// link resolves the base for one delivery — its own LinkBase, else BaseURL —
// and builds the link with the given builder.
func (m TokenMailer) link(build func(base, token string) string, linkBase, token string) string {
	return build(linkBaseOr(linkBase, m.BaseURL), token)
}

// send renders template id in the language resolved for the delivery — lang
// over Locale, per resolveLang — with link and token as the data, which is what
// the reference's three link senders render with (mailer.service.ts:186, 191,
// 201), and hands subject, HTML and text to the transport.
func (m TokenMailer) send(ctx context.Context, lang, id, to, token, link string) error {
	if m.Transport == nil {
		return errors.New("auth: mailer has no transport")
	}
	templates := m.Templates
	if templates == nil {
		templates = NewMailTemplater("")
	}
	rendered, err := templates.RenderMail(ctx, resolveLang(lang, m.Locale), id, MailTemplateData{
		Token: token,
		URL:   link,
	})
	if err != nil {
		return err
	}
	return m.Transport.Send(ctx, MailMessage{To: to, Subject: rendered.Subject, Body: rendered.HTML, IsHTML: true, Text: rendered.Text})
}

// PasswordResetMailer is the ready-made PasswordResetSender: it renders the
// password-reset template (TemplatePasswordReset — the built-in, or a
// TemplateStore's override) and hands the result to a MailerTransport, as the
// reference's sendPasswordReset does (mailer.service.ts:185-188).
//
// Use it as a sender through its Send method:
//
//	mailer, err := auth.NewGatewayMailerTransport(auth.MailerConfig{
//		Endpoint: endpoint, APIKey: apiKey, From: "noreply@example.com",
//	})
//	// handle err
//	auth.WithPasswordResetSender(auth.NewPasswordResetMailer(
//		mailer,
//		"Example App",
//		"https://app.example.com/auth",
//	).Send)
type PasswordResetMailer struct{ TokenMailer }

// NewPasswordResetMailer builds a PasswordResetMailer with the built-in
// templates. appName is what a template mentioning {{.appName}} shows; the
// built-ins mention none.
func NewPasswordResetMailer(transport MailerTransport, appName, baseURL string) *PasswordResetMailer {
	return &PasswordResetMailer{newTokenMailer(transport, appName, baseURL)}
}

// Send renders and delivers the reset mail. Its signature is
// PasswordResetSender's.
func (m *PasswordResetMailer) Send(ctx context.Context, delivery PasswordResetDelivery) error {
	if m == nil {
		return errors.New("auth: password reset mailer is nil")
	}
	return m.send(ctx, delivery.Lang, TemplatePasswordReset, delivery.Email, delivery.Token,
		m.link(PasswordResetURL, delivery.LinkBase, delivery.Token))
}

// EmailVerificationMailer is the ready-made EmailVerificationSender, rendering
// the verify-email template (TemplateVerifyEmail) as the reference's
// sendVerificationEmail does (mailer.service.ts:200-203). See
// PasswordResetMailer for the usage shape.
type EmailVerificationMailer struct{ TokenMailer }

// NewEmailVerificationMailer builds an EmailVerificationMailer with the built-in
// templates.
func NewEmailVerificationMailer(transport MailerTransport, appName, baseURL string) *EmailVerificationMailer {
	return &EmailVerificationMailer{newTokenMailer(transport, appName, baseURL)}
}

// Send renders and delivers the verification mail. Its signature is
// EmailVerificationSender's.
func (m *EmailVerificationMailer) Send(ctx context.Context, delivery EmailVerificationDelivery) error {
	if m == nil {
		return errors.New("auth: email verification mailer is nil")
	}
	return m.send(ctx, delivery.Lang, TemplateVerifyEmail, delivery.Email, delivery.Token,
		m.link(EmailVerificationURL, delivery.LinkBase, delivery.Token))
}

// EmailChangeMailer is the ready-made EmailChangeSender. It mails the pending
// address the verify-email template (TemplateVerifyEmail) under the
// change-email confirmation link, which is exactly what the reference does:
// /change-email/request has no template of its own and calls
// sendVerificationEmail with its own link (auth.router.ts:1027-1032,
// mailer.service.ts:200-203). There is no email_change id any more — the
// 0.3.x one was an alias of TemplateVerifyEmail through the 0.x line and went
// with v1.0.0 — so a deployment that wants different wording for this mail
// registers it under TemplateVerifyEmail on a separate templater, or stores
// an override under that id.
type EmailChangeMailer struct{ TokenMailer }

// NewEmailChangeMailer builds an EmailChangeMailer with the built-in templates.
func NewEmailChangeMailer(transport MailerTransport, appName, baseURL string) *EmailChangeMailer {
	return &EmailChangeMailer{newTokenMailer(transport, appName, baseURL)}
}

// Send renders and delivers the email-change mail to the new address. Its
// signature is EmailChangeSender's.
func (m *EmailChangeMailer) Send(ctx context.Context, delivery EmailChangeDelivery) error {
	if m == nil {
		return errors.New("auth: email change mailer is nil")
	}
	return m.send(ctx, delivery.Lang, TemplateVerifyEmail, delivery.NewEmail, delivery.Token,
		m.link(EmailChangeConfirmURL, delivery.LinkBase, delivery.Token))
}

// EmailChangedMailer is the ready-made EmailChangedSender: it renders the
// email-changed template (TemplateEmailChanged) with the new address as its
// data and mails it to the old one, as the reference's sendEmailChanged does
// (mailer.service.ts:205-208). It has no BaseURL because the notice carries no
// link.
//
//	auth.WithEmailChangedSender(auth.NewEmailChangedMailer(mailer, "Example App").Send)
type EmailChangedMailer struct {
	// Transport delivers the rendered message. Required.
	Transport MailerTransport
	// Locale is what TokenMailer.Locale is. The routes hand this mailer no
	// language at all (EmailChangedDelivery.Lang), so it is usually the rule
	// here rather than the default.
	Locale string
	// Templates renders subject and bodies. NewEmailChangedMailer fills this in.
	Templates *MailTemplater
}

// NewEmailChangedMailer builds an EmailChangedMailer with the built-in
// templates.
func NewEmailChangedMailer(transport MailerTransport, appName string) *EmailChangedMailer {
	return &EmailChangedMailer{Transport: transport, Templates: NewMailTemplater(appName)}
}

// Send renders and delivers the notice to the old address. Its signature is
// EmailChangedSender's.
func (m *EmailChangedMailer) Send(ctx context.Context, delivery EmailChangedDelivery) error {
	if m == nil || m.Transport == nil {
		return errors.New("auth: email changed mailer has no transport")
	}
	templates := m.Templates
	if templates == nil {
		templates = NewMailTemplater("")
	}
	// newEmail is the one key the reference renders this template with
	// (mailer.service.ts:206).
	rendered, err := templates.RenderMail(ctx, resolveLang(delivery.Lang, m.Locale), TemplateEmailChanged, MailTemplateData{
		NewEmail: delivery.NewEmail,
	})
	if err != nil {
		return err
	}
	return m.Transport.Send(ctx, MailMessage{To: delivery.OldEmail, Subject: rendered.Subject, Body: rendered.HTML, IsHTML: true, Text: rendered.Text})
}
