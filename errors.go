package auth

import "errors"

var (
	ErrInvalidCredentials  = errors.New("auth: invalid credentials")
	ErrUserExists          = errors.New("auth: user already exists")
	ErrInvalidToken        = errors.New("auth: invalid token")
	ErrSessionNotFound     = errors.New("auth: session not found")
	ErrSessionRevoked      = errors.New("auth: session revoked")
	ErrWeakPassword        = errors.New("auth: password is too weak")
	ErrFeatureNotSupported = errors.New("auth: feature not supported by configured stores")
	ErrEmailNotVerified    = errors.New("auth: email not verified")
	ErrInvalidCode         = errors.New("auth: invalid code")
	ErrTwoFactorRequired   = errors.New("auth: two-factor authentication required")
	ErrAlreadyExists       = errors.New("auth: resource already exists")
	ErrTenantNotFound      = errors.New("auth: tenant not found")
	ErrRoleNotFound        = errors.New("auth: role not found")

	// ErrInvalidInput is a registration missing one of the two fields the route
	// cannot proceed without. It is deliberately not ErrWeakPassword: an absent
	// password is not a rejected one, and the default register handler on the
	// private dev line node-auth refuses the pair together, before it hashes or
	// stores anything (node-auth auth.router.ts:518-519, resolved against
	// DevLineRevision). The published reference at ReferenceRevision mounts
	// /register only when the host supplies options.onRegister and has no
	// default handler at all, so it has no code of its own here. See
	// Service.Register.
	ErrInvalidInput = errors.New("auth: email and password are required")

	// ErrNewPasswordRequired is a password change that names no new password.
	// It is refused before anything else is looked at, for an account with a
	// password and for one without alike, which is the reference's order
	// (awesome-node-auth v1.10.8 auth.router.ts:1476-1479). It is deliberately
	// not ErrWeakPassword: an absent password is not a rejected one. See
	// Service.ChangePassword.
	ErrNewPasswordRequired = errors.New("auth: new password is required")

	// ErrEmailNotConfigured and ErrSMSNotConfigured mean the deployment has no
	// way to deliver the credential a send route just asked for. They are
	// deliberately not ErrFeatureNotSupported: that one says the configured
	// store cannot hold the column, and it is already on the wire as
	// NOT_IMPLEMENTED on these same routes. See delivery.go.
	ErrEmailNotConfigured = errors.New("auth: email delivery is not configured")
	ErrSMSNotConfigured   = errors.New("auth: sms delivery is not configured")

	// The password-reset, email-verification and email-change senders have no
	// NOT_CONFIGURED sentinel of their own: on those three routes the reference
	// sends nothing and still succeeds, so a nil sender is silence rather than an
	// error. Their one sentinel, ErrDeliveryFailed, lives beside them in
	// delivery_password_email.go.
)
