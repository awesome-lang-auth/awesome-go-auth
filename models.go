package auth

import "time"

// User is the canonical identity model.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	TenantID     string
	PhoneNumber  string
	FirstName    string
	LastName     string
	Role         string
	// IsAdmin is the reference's BaseUser.isAdmin (user.model.ts:81-90): the
	// stored flag the admin router's 'is-admin-flag' access policy reads, as
	// `granted = user.isAdmin === true` (admin.router.ts:370).
	//
	// It is a persisted field and not a projection of Role, and that is the
	// reference's own arrangement rather than a choice made here. The obvious
	// reading — that an admin is a user whose role says so — is the one the
	// reference explicitly declines: its doc on the field routes anyone wanting
	// role-shaped admin-ness away from it and to RBAC instead ("For more
	// granular RBAC control use IRolesPermissionsStore and a custom accessPolicy
	// function"), and buildPolicyGuard reads no role anywhere. The four access
	// policies it does offer are 'open', 'first-user', this flag, and a
	// host-supplied predicate that is handed the user and the RBAC store
	// (admin.router.ts:25-30, :366-382) — so a deployment that wants
	// `Role == "admin"` writes six lines of predicate, and the flag stays what it
	// is: a switch a host sets on a record, with no derivation behind it.
	//
	// Deriving it here anyway, in the shape of models.go's own
	// loginProviderOrLocal, would therefore not be reproducing the reference but
	// inventing a rule it does not have — and inventing it in the one place where
	// guessing wrong grants the admin console to the wrong person. A store that
	// never persisted the column keeps working: absent is false in TypeScript
	// (the field is `isAdmin?: boolean`, and the guard compares `=== true`) and
	// false is the zero value here, so the two agree without a migration.
	//
	// It is deliberately not projected onto PublicUser. The reference serialises
	// isAdmin nowhere — not on /me, not on the admin users table, which picks its
	// keys one by one and does not pick this one (admin.router.ts:764-773) — so no
	// shipped client knows the field exists, and adding it to the wire would be an
	// unrequested widening of the contract that also tells every caller which
	// accounts are worth attacking.
	IsAdmin bool
	// LoginProvider names the identity provider that created the account: an
	// OAuth provider's name for a user OAuthService.HandleCallback created,
	// empty for one registered with a password. Empty is read as
	// LoginProviderLocal wherever it reaches the wire — the reference's
	// `user.loginProvider ?? 'local'` (auth.router.ts:379) — so a store that
	// never persisted the field needs no migration to keep answering "local".
	LoginProvider                string
	IsEmailVerified              bool
	Require2FA                   bool
	IsTOTPEnabled                bool
	TOTPSecret                   string
	ResetTokenHash               string
	ResetTokenExpiresAt          *time.Time
	MagicLinkTokenHash           string
	MagicLinkTokenExpiresAt      *time.Time
	SMSCodeHash                  string
	SMSCodeExpiresAt             *time.Time
	EmailVerificationTokenHash   string
	EmailVerificationTokenExpiry *time.Time
	PendingEmail                 string
	EmailChangeTokenHash         string
	EmailChangeTokenExpiry       *time.Time
	Metadata                     map[string]any
	Roles                        []string
	Permissions                  []string
	Tenants                      []Tenant
	CustomClaims                 map[string]any
	CreatedAt                    time.Time
	UpdatedAt                    time.Time
	// AuthMethods, AuthTime and MFAAt describe how the session behind an access
	// token was authenticated: its amr, auth_time and mfa_at claims. They are
	// filled only on a principal built from a verified token — Auth.VerifyAccess,
	// and so the adapters' Middleware, and UserFromRS256Claims — and are zero on
	// a user read from a store, which records no authentication. MFAAt is zero
	// when the session never presented a second factor, so a check such as
	// time.Since(u.MFAAt) < 5*time.Minute refuses such a principal on its own.
	// None of the three is persisted by a UserStore or projected onto
	// PublicUser.
	AuthMethods []string
	AuthTime    time.Time
	MFAAt       time.Time
}

// LoginProviderLocal is the loginProvider a user without a recorded provider is
// reported under, on tokens and on the profile alike: the reference's
// `user.loginProvider ?? 'local'` (auth.router.ts:379).
const LoginProviderLocal = "local"

// loginProviderOrLocal is the loginProvider claim and profile field for u.
func (u User) loginProviderOrLocal() string {
	if u.LoginProvider == "" {
		return LoginProviderLocal
	}
	return u.LoginProvider
}

// Tenant represents an isolated workspace or organization.
type Tenant struct {
	ID        string
	Name      string
	IsActive  bool
	Config    map[string]any
	CreatedAt time.Time
}

// PublicUser is the response-safe projection of User. It is the only user shape
// adapters may serialise: credential material (password hash, TOTP secret,
// one-time token hashes and the pending email change) is deliberately absent.
type PublicUser struct {
	// Sub is the identifier under the name the reference uses and the shipped
	// clients require. Both cast it non-nullably — awesome-node-auth-flutter
	// does `json['sub'] as String` (auth_user.dart:76) and ng-awesome-node-auth
	// declares `sub: string` (auth.service.ts:10) — so omitting it does not
	// degrade a client, it throws inside one. It duplicates ID rather than
	// replacing it because `id` shipped in 0.2.0 and both clients read that as
	// optional, so emitting both breaks nobody.
	Sub   string `json:"sub"`
	ID    string `json:"id"`
	Email string `json:"email"`
	// Role is the reference's single-role field, distinct from Roles. Omitted
	// when empty, which it always is until something writes it.
	Role string `json:"role,omitempty"`
	// LoginProvider is always emitted, LoginProviderLocal when nothing recorded
	// one: the reference's /me body is its token payload, which carries
	// `loginProvider: user.loginProvider ?? 'local'` unconditionally
	// (auth.router.ts:379, :666-668).
	LoginProvider   string         `json:"loginProvider"`
	TenantID        string         `json:"tenantId,omitempty"`
	FirstName       string         `json:"firstName,omitempty"`
	LastName        string         `json:"lastName,omitempty"`
	PhoneNumber     string         `json:"phoneNumber,omitempty"`
	IsEmailVerified bool           `json:"isEmailVerified"`
	IsTOTPEnabled   bool           `json:"isTotpEnabled"`
	Roles           []string       `json:"roles,omitempty"`
	Permissions     []string       `json:"permissions,omitempty"`
	Tenants         []PublicTenant `json:"tenants,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	CustomClaims    map[string]any `json:"customClaims,omitempty"`
	CreatedAt       time.Time      `json:"createdAt"`
}

// PublicTenant is the response-safe projection of Tenant. The tenant Config
// blob is server-side configuration and is never serialised.
type PublicTenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IsActive  bool      `json:"isActive"`
	CreatedAt time.Time `json:"createdAt"`
}

// NewPublicUser projects a User onto its response-safe representation.
func NewPublicUser(user User) PublicUser {
	public := PublicUser{
		Sub:             user.ID,
		ID:              user.ID,
		Email:           user.Email,
		Role:            user.Role,
		LoginProvider:   user.loginProviderOrLocal(),
		TenantID:        user.TenantID,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		PhoneNumber:     user.PhoneNumber,
		IsEmailVerified: user.IsEmailVerified,
		IsTOTPEnabled:   user.IsTOTPEnabled,
		Roles:           user.Roles,
		Permissions:     user.Permissions,
		Metadata:        user.Metadata,
		CustomClaims:    user.CustomClaims,
		CreatedAt:       user.CreatedAt,
	}
	if len(user.Tenants) > 0 {
		public.Tenants = make([]PublicTenant, 0, len(user.Tenants))
		for _, tenant := range user.Tenants {
			public.Tenants = append(public.Tenants, PublicTenant{
				ID:        tenant.ID,
				Name:      tenant.Name,
				IsActive:  tenant.IsActive,
				CreatedAt: tenant.CreatedAt,
			})
		}
	}
	return public
}

// Session stores refresh-token bound session metadata.
type Session struct {
	ID               string
	UserID           string
	TenantID         string
	RefreshTokenHash string
	// CreatedAt is when the session was opened, which is when its user
	// authenticated: the auth_time claim of every access token the session
	// mints, refresh after refresh.
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	// AuthMethods are the authentication methods the session was opened with,
	// as RFC 8176 amr values (AMRPassword, AMROTP, AMRSMS, AMREmail, AMROAuth,
	// and AMRMFA when more than one factor was presented): the amr claim of
	// every access token the session mints. POST <prefix>/2fa/step-up adds
	// AMROTP and AMRMFA. Empty for a session opened before the field existed,
	// or by a path that cannot say how its user was proved
	// (Service.IssueTokensForUser), and then the tokens carry no amr at all
	// rather than a guess.
	//
	// A SessionStore persists it with the rest of the row. One that does not
	// loses it on the first refresh, which fails closed: the tokens stop
	// claiming any method, so a check for a second factor refuses them.
	AuthMethods []string
	// MFAAt is when the session last presented a second factor — at the login
	// that opened it, or at POST <prefix>/2fa/step-up since — and nil for a
	// session that never presented one: the mfa_at claim, absent when nil. The
	// same persistence rule applies.
	MFAAt *time.Time
	// TOTPBinding names the one TOTP secret POST <prefix>/2fa/step-up accepts a
	// code of on this session: a keyed fingerprint of the secret the user had
	// enrolled when the session opened. It is empty when the user had no TOTP
	// factor then, and for a session whose opener could not say how its user
	// was proved (Service.IssueTokensForUser), and an empty one never steps
	// up.
	//
	// It is what keeps a factor enrolled after the session opened — by
	// whoever holds the session's access token, through the voluntary
	// /2fa/setup and /2fa/verify-setup — from moving the session's mfa_at.
	// Such a factor proves nothing the session did not already prove; its
	// holder gets a session that can step up with it by signing in again.
	//
	// A SessionStore persists it with the rest of the row. One that does not
	// fails closed: the step-up answers 403 REAUTHENTICATION_REQUIRED.
	TOTPBinding string
	// StepUpAttempts counts the codes POST <prefix>/2fa/step-up has checked,
	// or is about to check, on this session since the last one it accepted:
	// each attempt is counted before its code is. The wrong code that reaches
	// StepUpFailureLimit revokes the session
	// (SessionAuthenticationStore.RecordStepUpAttempt).
	StepUpAttempts int
}

// AuthTokens are the issued access/refresh pair.
type AuthTokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration
}

// RegisterInput is the payload to create a user and initial session.
type RegisterInput struct {
	Email    string
	Password string
	TenantID string
}

// LoginInput is the payload used for user authentication.
type LoginInput struct {
	Email    string
	Password string
	TenantID string
}

type ForgotPasswordInput struct {
	Email    string
	TenantID string
	// LinkBase is the per-request base the reset link is built under, copied
	// onto PasswordResetDelivery.LinkBase. The adapters fill it from
	// HTTPConfig.LinkBase(Auth.ResolveSiteURL(r)); a direct caller may leave it
	// empty, in which case a ready-made mailer uses its static BaseURL.
	LinkBase string
	// Lang is the request's emailLang body field, copied onto
	// PasswordResetDelivery.Lang untouched (auth.router.ts:779, 788).
	Lang string
}

type ResetPasswordInput struct {
	Token       string
	NewPassword string
}

type MagicLinkSendInput struct {
	Email    string
	TenantID string
	// LinkBase and Lang are what ForgotPasswordInput's are, for
	// MagicLinkDelivery (auth.router.ts:1104, 1114).
	LinkBase string
	Lang     string
}

type MagicLinkVerifyInput struct {
	Token string
}

type SMSCodeSendInput struct {
	UserID   string
	Email    string
	TenantID string
}

type SMSCodeVerifyInput struct {
	UserID   string
	Email    string
	TenantID string
	Code     string
	// SecondFactor says the code is the second factor of a password login: the
	// caller identified UserID from a verified step-up token, as the step-up
	// branch of POST <prefix>/sms/verify does. The session then records it
	// (amr ["pwd","sms","mfa"] and an mfa_at); without it the code is a login
	// of its own (amr ["sms"]). Set it only after verifying that token — it is
	// what tells a resource server a second factor was presented, and nothing
	// checks it: the service cannot tell the two branches apart, so the value
	// is the caller's assertion. A direct caller that is not completing a
	// step-up token's challenge leaves it false.
	SecondFactor bool
}

type ChangePasswordInput struct {
	UserID          string
	TenantID        string
	CurrentPassword string
	NewPassword     string
}

type EmailVerificationInput struct {
	UserID   string
	TenantID string
	// LinkBase and Lang are what ForgotPasswordInput's are, for
	// EmailVerificationDelivery (auth.router.ts:941, 955-957).
	LinkBase string
	Lang     string
}

type VerifyEmailInput struct {
	Token string
}

type ChangeEmailRequestInput struct {
	UserID   string
	TenantID string
	NewEmail string
	// LinkBase and Lang are what ForgotPasswordInput's are, for
	// EmailChangeDelivery (auth.router.ts:1026-1028).
	LinkBase string
	Lang     string
}

type ConfirmEmailChangeInput struct {
	Token string
	// Lang is copied onto EmailChangedDelivery for the notice to the old
	// address. The adapters leave it empty: the reference's route reads only
	// token from the body and calls sendEmailChanged without a language
	// (auth.router.ts:1046, 1062, 1065), so the notice renders in the mailer's
	// default. It is here for a caller driving the service directly.
	Lang string
}

// UpdateProfileInput is the payload behind PATCH /profile. FirstName and
// LastName are pointers because the route is a *partial* update: the reference
// types the body { firstName?: string | null, lastName?: string | null } and
// passes it through verbatim, so a key the caller omitted arrives at the store as
// undefined and leaves the stored column alone (wire-contract §3.5,
// user-store.interface.ts:136).
//
// nil therefore means "not submitted, leave as it is" and a pointer to "" means
// "clear it" — the distinction a plain string cannot carry, and without which
// sending only firstName silently erases the stored lastName.
type UpdateProfileInput struct {
	UserID    string
	TenantID  string
	FirstName *string
	LastName  *string
}

type DeleteAccountInput struct {
	UserID   string
	TenantID string
}
