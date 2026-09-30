package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Service is the main entry point for authentication operations.
type Service struct {
	cfg      Config
	users    UserStore
	sessions SessionStore
	metadata UserMetadataStore
	rbac     RolesPermissionsStore
	tenants  TenantStore
	now      func() time.Time
}

type ServiceOption func(*Service)

func WithMetadataStore(store UserMetadataStore) ServiceOption {
	return func(s *Service) { s.metadata = store }
}

func WithRolesPermissionsStore(store RolesPermissionsStore) ServiceOption {
	return func(s *Service) { s.rbac = store }
}

func WithTenantStore(store TenantStore) ServiceOption {
	return func(s *Service) { s.tenants = store }
}

// NewService builds an auth service with validated configuration.
func NewService(cfg Config, users UserStore, sessions SessionStore, opts ...ServiceOption) (*Service, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if users == nil || sessions == nil {
		return nil, errors.New("auth: stores are required")
	}
	svc := &Service{
		cfg:      cfg,
		users:    users,
		sessions: sessions,
		now:      time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(svc)
		}
	}
	// A cost below the library default is legal — the test suites rely on it —
	// but it is never what a deployment wants, and the symptom (hashes that are
	// cheap to attack) is invisible from outside. validate stays a pure
	// value-in/error-out check in the style of its neighbours, so the one-shot
	// notice goes here, where construction already has the Logger.
	if cfg.BcryptCost != 0 && cfg.BcryptCost < bcrypt.DefaultCost {
		svc.logf("auth: bcrypt cost %d is below the default %d; password hashes will be cheaper to crack", cfg.BcryptCost, bcrypt.DefaultCost)
	}
	return svc, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// Register creates a user and opens a session for them.
//
// The two fields are required, and their absence is refused before any store is
// touched — the order the default register handler on the private dev line
// node-auth works in, which throws AuthError('Email and password are required',
// 'INVALID_INPUT', 400) before it hashes the password or calls userStore.create
// (node-auth auth.router.ts:515-525, resolved against DevLineRevision). That is
// the dev line and not the published reference at ReferenceRevision, whose
// /register is mounted only when the host supplies options.onRegister
// (auth.router.ts:713) and which has no default handler and no INVALID_INPUT
// code at all. Without the check an empty password reached the length test and
// came back as ErrWeakPassword, which tells a caller who sent no password to
// choose a stronger one, and an empty address reached the store and created a
// user with a blank email.
//
// The check runs after normalisation, so an address that is only whitespace is
// refused here rather than stored as the empty string. The dev line tests the
// untrimmed body value and would accept it; this is the narrower reading, and
// it can only refuse a request the dev line would have turned into an account
// with no usable address.
//
// A successful call also opens a session, which the published reference does
// not: see the register-issues-a-session entry in CompatibilityNotes.
func (s *Service) Register(ctx context.Context, in RegisterInput) (User, AuthTokens, error) {
	var zeroTokens AuthTokens
	in.Email = normalizeEmail(in.Email)
	if in.Email == "" || in.Password == "" {
		return User{}, zeroTokens, ErrInvalidInput
	}
	if len(in.Password) < s.cfg.MinPasswordLen {
		return User{}, zeroTokens, ErrWeakPassword
	}

	if _, err := s.users.GetUserByEmail(ctx, in.Email, in.TenantID); err == nil {
		return User{}, zeroTokens, ErrUserExists
	}

	pwHash, err := hashPassword(in.Password, s.cfg.BcryptCost)
	if err != nil {
		return User{}, zeroTokens, err
	}
	userID, err := newID("usr")
	if err != nil {
		return User{}, zeroTokens, err
	}
	now := s.now()
	created, err := s.users.CreateUser(ctx, User{
		ID:              userID,
		Email:           in.Email,
		PasswordHash:    pwHash,
		TenantID:        in.TenantID,
		IsEmailVerified: s.emailVerificationMode() == EmailVerificationModeNone,
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	if err != nil {
		return User{}, zeroTokens, fmt.Errorf("auth: create user: %w", err)
	}

	tokens, err := s.newSessionTokens(ctx, created)
	if err != nil {
		return User{}, zeroTokens, err
	}
	// node-auth auth.router.ts:813, the last thing POST /register does before it
	// answers 201. Publishing here rather than straight after CreateUser keeps
	// the dev line's rule that only the success path raises: there, anything
	// that throws between the register handler and the publish leaves the
	// account created and the event unraised — the welcome mail is the one
	// candidate — and here the extra session this port opens is (see the
	// register-issues-a-session deviation).
	s.publish(ctx, func() Event {
		return Event{
			Name:   EventUserCreated,
			UserID: created.ID,
			Data:   map[string]any{"email": created.Email, "method": registerMethodDefault},
		}
	})
	return created, tokens, nil
}

// Login verifies a password and issues a session, reporting a 2FA-gated account
// as ErrTwoFactorRequired.
//
// It is the narrow form of LoginWithChallenge, which is what the HTTP adapters
// call: the sentinel can say that a second factor is needed and nothing more, and
// the step-up routes need the token that comes with the challenge. Kept as it was
// for direct callers. See login_2fa.go.
//
// It shares the password path with LoginWithChallenge but stops at the decision
// rather than at the built challenge, so the sentinel is reported whenever a
// second factor is *required* and not merely whenever one could be minted. Going
// through the challenge would make this wrapper fail wherever minting fails —
// Config.BuildTokenClaims returning an error is enough (token.go:66-71) — and
// answer a 2FA account with that error instead of ErrTwoFactorRequired. Nothing
// is minted here: the token this call cannot return is never built.
func (s *Service) Login(ctx context.Context, in LoginInput) (User, AuthTokens, error) {
	var zeroTokens AuthTokens
	user, secondFactor, err := s.loginPassword(ctx, in)
	if err != nil {
		return User{}, zeroTokens, err
	}
	if secondFactor {
		return User{}, zeroTokens, ErrTwoFactorRequired
	}
	tokens, err := s.completeLocalLogin(ctx, user)
	if err != nil {
		return User{}, zeroTokens, err
	}
	return user, tokens, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (AuthTokens, error) {
	claims, err := s.parseToken(refreshToken, "refresh")
	if err != nil {
		return AuthTokens{}, err
	}

	tokHash := hashToken(refreshToken)
	session, err := s.sessions.GetSessionByRefreshTokenHash(ctx, tokHash)
	if err != nil {
		return AuthTokens{}, ErrSessionNotFound
	}
	if session.RevokedAt != nil {
		return AuthTokens{}, ErrSessionRevoked
	}
	if s.now().After(session.ExpiresAt.Add(s.cfg.ClockSkew)) {
		return AuthTokens{}, ErrInvalidToken
	}
	if session.ID != claims.Sid || session.UserID != claims.Sub {
		return AuthTokens{}, ErrInvalidToken
	}

	user, err := s.users.GetUserByID(ctx, claims.Sub, claims.Tid)
	if err != nil {
		return AuthTokens{}, ErrInvalidToken
	}

	newRefresh, refreshExp, err := s.issueToken(ctx, user, session.ID, "refresh", s.cfg.RefreshTokenTTL)
	if err != nil {
		return AuthTokens{}, err
	}
	newAccess, _, err := s.issueToken(ctx, user, session.ID, "access", s.cfg.AccessTokenTTL)
	if err != nil {
		return AuthTokens{}, err
	}

	session.RefreshTokenHash = hashToken(newRefresh)
	session.ExpiresAt = refreshExp
	if err := s.sessions.UpdateSession(ctx, session); err != nil {
		return AuthTokens{}, err
	}
	// node-auth auth.router.ts:733, the only session.* name either tree raises.
	//
	// previousSessionId is the dev line's `payload.sid` — the session the
	// presented refresh token named — and SessionID is the session that now
	// holds the rotated token. In this port those are the same string, because
	// rotation here rewrites the refresh-token hash of the existing session
	// while the reference opens a new session and revokes the old one. That is
	// registered as session-rotated-reports-one-session-id; a subscriber
	// tracking session lineage has to read it there before it treats the two
	// keys as a pair.
	s.publish(ctx, func() Event {
		return Event{
			Name:      EventSessionRotated,
			UserID:    user.ID,
			SessionID: session.ID,
			Data:      map[string]any{"previousSessionId": claims.Sid},
		}
	})
	return AuthTokens{AccessToken: newAccess, RefreshToken: newRefresh, ExpiresIn: s.cfg.AccessTokenTTL}, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	claims, err := s.parseToken(refreshToken, "refresh")
	if err != nil {
		return err
	}
	tokHash := hashToken(refreshToken)
	session, err := s.sessions.GetSessionByRefreshTokenHash(ctx, tokHash)
	if err != nil {
		return ErrSessionNotFound
	}
	if session.ID != claims.Sid {
		return ErrInvalidToken
	}
	now := s.now()
	session.RevokedAt = &now
	if err := s.sessions.UpdateSession(ctx, session); err != nil {
		return err
	}
	// node-auth auth.router.ts:692, after the cookies are cleared and on the
	// success path only: the route's catch clears them a second time and
	// publishes nothing (node-auth auth.router.ts:697-701). The payload is the
	// two identifiers and no data key at all — the one reachable site in the
	// vocabulary that carries neither.
	//
	// The dev line reads both off the access-token cookie it decoded into
	// req.user; this port reads them off the refresh token the caller
	// presented, because that is the credential Logout takes. They name the same
	// session either way, and the point both trees share is the one that
	// matters: neither reads the authenticated principal from the context, so a
	// logout answers for the session whose token was spent rather than for
	// whoever the request happened to be authenticated as.
	s.publish(ctx, func() Event {
		return Event{Name: EventAuthLogout, UserID: claims.Sub, SessionID: claims.Sid}
	})
	return nil
}

// Authenticate verifies an access token and returns the user it names. The
// token's signature, type, issuer and lifetime are checked, the session is
// validated when Config.SessionCheckOn is "allcalls", and the user is loaded
// from the UserStore; the failure sentinels are Me's — ErrInvalidToken,
// ErrSessionNotFound, ErrSessionRevoked. It is what the adapters' Middleware
// calls for every request to a protected route.
//
// The user comes back with the optional stores' enrichment — metadata, roles,
// permissions, tenants — because host handlers behind the middleware read those
// off UserFromContext for their own authorisation decisions, and each is a
// local store read that never fails the request: a store error is logged and
// the field left empty, as it always was. What Authenticate does not do is run
// Config.BuildTokenClaims, so CustomClaims is nil. The builder is a mint-time
// hook — with a ClaimsWebhook behind it, a network round trip — and what it
// computed is already inside the token the request carried; running it again
// on every request would make each protected route pay for a claim set nothing
// reads. Me is the call that runs it, for the one route whose body is the
// profile. This is also where the reference draws the line: its authMiddleware
// verifies the token and hands the route the verified payload as req.user
// (auth.middleware.ts:44-61). It does consult the session store — the allcalls
// check at :47-53 and the last-active touch at :56-58 — but never the user
// store and never buildTokenPayload; only its /me calls buildPayload again.
// Authenticate reads the user store in addition, because the Go middleware
// hands the route a User rather than a payload.
func (s *Service) Authenticate(ctx context.Context, accessToken string) (User, error) {
	claims, err := s.parseToken(accessToken, "access")
	if err != nil {
		return User{}, err
	}
	if err := s.validateSessionForAccess(ctx, claims); err != nil {
		return User{}, err
	}
	user, err := s.users.GetUserByID(ctx, claims.Sub, claims.Tid)
	if err != nil {
		return User{}, ErrInvalidToken
	}
	return s.enrichFromStores(ctx, user), nil
}

// Me is Authenticate plus the custom claims: the profile GET /me renders, with
// CustomClaims filled from Config.BuildTokenClaims so that the body reflects
// the hook the way the reference's /me does — its body is buildPayload(user)
// (auth.router.ts:656-680). A builder failure is logged and leaves CustomClaims
// nil rather than failing the call, as it always has: /me is a read, and a read
// should not go dark because a mint-time hook is down.
func (s *Service) Me(ctx context.Context, accessToken string) (User, error) {
	user, err := s.Authenticate(ctx, accessToken)
	if err != nil {
		return User{}, err
	}
	return s.enrichCustomClaims(ctx, user), nil
}

// The `data.method` values the dev line writes on identity.auth.login.success
// and identity.user.created. They are wire — a subscriber switches on them —
// so they are spelled once here rather than at each of the six sites that use
// them.
//
// Three of the four login values are spelled exactly like the
// available2faMethods entries in login_2fa.go, and are deliberately not shared
// with them. That list answers "which second factors can this user present";
// this one answers "which credential completed this login", and they coincide
// only because three credentials happen to be usable as either. A shared
// constant would make the wrong site compile on the day one list grows a value
// the other does not have.
//
// There is no fifth login value. AUTH_LOGIN_SUCCESS covers five publication
// points in the dev line and four methods, because the two magic-link sites —
// the direct login and the step-up branch of the same route — both write
// 'magic-link' (node-auth auth.router.ts:1269, :1284).
const (
	loginMethodLocal     = "local"      // node-auth auth.router.ts:651
	loginMethodTOTP      = "totp"       // node-auth auth.router.ts:970
	loginMethodMagicLink = "magic-link" // node-auth auth.router.ts:1269, :1284
	loginMethodSMS       = "sms"        // node-auth auth.router.ts:1410
	// registerMethodDefault is the 'default' half of
	// `options.onRegister ? 'custom' : 'default'` (node-auth
	// auth.router.ts:815). This port has no onRegister hook — see the
	// register-route-is-always-mounted deviation — so it is the only half
	// reachable here, and 'custom' is never written.
	registerMethodDefault = "default"
)

// publish raises the event build returns on Config.Events, carrying the request
// provenance from ctx, and does nothing whatever when no bus is configured.
//
// This is the port of publishRouterEvent's first line — `if (!eventBus)
// return;` (node-auth auth.router.ts:430) — and of the `?.` in the
// configurator's `this.options.eventBus?.publish(...)` (node-auth
// auth-configurator.ts:92). Most deployments subscribe to nothing, so the nil
// path is the hot one and it has to be free.
//
// That is why the parameter is a builder and not an Event. Every payload in
// this file is an Event with a map[string]any literal inside it, and a value
// parameter would build and allocate that map at all nineteen sites on every
// request whether or not anybody is listening. Passing a closure that is only
// ever called moves the whole construction behind the nil check; the closure
// itself does not escape — publish neither stores it nor lets it outlive the
// call — so escape analysis keeps it on the stack and the nil case allocates
// nothing at all. TestPublishWithoutBusAllocatesNothing pins that, because it
// is a property of the compiler's analysis rather than of the source, and a
// later edit that let build escape would quietly cost every deployment.
//
// PublishContext and never Publish. Publish alone would drop CorrelationID, IP
// and UserAgent — the three fields no Service method can see, because they live
// on the request and reach here only through the carrier an adapter installed
// (event_context.go). Losing them is invisible to a test that does not assert
// them and is exactly what the carrier was built to prevent, so there is one
// call to PublishContext in the package and it is this one.
func (s *Service) publish(ctx context.Context, build func() Event) {
	bus := s.cfg.Events
	if bus == nil {
		return
	}
	bus.PublishContext(ctx, build())
}

// issueSession opens a session for user and returns the tokens together with
// the id of the session now holding them: the reference's
// `const { sessionId } = await issueTokens(…)` (node-auth auth.router.ts:648,
// :732, :967, :1266, :1281, :1407, :1443).
//
// Eight of the dev line's twenty-six publication points put that id on the
// event, and before U18 nothing in this port needed it — newSessionTokens
// minted it, used it for the claims and dropped it. The split is the smallest
// change that exposes it: every existing caller keeps the two-value signature
// it was written against, and only the sites that publish take the third value.
func (s *Service) issueSession(ctx context.Context, user User) (AuthTokens, string, error) {
	sessionID, err := newID("ses")
	if err != nil {
		return AuthTokens{}, "", err
	}
	refreshToken, refreshExp, err := s.issueToken(ctx, user, sessionID, "refresh", s.cfg.RefreshTokenTTL)
	if err != nil {
		return AuthTokens{}, "", err
	}
	accessToken, _, err := s.issueToken(ctx, user, sessionID, "access", s.cfg.AccessTokenTTL)
	if err != nil {
		return AuthTokens{}, "", err
	}
	now := s.now()
	_, err = s.sessions.CreateSession(ctx, Session{
		ID:               sessionID,
		UserID:           user.ID,
		TenantID:         user.TenantID,
		RefreshTokenHash: hashToken(refreshToken),
		CreatedAt:        now,
		ExpiresAt:        refreshExp,
	})
	if err != nil {
		return AuthTokens{}, "", err
	}
	return AuthTokens{AccessToken: accessToken, RefreshToken: refreshToken, ExpiresIn: s.cfg.AccessTokenTTL}, sessionID, nil
}

func (s *Service) newSessionTokens(ctx context.Context, user User) (AuthTokens, error) {
	tokens, _, err := s.issueSession(ctx, user)
	return tokens, err
}

// completeLocalLogin is the tail POST /login shares between its two entry
// points: it opens the session and raises identity.auth.login.success with
// `method: "local"` (node-auth auth.router.ts:649-653).
//
// The reference has one route here and this port has two methods — Login,
// which collapses a second-factor account into ErrTwoFactorRequired, and
// LoginWithChallenge, which mints the challenge the adapters answer with. Both
// arrive by the same path through loginPassword and both end with a session, so
// the publication lives in the tail they share. One helper rather than two
// copies is what keeps the dev line's single site single: neither entry point
// can drift from the other, and no caller can reach both and publish twice.
func (s *Service) completeLocalLogin(ctx context.Context, user User) (AuthTokens, error) {
	tokens, sessionID, err := s.issueSession(ctx, user)
	if err != nil {
		return AuthTokens{}, err
	}
	s.publish(ctx, func() Event {
		return Event{
			Name:      EventAuthLoginSuccess,
			UserID:    user.ID,
			SessionID: sessionID,
			Data:      map[string]any{"method": loginMethodLocal},
		}
	})
	return tokens, nil
}

// sessionIDOf recovers the session id from an access token this service has
// just minted, for the one publication site that cannot take it from
// issueSession: Auth.OAuthComplete publishes identity.auth.oauth.success, and
// the session is opened two calls below it inside
// OAuthService.HandleCallbackWithPolicy, whose exported signature returns the
// tokens and not the id.
//
// Widening that signature would be a breaking change to an exported method for
// the benefit of one event, and threading the id through the four places it
// mints a session would spread the change across a file this PR otherwise does
// not touch. Reading it back costs one HMAC verification on a path that has
// just finished an HTTP round trip to the identity provider.
//
// An unparsable token yields the empty string rather than an error: the token
// was minted here microseconds ago, so this cannot fail for any reason the
// caller could act on, and an event with no session id is a smaller loss than a
// completed OAuth login reported as a failure.
func (s *Service) sessionIDOf(tokens AuthTokens) string {
	claims, err := s.parseToken(tokens.AccessToken, "access")
	if err != nil {
		return ""
	}
	return claims.Sid
}

func (s *Service) ForgotPassword(ctx context.Context, in ForgotPasswordInput) (string, error) {
	in.Email = normalizeEmail(in.Email)
	user, err := s.users.GetUserByEmail(ctx, in.Email, in.TenantID)
	if err != nil {
		return "", nil
	}
	ps, ok := s.users.(UserPasswordStore)
	if !ok {
		return "", ErrFeatureNotSupported
	}
	resetToken, err := randomToken(32)
	if err != nil {
		return "", err
	}
	expiresAt := s.now().Add(s.cfg.ResetTokenTTL)
	if err := ps.UpdateResetToken(ctx, user.ID, user.TenantID, hashToken(resetToken), expiresAt); err != nil {
		return "", err
	}
	// Store first, then send, as on the passwordless routes and in the reference
	// (auth.router.ts:784 then :787-792). A delivery failure is reported to the
	// caller and leaves the token in place; Auth.ForgotPassword is where the HTTP
	// surface decides not to let it change the answer.
	if err := s.deliverPasswordReset(ctx, user, resetToken, expiresAt, in.LinkBase, in.Lang); err != nil {
		return "", err
	}
	return resetToken, nil
}

func (s *Service) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if len(in.NewPassword) < s.cfg.MinPasswordLen {
		return ErrWeakPassword
	}
	ps, ok := s.users.(UserPasswordStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	user, err := ps.GetUserByResetTokenHash(ctx, hashToken(in.Token))
	if err != nil || user.ResetTokenExpiresAt == nil || s.now().After(user.ResetTokenExpiresAt.Add(s.cfg.ClockSkew)) {
		return ErrInvalidToken
	}
	pwHash, err := hashPassword(in.NewPassword, s.cfg.BcryptCost)
	if err != nil {
		return err
	}
	if err := ps.UpdatePassword(ctx, user.ID, user.TenantID, pwHash); err != nil {
		return err
	}
	// Nothing is published here, deliberately. POST /reset-password changes a
	// password exactly as POST /change-password does and raises no event in
	// either tree, where the authenticated route raises
	// identity.user.password.changed (node-auth auth.router.ts:1030 against the
	// reset route at :893-916, which has no publishRouterEvent call). The
	// asymmetry is the reference's; adding the obvious publication here is the
	// step that turns a port into a fork, and the conformance test in
	// event_publication_test.go has no site for it.
	return ps.ClearResetToken(ctx, user.ID, user.TenantID)
}

func (s *Service) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	if len(in.NewPassword) < s.cfg.MinPasswordLen {
		return ErrWeakPassword
	}
	user, err := s.users.GetUserByID(ctx, in.UserID, in.TenantID)
	if err != nil {
		return ErrInvalidCredentials
	}
	if !verifyPassword(in.CurrentPassword, user.PasswordHash) {
		return ErrInvalidCredentials
	}
	ps, ok := s.users.(UserPasswordStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	pwHash, err := hashPassword(in.NewPassword, s.cfg.BcryptCost)
	if err != nil {
		return err
	}
	if err := ps.UpdatePassword(ctx, user.ID, user.TenantID, pwHash); err != nil {
		return err
	}
	// node-auth auth.router.ts:1030, straight after the store write and before
	// the 200. The user id and nothing else: the dev line puts neither the
	// address nor any indication of what the password was on the payload.
	s.publish(ctx, func() Event {
		return Event{Name: EventUserPasswordChanged, UserID: user.ID}
	})
	return nil
}

// SendMagicLink mints a magic link, stores its hash and delivers it through
// Config.SendMagicLink.
//
// The returned plaintext token is redundant for an HTTP caller — the routes
// answer {"success":true} and drop it — and is kept for a direct caller that
// delivers the link itself, and for tests.
func (s *Service) SendMagicLink(ctx context.Context, in MagicLinkSendInput) (string, error) {
	ms, ok := s.users.(MagicLinkStore)
	if !ok {
		return "", ErrFeatureNotSupported
	}
	// Before the lookup, exactly as the reference orders it
	// (magic-link.strategy.ts:12-14 precedes :15). The ordering is visible: a
	// deployment that cannot send mail answers 500 even for an address it does
	// not have, so the not-configured failure outranks the anti-enumeration
	// silence below rather than hiding behind it.
	if s.cfg.SendMagicLink == nil {
		return "", ErrEmailNotConfigured
	}
	in.Email = normalizeEmail(in.Email)
	user, err := s.users.GetUserByEmail(ctx, in.Email, in.TenantID)
	if err != nil {
		return "", nil
	}
	magicToken, err := randomToken(32)
	if err != nil {
		return "", err
	}
	expiresAt := s.now().Add(s.cfg.MagicLinkTTL)
	if err := ms.UpdateMagicLinkToken(ctx, user.ID, user.TenantID, hashToken(magicToken), expiresAt); err != nil {
		return "", err
	}
	// Store first, then send — the reference's order (:22 then :28-33). A send
	// that fails leaves a stored token nobody received, which is harmless: it is
	// unguessable and expires on its own. Sending first would risk the opposite,
	// a delivered link the store never learned about.
	//
	// LinkBase and Lang are the request's, copied through untouched: the
	// reference hands the strategy its siteUrlOverride and lang as built and as
	// received (auth.router.ts:1104/1114 → magic-link.strategy.ts:25-29).
	if err := s.cfg.SendMagicLink(s.senderContext(ctx), MagicLinkDelivery{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Email:     user.Email,
		Token:     magicToken,
		ExpiresAt: expiresAt,
		LinkBase:  in.LinkBase,
		Lang:      in.Lang,
	}); err != nil {
		return "", fmt.Errorf("auth: deliver magic link: %w", err)
	}
	return magicToken, nil
}

func (s *Service) VerifyMagicLink(ctx context.Context, in MagicLinkVerifyInput) (User, AuthTokens, error) {
	return s.verifyMagicLink(ctx, in, "")
}

// verifyMagicLink consumes a magic link and issues a session for its owner.
//
// requireUserID, when set, is the identity the link has to belong to — the
// step-up flow, where the link is a second factor for a user the caller has
// already identified. It is checked *before* anything is issued, so a refused
// request leaves no session behind, and before the email-verification side
// effect, which the reference applies only on the login path
// (auth.router.ts:1158-1164 versus the 2fa branch at :1134-1156). The link is
// still consumed either way: the reference burns it inside the strategy before
// the router compares ids (magic-link.strategy.ts:50), so a mismatch costs the
// link there too.
//
// See VerifyMagicLinkForUser for the exported entry point.
func (s *Service) verifyMagicLink(ctx context.Context, in MagicLinkVerifyInput, requireUserID string) (User, AuthTokens, error) {
	ms, ok := s.users.(MagicLinkStore)
	if !ok {
		return User{}, AuthTokens{}, ErrFeatureNotSupported
	}
	user, err := ms.GetUserByMagicLinkTokenHash(ctx, hashToken(in.Token))
	if err != nil || user.MagicLinkTokenExpiresAt == nil || s.now().After(user.MagicLinkTokenExpiresAt.Add(s.cfg.ClockSkew)) {
		return User{}, AuthTokens{}, ErrInvalidToken
	}
	if err := ms.ClearMagicLinkToken(ctx, user.ID, user.TenantID); err != nil {
		return User{}, AuthTokens{}, err
	}
	if requireUserID != "" && user.ID != requireUserID {
		return User{}, AuthTokens{}, ErrMagicLinkOwnerMismatch
	}
	if requireUserID == "" && !user.IsEmailVerified {
		if evs, ok := s.users.(EmailVerificationStore); ok {
			_ = evs.MarkEmailVerified(ctx, user.ID, user.TenantID, true)
		}
		user.IsEmailVerified = true
	}
	tokens, sessionID, err := s.issueSession(ctx, user)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	// node-auth auth.router.ts:1267 and :1282 — two publication points, one
	// here. The dev line writes POST /magic-link/verify as two branches of one
	// route, the step-up branch that checks the temp token and the direct-login
	// branch that does not, and each ends with its own issueTokens and its own
	// publish; the two payloads are identical, `method: "magic-link"` and no
	// per-branch key. This port has those branches as requireUserID set or
	// empty, and they converge here, so one publication covers both.
	//
	// It is deliberately not `magic-link-2fa` for the step-up branch. Both dev
	// line sites write the same literal, and a subscriber that needed to tell
	// the two apart would have no way to in the reference either.
	s.publish(ctx, func() Event {
		return Event{
			Name:      EventAuthLoginSuccess,
			UserID:    user.ID,
			SessionID: sessionID,
			Data:      map[string]any{"method": loginMethodMagicLink},
		}
	})
	return user, tokens, nil
}

// SendSMSCode mints a one-time code, stores its hash and delivers it through
// Config.SendSMSCode. See SendMagicLink on the returned plaintext.
//
// The HTTP routes refuse an unconfigured deployment before they reach this call
// (Auth.SMSConfigured), because the reference checks config.sms at the top of
// the route rather than in the strategy. This check is what protects a direct
// caller, and it is why a handler that skipped the precheck still cannot store a
// code nobody can deliver.
func (s *Service) SendSMSCode(ctx context.Context, in SMSCodeSendInput) (string, error) {
	ss, ok := s.users.(SMSStore)
	if !ok {
		return "", ErrFeatureNotSupported
	}
	if s.cfg.SendSMSCode == nil {
		return "", ErrSMSNotConfigured
	}
	user, err := s.resolveUser(ctx, in.UserID, in.Email, in.TenantID)
	if err != nil || user.PhoneNumber == "" {
		return "", nil
	}
	code, err := randomNumericCode(6)
	if err != nil {
		return "", err
	}
	expiresAt := s.now().Add(s.cfg.SMSCodeTTL)
	if err := ss.UpdateSMSCode(ctx, user.ID, user.TenantID, hashToken(code), expiresAt); err != nil {
		return "", err
	}
	if err := s.cfg.SendSMSCode(ctx, SMSCodeDelivery{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Phone:     user.PhoneNumber,
		Code:      code,
		ExpiresAt: expiresAt,
	}); err != nil {
		return "", fmt.Errorf("auth: deliver sms code: %w", err)
	}
	return code, nil
}

func (s *Service) VerifySMSCode(ctx context.Context, in SMSCodeVerifyInput) (User, AuthTokens, error) {
	ss, ok := s.users.(SMSStore)
	if !ok {
		return User{}, AuthTokens{}, ErrFeatureNotSupported
	}
	user, err := s.resolveUser(ctx, in.UserID, in.Email, in.TenantID)
	if err != nil {
		return User{}, AuthTokens{}, ErrInvalidCredentials
	}
	matched, err := ss.GetUserBySMSCodeHash(ctx, user.ID, user.TenantID, hashToken(in.Code))
	if err != nil || matched.SMSCodeExpiresAt == nil || s.now().After(matched.SMSCodeExpiresAt.Add(s.cfg.ClockSkew)) {
		return User{}, AuthTokens{}, ErrInvalidCode
	}
	if err := ss.ClearSMSCode(ctx, matched.ID, matched.TenantID); err != nil {
		return User{}, AuthTokens{}, err
	}
	tokens, sessionID, err := s.issueSession(ctx, matched)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	// node-auth auth.router.ts:1408. As with magic-link, POST /sms/verify has a
	// step-up mode and a direct mode there and one publish serves the tail both
	// reach, with `method: "sms"` either way.
	s.publish(ctx, func() Event {
		return Event{
			Name:      EventAuthLoginSuccess,
			UserID:    matched.ID,
			SessionID: sessionID,
			Data:      map[string]any{"method": loginMethodSMS},
		}
	})
	return matched, tokens, nil
}

func (s *Service) SendVerificationEmailToken(ctx context.Context, in EmailVerificationInput) (string, error) {
	evs, ok := s.users.(EmailVerificationStore)
	if !ok {
		return "", ErrFeatureNotSupported
	}
	user, err := s.users.GetUserByID(ctx, in.UserID, in.TenantID)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	if user.IsEmailVerified {
		return "", nil
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	expiresAt := s.now().Add(s.cfg.EmailVerificationTTL)
	if err := evs.UpdateEmailVerificationToken(ctx, user.ID, user.TenantID, hashToken(token), expiresAt); err != nil {
		return "", err
	}
	// Store first, then send (auth.router.ts:953 then :956-961). A failed send
	// yields the reference's generic 500 and leaves the token stored.
	if err := s.deliverEmailVerification(ctx, user, token, expiresAt, in.LinkBase, in.Lang); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) VerifyEmail(ctx context.Context, in VerifyEmailInput) error {
	evs, ok := s.users.(EmailVerificationStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	user, err := evs.GetUserByEmailVerificationTokenHash(ctx, hashToken(in.Token))
	if err != nil || user.EmailVerificationTokenExpiry == nil || s.now().After(user.EmailVerificationTokenExpiry.Add(s.cfg.ClockSkew)) {
		return ErrInvalidToken
	}
	if err := evs.MarkEmailVerified(ctx, user.ID, user.TenantID, true); err != nil {
		return err
	}
	if err := evs.ClearEmailVerificationToken(ctx, user.ID, user.TenantID); err != nil {
		return err
	}
	// node-auth auth.router.ts:1096, after both writes: the flag is set and the
	// token cleared before the event says the address is verified.
	//
	// The other place this port marks an address verified raises nothing, and
	// that is the dev line's shape too: the first magic-link login verifies the
	// address as a side effect (verifyMagicLink above, node-auth
	// auth.router.ts:1277-1280) and publishes only the login.
	s.publish(ctx, func() Event {
		return Event{Name: EventUserEmailVerified, UserID: user.ID}
	})
	return nil
}

func (s *Service) RequestEmailChange(ctx context.Context, in ChangeEmailRequestInput) (string, error) {
	ecs, ok := s.users.(EmailChangeStore)
	if !ok {
		return "", ErrFeatureNotSupported
	}
	in.NewEmail = normalizeEmail(in.NewEmail)
	if _, err := s.users.GetUserByEmail(ctx, in.NewEmail, in.TenantID); err == nil {
		return "", ErrUserExists
	}
	user, err := s.users.GetUserByID(ctx, in.UserID, in.TenantID)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	expiresAt := s.now().Add(s.cfg.EmailChangeTTL)
	if err := ecs.UpdateEmailChangeToken(ctx, user.ID, user.TenantID, in.NewEmail, hashToken(token), expiresAt); err != nil {
		return "", err
	}
	// Store first, then send, and send to the *new* address: this mail verifies
	// that the new mailbox exists (auth.router.ts:1024 then :1027-1032, which mails
	// newEmail). The notice the reference sends to the old address happens on
	// /change-email/confirm — see ConfirmEmailChange.
	if err := s.deliverEmailChange(ctx, user, in.NewEmail, token, expiresAt, in.LinkBase, in.Lang); err != nil {
		return "", err
	}
	return token, nil
}

// ConfirmEmailChange spends an email-change token: the pending address becomes
// the account's, the token is cleared, and then the OLD address is sent the
// email-changed notice through Config.SendEmailChanged — the reference's order
// (auth.router.ts:1056-1066: oldEmail and newEmail read off the user,
// updateEmail, updateEmailChangeToken(null…), then sendEmailChanged(oldEmail,
// newEmail)).
//
// A failing notice is returned as an error, joined to ErrDeliveryFailed, with
// the change already applied. That is the reference's behaviour, reproduced
// rather than softened: its sendEmailChanged call is inside the route's try
// block, so a throwing mailer reaches handleError and the route answers the
// generic 500 for a change that has been committed (:1068-1069). Nothing is
// rolled back, in either port — the token is spent and the address has moved.
func (s *Service) ConfirmEmailChange(ctx context.Context, in ConfirmEmailChangeInput) error {
	ecs, ok := s.users.(EmailChangeStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	user, err := ecs.GetUserByEmailChangeTokenHash(ctx, hashToken(in.Token))
	if err != nil || user.EmailChangeTokenExpiry == nil || s.now().After(user.EmailChangeTokenExpiry.Add(s.cfg.ClockSkew)) {
		return ErrInvalidToken
	}
	// Read before the store moves them (auth.router.ts:1056-1057).
	oldEmail, newEmail := user.Email, user.PendingEmail
	if err := ecs.ApplyEmailChange(ctx, user.ID, user.TenantID); err != nil {
		return err
	}
	if err := ecs.ClearEmailChangeToken(ctx, user.ID, user.TenantID); err != nil {
		return err
	}
	if err := s.deliverEmailChanged(ctx, user, oldEmail, newEmail, in.Lang); err != nil {
		return err
	}
	// node-auth auth.router.ts:1175, and the order is the dev line's: the notice
	// to the old address is sent first and the event is raised only if it went
	// (:1168-1174 precedes the publish). A mailer that throws there reaches the
	// route's catch with the address already moved and the token already spent,
	// so the change is applied and nothing is published — which is the behaviour
	// ConfirmEmailChange's own doc comment already describes for the 500.
	s.publish(ctx, func() Event {
		return Event{
			Name:   EventUserEmailChanged,
			UserID: user.ID,
			Data:   map[string]any{"oldEmail": oldEmail, "newEmail": newEmail},
		}
	})
	return nil
}

func (s *Service) SetupTOTP(ctx context.Context, userID, tenantID string) (string, error) {
	_, err := s.users.GetUserByID(ctx, userID, tenantID)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	return generateTOTPSecret()
}

func (s *Service) VerifyTOTPSetup(ctx context.Context, userID, tenantID, secret, code string) error {
	ts, ok := s.users.(TOTPStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	if !validateTOTPCode(secret, code, s.now()) {
		return ErrInvalidCode
	}
	if err := ts.UpdateTOTPSecret(ctx, userID, tenantID, secret, true); err != nil {
		return err
	}
	// node-auth auth.router.ts:943, once the secret is confirmed and stored.
	// POST /2fa/setup, which only mints a candidate secret, publishes nothing in
	// either tree: enrolment is not enabled until a code verifies against it.
	s.publish(ctx, func() Event {
		return Event{Name: EventUser2FAEnabled, UserID: userID}
	})
	return nil
}

func (s *Service) VerifyTOTP(ctx context.Context, userID, tenantID, code string) (User, AuthTokens, error) {
	user, err := s.users.GetUserByID(ctx, userID, tenantID)
	if err != nil || !user.IsTOTPEnabled || user.TOTPSecret == "" {
		return User{}, AuthTokens{}, ErrInvalidCredentials
	}
	if !validateTOTPCode(user.TOTPSecret, code, s.now()) {
		return User{}, AuthTokens{}, ErrInvalidCode
	}
	tokens, sessionID, err := s.issueSession(ctx, user)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	// node-auth auth.router.ts:968: POST /2fa/verify completing the second step
	// of a password login. It is identity.auth.login.success and not a name of
	// its own — the credential is in `data.method`, which is what makes five
	// sites share one name.
	s.publish(ctx, func() Event {
		return Event{
			Name:      EventAuthLoginSuccess,
			UserID:    user.ID,
			SessionID: sessionID,
			Data:      map[string]any{"method": loginMethodTOTP},
		}
	})
	return user, tokens, nil
}

func (s *Service) GetMetadata(ctx context.Context, userID string) (map[string]any, error) {
	if s.metadata == nil {
		return nil, ErrFeatureNotSupported
	}
	return s.metadata.GetMetadata(ctx, userID)
}

func (s *Service) UpdateMetadata(ctx context.Context, userID string, metadata map[string]any) error {
	if s.metadata == nil {
		return ErrFeatureNotSupported
	}
	return s.metadata.UpdateMetadata(ctx, userID, metadata)
}

func (s *Service) CreateRole(ctx context.Context, role string, permissions []string) error {
	if s.rbac == nil {
		return ErrFeatureNotSupported
	}
	return s.rbac.CreateRole(ctx, role, permissions)
}

func (s *Service) AssignRole(ctx context.Context, userID, role, tenantID string) error {
	if s.rbac == nil {
		return ErrFeatureNotSupported
	}
	return s.rbac.AddRoleToUser(ctx, userID, role, tenantID)
}

func (s *Service) UserHasPermission(ctx context.Context, userID, permission, tenantID string) (bool, error) {
	if s.rbac == nil {
		return false, ErrFeatureNotSupported
	}
	return s.rbac.UserHasPermission(ctx, userID, permission, tenantID)
}

func (s *Service) CreateTenant(ctx context.Context, name string, config map[string]any) (Tenant, error) {
	if s.tenants == nil {
		return Tenant{}, ErrFeatureNotSupported
	}
	id, err := newID("tnt")
	if err != nil {
		return Tenant{}, err
	}
	return s.tenants.CreateTenant(ctx, Tenant{
		ID:        id,
		Name:      name,
		IsActive:  true,
		Config:    config,
		CreatedAt: s.now(),
	})
}

func (s *Service) AddUserToTenant(ctx context.Context, userID, tenantID string) error {
	if s.tenants == nil {
		return ErrFeatureNotSupported
	}
	return s.tenants.AssociateUserWithTenant(ctx, userID, tenantID)
}

func (s *Service) DisableTOTP(ctx context.Context, userID, tenantID string) error {
	ts, ok := s.users.(TOTPStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	if err := ts.UpdateTOTPSecret(ctx, userID, tenantID, "", false); err != nil {
		return err
	}
	// node-auth auth.router.ts:997, once the secret is gone. The two policy
	// refusals that guard the dev line's route — the per-user require2FA and the
	// settings store's system-wide one — return before it and publish nothing;
	// in this port those live above this call, on Auth, so a refused disable
	// never reaches here either.
	s.publish(ctx, func() Event {
		return Event{Name: EventUser2FADisabled, UserID: userID}
	})
	return nil
}

func (s *Service) ListSessions(ctx context.Context, userID, tenantID string) ([]Session, error) {
	store, ok := s.sessions.(SessionAdminStore)
	if !ok {
		return nil, ErrFeatureNotSupported
	}
	return store.ListSessionsForUser(ctx, userID, tenantID)
}

func (s *Service) RevokeSessionByID(ctx context.Context, sessionID string) error {
	store, ok := s.sessions.(SessionAdminStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	return store.RevokeSessionByID(ctx, sessionID)
}

func (s *Service) CleanupExpiredSessions(ctx context.Context) (int, error) {
	store, ok := s.sessions.(SessionAdminStore)
	if !ok {
		return 0, ErrFeatureNotSupported
	}
	return store.DeleteExpiredSessions(ctx, s.now())
}

// ListUsers, ListAllSessions and ListAllRoles resolve the three admin listers.
// They are the capability half of AdminUserStore, SessionLister and RoleLister:
// the assertion that fails here is what M8's `GET /admin/api/users`,
// `/admin/api/sessions` and `/admin/api/roles` turn into the reference's 501
// (admin.router.ts:754, :1093, :1133), so ErrFeatureNotSupported on these three
// means "the configured store cannot enumerate", never "there is nothing there".
// An empty page and this error are different answers and the router must keep
// them apart.
//
// Nothing is filtered, clamped or defaulted on the way through. `limit` clamped
// to 100 and defaulting to 20, `offset` defaulting to 0, the in-memory `filter`
// over a 500-row batch at offset 0, and the best-effort `total` are all query
// semantics of the route rather than of the store (admin.router.ts:750-782), and
// they belong to M8; passing them through untouched is what leaves M8 free to
// implement them without reopening this seam.
func (s *Service) ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]User, error) {
	store, ok := s.users.(AdminUserStore)
	if !ok {
		return nil, ErrFeatureNotSupported
	}
	return store.ListUsers(ctx, tenantID, limit, offset)
}

func (s *Service) ListAllSessions(ctx context.Context, limit, offset int) ([]Session, error) {
	store, ok := s.sessions.(SessionLister)
	if !ok {
		return nil, ErrFeatureNotSupported
	}
	return store.GetAllSessions(ctx, limit, offset)
}

// ListAllRoles asserts on s.rbac, which — unlike s.users and s.sessions — is
// optional and may be nil. A type assertion on a nil interface value fails
// rather than panicking, so the one check covers both "no RBAC store configured"
// and "the configured one cannot enumerate"; the route answers 404 for the first
// and 501 for the second (admin.router.ts:1130, :1133), and tells them apart by
// asking whether it was given a store, not by reading this error.
func (s *Service) ListAllRoles(ctx context.Context) ([]string, error) {
	store, ok := s.rbac.(RoleLister)
	if !ok {
		return nil, ErrFeatureNotSupported
	}
	return store.GetAllRoles(ctx)
}

// UpdateProfile applies a partial profile update: a nil field in the input is
// one the caller did not submit and must be left as it is stored (§3.5).
//
// UserAccountStore.UpdateProfile takes both names by value, so a nil field is
// resolved against the current record before the write rather than by widening
// the store interface — a store written against this package keeps compiling and
// still gets partial semantics. The read-modify-write is not atomic; two
// concurrent partial patches of *different* fields can still lose one. Making it
// atomic needs a store-level patch primitive, which is a breaking interface
// change and its own item; silently erasing a field on every single partial call
// is the failure this closes.
func (s *Service) UpdateProfile(ctx context.Context, in UpdateProfileInput) (User, error) {
	accountStore, ok := s.users.(UserAccountStore)
	if !ok {
		return User{}, ErrFeatureNotSupported
	}
	firstName, lastName := in.FirstName, in.LastName
	if firstName == nil || lastName == nil {
		current, err := s.users.GetUserByID(ctx, in.UserID, in.TenantID)
		if err != nil {
			return User{}, fmt.Errorf("auth: update profile: %w", err)
		}
		if firstName == nil {
			firstName = &current.FirstName
		}
		if lastName == nil {
			lastName = &current.LastName
		}
	}
	updated, err := accountStore.UpdateProfile(ctx, in.UserID, in.TenantID, strings.TrimSpace(*firstName), strings.TrimSpace(*lastName))
	if err != nil {
		return User{}, fmt.Errorf("auth: update profile: %w", err)
	}
	return s.enrichUser(ctx, updated)
}

// DeleteAccount runs the reference's account cleanup in the reference's order
// (auth.router.ts:1597-1636): sessions, then role assignments, then tenant
// memberships, then metadata, and the user record last. The order is not
// cosmetic — deleting the identity first and failing anywhere afterwards leaves
// sessions that still authenticate a user who no longer exists.
func (s *Service) DeleteAccount(ctx context.Context, in DeleteAccountInput) error {
	accountStore, ok := s.users.(UserAccountStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	if adminStore, ok := s.sessions.(SessionAdminStore); ok {
		sessions, err := adminStore.ListSessionsForUser(ctx, in.UserID, in.TenantID)
		if err == nil {
			for _, session := range sessions {
				_ = adminStore.RevokeSessionByID(ctx, session.ID)
			}
		}
	}
	if s.rbac != nil {
		roles, err := s.rbac.GetRolesForUser(ctx, in.UserID, in.TenantID)
		if err == nil {
			for _, role := range roles {
				_ = s.rbac.RemoveRoleFromUser(ctx, in.UserID, role, in.TenantID)
			}
		}
	}
	if s.tenants != nil {
		tenants, err := s.tenants.GetTenantsForUser(ctx, in.UserID)
		if err == nil {
			for _, tenant := range tenants {
				_ = s.tenants.DisassociateUserFromTenant(ctx, in.UserID, tenant.ID)
			}
		}
	}
	if s.metadata != nil {
		_ = s.metadata.ClearMetadata(ctx, in.UserID)
	}
	if err := accountStore.DeleteUser(ctx, in.UserID, in.TenantID); err != nil {
		return fmt.Errorf("auth: delete account: %w", err)
	}
	// node-auth auth.router.ts:1776, last of all — after every store the route
	// touches and after the cookies are cleared, which in this port the adapter
	// does on the way out. The user id is all the payload carries, and it names
	// an account that no longer exists: a subscriber that wants anything else
	// about the user has to have kept it from an earlier event, which is the
	// same constraint the dev line's subscribers work under.
	s.publish(ctx, func() Event {
		return Event{Name: EventUserDeleted, UserID: in.UserID}
	})
	return nil
}

func (s *Service) resolveUser(ctx context.Context, userID, email, tenantID string) (User, error) {
	trimmedUserID := strings.TrimSpace(userID)
	trimmedEmail := strings.TrimSpace(email)
	if trimmedUserID != "" {
		return s.users.GetUserByID(ctx, trimmedUserID, tenantID)
	}
	if trimmedEmail != "" {
		return s.users.GetUserByEmail(ctx, normalizeEmail(trimmedEmail), tenantID)
	}
	return User{}, ErrInvalidCredentials
}

func (s *Service) requiresTwoFactor(user User) bool {
	hasTOTP := user.IsTOTPEnabled && strings.TrimSpace(user.TOTPSecret) != ""
	return s.cfg.Require2FA || user.Require2FA || hasTOTP
}

// emailVerificationMode returns the normalized Config.EmailVerificationMode,
// falling back to none so that embedders that never set it keep the historical
// behaviour: a self-registered user is usable right away, and a user that is
// unverified for any other reason is still refused at login.
func (s *Service) emailVerificationMode() string {
	mode := strings.ToLower(strings.TrimSpace(s.cfg.EmailVerificationMode))
	if mode == "" {
		return EmailVerificationModeNone
	}
	return mode
}

func (s *Service) validateSessionForAccess(ctx context.Context, claims tokenClaims) error {
	mode := strings.ToLower(strings.TrimSpace(s.cfg.SessionCheckOn))
	if mode == "" {
		mode = SessionCheckOnRefresh
	}
	if mode != SessionCheckOnAllCalls {
		return nil
	}
	if strings.TrimSpace(claims.Sid) == "" {
		return ErrInvalidToken
	}

	session, supported, err := s.lookupSession(ctx, claims.Sid, claims.Sub, claims.Tid)
	if !supported {
		s.logf("auth: session all-calls check requested but session store does not support lookup")
		return nil
	}
	if err != nil {
		return ErrSessionNotFound
	}
	return s.validateSessionState(session, claims)
}

// revokeSession marks one session revoked: through SessionAdminStore when the
// store has it, and otherwise by looking the session up and writing it back
// with RevokedAt set. It is what the IdP uses to undo a replayed code's
// exchange.
func (s *Service) revokeSession(ctx context.Context, sessionID, userID, tenantID string) error {
	if admin, ok := s.sessions.(SessionAdminStore); ok {
		return admin.RevokeSessionByID(ctx, sessionID)
	}
	session, supported, err := s.lookupSession(ctx, sessionID, userID, tenantID)
	if !supported {
		return ErrFeatureNotSupported
	}
	if err != nil {
		return err
	}
	now := s.now()
	session.RevokedAt = &now
	return s.sessions.UpdateSession(ctx, session)
}

// canLookupSessions reports whether the session store can find a session by
// its id, through either of the two optional interfaces lookupSession tries.
func (s *Service) canLookupSessions() bool {
	if _, ok := s.sessions.(SessionLookupStore); ok {
		return true
	}
	_, ok := s.sessions.(SessionAdminStore)
	return ok
}

// lookupSession finds session sessionID of user userID in tenant tenantID:
// through SessionLookupStore when the store has it, and otherwise by listing
// the user's sessions through SessionAdminStore. supported is false when the
// store offers neither. err is ErrSessionNotFound when the session is not
// there — the store answered ErrSessionNotFound itself, or the listing does
// not contain it — and the store's own error otherwise, so that a caller can
// tell a session that is gone from a store that failed. The caller decides what an unsupported store means:
// the all-calls access check lets the token through with a log line, as it
// always has, and the IdP's refresh_token grant never issues a token it could
// not check.
func (s *Service) lookupSession(ctx context.Context, sessionID, userID, tenantID string) (session Session, supported bool, err error) {
	if lookup, ok := s.sessions.(SessionLookupStore); ok {
		session, err := lookup.GetSessionByID(ctx, sessionID)
		if err != nil {
			return Session{}, true, err
		}
		return session, true, nil
	}
	if admin, ok := s.sessions.(SessionAdminStore); ok {
		sessions, err := admin.ListSessionsForUser(ctx, userID, tenantID)
		if err != nil {
			return Session{}, true, err
		}
		for _, session := range sessions {
			if session.ID == sessionID {
				return session, true, nil
			}
		}
		return Session{}, true, ErrSessionNotFound
	}
	return Session{}, false, nil
}

func (s *Service) validateSessionState(session Session, claims tokenClaims) error {
	if session.ID != claims.Sid {
		return ErrInvalidToken
	}
	if session.UserID != claims.Sub {
		return ErrInvalidToken
	}
	if session.TenantID != claims.Tid {
		return ErrInvalidToken
	}
	if session.RevokedAt != nil {
		return ErrSessionRevoked
	}
	if s.now().After(session.ExpiresAt.Add(s.cfg.ClockSkew)) {
		return ErrInvalidToken
	}
	return nil
}

// enrichUser is the full profile — the stores' enrichment and then the custom
// claims — for the calls whose result is rendered as one: Me, UpdateProfile,
// UpdatePhoneNumber. Authenticate takes only the first half; see there.
func (s *Service) enrichUser(ctx context.Context, user User) (User, error) {
	return s.enrichCustomClaims(ctx, s.enrichFromStores(ctx, user)), nil
}

// enrichFromStores fills Metadata, Roles, Permissions and Tenants from the
// optional stores. Each read is best effort: a failure is logged and the field
// left as it was, so a profile is never refused for a store that is down.
func (s *Service) enrichFromStores(ctx context.Context, user User) User {
	if s.metadata != nil {
		metadata, err := s.metadata.GetMetadata(ctx, user.ID)
		if err != nil {
			s.logf("auth: metadata enrichment skipped for user %q: %v", user.ID, err)
		} else {
			user.Metadata = metadata
		}
	}
	if s.rbac != nil {
		roles, err := s.rbac.GetRolesForUser(ctx, user.ID, user.TenantID)
		if err != nil {
			s.logf("auth: role enrichment skipped for user %q: %v", user.ID, err)
		} else {
			user.Roles = roles
			permissions, err := s.rbac.GetPermissionsForUser(ctx, user.ID, user.TenantID)
			if err != nil {
				s.logf("auth: permission enrichment skipped for user %q: %v", user.ID, err)
			} else {
				user.Permissions = permissions
			}
		}
	}
	if s.tenants != nil {
		tenants, err := s.tenants.GetTenantsForUser(ctx, user.ID)
		if err != nil {
			s.logf("auth: tenant enrichment skipped for user %q: %v", user.ID, err)
		} else {
			user.Tenants = tenants
		}
	}
	return user
}

// enrichCustomClaims fills CustomClaims from Config.BuildTokenClaims, best
// effort as above. The user handed to the hook is the enriched one, so a
// builder — or the endpoint behind a ClaimsWebhook — sees roles and tenants
// here that it does not see at mint time, where the stored row is all there is.
func (s *Service) enrichCustomClaims(ctx context.Context, user User) User {
	if s.cfg.BuildTokenClaims == nil {
		return user
	}
	claims, err := s.cfg.BuildTokenClaims(ctx, user)
	if err != nil {
		s.logf("auth: custom claim enrichment skipped for user %q: %v", user.ID, err)
		return user
	}
	user.CustomClaims = claims
	return user
}

func (s *Service) logf(format string, args ...any) {
	if s.cfg.Logger != nil {
		s.cfg.Logger(format, args...)
	}
}
