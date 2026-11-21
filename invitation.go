package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// This file is the invitation flow: how an account comes to exist in a
// deployment that offers no sign-up.
//
// HTTPConfig.ClosedRegistration takes POST <prefix>/register off the wire, and
// the admin API has no route that creates an account (list, detail, delete and
// promote only, as in the reference). So an invite-only deployment had no way
// to provision a user over HTTP at all. The reference does not have one either:
// it ships the mail half — MailerService.sendInvitation and its `invitation`
// template, `{...data, link}` (mailer.service.ts:210-227) — and no route that
// creates, delivers or redeems an invitation. Everything below except the mail
// is therefore this port's own surface, registered as the deviation
// invitations-are-an-addition.
//
// The flow:
//
//   - POST <admin>/api/users/invitations (admin_invitations.go), behind the
//     admin guard — MachineAccess and the session policy alike — creates a
//     pending account (no password, no factor, address unverified) and an
//     invitation for it: a single-use token whose SHA-256 is all the store
//     keeps, valid Config.InvitationTTL (72 hours by default). The token goes
//     to Config.SendInvitation and is never in the answer, unless the host has
//     no sender and AdminOptions.RevealInvitationToken says the caller
//     delivers it.
//   - POST <prefix>/invitations/accept {token, password}, public and mounted
//     even under ClosedRegistration, spends the token, sets the password and
//     marks the address verified, then answers what the account's next step
//     is: the login's own second-factor challenge when one is demanded —
//     403 2FA_SETUP_REQUIRED with an enrolment token under Config.EnrolOnLogin
//     — and otherwise the registration's answer, 201 {"success":true,
//     "userId":…}, with the session Config.IssueSessionOnRegister allows.
//   - DELETE <admin>/api/users/invitations/{id} revokes an invitation and
//     removes the account it reserved if nothing has used that account;
//     GET <admin>/api/users/invitations lists the outstanding ones.
//
// What the pending account is. It is an ordinary row in the UserStore with no
// password, so the routes that act on an address act on it too:
// /forgot-password and /magic-link/send mail its owner a credential, which is
// as good as the invitation for whoever reads that mailbox. The invitation is
// the convenient door, not the only one, and the trust is the same: control of
// the invited address. What the invitation adds is the window and the
// revocation. A revoked invitation takes the account with it when nobody has
// used that account — no route then answers for the address — and leaves an
// account somebody has signed in to; an expired one stays listed, and
// revocable, until an administrator revokes it or deletes the user.

// InvitationAcceptRoute is the public route an invitee redeems an invitation
// at, relative to the mount prefix. It is also the path InvitationURL builds
// the emailed link on: no page ships for it, so the front end that owns the
// accept form serves GET on that path and posts {token, password} to the
// route, the arrangement the reference's emailed links already assume for
// /reset-password.
const InvitationAcceptRoute = "/invitations/accept"

// DefaultInvitationTTL is how long an invitation is valid when
// Config.InvitationTTL is zero.
const DefaultInvitationTTL = 72 * time.Hour

// CodeInvalidInvitation is the code of the one refusal POST
// <prefix>/invitations/accept gives for a token it will not honour.
const CodeInvalidInvitation = "INVALID_INVITATION"

// The invitation events. They are this port's, like EventAdminMachineAccess,
// and for the same reason they are outside the identity.* vocabulary
// EventNames returns: that list is the reference's, and nothing may join it
// without the reference declaring it first. IsEventName reports false for all
// three; a subscriber names them, or uses the wildcard.
//
// None carries the token, its hash or the accept link. Each names the
// account's user and tenant, and carries the request's provenance — the admin
// routes install it the way the admin router's own publications do, and the
// accept route sits behind EventContextMiddleware like every auth route.
const (
	// EventUserInvited is raised once an invitation has been stored and, when
	// Config.SendInvitation is set, delivered. Data: invitationId, email,
	// invitedBy, invitedByKind, expiresAt, and accountCreated — false when a
	// re-invitation reused the pending account (Config.InvitationReinvite).
	EventUserInvited = "identity.user.invited"
	// EventUserInvitationAccepted is raised once the invitee's password is set
	// and the address marked verified, before any challenge or session. Data:
	// invitationId. A session that the acceptance opens raises
	// identity.auth.login.success after it, with method "local", as a
	// registration that opens one does.
	EventUserInvitationAccepted = "identity.user.invitation.accepted"
	// EventUserInvitationRevoked is raised when an administrator revokes an
	// invitation. Data: invitationId, revokedBy, revokedByKind, and
	// accountRemoved — whether the pending account went with it.
	EventUserInvitationRevoked = "identity.user.invitation.revoked"
)

// The two kinds of principal Invitation.InvitedByKind names.
const (
	// InvitedByMachine is a caller AdminOptions.MachineAccess admitted;
	// InvitedBy is the principal the host's function named.
	InvitedByMachine = "machine"
	// InvitedByUser is a person the admin guard resolved; InvitedBy is the
	// user's id.
	InvitedByUser = "user"
)

var (
	// ErrInvalidInvitation is the one answer to an invitation token that is not
	// honoured: unknown, expired, revoked, already accepted, or naming an
	// account that is gone or no longer pending. They are one sentinel, and one
	// wire answer, so that the accept route tells a holder of a guessed or
	// leaked token nothing about which it was.
	ErrInvalidInvitation = errors.New("auth: invalid or expired invitation")
	// ErrInvitationNotFound is what an InvitationStore answers when no
	// invitation matches: an unknown id, and — from ConsumeInvitation — a
	// token hash that matches nothing pending and unexpired.
	ErrInvitationNotFound = errors.New("auth: invitation not found")
	// ErrInvitationNotPending is what InvitationStore.RevokeInvitation answers,
	// together with the record, for an invitation that was already accepted or
	// revoked.
	ErrInvitationNotPending = errors.New("auth: invitation is no longer pending")
)

// HTTPErrInvalidInvitation is POST <prefix>/invitations/accept's refusal of a
// token, whatever the reason; see ErrInvalidInvitation. It is a 401 because
// the token is the route's credential, as the magic-link route's refusal is,
// and not a 410: a status that told a spent token from an unknown one would
// tell a token's holder that the invitation had existed.
var HTTPErrInvalidInvitation = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid or expired invitation", Code: CodeInvalidInvitation}

// HTTPErrInvitationInputRequired is POST <prefix>/invitations/accept's answer
// to a body without a token or without a password.
var HTTPErrInvitationInputRequired = HTTPError{Status: http.StatusBadRequest, Message: "Token and password are required", Code: CodeInvalidInput}

// Invitation is one invitation as the store holds it. The plaintext token is
// never part of it: TokenHash is hashToken of the token — hex SHA-256 — and the
// token itself exists only in the delivery and, for a direct caller, in
// InvitationResult.
//
// A record is pending while AcceptedAt and RevokedAt are both nil; whether a
// pending record has expired is a question of ExpiresAt against the clock, and
// an expired record stays pending — listed, revocable, and no longer
// accepted — until it is revoked.
type Invitation struct {
	// ID is the public handle, "inv_" and 32 hex digits: what the admin routes
	// name and revoke an invitation by, and what the events carry.
	ID string
	// TokenHash is the key ConsumeInvitation finds the record by.
	TokenHash string
	// UserID and TenantID are the pending account the invitation was made
	// for; Email is that account's address as it was invited, normalised.
	UserID   string
	TenantID string
	Email    string
	// Role is the single-role field the account was created with (User.Role),
	// empty when the invitation named none.
	Role string
	// Metadata is the invitation's metadata as the administrator sent it. The
	// account's metadata is written through the UserMetadataStore when one is
	// configured; the copy here is what the delivery and the listing carry.
	Metadata map[string]any
	// InvitedBy and InvitedByKind name who created the invitation: a machine
	// principal (InvitedByMachine) or a user id (InvitedByUser). Both are
	// empty when the admin guard identified nobody — AdminOpen, or the legacy
	// secret — and for a direct caller that named nobody.
	InvitedBy     string
	InvitedByKind string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	// AcceptedAt is set by ConsumeInvitation, RevokedAt by RevokeInvitation;
	// at most one of the two is ever set.
	AcceptedAt *time.Time
	RevokedAt  *time.Time
}

// Pending reports whether the invitation was neither accepted nor revoked.
func (inv Invitation) Pending() bool { return inv.AcceptedAt == nil && inv.RevokedAt == nil }

// Expired reports whether the invitation's lifetime is over at now. A token is
// honoured strictly before ExpiresAt.
func (inv Invitation) Expired(now time.Time) bool { return !now.Before(inv.ExpiresAt) }

// InvitationStore persists invitations. Config.Invitations (WithInvitationStore)
// is the switch for the whole feature: with no store, none of the four routes
// is registered.
//
// MemoryInvitationStore is the in-process implementation. Like
// MemoryAuthCodeStore it is correct only while every request is served by the
// same process; a serverless or multi-instance deployment supplies a shared
// one, and what that one owes is below.
//
// # What an implementation must guarantee
//
// The service relies on each point and checks only the hash and the expiry
// again itself.
//
//   - Keyed by Invitation.TokenHash for the consume, never by the token, which
//     the store never sees. ID and TokenHash are each unique; both are random
//     (128 and 256 bits), so CreateInvitation need not detect a collision, and
//     MemoryInvitationStore refuses one with ErrAlreadyExists.
//   - ConsumeInvitation is the single-use guarantee, and it is atomic: for a
//     given hash, however many calls run concurrently and on however many
//     processes, exactly one returns a nil error, and only while the record is
//     pending and now is before ExpiresAt. That call sets AcceptedAt to now and
//     returns the record as updated. Every other call — an unknown hash, an
//     expired record, an accepted or revoked one, the losers of a race —
//     returns ErrInvitationNotFound and no record, with no distinction between
//     them. "Expired" is decided against the now the call is given, never
//     left to a background sweep: a TTL that deletes rows late must not make
//     an expired token redeemable.
//   - RevokeInvitation is atomic against ConsumeInvitation: an invitation is
//     accepted or revoked, never both, and whichever write lands first wins.
//     A pending record — expired or not — gets RevokedAt set to now and is
//     returned with a nil error. An accepted or already revoked one is
//     returned unchanged with ErrInvitationNotPending. An unknown id is
//     ErrInvitationNotFound.
//   - ListPendingInvitations pages the records that are neither accepted nor
//     revoked, expired ones included, in ID order (ascending, Go string
//     comparison), under the paging rules AdminUserStore states: limit <= 0 is
//     an empty page, offset < 0 reads as 0, a short page means nothing follows.
//   - PendingInvitationsForUser returns the same kind of record for one user
//     id, in ID order, and it must be a consistent read: it reflects every
//     create, consume and revoke that returned before it was called. It is how
//     a re-invitation tells an account an invitation reserved from one some
//     other route left passwordless — a stale empty answer makes a legitimate
//     re-invitation a 409 — and how a revocation tells whether another
//     invitation still holds the account — a stale answer that misses a newer
//     invitation lets the revocation delete the account that invitation is
//     about to activate.
//   - Records, and the Metadata map in them, belong to the caller once
//     returned: the store keeps its own copy.
//   - Errors other than the two sentinels are answered as the generic 500 and
//     change nothing the service has not already written; the store is not
//     expected to map them.
//
// # Implementing it on DynamoDB
//
// The first shared implementation is a DynamoDB single-table design, and the
// atomicity points are where it can go wrong. One layout that keeps them:
//
//   - One item per invitation: PK "INV#<ID>", with every field above —
//     tokenHash, userId, tenantId, email, role, metadata (a map), invitedBy,
//     invitedByKind, createdAt, expiresAt (epoch seconds as N, so it can be
//     compared in a condition), acceptedAt, revokedAt — and a TTL attribute
//     some retention past expiresAt.
//   - One pointer item per token: PK "INVTOKEN#<tokenHash>" holding the id,
//     and one membership item per pending invitation in the user's own
//     partition: PK "INVUSER#<userId>", SK "<id>". All three are written in
//     one TransactWriteItems at create, with attribute_not_exists(PK) on each.
//   - ConsumeInvitation: a consistent GetItem of the token pointer, then one
//     TransactWriteItems of two actions — an Update of the invitation
//     conditioned on attribute_not_exists(acceptedAt) AND
//     attribute_not_exists(revokedAt) AND expiresAt > :now AND
//     tokenHash = :hash, setting acceptedAt, and a Delete of the membership
//     item — then the updated record. A cancelled transaction, or a missing
//     pointer, is ErrInvitationNotFound. Reading the invitation and then
//     writing it unconditionally is not equivalent: two accepts both read a
//     pending item.
//   - RevokeInvitation: the same transaction with the expiry clause dropped,
//     setting revokedAt; on a cancellation read the item (a consistent
//     GetItem, or ReturnValuesOnConditionCheckFailure ALL_OLD) to tell
//     ErrInvitationNotPending from ErrInvitationNotFound.
//   - PendingInvitationsForUser: a Query of PK "INVUSER#<userId>" with
//     ConsistentRead, then a consistent BatchGetItem of the invitations it
//     names. The membership item leaves the partition in the very transaction
//     that ends the invitation, so the answer is exact — which a GSI, whose
//     reads are eventually consistent, cannot give.
//   - ListPendingInvitations: a sparse GSI whose partition key is a constant
//     ("INV#PENDING") and whose sort key is the id, written at create and
//     REMOVEd by the consume and the revoke update. Its reads are eventually
//     consistent, which the one caller, the admin console's listing,
//     tolerates.
type InvitationStore interface {
	CreateInvitation(ctx context.Context, invitation Invitation) error
	ConsumeInvitation(ctx context.Context, tokenHash string, now time.Time) (Invitation, error)
	RevokeInvitation(ctx context.Context, id string, now time.Time) (Invitation, error)
	ListPendingInvitations(ctx context.Context, limit, offset int) ([]Invitation, error)
	PendingInvitationsForUser(ctx context.Context, userID string) ([]Invitation, error)
}

// InviteUserInput is what Service.InviteUser takes.
type InviteUserInput struct {
	// Email is the address to invite. It is normalised as Register normalises
	// it, and required.
	Email string
	// TenantID is the tenant the account is created in.
	TenantID string
	// Role is written to User.Role on the account the call creates. Optional.
	// A re-invitation reuses the pending account as it is, role included.
	Role string
	// Metadata is stored on the invitation and handed to the sender, and is
	// written through the UserMetadataStore, when one is configured, for an
	// account the call creates. Optional.
	Metadata map[string]any
	// InvitedBy and InvitedByKind are recorded on the invitation and the
	// identity.user.invited event: the audit of who invited. The admin route
	// fills them from the guard — the machine principal, or the signed-in
	// user's id.
	InvitedBy     string
	InvitedByKind string
	// LinkBase and Lang are what ForgotPasswordInput's are, copied onto the
	// InvitationDelivery untouched.
	LinkBase string
	Lang     string
}

// InvitationResult is what Service.InviteUser returns.
type InvitationResult struct {
	Invitation Invitation
	// User is the pending account the invitation was made for.
	User User
	// Token is the plaintext token. The HTTP route hands it to nobody unless
	// AdminOptions.RevealInvitationToken allows it; it is returned here for a
	// direct caller that delivers the invitation itself, as SendMagicLink
	// returns its token.
	Token string
	// AccountCreated is false when a re-invitation reused the pending account
	// an earlier invitation created (Config.InvitationReinvite).
	AccountCreated bool
}

// AcceptInvitationInput is what Service.AcceptInvitation takes: the body of
// POST <prefix>/invitations/accept.
type AcceptInvitationInput struct {
	Token    string
	Password string
}

// InvitationAcceptance is what Service.AcceptInvitation returns. Exactly one of
// three things happened: a second factor is demanded and Challenge says how to
// present or enrol it; a session was opened (Tokens); or neither, and the
// invitee logs in with the password just set.
type InvitationAcceptance struct {
	// User is the account as it now is: password set, address verified.
	User User
	// Invitation is the record as accepted.
	Invitation Invitation
	// Tokens is the session, zero unless Config.IssueSessionOnRegister opened
	// one; see Service.AcceptInvitation.
	Tokens AuthTokens
	// Challenge is the login's own second-factor answer for the account, nil
	// when none is demanded.
	Challenge *TwoFactorChallenge
}

// InvitationAcceptRequest is the body POST <prefix>/invitations/accept reads.
// An absent body is a body with both members omitted.
type InvitationAcceptRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// InvitationRevocation is what Service.RevokeInvitation returns.
type InvitationRevocation struct {
	Invitation Invitation
	// AccountRemoved reports that the pending account the invitation reserved
	// was deleted with it.
	AccountRemoved bool
}

// InvitationsEnabled reports whether Config.Invitations is set: the switch the
// adapters mount POST <prefix>/invitations/accept on and the admin router
// registers its three invitation routes on.
func (s *Service) InvitationsEnabled() bool { return s.cfg.Invitations != nil }

// invitationTTL is Config.InvitationTTL resolved: zero means
// DefaultInvitationTTL.
func (s *Service) invitationTTL() time.Duration {
	if s.cfg.InvitationTTL > 0 {
		return s.cfg.InvitationTTL
	}
	return DefaultInvitationTTL
}

// invitationCapabilityGap names the optional user-store capability the flow
// needs and the configured store lacks, or "" when it has all three:
// UserPasswordStore, because the acceptance sets the password;
// EmailVerificationStore, because it marks the address verified, which the
// login's gate and the enrolment token both read; and UserAccountStore,
// because a revocation, and a send that fails, remove the pending account.
//
// They are asked at invitation time, before anything is written, so that no
// invitation is ever created that its acceptance could not complete.
func (s *Service) invitationCapabilityGap() string {
	if _, ok := s.users.(UserPasswordStore); !ok {
		return "UserPasswordStore"
	}
	if _, ok := s.users.(EmailVerificationStore); !ok {
		return "EmailVerificationStore"
	}
	if _, ok := s.users.(UserAccountStore); !ok {
		return "UserAccountStore"
	}
	return ""
}

// pendingAccount reports whether user can still be activated by an
// invitation: no password and no second factor.
func pendingAccount(user User) bool {
	hasTOTP := user.IsTOTPEnabled && strings.TrimSpace(user.TOTPSecret) != ""
	return user.PasswordHash == "" && !hasTOTP
}

// InviteUser creates a pending account for an address and an invitation to
// activate it, and delivers the invitation through Config.SendInvitation.
//
// The order of what happens is the contract:
//
//  1. Config.Invitations unset, or a user store without UserPasswordStore,
//     EmailVerificationStore or UserAccountStore, is ErrFeatureNotSupported,
//     before anything is read. An empty address is ErrInvalidInput.
//  2. An account that already holds the address is ErrUserExists — unless
//     Config.InvitationReinvite is on and that account is still pending: no
//     password, no factor, and an invitation outstanding for it. Then the
//     account is reused and AccountCreated is false. Otherwise a new account
//     is created in in.TenantID with no password, an unverified address and
//     in.Role, and in.Metadata is written through the UserMetadataStore when
//     one is configured.
//  3. A token of 256 random bits is minted and the invitation stored under its
//     hash, valid Config.InvitationTTL.
//  4. With a sender configured the invitation is delivered. A failed send
//     undoes the call: the invitation is revoked and an account this call
//     created is deleted, so the same call can simply be repeated. The error
//     joins ErrDeliveryFailed and the sender's.
//  5. On a re-invitation, the invitations it replaces are revoked, so the
//     account has one live token.
//  6. identity.user.invited is raised.
//
// The plaintext token is in the result whatever the configuration: a direct
// caller with no sender delivers it itself. It is never logged.
func (s *Service) InviteUser(ctx context.Context, in InviteUserInput) (InvitationResult, error) {
	store := s.cfg.Invitations
	if store == nil {
		return InvitationResult{}, ErrFeatureNotSupported
	}
	if gap := s.invitationCapabilityGap(); gap != "" {
		return InvitationResult{}, fmt.Errorf("%w: the user store does not implement %s", ErrFeatureNotSupported, gap)
	}
	email := normalizeEmail(in.Email)
	if email == "" {
		return InvitationResult{}, ErrInvalidInput
	}

	now := s.now()
	var (
		user     User
		created  bool
		replaced []Invitation
	)
	existing, err := s.users.GetUserByEmail(ctx, email, in.TenantID)
	if err == nil {
		if !s.cfg.InvitationReinvite || !pendingAccount(existing) {
			return InvitationResult{}, ErrUserExists
		}
		replaced, err = store.PendingInvitationsForUser(ctx, existing.ID)
		if err != nil {
			return InvitationResult{}, fmt.Errorf("auth: invite: read pending invitations: %w", err)
		}
		if len(replaced) == 0 {
			// No password and no invitation: an account some other route made
			// passwordless — OAuth, a magic-link-only account — and not one an
			// invitation reserved. Re-inviting it would hand a password to an
			// account nobody invited.
			return InvitationResult{}, ErrUserExists
		}
		user = existing
	} else {
		user, err = s.createPendingAccount(ctx, email, in, now)
		if err != nil {
			return InvitationResult{}, err
		}
		created = true
	}

	token, err := randomToken(32)
	if err != nil {
		s.discardPendingAccount(ctx, user, created)
		return InvitationResult{}, err
	}
	id, err := newID("inv")
	if err != nil {
		s.discardPendingAccount(ctx, user, created)
		return InvitationResult{}, err
	}
	invitation := Invitation{
		ID:            id,
		TokenHash:     hashToken(token),
		UserID:        user.ID,
		TenantID:      user.TenantID,
		Email:         email,
		Role:          user.Role,
		Metadata:      copyMetadata(in.Metadata),
		InvitedBy:     in.InvitedBy,
		InvitedByKind: in.InvitedByKind,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.invitationTTL()),
	}
	if err := store.CreateInvitation(ctx, invitation); err != nil {
		s.discardPendingAccount(ctx, user, created)
		return InvitationResult{}, fmt.Errorf("auth: invite: store invitation: %w", err)
	}

	if err := s.deliverInvitation(ctx, invitation, token, in.LinkBase, in.Lang); err != nil {
		// Undo, so that a retry of the same call finds nothing in its way: in
		// conflict mode the account would otherwise answer 409 to the retry.
		// The undo is best effort and its own failures are logged — the send
		// failure is what the caller is told about.
		if _, revokeErr := store.RevokeInvitation(ctx, invitation.ID, s.now()); revokeErr != nil {
			s.logf("auth: invite: revoking the undelivered invitation %s failed: %v", invitation.ID, revokeErr)
		}
		s.discardPendingAccount(ctx, user, created)
		return InvitationResult{}, err
	}

	// The tokens this one replaces, retired only now that it has been
	// delivered: a re-invitation whose send failed leaves the earlier token
	// working.
	for _, earlier := range replaced {
		if _, err := store.RevokeInvitation(ctx, earlier.ID, s.now()); err != nil && !errors.Is(err, ErrInvitationNotPending) {
			s.logf("auth: invite: retiring invitation %s, replaced by %s, failed: %v", earlier.ID, invitation.ID, err)
		}
	}

	s.publish(ctx, func() Event {
		return Event{
			Name:     EventUserInvited,
			UserID:   user.ID,
			TenantID: user.TenantID,
			Data: map[string]any{
				"invitationId":   invitation.ID,
				"email":          invitation.Email,
				"invitedBy":      invitation.InvitedBy,
				"invitedByKind":  invitation.InvitedByKind,
				"expiresAt":      invitation.ExpiresAt.UTC().Format(time.RFC3339),
				"accountCreated": created,
			},
		}
	})
	return InvitationResult{Invitation: invitation, User: user, Token: token, AccountCreated: created}, nil
}

// createPendingAccount writes the account an invitation reserves: no password,
// an unverified address, the invited role, and the metadata through the
// metadata store when there is one.
func (s *Service) createPendingAccount(ctx context.Context, email string, in InviteUserInput, now time.Time) (User, error) {
	userID, err := newID("usr")
	if err != nil {
		return User{}, err
	}
	created, err := s.users.CreateUser(ctx, User{
		ID:        userID,
		Email:     email,
		TenantID:  in.TenantID,
		Role:      in.Role,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		if errors.Is(err, ErrUserExists) || errors.Is(err, ErrAlreadyExists) {
			// Created by somebody else between the lookup and the write.
			return User{}, ErrUserExists
		}
		return User{}, fmt.Errorf("auth: invite: create user: %w", err)
	}
	if s.metadata != nil && len(in.Metadata) > 0 {
		if err := s.metadata.UpdateMetadata(ctx, created.ID, copyMetadata(in.Metadata)); err != nil {
			s.discardPendingAccount(ctx, created, true)
			return User{}, fmt.Errorf("auth: invite: write metadata: %w", err)
		}
	}
	return created, nil
}

// discardPendingAccount deletes an account InviteUser created when a later step
// of the same call fails, together with the metadata it wrote. An account the
// call did not create is never touched. Failures are logged and swallowed: the
// caller is reporting the error that caused the undo.
func (s *Service) discardPendingAccount(ctx context.Context, user User, created bool) {
	if !created {
		return
	}
	accounts, ok := s.users.(UserAccountStore)
	if !ok {
		return
	}
	if err := accounts.DeleteUser(ctx, user.ID, user.TenantID); err != nil {
		s.logf("auth: invite: removing the pending account %s failed: %v", user.ID, err)
	}
	if s.metadata != nil {
		if err := s.metadata.ClearMetadata(ctx, user.ID); err != nil {
			s.logf("auth: invite: clearing the metadata of %s failed: %v", user.ID, err)
		}
	}
}

// deliverInvitation is the send step of InviteUser. A nil sender is silence:
// the caller has the token in the result.
func (s *Service) deliverInvitation(ctx context.Context, invitation Invitation, token, linkBase, lang string) error {
	if s.cfg.SendInvitation == nil {
		return nil
	}
	err := s.cfg.SendInvitation(s.senderContext(ctx), InvitationDelivery{
		InvitationID: invitation.ID,
		UserID:       invitation.UserID,
		TenantID:     invitation.TenantID,
		Email:        invitation.Email,
		Role:         invitation.Role,
		Metadata:     copyMetadata(invitation.Metadata),
		Token:        token,
		ExpiresAt:    invitation.ExpiresAt,
		LinkBase:     linkBase,
		Lang:         lang,
	})
	if err != nil {
		return fmt.Errorf("auth: deliver invitation: %w: %w", ErrDeliveryFailed, err)
	}
	return nil
}

// AcceptInvitation redeems an invitation: it spends the token, sets the
// invitee's password, marks the address verified, and answers what comes next.
//
// In order:
//
//  1. Config.Invitations unset is ErrFeatureNotSupported. An empty token or
//     password is ErrInvalidInput; a password shorter than
//     Config.MinPasswordLen is ErrWeakPassword. Neither touches the token, so
//     a rejected password does not cost the invitee the invitation.
//  2. The token is consumed: InvitationStore.ConsumeInvitation by its hash,
//     atomically and once, then the stored hash compared with the presented
//     one in constant time. An unknown, expired, revoked or already accepted
//     token is ErrInvalidInvitation.
//  3. The account is read back. One that is gone, that already has a
//     password or a factor, or whose address is no longer the invited one is
//     ErrInvalidInvitation too — the token is spent either way. Every refusal
//     from here and from step 2 is the same sentinel, so the route answers
//     every one of them alike.
//  4. The password is stored and the address marked verified: the token is
//     proof that the invitee reads the mailbox it was sent to. A host that
//     reveals the token (AdminOptions.RevealInvitationToken) and hands it over
//     some other channel takes that guarantee on itself.
//  5. identity.user.invitation.accepted is raised.
//  6. What the login would do next with this account and this password. When
//     a second factor is demanded of it (Config.Require2FA, the user's own
//     flag) the result carries the login's own challenge (twoFactorChallenge):
//     with no factor to present that is 2FA_SETUP_REQUIRED, whose tempToken is
//     an enrolment token under Config.EnrolOnLogin — so the invitee enrols
//     TOTP through POST <prefix>/2fa/setup and POST <prefix>/2fa/verify-setup
//     before any session exists — and a token no route completes without it,
//     exactly as the login answers. Otherwise it is the registration's
//     answer: a session only when Config.IssueSessionOnRegister allows one
//     (registerIssuesSession), raising identity.auth.login.success with method
//     "local", and none by default — the invitee then logs in.
//
// A failure after step 2 leaves the token spent; the invitee is re-invited.
func (s *Service) AcceptInvitation(ctx context.Context, in AcceptInvitationInput) (InvitationAcceptance, error) {
	store := s.cfg.Invitations
	if store == nil {
		return InvitationAcceptance{}, ErrFeatureNotSupported
	}
	if in.Token == "" || in.Password == "" {
		return InvitationAcceptance{}, ErrInvalidInput
	}
	if len(in.Password) < s.cfg.MinPasswordLen {
		return InvitationAcceptance{}, ErrWeakPassword
	}
	// Checked before the token is spent, for the same reason as the password:
	// a deployment fault must not cost the invitee the invitation. InviteUser
	// refuses such a store, so this is a store swapped since.
	passwords, ok := s.users.(UserPasswordStore)
	if !ok {
		return InvitationAcceptance{}, ErrFeatureNotSupported
	}
	verification, ok := s.users.(EmailVerificationStore)
	if !ok {
		return InvitationAcceptance{}, ErrFeatureNotSupported
	}

	presented := hashToken(in.Token)
	invitation, err := store.ConsumeInvitation(ctx, presented, s.now())
	switch {
	case errors.Is(err, ErrInvitationNotFound):
		return InvitationAcceptance{}, ErrInvalidInvitation
	case err != nil:
		return InvitationAcceptance{}, fmt.Errorf("auth: accept invitation: %w", err)
	}
	// The store found the record by this hash; comparing it again is the
	// defence against a store that answers with the wrong row, and it is done
	// in constant time so that the comparison says nothing about how much of a
	// guess was right.
	if !secureEqual(invitation.TokenHash, presented) {
		return InvitationAcceptance{}, ErrInvalidInvitation
	}

	user, err := s.users.GetUserByID(ctx, invitation.UserID, invitation.TenantID)
	switch {
	case errors.Is(err, ErrUserNotFound):
		return InvitationAcceptance{}, ErrInvalidInvitation
	case err != nil:
		return InvitationAcceptance{}, fmt.Errorf("auth: accept invitation: read user: %w", err)
	}
	if !pendingAccount(user) || normalizeEmail(user.Email) != invitation.Email {
		return InvitationAcceptance{}, ErrInvalidInvitation
	}

	pwHash, err := hashPassword(in.Password, s.cfg.BcryptCost)
	if err != nil {
		return InvitationAcceptance{}, err
	}
	if err := passwords.UpdatePassword(ctx, user.ID, user.TenantID, pwHash); err != nil {
		return InvitationAcceptance{}, fmt.Errorf("auth: accept invitation: set password: %w", err)
	}
	if !user.IsEmailVerified {
		if err := verification.MarkEmailVerified(ctx, user.ID, user.TenantID, true); err != nil {
			return InvitationAcceptance{}, fmt.Errorf("auth: accept invitation: verify address: %w", err)
		}
	}
	// The row as it now is. The enrolment token a challenge carries is bound
	// to the stored password hash (its cred claim), so it has to be minted
	// from the hash just written, not from the passwordless row read above.
	user.PasswordHash = pwHash
	user.IsEmailVerified = true

	s.publish(ctx, func() Event {
		return Event{
			Name:     EventUserInvitationAccepted,
			UserID:   user.ID,
			TenantID: user.TenantID,
			Data:     map[string]any{"invitationId": invitation.ID},
		}
	})

	result := InvitationAcceptance{User: user, Invitation: invitation}
	if s.requiresTwoFactor(user) {
		challenge, err := s.twoFactorChallenge(ctx, user)
		if err != nil {
			return InvitationAcceptance{}, err
		}
		result.Challenge = challenge
		return result, nil
	}
	if s.registerIssuesSession(user) {
		tokens, err := s.completeLocalLogin(ctx, user)
		if err != nil {
			return InvitationAcceptance{}, err
		}
		result.Tokens = tokens
	}
	return result, nil
}

// RevokeInvitation revokes a pending invitation — expired or not — and deletes
// the account it reserved if nothing has used that account since the
// invitation created it (untouchedAccount): no password, no factor, the
// address still unverified, no phone and no login provider on the row, no
// session ever opened for it, and no other invitation outstanding. An account
// somebody has signed in to — a magic link to the invited mailbox, a password
// reset, a linked provider — is kept, and AccountRemoved says so; deleting it
// is then an administrator's explicit DELETE <admin>/api/users/{id}.
//
// An unknown id is ErrInvitationNotFound; an invitation already accepted or
// revoked is ErrInvitationNotPending, with the record. revokedBy and
// revokedByKind are the audit, as InviteUserInput's InvitedBy pair is, and
// ride on identity.user.invitation.revoked.
//
// The Service sees the user store and the session store; Auth.RevokeInvitation
// — which the admin route calls — also asks the OAuth wiring's linked accounts,
// which only the Auth holds.
func (s *Service) RevokeInvitation(ctx context.Context, id, revokedBy, revokedByKind string) (InvitationRevocation, error) {
	return s.revokeInvitation(ctx, id, revokedBy, revokedByKind, nil)
}

// accountInUse is evidence of use a caller holds and the Service does not: the
// Auth's linked accounts. An error counts as use, so the account is kept.
type accountInUse func(ctx context.Context, user User) (bool, error)

func (s *Service) revokeInvitation(ctx context.Context, id, revokedBy, revokedByKind string, inUse accountInUse) (InvitationRevocation, error) {
	store := s.cfg.Invitations
	if store == nil {
		return InvitationRevocation{}, ErrFeatureNotSupported
	}
	invitation, err := store.RevokeInvitation(ctx, id, s.now())
	if err != nil {
		return InvitationRevocation{Invitation: invitation}, err
	}
	removed := s.removeReservedAccount(ctx, invitation, inUse)
	s.publish(ctx, func() Event {
		return Event{
			Name:     EventUserInvitationRevoked,
			UserID:   invitation.UserID,
			TenantID: invitation.TenantID,
			Data: map[string]any{
				"invitationId":   invitation.ID,
				"revokedBy":      revokedBy,
				"revokedByKind":  revokedByKind,
				"accountRemoved": removed,
			},
		}
	})
	return InvitationRevocation{Invitation: invitation, AccountRemoved: removed}, nil
}

// removeReservedAccount deletes the account a revoked invitation reserved,
// when nothing has used it and nothing else holds it. Every failure, and every
// question it cannot answer, leaves the account in place and is logged: the
// revocation itself has already happened, and the token is dead either way.
func (s *Service) removeReservedAccount(ctx context.Context, invitation Invitation, inUse accountInUse) bool {
	accounts, ok := s.users.(UserAccountStore)
	if !ok {
		return false
	}
	user, err := s.users.GetUserByID(ctx, invitation.UserID, invitation.TenantID)
	if err != nil {
		return false
	}
	untouched, err := s.untouchedAccount(ctx, user, inUse)
	if err != nil {
		s.logf("auth: revoke invitation %s: could not tell whether account %s has been used; it is kept: %v", invitation.ID, user.ID, err)
		return false
	}
	if !untouched {
		return false
	}
	others, err := s.cfg.Invitations.PendingInvitationsForUser(ctx, user.ID)
	if err != nil {
		s.logf("auth: revoke invitation %s: reading the account's other invitations failed; the account is kept: %v", invitation.ID, err)
		return false
	}
	if len(others) > 0 {
		return false
	}
	if err := accounts.DeleteUser(ctx, user.ID, user.TenantID); err != nil {
		s.logf("auth: revoke invitation %s: removing the pending account %s failed: %v", invitation.ID, user.ID, err)
		return false
	}
	if s.metadata != nil {
		if err := s.metadata.ClearMetadata(ctx, user.ID); err != nil {
			s.logf("auth: revoke invitation %s: clearing the metadata of %s failed: %v", invitation.ID, user.ID, err)
		}
	}
	return true
}

// untouchedAccount reports whether user is still the account an invitation
// created and nothing else: the only kind a revocation may delete.
//
// It is stricter than pendingAccount, which is what an acceptance asks — "can
// a first password still be set?" — because an account with no password can
// still be in use. A magic link to the invited mailbox signs it in and marks
// the address verified; an OAuth link leaves a linked account and a session;
// an SMS login needs a phone on the row. So, beyond no password and no factor:
// the address is still unverified, the row has no phone and no login
// provider, the session store — when it can list a user's sessions — holds
// none for it, live or revoked, and inUse, when given, finds nothing. A store
// that cannot list sessions leaves that question to the row's own markers.
func (s *Service) untouchedAccount(ctx context.Context, user User, inUse accountInUse) (bool, error) {
	if !pendingAccount(user) || user.IsEmailVerified || user.PhoneNumber != "" || user.LoginProvider != "" {
		return false, nil
	}
	if admin, ok := s.sessions.(SessionAdminStore); ok {
		sessions, err := admin.ListSessionsForUser(ctx, user.ID, user.TenantID)
		if err != nil {
			return false, err
		}
		if len(sessions) > 0 {
			return false, nil
		}
	}
	if inUse != nil {
		used, err := inUse(ctx, user)
		if err != nil || used {
			return false, err
		}
	}
	return true, nil
}

// accountHasLinkedProvider is the Auth's evidence of use: an OAuth identity
// linked to the account, which /link-verify writes without touching the row.
func (a *Auth) accountHasLinkedProvider(ctx context.Context, user User) (bool, error) {
	if a.oauth == nil || a.oauth.LinkedAccounts == nil {
		return false, nil
	}
	links, err := a.oauth.LinkedAccounts.ListForUser(ctx, user.ID)
	if err != nil {
		return false, err
	}
	return len(links) > 0, nil
}

// ListPendingInvitations pages the invitations that are neither accepted nor
// revoked, expired ones included, in ID order — InvitationStore's paging rules.
// The records carry TokenHash; the admin route never serialises it.
func (s *Service) ListPendingInvitations(ctx context.Context, limit, offset int) ([]Invitation, error) {
	store := s.cfg.Invitations
	if store == nil {
		return nil, ErrFeatureNotSupported
	}
	return store.ListPendingInvitations(ctx, limit, offset)
}

// copyMetadata is a shallow copy, so that a record, a delivery and the caller's
// map never share one.
func copyMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}
	out := make(map[string]any, len(metadata))
	for k, v := range metadata {
		out[k] = v
	}
	return out
}

// InvitationAcceptHTTPError maps a Service.AcceptInvitation failure. Every
// refusal of the token is HTTPErrInvalidInvitation; a missing field is
// HTTPErrInvitationInputRequired and a short password the WEAK_PASSWORD every
// other route answers; a store without the capability the flow needs, and
// every other failure, the generic 500.
func InvitationAcceptHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrInvalidInvitation):
		return HTTPErrInvalidInvitation
	case errors.Is(err, ErrInvalidInput):
		return HTTPErrInvitationInputRequired
	case errors.Is(err, ErrWeakPassword):
		return HTTPErrWeakPassword
	default:
		return HTTPErrInternal
	}
}

// WriteInvitationAcceptance writes the answer to a successful POST
// <prefix>/invitations/accept, the one body the four adapters share for it:
// the login's challenge when the acceptance carries one (WriteTwoFactorChallenge,
// no cookie on either branch), and otherwise the registration's answer
// (WriteRegistration) — 201 {"success":true,"userId":…}, with the session in
// cookies or in the body when one was opened.
func (c HTTPConfig) WriteInvitationAcceptance(w http.ResponseWriter, r *http.Request, acceptance InvitationAcceptance) {
	if acceptance.Challenge != nil {
		WriteTwoFactorChallenge(w, *acceptance.Challenge)
		return
	}
	c.WriteRegistration(w, r, acceptance.User.ID, acceptance.Tokens)
}

// InvitationsEnabled reports Config.Invitations. The adapters mount POST
// <prefix>/invitations/accept on it, outside ClosedRegistration and inside
// ResourceServer's gate, and the admin router registers its three invitation
// routes on it.
func (a *Auth) InvitationsEnabled() bool { return a.service.InvitationsEnabled() }

// InviteUser delegates to Service.InviteUser.
func (a *Auth) InviteUser(ctx context.Context, in InviteUserInput) (InvitationResult, error) {
	return a.service.InviteUser(ctx, in)
}

// AcceptInvitation delegates to Service.AcceptInvitation.
func (a *Auth) AcceptInvitation(ctx context.Context, in AcceptInvitationInput) (InvitationAcceptance, error) {
	return a.service.AcceptInvitation(ctx, in)
}

// RevokeInvitation is Service.RevokeInvitation with one more piece of evidence
// that the account has been used: an OAuth identity linked to it, which the
// Auth's wiring holds and the Service does not. The admin route calls this.
func (a *Auth) RevokeInvitation(ctx context.Context, id, revokedBy, revokedByKind string) (InvitationRevocation, error) {
	return a.service.revokeInvitation(ctx, id, revokedBy, revokedByKind, a.accountHasLinkedProvider)
}

// ListPendingInvitations delegates to Service.ListPendingInvitations.
func (a *Auth) ListPendingInvitations(ctx context.Context, limit, offset int) ([]Invitation, error) {
	return a.service.ListPendingInvitations(ctx, limit, offset)
}
