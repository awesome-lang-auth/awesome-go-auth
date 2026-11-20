package auth

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// This file is the declarative half of Config.BuildTokenClaims: three
// constructors that build the hook out of a static map, a field mapping and a
// chain of other hooks, so a deployment whose claims are configuration rather
// than code does not have to write the closure by hand. The consumer's
// security.jwt.extraClaims knob — {claimName: {fromUserField: x} | {const: y}}
// (config-schema.md §1.1, §3.1) — decodes onto UserFieldClaims and StaticClaims
// joined by ChainClaims; its claimsWebhook knob is ClaimsWebhook, next door.
//
// None of this has a reference counterpart. awesome-node-auth has exactly one
// mechanism, the in-process config.buildTokenPayload(user) function
// (auth-config.model.ts:316), and the only behaviour it fixes is the merge: the
// function's result is spread over the six base claims (auth.router.ts:378-384),
// which issueToken already honours for any hook. The helpers are this port's
// own extension (upstream plan, PR 2.3) and produce nothing a hand-written hook
// could not: a token minted through them is indistinguishable on the wire from
// one minted through the closure they replace.

// TokenClaimsBuilder is the type of Config.BuildTokenClaims and of the hook
// WithTokenClaimsBuilder accepts: given the user a token is being minted for,
// it returns the claims to spread over the six base claims. It is an alias, not
// a distinct type, so a plain func literal satisfies both exactly as it did
// before the name existed.
//
// The result may override sub, email, role, loginProvider, isEmailVerified and
// isTotpEnabled; the session claims sid, tid, jti, typ, iss, iat and exp are
// reserved — written after the merge — and so are amr, auth_time and mfa_at,
// which come from the session alone; none can be set from any builder (see
// mintToken). A builder error fails the mint: the login, refresh or step-up
// that needed the token answers 500 rather than issuing a token carrying fewer
// claims than the deployment configured.
type TokenClaimsBuilder = func(ctx context.Context, user User) (map[string]any, error)

// StaticClaims returns a builder that adds the same claims to every token: the
// {const: <value>} form of the consumer's extraClaims table.
//
// The map is copied on construction and again on every call, so neither a
// caller that goes on mutating the map it passed in nor one that edits a
// returned result can change what the next token carries. A nil or empty map
// is a builder that adds nothing.
//
// StaticClaims has no error to return, so it cannot refuse a reserved session
// claim name the way UserFieldClaims does: an entry named sid, tid, jti, typ,
// iss, iat, exp, amr, auth_time or mfa_at is discarded by mintToken on every
// mint, exactly as the same name from a hand-written hook is. A deployment that decodes the
// {const: ...} table should check the names before building.
func StaticClaims(claims map[string]any) TokenClaimsBuilder {
	frozen := copyClaims(claims)
	return func(context.Context, User) (map[string]any, error) {
		return copyClaims(frozen), nil
	}
}

// UserFieldClaims returns a builder that copies fields of the User into named
// claims: the {fromUserField: <field>} form of the consumer's extraClaims
// table. fields maps each claim name to the User field it reads, spelled as
// the field is on GET /me:
//
//	id, email, role, tenantId, firstName, lastName, phoneNumber,
//	isEmailVerified, isTotpEnabled, loginProvider
//
// A field name outside that list, or an empty claim name, is an error from this
// constructor and never from a mint: a mapping is configuration, and a typo in
// configuration should fail at startup rather than turn every login into a
// 500. So is a claim name that is one of the reserved session claims — sid,
// tid, jti, typ, iss, iat, exp: issueToken writes those after the merge, so
// such a mapping would never reach a token, and a mapping that can never reach
// a token is a configuration error rather than a claim. The six base claims
// (sub, email, role, loginProvider, isEmailVerified, isTotpEnabled) are not
// reserved and may be mapped over, as the reference allows. loginProvider
// reads as LoginProviderLocal when the user has none recorded, as the base
// claim and /me do.
//
// Every mapped claim is emitted on every token with whatever the field holds:
// an empty firstName becomes an empty-string claim, not an absent one. A
// mapping declares that a claim exists; making its presence depend on the
// value would leave a consumer unable to tell "not configured" from "empty".
func UserFieldClaims(fields map[string]string) (TokenClaimsBuilder, error) {
	readers := make(map[string]func(User) any, len(fields))
	for claim, field := range fields {
		if strings.TrimSpace(claim) == "" {
			return nil, fmt.Errorf("auth: user field claims: empty claim name for user field %q", field)
		}
		if isReservedClaim(claim) {
			return nil, fmt.Errorf("auth: user field claims: claim %q is a reserved session claim (%s) and would be discarded on every mint; choose another name",
				claim, strings.Join(reservedClaimNames, ", "))
		}
		read, ok := userClaimFields[field]
		if !ok {
			return nil, fmt.Errorf("auth: user field claims: claim %q reads unknown user field %q; want one of %s",
				claim, field, strings.Join(userClaimFieldNames(), ", "))
		}
		readers[claim] = read
	}
	return func(_ context.Context, user User) (map[string]any, error) {
		claims := make(map[string]any, len(readers))
		for claim, read := range readers {
			claims[claim] = read(user)
		}
		return claims, nil
	}, nil
}

// userClaimFields is the allowlist UserFieldClaims reads from, keyed by the
// name each field has on GET /me (PublicUser's JSON tags). The credential
// columns are deliberately absent — PasswordHash, TOTPSecret and the one-time
// token hashes have no business in a token — and so are the enriched
// collections (metadata, roles, permissions, tenants): a mint sees the stored
// row, which the optional stores have not filled, and a collection is not a
// claim value.
var userClaimFields = map[string]func(User) any{
	"id":              func(u User) any { return u.ID },
	"email":           func(u User) any { return u.Email },
	"role":            func(u User) any { return u.Role },
	"tenantId":        func(u User) any { return u.TenantID },
	"firstName":       func(u User) any { return u.FirstName },
	"lastName":        func(u User) any { return u.LastName },
	"phoneNumber":     func(u User) any { return u.PhoneNumber },
	"isEmailVerified": func(u User) any { return u.IsEmailVerified },
	"isTotpEnabled":   func(u User) any { return u.IsTOTPEnabled },
	"loginProvider":   func(u User) any { return u.loginProviderOrLocal() },
}

// userClaimFieldNames lists the allowlist in a stable order, for error text.
func userClaimFieldNames() []string {
	names := make([]string, 0, len(userClaimFields))
	for name := range userClaimFields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ChainClaims returns a builder that runs builders in order and merges their
// results, later ones winning on a shared claim name — so a StaticClaims placed
// after a UserFieldClaims overrides it, and a hand-written hook placed last has
// the final say. The first error stops the chain and is returned as it is; the
// builders after it do not run. Nil builders are skipped, and a chain of none
// adds nothing.
func ChainClaims(builders ...TokenClaimsBuilder) TokenClaimsBuilder {
	return func(ctx context.Context, user User) (map[string]any, error) {
		merged := map[string]any{}
		for _, build := range builders {
			if build == nil {
				continue
			}
			claims, err := build(ctx, user)
			if err != nil {
				return nil, err
			}
			for name, value := range claims {
				merged[name] = value
			}
		}
		return merged, nil
	}
}

// copyClaims returns a shallow copy of claims; nil in, empty map out.
func copyClaims(claims map[string]any) map[string]any {
	out := make(map[string]any, len(claims))
	for name, value := range claims {
		out[name] = value
	}
	return out
}
