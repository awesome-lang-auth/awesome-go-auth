package auth

import (
	"fmt"
	"sort"
	"strings"
)

// This file is the provisioning policy the OAuth callback applies: what happens
// when the provider has authenticated somebody the deployment has no account
// for, or has an account for under a different provider.
//
// The reference defines none of it. GenericOAuthStrategy.findOrCreateUser is
// abstract (generic-oauth.strategy.ts:169-172, google.strategy.ts:67,
// github.strategy.ts:78): the integrator writes the function, and the library
// only knows two outcomes — a user, which handleOAuthLogin turns into a session
// (auth.router.ts:1298-1317), or an AuthError coded OAUTH_ACCOUNT_CONFLICT,
// which the callback stashes and redirects to /account-conflict
// (auth.router.ts:1346-1355). This port cannot ask for that function: its
// consumer configures the library from a file rather than subclassing it, so
// the policy is declarative here and OAuthProvisioning is the whole vocabulary
// a findOrCreateUser would have had. The conflict outcome is the reference's
// and reaches the wire exactly as the reference sends it; the refusals are this
// port's own and are registered in compatibility.go.
//
// The defaults are the findOrCreateUser the reference documents for its
// integrators (README.detailed.md "OAuth Strategies", at 1.10.8): an existing
// (provider, providerAccountId) link signs in, an address some other account
// already holds raises OAUTH_ACCOUNT_CONFLICT, and anything else is created.
// The reference's own words are that two accounts must never be linked just
// because they share an address — two providers can assert the same address
// without representing the same person (user-store.interface.ts:105-119) — so
// the conflict flow, where the link is made only once the address has been
// proven by mail, is what a deployment that configures nothing gets. Linking by
// address is still available, as OnEmailMatch link, for a host that chooses it.
//
// Through 0.12.0 the default was link, which signed a provider account into
// whatever account held the address it asserted, verified or not (issue #36).

// The three OnEmailMatch modes.
const (
	// OAuthEmailMatchLink links the provider account to the account that
	// already holds the address and signs that account in. It is an explicit
	// opt-in, and it trusts the provider's address as far as the rest of the
	// policy does: on its own it links an address the provider never verified,
	// which against a provider that lets a user type any address (GitHub's
	// public profile email, many self-hosted OIDC servers) hands the existing
	// account to whoever registered that address there. A host that wants it
	// should pair it with RequireVerifiedEmail, which refuses every callback
	// whose provider did not assert the address — creation and existing links
	// included, not only this branch.
	OAuthEmailMatchLink = "link"
	// OAuthEmailMatchConflict refuses to link and raises the reference's
	// OAUTH_ACCOUNT_CONFLICT: the callback stashes (email, provider,
	// providerAccountId) and redirects the browser to /account-conflict, where
	// the front-end drives /link-request and /link-verify so the link is made
	// only after the address has been proven by mail. It is the default, and
	// what an empty OnEmailMatch means.
	//
	// Without OAuthWiring.PendingLinks the redirect is still sent but nothing is
	// stashed, exactly as the reference behaves without a pendingLinkStore, and
	// an unauthenticated /link-request then has no identity to resolve.
	OAuthEmailMatchConflict = "conflict"
	// OAuthEmailMatchReject refuses outright, with no linking flow offered:
	// 403 OAUTH_USER_NOT_PROVISIONED, the same answer AutoCreate false gives,
	// because both mean the deployment will not provision this identity.
	OAuthEmailMatchReject = "reject"
)

// OAuthProvisioning is the declarative replacement for the abstract
// findOrCreateUser the reference makes every integrator write
// (generic-oauth.strategy.ts:169-172). It governs the whole callback, not only
// the create branch: RequireVerifiedEmail and AllowedEmailDomains are checked
// before the identity is resolved at all, exactly as a findOrCreateUser that
// began with those checks would.
//
// The zero value is not the default policy — DefaultOAuthProvisioning is, and
// OAuthWiring.Provisioning is a pointer so that a deployment which sets nothing
// gets it, account creation included. A policy given explicitly is taken as
// written: AutoCreate false means false. The one field whose empty value still
// means a default is OnEmailMatch, which has no empty mode: "" is
// OAuthEmailMatchConflict, the safe answer, so a policy built field by field
// that forgets OnEmailMatch never links by address.
type OAuthProvisioning struct {
	// AutoCreate allows the callback to create an account for a provider
	// identity nothing here knows yet. With it false the callback answers
	// 403 OAUTH_USER_NOT_PROVISIONED instead, so accounts can only be made by
	// some other path (an invitation, an admin, /register).
	AutoCreate bool
	// AllowedEmailDomains restricts which addresses may sign in through any
	// provider. Empty allows every address. An entry is a bare domain —
	// "example.com", or "@example.com", which is accepted and normalised —
	// matched case-insensitively against the part of the profile address after
	// the last @, with no subdomain matching: "example.com" does not admit
	// "mail.example.com". A profile with no address at all is refused whenever
	// the list is non-empty, because nothing about it can be checked.
	AllowedEmailDomains []string
	// RequireVerifiedEmail demands that the provider actually asserted the
	// address. A profile whose emailVerified is false — and one where the
	// provider said nothing, which is most of them — is refused with
	// 403 OAUTH_EMAIL_NOT_VERIFIED. It is off by default: turning it on for a
	// provider that does not send the claim refuses every login through it.
	RequireVerifiedEmail bool
	// OnEmailMatch decides what happens when the provider account is unknown
	// but some account already holds the profile address:
	// OAuthEmailMatchConflict (the default, and what "" means),
	// OAuthEmailMatchLink or OAuthEmailMatchReject. Link applies no check of its
	// own on whether the provider verified the address; see OAuthEmailMatchLink.
	OnEmailMatch string
	// FieldMap fills further User fields from the raw provider profile when the
	// callback creates an account. The keys are the fields it may write —
	// firstName, lastName, phoneNumber and role — and the values are
	// expressions in the ProfileMap grammar, evaluated against the same
	// userinfo document (see CompileProfileMap): "$.given_name",
	// "$.name.first ?? $.given_name", "$.roles[0]", or a quoted literal as the
	// last resort. A key outside that list, or a value that does not compile,
	// is refused by Validate and therefore by WithOAuth, so a typo in
	// configuration fails at start-up rather than at the first login. An
	// expression that resolves to nothing leaves its field alone; one that
	// resolves to an object or an array fails the callback.
	//
	// The fields the profile itself owns are deliberately not targets: id and
	// email come from OAuthUserInfo (map them with ProfileMap), tenantId comes
	// from the wiring, loginProvider is the provider, and isEmailVerified is
	// this policy's business rather than a mapping's.
	FieldMap map[string]string
}

// DefaultOAuthProvisioning is the policy a wiring without one gets: create
// missing accounts, and answer an address another account already holds with
// the reference's OAUTH_ACCOUNT_CONFLICT rather than linking it — the
// findOrCreateUser the reference documents (README.detailed.md "OAuth
// Strategies"). Through 0.12.0 it linked the address instead (issue #36); a
// host that relied on that sets OnEmailMatch: OAuthEmailMatchLink explicitly.
func DefaultOAuthProvisioning() OAuthProvisioning {
	return OAuthProvisioning{AutoCreate: true, OnEmailMatch: OAuthEmailMatchConflict}
}

// Validate reports what is wrong with a policy loaded from configuration: an
// unknown OnEmailMatch mode, an empty or malformed domain entry, a FieldMap
// key that is not a field this policy may write, or a FieldMap expression that
// does not compile. WithOAuth runs it, so a deployment that wires an invalid
// policy fails at construction; it is exported so one can check a policy before
// wiring anything, as CompileProfileMap can be.
func (p OAuthProvisioning) Validate() error {
	switch p.OnEmailMatch {
	case "", OAuthEmailMatchLink, OAuthEmailMatchConflict, OAuthEmailMatchReject:
	default:
		return fmt.Errorf("auth: oauth provisioning: unknown OnEmailMatch %q (want %s, %s or %s)",
			p.OnEmailMatch, OAuthEmailMatchLink, OAuthEmailMatchConflict, OAuthEmailMatchReject)
	}
	for _, domain := range p.AllowedEmailDomains {
		if normalizeEmailDomain(domain) == "" {
			return fmt.Errorf("auth: oauth provisioning: empty entry in AllowedEmailDomains")
		}
	}
	_, err := compileUserFieldMap(p.FieldMap)
	return err
}

// normalized fills the defaults an empty field stands for. Only OnEmailMatch
// has one, and it is the conflict, so that leaving the mode out can never
// enable linking by address: every other field means what it says.
func (p OAuthProvisioning) normalized() OAuthProvisioning {
	if p.OnEmailMatch == "" {
		p.OnEmailMatch = OAuthEmailMatchConflict
	}
	return p
}

// admit is the pair of checks that gate the whole callback, in this order:
// the provider has to have asserted the address, and the address has to be in
// a domain the deployment admits. Both are refusals with no reference
// counterpart (compatibility.go), and both are off by default.
func (p OAuthProvisioning) admit(info OAuthUserInfo) error {
	if p.RequireVerifiedEmail && (info.EmailVerified == nil || !*info.EmailVerified) {
		return errOAuthEmailNotVerified
	}
	if !emailDomainAllowed(info.Email, p.AllowedEmailDomains) {
		return errOAuthEmailDomainNotAllowed
	}
	return nil
}

// emailVerifiedOnCreate is decision D-11: an account the callback creates is
// verified unless the provider said otherwise. Silence is the common case —
// GitHub sends no claim for a public address, and so does any provider without
// an OpenID Connect userinfo — and treating silence as unverified would lock
// every such account out of a deployment that gates login on verification,
// where this port has always marked them verified. A provider that positively
// says false is believed.
func emailVerifiedOnCreate(info OAuthUserInfo) bool {
	return info.EmailVerified == nil || *info.EmailVerified
}

// normalizeEmailDomain renders one AllowedEmailDomains entry: trimmed,
// lower-cased, with a leading @ dropped so both spellings work.
func normalizeEmailDomain(domain string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "@")
}

// emailDomainAllowed matches the address against the allowlist. An empty list
// allows everything, including an address the provider never gave; a non-empty
// one refuses anything it cannot read a domain from.
func emailDomainAllowed(email string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	got := strings.ToLower(strings.TrimSpace(email[at+1:]))
	for _, domain := range domains {
		if normalized := normalizeEmailDomain(domain); normalized != "" && normalized == got {
			return true
		}
	}
	return false
}

// userFieldMapTargets is the allowlist FieldMap may write, keyed by the name
// each field has on GET /me (PublicUser's JSON tags), as UserFieldClaims keys
// its own allowlist. All four are strings, so a mapped value is rendered the
// way the ProfileMap grammar renders any scalar.
var userFieldMapTargets = map[string]func(*User, string){
	"firstName":   func(u *User, v string) { u.FirstName = v },
	"lastName":    func(u *User, v string) { u.LastName = v },
	"phoneNumber": func(u *User, v string) { u.PhoneNumber = v },
	"role":        func(u *User, v string) { u.Role = v },
}

// userFieldMapTargetNames lists the allowlist in a stable order, for error text.
func userFieldMapTargetNames() []string {
	names := make([]string, 0, len(userFieldMapTargets))
	for name := range userFieldMapTargets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// userFieldSetter is one compiled FieldMap entry.
type userFieldSetter struct {
	field string
	expr  profileExpr
	set   func(*User, string)
}

// compileUserFieldMap compiles a FieldMap into the setters the create branch
// runs, in a stable field order so two runs over the same document produce the
// same user. A nil or empty map compiles to no setters.
func compileUserFieldMap(m map[string]string) ([]userFieldSetter, error) {
	fields := make([]string, 0, len(m))
	for field := range m {
		fields = append(fields, field)
	}
	sort.Strings(fields)

	setters := make([]userFieldSetter, 0, len(fields))
	for _, field := range fields {
		set, ok := userFieldMapTargets[field]
		if !ok {
			return nil, fmt.Errorf("auth: oauth provisioning: field map: unknown target %q (want one of %s)",
				field, strings.Join(userFieldMapTargetNames(), ", "))
		}
		expr, err := compileProfileExpr(m[field])
		if err != nil {
			return nil, fmt.Errorf("auth: oauth provisioning: field map: %s: %w", field, err)
		}
		setters = append(setters, userFieldSetter{field: field, expr: expr, set: set})
	}
	return setters, nil
}

// applyUserFieldMap writes the mapped fields onto the user being created. A
// field whose expression resolves to nothing is left alone — the mapping says
// where a value would come from, not that the provider must send one — while a
// value that has no scalar form fails the creation rather than being coerced.
func applyUserFieldMap(setters []userFieldSetter, raw map[string]any, user *User) error {
	for _, setter := range setters {
		value, found := setter.expr.eval(raw)
		if !found {
			continue
		}
		text, err := profileString(value)
		if err != nil {
			return fmt.Errorf("auth: oauth provisioning: field map: %s: %v in %q", setter.field, err, setter.expr.source)
		}
		setter.set(user, text)
	}
	return nil
}
