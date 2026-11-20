package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestStaticClaims_ReturnsTheClaimsFromACopy(t *testing.T) {
	input := map[string]any{"plan": "pro", "seats": 3}
	build := StaticClaims(input)
	// Neither mutating the input after construction nor editing a result may
	// change what the next token carries.
	input["plan"] = "mutated after construction"
	input["extra"] = true

	first, err := build(context.Background(), User{ID: "usr_1"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if first["plan"] != "pro" || first["seats"] != 3 || len(first) != 2 {
		t.Fatalf("claims = %+v, want the map as it was at construction", first)
	}
	first["plan"] = "mutated result"
	delete(first, "seats")

	second, err := build(context.Background(), User{ID: "usr_2"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if second["plan"] != "pro" || second["seats"] != 3 || len(second) != 2 {
		t.Fatalf("second call = %+v, want the same claims as the first", second)
	}
}

func TestStaticClaims_NilAddsNothing(t *testing.T) {
	claims, err := StaticClaims(nil)(context.Background(), User{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if claims == nil || len(claims) != 0 {
		t.Fatalf("claims = %#v, want an empty, non-nil map", claims)
	}
}

func TestUserFieldClaims_ReadsEveryAllowlistedField(t *testing.T) {
	user := User{
		ID: "usr_42", Email: "field@example.com", Role: "admin", TenantID: "t1",
		FirstName: "Ada", LastName: "Lovelace", PhoneNumber: "+391234567",
		IsEmailVerified: true, IsTOTPEnabled: true, LoginProvider: "github",
		// Credential material sits on the same struct; nothing below is
		// reachable through the allowlist, which the unknown-field test pins.
		PasswordHash: "hash-value", TOTPSecret: "totp-value",
	}
	fields := map[string]string{}
	for _, name := range userClaimFieldNames() {
		fields["u_"+name] = name
	}
	build, err := UserFieldClaims(fields)
	if err != nil {
		t.Fatalf("UserFieldClaims: %v", err)
	}
	claims, err := build(context.Background(), user)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := map[string]any{
		"u_id": "usr_42", "u_email": "field@example.com", "u_role": "admin", "u_tenantId": "t1",
		"u_firstName": "Ada", "u_lastName": "Lovelace", "u_phoneNumber": "+391234567",
		"u_isEmailVerified": true, "u_isTotpEnabled": true, "u_loginProvider": "github",
	}
	if len(claims) != len(want) {
		t.Fatalf("claims = %+v, want %+v", claims, want)
	}
	for name, value := range want {
		if claims[name] != value {
			t.Errorf("%s = %#v, want %#v", name, claims[name], value)
		}
	}
	// The allowlist is exactly the ten documented names, spelled as /me does.
	const documented = "email,firstName,id,isEmailVerified,isTotpEnabled,lastName,loginProvider,phoneNumber,role,tenantId"
	if got := strings.Join(userClaimFieldNames(), ","); got != documented {
		t.Fatalf("allowlist = %s, want %s (update the UserFieldClaims doc comment too)", got, documented)
	}
}

func TestUserFieldClaims_LoginProviderReadsLocalWhenUnset(t *testing.T) {
	build, err := UserFieldClaims(map[string]string{"provider": "loginProvider"})
	if err != nil {
		t.Fatalf("UserFieldClaims: %v", err)
	}
	claims, err := build(context.Background(), User{ID: "usr_1"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if claims["provider"] != LoginProviderLocal {
		t.Fatalf("provider = %#v, want %q", claims["provider"], LoginProviderLocal)
	}
}

func TestUserFieldClaims_EmptyFieldIsAnEmptyClaim(t *testing.T) {
	build, err := UserFieldClaims(map[string]string{"given": "firstName"})
	if err != nil {
		t.Fatalf("UserFieldClaims: %v", err)
	}
	claims, err := build(context.Background(), User{ID: "usr_1"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	value, present := claims["given"]
	if !present || value != "" {
		t.Fatalf("given = %#v (present %v), want an empty-string claim, not an absent one", value, present)
	}
}

func TestUserFieldClaims_RejectsUnknownFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields map[string]string
	}{
		{"credential column", map[string]string{"secret": "passwordHash"}},
		{"Go spelling of a credential", map[string]string{"secret": "PasswordHash"}},
		{"totp secret", map[string]string{"secret": "totpSecret"}},
		{"Go spelling of an allowed field", map[string]string{"mail": "Email"}},
		{"enriched collection", map[string]string{"roles": "roles"}},
		{"empty field", map[string]string{"x": ""}},
		{"one bad among good", map[string]string{"mail": "email", "nope": "nothing"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build, err := UserFieldClaims(tc.fields)
			if err == nil {
				t.Fatalf("UserFieldClaims(%v) accepted an unknown field", tc.fields)
			}
			if build != nil {
				t.Fatalf("a failed constructor returned a builder")
			}
			// The message names the offending field and lists the allowlist,
			// so a startup failure is fixable from the log line alone.
			for _, field := range tc.fields {
				if !strings.Contains(err.Error(), "tenantId") {
					t.Fatalf("error %q does not list the allowed fields", err)
				}
				if _, allowed := userClaimFields[field]; !allowed && !strings.Contains(err.Error(), `"`+field+`"`) {
					t.Fatalf("error %q does not name the unknown field %q", err, field)
				}
			}
		})
	}
}

func TestUserFieldClaims_RejectsEmptyClaimNames(t *testing.T) {
	for _, claim := range []string{"", "   "} {
		if _, err := UserFieldClaims(map[string]string{claim: "email"}); err == nil {
			t.Fatalf("UserFieldClaims accepted the claim name %q", claim)
		}
	}
}

// TestUserFieldClaims_RejectsReservedClaimNames: a mapping onto sid, tid, jti,
// typ, iss, iat, exp, amr, auth_time or mfa_at would be discarded by mintToken
// on every mint, so the
// constructor refuses it — the silent-configuration failure the allowlist
// exists to prevent, on the claim side rather than the field side. The base
// claims are not reserved: mapping over email or role is the reference's own
// override semantics and stays allowed.
func TestUserFieldClaims_RejectsReservedClaimNames(t *testing.T) {
	for _, claim := range reservedClaimNames {
		t.Run(claim, func(t *testing.T) {
			build, err := UserFieldClaims(map[string]string{"tenant": "tenantId", claim: "id"})
			if err == nil {
				t.Fatalf("UserFieldClaims accepted the reserved claim name %q", claim)
			}
			if build != nil {
				t.Fatal("a failed constructor returned a builder")
			}
			// The message names the claim and says why, so the startup failure
			// is fixable from the log line alone.
			if !strings.Contains(err.Error(), `"`+claim+`"`) || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("error %q does not name the reserved claim %q", err, claim)
			}
		})
	}
	// Exact match only: a differently cased or padded name is a claim of the
	// hook's own, which issueToken leaves alone.
	for _, claim := range []string{"Exp", "SID", " typ"} {
		if _, err := UserFieldClaims(map[string]string{claim: "id"}); err != nil {
			t.Fatalf("UserFieldClaims(%q) = %v, want the name accepted as a non-reserved claim", claim, err)
		}
	}
	// The base claims stay overridable.
	for _, claim := range []string{"sub", "email", "role", "loginProvider", "isEmailVerified", "isTotpEnabled"} {
		if _, err := UserFieldClaims(map[string]string{claim: "id"}); err != nil {
			t.Fatalf("UserFieldClaims(%q) = %v, want a base claim to be mappable", claim, err)
		}
	}
}

// TestReservedClaimNames_MatchIssueToken ties the constructor's list to the
// mint: every name UserFieldClaims refuses is one mintToken owns, and the list
// is exactly the ten the docs and the CHANGELOG name — the seven session
// claims and the three of the authentication context — so neither can drift
// from the other without a test noticing.
func TestReservedClaimNames_MatchIssueToken(t *testing.T) {
	const documented = "sid,tid,jti,typ,iss,iat,exp,amr,auth_time,mfa_at"
	if got := strings.Join(reservedClaimNames, ","); got != documented {
		t.Fatalf("reservedClaimNames = %s, want %s (update issueToken, the docs and this test together)", got, documented)
	}
	svc := testServiceForToken(t)
	const sentinel = "from-the-hook"
	svc.cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) {
		claims := map[string]any{"plan": sentinel}
		for _, name := range reservedClaimNames {
			claims[name] = sentinel
		}
		return claims, nil
	}
	token, _, err := svc.issueToken(context.Background(), User{ID: "usr_r", TenantID: "t1"}, "ses_r", "access", time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	claims := decodeSegment(t, mustSegment(t, token, 1))
	for _, name := range reservedClaimNames {
		if claims[name] == sentinel {
			t.Errorf("%s = %#v: listed as reserved but not overwritten by issueToken", name, claims[name])
		}
	}
	if claims["plan"] != sentinel {
		t.Fatalf("plan = %#v, want the hook's value: a non-reserved claim must still go through", claims["plan"])
	}
}

func TestChainClaims_LaterBuilderWins(t *testing.T) {
	fields, err := UserFieldClaims(map[string]string{"plan": "role", "who": "email"})
	if err != nil {
		t.Fatalf("UserFieldClaims: %v", err)
	}
	user := User{ID: "usr_1", Email: "chain@example.com", Role: "member"}

	claims, err := ChainClaims(fields, StaticClaims(map[string]any{"plan": "pro"}))(context.Background(), user)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	if claims["plan"] != "pro" || claims["who"] != "chain@example.com" || len(claims) != 2 {
		t.Fatalf("fields then static = %+v, want plan overridden by the static builder", claims)
	}

	claims, err = ChainClaims(StaticClaims(map[string]any{"plan": "pro"}), fields)(context.Background(), user)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	if claims["plan"] != "member" || claims["who"] != "chain@example.com" || len(claims) != 2 {
		t.Fatalf("static then fields = %+v, want plan overridden by the field builder", claims)
	}
}

func TestChainClaims_FirstErrorStopsTheChain(t *testing.T) {
	boom := errors.New("boom")
	reached := false
	build := ChainClaims(
		StaticClaims(map[string]any{"a": 1}),
		func(context.Context, User) (map[string]any, error) { return nil, boom },
		func(context.Context, User) (map[string]any, error) {
			reached = true
			return map[string]any{"b": 2}, nil
		},
	)
	claims, err := build(context.Background(), User{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the second builder's error as it is", err)
	}
	if claims != nil {
		t.Fatalf("claims = %+v on error, want nil", claims)
	}
	if reached {
		t.Fatal("the builder after the failing one ran")
	}
}

func TestChainClaims_SkipsNilAndMergesFresh(t *testing.T) {
	empty, err := ChainClaims()(context.Background(), User{})
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty chain = %#v, %v; want an empty, non-nil map", empty, err)
	}
	build := ChainClaims(nil, StaticClaims(map[string]any{"a": 1}), nil, StaticClaims(nil))
	first, err := build(context.Background(), User{})
	if err != nil || first["a"] != 1 || len(first) != 1 {
		t.Fatalf("chain with nils = %#v, %v", first, err)
	}
	first["a"] = "edited"
	second, err := build(context.Background(), User{})
	if err != nil || second["a"] != 1 {
		t.Fatalf("second call = %#v, %v; a result must be the caller's to edit", second, err)
	}
}

// TestHelpersMintThroughIssueToken runs the helpers where they are meant to
// run: as Config.BuildTokenClaims, on a real mint. The chain maps a field onto
// the base claim email — the reference's override — and adds a static sid and
// typ, which StaticClaims cannot refuse and the merge order in issueToken must
// discard exactly as it does for a hand-written hook.
func TestHelpersMintThroughIssueToken(t *testing.T) {
	svc := testServiceForToken(t)
	fields, err := UserFieldClaims(map[string]string{"tenant": "tenantId", "email": "id"})
	if err != nil {
		t.Fatalf("UserFieldClaims: %v", err)
	}
	svc.cfg.BuildTokenClaims = ChainClaims(fields, StaticClaims(map[string]any{"plan": "pro", "typ": "access", "sid": "ses_attacker"}))

	user := User{ID: "usr_h", TenantID: "t1", Email: "helpers@example.com"}
	token, _, err := svc.issueToken(context.Background(), user, "ses_h", "refresh", time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	claims := decodeSegment(t, mustSegment(t, token, 1))
	for key, want := range map[string]any{
		"tenant": "t1",
		"plan":   "pro",
		"email":  "usr_h",
		"typ":    "refresh",
		"sid":    "ses_h",
	} {
		if claims[key] != want {
			t.Errorf("%s = %#v, want %#v (payload %+v)", key, claims[key], want, claims)
		}
	}
	if _, err := svc.parseToken(token, "refresh"); err != nil {
		t.Fatalf("a token minted through the helpers must parse: %v", err)
	}
}
