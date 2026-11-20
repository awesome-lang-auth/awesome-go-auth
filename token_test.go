package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testServiceForToken(t *testing.T) *Service {
	t.Helper()
	cfg := testConfig("tokentest12345678901234567890123")
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

// decodeSegment decodes one base64url JWT segment into a claim/header map.
func decodeSegment(t *testing.T, segment string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal segment: %v", err)
	}
	return out
}

// resignWithHeader rebuilds a token with a different JOSE header, keeping the
// original claims and producing a signature that is valid for the given secret.
func resignWithHeader(t *testing.T, token, secret string, header map[string]any) string {
	t.Helper()
	_, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	sigInput := base64.RawURLEncoding.EncodeToString(raw) + "." + payload
	return sigInput + "." + sign(sigInput, secret)
}

// resignWithRawHeader is resignWithHeader for headers that must be byte-exact:
// it takes the header as verbatim JSON so member order and duplicate members
// survive, which marshalling a Go map would not preserve.
func resignWithRawHeader(t *testing.T, token, secret, headerJSON string) string {
	t.Helper()
	_, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	sigInput := base64.RawURLEncoding.EncodeToString([]byte(headerJSON)) + "." + payload
	return sigInput + "." + sign(sigInput, secret)
}

// decodeRawSegment decodes one base64url JWT segment to its raw bytes.
func decodeRawSegment(t *testing.T, segment string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	return raw
}

// mutateOneByte replaces old with new in raw and asserts that the result is
// still well-formed JSON differing from the input in exactly one byte, so a
// test built on it really pins single-byte sensitivity rather than accidentally
// tripping a base64 or JSON decode error.
func mutateOneByte(t *testing.T, raw []byte, old, new string) []byte {
	t.Helper()
	mutated := bytes.Replace(raw, []byte(old), []byte(new), 1)
	if bytes.Equal(mutated, raw) {
		t.Fatalf("substring %q not found in %s", old, raw)
	}
	if len(mutated) != len(raw) {
		t.Fatalf("mutation changed the segment length: %d -> %d", len(raw), len(mutated))
	}
	diff := 0
	for i := range raw {
		if raw[i] != mutated[i] {
			diff++
		}
	}
	if diff != 1 {
		t.Fatalf("expected exactly one byte to change, %d changed", diff)
	}
	if !json.Valid(mutated) {
		t.Fatalf("mutated segment is not valid JSON: %s", mutated)
	}
	return mutated
}

func TestIssueToken_AccessAndParse(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_001", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_001", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	claims, err := svc.parseToken(token, "access")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if claims.Sub != "usr_001" {
		t.Fatalf("unexpected sub: %s", claims.Sub)
	}
	if claims.Tid != "t1" {
		t.Fatalf("unexpected tid: %s", claims.Tid)
	}
	if claims.Typ != "access" {
		t.Fatalf("unexpected typ: %s", claims.Typ)
	}
	if claims.Sid != "ses_001" {
		t.Fatalf("unexpected sid: %s", claims.Sid)
	}
	if claims.Iss != svc.cfg.Issuer {
		t.Fatalf("unexpected iss: %s", claims.Iss)
	}
	if claims.Jti == "" {
		t.Fatal("jti should not be empty")
	}
}

func TestIssueToken_RefreshAndParse(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_002", TenantID: "t2"}
	token, _, err := svc.issueToken(ctx, user, "ses_002", "refresh", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	claims, err := svc.parseToken(token, "refresh")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if claims.Typ != "refresh" {
		t.Fatalf("unexpected typ: %s", claims.Typ)
	}
}

func TestIssueToken_ThreeSegmentJWT(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_010", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_010", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a 3-segment JWT, got %d segments: %q", len(parts), token)
	}
	for i, part := range parts {
		if part == "" {
			t.Fatalf("segment %d is empty", i)
		}
		if strings.ContainsAny(part, "+/=") {
			t.Fatalf("segment %d is not base64url without padding: %q", i, part)
		}
	}
}

func TestIssueToken_JOSEHeader(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_011", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_011", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	header, _, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	decoded := decodeSegment(t, header)
	if decoded["alg"] != "HS256" {
		t.Fatalf("unexpected alg: %v", decoded["alg"])
	}
	if decoded["typ"] != "JWT" {
		t.Fatalf("unexpected header typ: %v", decoded["typ"])
	}
}

func TestIssueToken_ClaimsSegmentCarriesRegisteredClaims(t *testing.T) {
	svc := testServiceForToken(t)
	now := time.Now().Truncate(time.Second)
	svc.now = func() time.Time { return now }
	ctx := context.Background()
	user := User{ID: "usr_012", TenantID: "t1", Email: "claims@example.com", Role: "admin", IsEmailVerified: true, IsTOTPEnabled: true}
	token, _, err := svc.issueToken(ctx, user, "ses_012", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	_, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	claims := decodeSegment(t, payload)
	if claims["sub"] != "usr_012" || claims["sid"] != "ses_012" || claims["tid"] != "t1" {
		t.Fatalf("unexpected identity claims: %+v", claims)
	}
	if claims["typ"] != "access" || claims["iss"] != svc.cfg.Issuer {
		t.Fatalf("unexpected typ/iss claims: %+v", claims)
	}
	if claims["jti"] == "" || claims["jti"] == nil {
		t.Fatalf("jti claim missing: %+v", claims)
	}
	if claims["iat"] != float64(now.Unix()) || claims["exp"] != float64(now.Add(15*time.Minute).Unix()) {
		t.Fatalf("unexpected iat/exp claims: %+v", claims)
	}
	if claims["email"] != "claims@example.com" || claims["role"] != "admin" {
		t.Fatalf("unexpected profile claims: %+v", claims)
	}
	if claims["isEmailVerified"] != true || claims["isTotpEnabled"] != true {
		t.Fatalf("unexpected flag claims: %+v", claims)
	}
}

func TestParseToken_WrongType(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_003", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_003", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	_, err = svc.parseToken(token, "refresh")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for wrong type, got %v", err)
	}
}

func TestParseToken_TamperedSignature(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_004", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_004", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	tampered := token[:len(token)-4] + "xxxx"
	_, err = svc.parseToken(tampered, "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for tampered token, got %v", err)
	}
}

func TestParseToken_TamperedClaims(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_013", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_013", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	header, payload, sig, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	claims := decodeSegment(t, payload)
	claims["sub"] = "usr_attacker"
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	forged := header + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + sig
	if _, err := svc.parseToken(forged, "access"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for tampered claims, got %v", err)
	}
}

func TestParseToken_RejectsAlgNone(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_014", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_014", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	// Unsecured JWT: alg "none" with an empty signature segment.
	_, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	if _, err := svc.parseToken(noneHeader+"."+payload+".", "access"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for alg none with empty signature, got %v", err)
	}
	// Same claims, alg "none", but carrying a signature that is valid for the
	// service secret: the allow-list must still refuse it.
	resigned := resignWithHeader(t, token, svc.cfg.Secret, map[string]any{"alg": "none", "typ": "JWT"})
	if _, err := svc.parseToken(resigned, "access"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for alg none with valid mac, got %v", err)
	}
}

func TestParseToken_RejectsAlgConfusion(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_015", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_015", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	for _, alg := range []string{"RS256", "RS512", "HS384", "HS512", "ES256", "hs256", ""} {
		resigned := resignWithHeader(t, token, svc.cfg.Secret, map[string]any{"alg": alg, "typ": "JWT"})
		if _, err := svc.parseToken(resigned, "access"); err != ErrInvalidToken {
			t.Fatalf("expected ErrInvalidToken for alg %q, got %v", alg, err)
		}
	}
}

// TestParseToken_RejectsHeaderWithoutExactAlgMember pins the *member name* of
// the allow-list check, not only its value. Decoding the header into a struct
// makes encoding/json match fields case-insensitively, which accepts headers
// carrying no lowercase "alg" at all — and, worse, a header whose lowercase
// "alg" says "none" but which is followed by an "ALG" member that overwrites
// the field. Every spec-compliant verifier reads such a token as alg "none"
// and refuses it; so must this one.
func TestParseToken_RejectsHeaderWithoutExactAlgMember(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_021", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_021", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	// Control: the byte-exact header of a real token must still parse when it
	// is re-signed through the same path the negative cases use.
	control := resignWithRawHeader(t, token, svc.cfg.Secret, `{"alg":"HS256","typ":"JWT"}`)
	if _, err := svc.parseToken(control, "access"); err != nil {
		t.Fatalf("a byte-exact HS256 header must parse: %v", err)
	}
	for _, header := range []string{
		`{"ALG":"HS256","typ":"JWT"}`,
		`{"Alg":"HS256","typ":"JWT"}`,
		`{"alg":"none","ALG":"HS256","typ":"JWT"}`,
		`{"typ":"JWT"}`,
		`{"alg":256,"typ":"JWT"}`,
		`{"alg":["HS256"],"typ":"JWT"}`,
	} {
		resigned := resignWithRawHeader(t, token, svc.cfg.Secret, header)
		if _, err := svc.parseToken(resigned, "access"); err != ErrInvalidToken {
			t.Fatalf("expected ErrInvalidToken for header %s, got %v", header, err)
		}
	}
}

// TestParseToken_SingleByteMutation alters exactly one byte of the header JSON,
// then exactly one byte of the claims JSON, leaving both segments well-formed
// base64url and well-formed JSON and reusing the original signature. The
// signing input is the two segments verbatim, so both tokens must fail on the
// MAC — the header case in particular cannot be rejected by the allow-list,
// since alg stays "HS256".
func TestParseToken_SingleByteMutation(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_022", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_022", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	header, payload, sig, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}

	// {"alg":"HS256","typ":"JWT"} -> {"alg":"HS256","typ":"JWt"}
	mutatedHeader := mutateOneByte(t, decodeRawSegment(t, header), `"typ":"JWT"`, `"typ":"JWt"`)
	forged := base64.RawURLEncoding.EncodeToString(mutatedHeader) + "." + payload + "." + sig
	if _, err := svc.parseToken(forged, "access"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for a single-byte header change, got %v", err)
	}

	// "sub":"usr_022" -> "sub":"usr_023"
	mutatedPayload := mutateOneByte(t, decodeRawSegment(t, payload), `"sub":"usr_022"`, `"sub":"usr_023"`)
	forged = header + "." + base64.RawURLEncoding.EncodeToString(mutatedPayload) + "." + sig
	if _, err := svc.parseToken(forged, "access"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for a single-byte claims change, got %v", err)
	}
}

// TestParseToken_TypeIsNotInterchangeable pins the typ claim in both
// directions: an access token must not satisfy a refresh-token check and a
// refresh token must not satisfy an access-token check. TestParseToken_WrongType
// only covers the first direction.
func TestParseToken_TypeIsNotInterchangeable(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_023", TenantID: "t1"}
	access, _, err := svc.issueToken(ctx, user, "ses_023", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken access: %v", err)
	}
	refresh, _, err := svc.issueToken(ctx, user, "ses_023", "refresh", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("issueToken refresh: %v", err)
	}
	if _, err := svc.parseToken(access, "refresh"); err != ErrInvalidToken {
		t.Fatalf("an access token must not be accepted where a refresh token is required, got %v", err)
	}
	if _, err := svc.parseToken(refresh, "access"); err != ErrInvalidToken {
		t.Fatalf("a refresh token must not be accepted where an access token is required, got %v", err)
	}
	if _, err := svc.parseToken(access, "access"); err != nil {
		t.Fatalf("access token must parse as access: %v", err)
	}
	if _, err := svc.parseToken(refresh, "refresh"); err != nil {
		t.Fatalf("refresh token must parse as refresh: %v", err)
	}
	// The distinction is carried by the typ claim itself, not by anything
	// outside the token: rewriting typ (and re-signing with the real secret)
	// is what a holder of the secret would do, and the claim is what decides.
	claims := decodeSegment(t, mustSegment(t, refresh, 1))
	claims["typ"] = "access"
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	headerSeg := mustSegment(t, refresh, 0)
	sigInput := headerSeg + "." + base64.RawURLEncoding.EncodeToString(raw)
	promoted := sigInput + "." + sign(sigInput, svc.cfg.Secret)
	if _, err := svc.parseToken(promoted, "access"); err != nil {
		t.Fatalf("typ is the discriminator, so a re-signed typ=access token must parse: %v", err)
	}
	if _, err := svc.parseToken(promoted, "refresh"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken once typ no longer says refresh, got %v", err)
	}
}

// mustSegment returns segment i of a compact JWS serialization.
func mustSegment(t *testing.T, token string, i int) string {
	t.Helper()
	header, payload, sig, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	return []string{header, payload, sig}[i]
}

func TestParseToken_CrossSecret(t *testing.T) {
	issuer := testServiceForToken(t)
	verifier := testServiceForToken(t)
	verifier.cfg.Secret = "othersecret1234567890123456789012"
	ctx := context.Background()
	user := User{ID: "usr_016", TenantID: "t1"}
	token, _, err := issuer.issueToken(ctx, user, "ses_016", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	if _, err := verifier.parseToken(token, "access"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for token signed with another secret, got %v", err)
	}
}

func TestParseToken_ExpiredToken(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	now := time.Now()
	svc.now = func() time.Time { return now }
	user := User{ID: "usr_005", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_005", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	svc.now = func() time.Time { return now.Add(16*time.Minute + svc.cfg.ClockSkew + time.Second) }
	_, err = svc.parseToken(token, "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for expired token, got %v", err)
	}
}

func TestParseToken_WithinClockSkew(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	now := time.Now()
	svc.now = func() time.Time { return now }
	user := User{ID: "usr_017", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_017", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	svc.now = func() time.Time { return now.Add(15*time.Minute + svc.cfg.ClockSkew - time.Second) }
	if _, err := svc.parseToken(token, "access"); err != nil {
		t.Fatalf("token just inside the clock skew window must parse: %v", err)
	}
}

func TestParseToken_WrongIssuer(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	svc.cfg.Issuer = "wrong-issuer"
	user := User{ID: "usr_006", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_006", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	svc.cfg.Issuer = "awesome-go-auth"
	_, err = svc.parseToken(token, "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for wrong issuer, got %v", err)
	}
}

func TestParseToken_InvalidFormat(t *testing.T) {
	svc := testServiceForToken(t)
	for _, token := range []string{"notavalidtoken", "onlytwo.segments"} {
		if _, err := svc.parseToken(token, "access"); err != ErrInvalidToken {
			t.Fatalf("expected ErrInvalidToken for %q, got %v", token, err)
		}
	}
}

func TestParseToken_InvalidBase64Header(t *testing.T) {
	svc := testServiceForToken(t)
	sigInput := "!!!invalid!!!." + base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"access"}`))
	_, err := svc.parseToken(sigInput+"."+sign(sigInput, svc.cfg.Secret), "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for invalid base64 header, got %v", err)
	}
}

func TestParseToken_InvalidBase64Payload(t *testing.T) {
	svc := testServiceForToken(t)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	sigInput := header + ".!!!invalid!!!"
	_, err := svc.parseToken(sigInput+"."+sign(sigInput, svc.cfg.Secret), "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for invalid base64 payload, got %v", err)
	}
}

func TestIssueToken_CustomClaims(t *testing.T) {
	svc := testServiceForToken(t)
	svc.cfg.BuildTokenClaims = func(ctx context.Context, user User) (map[string]any, error) {
		return map[string]any{"custom": "value"}, nil
	}
	ctx := context.Background()
	user := User{ID: "usr_007", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_007", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken with custom claims: %v", err)
	}
	_, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	claims := decodeSegment(t, payload)
	if claims["custom"] != "value" {
		t.Fatalf("custom claim missing from token payload: %+v", claims)
	}
	if claims["sub"] != "usr_007" {
		t.Fatalf("custom claims must not drop the registered claims: %+v", claims)
	}
	if _, err := svc.parseToken(token, "access"); err != nil {
		t.Fatalf("token with custom claims must still parse: %v", err)
	}
}

func TestIssueToken_ExpiryIsCorrect(t *testing.T) {
	svc := testServiceForToken(t)
	now := time.Now().Truncate(time.Second)
	svc.now = func() time.Time { return now }
	ctx := context.Background()
	user := User{ID: "usr_008", TenantID: "t1"}
	ttl := 15 * time.Minute
	_, exp, err := svc.issueToken(ctx, user, "ses_008", "access", ttl)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	expectedExp := now.Add(ttl)
	if !exp.Equal(expectedExp) {
		t.Fatalf("expected expiry %v, got %v", expectedExp, exp)
	}
}

func TestIssueToken_UniqueJTI(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_009", TenantID: "t1"}
	tok1, _, _ := svc.issueToken(ctx, user, "ses_009a", "access", time.Minute)
	tok2, _, _ := svc.issueToken(ctx, user, "ses_009b", "access", time.Minute)
	if tok1 == tok2 {
		t.Fatal("tokens with different session IDs should be different")
	}
	claims1, err := svc.parseToken(tok1, "access")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	claims2, err := svc.parseToken(tok2, "access")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if claims1.Jti == claims2.Jti {
		t.Fatalf("jti must be unique per token, got %q twice", claims1.Jti)
	}
}

// TestIssueToken_ReservedClaimsSurviveCustomClaims pins the merge order. The
// Config.BuildTokenClaims result used to be spread over the whole payload, so
// a hook claim named sid, tid, jti, typ, iss, iat or exp replaced the session
// binding, tenant scope, token id, type, issuer or lifetime of every token
// minted. Those seven are now written after the merge — on the access token,
// the refresh token and the step-up token alike — which is the guarantee the
// reference gives its own session claims by assigning sid after the spread
// (auth.router.ts:433) and stripping iat/exp before signing
// (token.service.ts:19).
func TestIssueToken_ReservedClaimsSurviveCustomClaims(t *testing.T) {
	svc := testServiceForToken(t)
	now := time.Now().Truncate(time.Second)
	svc.now = func() time.Time { return now }
	svc.cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) {
		return map[string]any{
			"sid": "ses_attacker",
			"tid": "t_attacker",
			"jti": "jti_attacker",
			"typ": "access",
			"iss": "attacker",
			"iat": 0,
			"exp": now.Add(100 * 365 * 24 * time.Hour).Unix(),
			// A claim outside the reserved set still goes through, so the test
			// cannot pass by the hook being ignored altogether.
			"plan": "pro",
		}, nil
	}
	ctx := context.Background()
	user := User{ID: "usr_030", TenantID: "t1"}
	for _, tc := range []struct {
		typ string
		sid string
		ttl time.Duration
	}{
		{"access", "ses_030", 15 * time.Minute},
		{"refresh", "ses_030", 30 * 24 * time.Hour},
		{tokenTypeTemp, "", 5 * time.Minute},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			token, _, err := svc.issueToken(ctx, user, tc.sid, tc.typ, tc.ttl)
			if err != nil {
				t.Fatalf("issueToken: %v", err)
			}
			claims := decodeSegment(t, mustSegment(t, token, 1))
			for key, want := range map[string]any{
				"sid":  tc.sid,
				"tid":  "t1",
				"typ":  tc.typ,
				"iss":  svc.cfg.Issuer,
				"iat":  float64(now.Unix()),
				"exp":  float64(now.Add(tc.ttl).Unix()),
				"plan": "pro",
			} {
				if claims[key] != want {
					t.Errorf("%s = %#v, want %#v (payload %+v)", key, claims[key], want, claims)
				}
			}
			if jti, _ := claims["jti"].(string); jti == "" || jti == "jti_attacker" {
				t.Errorf("jti = %#v, want a freshly minted id", claims["jti"])
			}
			// What the verifier sees agrees with the segment: the token parses
			// under its own type with its own session and lifetime, and under
			// no other type.
			parsed, err := svc.parseToken(token, tc.typ)
			if err != nil {
				t.Fatalf("parseToken as %s: %v", tc.typ, err)
			}
			if parsed.Sid != tc.sid || parsed.Tid != "t1" || parsed.Exp != now.Add(tc.ttl).Unix() {
				t.Fatalf("parsed claims %+v carry hook values", parsed)
			}
			for _, other := range []string{"access", "refresh", tokenTypeTemp} {
				if other == tc.typ {
					continue
				}
				if _, err := svc.parseToken(token, other); err != ErrInvalidToken {
					t.Errorf("a %s token parsed as %s: %v", tc.typ, other, err)
				}
			}
		})
	}
}

// TestIssueTempToken_TypeCannotBePromotedByCustomClaims is the case the
// reservation exists for. The step-up token is typed so that it cannot serve
// as an access token (see tokenTypeTemp); with the old merge a hook returning
// {"typ": "access"} undid that for every tempToken minted, handing whoever
// held one a full session credential before the second factor was presented.
func TestIssueTempToken_TypeCannotBePromotedByCustomClaims(t *testing.T) {
	svc := testServiceForToken(t)
	svc.cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) {
		return map[string]any{"typ": "access", "sid": "ses_forged"}, nil
	}
	ctx := context.Background()
	user, _, err := svc.Register(ctx, RegisterInput{Email: "stepup@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	temp, err := svc.IssueTempToken(ctx, user)
	if err != nil {
		t.Fatalf("IssueTempToken: %v", err)
	}
	subject, err := svc.VerifyTempToken(temp)
	if err != nil {
		t.Fatalf("VerifyTempToken: %v", err)
	}
	if subject.UserID != user.ID || subject.TenantID != "t1" {
		t.Fatalf("subject = %+v, want %s in t1", subject, user.ID)
	}
	if _, err := svc.Me(ctx, temp); err != ErrInvalidToken {
		t.Fatalf("a tempToken must not authenticate as an access token, got %v", err)
	}
}

// TestIssueToken_CustomClaimsOverrideBaseClaims pins the other half of the
// reference's merge: the six base claims are the hook's to override —
// auth.router.ts:378-384 spreads config.buildTokenPayload(user) over exactly
// {sub, email, role, loginProvider, isEmailVerified, isTotpEnabled}.
func TestIssueToken_CustomClaimsOverrideBaseClaims(t *testing.T) {
	svc := testServiceForToken(t)
	svc.cfg.BuildTokenClaims = func(context.Context, User) (map[string]any, error) {
		return map[string]any{
			"email":           "hook@example.com",
			"role":            "auditor",
			"loginProvider":   "saml",
			"isEmailVerified": true,
			"isTotpEnabled":   true,
		}, nil
	}
	ctx := context.Background()
	user := User{ID: "usr_031", TenantID: "t1", Email: "stored@example.com", Role: "member"}
	token, _, err := svc.issueToken(ctx, user, "ses_031", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	claims := decodeSegment(t, mustSegment(t, token, 1))
	for key, want := range map[string]any{
		"sub":             "usr_031",
		"email":           "hook@example.com",
		"role":            "auditor",
		"loginProvider":   "saml",
		"isEmailVerified": true,
		"isTotpEnabled":   true,
		"sid":             "ses_031",
	} {
		if claims[key] != want {
			t.Errorf("%s = %#v, want %#v (payload %+v)", key, claims[key], want, claims)
		}
	}
	if _, err := svc.parseToken(token, "access"); err != nil {
		t.Fatalf("a token with overridden base claims must still parse: %v", err)
	}
}

// TestIssueToken_LoginProviderClaim: every token carries loginProvider — the
// reference's `user.loginProvider ?? 'local'` (auth.router.ts:379) — on the
// access token, on the refresh token, which carries the identical claim set
// (token.service.ts:25-29), and on the step-up token, which the reference
// mints from the same payload (auth.router.ts:572-575).
func TestIssueToken_LoginProviderClaim(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		user User
		want string
	}{
		{"defaults to local", User{ID: "usr_032", TenantID: "t1"}, LoginProviderLocal},
		{"reports the recorded provider", User{ID: "usr_033", TenantID: "t1", LoginProvider: "github"}, "github"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokens, err := svc.newSessionTokens(ctx, tc.user)
			if err != nil {
				t.Fatalf("newSessionTokens: %v", err)
			}
			temp, err := svc.IssueTempToken(ctx, tc.user)
			if err != nil {
				t.Fatalf("IssueTempToken: %v", err)
			}
			for name, token := range map[string]string{"access": tokens.AccessToken, "refresh": tokens.RefreshToken, "temp": temp} {
				if got := decodeSegment(t, mustSegment(t, token, 1))["loginProvider"]; got != tc.want {
					t.Errorf("%s token loginProvider = %#v, want %q", name, got, tc.want)
				}
			}
		})
	}
}

// TestIssueToken_LoginProviderAfterOAuthCallback drives the user-creation path
// of OAuthService.HandleCallback: the account it creates records the provider,
// the store hands it back, and the session it issues says so. An account the
// callback only links keeps what it was created with — the reference's
// linkAccount writes a linked-accounts row and touches no user column
// (auth.router.ts:1336-1343).
func TestIssueToken_LoginProviderAfterOAuthCallback(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	oauth := NewOAuthService()
	links := NewMemoryLinkedAccounts()

	created, tokens, err := oauth.HandleCallback(ctx, svc, links, OAuthUserInfo{Provider: "acme", ProviderID: "acme-1", Email: "oauth@example.com"}, "t1", "")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if created.LoginProvider != "acme" {
		t.Fatalf("LoginProvider = %q, want %q", created.LoginProvider, "acme")
	}
	stored, err := svc.users.GetUserByID(ctx, created.ID, "t1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if stored.LoginProvider != "acme" {
		t.Fatalf("stored LoginProvider = %q, want %q", stored.LoginProvider, "acme")
	}
	if got := NewPublicUser(stored).LoginProvider; got != "acme" {
		t.Fatalf("PublicUser.LoginProvider = %q, want %q", got, "acme")
	}
	for name, token := range map[string]string{"access": tokens.AccessToken, "refresh": tokens.RefreshToken} {
		if got := decodeSegment(t, mustSegment(t, token, 1))["loginProvider"]; got != "acme" {
			t.Errorf("%s token loginProvider = %#v, want %q", name, got, "acme")
		}
	}

	local, _, err := svc.Register(ctx, RegisterInput{Email: "linked@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	// Linking by address is an explicit policy since the default became the
	// conflict (issue #36).
	linkPolicy := DefaultOAuthProvisioning()
	linkPolicy.OnEmailMatch = OAuthEmailMatchLink
	linked, tokens, err := oauth.HandleCallbackWithPolicy(ctx, svc, links, OAuthUserInfo{Provider: "acme", ProviderID: "acme-2", Email: "linked@example.com"}, "t1", "", linkPolicy)
	if err != nil {
		t.Fatalf("HandleCallback for an existing account: %v", err)
	}
	if linked.ID != local.ID || linked.LoginProvider != "" {
		t.Fatalf("linked user = %+v, want the password account %s with no recorded provider", linked, local.ID)
	}
	if got := decodeSegment(t, mustSegment(t, tokens.AccessToken, 1))["loginProvider"]; got != LoginProviderLocal {
		t.Errorf("a linked password account's token loginProvider = %#v, want %q", got, LoginProviderLocal)
	}
}
