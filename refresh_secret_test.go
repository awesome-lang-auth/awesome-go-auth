package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Config.RefreshSecret (#25): refresh tokens are signed and verified with it
// when it is set, as the reference signs them with refreshTokenSecret
// (token.service.ts:67-71, :237), and with Config.Secret when it is not, which
// is how every refresh token was signed before the field existed.

const (
	testAccessSecret  = "access-secret-0123456789abcdefghij"
	testRefreshSecret = "refresh-secret-0123456789abcdefghi"
)

func newRefreshSecretService(t *testing.T, refreshSecret string) *Service {
	t.Helper()
	cfg := testConfig(testAccessSecret)
	cfg.RefreshSecret = refreshSecret
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

// resignClaims returns token's header and payload re-signed with secret: the
// same token a holder of that secret would mint.
func resignClaims(t *testing.T, token, secret string) string {
	t.Helper()
	header, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	return header + "." + payload + "." + sign(header+"."+payload, secret)
}

// retypeClaims rewrites the typ claim of token and signs the result with
// secret.
func retypeClaims(t *testing.T, token, typ, secret string) string {
	t.Helper()
	header, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	claims := decodeSegment(t, payload)
	claims["typ"] = typ
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	sigInput := header + "." + base64.RawURLEncoding.EncodeToString(raw)
	return sigInput + "." + sign(sigInput, secret)
}

func TestRefreshSecretUnsetSignsRefreshTokensWithSecret(t *testing.T) {
	svc := newRefreshSecretService(t, "")
	ctx := context.Background()
	user := User{ID: "usr_rs1", TenantID: "t1"}
	refresh, _, err := svc.issueToken(ctx, user, "ses_rs1", "refresh", time.Hour)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	// Byte for byte the token the library minted before the field existed.
	if resigned := resignClaims(t, refresh, testAccessSecret); resigned != refresh {
		t.Fatal("with RefreshSecret unset, a refresh token must be signed with Config.Secret")
	}
	if _, err := svc.parseToken(refresh, "refresh"); err != nil {
		t.Fatalf("parse refresh: %v", err)
	}
}

func TestRefreshSecretSignsAndVerifiesOnlyRefreshTokens(t *testing.T) {
	svc := newRefreshSecretService(t, testRefreshSecret)
	ctx := context.Background()
	user := User{ID: "usr_rs2", TenantID: "t1"}

	refresh, _, err := svc.issueToken(ctx, user, "ses_rs2", "refresh", time.Hour)
	if err != nil {
		t.Fatalf("issueToken refresh: %v", err)
	}
	access, _, err := svc.issueToken(ctx, user, "ses_rs2", "access", time.Minute)
	if err != nil {
		t.Fatalf("issueToken access: %v", err)
	}
	temp, err := svc.IssueTempToken(ctx, user)
	if err != nil {
		t.Fatalf("IssueTempToken: %v", err)
	}

	// Each token is signed with its own key and verifies.
	if resignClaims(t, refresh, testRefreshSecret) != refresh {
		t.Error("refresh token is not signed with RefreshSecret")
	}
	if resignClaims(t, access, testAccessSecret) != access {
		t.Error("access token is not signed with Secret")
	}
	// The step-up token is the reference's access token, so it stays on
	// accessTokenSecret.
	if resignClaims(t, temp, testAccessSecret) != temp {
		t.Error("step-up token is not signed with Secret")
	}
	if _, err := svc.parseToken(refresh, "refresh"); err != nil {
		t.Errorf("parse refresh: %v", err)
	}
	if _, err := svc.parseToken(access, "access"); err != nil {
		t.Errorf("parse access: %v", err)
	}
	if _, err := svc.VerifyTempToken(temp); err != nil {
		t.Errorf("verify temp: %v", err)
	}

	// A holder of the access secret can no longer mint a refresh token...
	if _, err := svc.parseToken(resignClaims(t, refresh, testAccessSecret), "refresh"); err != ErrInvalidToken {
		t.Errorf("a refresh token signed with Secret must be refused, got %v", err)
	}
	// ...nor turn an access token into one.
	if _, err := svc.parseToken(retypeClaims(t, access, "refresh", testAccessSecret), "refresh"); err != ErrInvalidToken {
		t.Errorf("an access token retyped to refresh and signed with Secret must be refused, got %v", err)
	}
	// And a holder of the refresh secret cannot mint an access token.
	if _, err := svc.parseToken(retypeClaims(t, refresh, "access", testRefreshSecret), "access"); err != ErrInvalidToken {
		t.Errorf("a token signed with RefreshSecret must not pass as an access token, got %v", err)
	}
	if _, err := svc.parseToken(retypeClaims(t, refresh, tokenTypeTemp, testRefreshSecret), tokenTypeTemp); err != ErrInvalidToken {
		t.Errorf("a token signed with RefreshSecret must not pass as a step-up token, got %v", err)
	}
}

// TestRefreshSecretRotationEndsSessionsNotAccessTokens is the use the issue
// names: rotating the refresh key alone forces re-authentication, while the
// access tokens already handed out keep working until they expire.
func TestRefreshSecretRotationEndsSessionsNotAccessTokens(t *testing.T) {
	ctx := context.Background()
	users := NewMemoryUserStore()
	sessions := NewMemorySessionStore()
	cfg := testConfig(testAccessSecret)
	cfg.RefreshSecret = testRefreshSecret
	before, err := NewService(cfg, users, sessions)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if _, _, err := before.Register(ctx, RegisterInput{Email: "rotate@example.com", Password: "password1", TenantID: "t1"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	_, tokens, err := before.Login(ctx, LoginInput{Email: "rotate@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	rotated, err := before.Refresh(ctx, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("refresh before rotation: %v", err)
	}

	cfg.RefreshSecret = "a-new-refresh-secret-0123456789abc"
	after, err := NewService(cfg, users, sessions)
	if err != nil {
		t.Fatalf("new service after rotation: %v", err)
	}
	if _, err := after.Refresh(ctx, rotated.RefreshToken); err == nil {
		t.Fatal("a refresh token signed with the previous RefreshSecret must be refused")
	}
	if _, err := after.Authenticate(ctx, rotated.AccessToken); err != nil {
		t.Fatalf("an access token must survive a refresh-key rotation: %v", err)
	}
}

func TestConfigValidateRefreshSecret(t *testing.T) {
	cfg := testConfig(testAccessSecret)
	if err := cfg.validate(); err != nil {
		t.Fatalf("empty RefreshSecret must validate: %v", err)
	}
	cfg.RefreshSecret = "too-short"
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "refresh secret") {
		t.Fatalf("a short RefreshSecret must be refused, got %v", err)
	}
	cfg.RefreshSecret = testRefreshSecret
	if err := cfg.validate(); err != nil {
		t.Fatalf("a 32-char RefreshSecret must validate: %v", err)
	}
	// Equal to Secret is accepted for now; the reference's 1.10.3 refusal is
	// planned for v1.0.0 (see Config.RefreshSecret).
	cfg.RefreshSecret = cfg.Secret
	if err := cfg.validate(); err != nil {
		t.Fatalf("RefreshSecret equal to Secret must still validate in 0.x: %v", err)
	}
}

func TestWithRefreshSecret(t *testing.T) {
	for _, secret := range []string{"", "too-short"} {
		_, err := New(WithRefreshSecret(secret))
		if err == nil || !strings.Contains(err.Error(), "omit WithRefreshSecret") {
			t.Fatalf("WithRefreshSecret(%q): want an error naming the remedy, got %v", secret, err)
		}
	}
	a, err := New(WithRefreshSecret(testRefreshSecret))
	if err != nil {
		t.Fatalf("WithRefreshSecret: %v", err)
	}
	if a.service.cfg.RefreshSecret != testRefreshSecret {
		t.Fatalf("stored %q", a.service.cfg.RefreshSecret)
	}
	a, err = New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.service.cfg.RefreshSecret != "" {
		t.Fatalf("RefreshSecret defaults to %q, want empty (falls back to Secret)", a.service.cfg.RefreshSecret)
	}
}
