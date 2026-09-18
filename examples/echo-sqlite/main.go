// Echo + SQLite example for awesome-go-auth.
//
// It wires the Echo adapter, OAuth login with account linking, and the embedded
// UI. The SQLite store is left as a comment skeleton — swap NewMemoryUserStore
// for your modernc.org/sqlite or mattn/go-sqlite3 implementation.
//
//	go run ./examples/echo-sqlite
//
// This file is compiled by `go build ./...`, so it cannot drift away from the
// library API without CI noticing.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
	echoAdapter "github.com/nik2208/awesome-go-auth/adapter/echo"
)

func main() {
	// ── 1. Build the auth instance ─────────────────────────────────────────
	a, err := auth.New(
		auth.WithSecret(getEnv("AUTH_SECRET", "change-me-in-production-32bytes!!")),
		auth.WithIssuer("https://api.example.com"),
		auth.WithTokenTTLs(15*time.Minute, 7*24*time.Hour),
		// Swap for your SQLiteUserStore:
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
		auth.WithMetadataProvider(auth.NewMemoryMetadataStore()),
		auth.WithRBACProvider(auth.NewMemoryRolesPermissionsStore()),
		auth.WithTenantProvider(auth.NewMemoryTenantStore()),
		auth.WithRequire2FA(false),
		// The passwordless routes need somewhere to send what they mint, or they
		// answer 500 EMAIL_NOT_CONFIGURED / SMS_NOT_CONFIGURED. These log instead
		// of sending; in production use a transport:
		//
		//	mailer, err := auth.NewGatewayMailerTransport(auth.MailerConfig{
		//		Endpoint: endpoint, APIKey: apiKey, From: "noreply@example.com",
		//	})
		//	auth.WithMagicLinkSender(auth.NewMagicLinkMailer(
		//		mailer,
		//		"My App", "https://api.example.com/auth",
		//	).Send),
		auth.WithMagicLinkSender(func(_ context.Context, d auth.MagicLinkDelivery) error {
			log.Printf("[auth] magic link for %s: %s", d.Email, auth.MagicLinkURL("http://localhost:8080/auth", d.Token))
			return nil
		}),
		auth.WithSMSCodeSender(func(_ context.Context, d auth.SMSCodeDelivery) error {
			log.Printf("[auth] sms to %s: %s", d.Phone, auth.SMSCodeMessage(d.Code))
			return nil
		}),
		// The password-reset, verification and email-change routes answer 200 and
		// mail nothing without these three, as a reference deployment with no email
		// block does. NewPasswordResetMailer / NewEmailVerificationMailer /
		// NewEmailChangeMailer over a MailerTransport give you the built-in
		// templates instead of a callback.
		auth.WithPasswordResetSender(func(_ context.Context, d auth.PasswordResetDelivery) error {
			log.Printf("[auth] password reset for %s: %s", d.Email, auth.PasswordResetURL("http://localhost:8080/auth", d.Token))
			return nil
		}),
		auth.WithEmailVerificationSender(func(_ context.Context, d auth.EmailVerificationDelivery) error {
			log.Printf("[auth] verify %s: %s", d.Email, auth.EmailVerificationURL("http://localhost:8080/auth", d.Token))
			return nil
		}),
		// Note the recipient: the new address, not the current one.
		auth.WithEmailChangeSender(func(_ context.Context, d auth.EmailChangeDelivery) error {
			log.Printf("[auth] email change to %s: %s", d.NewEmail, auth.EmailChangeConfirmURL("http://localhost:8080/auth", d.Token))
			return nil
		}),
		auth.WithLogger(func(format string, args ...any) {
			log.Printf("[auth] "+format, args...)
		}),
	)
	if err != nil {
		log.Fatalf("auth init: %v", err)
	}
	svc := a.Service()

	// ── 2. OAuth providers (optional) ─────────────────────────────────────
	oauthSvc := auth.NewOAuthService(
		auth.GoogleProvider(
			getEnv("GOOGLE_CLIENT_ID", ""),
			getEnv("GOOGLE_CLIENT_SECRET", ""),
			"http://localhost:8080/oauth/google/callback",
		),
		auth.GitHubProvider(
			getEnv("GITHUB_CLIENT_ID", ""),
			getEnv("GITHUB_CLIENT_SECRET", ""),
			"http://localhost:8080/oauth/github/callback",
		),
	)
	linkedAccounts := auth.NewMemoryLinkedAccounts()

	// ── 3. Echo server ────────────────────────────────────────────────────
	e := echo.New()
	e.HideBanner = true

	// One call mounts every auth route under the configured prefix (/auth by
	// default); echoAdapter.MountWithConfig takes an *echo.Group for a different
	// prefix or cookie policy — and, here, for the hosted UI.
	//
	// UI.Enabled mounts it at /auth/ui: the login, register, forgot-password and
	// 2FA pages, the config document they boot from, and auth.js beside them.
	// Branding is optional — with none, the pages render the library's defaults.
	//
	// Admin mounts the admin console at /admin — beside the auth mount, not
	// under it, as the reference's admin router is a sibling of its auth router
	// — with the reference's own SPA served from the same mount. It mounts only
	// with an access decision: AdminIsAdminFlag admits a session whose user
	// carries the IsAdmin flag and nothing else (admin.router.ts:370). Set the
	// flag on the first administrator through the user store; from inside the
	// console, POST /admin/users/{id}/promote with {"method": "flag"} grants it
	// to the next.
	uiCfg := auth.DefaultHTTPConfig()
	uiCfg.UI.Enabled = true
	uiCfg.UI.Branding = auth.UIBranding{SiteName: "Echo + SQLite Example"}
	uiCfg.Admin.Enabled = true
	uiCfg.Admin.AccessPolicy = auth.AdminIsAdminFlag()
	echoAdapter.MountWithConfig(e.Group(""), a, uiCfg)

	// ── 4. OAuth login ────────────────────────────────────────────────────
	e.GET("/oauth/:provider/authorize", func(c echo.Context) error {
		// A real deployment must bind the state to the browser session; this
		// example only needs it to be unguessable per request. A timestamp will
		// not do — the state is the CSRF defence on the callback.
		state, err := randomState()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		authURL, err := oauthSvc.AuthorizeURL(c.Param("provider"), state)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		return c.Redirect(http.StatusFound, authURL)
	})
	e.GET("/oauth/:provider/callback", func(c echo.Context) error {
		provider := c.Param("provider")
		info, err := oauthSvc.ExchangeCode(c.Request().Context(), provider, c.QueryParam("code"))
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		user, tokens, err := oauthSvc.HandleCallback(c.Request().Context(), svc, linkedAccounts, info, "", "")
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		// Never serialise the raw User: it carries the password hash and the TOTP
		// secret. NewPublicUser is the response-safe projection the auth routes use.
		return c.JSON(http.StatusOK, map[string]any{
			"success":      true,
			"user":         auth.NewPublicUser(user),
			"accessToken":  tokens.AccessToken,
			"refreshToken": tokens.RefreshToken,
		})
	})

	// Nothing is left to mount by hand for the UI: the hosted pages are at
	// /auth/ui (mounted above), auth.js with them at /auth/ui/auth.js, which is
	// where those pages load it from, and the admin console at /admin.

	addr := getEnv("ADDR", ":8080")
	log.Printf("listening on %s", addr)
	log.Fatal(e.Start(addr))
}

// ── SQLite store skeleton ──────────────────────────────────────────────────
// Implement with your preferred SQLite driver:
//
// type SQLiteUserStore struct{ db *sql.DB }
// func (s *SQLiteUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) { ... }
// func (s *SQLiteUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) { ... }
// func (s *SQLiteUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) { ... }

func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
