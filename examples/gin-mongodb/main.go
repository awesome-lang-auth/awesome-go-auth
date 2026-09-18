// Gin + MongoDB example for awesome-go-auth.
//
// It wires the Gin adapter, the OIDC identity-provider endpoints and the
// generated OpenAPI spec. The Mongo store is left as a comment skeleton — swap
// NewMemoryUserStore for your go.mongodb.org/mongo-driver implementation.
//
//	go run ./examples/gin-mongodb
//
// This file is compiled by `go build ./...`, so it cannot drift away from the
// library API without CI noticing.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
	ginAdapter "github.com/nik2208/awesome-go-auth/adapter/gin"
)

func main() {
	// ── 1. Build the auth instance ─────────────────────────────────────────
	a, err := auth.New(
		auth.WithSecret(getEnv("AUTH_SECRET", "change-me-in-production-32bytes!!")),
		auth.WithIssuer("https://api.example.com"),
		auth.WithTokenTTLs(15*time.Minute, 7*24*time.Hour),
		// Swap for your MongoUserStore:
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
		auth.WithMetadataProvider(auth.NewMemoryMetadataStore()),
		auth.WithRBACProvider(auth.NewMemoryRolesPermissionsStore()),
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
	)
	if err != nil {
		log.Fatalf("auth init: %v", err)
	}
	svc := a.Service()

	// ── 2. OIDC IDP (optional) ─────────────────────────────────────────────
	// Issuer carries the /oidc mount prefix below, because the discovery
	// document derives every endpoint from it — including jwks_uri, which has to
	// resolve to the JWKS route RegisterHandlers actually serves. That also puts
	// /oidc in the iss claim of every token this IdP mints; a deployment that
	// needs a bare iss leaves Issuer alone and sets IDPConfig.JWKSURL to the
	// absolute JWKS URL instead. See README_DETAILED.md, "OIDC IDP".
	idp, err := auth.NewIDP(
		auth.IDPConfig{
			Issuer:         "https://auth.example.com/oidc",
			AccessTokenTTL: 15 * time.Minute,
			IDTokenTTL:     time.Hour,
		},
		svc,
		auth.IDPClient{
			ClientID:     "webapp",
			ClientSecret: getEnv("IDP_CLIENT_SECRET", "secret"),
			RedirectURIs: []string{"https://app.example.com/callback"},
			Name:         "Web App",
		},
	)
	if err != nil {
		log.Fatalf("idp init: %v", err)
	}

	// ── 3. Gin router ─────────────────────────────────────────────────────
	if getEnv("GIN_MODE", "") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()

	// One call mounts every auth route under the configured prefix (/auth by
	// default). Mounting on a group works too — the CSRF middleware locates the
	// prefix on any segment boundary.
	//
	// Docs.Enabled adds GET /auth/openapi.json (the generated document for this
	// mount) and GET /auth/docs (the Swagger UI page reading it). The library
	// takes a plain bool and never reads the environment itself, so resolving
	// what the reference resolves against NODE_ENV is this one line. Leave it
	// off in production: the UI page loads swagger-ui-dist from the unpkg CDN
	// onto the auth origin.
	//
	// UI.Enabled mounts the hosted UI at /auth/ui: the login, register,
	// forgot-password and 2FA pages, the config document they boot from, and
	// auth.js beside them — the pages load it from /auth/ui/auth.js, so it
	// needs no route of its own. Branding is optional — with none, the pages
	// render the library's defaults.
	//
	// Admin mounts the admin console at /admin — beside the auth mount, not
	// under it, as the reference's admin router is a sibling of its auth router
	// — with the reference's own SPA served from the same mount. It mounts only
	// with an access decision: AdminIsAdminFlag admits a session whose user
	// carries the IsAdmin flag and nothing else (admin.router.ts:370). Set the
	// flag on the first administrator through the user store; from inside the
	// console, POST /admin/users/{id}/promote with {"method": "flag"} grants it
	// to the next.
	cfg := auth.DefaultHTTPConfig()
	cfg.Docs.Enabled = getEnv("APP_ENV", "development") != "production"
	cfg.UI.Enabled = true
	cfg.UI.Branding = auth.UIBranding{SiteName: "Gin + MongoDB Example"}
	cfg.Admin.Enabled = true
	cfg.Admin.AccessPolicy = auth.AdminIsAdminFlag()
	ginAdapter.MountWithConfig(r, a, cfg)

	// OIDC IDP endpoints, on a mux of this application's own, under /oidc.
	//
	// The other way is auth.WithIDP(idp) on auth.New above, after which
	// ginAdapter.Mount serves the JWKS document and the four OIDC endpoints
	// under the auth prefix instead — /auth/authorize, /auth/token,
	// /auth/userinfo and /auth/.well-known/openid-configuration — with Issuer
	// carrying that prefix rather than /oidc. Pick one: doing both puts the
	// same endpoints at two URLs, and on a single net/http mux it panics at
	// mount time. See README_DETAILED.md, "OIDC IDP".
	oidcMux := http.NewServeMux()
	idp.RegisterHandlers(oidcMux, "/oidc/")
	r.Any("/oidc/*path", gin.WrapH(oidcMux))

	// A second copy of the document, at the root and under this app's own name.
	// The mount already serves one at /auth/openapi.json (see Docs.Enabled
	// above); this is the exported handler, for a host that wants the document
	// somewhere else or wants to fill in the fields that name its API rather
	// than the library's. APIPrefix must match the mount.
	r.GET("/openapi.json", gin.WrapH(auth.OpenAPIHandler(auth.OpenAPIInfo{
		Title:     "My App API",
		ServerURL: "https://api.example.com",
		APIPrefix: cfg.Prefix(),
		Docs:      cfg.Docs.Enabled,
	})))

	addr := getEnv("ADDR", ":8080")
	log.Printf("listening on %s", addr)
	log.Fatal(r.Run(addr))
}

// ── MongoDB store skeleton ─────────────────────────────────────────────────
// Implement these when you add a mongo-driver dependency:
//
// type MongoUserStore struct{ coll *mongo.Collection }
// func (s *MongoUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) { ... }
// func (s *MongoUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) { ... }
// func (s *MongoUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) { ... }

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
