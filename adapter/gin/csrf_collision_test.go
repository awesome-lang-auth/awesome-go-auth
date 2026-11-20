package gin_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
	ginadapter "github.com/nik2208/awesome-go-auth/adapter/gin"
	"golang.org/x/crypto/bcrypt"
)

// TestCSRFEnforcedUnderAPrefixCollidingGroup is the end-to-end half of
// TestCSRFManualCheckSurvivesAPrefixCollidingBasePath in the root package: proof
// that the colliding mount is a real deployment and not just a string the
// predicate can be handed.
//
// A host that groups its API under /auth and keeps the default /auth prefix serves
// /auth/auth/link-request. The CSRF middleware is told the prefix but never the
// base, so it used to resolve that path to "/auth/link-request" — in neither route
// table — and POST /auth/auth/link-request fell through to the cookie test. A
// forgery carries no cookie, so it was not enforced: this test used to see
// 200 {"success":true} with the link token written and the mail sent.
//
// One framework is enough to pin reachability; the predicate itself is shared by
// all four adapters and is pinned in the root package.
func TestCSRFEnforcedUnderAPrefixCollidingGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	pending := auth.NewMemoryPendingLinks()
	var delivered int
	a, err := auth.New(
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
		// The only Auth in the adapter suites not built by wiretest.NewEnv, so
		// it needs the same cheap cost; this test is about CSRF, not hashing.
		auth.WithBcryptCost(bcrypt.MinCost),
		auth.WithOAuth(auth.OAuthWiring{
			LinkedAccounts: auth.NewMemoryLinkedAccounts(),
			PendingLinks:   pending,
			SiteURL:        "https://app.example.com",
			TenantID:       "t1",
			DeliverLinkToken: func(_ context.Context, _ auth.LinkTokenDelivery) error {
				delivered++
				return nil
			},
		}),
	)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	if _, _, err := a.Register(context.Background(), auth.RegisterInput{
		Email: "collide@example.com", Password: "password1", TenantID: "t1",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// The stash is what stands in for authentication inside the handler, so it is
	// what makes the unenforced case an authenticated-equivalent write.
	if err := pending.Save(context.Background(), "pending-link:collide@example.com|acme", auth.OAuthPendingMeta{
		Provider: "acme", Email: "collide@example.com", ProviderAccountID: "acme-1", TenantID: "t1",
	}, time.Hour); err != nil {
		t.Fatalf("stash: %v", err)
	}

	engine := gin.New()
	ginadapter.MountWithConfig(engine.Group("/auth"), a, auth.DefaultHTTPConfig())

	body := func() *bytes.Reader {
		return bytes.NewReader([]byte(`{"email":"collide@example.com","provider":"acme"}`))
	}

	// The forgery: nothing on the request, and text/plain because auth.DecodeOptionalJSON does
	// not inspect Content-Type, so a plain <form enctype="text/plain"> reaches it.
	forged := httptest.NewRequest(http.MethodPost, "/auth/auth/link-request", body())
	forged.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, forged)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("forged POST /auth/auth/link-request = %d, want 403 (body %q, deliveries=%d)",
			rec.Code, rec.Body.String(), delivered)
	}
	if delivered != 0 {
		t.Fatalf("the refused forgery delivered %d link token(s)", delivered)
	}

	// The legitimate client is unaffected: a matching double-submit still passes at
	// the same colliding path, so the fix widened enforcement without breaking it.
	ok := httptest.NewRequest(http.MethodPost, "/auth/auth/link-request", body())
	ok.Header.Set("Content-Type", "application/json")
	ok.AddCookie(&http.Cookie{Name: "__Host-csrf-token", Value: "0123456789abcdef0123456789abcdef"})
	ok.Header.Set(auth.CSRFHeaderName, "0123456789abcdef0123456789abcdef")
	good := httptest.NewRecorder()
	engine.ServeHTTP(good, ok)
	if good.Code != http.StatusOK {
		t.Fatalf("legitimate POST /auth/auth/link-request = %d, want 200: %s", good.Code, good.Body.String())
	}
	if delivered != 1 {
		t.Fatalf("deliveries = %d, want 1 after the legitimate request", delivered)
	}
}
