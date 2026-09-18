package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The admin console's OpenAPI document, and the two routes that serve it.

// TestAdminOpenAPIPathsFollowTheFlags pins which path items each flag selects,
// which is the reference's whole conditional structure (openapi.ts:672-1234).
func TestAdminOpenAPIPathsFollowTheFlags(t *testing.T) {
	base := DefaultAdminPath
	unconditional := []string{
		base + AdminPingPath,
		base + AdminUsersPath,
		base + AdminUsersPath + "/{id}",
		base + AdminTwoFAPolicyPath,
	}

	document := GenerateAdminOpenAPISpec(AdminOpenAPIInfo{})
	paths := specPaths(t, document)
	for _, path := range unconditional {
		if _, ok := paths[path]; !ok {
			t.Errorf("a document with no flags omits %q, which is unconditional there", path)
		}
	}
	if len(paths) != len(unconditional) {
		t.Errorf("a document with no flags describes %v, want only the four unconditional paths",
			adminSortedKeys(paths))
	}

	cases := []struct {
		name string
		info AdminOpenAPIInfo
		adds []string
	}{
		{"metadata", AdminOpenAPIInfo{Metadata: true}, []string{
			base + AdminUsersPath + "/{id}/metadata",
		}},
		{"linked accounts", AdminOpenAPIInfo{LinkedAccounts: true}, []string{
			base + AdminUsersPath + "/{id}/linked-accounts",
		}},
		{"roles", AdminOpenAPIInfo{Roles: true}, []string{
			base + AdminUsersPath + "/{id}/roles",
			base + AdminUsersPath + "/{id}/roles/{role}",
			base + AdminRolesPath,
			base + AdminRolesPath + "/{name}",
		}},
		{"tenants", AdminOpenAPIInfo{Tenants: true}, []string{
			base + AdminUsersPath + "/{id}/tenants",
			base + AdminTenantsPath,
			base + AdminTenantsPath + "/{id}",
			base + AdminTenantsPath + "/{id}/users",
			base + AdminTenantsPath + "/{id}/users/{userId}",
		}},
		{"settings", AdminOpenAPIInfo{Settings: true}, []string{base + AdminSettingsPath}},
		{"sessions", AdminOpenAPIInfo{Sessions: true}, []string{
			base + AdminSessionsPath,
			base + AdminSessionsPath + "/{handle}",
		}},
		{"api keys", AdminOpenAPIInfo{APIKeys: true}, []string{
			base + "/api/api-keys",
			base + "/api/api-keys/{id}",
			base + "/api/api-keys/{id}/revoke",
		}},
		{"webhooks", AdminOpenAPIInfo{Webhooks: true}, []string{
			base + "/api/webhooks",
			base + "/api/webhooks/{id}",
		}},
		// The reference's dead flag. Both paths are ones the admin router has
		// never served, and nothing sets it; see openapi_admin.go's header.
		{"the ui flag nothing sets", AdminOpenAPIInfo{UI: true}, []string{
			base + "/api/ui-settings",
			base + "/api/ui/logo",
		}},
		{"the documentation pair", AdminOpenAPIInfo{Docs: true}, []string{
			base + AdminOpenAPIPath,
			base + AdminDocsPath,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := specPaths(t, GenerateAdminOpenAPISpec(c.info))
			for _, path := range c.adds {
				if _, ok := got[path]; !ok {
					t.Errorf("the flag does not add %q", path)
				}
			}
			if len(got) != len(unconditional)+len(c.adds) {
				t.Errorf("document describes %v, want the four unconditional paths plus %v",
					adminSortedKeys(got), c.adds)
			}
		})
	}
}

// TestAdminOpenAPIBasePath pins that every path item is written below the
// configured base and that the base is the admin mount by default — the
// reference's `basePath = '/admin'` (openapi.ts:674), read against
// AdminOptions.Docs.BasePath here.
func TestAdminOpenAPIBasePath(t *testing.T) {
	for _, base := range []string{"", "/admin", "/edge/console"} {
		document := GenerateAdminOpenAPISpec(AdminOpenAPIInfo{BasePath: base, Sessions: true})
		want := base
		if want == "" {
			want = DefaultAdminPath
		}
		for path := range specPaths(t, document) {
			if !strings.HasPrefix(path, want+"/") {
				t.Errorf("BasePath %q produced the path %q", base, path)
			}
		}
	}

	for input, want := range map[string]string{
		"":               DefaultAdminPath,
		"  ":             DefaultAdminPath,
		"edge/console":   "/edge/console",
		"/edge/console/": "/edge/console",
	} {
		cfg := HTTPConfig{Admin: AdminOptions{Docs: DocsOptions{BasePath: input}}}
		if got := cfg.AdminDocsBasePath(); got != want {
			t.Errorf("AdminDocsBasePath(%q) = %q, want %q", input, got, want)
		}
	}
	// The default follows the mount, not the literal: a console at /back/office
	// describes itself there.
	cfg := HTTPConfig{Admin: AdminOptions{Path: "/back/office"}}
	if got := cfg.AdminDocsBasePath(); got != "/back/office" {
		t.Errorf("AdminDocsBasePath() = %q, want the admin mount", got)
	}
}

// TestAdminOpenAPIInfoFollowsTheStores pins that the eight flags are the
// console's own feature flags, so the document and the SPA's tabs cannot come to
// disagree.
func TestAdminOpenAPIInfoFollowsTheStores(t *testing.T) {
	cfg := uploadConfig()
	cfg.Admin.Docs.Enabled = true

	bare, err := New(WithUserStore(NewMemoryUserStore()), WithSessionStore(NewMemorySessionStore()))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	info := bare.AdminOpenAPIInfo(cfg)
	if info.Roles || info.Tenants || info.Metadata || info.Settings || info.LinkedAccounts {
		t.Errorf("a deployment with no optional stores produced %+v", info)
	}
	if !info.Docs {
		t.Error("Docs must follow AdminOptions.Docs.Enabled")
	}
	// Never set from a configuration, at any wiring. See openapi_admin.go.
	if info.UI {
		t.Error("AdminOpenAPIInfo.UI must never be set from a configuration")
	}

	full := newAdminOpenAPIAuth(t)
	info = full.AdminOpenAPIInfo(cfg)
	if !info.Roles || !info.Tenants || !info.Metadata || !info.Settings || !info.LinkedAccounts {
		t.Errorf("a fully wired deployment produced %+v", info)
	}
	if info.BasePath != cfg.AdminDocsBasePath() {
		t.Errorf("BasePath = %q, want %q", info.BasePath, cfg.AdminDocsBasePath())
	}
}

// TestAdminOpenAPIDocumentMatchesTheMount is the forward direction: every
// operation the document describes is a route this handler routes.
//
// Only the forward direction. The reference's document is deliberately smaller
// than its router — see openapi_admin.go — and the routes it leaves out are
// pinned below instead, so that neither list can drift unnoticed.
func TestAdminOpenAPIDocumentMatchesTheMount(t *testing.T) {
	a := newAdminOpenAPIAuth(t)
	cfg := uploadConfig()
	cfg.Admin.Docs.Enabled = true
	handler := a.AdminHandler(cfg)

	paths := specPaths(t, GenerateAdminOpenAPISpec(a.AdminOpenAPIInfo(cfg)))
	parameter := regexp.MustCompile(`\{[^}]+\}`)
	for path, item := range paths {
		operations, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("path item %q = %#v, want an object", path, item)
		}
		target := parameter.ReplaceAllString(path, "probe")
		for method := range operations {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(strings.ToUpper(method), target, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rec, req)
			// The router's own 404 is Go's plain-text one; a handler's 404 —
			// "User not found" for the probe id above — is the admin envelope
			// and means the route exists.
			if rec.Code == http.StatusMethodNotAllowed ||
				(rec.Code == http.StatusNotFound && strings.Contains(rec.Body.String(), "404 page not found")) {
				t.Errorf("%s %s is documented and is not mounted (%d)", method, target, rec.Code)
			}
		}
	}
}

// adminUndocumentedPaths is the reverse direction of the admin document,
// spelled out rather than derived: the routes the console mounts and the
// reference's generator does not describe, the four upload routes included,
// each with the reason. Relative to the admin mount, as the constants are.
//
// It is a stop-point. A PR that decides the document should grow one of these
// has to delete its line here, which is exactly the visibility a deliberate
// divergence from a transcription needs. Two tests read it:
// TestAdminOpenAPIOmitsWhatTheReferenceOmits holds the document to it, and
// TestVendoredAssetsCallRoutesThatExist (ui_upstream_test.go) lets a call in
// the vendored admin SPA resolve to one of these, since a route the SPA calls
// and the document leaves out is still a route the console serves.
var adminUndocumentedPaths = map[string]string{
	AdminPromoteUsersPath + "/{id}" + AdminPromoteSuffix: "the promote route, which the dev " +
		"line's own generator does not describe either — so the one route that grants the " +
		"admin console is the one route the document does not mention",
	AdminShellPath:                  "the SPA shell",
	AdminCSSPath:                    "a static asset",
	AdminJSPath:                     "a static asset",
	AdminLoginPath:                  "the console's own login",
	AdminLogoutPath:                 "the console's own logout",
	AdminActionsPath:                "the action registry listing",
	AdminSettingsUIPath:             "the branding patch, which hasUi describes at /api/ui-settings instead",
	AdminMailTemplatesPath:          "the mail template routes",
	AdminUITemplatesPath:            "the UI translation routes",
	AdminUploadLogoPath:             "the logo upload, which hasUi describes at /api/ui/logo instead",
	AdminUploadBGImagePath:          "the background upload",
	AdminUploadFilesPath:            "the upload listing",
	AdminUploadPath + "/{filename}": "the upload delete",
}

// TestAdminOpenAPIOmitsWhatTheReferenceOmits holds the document to
// adminUndocumentedPaths: none of them is described.
func TestAdminOpenAPIOmitsWhatTheReferenceOmits(t *testing.T) {
	a := newAdminOpenAPIAuth(t)
	cfg := uploadConfig()
	cfg.Admin.Docs.Enabled = true
	paths := specPaths(t, GenerateAdminOpenAPISpec(a.AdminOpenAPIInfo(cfg)))

	base := cfg.AdminDocsBasePath()
	for rel, what := range adminUndocumentedPaths {
		if _, ok := paths[base+rel]; ok {
			t.Errorf("the document describes %q (%s), which the reference's does not", base+rel, what)
		}
	}
}

// TestAdminDocsRoutesAreUnguarded is the asymmetry this PR decided in the open:
// every route under /api/* is registered with the guard except these two, which
// the reference registers without it (admin.router.ts:1499, :1517).
//
// The policy here is AdminIsAdminFlag with no credential presented, so every
// guarded route answers 401 and these two must not.
func TestAdminDocsRoutesAreUnguarded(t *testing.T) {
	a := newAdminOpenAPIAuth(t)
	cfg := uploadConfig()
	cfg.Admin.AccessPolicy = AdminIsAdminFlag()
	cfg.Admin.Docs.Enabled = true
	handler := a.AdminHandler(cfg)

	// The guard is real: a neighbouring route refuses the same anonymous caller.
	rec := adminDocsGet(handler, AdminPingPath)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET %s = %d, want 401 — the guard must be in force for this case to mean anything",
			AdminPingPath, rec.Code)
	}

	rec = adminDocsGet(handler, AdminOpenAPIPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 to an anonymous caller", AdminOpenAPIPath, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var served map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &served); err != nil {
		t.Fatalf("decode the served document: %v", err)
	}
	if served["openapi"] != "3.0.3" {
		t.Errorf("openapi = %v, want 3.0.3", served["openapi"])
	}
	// The served document is this mount's, not a default: it carries the flags
	// the adapter was configured with.
	if _, ok := specPaths(t, served)[cfg.AdminDocsBasePath()+AdminSessionsPath]; !ok {
		t.Error("the served document omits the session routes this deployment mounts")
	}

	rec = adminDocsGet(handler, AdminDocsPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 to an anonymous caller", AdminDocsPath, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	page := rec.Body.String()
	if !strings.Contains(page, cfg.AdminDocsBasePath()+AdminOpenAPIPath) {
		t.Errorf("the page does not fetch the document beside it:\n%s", page)
	}
	// The reference's one page builder serves all three of its routers, so the
	// title says "Tools API" on the admin console too. Third reproduction.
	if !strings.Contains(page, "Tools API") {
		t.Error("the Swagger page must be the shared one, quirk included")
	}
}

// TestAdminDocsRoutesAreOptIn is the other half: off by default, where the
// reference's `swagger: 'auto'` serves them everywhere except under
// NODE_ENV=production. The docs-routes-are-opt-in deviation covers all three
// routers now.
func TestAdminDocsRoutesAreOptIn(t *testing.T) {
	a := newAdminOpenAPIAuth(t)
	handler := a.AdminHandler(uploadConfig())
	for _, rel := range []string{AdminOpenAPIPath, AdminDocsPath} {
		if rec := adminDocsGet(handler, rel); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d with Docs.Enabled unset, want 404", rel, rec.Code)
		}
	}
}

// TestAdminOpenAPISecurity pins the one thing the document says about the
// asymmetry above: every operation declares AdminAuth except the two
// documentation ones, which declare nothing because they require nothing.
func TestAdminOpenAPISecurity(t *testing.T) {
	document := GenerateAdminOpenAPISpec(AdminOpenAPIInfo{
		Sessions: true, Roles: true, Tenants: true, Metadata: true,
		Settings: true, LinkedAccounts: true, APIKeys: true, Webhooks: true, Docs: true,
	})
	base := DefaultAdminPath
	public := map[string]bool{base + AdminOpenAPIPath: true, base + AdminDocsPath: true}

	for path, item := range specPaths(t, document) {
		for method, operation := range item.(map[string]any) {
			fields, ok := operation.(map[string]any)
			if !ok {
				t.Fatalf("%s %s = %#v, want an object", method, path, operation)
			}
			_, declared := fields["security"]
			if public[path] && declared {
				t.Errorf("%s %s declares security, and it requires none", method, path)
			}
			if !public[path] && !declared {
				t.Errorf("%s %s declares no security, and every other operation does", method, path)
			}
		}
	}

	schemes, ok := document["components"].(map[string]any)["securitySchemes"].(map[string]any)
	if !ok || len(schemes) != 1 {
		t.Fatalf("securitySchemes = %#v, want the one AdminAuth scheme", schemes)
	}
	if _, ok := schemes["AdminAuth"]; !ok {
		t.Errorf("securitySchemes = %v, want AdminAuth", schemes)
	}
}

// TestAdminOpenAPITags pins the tags block's order and its conditional entries
// (openapi.ts:1334-1344), which is the one list in the document where order is
// part of the value.
func TestAdminOpenAPITags(t *testing.T) {
	names := func(info AdminOpenAPIInfo) []string {
		document := GenerateAdminOpenAPISpec(info)
		tags, ok := document["tags"].([]map[string]any)
		if !ok {
			t.Fatalf("tags = %#v, want a list", document["tags"])
		}
		out := make([]string, 0, len(tags))
		for _, tag := range tags {
			out = append(out, tag["name"].(string))
		}
		return out
	}

	got := names(AdminOpenAPIInfo{})
	want := []string{"Admin", "Admin — Users"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("tags with no flags = %v, want %v", got, want)
	}

	got = names(AdminOpenAPIInfo{Sessions: true, Roles: true, Tenants: true, Settings: true,
		APIKeys: true, Webhooks: true, UI: true, Docs: true})
	want = []string{
		"Admin", "Admin — Users", "Admin — Sessions", "Admin — Roles", "Admin — Tenants",
		"Admin — Settings", "Admin — API Keys", "Admin — Webhooks", "Admin — UI", "Docs",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("tags = %v, want %v", got, want)
	}

	// Metadata and LinkedAccounts add path items and no tag of their own: their
	// operations are tagged "Admin — Users", which is unconditional.
	if got := names(AdminOpenAPIInfo{Metadata: true, LinkedAccounts: true}); len(got) != 2 {
		t.Errorf("tags = %v, want no tag for metadata or linked accounts", got)
	}
}

// TestAdminOpenAPISchemasAreUnconditional pins that the components block is
// built whole whatever the flags say, as the reference builds it
// (openapi.ts:1236-1332) — a $ref a conditional path item resolves against has
// to be there in every document that can contain that item.
func TestAdminOpenAPISchemasAreUnconditional(t *testing.T) {
	want := []string{
		"SuccessResponse", "AdminUser", "AdminSession", "AdminTenant",
		"AdminSettings", "AdminApiKey", "AdminWebhook", "UiSettings",
	}
	for _, info := range []AdminOpenAPIInfo{{}, {Sessions: true, Roles: true, Tenants: true}} {
		schemas, ok := GenerateAdminOpenAPISpec(info)["components"].(map[string]any)["schemas"].(map[string]any)
		if !ok {
			t.Fatal("components.schemas is missing")
		}
		if len(schemas) != len(want) {
			t.Errorf("schemas = %v, want all eight in every document", adminSortedKeys(schemas))
		}
		for _, name := range want {
			if _, ok := schemas[name]; !ok {
				t.Errorf("schemas is missing %q", name)
			}
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// newAdminOpenAPIAuth wires every store the eight flags read, so the document is
// generated at its widest. The API-key and webhook flags stay false because
// adminFeatures reports them false until U14b lands, which is the whole point of
// deriving the info from that function.
func newAdminOpenAPIAuth(t *testing.T) *Auth {
	t.Helper()
	a, err := New(
		WithUserStore(NewMemoryUserStore()),
		WithSessionStore(NewMemorySessionStore()),
		WithRBACProvider(NewMemoryRolesPermissionsStore()),
		WithTenantProvider(NewMemoryTenantStore()),
		WithMetadataProvider(NewMemoryMetadataStore()),
		WithSettingsStore(NewMemorySettingsStore()),
		WithTemplateStore(NewMemoryTemplateStore()),
		WithUploadStore(NewMemoryUploadStore()),
		WithOAuth(OAuthWiring{LinkedAccounts: NewMemoryLinkedAccounts()}),
	)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

func adminDocsGet(handler http.Handler, rel string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin"+rel, nil))
	return rec
}

func specPaths(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	paths, ok := document["paths"].(map[string]any)
	if !ok {
		t.Fatalf("paths = %#v, want an object", document["paths"])
	}
	return paths
}

func adminSortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
