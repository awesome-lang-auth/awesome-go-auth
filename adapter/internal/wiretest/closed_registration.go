package wiretest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// Closed registration: HTTPConfig.ClosedRegistration, the reference's
// deployment without an onRegister hook (auth.router.ts:712-715,
// ui.router.ts:115).
//
// It has four surfaces and this file pins each of them on every adapter:
// POST <prefix>/register is not mounted, GET <prefix>/ui/config answers
// features.register false, the page the built-in UI renders carries that same
// flag in its injected config (which is what hides the sign-up link), and the
// OpenAPI document leaves the path out. The last of those is also held to the
// mount in both directions by closedRegistrationRouteSet, registered in
// conditionalRoutes.
//
// What stays is pinned beside what goes: the rest of the credential set,
// Service.Register for the host, and the <prefix>/ui/register page, which the
// reference serves without a hook too.

// closedRegistrationRouteSet is the conditional set for
// HTTPConfig.ClosedRegistration. Like the resource-server set it subtracts: it
// adds no route and removes the one the flag unmounts.
func closedRegistrationRouteSet() conditionalRouteSet {
	return conditionalRouteSet{
		name:      "ClosedRegistration",
		configure: func(pc *probeConfig) { pc.HTTP.ClosedRegistration = true },
		removes:   map[string]string{auth.RegisterRoute: http.MethodPost},
		spec:      func() auth.OpenAPIInfo { return auth.OpenAPIInfo{ClosedRegistration: true} },
	}
}

func closedRegistrationConfig() auth.HTTPConfig {
	cfg := auth.DefaultHTTPConfig()
	cfg.ClosedRegistration = true
	return cfg
}

func testClosedRegistration(t *testing.T, mount Mounter) {
	t.Run("POST /register is not mounted", func(t *testing.T) {
		env := NewEnv(t, mount, closedRegistrationConfig())
		const email = "closed@example.com"
		rec := env.Do(env.Request(http.MethodPost, auth.RegisterRoute, map[string]string{
			"email": email, "password": "password1", "tenantId": testTenant,
		}))
		// Only the status: an unregistered path is answered by the router, and
		// the four routers write four different bodies — the reference's
		// hookless route falls through to the application's 404 the same way.
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST /register = %d, want 404 with ClosedRegistration (body %q)", rec.Code, rec.Body.String())
		}
		// And nothing was created behind it: the route is gone, not refusing.
		if _, err := env.Auth.Service().FindUser(context.Background(), "", email, testTenant); err == nil {
			t.Fatal("an account exists for the address the closed route was sent")
		}
		// The flag is what unmounts it: the same adapter without it serves the
		// route.
		open := NewEnv(t, mount, auth.DefaultHTTPConfig())
		AssertStatus(t, open.Do(open.Request(http.MethodPost, auth.RegisterRoute, credentials(email))), http.StatusCreated)
	})

	t.Run("the host still registers, and the account logs in", func(t *testing.T) {
		// Invitations and admin-created accounts go through Service.Register,
		// which the flag leaves alone; the account it creates is an ordinary one.
		env := NewEnv(t, mount, closedRegistrationConfig())
		const email = "invited@example.com"
		if _, _, err := env.Auth.Register(context.Background(), auth.RegisterInput{Email: email, Password: "password1", TenantID: testTenant}); err != nil {
			t.Fatalf("Auth.Register with ClosedRegistration: %v", err)
		}
		rec := env.Do(env.Request(http.MethodPost, "/login", credentials(email)))
		AssertStatus(t, rec, http.StatusOK)
		Cookie(t, rec, hostAccess)
	})

	t.Run("the rest of the credential set stays mounted", func(t *testing.T) {
		env := NewEnv(t, mount, closedRegistrationConfig())
		for route, method := range auth.ResourceServerGatedRoutes() {
			if route == auth.RegisterRoute {
				continue
			}
			rec := env.Do(env.Request(method, route, map[string]string{}))
			if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d with ClosedRegistration, want it still mounted (body %q)",
					method, route, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("ui/config reports register false", func(t *testing.T) {
		cfg := uiHTTPConfig()
		cfg.ClosedRegistration = true
		features := uiObject(t, uiDocument(t, NewEnv(t, mount, cfg), ""), "features")
		if features["register"] != false {
			t.Errorf("features.register = %#v with ClosedRegistration, want false", features["register"])
		}
		// Only that flag moves: the document keeps all eight.
		AssertKeys(t, features, "register", "magicLink", "sms", "google", "github",
			"forgotPassword", "verifyEmail", "twoFactor")

		open := uiObject(t, uiDocument(t, NewEnv(t, mount, uiHTTPConfig()), ""), "features")
		if open["register"] != true {
			t.Errorf("features.register = %#v without ClosedRegistration, want true", open["register"])
		}
	})

	t.Run("the rendered login page is told to hide sign-up", func(t *testing.T) {
		// The vendored login.html shows its "Sign up" link only when
		// AuthService.config.features.register is true, and the config it reads
		// is the object the SSR injection writes into the page. So the flag in
		// that object is the whole of "the hosted UI hides sign-up".
		cfg := uiHTTPConfig()
		cfg.ClosedRegistration = true
		env := NewEnv(t, mount, cfg)
		for _, page := range []string{"", "/login"} {
			rec := uiPageRequest(t, env, page)
			AssertStatus(t, rec, http.StatusOK)
			if !strings.Contains(rec.Body.String(), `data-feature="register"`) {
				t.Fatalf("%s: the page has no register affordance to hide; the assertion below would prove nothing", uiPageName(page))
			}
			features := injectedFeatures(t, rec.Body.String())
			if features["register"] != false {
				t.Errorf("%s: injected features.register = %#v, want false", uiPageName(page), features["register"])
			}
		}
		open := NewEnv(t, mount, uiHTTPConfig())
		if got := injectedFeatures(t, uiPageRequest(t, open, "/login").Body.String())["register"]; got != true {
			t.Errorf("injected features.register = %#v without ClosedRegistration, want true", got)
		}
	})

	t.Run("the register page is still served", func(t *testing.T) {
		// The reference serves register.html whether or not onRegister is set:
		// its catch-all renders any page it has a file for. Closing
		// registration hides the link to it, and leaves the page — whose form
		// posts to a route that is no longer there — as the reference does.
		cfg := uiHTTPConfig()
		cfg.ClosedRegistration = true
		rec := uiPageRequest(t, NewEnv(t, mount, cfg), "/register")
		AssertStatus(t, rec, http.StatusOK)
		if got := injectedFeatures(t, rec.Body.String())["register"]; got != false {
			t.Errorf("injected features.register = %#v on the register page, want false", got)
		}
	})

	t.Run("the served OpenAPI document omits /register", func(t *testing.T) {
		cfg := closedRegistrationConfig()
		cfg.Docs.Enabled = true
		paths := servedOpenAPIPaths(t, NewEnv(t, mount, cfg))
		if _, ok := paths[cfg.Prefix()+auth.RegisterRoute]; ok {
			t.Errorf("the served document describes %s with ClosedRegistration", cfg.Prefix()+auth.RegisterRoute)
		}
		if _, ok := paths[cfg.Prefix()+"/login"]; !ok {
			t.Errorf("the served document lost %s, which closed registration does not touch", cfg.Prefix()+"/login")
		}

		open := auth.DefaultHTTPConfig()
		open.Docs.Enabled = true
		if _, ok := servedOpenAPIPaths(t, NewEnv(t, mount, open))[open.Prefix()+auth.RegisterRoute]; !ok {
			t.Errorf("the served document omits %s without ClosedRegistration", open.Prefix()+auth.RegisterRoute)
		}
	})

	t.Run("together with resource-server mode", func(t *testing.T) {
		// Two switches over the same route must not register it twice or fail
		// to mount: the route is simply absent, as under either one alone.
		cfg := closedRegistrationConfig()
		cfg.ResourceServer = true
		env := NewEnv(t, mount, cfg)
		rec := env.Do(env.Request(http.MethodPost, auth.RegisterRoute, credentials("both@example.com")))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST /register = %d under both switches, want 404", rec.Code)
		}
	})
}

// injectedFeatures reads the features object out of the config the SSR
// injection writes into a rendered page:
//
//	<script>window.__AUTH_CONFIG__ = {…};</script>
func injectedFeatures(t *testing.T, page string) map[string]any {
	t.Helper()
	const open, closing = "window.__AUTH_CONFIG__ = ", ";</script>"
	start := strings.Index(page, open)
	if start < 0 {
		t.Fatalf("the page carries no injected config: %.200q", page)
	}
	rest := page[start+len(open):]
	end := strings.Index(rest, closing)
	if end < 0 {
		t.Fatalf("the injected config is not terminated: %.200q", rest)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(rest[:end]), &config); err != nil {
		t.Fatalf("decode injected config %.200q: %v", rest[:end], err)
	}
	features, ok := config["features"].(map[string]any)
	if !ok {
		t.Fatalf("the injected config has no features object: %#v", config["features"])
	}
	return features
}

// servedOpenAPIPaths fetches GET <prefix>/openapi.json and returns its paths.
func servedOpenAPIPaths(t *testing.T, env *Env) map[string]any {
	t.Helper()
	rec := env.Do(env.Request(http.MethodGet, auth.DocsSpecPath, nil))
	AssertStatus(t, rec, http.StatusOK)
	paths, ok := Body(t, rec)["paths"].(map[string]any)
	if !ok {
		t.Fatalf("the served document has no paths object: %.200q", rec.Body.String())
	}
	return paths
}
