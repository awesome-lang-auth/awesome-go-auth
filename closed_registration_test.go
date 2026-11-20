package auth

import (
	"context"
	"testing"
)

// TestRegisterMounted is the condition the four adapters read before they
// register POST <prefix>/register: either switch takes the route away, and only
// the configuration with neither mounts it.
func TestRegisterMounted(t *testing.T) {
	for _, tc := range []struct {
		name           string
		resourceServer bool
		closed         bool
		want           bool
	}{
		{"neither", false, false, true},
		{"closed registration", false, true, false},
		{"resource server", true, false, false},
		{"both", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultHTTPConfig()
			cfg.ResourceServer = tc.resourceServer
			cfg.ClosedRegistration = tc.closed
			if got := cfg.RegisterMounted(); got != tc.want {
				t.Errorf("RegisterMounted() = %v, want %v", got, tc.want)
			}
		})
	}
	if !DefaultHTTPConfig().RegisterMounted() {
		t.Error("the default configuration does not mount POST /register; closing registration must be opt-in")
	}
}

// TestUIConfigRegisterFollowsClosedRegistration: features.register is the one
// flag the wire configuration decides. It answers false under
// ClosedRegistration — the reference's hookless deployment — and true
// otherwise, and closing registration moves no other flag.
func TestUIConfigRegisterFollowsClosedRegistration(t *testing.T) {
	cfg := uiTestConfig()
	cfg.TwoFactorAppName = "Acme"
	a := uiTestAuth(t, cfg, uiTestOAuth("google"))

	open := DefaultHTTPConfig()
	closed := DefaultHTTPConfig()
	closed.ClosedRegistration = true

	openFeatures := a.UIConfig(context.Background(), nil, open).Features
	closedFeatures := a.UIConfig(context.Background(), nil, closed).Features
	if !openFeatures.Register {
		t.Error("features.register = false without ClosedRegistration, want true")
	}
	if closedFeatures.Register {
		t.Error("features.register = true with ClosedRegistration, want false")
	}
	closedFeatures.Register = true
	if closedFeatures != openFeatures {
		t.Errorf("closing registration moved another flag:\nopen   %+v\nclosed %+v", openFeatures, closedFeatures)
	}

	// Resource-server mode unmounts the route too, and the flag does not follow
	// it there: that half of register-route-is-always-mounted is unchanged.
	rs := DefaultHTTPConfig()
	rs.ResourceServer = true
	if !a.UIConfig(context.Background(), nil, rs).Features.Register {
		t.Error("features.register = false under ResourceServer alone, want true as before")
	}
}

// TestGenerateOpenAPISpecClosedRegistration: OpenAPIInfo.ClosedRegistration
// takes POST <prefix>/register out of the document and nothing else. The
// wiretest harness's "ClosedRegistration" set holds this to what the four
// adapters mount; this is the generator on its own.
func TestGenerateOpenAPISpecClosedRegistration(t *testing.T) {
	paths := func(info OpenAPIInfo) map[string]any {
		spec := GenerateOpenAPISpec(info)
		out, ok := spec["paths"].(map[string]any)
		if !ok {
			t.Fatalf("paths is %T", spec["paths"])
		}
		return out
	}

	for _, tc := range []struct{ name, prefix, want string }{
		{"the default prefix", "", DefaultAPIPrefix},
		{"a configured prefix", "/api/auth", "/api/auth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := paths(OpenAPIInfo{APIPrefix: tc.prefix})[tc.want+RegisterRoute]; !ok {
				t.Fatalf("%s is not documented without the flag", tc.want+RegisterRoute)
			}
			documented := paths(OpenAPIInfo{APIPrefix: tc.prefix, ClosedRegistration: true})
			if _, ok := documented[tc.want+RegisterRoute]; ok {
				t.Errorf("%s is documented with ClosedRegistration", tc.want+RegisterRoute)
			}
			if _, ok := documented[tc.want+"/login"]; !ok {
				t.Errorf("%s was dropped, and closed registration does not touch it", tc.want+"/login")
			}
		})
	}

	base := len(paths(OpenAPIInfo{}))
	if got := len(paths(OpenAPIInfo{ClosedRegistration: true})); got != base-1 {
		t.Errorf("OpenAPIInfo.ClosedRegistration removed %d paths, want 1", base-got)
	}
	// Under ResourceServer the route is already gone; adding the flag changes
	// nothing.
	if rs, both := len(paths(OpenAPIInfo{ResourceServer: true})), len(paths(OpenAPIInfo{ResourceServer: true, ClosedRegistration: true})); rs != both {
		t.Errorf("ResourceServer documents %d paths and ResourceServer+ClosedRegistration %d, want the same", rs, both)
	}
}
