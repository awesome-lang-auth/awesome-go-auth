package wiretest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// Conformance cases for the body bound of the public routes that send or
// spend a one-time credential: forgot-password, reset-password, the magic-link
// and SMS send and verify pairs, change-email/confirm, invitations/accept and
// the link-request/link-verify pair. Each refuses a body over 16 KiB with 413
// before anything reads it — the rate limiter included, which on some
// deployments decodes the body itself — and so before any account is looked
// up: the answer cannot differ by address.

// credentialBodyLimit is the bound, spelt out rather than read from the
// package so that the suite states the number it holds the adapters to.
const credentialBodyLimit = 16 << 10

// credentialRoutes are the bounded routes and a body each would accept, which
// the cases pad to the size they need.
var credentialRoutes = []struct {
	route  string
	fields map[string]string
}{
	{"/forgot-password", map[string]string{"email": "bodylimit@example.com", "tenantId": testTenant}},
	{"/reset-password", map[string]string{"token": "no-such-token", "password": "newpassword1"}},
	{"/magic-link/send", map[string]string{"email": "bodylimit@example.com", "tenantId": testTenant}},
	{"/magic-link/verify", map[string]string{"token": "no-such-token"}},
	{"/sms/send", map[string]string{"email": "bodylimit@example.com", "tenantId": testTenant}},
	{"/sms/verify", map[string]string{"userId": "usr_none", "code": "123456"}},
	{"/change-email/confirm", map[string]string{"token": "no-such-token"}},
	{auth.InvitationAcceptRoute, map[string]string{"token": "no-such-token", "password": "newpassword1"}},
	{"/link-request", map[string]string{"email": "bodylimit@example.com"}},
	{"/link-verify", map[string]string{"token": "no-such-token"}},
}

// paddedBody is fields encoded as JSON with a "pad" member sized so that the
// whole body is exactly size bytes. The routes ignore a member they do not
// read, so only the size can decide a refusal.
func paddedBody(t *testing.T, fields map[string]string, size int) []byte {
	t.Helper()
	with := func(pad string) []byte {
		body := map[string]string{"pad": pad}
		for k, v := range fields {
			body[k] = v
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return encoded
	}
	base := len(with(""))
	if size < base {
		t.Fatalf("a %d-byte body cannot hold %v", size, fields)
	}
	return with(string(bytes.Repeat([]byte("a"), size-base)))
}

// bodyRequest builds a POST carrying body; unsized hides its length, as a
// chunked request does, so the bound cannot rely on Content-Length.
func bodyRequest(env *Env, route string, body []byte, unsized bool) *http.Request {
	req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+route, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if unsized {
		req.ContentLength = -1
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	return req
}

func testCredentialBodyLimit(t *testing.T, mount Mounter) {
	newBoundEnv := func(t *testing.T) (*Env, *rateLimitRecorder) {
		recorder := &rateLimitRecorder{}
		cfg := auth.DefaultHTTPConfig()
		cfg.RateLimiter = recorder.middleware
		env := NewEnv(t, mount, cfg, auth.WithInvitationStore(auth.NewMemoryInvitationStore()))
		env.Seed("bodylimit@example.com")
		return env, recorder
	}

	for _, rt := range credentialRoutes {
		t.Run(rt.route, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				unsized bool
			}{
				{"a declared length over the limit is 413 before anything reads it", false},
				{"a body with no declared length is cut at the limit", true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					env, recorder := newBoundEnv(t)
					rec := env.Do(bodyRequest(env, rt.route, paddedBody(t, rt.fields, credentialBodyLimit+1), tc.unsized))
					AssertError(t, rec, http.StatusRequestEntityTooLarge, "Request body too large", "BODY_TOO_LARGE")
					if seen := recorder.take(); len(seen) != 0 {
						t.Errorf("the rate limiter ran for an over-large body: %q", seen)
					}
					if d := env.Delivered; len(d.PasswordResets)+len(d.MagicLinks)+len(d.SMSCodes) != 0 {
						t.Errorf("an over-large body was acted on: %+v", d)
					}
				})
			}

			t.Run("a body at the limit is not refused for its size", func(t *testing.T) {
				env, _ := newBoundEnv(t)
				rec := env.Do(bodyRequest(env, rt.route, paddedBody(t, rt.fields, credentialBodyLimit), false))
				if rec.Code == http.StatusRequestEntityTooLarge {
					t.Errorf("a %d-byte body was refused as too large: %s", credentialBodyLimit, rec.Body.String())
				}
			})
		})
	}

	// The refusal is decided before the address is read, so a known and an
	// unknown address get the same bytes.
	t.Run("forgot-password answers a known and an unknown address alike", func(t *testing.T) {
		env, _ := newBoundEnv(t)
		known := env.Do(bodyRequest(env, "/forgot-password",
			paddedBody(t, map[string]string{"email": "bodylimit@example.com", "tenantId": testTenant}, credentialBodyLimit+1), false))
		unknown := env.Do(bodyRequest(env, "/forgot-password",
			paddedBody(t, map[string]string{"email": "nobody@example.com", "tenantId": testTenant}, credentialBodyLimit+1), false))
		if known.Code != unknown.Code || known.Body.String() != unknown.Body.String() {
			t.Errorf("known address: %d %q; unknown address: %d %q", known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
		}
	})
}
