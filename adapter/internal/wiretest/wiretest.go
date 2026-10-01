// Package wiretest is the shared wire-contract conformance suite for the HTTP
// adapters.
//
// The four adapters must be interchangeable: a client that talks to the
// net/http mount has to see the same statuses, bodies and Set-Cookie headers
// from chi, gin and echo. Asserting that four times over invites drift, so the
// assertions live here once and each adapter's test file supplies nothing but a
// Mounter. A route added in a later PR is pinned for every adapter by extending
// this suite.
package wiretest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
	"golang.org/x/crypto/bcrypt"
)

// Mounter builds a handler serving a's auth routes under cfg.
type Mounter func(t *testing.T, a *auth.Auth, cfg auth.HTTPConfig) http.Handler

// Deliveries records what the delivery senders were handed, so a send route can
// be asserted on from the outside: the credential never appears in the response,
// and checking only that the store holds a hash cannot tell "delivered" from
// "minted and dropped on the floor".
type Deliveries struct {
	MagicLinks []auth.MagicLinkDelivery
	SMSCodes   []auth.SMSCodeDelivery
	// The §2 half of the seam. Unlike the two above, these three are not a
	// precondition of any route: an env without them answers exactly as it did
	// before the senders existed.
	PasswordResets     []auth.PasswordResetDelivery
	EmailVerifications []auth.EmailVerificationDelivery
	EmailChanges       []auth.EmailChangeDelivery
	// EmailChanged is the notice /change-email/confirm sends to the OLD
	// address once the change is applied (auth.router.ts:1060-1066).
	EmailChanged []auth.EmailChangedDelivery
}

func (d *Deliveries) senderOptions() []auth.Option {
	return []auth.Option{
		auth.WithMagicLinkSender(func(_ context.Context, delivery auth.MagicLinkDelivery) error {
			d.MagicLinks = append(d.MagicLinks, delivery)
			return nil
		}),
		auth.WithSMSCodeSender(func(_ context.Context, delivery auth.SMSCodeDelivery) error {
			d.SMSCodes = append(d.SMSCodes, delivery)
			return nil
		}),
		auth.WithPasswordResetSender(func(_ context.Context, delivery auth.PasswordResetDelivery) error {
			d.PasswordResets = append(d.PasswordResets, delivery)
			return nil
		}),
		auth.WithEmailVerificationSender(func(_ context.Context, delivery auth.EmailVerificationDelivery) error {
			d.EmailVerifications = append(d.EmailVerifications, delivery)
			return nil
		}),
		auth.WithEmailChangeSender(func(_ context.Context, delivery auth.EmailChangeDelivery) error {
			d.EmailChanges = append(d.EmailChanges, delivery)
			return nil
		}),
		auth.WithEmailChangedSender(func(_ context.Context, delivery auth.EmailChangedDelivery) error {
			d.EmailChanged = append(d.EmailChanged, delivery)
			return nil
		}),
	}
}

// Env is one mounted adapter under test.
type Env struct {
	T       *testing.T
	Auth    *auth.Auth
	Handler http.Handler
	Config  auth.HTTPConfig
	// Delivered is what the recording senders received. It is empty on an env
	// built by NewEnvWithoutDelivery, which wires no senders at all.
	Delivered *Deliveries
}

// NewEnv builds an auth instance and mounts it.
//
// The delivery seam is satisfied with recording senders, because it is a
// precondition of two routes in this suite: without them /magic-link/send and
// /sms/send answer 500 EMAIL_NOT_CONFIGURED and 500 SMS_NOT_CONFIGURED, which
// is correct behaviour but not what the other cases are about. A caller may
// still override either sender through opts, which are applied last.
func NewEnv(t *testing.T, mount Mounter, cfg auth.HTTPConfig, opts ...auth.Option) *Env {
	t.Helper()
	delivered := &Deliveries{}
	env := newEnv(t, mount, cfg, append(delivered.senderOptions(), opts...)...)
	env.Delivered = delivered
	return env
}

// NewEnvWithoutDelivery builds an env whose delivery seam is unconfigured: the
// deployment that can mint a credential and has no way to send it.
func NewEnvWithoutDelivery(t *testing.T, mount Mounter, cfg auth.HTTPConfig, opts ...auth.Option) *Env {
	t.Helper()
	env := newEnv(t, mount, cfg, opts...)
	env.Delivered = &Deliveries{}
	return env
}

// newEnv is where every Env in the suite is actually built, so it is the one
// place the bcrypt cost needs pinning. The suite runs hundreds of Envs and seeds
// most of them, and at the production default each seed is tens of milliseconds
// of key derivation that none of the wire assertions look at — they check
// statuses, bodies and Set-Cookie headers. bcrypt.MinCost keeps the hashes real
// (verification is exercised for the whole login path) while taking the cost out
// of the runtime.
//
// The defaults are prepended rather than appended so a caller that deliberately
// wants a different cost, or its own store, can still override them.
func newEnv(t *testing.T, mount Mounter, cfg auth.HTTPConfig, opts ...auth.Option) *Env {
	t.Helper()
	opts = append([]auth.Option{
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
		auth.WithBcryptCost(bcrypt.MinCost),
	}, opts...)
	a, err := auth.New(opts...)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return &Env{T: t, Auth: a, Handler: mount(t, a, cfg), Config: cfg}
}

// Do issues a request against the mounted handler.
func (e *Env) Do(req *http.Request) *httptest.ResponseRecorder {
	e.T.Helper()
	rec := httptest.NewRecorder()
	e.Handler.ServeHTTP(rec, req)
	return rec
}

// Request builds a JSON request against a route below the mount prefix.
func (e *Env) Request(method, route string, body any) *http.Request {
	e.T.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(body)
		if err != nil {
			e.T.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, e.Config.Prefix()+route, reader)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// Seed registers a user directly through the service, bypassing HTTP, and
// logs it in for the session the cases authenticate with: registration opens
// none by default (Config.IssueSessionOnRegister is off, the reference's
// answer). Where the login itself would not open one — a required second
// factor, a strict email-verification gate — the tokens are the zero value, as
// the login leaves them.
func (e *Env) Seed(email string) (auth.User, auth.AuthTokens) {
	e.T.Helper()
	ctx := context.Background()
	user, tokens, err := e.Auth.Register(ctx, auth.RegisterInput{Email: email, Password: "password1", TenantID: "t1"})
	if err != nil {
		e.T.Fatalf("seed %s: %v", email, err)
	}
	if tokens.AccessToken == "" {
		if _, loggedIn, err := e.Auth.Login(ctx, auth.LoginInput{Email: email, Password: "password1", TenantID: "t1"}); err == nil {
			tokens = loggedIn
		}
	}
	return user, tokens
}

// Body decodes a JSON response body.
func Body(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return body
}

// AssertStatus fails unless the status matches exactly.
func AssertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body %q)", rec.Code, want, rec.Body.String())
	}
}

// AssertKeys fails unless the body carries exactly these top-level keys. This
// is what stops a reverted shape from passing: an extra "user" wrapper or a
// leaked "tokens" object fails here even if every asserted value is right.
func AssertKeys(t *testing.T, body map[string]any, want ...string) {
	t.Helper()
	got := make([]string, 0, len(body))
	for k := range body {
		got = append(got, k)
	}
	sort.Strings(got)
	sorted := append([]string(nil), want...)
	sort.Strings(sorted)
	if strings.Join(got, ",") != strings.Join(sorted, ",") {
		t.Fatalf("body keys = [%s], want [%s]", strings.Join(got, ","), strings.Join(sorted, ","))
	}
}

// AssertError fails unless the body is the family error envelope with this code.
// An empty code asserts that no "code" field is present at all.
func AssertError(t *testing.T, rec *httptest.ResponseRecorder, status int, message, code string) {
	t.Helper()
	AssertStatus(t, rec, status)
	body := Body(t, rec)
	if code == "" {
		AssertKeys(t, body, "error")
	} else {
		AssertKeys(t, body, "error", "code")
		if body["code"] != code {
			t.Fatalf("code = %v, want %q", body["code"], code)
		}
	}
	if body["error"] != message {
		t.Fatalf("error = %v, want %q", body["error"], message)
	}
}

// Cookie finds a Set-Cookie by name.
func Cookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no Set-Cookie named %q in %v", name, cookieNames(rec))
	return nil
}

// AssertNoCookie fails when a Set-Cookie with this name is present.
func AssertNoCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			t.Fatalf("unexpected Set-Cookie %q (%s)", name, c.String())
		}
	}
}

// AssertNoCookies fails when the response sets any cookie at all.
func AssertNoCookies(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if names := cookieNames(rec); len(names) > 0 {
		t.Fatalf("expected no Set-Cookie headers, got %v", names)
	}
}

func cookieNames(rec *httptest.ResponseRecorder) []string {
	var names []string
	for _, c := range rec.Result().Cookies() {
		names = append(names, c.Name)
	}
	return names
}

// AssertCleared fails unless the last Set-Cookie with this name expires it. The
// last one wins in a browser, so a clear that is followed by a fresh value is
// not a clear.
func AssertCleared(t *testing.T, rec *httptest.ResponseRecorder, name string) {
	t.Helper()
	var last *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			last = c
		}
	}
	if last == nil {
		t.Errorf("cookie %q was never cleared", name)
		return
	}
	if last.MaxAge >= 0 || last.Value != "" {
		t.Errorf("cookie %q not expired: %s", name, last.String())
	}
}

func stringReader(s string) *strings.Reader { return strings.NewReader(s) }

// CookieSpec is the exact set of attributes a cookie must carry.
type CookieSpec struct {
	Path     string
	Domain   string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

// AssertCookieAttrs fails unless every attribute matches.
func AssertCookieAttrs(t *testing.T, c *http.Cookie, want CookieSpec) {
	t.Helper()
	if c.Path != want.Path {
		t.Errorf("%s Path = %q, want %q", c.Name, c.Path, want.Path)
	}
	if c.Domain != want.Domain {
		t.Errorf("%s Domain = %q, want %q", c.Name, c.Domain, want.Domain)
	}
	if c.MaxAge != want.MaxAge {
		t.Errorf("%s Max-Age = %d, want %d", c.Name, c.MaxAge, want.MaxAge)
	}
	if c.Secure != want.Secure {
		t.Errorf("%s Secure = %v, want %v", c.Name, c.Secure, want.Secure)
	}
	if c.HttpOnly != want.HttpOnly {
		t.Errorf("%s HttpOnly = %v, want %v", c.Name, c.HttpOnly, want.HttpOnly)
	}
	if c.SameSite != want.SameSite {
		t.Errorf("%s SameSite = %v, want %v", c.Name, c.SameSite, want.SameSite)
	}
}

// Replay copies the cookies a response set onto a new request the way a browser
// would: expired ones are dropped, and so are the ones whose Path does not cover
// the new request. Honouring Path is what makes the replay honest — a suite that
// ignores it cannot tell a cookie scoped to <prefix>/refresh from one scoped to
// "/", and would pass a handler that only works because the test sent a cookie
// no browser would have sent.
func Replay(req *http.Request, rec *httptest.ResponseRecorder) *http.Request {
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			continue
		}
		if !pathCovers(c.Path, req.URL.Path) {
			continue
		}
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return req
}

// pathCovers implements RFC 6265 §5.1.4 path matching.
func pathCovers(cookiePath, requestPath string) bool {
	if cookiePath == "" || cookiePath == "/" {
		return true
	}
	if requestPath == cookiePath {
		return true
	}
	if !strings.HasPrefix(requestPath, cookiePath) {
		return false
	}
	return strings.HasSuffix(cookiePath, "/") || strings.HasPrefix(requestPath[len(cookiePath):], "/")
}
