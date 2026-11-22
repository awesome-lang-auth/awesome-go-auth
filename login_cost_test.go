package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Tests for the cost of a refused password login: whatever the address names —
// no account, an account without a password, an account whose stored value is
// no bcrypt hash at all, an account and a wrong password — the login runs
// exactly one bcrypt comparison at the deployment's cost, so the time it takes
// does not say which of those it was.
//
// Nothing here reads a clock. A wall-clock comparison under -race is noise, and
// the property is not "about the same time" but "the same work": the
// comparison is counted through Service.compareHash, the one call on these
// paths that costs anything, and its cost is read off the hash it was handed.

// comparisons records every hash a Service compared a password against.
type comparisons struct {
	mu     sync.Mutex
	hashes [][]byte
}

// count installs the recorder on svc, in front of the real comparison.
func (c *comparisons) count(svc *Service) {
	inner := svc.compareHash
	svc.compareHash = func(hash, password []byte) error {
		c.mu.Lock()
		c.hashes = append(c.hashes, bytes.Clone(hash))
		c.mu.Unlock()
		return inner(hash, password)
	}
}

func (c *comparisons) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hashes = nil
}

// atCost is how many of the recorded comparisons were real bcrypt work at
// cost: a hash bcrypt parses, at that cost. A comparison against "" or a
// placeholder is recorded too, and costs nothing — bcrypt refuses it before
// any key derivation — which is exactly what must not decide the answer's
// timing.
func (c *comparisons) atCost(cost int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, h := range c.hashes {
		if got, err := bcrypt.Cost(h); err == nil && got == cost {
			n++
		}
	}
	return n
}

func (c *comparisons) all() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.hashes...)
}

// loginCostFixture is a service with one account of each kind a login can
// name, every real hash written at testBcryptCost.
type loginCostFixture struct {
	svc      *Service
	compared *comparisons
}

const (
	loginCostKnown        = "known@example.com"
	loginCostPasswordless = "passwordless@example.com"
	loginCostPlaceholder  = "migrating@example.com"
	loginCostPassword     = "correct horse 1"
)

func newLoginCostFixture(t *testing.T, opts ...func(*Config)) loginCostFixture {
	t.Helper()
	cfg := testConfig(testSecret)
	for _, opt := range opts {
		opt(&cfg)
	}
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	hash, err := hashPassword(loginCostPassword, testBcryptCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	for _, u := range []User{
		{ID: "usr_known", Email: loginCostKnown, PasswordHash: hash},
		// OAuth-only or magic-link-only: no stored hash at all.
		{ID: "usr_passwordless", Email: loginCostPasswordless},
		// What a migration leaves behind until the verifier adopts a password:
		// a marker in the hash column, which bcrypt cannot parse.
		{ID: "usr_placeholder", Email: loginCostPlaceholder, PasswordHash: "legacy:pbkdf2:not-a-bcrypt-hash"},
	} {
		u.TenantID = "t1"
		u.IsEmailVerified = true
		if _, err := svc.users.CreateUser(context.Background(), u); err != nil {
			t.Fatalf("seed %s: %v", u.Email, err)
		}
	}
	f := loginCostFixture{svc: svc, compared: &comparisons{}}
	f.compared.count(svc)
	return f
}

// TestLoginRunsOneFullComparisonOnEveryPath is the property itself, on both
// entry points a password login has: Service.Login and LoginWithChallenge,
// which is what the four adapters, the IdP's login form and the MCP tool call.
func TestLoginRunsOneFullComparisonOnEveryPath(t *testing.T) {
	cases := []struct {
		name, email, password string
		wantErr               error
	}{
		{"an address no account holds", "nobody@example.com", loginCostPassword, ErrInvalidCredentials},
		{"an account without a password", loginCostPasswordless, loginCostPassword, ErrInvalidCredentials},
		{"an account whose stored value is not a bcrypt hash", loginCostPlaceholder, loginCostPassword, ErrInvalidCredentials},
		{"an account and a wrong password", loginCostKnown, "wrong password 1", ErrInvalidCredentials},
		{"an account and its password", loginCostKnown, loginCostPassword, nil},
	}
	entries := []struct {
		name  string
		login func(*Service, LoginInput) error
	}{
		{"Login", func(s *Service, in LoginInput) error {
			_, _, err := s.Login(context.Background(), in)
			return err
		}},
		{"LoginWithChallenge", func(s *Service, in LoginInput) error {
			_, err := s.LoginWithChallenge(context.Background(), in)
			return err
		}},
	}
	for _, entry := range entries {
		for _, tc := range cases {
			t.Run(entry.name+"/"+tc.name, func(t *testing.T) {
				f := newLoginCostFixture(t)
				err := entry.login(f.svc, LoginInput{Email: tc.email, Password: tc.password, TenantID: "t1"})
				if !errors.Is(err, tc.wantErr) && (tc.wantErr != nil || err != nil) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if got := f.compared.atCost(testBcryptCost); got != 1 {
					t.Errorf("full-cost bcrypt comparisons = %d, want exactly 1 (recorded %d comparisons in all): "+
						"a refusal that skips the comparison answers measurably sooner, and says the address is the cheap kind",
						got, len(f.compared.all()))
				}
			})
		}
	}
}

// TestLoginStandInHashFollowsTheDeploymentCost: the hash a login compares
// against when the account has none is written at the cost every real hash is
// written at — Config.BcryptCost, and bcrypt.DefaultCost when it is unset —
// and it is computed once per Service, not once per login.
func TestLoginStandInHashFollowsTheDeploymentCost(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured int
		want       int
	}{
		{"unset means bcrypt.DefaultCost", 0, bcrypt.DefaultCost},
		{"a configured cost", bcrypt.MinCost + 1, bcrypt.MinCost + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLoginCostFixture(t, func(c *Config) { c.BcryptCost = tc.configured })
			for i := 0; i < 2; i++ {
				if _, _, err := f.svc.Login(context.Background(), LoginInput{
					Email: "nobody@example.com", Password: "whatever 1", TenantID: "t1",
				}); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("login %d: err = %v, want ErrInvalidCredentials", i, err)
				}
			}
			hashes := f.compared.all()
			if len(hashes) != 2 {
				t.Fatalf("recorded %d comparisons for two logins, want 2", len(hashes))
			}
			for i, h := range hashes {
				if got, err := bcrypt.Cost(h); err != nil || got != tc.want {
					t.Errorf("comparison %d ran against a hash of cost %d (err %v), want %d", i, got, err, tc.want)
				}
			}
			if !bytes.Equal(hashes[0], hashes[1]) {
				t.Error("the two logins compared against different stand-in hashes: it must be computed once, " +
					"since computing it costs what a comparison costs and would double the unknown address's time")
			}
		})
	}
}

// TestLoginWithAVerifierStillComparesOnce: an account the hash does not verify
// still reaches Config.PasswordVerifier, after the one comparison, and the
// verifier's answer still decides — the stand-in hash changes the cost of the
// refusal, never its outcome.
func TestLoginWithAVerifierStillComparesOnce(t *testing.T) {
	var asked []string
	f := newLoginCostFixture(t, func(c *Config) {
		c.PasswordVerifier = func(_ context.Context, user User, password string) (bool, bool, error) {
			asked = append(asked, user.Email)
			return user.Email == loginCostPlaceholder && password == "legacy password 1", false, nil
		}
	})

	if _, _, err := f.svc.Login(context.Background(), LoginInput{
		Email: loginCostPasswordless, Password: "anything 1", TenantID: "t1",
	}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("passwordless login: err = %v, want ErrInvalidCredentials", err)
	}
	if got := f.compared.atCost(testBcryptCost); got != 1 {
		t.Errorf("full-cost comparisons = %d, want 1", got)
	}

	f.compared.reset()
	if _, _, err := f.svc.Login(context.Background(), LoginInput{
		Email: loginCostPlaceholder, Password: "legacy password 1", TenantID: "t1",
	}); err != nil {
		t.Fatalf("a password the verifier accepts was refused: %v", err)
	}
	if got := f.compared.atCost(testBcryptCost); got != 1 {
		t.Errorf("full-cost comparisons = %d, want 1", got)
	}
	if strings.Join(asked, ",") != loginCostPasswordless+","+loginCostPlaceholder {
		t.Errorf("verifier asked about %q, want both accounts whose hash did not verify", asked)
	}
}

// TestAdminLoginRunsOneFullComparisonOnEveryPath is the same property on
// POST <admin>/login, which had the same shape: bcrypt ran only when an email
// matched the root user or a stored account with a password.
func TestAdminLoginRunsOneFullComparisonOnEveryPath(t *testing.T) {
	rootHash, err := hashPassword("root password 1", testBcryptCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	cases := []struct {
		name, body string
		want       int
	}{
		{"an address no account holds", `{"email":"nobody@example.com","password":"x"}`, http.StatusUnauthorized},
		{"an account without a password", `{"email":"` + loginCostPasswordless + `","password":"x"}`, http.StatusUnauthorized},
		{"an account whose stored value is not a bcrypt hash", `{"email":"` + loginCostPlaceholder + `","password":"x"}`, http.StatusUnauthorized},
		{"an account and a wrong password", `{"email":"` + loginCostKnown + `","password":"x"}`, http.StatusUnauthorized},
		{"the root user and a wrong password", `{"email":"root@example.com","password":"x"}`, http.StatusUnauthorized},
		{"the bootstrap name and a wrong secret", `{"email":"admin","password":"x"}`, http.StatusUnauthorized},
		{"no address and a wrong secret", `{"password":"x"}`, http.StatusUnauthorized},
		{"an account and its password", `{"email":"` + loginCostKnown + `","password":"` + loginCostPassword + `"}`, http.StatusOK},
		{"the root user and its password", `{"email":"root@example.com","password":"root password 1"}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLoginCostFixture(t)
			a := &Auth{service: f.svc}
			cfg := DefaultHTTPConfig()
			cfg.Admin = AdminOptions{
				Enabled:      true,
				AccessPolicy: AdminIsAdminFlag(),
				RootUser:     &AdminRootUser{Email: "root@example.com", PasswordHash: rootHash},
				Secret:       "bootstrap-secret-0123456789abcdef",
			}
			// The store holds its accounts under tenant t1 and the admin login
			// looks up the empty tenant, as the reference's findByEmail(email)
			// does; seed the same three there.
			for _, u := range []User{
				{ID: "adm_known", Email: loginCostKnown},
				{ID: "adm_passwordless", Email: loginCostPasswordless},
				{ID: "adm_placeholder", Email: loginCostPlaceholder, PasswordHash: "legacy:pbkdf2:not-a-bcrypt-hash"},
			} {
				if u.ID == "adm_known" {
					u.PasswordHash, _ = hashPassword(loginCostPassword, testBcryptCost)
				}
				if _, err := f.svc.users.CreateUser(context.Background(), u); err != nil {
					t.Fatalf("seed %s: %v", u.Email, err)
				}
			}
			f.compared.reset()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, cfg.AdminPath()+AdminLoginPath, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			a.AdminGuard(cfg).adminLogin(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if got := f.compared.atCost(testBcryptCost); got != 1 {
				t.Errorf("full-cost bcrypt comparisons = %d, want exactly 1 (recorded %d in all)", got, len(f.compared.all()))
			}
		})
	}
}

// TestAdminLoginRootAddressHeldByAStoreAccount pins the one path of POST
// <admin>/login that costs more than one comparison, and why it is kept: when
// a store account holds the configured root user's address, a wrong password
// is compared against the root's hash and then against the account's, as the
// reference does — the account still signs in to the console with its own
// password, which capping the route at one comparison would stop. The
// deployment avoids the case by giving the root an address no account holds.
func TestAdminLoginRootAddressHeldByAStoreAccount(t *testing.T) {
	rootHash, err := hashPassword("root password 1", testBcryptCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	cases := []struct {
		name, password string
		status, cost   int
	}{
		{"a wrong password costs two comparisons", "x", http.StatusUnauthorized, 2},
		{"the account's own password still signs in", "store password 1", http.StatusOK, 2},
		{"the root's password signs in with one comparison", "root password 1", http.StatusOK, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLoginCostFixture(t)
			a := &Auth{service: f.svc}
			cfg := DefaultHTTPConfig()
			cfg.Admin = AdminOptions{
				Enabled:      true,
				AccessPolicy: AdminIsAdminFlag(),
				RootUser:     &AdminRootUser{Email: "root@example.com", PasswordHash: rootHash},
			}
			hash, err := hashPassword("store password 1", testBcryptCost)
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if _, err := f.svc.users.CreateUser(context.Background(), User{ID: "adm_root_row", Email: "root@example.com", PasswordHash: hash}); err != nil {
				t.Fatalf("seed: %v", err)
			}
			f.compared.reset()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, cfg.AdminPath()+AdminLoginPath,
				strings.NewReader(`{"email":"root@example.com","password":"`+tc.password+`"}`))
			req.Header.Set("Content-Type", "application/json")
			a.AdminGuard(cfg).adminLogin(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if got := f.compared.atCost(testBcryptCost); got != tc.cost {
				t.Errorf("full-cost bcrypt comparisons = %d, want %d", got, tc.cost)
			}
		})
	}
}
