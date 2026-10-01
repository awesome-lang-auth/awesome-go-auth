package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// testBcryptCost is the cost every fixture in this package hashes at.
//
// bcrypt is deliberately slow, and that slowness is the point in production and
// pure overhead here: the fixtures hash so that login, reset and
// change-password have a real hash to verify against, and bcrypt reads the cost
// out of the hash it is verifying, so MinCost exercises identical code for a
// fraction of the time.
//
// Nothing outside the tests can reach this. An unset Config.BcryptCost is
// bcrypt.DefaultCost, which TestUnconfiguredBcryptCostIsDefaultCost pins
// through a real Register on every constructor.
const testBcryptCost = bcrypt.MinCost

// testSecret is a valid 32-char secret for fixtures that do not care which.
const testSecret = "12345678901234567890123456789012"

// testConfig is DefaultConfig with the bcrypt cost lowered. Tests that build a
// Service directly start here instead of at DefaultConfig.
func testConfig(secret string) Config {
	cfg := DefaultConfig(secret)
	cfg.BcryptCost = testBcryptCost
	// The suites seed users through Register and authenticate with the session
	// it hands back, so the shared test config opts in to it. The default — off,
	// the reference's answer — is pinned in register_session_test.go.
	cfg.IssueSessionOnRegister = true
	// Delivery is a precondition of the passwordless send calls, so a service
	// built for a test about something else still has to satisfy it. See
	// noopDelivery in delivery_test.go.
	noopDelivery(&cfg)
	return cfg
}

// newTestAuth is New with the bcrypt cost lowered. Tests that build an Auth
// start here instead of at New. Options passed in are applied after, so a test
// that wants a specific cost can still say so.
func newTestAuth(opts ...Option) (*Auth, error) {
	return New(append([]Option{WithBcryptCost(testBcryptCost), WithIssueSessionOnRegister(true)}, opts...)...)
}

// TestUnconfiguredBcryptCostIsDefaultCost is the guard on the production
// default: an embedder that configures no cost must get bcrypt.DefaultCost, and
// must never get bcrypt.MinCost by falling through the "unset" case.
//
// The assertion is made on the cost recovered from a hash a real Register
// produced, not on the Config field. Reading the field back would pass even if
// nothing threaded it into hashPassword; recovering it from the stored hash
// fails if the value is dropped anywhere along the way.
func TestUnconfiguredBcryptCostIsDefaultCost(t *testing.T) {
	if got := DefaultConfig(testSecret).BcryptCost; got != bcrypt.DefaultCost {
		t.Fatalf("DefaultConfig().BcryptCost = %d, want bcrypt.DefaultCost (%d)", got, bcrypt.DefaultCost)
	}

	zeroed := DefaultConfig(testSecret)
	zeroed.BcryptCost = 0

	cases := []struct {
		name  string
		build func(t *testing.T, users UserStore) *Auth
	}{
		{
			// The plain constructor, configured with nothing but a store to read
			// the hash back out of.
			name: "New",
			build: func(t *testing.T, users UserStore) *Auth {
				a, err := New(WithUserStore(users))
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return a
			},
		},
		{
			// A Config the caller populated from DefaultConfig and did not touch.
			name: "NewWithConfig",
			build: func(t *testing.T, users UserStore) *Auth {
				a, err := NewWithConfig(DefaultConfig(testSecret), WithUserStore(users))
				if err != nil {
					t.Fatalf("NewWithConfig: %v", err)
				}
				return a
			},
		},
		{
			// A Config carrying an explicit zero, which is what a hand-built
			// struct literal or a deserialized document with the key absent
			// produces. Zero means unset, and unset means DefaultCost.
			name: "explicit zero BcryptCost",
			build: func(t *testing.T, users UserStore) *Auth {
				a, err := NewWithConfig(zeroed, WithUserStore(users))
				if err != nil {
					t.Fatalf("NewWithConfig: %v", err)
				}
				return a
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			users := NewMemoryUserStore()
			a := tc.build(t, users)
			user, _, err := a.Register(context.Background(), RegisterInput{
				Email: "default-cost@example.com", Password: "password1", TenantID: "t1",
			})
			if err != nil {
				t.Fatalf("register: %v", err)
			}
			assertHashCost(t, user.PasswordHash, bcrypt.DefaultCost)
		})
	}
}

// TestConfiguredBcryptCostReachesEveryHashingPath walks every path in the
// library that writes a bcrypt hash and checks the configured cost came out the
// other end. A path that still calls bcrypt.DefaultCost directly, or that reads
// a Config the caller never populated, fails here.
//
// The cost is deliberately neither DefaultCost nor the package's testBcryptCost,
// so neither the production fallback nor the fixture default can satisfy it by
// accident.
func TestConfiguredBcryptCostReachesEveryHashingPath(t *testing.T) {
	const cost = bcrypt.MinCost + 1
	ctx := context.Background()

	t.Run("Register", func(t *testing.T) {
		users := NewMemoryUserStore()
		a := mustAuthAtCost(t, cost, users)
		user, _, err := a.Register(ctx, RegisterInput{Email: "reg@example.com", Password: "password1", TenantID: "t1"})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		assertHashCost(t, user.PasswordHash, cost)
	})

	t.Run("ResetPassword", func(t *testing.T) {
		users := NewMemoryUserStore()
		a := mustAuthAtCost(t, cost, users)
		user, _, err := a.Register(ctx, RegisterInput{Email: "reset@example.com", Password: "password1", TenantID: "t1"})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		token, err := a.ForgotPassword(ctx, ForgotPasswordInput{Email: "reset@example.com", TenantID: "t1"})
		if err != nil {
			t.Fatalf("forgot: %v", err)
		}
		if err := a.ResetPassword(ctx, ResetPasswordInput{Token: token, NewPassword: "password2"}); err != nil {
			t.Fatalf("reset: %v", err)
		}
		assertHashCost(t, reloadHash(t, users, user.ID), cost)
	})

	t.Run("ChangePassword", func(t *testing.T) {
		users := NewMemoryUserStore()
		a := mustAuthAtCost(t, cost, users)
		user, _, err := a.Register(ctx, RegisterInput{Email: "change@example.com", Password: "password1", TenantID: "t1"})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		if err := a.Service().ChangePassword(ctx, ChangePasswordInput{
			UserID: user.ID, TenantID: "t1", CurrentPassword: "password1", NewPassword: "password2",
		}); err != nil {
			t.Fatalf("change: %v", err)
		}
		assertHashCost(t, reloadHash(t, users, user.ID), cost)
	})

	t.Run("SetInitialPasswordOnPasswordlessAccount", func(t *testing.T) {
		// (*Auth).ChangePassword, not Service.ChangePassword: the only route by
		// which an account with no password acquires one, and a separate
		// hashPassword call site from the one above.
		users := NewMemoryUserStore()
		a := mustAuthAtCost(t, cost, users)
		user, _, err := a.Register(ctx, RegisterInput{Email: "passwordless@example.com", Password: "password1", TenantID: "t1"})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		if err := users.UpdatePassword(ctx, user.ID, "t1", ""); err != nil {
			t.Fatalf("clear password: %v", err)
		}
		if err := a.ChangePassword(ctx, ChangePasswordInput{
			UserID: user.ID, TenantID: "t1", NewPassword: "password2",
		}); err != nil {
			t.Fatalf("set initial password: %v", err)
		}
		assertHashCost(t, reloadHash(t, users, user.ID), cost)
	})

	t.Run("APIKeyCreate", func(t *testing.T) {
		svc := NewAPIKeyService(cost)
		_, record, err := svc.Create(ctx, newMemAPIKeyStore(), "k", "svc", nil, nil, nil)
		if err != nil {
			t.Fatalf("create api key: %v", err)
		}
		assertHashCost(t, record.KeyHash, cost)
	})
}

// TestAPIKeyServiceZeroCostIsDefaultCost pins the same "unset means the safe
// default" rule on the API-key constructor, which takes the cost as a bare int
// and so cannot lean on Config.validate.
func TestAPIKeyServiceZeroCostIsDefaultCost(t *testing.T) {
	_, record, err := NewAPIKeyService(0).Create(context.Background(), newMemAPIKeyStore(), "k", "svc", nil, nil, nil)
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	assertHashCost(t, record.KeyHash, bcrypt.DefaultCost)
}

// TestHashPasswordZeroCostIsDefaultCost pins the resolution at the single sink,
// independently of any Config, so the rule survives a caller that stops going
// through Config entirely.
func TestHashPasswordZeroCostIsDefaultCost(t *testing.T) {
	hash, err := hashPassword("password1", 0)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	assertHashCost(t, hash, bcrypt.DefaultCost)
}

// TestVerifyPasswordWorksAcrossCosts is the reason the fixtures may hash
// cheaply at all: the cost lives in the hash, so a hash written at one cost
// verifies under a service configured for another. Were this not so, lowering
// the fixture cost would change what the suite tests.
func TestVerifyPasswordWorksAcrossCosts(t *testing.T) {
	for _, cost := range []int{bcrypt.MinCost, bcrypt.MinCost + 1, bcrypt.DefaultCost} {
		hash, err := hashPassword("password1", cost)
		if err != nil {
			t.Fatalf("hashPassword at cost %d: %v", cost, err)
		}
		if !verifyPassword("password1", hash) {
			t.Fatalf("cost %d: correct password failed to verify", cost)
		}
		if verifyPassword("wrong-password", hash) {
			t.Fatalf("cost %d: wrong password verified", cost)
		}
	}
}

func TestConfigValidateBcryptCost(t *testing.T) {
	cases := []struct {
		name string
		cost int
		ok   bool
	}{
		{"unset", 0, true},
		{"min", bcrypt.MinCost, true},
		{"default", bcrypt.DefaultCost, true},
		{"max", bcrypt.MaxCost, true},
		{"below min", bcrypt.MinCost - 1, false},
		{"above max", bcrypt.MaxCost + 1, false},
		{"negative", -1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig(testSecret)
			cfg.BcryptCost = tc.cost
			err := cfg.validate()
			if tc.ok {
				if err != nil {
					t.Fatalf("cost %d: unexpected error: %v", tc.cost, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("cost %d: expected an error", tc.cost)
			}
			// The message has to name the field and the accepted range, or an
			// operator reading a startup failure cannot act on it.
			for _, want := range []string{"bcrypt cost", "4", "31"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

func TestWithBcryptCostRejectsOutOfRange(t *testing.T) {
	// Zero is rejected here although Config accepts it: an explicit setter
	// reached with an unset value is a caller mistake, not a request for the
	// default.
	for _, cost := range []int{0, -1, bcrypt.MinCost - 1, bcrypt.MaxCost + 1} {
		_, err := New(WithBcryptCost(cost))
		if err == nil {
			t.Fatalf("WithBcryptCost(%d): expected an error", cost)
		}
		// The message must carry the remedy, not just the range. An operator
		// who lands here with an unset value and is told only "must be between
		// 4 and 31" has 4 as the nearest legal answer, which is precisely the
		// weak cost this change exists to keep out of production.
		for _, want := range []string{"bcrypt cost", "4", "31", "omit WithBcryptCost", "10"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("WithBcryptCost(%d) error %q does not mention %q", cost, err, want)
			}
		}
	}
	for _, cost := range []int{bcrypt.MinCost, bcrypt.DefaultCost, bcrypt.MaxCost} {
		a, err := New(WithBcryptCost(cost))
		if err != nil {
			t.Fatalf("WithBcryptCost(%d): %v", cost, err)
		}
		if a.service.cfg.BcryptCost != cost {
			t.Fatalf("WithBcryptCost(%d) stored %d", cost, a.service.cfg.BcryptCost)
		}
	}
}

// TestBelowDefaultBcryptCostIsLogged covers the one thing an operator cannot
// see from outside: a cost that is legal, accepted, and weaker than the
// library's own baseline. It is a notice, not a rejection — the suites below
// depend on being allowed to do it.
func TestBelowDefaultBcryptCostIsLogged(t *testing.T) {
	cases := []struct {
		name     string
		cost     int
		wantWarn bool
	}{
		{"below default warns", bcrypt.MinCost, true},
		{"default is silent", bcrypt.DefaultCost, false},
		{"above default is silent", bcrypt.DefaultCost + 1, false},
		{"unset is silent", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var lines []string
			cfg := DefaultConfig(testSecret)
			cfg.BcryptCost = tc.cost
			cfg.Logger = func(format string, args ...any) { lines = append(lines, format) }
			if _, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore()); err != nil {
				t.Fatalf("new service: %v", err)
			}
			var warned bool
			for _, l := range lines {
				if strings.Contains(l, "bcrypt cost") {
					warned = true
				}
			}
			if warned != tc.wantWarn {
				t.Fatalf("cost %d: warned = %v, want %v (lines %q)", tc.cost, warned, tc.wantWarn, lines)
			}
		})
	}
}

// TestNewWithConfigReachesFieldsWithNoOption is the other half of #25: fields
// that Config declares but no Option sets are now reachable.
func TestNewWithConfigReachesFieldsWithNoOption(t *testing.T) {
	cfg := testConfig(testSecret)
	cfg.EmailVerificationMode = EmailVerificationModeStrict
	cfg.MinPasswordLen = 12
	cfg.ResetTokenTTL = 90 * time.Minute

	a, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	got := a.service.cfg
	if got.EmailVerificationMode != EmailVerificationModeStrict {
		t.Fatalf("EmailVerificationMode = %q", got.EmailVerificationMode)
	}
	if got.MinPasswordLen != 12 {
		t.Fatalf("MinPasswordLen = %d", got.MinPasswordLen)
	}
	if got.ResetTokenTTL != cfg.ResetTokenTTL {
		t.Fatalf("ResetTokenTTL = %v", got.ResetTokenTTL)
	}
}

func TestNewWithConfigValidatesLikeNew(t *testing.T) {
	if _, err := NewWithConfig(Config{}); err == nil {
		t.Fatal("expected a zero Config to be rejected")
	}
	cfg := testConfig(testSecret)
	cfg.BcryptCost = bcrypt.MaxCost + 1
	if _, err := NewWithConfig(cfg); err == nil {
		t.Fatal("expected an out-of-range bcrypt cost to be rejected")
	}
}

func mustAuthAtCost(t *testing.T, cost int, users UserStore) *Auth {
	t.Helper()
	a, err := New(WithUserStore(users), WithBcryptCost(cost))
	if err != nil {
		t.Fatalf("New at cost %d: %v", cost, err)
	}
	return a
}

func reloadHash(t *testing.T, users UserStore, userID string) string {
	t.Helper()
	user, err := users.GetUserByID(context.Background(), userID, "t1")
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	return user.PasswordHash
}

func assertHashCost(t *testing.T, hash string, want int) {
	t.Helper()
	if hash == "" {
		t.Fatal("no hash was stored")
	}
	got, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("bcrypt.Cost(%q): %v", hash, err)
	}
	if got != want {
		t.Fatalf("hash cost = %d, want %d", got, want)
	}
}
