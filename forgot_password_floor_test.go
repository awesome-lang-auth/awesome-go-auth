package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Tests for Config.ForgotPasswordMinResponseTime: with a floor configured, the
// HTTP surface of /forgot-password answers no sooner than the floor after the
// request reached it, whichever branch the request took — a known address
// whose mail went out, an unknown one, one an invitation reserves, a failed
// delivery, a failed store — and whether or not the request context was
// cancelled on the way, and never later than shortly before the request
// context's deadline.
//
// The clock is the service's own (Service.now) and the wait is recorded, not
// slept (Service.sleep), so every assertion is exact: the work a branch did,
// plus the pad the floor asked for, is the floor.

type floorFixture struct {
	a *Auth

	mu        sync.Mutex
	now       time.Time
	pads      []time.Duration
	sendTakes time.Duration
	sendErr   error
}

func (f *floorFixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *floorFixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func (f *floorFixture) sleep(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pads = append(f.pads, d)
}

func (f *floorFixture) takePads() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	pads := f.pads
	f.pads = nil
	return pads
}

// send is the reset sender: it takes sendTakes of the fixture's clock — the
// relay's round trip — and answers sendErr.
func (f *floorFixture) send(context.Context, PasswordResetDelivery) error {
	f.advance(f.sendTakes)
	return f.sendErr
}

func newFloorFixture(t *testing.T, floor time.Duration, opts ...Option) *floorFixture {
	t.Helper()
	// Frozen at the real present, so that a deadline set relative to it is a
	// real deadline in the near future and the context stays live.
	f := &floorFixture{now: time.Now()}
	base := []Option{
		WithPasswordResetSender(f.send),
		WithForgotPasswordMinResponseTime(floor),
		WithInvitationStore(NewMemoryInvitationStore()),
	}
	f.a = newPasswordEmailAuth(t, nil, append(base, opts...)...)
	f.a.service.now = f.clock
	f.a.service.sleep = f.sleep
	ctx := context.Background()
	if _, _, err := f.a.Register(ctx, RegisterInput{Email: "known@example.com", Password: "password1", TenantID: "t1"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := f.a.Service().InviteUser(ctx, InviteUserInput{Email: "invited@example.com", TenantID: "t1"}); err != nil {
		t.Fatalf("invite: %v", err)
	}
	return f
}

// ask runs one /forgot-password through the HTTP surface and reports how much
// of the fixture's clock the work took and what the floor added.
func (f *floorFixture) ask(t *testing.T, ctx context.Context, email string) (work, pad time.Duration, err error) {
	t.Helper()
	start := f.clock()
	_, err = f.a.ForgotPassword(ctx, ForgotPasswordInput{Email: email, TenantID: "t1"})
	work = f.clock().Sub(start)
	pads := f.takePads()
	switch len(pads) {
	case 0:
	case 1:
		pad = pads[0]
	default:
		t.Fatalf("the answer was held %d times: %v", len(pads), pads)
	}
	return work, pad, err
}

// TestForgotPasswordFloorHoldsEveryBranchAlike is the property: whatever the
// branch, the work it did plus the pad is exactly the floor.
func TestForgotPasswordFloorHoldsEveryBranchAlike(t *testing.T) {
	const floor = 2 * time.Second
	cases := []struct {
		name      string
		email     string
		sendTakes time.Duration
		sendErr   error
		wantWork  time.Duration
	}{
		{"a known address whose mail went out", "known@example.com", 1500 * time.Millisecond, nil, 1500 * time.Millisecond},
		{"an unknown address", "nobody@example.com", 1500 * time.Millisecond, nil, 0},
		{"an address an invitation reserves", "invited@example.com", 1500 * time.Millisecond, nil, 0},
		{"a known address whose delivery failed", "known@example.com", 700 * time.Millisecond, errors.New("relay answered 429"), 700 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFloorFixture(t, floor)
			f.sendTakes, f.sendErr = tc.sendTakes, tc.sendErr
			work, pad, err := f.ask(t, context.Background(), tc.email)
			if err != nil {
				t.Fatalf("forgot password: %v", err)
			}
			if work != tc.wantWork {
				t.Fatalf("the branch took %v of the clock, want %v", work, tc.wantWork)
			}
			if work+pad != floor {
				t.Errorf("work %v + pad %v = %v, want the floor %v", work, pad, work+pad, floor)
			}
		})
	}

	// A store that fails after a good send is the one branch that answers an
	// error (the 500); it is held as long as the others.
	t.Run("a known address whose token could not be stored", func(t *testing.T) {
		f := newFloorFixture(t, floor, WithUserStore(failingResetTokenStore{NewMemoryUserStore()}))
		f.sendTakes = 800 * time.Millisecond
		work, pad, err := f.ask(t, context.Background(), "known@example.com")
		if !errors.Is(err, errResetTokenWrite) {
			t.Fatalf("err = %v, want the store's error", err)
		}
		if work+pad != floor {
			t.Errorf("work %v + pad %v = %v, want the floor %v", work, pad, work+pad, floor)
		}
	})
}

// TestForgotPasswordFloorNeverPassesTheDeadline: a context whose deadline
// comes before the floor cuts the wait short of the deadline, leaving the
// headroom to write the answer — on a Lambda, the deadline is the function's,
// and an answer written after it is a timeout.
func TestForgotPasswordFloorNeverPassesTheDeadline(t *testing.T) {
	f := newFloorFixture(t, 5*time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), f.clock().Add(time.Second))
	defer cancel()
	_, pad, err := f.ask(t, ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}
	if want := time.Second - forgotPasswordAnswerHeadroom; pad != want {
		t.Errorf("pad = %v, want %v: the deadline less the headroom", pad, want)
	}
}

// TestForgotPasswordFloorAddsNothingPastTheFloor: a branch that already took
// longer than the floor is not held at all. The floor hides the slow branch
// only when it is set above the delivery's worst case.
func TestForgotPasswordFloorAddsNothingPastTheFloor(t *testing.T) {
	f := newFloorFixture(t, 2*time.Second)
	f.sendTakes = 3 * time.Second
	work, pad, err := f.ask(t, context.Background(), "known@example.com")
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}
	if work != 3*time.Second || pad != 0 {
		t.Errorf("work %v, pad %v; want 3s and no pad", work, pad)
	}
}

// TestForgotPasswordFloorUnsetHoldsNothing pins the default, which is the
// behaviour before the option: no branch is held. It passed before the option
// existed.
func TestForgotPasswordFloorUnsetHoldsNothing(t *testing.T) {
	f := newFloorFixture(t, 0)
	f.sendTakes = 1500 * time.Millisecond
	for _, email := range []string{"known@example.com", "nobody@example.com", "invited@example.com"} {
		if _, pad, err := f.ask(t, context.Background(), email); err != nil || pad != 0 {
			t.Errorf("%s: pad %v, err %v; want no hold with the floor unset", email, pad, err)
		}
	}
}

// TestForgotPasswordFloorIsValidated: a negative floor is a mistake, not
// "off", and refused.
func TestForgotPasswordFloorIsValidated(t *testing.T) {
	if _, err := New(WithForgotPasswordMinResponseTime(-time.Second)); err == nil {
		t.Error("a negative ForgotPasswordMinResponseTime was accepted")
	}
	cfg := DefaultConfig(testSecret)
	cfg.ForgotPasswordMinResponseTime = -time.Millisecond
	if _, err := NewWithConfig(cfg); err == nil {
		t.Error("a Config with a negative ForgotPasswordMinResponseTime was accepted")
	}
	if _, err := New(WithForgotPasswordMinResponseTime(0)); err != nil {
		t.Errorf("zero is off and valid: %v", err)
	}
}

// TestForgotPasswordFloorHoldsACancelledRequest: a request whose context is
// cancelled is held to the floor like any other. On a Go net/http server a
// client that half-closes its connection cancels the request context and can
// still read the answer, so ending the hold there would hand it the time the
// work took — the difference the floor hides. The cancellation comes before
// the call, and in the middle of a known address's send. The clock and the
// wait are the real ones here, since the wait itself is what is under test;
// only the lower bound is asserted, which the timer guarantees.
func TestForgotPasswordFloorHoldsACancelledRequest(t *testing.T) {
	const floor = 150 * time.Millisecond
	spy := &passwordEmailSpy{}
	a := newPasswordEmailAuth(t, spy, WithForgotPasswordMinResponseTime(floor))
	if _, _, err := a.Register(context.Background(), RegisterInput{Email: "known@example.com", Password: "password1", TenantID: "t1"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, tc := range []struct {
		name, email string
		midSend     bool
	}{
		{"an unknown address, cancelled before the call", "nobody@example.com", false},
		{"a known address, cancelled before the call", "known@example.com", false},
		{"a known address, cancelled in the middle of the send", "known@example.com", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			spy.inspect = nil
			if tc.midSend {
				spy.inspect = cancel
			} else {
				cancel()
			}
			start := time.Now()
			if _, err := a.ForgotPassword(ctx, ForgotPasswordInput{Email: tc.email, TenantID: "t1"}); err != nil {
				t.Fatalf("forgot password: %v", err)
			}
			if elapsed := time.Since(start); elapsed < floor {
				t.Errorf("answered after %v, before the %v floor", elapsed, floor)
			}
		})
	}
}
