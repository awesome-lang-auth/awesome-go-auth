package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests for the order of POST /forgot-password: a reset token is stored only
// once its delivery succeeded. Every issue replaces the token an account
// held, so storing first let a request whose mail was refused or lost kill the
// link the person had been mailed before, for a mail nobody received.

// TestForgotPasswordRefusedSendKeepsTheEarlierLink is the case as a consumer
// meets it, through DeliveryWebhook: the receiver relays the first reset and
// refuses the second — a daily cap answering 429, say — and the link in the
// first mail still has to work.
func TestForgotPasswordRefusedSendKeepsTheEarlierLink(t *testing.T) {
	var (
		mu       sync.Mutex
		received []string
		status   = http.StatusOK
	)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Delivery PasswordResetDelivery `json:"delivery"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		received = append(received, body.Delivery.Token)
		answer := status
		mu.Unlock()
		w.WriteHeader(answer)
	}))
	defer receiver.Close()
	hook, err := NewDeliveryWebhook(receiver.URL, "")
	if err != nil {
		t.Fatalf("webhook: %v", err)
	}
	a := newPasswordEmailAuth(t, nil, WithPasswordResetSender(hook.SendPasswordReset))
	ctx := context.Background()
	if _, _, err := a.Register(ctx, RegisterInput{Email: "relayed@example.com", Password: "password1", TenantID: "t1"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	ask := func() {
		t.Helper()
		if _, err := a.ForgotPassword(ctx, ForgotPasswordInput{Email: "relayed@example.com", TenantID: "t1"}); err != nil {
			t.Fatalf("forgot password: %v", err)
		}
	}

	ask() // relayed
	mu.Lock()
	status = http.StatusTooManyRequests
	mu.Unlock()
	ask() // refused by the receiver; the route still answers success

	if len(received) != 2 {
		t.Fatalf("the receiver saw %d deliveries, want 2", len(received))
	}
	mailed, refused := received[0], received[1]
	if err := a.ResetPassword(ctx, ResetPasswordInput{Token: refused, NewPassword: "notdelivered1"}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("the token whose delivery was refused: err = %v, want ErrInvalidToken; it was never mailed, so it must never have been stored", err)
	}
	if err := a.ResetPassword(ctx, ResetPasswordInput{Token: mailed, NewPassword: "newpassword1"}); err != nil {
		t.Errorf("the link mailed before the refused request: %v; a refused delivery must not kill it", err)
	}
	if _, _, err := a.Login(ctx, LoginInput{Email: "relayed@example.com", Password: "newpassword1", TenantID: "t1"}); err != nil {
		t.Errorf("login with the password set through the mailed link: %v", err)
	}
}

// TestForgotPasswordSendsBeforeItStores observes the order from inside the
// sender: while it runs, the store still holds what the account held before —
// nothing on a first request, the earlier token's hash on a later one — and
// the new hash is there once the send has succeeded.
func TestForgotPasswordSendsBeforeItStores(t *testing.T) {
	spy := &passwordEmailSpy{}
	svc := newPasswordEmailSvc(t, spy)
	user := seedUser(t, svc, "resetorder@example.com")
	var seen string
	spy.inspect = func() { seen = storedUser(t, svc, user.ID).ResetTokenHash }

	first, err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: user.Email, TenantID: "t1"})
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}
	if seen != "" {
		t.Error("the token was stored before its delivery succeeded")
	}
	if got := storedUser(t, svc, user.ID).ResetTokenHash; got != hashToken(first) {
		t.Error("the token was not stored once its delivery succeeded")
	}

	second, err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: user.Email, TenantID: "t1"})
	if err != nil {
		t.Fatalf("forgot password again: %v", err)
	}
	if seen != hashToken(first) {
		t.Error("while the second mail was being sent the store no longer held the first token")
	}
	if got := storedUser(t, svc, user.ID).ResetTokenHash; got != hashToken(second) {
		t.Error("the second token did not replace the first once it was delivered")
	}
}

// TestForgotPasswordFailedSendStoresNothing: the service still reports the
// failed send — ErrDeliveryFailed joined to the transport's error — and stores
// nothing, so the account keeps the token it had.
func TestForgotPasswordFailedSendStoresNothing(t *testing.T) {
	spy := &passwordEmailSpy{}
	svc := newPasswordEmailSvc(t, spy)
	user := seedUser(t, svc, "resetfail@example.com")
	earlier, err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: user.Email, TenantID: "t1"})
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}

	spy.fail = errors.New("mail gateway unreachable")
	_, err = svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: user.Email, TenantID: "t1"})
	if !errors.Is(err, ErrDeliveryFailed) || !errors.Is(err, spy.fail) {
		t.Fatalf("err = %v, want it to wrap both ErrDeliveryFailed and the transport failure", err)
	}
	if got := storedUser(t, svc, user.ID).ResetTokenHash; got != hashToken(earlier) {
		t.Error("a failed send replaced the token the account already held")
	}
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: earlier, NewPassword: "newpassword1"}); err != nil {
		t.Errorf("the earlier link after a failed send: %v", err)
	}
}

// failingResetTokenStore is a MemoryUserStore whose reset-token write fails.
type failingResetTokenStore struct{ *MemoryUserStore }

var errResetTokenWrite = errors.New("reset token write throttled")

func (failingResetTokenStore) UpdateResetToken(context.Context, string, string, string, time.Time) error {
	return errResetTokenWrite
}

// TestForgotPasswordStoreFailureAfterTheSend is what the order costs: a store
// write that fails after a delivery that succeeded leaves a mailed link that
// was never stored. It is the store failure it always was on the wire — the
// generic 500, not swallowed — and it is logged, because the mail in the
// person's inbox will not work and nothing else says why.
func TestForgotPasswordStoreFailureAfterTheSend(t *testing.T) {
	spy := &passwordEmailSpy{}
	var (
		mu     sync.Mutex
		logged []string
	)
	a := newPasswordEmailAuth(t, spy,
		WithUserStore(failingResetTokenStore{NewMemoryUserStore()}),
		WithLogger(func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, fmt.Sprintf(format, args...))
		}))
	if _, _, err := a.Register(context.Background(), RegisterInput{Email: "storefail@example.com", Password: "password1", TenantID: "t1"}); err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err := a.ForgotPassword(context.Background(), ForgotPasswordInput{Email: "storefail@example.com", TenantID: "t1"})
	if !errors.Is(err, errResetTokenWrite) || errors.Is(err, ErrDeliveryFailed) {
		t.Fatalf("err = %v, want the store's error and not a delivery failure", err)
	}
	if got := ForgotPasswordHTTPError(err); got != HTTPErrInternal {
		t.Errorf("wire answer = %+v, want the generic 500", got)
	}
	if len(spy.resets) != 1 {
		t.Fatalf("the sender was called %d times, want 1: the send comes first", len(spy.resets))
	}
	var line string
	for _, l := range logged {
		if strings.Contains(l, "could not be stored") {
			line = l
		}
	}
	if line == "" || strings.Contains(line, "storefail@example.com") {
		t.Errorf("log lines = %q, want one saying the mailed link will not work, without the address", logged)
	}
}

// ctxResetTokenStore is a MemoryUserStore whose reset-token write honours the
// context, as a store behind a network call does: a cancelled context fails
// the write.
type ctxResetTokenStore struct{ *MemoryUserStore }

func (s ctxResetTokenStore) UpdateResetToken(ctx context.Context, userID, tenantID, hash string, expiry time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.MemoryUserStore.UpdateResetToken(ctx, userID, tenantID, hash, expiry)
}

// ctxInvitationStore is a MemoryInvitationStore whose read of an account's
// invitations honours the context in the same way.
type ctxInvitationStore struct{ *MemoryInvitationStore }

func (s ctxInvitationStore) PendingInvitationsForUser(ctx context.Context, userID string) ([]Invitation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.MemoryInvitationStore.PendingInvitationsForUser(ctx, userID)
}

// TestForgotPasswordACallerThatLeavesCannotSplitTheSendFromTheStore: a
// caller that goes away once the address has named an account — on a Go
// net/http server, a client that half-closes its connection, which cancels
// the request context and can still read the answer — changes nothing. The
// sender runs under a live context and the token it mailed is stored, so the
// mailed link works; and neither the store write nor the invitation check
// fails for the cancellation, which would answer an error only a known
// address can get. The request's deadline still bounds the work.
func TestForgotPasswordACallerThatLeavesCannotSplitTheSendFromTheStore(t *testing.T) {
	t.Run("cancelled in the middle of the send", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var mailed string
		var seen error
		a := newPasswordEmailAuth(t, nil,
			WithUserStore(ctxResetTokenStore{NewMemoryUserStore()}),
			WithPasswordResetSender(func(sctx context.Context, d PasswordResetDelivery) error {
				mailed = d.Token
				cancel() // the client hangs up while the relay is still answering
				seen = sctx.Err()
				return sctx.Err() // what a sender that honours its context answers
			}))
		if _, _, err := a.Register(context.Background(), RegisterInput{Email: "leaves@example.com", Password: "password1", TenantID: "t1"}); err != nil {
			t.Fatalf("register: %v", err)
		}
		if _, err := a.ForgotPassword(ctx, ForgotPasswordInput{Email: "leaves@example.com", TenantID: "t1"}); err != nil {
			t.Fatalf("forgot password: %v; a client going away must not turn a known address into an error", err)
		}
		if seen != nil {
			t.Errorf("the sender saw its context end (%v) when the caller went away", seen)
		}
		if err := a.ResetPassword(context.Background(), ResetPasswordInput{Token: mailed, NewPassword: "newpassword1"}); err != nil {
			t.Errorf("the link mailed to a caller that went away: %v; it must have been stored", err)
		}
	})

	t.Run("cancelled before the account was read further", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		a := newPasswordEmailAuth(t, &passwordEmailSpy{},
			WithUserStore(ctxResetTokenStore{NewMemoryUserStore()}),
			WithInvitationStore(ctxInvitationStore{NewMemoryInvitationStore()}))
		if _, _, err := a.Register(context.Background(), RegisterInput{Email: "known@example.com", Password: "password1", TenantID: "t1"}); err != nil {
			t.Fatalf("register: %v", err)
		}
		if _, err := a.Service().InviteUser(context.Background(), InviteUserInput{Email: "invited@example.com", TenantID: "t1"}); err != nil {
			t.Fatalf("invite: %v", err)
		}
		// The memory store's lookup ignores the context, so both addresses
		// name an account; what follows the lookup honours it.
		for _, email := range []string{"known@example.com", "invited@example.com", "nobody@example.com"} {
			if _, err := a.ForgotPassword(ctx, ForgotPasswordInput{Email: email, TenantID: "t1"}); err != nil {
				t.Errorf("%s: %v; a cancelled request must answer as any other", email, err)
			}
		}
	})

	t.Run("the deadline still applies", func(t *testing.T) {
		deadline := time.Now().Add(time.Minute)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		var got time.Time
		var had bool
		a := newPasswordEmailAuth(t, nil, WithPasswordResetSender(func(sctx context.Context, _ PasswordResetDelivery) error {
			got, had = sctx.Deadline()
			return nil
		}))
		if _, _, err := a.Register(context.Background(), RegisterInput{Email: "deadline@example.com", Password: "password1", TenantID: "t1"}); err != nil {
			t.Fatalf("register: %v", err)
		}
		if _, err := a.ForgotPassword(ctx, ForgotPasswordInput{Email: "deadline@example.com", TenantID: "t1"}); err != nil {
			t.Fatalf("forgot password: %v", err)
		}
		if !had || !got.Equal(deadline) {
			t.Errorf("the sender's deadline = %v (%v), want the request's %v", got, had, deadline)
		}
	})
}
