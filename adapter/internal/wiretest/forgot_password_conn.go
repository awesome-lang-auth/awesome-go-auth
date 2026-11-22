package wiretest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Conformance cases for POST /forgot-password over a real connection, where a
// client can hang up half-way: it sends the request and then half-closes its
// side (TCP FIN), which on a Go net/http server cancels the request context
// while the client can still read the answer. A client that does this must
// learn nothing the route hides and must not change what the route does: the
// minimum response time still holds, the link it was mailed is still stored,
// and a store that honours its context still answers a known address as it
// answers an unknown one.
//
// These run against httptest.NewServer, not a recorder, because only a real
// connection carries the half-close; the timings asserted are lower bounds a
// timer guarantees.

// halfClosedForgot posts /forgot-password for email over a fresh connection,
// half-closes it — right after the request, or once hangUp is closed when it
// is not nil — and reads the answer.
func halfClosedForgot(t *testing.T, srv *httptest.Server, env *Env, email string, hangUp <-chan struct{}) (int, map[string]any, time.Duration) {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	body := fmt.Sprintf(`{"email":%q,"tenantId":%q}`, email, testTenant)
	request := fmt.Sprintf("POST %s/forgot-password HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		env.Config.Prefix(), len(body), body)
	start := time.Now()
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write: %v", err)
	}
	if hangUp != nil {
		select {
		case <-hangUp:
		case <-time.After(10 * time.Second):
			t.Fatal("the moment to hang up never came")
		}
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("half-close: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)
	var decoded map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &decoded)
	return resp.StatusCode, decoded, elapsed
}

func assertHalfClosedSuccess(t *testing.T, email string, status int, body map[string]any) {
	t.Helper()
	if status != http.StatusOK || len(body) != 1 || body["success"] != true {
		t.Errorf("%s: answered %d %v, want 200 {\"success\":true}", email, status, body)
	}
}

// ctxResetTokenStore is a MemoryUserStore whose reset-token write honours the
// request context, as a store behind a network call does.
type ctxResetTokenStore struct{ *auth.MemoryUserStore }

func (s ctxResetTokenStore) UpdateResetToken(ctx context.Context, userID, tenantID, hash string, expiry time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.MemoryUserStore.UpdateResetToken(ctx, userID, tenantID, hash, expiry)
}

func testForgotPasswordOverAConnection(t *testing.T, mount Mounter) {
	// The floor holds a request whose client half-closed, for a known and an
	// unknown address alike: ending the hold on the cancellation would hand
	// the client the time the work took.
	t.Run("a half-closed request is still held to the minimum response time", func(t *testing.T) {
		const floor = 300 * time.Millisecond
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithForgotPasswordMinResponseTime(floor))
		env.Seed("halfclosed@example.com")
		srv := httptest.NewServer(env.Handler)
		defer srv.Close()
		for _, email := range []string{"halfclosed@example.com", "nobody@example.com"} {
			status, body, elapsed := halfClosedForgot(t, srv, env, email, nil)
			assertHalfClosedSuccess(t, email, status, body)
			if elapsed < floor {
				t.Errorf("%s: answered after %v, before the %v floor", email, elapsed, floor)
			}
		}
	})

	// The client hangs up while the library's DeliveryWebhook is still waiting
	// for the relay's answer — the relay has the delivery, so the mail goes
	// out. The send runs on to that answer and the token is stored, so the
	// link in the mail works.
	t.Run("a half-closed request still stores the link it mailed", func(t *testing.T) {
		var (
			mu       sync.Mutex
			mailed   []string
			received = make(chan struct{})
		)
		relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var envelope struct {
				Delivery auth.PasswordResetDelivery `json:"delivery"`
			}
			_ = json.NewDecoder(r.Body).Decode(&envelope)
			mu.Lock()
			mailed = append(mailed, envelope.Delivery.Token) // accepted: the mail leaves now
			if len(mailed) == 1 {
				close(received)
			}
			mu.Unlock()
			time.Sleep(300 * time.Millisecond) // and the answer comes later
			w.WriteHeader(http.StatusOK)
		}))
		defer relay.Close()
		hook, err := auth.NewDeliveryWebhook(relay.URL, "")
		if err != nil {
			t.Fatalf("webhook: %v", err)
		}
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithPasswordResetSender(hook.SendPasswordReset))
		env.Seed("mailedlink@example.com")
		srv := httptest.NewServer(env.Handler)
		defer srv.Close()

		// The client hangs up once the relay has the delivery.
		status, body, _ := halfClosedForgot(t, srv, env, "mailedlink@example.com", received)
		assertHalfClosedSuccess(t, "mailedlink@example.com", status, body)
		mu.Lock()
		tokens := append([]string(nil), mailed...)
		mu.Unlock()
		if len(tokens) != 1 {
			t.Fatalf("the relay received %d resets, want 1", len(tokens))
		}
		assertSuccessBody(t, env.Do(env.Request(http.MethodPost, "/reset-password", map[string]string{
			"token": tokens[0], "password": "afterhangup1",
		})))
	})

	// A store whose write honours the request context would fail it for a
	// half-closed request — and only a known address reaches the write, so
	// the 500 alone would name the account.
	t.Run("a half-closed request is answered alike for a known and an unknown address", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(),
			auth.WithUserStore(ctxResetTokenStore{auth.NewMemoryUserStore()}),
			auth.WithPasswordResetSender(func(context.Context, auth.PasswordResetDelivery) error {
				time.Sleep(200 * time.Millisecond) // a relay that answers late
				return nil
			}))
		env.Seed("ctxstore@example.com")
		srv := httptest.NewServer(env.Handler)
		defer srv.Close()
		for _, email := range []string{"ctxstore@example.com", "nobody@example.com"} {
			status, body, _ := halfClosedForgot(t, srv, env, email, nil)
			assertHalfClosedSuccess(t, email, status, body)
		}
	})
}
