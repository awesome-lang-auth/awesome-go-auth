package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests for the delivery webhook. The request it sends has no reference wire
// (upstream plan D-3), so what is pinned here is this port's own contract as
// README_DETAILED.md "Delivery webhook" states it: the exact body per kind, the
// four family headers, the signature a receiver verifies, and what an error may
// and may not say.

// webhookCall is one request as the receiver saw it.
type webhookCall struct {
	method string
	path   string
	header http.Header
	body   []byte
}

// webhookReceiver is an httptest server that records every request and answers
// with a fixed status and body.
type webhookReceiver struct {
	*httptest.Server
	mu     sync.Mutex
	calls  []webhookCall
	status int
	reply  string
}

func newWebhookReceiver(t *testing.T, status int) *webhookReceiver {
	t.Helper()
	rcv := &webhookReceiver{status: status}
	rcv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		rcv.mu.Lock()
		rcv.calls = append(rcv.calls, webhookCall{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Clone(),
			body:   body,
		})
		reply := rcv.reply
		rcv.mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(rcv.Close)
	return rcv
}

func (r *webhookReceiver) last(t *testing.T) webhookCall {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		t.Fatal("the receiver saw no request")
	}
	return r.calls[len(r.calls)-1]
}

func (r *webhookReceiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// The fixtures every kind is sent with. The expiry is fixed so the body can be
// pinned byte for byte.
var (
	webhookExpiry   = time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	webhookFixtures = []struct {
		kind   string
		send   func(*DeliveryWebhook, context.Context) error
		body   string
		secret string // the credential the body carries
		to     string // the full recipient
	}{
		{
			kind: DeliveryKindMagicLink,
			send: func(w *DeliveryWebhook, ctx context.Context) error {
				return w.SendMagicLink(ctx, MagicLinkDelivery{UserID: "usr_1", TenantID: "t1", Email: "ada@example.com", Token: "tok-magic-9f3a", ExpiresAt: webhookExpiry})
			},
			body:   `{"kind":"magic-link","delivery":{"userId":"usr_1","tenantId":"t1","email":"ada@example.com","token":"tok-magic-9f3a","expiresAt":"2026-09-11T10:00:00Z"}}`,
			secret: "tok-magic-9f3a",
			to:     "ada@example.com",
		},
		{
			kind: DeliveryKindPasswordReset,
			send: func(w *DeliveryWebhook, ctx context.Context) error {
				return w.SendPasswordReset(ctx, PasswordResetDelivery{UserID: "usr_1", TenantID: "t1", Email: "ada@example.com", Token: "tok-reset-9f3a", ExpiresAt: webhookExpiry})
			},
			body:   `{"kind":"password-reset","delivery":{"userId":"usr_1","tenantId":"t1","email":"ada@example.com","token":"tok-reset-9f3a","expiresAt":"2026-09-11T10:00:00Z"}}`,
			secret: "tok-reset-9f3a",
			to:     "ada@example.com",
		},
		{
			kind: DeliveryKindEmailVerification,
			send: func(w *DeliveryWebhook, ctx context.Context) error {
				return w.SendEmailVerification(ctx, EmailVerificationDelivery{UserID: "usr_1", TenantID: "t1", Email: "ada@example.com", Token: "tok-verify-9f3a", ExpiresAt: webhookExpiry})
			},
			body:   `{"kind":"email-verification","delivery":{"userId":"usr_1","tenantId":"t1","email":"ada@example.com","token":"tok-verify-9f3a","expiresAt":"2026-09-11T10:00:00Z"}}`,
			secret: "tok-verify-9f3a",
			to:     "ada@example.com",
		},
		{
			kind: DeliveryKindEmailChange,
			send: func(w *DeliveryWebhook, ctx context.Context) error {
				return w.SendEmailChange(ctx, EmailChangeDelivery{UserID: "usr_1", TenantID: "t1", NewEmail: "ada.new@example.org", Token: "tok-change-9f3a", ExpiresAt: webhookExpiry})
			},
			body:   `{"kind":"email-change","delivery":{"userId":"usr_1","tenantId":"t1","newEmail":"ada.new@example.org","token":"tok-change-9f3a","expiresAt":"2026-09-11T10:00:00Z"}}`,
			secret: "tok-change-9f3a",
			to:     "ada.new@example.org",
		},
		{
			kind: DeliveryKindSMSCode,
			send: func(w *DeliveryWebhook, ctx context.Context) error {
				return w.SendSMSCode(ctx, SMSCodeDelivery{UserID: "usr_1", TenantID: "t1", Phone: "+15555550104", Code: "482913", ExpiresAt: webhookExpiry})
			},
			body:   `{"kind":"sms-code","delivery":{"userId":"usr_1","tenantId":"t1","phone":"+15555550104","code":"482913","expiresAt":"2026-09-11T10:00:00Z"}}`,
			secret: "482913",
			to:     "+15555550104",
		},
		{
			kind: DeliveryKindInvitation,
			send: func(w *DeliveryWebhook, ctx context.Context) error {
				return w.SendInvitation(ctx, InvitationDelivery{InvitationID: "inv_1", UserID: "usr_1", TenantID: "t1", Email: "ada@example.com", Role: "operator", Token: "tok-invite-9f3a", ExpiresAt: webhookExpiry})
			},
			body:   `{"kind":"invitation","delivery":{"invitationId":"inv_1","userId":"usr_1","tenantId":"t1","email":"ada@example.com","role":"operator","token":"tok-invite-9f3a","expiresAt":"2026-09-11T10:00:00Z"}}`,
			secret: "tok-invite-9f3a",
			to:     "ada@example.com",
		},
	}
)

// One value has to be wireable to all six seams; that is the point of it.
var (
	_ MagicLinkSender         = (&DeliveryWebhook{}).SendMagicLink
	_ PasswordResetSender     = (&DeliveryWebhook{}).SendPasswordReset
	_ EmailVerificationSender = (&DeliveryWebhook{}).SendEmailVerification
	_ EmailChangeSender       = (&DeliveryWebhook{}).SendEmailChange
	_ SMSCodeSender           = (&DeliveryWebhook{}).SendSMSCode
	_ InvitationSender        = (&DeliveryWebhook{}).SendInvitation
)

func TestDeliveryWebhookWiresToEverySeam(t *testing.T) {
	hook, err := NewDeliveryWebhook("https://hooks.example.com/auth-delivery", "s3cret")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	a, err := New(
		WithUserStore(NewMemoryUserStore()),
		WithSessionStore(NewMemorySessionStore()),
		WithMagicLinkSender(hook.SendMagicLink),
		WithPasswordResetSender(hook.SendPasswordReset),
		WithEmailVerificationSender(hook.SendEmailVerification),
		WithEmailChangeSender(hook.SendEmailChange),
		WithSMSCodeSender(hook.SendSMSCode),
		WithInvitationSender(hook.SendInvitation),
	)
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	if a == nil {
		t.Fatal("nil auth")
	}
}

func TestNewDeliveryWebhookValidatesTheURL(t *testing.T) {
	for _, bad := range []string{
		"",
		"hooks.example.com/auth-delivery", // no scheme
		"/auth-delivery",                  // relative
		"ftp://hooks.example.com/x",       // not http(s)
		"http://",                         // no host
		"http://[::1",                     // unparseable
	} {
		if _, err := NewDeliveryWebhook(bad, ""); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, good := range []string{
		"http://localhost:8080/hook",
		"https://hooks.example.com/auth-delivery?tenant=t1",
		"HTTPS://hooks.example.com/x",
	} {
		hook, err := NewDeliveryWebhook(good, "s3cret")
		if err != nil {
			t.Errorf("%q was refused: %v", good, err)
			continue
		}
		if hook.URL != good || hook.Secret != "s3cret" {
			t.Errorf("%q: fields not carried: %+v", good, hook)
		}
		if hook.Timeout != 5*time.Second {
			t.Errorf("%q: default timeout = %v, want 5s", good, hook.Timeout)
		}
	}
}

// TestDeliveryWebhookRequestShape pins the body byte for byte, per kind: the
// {"kind","delivery"} envelope, the camelCase field names, the field order, and
// the RFC 3339 expiry. A receiver is written against exactly this.
func TestDeliveryWebhookRequestShape(t *testing.T) {
	for _, tc := range webhookFixtures {
		t.Run(tc.kind, func(t *testing.T) {
			rcv := newWebhookReceiver(t, http.StatusOK)
			hook, err := NewDeliveryWebhook(rcv.URL+"/auth-delivery", "")
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			if err := tc.send(hook, context.Background()); err != nil {
				t.Fatalf("send: %v", err)
			}
			call := rcv.last(t)
			if call.method != http.MethodPost {
				t.Errorf("method = %s, want POST", call.method)
			}
			if call.path != "/auth-delivery" {
				t.Errorf("path = %q", call.path)
			}
			if got := call.header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q", got)
			}
			if got := call.header.Get("X-Webhook-Event"); got != "delivery."+tc.kind {
				t.Errorf("X-Webhook-Event = %q, want %q", got, "delivery."+tc.kind)
			}
			if string(call.body) != tc.body {
				t.Errorf("body =\n%s\nwant\n%s", call.body, tc.body)
			}
		})
	}
}

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// The delivery id is a fresh UUID per request and the timestamp is
// toISOString's form (webhook-sender.ts:27-28); without a secret there is no
// signature header at all (:31-33).
func TestDeliveryWebhookEnvelopeHeaders(t *testing.T) {
	rcv := newWebhookReceiver(t, http.StatusOK)
	hook, err := NewDeliveryWebhook(rcv.URL, "")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	before := time.Now().Add(-time.Second)
	for i := 0; i < 2; i++ {
		if err := hook.SendMagicLink(context.Background(), MagicLinkDelivery{Email: "ada@example.com", Token: "t", ExpiresAt: webhookExpiry}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	after := time.Now().Add(time.Second)

	rcv.mu.Lock()
	calls := append([]webhookCall(nil), rcv.calls...)
	rcv.mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("receiver saw %d requests, want 2", len(calls))
	}
	ids := map[string]bool{}
	for _, call := range calls {
		id := call.header.Get("X-Webhook-Delivery")
		if !uuidV4.MatchString(id) {
			t.Errorf("X-Webhook-Delivery = %q, want a v4 UUID", id)
		}
		ids[id] = true

		ts := call.header.Get("X-Webhook-Timestamp")
		parsed, err := time.Parse("2006-01-02T15:04:05.000Z07:00", ts)
		if err != nil || !strings.HasSuffix(ts, "Z") {
			t.Errorf("X-Webhook-Timestamp = %q, want ISO 8601 UTC with milliseconds (%v)", ts, err)
		} else if parsed.Before(before) || parsed.After(after) {
			t.Errorf("X-Webhook-Timestamp = %q is not now", ts)
		}

		if _, present := call.header["X-Webhook-Signature"]; present {
			t.Error("X-Webhook-Signature was sent without a secret")
		}
	}
	if len(ids) != 2 {
		t.Errorf("delivery ids were not fresh per request: %v", ids)
	}
}

// The signature is the reference's sign(): "sha256=" + hex(HMAC-SHA256(secret,
// body)) over the raw body (webhook-sender.ts:54-56). It is recomputed here from
// scratch, and cross-checked with the package's own verifier so the two halves
// of this family agree.
func TestDeliveryWebhookSignsTheBodyWithTheSecret(t *testing.T) {
	const secret = "whsec_0123456789abcdef"
	for _, tc := range webhookFixtures {
		t.Run(tc.kind, func(t *testing.T) {
			rcv := newWebhookReceiver(t, http.StatusOK)
			hook, err := NewDeliveryWebhook(rcv.URL, secret)
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			if err := tc.send(hook, context.Background()); err != nil {
				t.Fatalf("send: %v", err)
			}
			call := rcv.last(t)
			got := call.header.Get("X-Webhook-Signature")

			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(call.body)
			want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			if got != want {
				t.Errorf("X-Webhook-Signature = %q, want %q", got, want)
			}
			if err := VerifyWebhookSignature(secret, call.body, got); err != nil {
				t.Errorf("VerifyWebhookSignature rejected the sender's own signature: %v", err)
			}
			if err := VerifyWebhookSignature("not-the-secret", call.body, got); err == nil {
				t.Error("the signature verified under a different secret")
			}
			if err := VerifyWebhookSignature(secret, append([]byte(nil), call.body[1:]...), got); err == nil {
				t.Error("the signature verified over a tampered body")
			}
		})
	}
}

// 2xx is delivered; everything else is not, redirects included.
func TestDeliveryWebhookStatusContract(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent} {
		rcv := newWebhookReceiver(t, status)
		hook, _ := NewDeliveryWebhook(rcv.URL, "")
		if err := hook.SendSMSCode(context.Background(), SMSCodeDelivery{Phone: "+1", Code: "1"}); err != nil {
			t.Errorf("status %d: %v", status, err)
		}
	}
	for _, status := range []int{http.StatusMovedPermanently, http.StatusBadRequest, http.StatusUnauthorized, http.StatusInternalServerError, http.StatusBadGateway} {
		rcv := newWebhookReceiver(t, status)
		hook, _ := NewDeliveryWebhook(rcv.URL, "")
		err := hook.SendSMSCode(context.Background(), SMSCodeDelivery{Phone: "+1", Code: "1"})
		if err == nil {
			t.Errorf("status %d was accepted as delivered", status)
			continue
		}
		if !strings.Contains(err.Error(), "status "+strconv.Itoa(status)) {
			t.Errorf("status %d: error does not name it: %v", status, err)
		}
	}
}

func TestDeliveryWebhookTransportFailureIsAnError(t *testing.T) {
	rcv := newWebhookReceiver(t, http.StatusOK)
	hook, _ := NewDeliveryWebhook(rcv.URL, "")
	rcv.Close() // connection refused from here on
	if err := hook.SendMagicLink(context.Background(), MagicLinkDelivery{Email: "ada@example.com", Token: "t"}); err == nil {
		t.Error("a refused connection was reported as delivered")
	}
}

// The timeout is honoured: a receiver that never answers costs Timeout, not the
// route's patience, and the error says why.
func TestDeliveryWebhookHonoursTheTimeout(t *testing.T) {
	// The handler holds every request until the test releases it. It does not
	// wait on r.Context() alone: the server only watches for the client hanging
	// up once the body has been read, and a receiver that stalls before reading
	// is exactly the case a timeout is for.
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}))
	defer server.Close() // runs second: waits for the handlers…
	defer close(release) // …which this lets go first

	hook, err := NewDeliveryWebhook(server.URL, "")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	hook.Timeout = 50 * time.Millisecond

	start := time.Now()
	err = hook.SendPasswordReset(context.Background(), PasswordResetDelivery{Email: "ada@example.com", Token: "t"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a receiver that never answered was reported as delivered")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error does not unwrap to context.DeadlineExceeded: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("send took %v with a 50ms timeout", elapsed)
	}

	// A deadline already on ctx that is shorter than Timeout wins.
	hook.Timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start = time.Now()
	if err := hook.SendPasswordReset(ctx, PasswordResetDelivery{Email: "ada@example.com", Token: "t"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("caller's deadline was not honoured: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("send took %v with a 50ms caller deadline", elapsed)
	}
}

// A zero Timeout on a struct literal means the default, not "forever": the
// request context carries a deadline either way.
func TestDeliveryWebhookZeroTimeoutMeansTheDefault(t *testing.T) {
	var deadlineSet bool
	rcv := newWebhookReceiver(t, http.StatusOK)
	hook := &DeliveryWebhook{
		URL: rcv.URL,
		Client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			_, deadlineSet = r.Context().Deadline()
			return http.DefaultTransport.RoundTrip(r)
		})},
	}
	if err := hook.SendSMSCode(context.Background(), SMSCodeDelivery{Phone: "+1", Code: "1"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !deadlineSet {
		t.Error("no deadline on the request with Timeout unset")
	}
}

// The supplied Client is the one used, so a deployment can put its own
// transport, proxy or instrumentation on the path.
func TestDeliveryWebhookUsesTheSuppliedClient(t *testing.T) {
	var seen string
	hook := &DeliveryWebhook{
		URL: "https://hooks.example.com/auth-delivery",
		Client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			seen = r.URL.String()
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		})},
	}
	if err := hook.SendSMSCode(context.Background(), SMSCodeDelivery{Phone: "+1", Code: "1"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if seen != "https://hooks.example.com/auth-delivery" {
		t.Errorf("request went to %q", seen)
	}
}

// TestDeliveryWebhookErrorsNeverLeakTheCredential is the contract that matters
// most: an error is logged (Auth.ForgotPassword) and inspected by host code, so
// whatever it says must not be the token, the code, the full recipient or the
// secret — even when the receiver echoes the whole request back in its failure
// body. The recipient's domain is allowed, and expected, for mail.
func TestDeliveryWebhookErrorsNeverLeakTheCredential(t *testing.T) {
	const secret = "whsec_do_not_print_me"
	for _, tc := range webhookFixtures {
		t.Run(tc.kind, func(t *testing.T) {
			// A 500 whose body parrots the request, then a dead endpoint.
			rcv := newWebhookReceiver(t, http.StatusInternalServerError)
			rcv.mu.Lock()
			rcv.reply = `{"error":"rejected","echo":` + tc.body + `,"secret":"` + secret + `"}`
			rcv.mu.Unlock()
			hook, err := NewDeliveryWebhook(rcv.URL, secret)
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			statusErr := tc.send(hook, context.Background())
			rcv.Close()
			transportErr := tc.send(hook, context.Background())

			for name, err := range map[string]error{"status": statusErr, "transport": transportErr} {
				if err == nil {
					t.Fatalf("%s: no error", name)
				}
				msg := err.Error()
				for _, forbidden := range []string{tc.secret, tc.to, secret} {
					if strings.Contains(msg, forbidden) {
						t.Errorf("%s error carries %q: %s", name, forbidden, msg)
					}
				}
				if !strings.Contains(msg, "delivery webhook "+tc.kind) {
					t.Errorf("%s error does not name the kind: %s", name, msg)
				}
				if at := strings.LastIndex(tc.to, "@"); at >= 0 {
					if domain := tc.to[at:]; !strings.Contains(msg, domain) {
						t.Errorf("%s error does not name the recipient's domain %q: %s", name, domain, msg)
					}
				}
			}
		})
	}
}

func TestDeliveryWebhookNilReceiver(t *testing.T) {
	var hook *DeliveryWebhook
	if err := hook.SendMagicLink(context.Background(), MagicLinkDelivery{}); err == nil {
		t.Error("a nil webhook must fail, not panic or succeed")
	}
}

func TestEmailDomain(t *testing.T) {
	for in, want := range map[string]string{
		"ada@example.com":    "@example.com",
		"a@b@example.org":    "@example.org",
		"no-at-sign":         "",
		"trailing-at@":       "",
		"":                   "",
		"@only-domain.test":  "@only-domain.test",
		"ada@sub.example.io": "@sub.example.io",
	} {
		if got := emailDomain(in); got != want {
			t.Errorf("emailDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
