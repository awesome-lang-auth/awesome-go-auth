package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The endpoint is validated at construction so that a misconfiguration surfaces
// at start-up rather than as a 500 on the first send. A rejection must never
// quote the API key.
func TestNewGatewayMailerTransportEndpointValidation(t *testing.T) {
	const key = "key-must-not-leak"
	cases := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{"empty", "", true},
		{"relative path", "/mail/send", true},
		{"host without scheme", "mail.example.com/send", true},
		{"unparseable", "http://[::1", true},
		{"scheme without host", "http:///send", true},
		{"not an http scheme", "mailto:ops@example.com", true},
		{"http", "http://mail.example.com/send", false},
		{"https with a query of its own", "https://mail.example.com/send?account=a1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport, err := NewGatewayMailerTransport(MailerConfig{Endpoint: tc.endpoint, APIKey: key})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil {
				if transport != nil {
					t.Error("a failed constructor must not hand back a transport")
				}
				if strings.Contains(err.Error(), key) {
					t.Errorf("error %q quotes the API key", err)
				}
				return
			}
			if transport == nil {
				t.Fatal("constructor returned neither a transport nor an error")
			}
		})
	}
}

// TestGatewayMailerTransportRequestShape pins the reference gateway contract:
// POST to the endpoint, path and query kept, Content-Type application/json,
// the API key in X-API-Key, and the body {to, subject, html, text, from,
// fromName, provider} with exactly those keys (mailer.service.ts:133-141,
// 261-291). Each case lists the entire body it expects; an extra key fails.
func TestGatewayMailerTransportRequestShape(t *testing.T) {
	cases := []struct {
		name string
		cfg  MailerConfig // Endpoint is filled in by the test
		msg  MailMessage
		want map[string]string
	}{
		{
			name: "html body with a text alternative, every config field set",
			cfg:  MailerConfig{APIKey: "key-abc", From: "noreply@example.com", FromName: "Example", Provider: "ses"},
			msg:  MailMessage{To: "u@example.com", Subject: "Hi", Body: "<p>hi</p>", IsHTML: true, Text: "hi"},
			want: map[string]string{
				"to":       "u@example.com",
				"subject":  "Hi",
				"html":     "<p>hi</p>",
				"text":     "hi",
				"from":     "noreply@example.com",
				"fromName": "Example",
				"provider": "ses",
			},
		},
		{
			// text ?? html (mailer.service.ts:246); fromName and provider are
			// optional in the reference and absent when unset, not blank.
			name: "html body without text sends the html as text; unset optionals are absent",
			cfg:  MailerConfig{APIKey: "key-abc", From: "noreply@example.com"},
			msg:  MailMessage{To: "u@example.com", Subject: "Hi", Body: "<p>hi</p>", IsHTML: true},
			want: map[string]string{
				"to":      "u@example.com",
				"subject": "Hi",
				"html":    "<p>hi</p>",
				"text":    "<p>hi</p>",
				"from":    "noreply@example.com",
			},
		},
		{
			// The reference has no text-only path; html is sent empty rather
			// than filled with a body that is not HTML. Text is ignored because
			// Body already is the text.
			name: "plain text body goes out as text with an empty html",
			cfg:  MailerConfig{APIKey: "key-abc", From: "noreply@example.com", Provider: "smtp"},
			msg:  MailMessage{To: "u@example.com", Subject: "Hi", Body: "hi there", Text: "ignored"},
			want: map[string]string{
				"to":       "u@example.com",
				"subject":  "Hi",
				"html":     "",
				"text":     "hi there",
				"from":     "noreply@example.com",
				"provider": "smtp",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			type captured struct {
				method      string
				path        string
				rawQuery    string
				contentType string
				apiKey      string
				body        map[string]any
				decodeErr   error
			}
			var got captured
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got.method = r.Method
				got.path = r.URL.Path
				got.rawQuery = r.URL.RawQuery
				got.contentType = r.Header.Get("Content-Type")
				got.apiKey = r.Header.Get("X-API-Key")
				raw, err := io.ReadAll(r.Body)
				if err == nil {
					err = json.Unmarshal(raw, &got.body)
				}
				got.decodeErr = err
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			cfg := tc.cfg
			// The endpoint carries a path and a parameter of its own; both survive.
			cfg.Endpoint = server.URL + "/mail/send?account=acct1"
			transport, err := NewGatewayMailerTransport(cfg)
			if err != nil {
				t.Fatalf("constructor: %v", err)
			}
			if err := transport.Send(context.Background(), tc.msg); err != nil {
				t.Fatalf("send: %v", err)
			}

			if got.method != http.MethodPost {
				t.Errorf("method = %s, want POST", got.method)
			}
			if got.path != "/mail/send" {
				t.Errorf("path = %q", got.path)
			}
			if got.rawQuery != "account=acct1" {
				t.Errorf("query = %q", got.rawQuery)
			}
			if got.contentType != "application/json" {
				t.Errorf("Content-Type = %q", got.contentType)
			}
			if got.apiKey != tc.cfg.APIKey {
				t.Errorf("X-API-Key = %q, want %q", got.apiKey, tc.cfg.APIKey)
			}
			if got.decodeErr != nil {
				t.Fatalf("body is not JSON: %v", got.decodeErr)
			}
			for key, want := range tc.want {
				value, ok := got.body[key].(string)
				if !ok {
					t.Errorf("body[%q] = %v (%T), want the string %q", key, got.body[key], got.body[key], want)
					continue
				}
				if value != want {
					t.Errorf("body[%q] = %q, want %q", key, value, want)
				}
			}
			for key := range got.body {
				if _, ok := tc.want[key]; !ok {
					t.Errorf("body carries an unexpected key %q", key)
				}
			}
		})
	}
}

// The header is sent even when the key is blank: the reference always sets it
// (mailer.service.ts:274), and a gateway that keys on its presence must not see
// the request change shape because a deployment left the value empty.
func TestGatewayMailerTransportAlwaysSendsTheAPIKeyHeader(t *testing.T) {
	present := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["X-Api-Key"]
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport, err := NewGatewayMailerTransport(MailerConfig{Endpoint: server.URL, From: "a@b"})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if err := transport.Send(context.Background(), MailMessage{To: "u@example.com", Body: "m"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !present {
		t.Error("X-API-Key was omitted for an empty key")
	}
}

// 2xx only, as the reference has it (mailer.service.ts:280-284): every 2xx is
// delivered, and a 3xx or a 4xx/5xx from a misbehaving gateway is not. An error
// names the status.
func TestGatewayMailerTransportStatusHandling(t *testing.T) {
	cases := []struct {
		status  int
		wantErr bool
	}{
		{http.StatusOK, false},
		{http.StatusCreated, false},
		{http.StatusAccepted, false},
		{http.StatusNoContent, false},
		{http.StatusMovedPermanently, true},
		{http.StatusBadRequest, true},
		{http.StatusUnauthorized, true},
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer server.Close()

			transport, err := NewGatewayMailerTransport(MailerConfig{Endpoint: server.URL, APIKey: "k", From: "a@b"})
			if err != nil {
				t.Fatalf("constructor: %v", err)
			}
			err = transport.Send(context.Background(), MailMessage{To: "u@example.com", Body: "m"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("status %d: err = %v, wantErr %v", tc.status, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), fmt.Sprint(tc.status)) {
				t.Errorf("error %q does not name the status %d", err, tc.status)
			}
		})
	}
}

// Whatever goes wrong — a gateway that echoes the header back in its error
// body, a connection that never opens, a context already cancelled — the error
// a caller gets must not carry the API key: senders' errors are host code's to
// log.
func TestGatewayMailerTransportErrorsNeverCarryTheAPIKey(t *testing.T) {
	const key = "sk-live-do-not-leak"

	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"bad key %s"}`, r.Header.Get("X-API-Key"))
	}))
	defer echo.Close()

	// A server that has been closed keeps its address and refuses connections.
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name     string
		endpoint string
		ctx      context.Context
	}{
		{"non-2xx whose body echoes the key", echo.URL, context.Background()},
		{"connection refused", closedURL, context.Background()},
		{"context already cancelled", echo.URL, cancelled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport, err := NewGatewayMailerTransport(MailerConfig{Endpoint: tc.endpoint, APIKey: key, From: "a@b"})
			if err != nil {
				t.Fatalf("constructor: %v", err)
			}
			err = transport.Send(tc.ctx, MailMessage{To: "u@example.com", Body: "m"})
			if err == nil {
				t.Fatal("send succeeded; the case is meant to fail")
			}
			if strings.Contains(err.Error(), key) {
				t.Errorf("error %q carries the API key", err)
			}
		})
	}
}

// roundTripFunc lets a test stand in for the network.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Without a client the request is bounded by the same 10-second timeout the
// other HTTP transports use; with one, that client makes the request.
func TestGatewayMailerTransportClient(t *testing.T) {
	t.Run("default is bounded", func(t *testing.T) {
		transport, err := NewGatewayMailerTransport(MailerConfig{Endpoint: "https://mail.example.com/send"})
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}
		gateway, ok := transport.(*gatewayMailerTransport)
		if !ok {
			t.Fatalf("transport is a %T", transport)
		}
		if gateway.client == nil || gateway.client.Timeout != 10*time.Second {
			t.Errorf("default client = %+v, want a 10s timeout", gateway.client)
		}
	})

	t.Run("injected client is used", func(t *testing.T) {
		used := false
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			used = true
			if r.URL.String() != "https://mail.example.com/send" {
				t.Errorf("url = %s", r.URL)
			}
			return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(""))}, nil
		})}
		transport, err := NewGatewayMailerTransport(MailerConfig{Endpoint: "https://mail.example.com/send", Client: client})
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}
		if err := transport.Send(context.Background(), MailMessage{To: "u@example.com", Body: "m"}); err != nil {
			t.Fatalf("send: %v", err)
		}
		if !used {
			t.Error("the injected client was bypassed")
		}
	})
}
