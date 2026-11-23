package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The body bound by itself. The wiretest suite holds the four adapters to it
// on every route it covers; these are the branches a route cannot easily
// reach: what is handed on, what is never read, and a body that stops
// arriving.

// refuseToBeRead fails the test if anything reads from it.
type refuseToBeRead struct{ t *testing.T }

func (r refuseToBeRead) Read([]byte) (int, error) {
	r.t.Error("a body whose declared length is over the bound was read")
	return 0, io.EOF
}

// brokenBody delivers a few bytes and then fails, like a client that went away.
type brokenBody struct{ sent bool }

func (b *brokenBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, `{"email":"`), nil
	}
	return 0, errors.New("connection reset by peer")
}

func envelope(t *testing.T, rec *httptest.ResponseRecorder) HTTPError {
	t.Helper()
	var got HTTPError
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	got.Status = rec.Code
	return got
}

func TestLimitCredentialRouteBody(t *testing.T) {
	t.Run("a body within the bound is handed on byte for byte", func(t *testing.T) {
		sent := `{"email":"within@example.com","emailLang":"it"}  ` + "\n"
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", strings.NewReader(sent))
		req.ContentLength = -1 // as if chunked: the bound must not rely on it
		rec := httptest.NewRecorder()
		if !LimitCredentialRouteBody(rec, req) {
			t.Fatalf("refused: %d %s", rec.Code, rec.Body.String())
		}
		got, err := io.ReadAll(req.Body)
		if err != nil || string(got) != sent {
			t.Errorf("handed on %q (%v), want %q", got, err, sent)
		}
		if req.ContentLength != int64(len(sent)) {
			t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(sent))
		}
	})

	t.Run("an absent body is left alone", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", nil)
		rec := httptest.NewRecorder()
		if !LimitCredentialRouteBody(rec, req) || rec.Body.Len() != 0 {
			t.Errorf("an absent body was refused or answered: %d %q", rec.Code, rec.Body.String())
		}
	})

	t.Run("a declared length over the bound is refused unread", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", refuseToBeRead{t})
		req.ContentLength = CredentialRouteMaxBodyBytes + 1
		rec := httptest.NewRecorder()
		if LimitCredentialRouteBody(rec, req) {
			t.Fatal("an over-large declared body was let through")
		}
		if got := envelope(t, rec); got != HTTPErrBodyTooLarge {
			t.Errorf("answer = %+v, want %+v", got, HTTPErrBodyTooLarge)
		}
	})

	t.Run("the bound is the 16 KiB the routes are documented with", func(t *testing.T) {
		if CredentialRouteMaxBodyBytes != 16*1024 {
			t.Errorf("CredentialRouteMaxBodyBytes = %d, want 16384", CredentialRouteMaxBodyBytes)
		}
		at := bytes.Repeat([]byte("a"), CredentialRouteMaxBodyBytes)
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(at))
		if !LimitCredentialRouteBody(httptest.NewRecorder(), req) {
			t.Error("a body of exactly the bound was refused")
		}
	})

	t.Run("a body that stops arriving is the decoder's 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", &brokenBody{})
		req.ContentLength = -1
		rec := httptest.NewRecorder()
		if LimitCredentialRouteBody(rec, req) {
			t.Fatal("a broken body was let through")
		}
		if got := envelope(t, rec); got != HTTPErrInvalidBody {
			t.Errorf("answer = %+v, want %+v", got, HTTPErrInvalidBody)
		}
	})

	t.Run("the middleware form refuses before the next handler", func(t *testing.T) {
		reached := false
		h := CredentialRouteBodyLimit(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
		over := bytes.Repeat([]byte("a"), CredentialRouteMaxBodyBytes+1)
		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(over))
		req.ContentLength = -1
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if reached || rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("reached = %v, status = %d; want the next handler skipped and 413", reached, rec.Code)
		}
	})
}
