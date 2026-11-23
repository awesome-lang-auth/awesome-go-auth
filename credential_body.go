package auth

import (
	"bytes"
	"io"
	"net/http"
)

// This file bounds the request body of the public routes that send or spend a
// one-time credential: POST <prefix>/forgot-password, /reset-password,
// /magic-link/send, /magic-link/verify, /sms/send, /sms/verify,
// /change-email/confirm, /invitations/accept, /link-request and /link-verify.
//
// Each takes a stranger's body with no session in front of it, and each needs a
// few short fields — an address, a token, a password, a code, a language. The
// reference parses nothing itself: its host's express.json() does, under that
// parser's 100 kB default, and refuses a larger body with a 413 that reaches the
// host application's error handler rather than the router. This port has no
// host layer to leave it to, so the four adapters put the bound in front of
// these routes themselves, outermost — before the rate limiter, which in some
// deployments decodes the body to find the address it limits, and so before any
// account is looked up: the answer to an over-large body cannot depend on who
// it names. It is registered as the deviation credential-route-bodies-are-bounded.
//
// The bound limits what the server reads, not what a sender relays. A body
// within it can still carry an emailLang of several kilobytes, which a delivery
// webhook forwards JSON-encoded — '<', '>' and '&' escaped to six bytes each —
// to a receiver that may refuse it for its size. Config.EmailLangs is the
// control for that: set, only a configured language reaches a sender.
//
// It covers these ten routes and no others: the public routes that hand their
// body to a sender or spend a credential a mail or a text delivered. The rest
// of the public surface — POST <prefix>/register, /login, /refresh, /logout,
// the /2fa routes, the IdP's token endpoint and the admin console's /login —
// reads a stranger's body too but does neither, and is not bounded here; nor
// are the mail routes behind a session or the admin guard
// (/send-verification-email, /change-email/request, the admin invitation),
// whose caller is authenticated and whose language EmailLangs bounds. A
// deployment that wants every body bounded puts a limit in front of the mount:
// net/http's http.MaxBytesHandler, or CredentialRouteBodyLimit itself.

// CredentialRouteMaxBodyBytes is the largest body the public credential routes
// accept: 16 KiB, well over anything those routes read — the longest is a
// password, which bcrypt caps at 72 bytes — and under what a parser further on
// is asked to take. It bounds the request, not the delivery a sender builds
// from it; see the file comment.
const CredentialRouteMaxBodyBytes = 16 << 10

// CodeBodyTooLarge is the code of the answer to a body over the bound. It has
// no reference counterpart: the reference's 413 is express.json()'s, written by
// the host's error handler.
const CodeBodyTooLarge = "BODY_TOO_LARGE"

// HTTPErrBodyTooLarge is the answer to a body over CredentialRouteMaxBodyBytes.
var HTTPErrBodyTooLarge = HTTPError{Status: http.StatusRequestEntityTooLarge, Message: "Request body too large", Code: CodeBodyTooLarge}

// LimitCredentialRouteBody bounds r's body at CredentialRouteMaxBodyBytes and
// reports whether the request may go on. When it may not, the answer is
// written: 413 BODY_TOO_LARGE for a body over the bound, or the decoder's own
// 400 INVALID_BODY for one that stopped arriving part-way.
//
// A declared Content-Length over the bound is refused before a byte is read.
// Any other body is read up to one byte past the bound — so a body that
// declares no length, or understates it, is refused there too — and, when it
// fits, put back as a buffer, so that whatever runs next (a rate limiter that
// decodes it, the handler's DecodeOptionalJSON) reads it exactly as it was
// sent. An absent body is left alone: the routes accept one.
//
// It is the gin and echo adapters' form; CredentialRouteBodyLimit is the
// net/http middleware over the same check.
func LimitCredentialRouteBody(w http.ResponseWriter, r *http.Request) bool {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return true
	}
	if r.ContentLength > CredentialRouteMaxBodyBytes {
		WriteHTTPError(w, HTTPErrBodyTooLarge)
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, CredentialRouteMaxBodyBytes+1))
	if err != nil {
		WriteHTTPError(w, HTTPErrInvalidBody)
		return false
	}
	if len(body) > CredentialRouteMaxBodyBytes {
		WriteHTTPError(w, HTTPErrBodyTooLarge)
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return true
}

// CredentialRouteBodyLimit is LimitCredentialRouteBody as net/http middleware.
// The adapters wrap each public credential route in it outermost, ahead of
// HTTPConfig.RateLimiter and the CSRF check; a host mounting one of those
// handlers itself — (*nethttp.Adapter).ForgotPassword, say — wraps it the same
// way to keep the bound.
func CredentialRouteBodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !LimitCredentialRouteBody(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}
