package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ClaimsWebhook is a TokenClaimsBuilder that asks an HTTP endpoint for the
// claims: the consumer's security.jwt.claimsWebhook {url, timeoutMs} knob
// (config-schema.md §1.1, §3.1), the escape hatch for claims that are computed
// rather than mapped. It is this port's own extension, like the helpers in
// claims.go: the reference's only hook is the in-process
// config.buildTokenPayload(user) (auth.router.ts:378-384), which never crosses
// HTTP, so the request and response below have no reference wire to cite. The
// envelope is the family's outbound-webhook convention — the four X-Webhook-*
// headers and the "sha256=<hex>" HMAC form of the reference's WebhookSender
// (src/tools/webhook-sender.ts:24-33, :54-56) — so a receiver written for the
// tools router's webhooks verifies these the same way.
//
// Every mint — login, refresh, the 2FA step-up token — and every GET /me POSTs
// one request to URL with Content-Type: application/json, the body
//
//	{"user": <the user as GET /me renders it — PublicUser, credentials omitted>}
//
// and the headers
//
//	X-Webhook-Event:     claims.build
//	X-Webhook-Delivery:  <a fresh UUID per request>
//	X-Webhook-Timestamp: <ISO 8601 UTC with milliseconds>
//	X-Webhook-Signature: sha256=<hex HMAC-SHA256 of the body>   (only when Secret is set)
//
// and expects a 2xx answer whose JSON body is
//
//	{"claims": {<claim name>: <value>, ...}}
//
// The claims object becomes the builder's result and is merged as any hook's
// is: it may override the six base claims and cannot set the reserved claims —
// mintToken writes sid, tid, jti, typ, iss, iat and exp after the merge, and
// deletes amr, auth_time and mfa_at, writing them back from the session alone —
// so an endpoint that is compromised, or merely confused, cannot retype a
// token, rebind its session or claim a second factor nobody presented. Anything else is an error: a non-2xx status,
// a transport failure, the timeout, a body over 64 KiB, a body that is not
// JSON, a missing or null "claims" member or one that is not an object. An
// error fails the mint, and the route answers 500 exactly as it does for any
// failing Config.BuildTokenClaims (token.go). Failing closed is the point: a
// token minted without the claims the deployment configured would authorise
// less, or more, than the deployment decided.
//
// A builder runs on every mint and on GET /me, and only there: the adapters'
// Middleware authenticates through Service.Authenticate, which never calls it.
// One login is therefore one request here, and a protected route is none.
//
// The zero value is usable once URL is set; NewClaimsWebhook additionally
// validates the URL and fills in the default timeout. A ClaimsWebhook is safe
// for concurrent use once its fields stop changing.
type ClaimsWebhook struct {
	// URL is the absolute http(s) address every request goes to.
	URL string
	// Secret keys the signature. Empty sends no X-Webhook-Signature header at
	// all, as the reference's sender does without one (webhook-sender.ts:31-33).
	// It is never sent and never appears in an error.
	Secret string
	// Timeout bounds one request, connect to last byte, through the request
	// context — a shorter deadline already on ctx wins. Zero or negative means
	// 2 seconds: a login is waiting on the answer.
	Timeout time.Duration
	// Client issues the requests. Nil means http.DefaultClient. A Client with a
	// Timeout of its own is bounded by both.
	Client *http.Client
}

// ClaimsWebhookEvent is the X-Webhook-Event value of every request a
// ClaimsWebhook sends.
const ClaimsWebhookEvent = "claims.build"

// defaultClaimsWebhookTimeout bounds a request whose ClaimsWebhook.Timeout is
// unset. Shorter than a delivery's: nothing is being sent anywhere, and the
// caller is a login.
const defaultClaimsWebhookTimeout = 2 * time.Second

// maxClaimsWebhookResponse is the most of a response body Build reads. A
// claims object is a handful of members; a body past this is not one, and an
// endpoint that answers with megabytes must not be able to make every login
// buffer them.
const maxClaimsWebhookResponse = 64 << 10

// The envelope headers, named as the reference names them
// (webhook-sender.ts:24-33), and the timestamp layout — Date.prototype
// .toISOString's output: UTC, three fractional digits, a literal Z.
//
// TODO(rebase onto main): delivery_webhook.go on main (#50) already defines
// these as webhookEventHeader, webhookDeliveryHeader, webhookTimestampHeader,
// webhookSignatureHeader and webhookTimestampLayout, and claimsWebhookSignature
// and claimsWebhookDeliveryID below duplicate its signWebhookBody and
// newUUIDv4. That file is not in this tree, so the copies stay until the
// rebase; then delete all seven here and call delivery_webhook.go's.
const (
	claimsWebhookEventHeader     = "X-Webhook-Event"
	claimsWebhookDeliveryHeader  = "X-Webhook-Delivery"
	claimsWebhookTimestampHeader = "X-Webhook-Timestamp"
	claimsWebhookSignatureHeader = "X-Webhook-Signature"
	claimsWebhookTimestampLayout = "2006-01-02T15:04:05.000Z07:00"
)

// NewClaimsWebhook builds a ClaimsWebhook for an absolute http(s) URL with the
// default 2 second timeout. secret may be empty, in which case requests are
// unsigned.
func NewClaimsWebhook(rawURL, secret string) (*ClaimsWebhook, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("auth: claims webhook url: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("auth: claims webhook url %q: want an absolute http(s) URL", rawURL)
	}
	return &ClaimsWebhook{URL: rawURL, Secret: secret, Timeout: defaultClaimsWebhookTimeout}, nil
}

// claimsWebhookRequest is the body Build posts.
type claimsWebhookRequest struct {
	User PublicUser `json:"user"`
}

// Build posts user to the endpoint and returns the claims it answers with. Its
// signature is TokenClaimsBuilder's, so a *ClaimsWebhook is wired with
// WithTokenClaimsBuilder(hook.Build) or as one link of a ChainClaims.
//
// An error carries the status or the transport failure and nothing from the
// response body, which an endpoint may well fill with an echo of the request.
func (w *ClaimsWebhook) Build(ctx context.Context, user User) (map[string]any, error) {
	if w == nil {
		return nil, errors.New("auth: claims webhook is nil")
	}
	const where = "auth: claims webhook"

	body, err := json.Marshal(claimsWebhookRequest{User: NewPublicUser(user)})
	if err != nil {
		return nil, fmt.Errorf("%s: encode: %w", where, err)
	}
	deliveryID, err := claimsWebhookDeliveryID()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}

	timeout := w.Timeout
	if timeout <= 0 {
		timeout = defaultClaimsWebhookTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(claimsWebhookEventHeader, ClaimsWebhookEvent)
	req.Header.Set(claimsWebhookDeliveryHeader, deliveryID)
	req.Header.Set(claimsWebhookTimestampHeader, time.Now().UTC().Format(claimsWebhookTimestampLayout))
	if w.Secret != "" {
		req.Header.Set(claimsWebhookSignatureHeader, claimsWebhookSignature(w.Secret, body))
	}

	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// A *url.Error names the URL and the cause — context.DeadlineExceeded
		// on the timeout — and never the body.
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: status %d", where, resp.StatusCode)
	}

	// One byte past the limit is read so that "exactly the limit" and "more
	// than the limit" can be told apart.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxClaimsWebhookResponse+1))
	if err != nil {
		return nil, fmt.Errorf("%s: read response: %w", where, err)
	}
	if len(raw) > maxClaimsWebhookResponse {
		return nil, fmt.Errorf("%s: response exceeds %d bytes", where, maxClaimsWebhookResponse)
	}

	// The envelope is decoded as a map rather than a struct so that the member
	// is found by its exact name: encoding/json matches a struct tag
	// case-insensitively, and "Claims" is not the contract. The member is kept
	// raw so that "absent", "null" and "not an object" can each be refused by
	// name rather than collapsing into an empty map.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("%s: decode response: %w", where, err)
	}
	member, ok := envelope["claims"]
	if !ok || bytes.Equal(bytes.TrimSpace(member), []byte("null")) {
		return nil, fmt.Errorf("%s: response has no claims object", where)
	}
	var claims map[string]any
	if err := json.Unmarshal(member, &claims); err != nil {
		return nil, fmt.Errorf("%s: claims is not an object: %w", where, err)
	}
	return claims, nil
}

// claimsWebhookSignature is the reference's WebhookSender.sign
// (webhook-sender.ts:54-56): "sha256=" + hex(HMAC-SHA256(secret, body)). It is
// the form VerifyWebhookSignature checks.
func claimsWebhookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// claimsWebhookDeliveryID is what the reference's randomUUID() gives
// X-Webhook-Delivery: a random (version 4, variant 1) UUID in its canonical
// 8-4-4-4-12 spelling.
func claimsWebhookDeliveryID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("random uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
