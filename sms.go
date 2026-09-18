package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// SMSTransport delivers a text message to a handset. It is the SMS counterpart
// of MailerTransport: SMSTransportSender turns one into the SMSCodeSender that
// Config.SendSMSCode wants.
type SMSTransport interface {
	Send(ctx context.Context, phone, message string) error
}

// HTTPSMSTransport talks to the gateway contract the rest of this family talks
// to: a GET against the endpoint carrying username, password, phone and message
// as query parameters, with the API key in an X-API-Key header
// (awesome-node-auth src/services/sms.service.ts:16-46, documented in
// config-schema.md §1.6).
//
// The credentials travel in the URL. That is a real hazard — query strings reach
// access logs, proxies and Referer headers — and the spec calls it out as one
// (config-schema.md §1.6, "credentials-in-URL hazard the product must fix"). It
// is reproduced here anyway, because the endpoint on the other side is the
// deployment's existing gateway and it is the request that gateway is built to
// accept; a "fixed" request would simply fail to send. The fix belongs at the
// gateway, and until it happens the way out is the seam itself: Config.SendSMSCode
// takes any SMSCodeSender, so a deployment whose provider accepts a safer shape
// supplies its own transport and never constructs this one.
type HTTPSMSTransport struct {
	EndpointURL string
	APIKey      string
	Username    string
	Password    string
	client      *http.Client
}

// NewHTTPSMSTransport creates a transport for a query-parameter SMS gateway.
func NewHTTPSMSTransport(endpointURL, apiKey, username, password string) *HTTPSMSTransport {
	return &HTTPSMSTransport{
		EndpointURL: endpointURL,
		APIKey:      apiKey,
		Username:    username,
		Password:    password,
		client:      &http.Client{Timeout: 10 * time.Second},
	}
}

func (t *HTTPSMSTransport) Send(ctx context.Context, phone, message string) error {
	endpoint, err := url.Parse(t.EndpointURL)
	if err != nil {
		return fmt.Errorf("auth: sms endpoint: %w", err)
	}
	// Parsing the endpoint's own query first keeps any parameters it already
	// carries — a provider that routes on ?account=… in the configured URL keeps
	// working. The reference preserves them the same way.
	params := endpoint.Query()
	params.Set("username", t.Username)
	params.Set("password", t.Password)
	params.Set("phone", phone)
	params.Set("message", message)
	endpoint.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	// Set unconditionally, empty value included: the reference always sends the
	// header, and a gateway that keys on its presence must not see the request
	// change shape because a deployment left the key blank.
	req.Header.Set("X-API-Key", t.APIKey)

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth: sms http send: %w", err)
	}
	resp.Body.Close()
	// 2xx only, as the reference has it (sms.service.ts:36-39), the same bound
	// NewGatewayMailerTransport applies (mailer.service.ts:280-284).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("auth: sms http status %d", resp.StatusCode)
	}
	return nil
}
