package simple

import (
	"context"
	"net/url"
	"strings"
)

const (
	authPath     = "/auth"
	variablePath = "/auth/variable"
)

// Expiration is the outcome of a key-expiration lookup.
type Expiration struct {
	// Permanent keys never expire ("Never").
	Permanent bool
	// ExpiresAt is the formatted UTC expiry string (for example
	// "2026-08-15 12:00:00 UTC"). Empty for permanent keys.
	ExpiresAt string
}

// VariableValue is the outcome of a variable lookup.
type VariableValue struct {
	// Found is false when the variable is missing, protected, or the key
	// check failed.
	Found bool
	// Value is the variable contents when Found.
	Value string
}

// ResetOutcome is the outcome of an HWID reset request.
type ResetOutcome uint8

const (
	// ResetGranted: the HWID was cleared.
	ResetGranted ResetOutcome = iota
	// ResetDenied: self-service resets are disabled for the system (or the
	// key is not eligible).
	ResetDenied
	// ResetTooSoon: the 30-day cooldown is still running.
	ResetTooSoon
)

func (o ResetOutcome) String() string {
	switch o {
	case ResetGranted:
		return "granted"
	case ResetDenied:
		return "denied"
	case ResetTooSoon:
		return "tooSoon"
	default:
		return "unknown"
	}
}

// Client performs stateless Simple checks. One Client per system; safe for
// concurrent use.
type Client struct {
	config Config
	http   HTTPClient
}

// Option customizes NewClient.
type Option func(*Client)

// WithHTTPClient injects a custom transport (tests, proxies).
func WithHTTPClient(http HTTPClient) Option {
	return func(c *Client) { c.http = http }
}

// NewClient validates the configuration and returns a ready Client.
func NewClient(config Config, options ...Option) (*Client, error) {
	if err := resolveDefaultHWID(&config); err != nil {
		return nil, configurationError("Could not derive the default hardware ID: %v. Supply a custom HWID or use \"1\" to disable device checks.", err)
	}
	if config.SystemID == "" {
		return nil, configurationError("System ID must not be empty.")
	}
	if config.Version == "" {
		return nil, configurationError("Version must not be empty.")
	}
	if !strings.HasPrefix(config.BaseURL, "https://") {
		return nil, configurationError("Base URL must use HTTPS.")
	}
	client := &Client{config: config}
	for _, option := range options {
		option(client)
	}
	if client.http == nil {
		client.http = NewDefaultHTTPClient(config.RequestTimeout, config.UserAgent)
	}
	return client, nil
}

// Config returns the configuration.
func (c *Client) Config() Config { return c.config }

func (c *Client) endpoint(path string) string {
	if strings.HasSuffix(c.config.BaseURL, "/") {
		return c.config.BaseURL[:len(c.config.BaseURL)-1] + path
	}
	return c.config.BaseURL + path
}

// request performs one POST and returns the trimmed body plus headers.
func (c *Client) request(ctx context.Context, path string, fields url.Values) (string, HTTPResponse, error) {
	response := c.http.PostForm(ctx, c.endpoint(path), fields)
	if !response.OK() {
		if response.Err != nil {
			return "", response, transportError("request failed: %s", response.Err.Error())
		}
		return "", response, transportError("server returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(response.Body))
	}
	return strings.TrimSpace(response.Body), response, nil
}

func (c *Client) baseFields() url.Values {
	fields := url.Values{
		"system":  {c.config.SystemID},
		"version": {c.config.Version},
		"hwid":    {c.config.HWID},
		"clean":   {"1"},
	}
	if c.config.ProgramDigest != "" {
		fields.Set("digest", c.config.ProgramDigest)
	}
	return fields
}

// AuthenticateWithKey checks a license key (mikros mode). It returns true
// only when the server answers literally "true".
func (c *Client) AuthenticateWithKey(ctx context.Context, licenseKey string) (bool, error) {
	fields := c.baseFields()
	fields.Set("key", licenseKey)
	return c.authenticate(ctx, fields)
}

// AuthenticateWithPassword checks username + password credentials (goliath
// mode).
func (c *Client) AuthenticateWithPassword(ctx context.Context, username, password string) (bool, error) {
	fields := c.baseFields()
	fields.Set("username", username)
	fields.Set("password", password)
	return c.authenticate(ctx, fields)
}

func (c *Client) authenticate(ctx context.Context, fields url.Values) (bool, error) {
	body, _, err := c.request(ctx, authPath, fields)
	if err != nil {
		return false, err
	}
	if body == "true" {
		return true, nil
	}
	return false, classify(body)
}

// KeyExpirationForKey returns the expiry of a license key.
func (c *Client) KeyExpirationForKey(ctx context.Context, licenseKey string) (Expiration, error) {
	fields := c.baseFields()
	fields.Set("key", licenseKey)
	fields.Set("intent", "expiration")
	return c.expiration(ctx, fields)
}

// KeyExpirationForPassword returns the expiry of the authenticated user's
// key for this system.
func (c *Client) KeyExpirationForPassword(ctx context.Context, username, password string) (Expiration, error) {
	fields := c.baseFields()
	fields.Set("username", username)
	fields.Set("password", password)
	fields.Set("intent", "expiration")
	return c.expiration(ctx, fields)
}

func (c *Client) expiration(ctx context.Context, fields url.Values) (Expiration, error) {
	body, response, err := c.request(ctx, authPath, fields)
	if err != nil {
		return Expiration{}, err
	}
	// A successful intent response carries auth: true; failures carry the
	// reason in auth (and the body).
	if response.Header("auth") != "true" {
		return Expiration{}, classify(body)
	}
	if body == "Never" || body == "N/A" {
		return Expiration{Permanent: true, ExpiresAt: body}, nil
	}
	return Expiration{ExpiresAt: body}, nil
}

// GetVariable fetches a server-side variable. Pass a license key when the
// variable is protected.
func (c *Client) GetVariable(ctx context.Context, name string, licenseKey ...string) (VariableValue, error) {
	fields := url.Values{
		"system":   {c.config.SystemID},
		"variable": {name},
		"clean":    {"1"},
	}
	if len(licenseKey) > 0 && licenseKey[0] != "" {
		fields.Set("key", licenseKey[0])
	}

	body, response, err := c.request(ctx, variablePath, fields)
	if err != nil {
		return VariableValue{}, err
	}
	// The intent header disambiguates: "true" means the body is the value
	// (even when the value is literally "false"); "false" means missing,
	// protected, or unauthorized; anything else is an error reason.
	switch response.Header("intent") {
	case "true":
		return VariableValue{Found: true, Value: body}, nil
	case "false":
		return VariableValue{Found: false}, nil
	default:
		return VariableValue{}, classify(body)
	}
}

// ResetHwidForKey clears the HWID bound to a license key (self-service;
// per-system flag and a 30-day cooldown apply).
func (c *Client) ResetHwidForKey(ctx context.Context, licenseKey string) (ResetOutcome, error) {
	fields := c.baseFields()
	fields.Set("key", licenseKey)
	fields.Set("intent", "hwidreset")
	return c.resetHwid(ctx, fields)
}

// ResetHwidForPassword clears the HWID of the authenticated user's key.
func (c *Client) ResetHwidForPassword(ctx context.Context, username, password string) (ResetOutcome, error) {
	fields := c.baseFields()
	fields.Set("username", username)
	fields.Set("password", password)
	fields.Set("intent", "hwidreset")
	return c.resetHwid(ctx, fields)
}

func (c *Client) resetHwid(ctx context.Context, fields url.Values) (ResetOutcome, error) {
	body, response, err := c.request(ctx, authPath, fields)
	if err != nil {
		return ResetDenied, err
	}
	// Credential failures carry the reason in the auth header (and body).
	if authHeader := response.Header("auth"); authHeader != "" && authHeader != "true" {
		return ResetDenied, classify(body)
	}
	// The intent header carries true/false/toosoon; the clean body carries
	// "1"/""/"toosoon".
	switch response.Header("intent") {
	case "true", "1":
		return ResetGranted, nil
	case "toosoon":
		return ResetTooSoon, nil
	case "false", "":
		if body == "toosoon" {
			return ResetTooSoon, nil
		}
		if body == "true" || body == "1" {
			return ResetGranted, nil
		}
		return ResetDenied, nil
	default:
		return ResetDenied, &Error{Kind: ErrUnknownReason, Reason: response.Header("intent"), Message: "Unexpected hwidreset response."}
	}
}
