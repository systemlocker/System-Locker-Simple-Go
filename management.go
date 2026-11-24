package simple

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Management wraps the Management API v2 (/api/v2). It is independent of
// the authentication protocol and is meant for your server-side tooling.
// Config.APIKey must hold a scoped v2 bearer credential for this system;
// treat it as a secret and keep it on servers you control. Access it
// through Client.Management().
type Management struct{ client *Client }

// KeyExpiry enumerates the key-generation expiry presets. Duration presets
// start counting when the key is redeemed.
type KeyExpiry int

const (
	ExpiryPermanent KeyExpiry = iota
	ExpiryOneDay
	ExpiryOneWeek
	ExpiryOneMonth
	ExpiryThreeMonths
	ExpiryOneYear
)

// presetSeconds maps each KeyExpiry preset (by index) to its duration.
// Index 0 (permanent) is never sent as a duration.
var presetSeconds = [...]int{0, 86400, 604800, 2592000, 7776000, 31536000}

// Management returns the management sub-API. It requires Config.APIKey and
// an HTTP client that implements JSONHTTPClient (DefaultHTTPClient does).
func (c *Client) Management() *Management { return &Management{client: c} }

// JSONHTTPClient is the optional transport operation the management API
// needs. Custom HTTPClient implementations that only support form posts keep
// working for authentication; they must add RequestJSON to use management.
// data is marshalled as the JSON request body when non-nil.
type JSONHTTPClient interface {
	RequestJSON(ctx context.Context, method, url string, data any, headers map[string]string) HTTPResponse
}

// decodeManagementData unmarshals a response's data object into target after
// checking that every named field is present (a missing field and a JSON
// null would otherwise both decode to the zero value).
func decodeManagementData(body json.RawMessage, target any, fields ...string) error {
	var object map[string]json.RawMessage
	if json.Unmarshal(body, &object) != nil || object == nil {
		return transportError("invalid management data")
	}
	for _, name := range fields {
		if _, ok := object[name]; !ok {
			return transportError("missing management field: %s", name)
		}
	}
	if json.Unmarshal(body, target) != nil {
		return transportError("invalid management data")
	}
	return nil
}

// Request calls any v2 resource path (relative to /api/v2, for example
// "/permissions" or "/systems/{id}/nightflyer") and returns the response's
// JSON data member. data, when non-nil, is sent as the JSON body; POST, PUT
// and PATCH without data send an empty object. A non-2xx response returns an
// *Error whose Reason is the server's machine-readable error code (for
// example "INSUFFICIENT_SCOPE"). Mutations are never retried.
func (m *Management) Request(ctx context.Context, method, path string, data any) (json.RawMessage, error) {
	credential := m.client.config.APIKey
	if credential == "" || strings.ContainsAny(credential, "\r\n") {
		return nil, configurationError("a management bearer credential is required")
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "#") {
		return nil, configurationError("invalid management resource path")
	}
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return nil, configurationError("invalid management method")
	}
	transport, ok := m.client.http.(JSONHTTPClient)
	if !ok {
		return nil, configurationError("HTTP client must implement JSONHTTPClient for management")
	}
	// The server requires a JSON Content-Type on every mutation, even one
	// without fields.
	if data == nil && (method == "POST" || method == "PUT" || method == "PATCH") {
		data = map[string]any{}
	}
	response := transport.RequestJSON(ctx, method, m.client.endpoint("/api/v2"+path), data,
		map[string]string{"Authorization": "Bearer " + credential, "Accept": "application/json"})
	if response.Err != nil {
		return nil, transportError("management request failed: %v", response.Err)
	}
	var envelope struct {
		Data  json.RawMessage `json:"data"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(response.Body), &envelope); err != nil {
		return nil, transportError("management returned invalid JSON (HTTP %d)", response.StatusCode)
	}
	if !response.OK() {
		message := envelope.Error.Message
		if message == "" {
			message = fmt.Sprintf("management HTTP %d", response.StatusCode)
		}
		return nil, &Error{Kind: ErrTransport, Reason: envelope.Error.Code, Message: message}
	}
	if len(envelope.Data) == 0 {
		return nil, &Error{Kind: ErrUnknownReason, Message: "management response is missing data"}
	}
	return envelope.Data, nil
}

func (m *Management) systemPath() string {
	return "/systems/" + url.PathEscape(m.client.config.SystemID)
}

func (m *Management) keyPath(license string) string {
	return m.systemPath() + "/keys/" + url.PathEscape(license)
}

// Permissions returns the scopes granted to the configured credential. This
// endpoint requires no scope.
func (m *Management) Permissions(ctx context.Context) ([]string, error) {
	body, err := m.Request(ctx, "GET", "/permissions", nil)
	if err != nil {
		return nil, err
	}
	var data struct {
		Scopes []string `json:"scopes"`
	}
	if err := decodeManagementData(body, &data, "scopes"); err != nil || data.Scopes == nil {
		return nil, transportError("invalid permissions data")
	}
	return data.Scopes, nil
}

// RedeemedUserCount returns the system's user count (accounts plus key-only
// redemptions). The server refreshes this figure periodically, so it can lag
// behind recent redemptions. Requires systems.read.
func (m *Management) RedeemedUserCount(ctx context.Context) (int, error) {
	body, err := m.Request(ctx, "GET", m.systemPath()+"/statistics", nil)
	if err != nil {
		return 0, err
	}
	var data struct {
		TotalUsers *int `json:"total_users"`
	}
	if err := decodeManagementData(body, &data, "total_users"); err != nil || data.TotalUsers == nil || *data.TotalUsers < 0 {
		return 0, transportError("invalid statistics data")
	}
	return *data.TotalUsers, nil
}

// KeyStatus returns how a license key is claimed: "user" (attached to an
// account), "mikros" (redeemed without an account) or "unclaimed".
// Requires keys.read.
func (m *Management) KeyStatus(ctx context.Context, license string) (string, error) {
	body, err := m.Request(ctx, "GET", m.keyPath(license), nil)
	if err != nil {
		return "", err
	}
	var data struct {
		ClaimType *string `json:"claim_type"`
	}
	if err := decodeManagementData(body, &data, "claim_type"); err != nil || data.ClaimType == nil {
		return "", transportError("invalid key data")
	}
	return *data.ClaimType, nil
}

// KeyExpiration returns a license key's expiry. ExpiresAt is an RFC 3339 UTC
// timestamp, or empty when the key has no fixed expiry. Permanent is only
// reported for redeemed keys: an unredeemed duration key has no timestamp
// yet either. Requires keys.read.
func (m *Management) KeyExpiration(ctx context.Context, license string) (Expiration, error) {
	body, err := m.Request(ctx, "GET", m.keyPath(license), nil)
	if err != nil {
		return Expiration{}, err
	}
	var data struct {
		ExpiresAt  *string `json:"expires_at"`
		RedeemedAt *string `json:"redeemed_at"`
	}
	if err := decodeManagementData(body, &data, "expires_at", "redeemed_at"); err != nil {
		return Expiration{}, transportError("invalid key data")
	}
	result := Expiration{Permanent: data.ExpiresAt == nil && data.RedeemedAt != nil}
	if data.ExpiresAt != nil {
		result.ExpiresAt = *data.ExpiresAt
	}
	return result, nil
}

// raw returns a mutation's JSON data as a string.
func (m *Management) raw(ctx context.Context, method, path string, data any) (string, error) {
	body, err := m.Request(ctx, method, path, data)
	return string(body), err
}

// ResetHwid performs an administrative HWID reset of one key (no cooldown)
// and returns the key's details as JSON. Self-service resets use
// Client.ResetHwidForKey. Requires keys.update.
func (m *Management) ResetHwid(ctx context.Context, license string) (string, error) {
	return m.raw(ctx, "POST", m.keyPath(license)+"/hwid-reset", nil)
}

// ResetAllHwids resets the HWID of every key in the system and returns
// {"updated": count} as JSON. Use with care. Requires keys.update.
func (m *Management) ResetAllHwids(ctx context.Context) (string, error) {
	return m.raw(ctx, "POST", m.systemPath()+"/keys/hwid-reset", nil)
}

// GenerateKeys generates count (1–100) license keys with the given expiry
// preset, optionally annotated with a note (≤250 characters), and returns
// them one per line. Duration presets start at redemption. Requires
// keys.create.
func (m *Management) GenerateKeys(ctx context.Context, expiry KeyExpiry, count int, note string) (string, error) {
	if count < 1 || count > 100 {
		return "", configurationError("count must be in [1, 100]")
	}
	if len([]rune(note)) > 250 {
		return "", configurationError("note must be at most 250 characters")
	}
	if expiry < 0 || int(expiry) >= len(presetSeconds) {
		return "", configurationError("invalid expiry preset")
	}
	policy := map[string]any{"type": "perpetual"}
	if expiry != ExpiryPermanent {
		policy = map[string]any{"type": "after_redemption", "seconds": presetSeconds[expiry]}
	}
	body, err := m.Request(ctx, "POST", m.systemPath()+"/keys", map[string]any{"count": count, "notes": note, "expiry": policy})
	if err != nil {
		return "", err
	}
	var data struct {
		Keys []string `json:"keys"`
	}
	if err := decodeManagementData(body, &data, "keys"); err != nil || data.Keys == nil {
		return "", transportError("invalid generated keys data")
	}
	return strings.Join(data.Keys, "\n"), nil
}

// BanKey permanently deletes a key and returns {"deleted": true} as JSON.
// Requires keys.delete.
func (m *Management) BanKey(ctx context.Context, license string) (string, error) {
	return m.raw(ctx, "DELETE", m.keyPath(license), nil)
}

// AddTime extends a key's expiry by a positive number of seconds and returns
// the key's details as JSON. It replaces the retired absolute-expiry
// adjustment, which has no v2 equivalent. Requires keys.update.
func (m *Management) AddTime(ctx context.Context, license string, seconds int64) (string, error) {
	if seconds <= 0 {
		return "", configurationError("seconds must be a positive integer")
	}
	return m.raw(ctx, "POST", m.keyPath(license)+"/time", map[string]any{"seconds": seconds})
}
