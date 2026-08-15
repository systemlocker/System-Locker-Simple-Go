package simple

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

// Management wraps the /api/v1 management endpoint. It is independent of the
// authentication protocol and is meant for your server-side tooling; treat
// the API key as a secret. Access it through Client.Management().
type Management struct {
	client *Client
}

// KeyExpiry enumerates the expiry presets the server understands for key
// generation and expiry adjustment.
type KeyExpiry int

const (
	ExpiryPermanent KeyExpiry = iota
	ExpiryOneDay
	ExpiryOneWeek
	ExpiryOneMonth
	ExpiryThreeMonths
	ExpiryOneYear
)

func (e KeyExpiry) wire() string { return strconv.Itoa(int(e)) }

// Management returns the management sub-API. It requires Config.APIKey.
func (c *Client) Management() *Management { return &Management{client: c} }

func (m *Management) post(ctx context.Context, fields url.Values) (string, error) {
	if m.client.config.APIKey == "" {
		return "", configurationError("management API key not configured")
	}
	fields.Set("key", m.client.config.APIKey)
	body, _, err := m.client.request(ctx, "/api/v1", fields)
	return body, err
}

// RedeemedUserCount returns the number of redeemed keys for the system.
func (m *Management) RedeemedUserCount(ctx context.Context) (int, error) {
	body, err := m.post(ctx, url.Values{"select": {"users"}})
	if err != nil {
		return 0, err
	}
	count, parseErr := strconv.Atoi(body)
	if parseErr != nil {
		return 0, &Error{Kind: ErrUnknownReason, Reason: body, Message: "non-numeric users response: " + body}
	}
	return count, nil
}

// KeyStatus returns the redemption status of a license key as a
// human-readable string forwarded from the server.
func (m *Management) KeyStatus(ctx context.Context, license string) (string, error) {
	return m.post(ctx, url.Values{"select": {"key"}, "lkey": {license}})
}

// KeyExpiration returns the expiration date of a license key.
func (m *Management) KeyExpiration(ctx context.Context, license string) (Expiration, error) {
	body, err := m.post(ctx, url.Values{"select": {"expiration"}, "lkey": {license}})
	if err != nil {
		return Expiration{}, err
	}
	lower := strings.ToLower(body)
	return Expiration{Permanent: lower == "permanent" || lower == "never" || body == "0", ExpiresAt: body}, nil
}

// ResetHwid resets the HWID of one key. asAdmin bypasses the 30-day
// cooldown.
func (m *Management) ResetHwid(ctx context.Context, license string, asAdmin bool) (string, error) {
	fields := url.Values{"command": {"hwidreset"}, "license": {license}}
	if !asAdmin {
		fields.Set("as_admin", "false")
	}
	return m.post(ctx, fields)
}

// ResetAllHwids resets the HWID of every key in the system. Use with care.
func (m *Management) ResetAllHwids(ctx context.Context) (string, error) {
	return m.post(ctx, url.Values{"command": {"systemhwidreset"}})
}

// GenerateKeys generates count (1–100) license keys with the given expiry
// preset, optionally annotated with a note (≤250 characters). The response
// is the raw server body (typically the keys, one per line).
func (m *Management) GenerateKeys(ctx context.Context, expiry KeyExpiry, count int, note string) (string, error) {
	if count < 1 || count > 100 {
		return "", configurationError("count must be in [1, 100]")
	}
	if len(note) > 250 {
		return "", configurationError("note must be at most 250 characters")
	}
	fields := url.Values{
		"command": {"genkeys"},
		"expire":  {expiry.wire()},
		"count":   {strconv.Itoa(count)},
	}
	if note != "" {
		fields.Set("note", note)
	}
	return m.post(ctx, fields)
}

// BanKey permanently deletes a key.
func (m *Management) BanKey(ctx context.Context, license string) (string, error) {
	return m.post(ctx, url.Values{"command": {"bankey"}, "license": {license}})
}

// AdjustExpiry sets a key's expiry. newExpiry is a date the server
// understands (e.g. "2026-12-31"), or "0" for permanent. tz is an IANA
// timezone such as "America/Chicago".
func (m *Management) AdjustExpiry(ctx context.Context, license, newExpiry, tz string) (string, error) {
	return m.post(ctx, url.Values{
		"command":   {"adjustexpiry"},
		"license":   {license},
		"newexpiry": {newExpiry},
		"tz":        {tz},
	})
}
