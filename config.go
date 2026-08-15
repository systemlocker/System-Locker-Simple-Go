// Package simple is the official System Locker client for the stateless
// "Simple" authentication protocol (POST /auth): one request, one answer,
// no sessions, no heartbeats. It is the right fit for software running on
// machines you control. For software distributed to
// untrusted machines, use a Bedrock client instead.
package simple

import (
	"time"

	"github.com/systemlocker/system-locker-simple-go/hwid"
)

// Config configures a Simple Client.
type Config struct {
	// SystemID is the system identifier from the developer dashboard.
	// Required.
	SystemID string

	// Version is the client version reported to the server.
	Version string

	// HWID is the device identifier reported to the server. An empty value
	// (the default) derives a stable hardware ID. Supply a custom value, or
	// use "1" to explicitly disable device locking.
	HWID string

	// RequestTimeout bounds each HTTP request. Default 15s.
	RequestTimeout time.Duration

	// BaseURL is the System Locker API root. Default
	// https://systemlocker.net. HTTPS is enforced.
	BaseURL string

	// UserAgent identifies the client to the server.
	UserAgent string

	// ProgramDigest, when set, is checked against the system's expected
	// program digest.
	ProgramDigest string

	// APIKey is the management API key. Only needed for the Management
	// sub-API.
	APIKey string
}

// DefaultConfig returns a Config with every default filled in. Set SystemID
// and Version on the result before constructing a Client.
func DefaultConfig() Config {
	return Config{
		HWID:           "",
		RequestTimeout: 15 * time.Second,
		BaseURL:        "https://systemlocker.net",
		UserAgent:      "systemlocker-simple-go/0.1",
	}
}

func resolveDefaultHWID(config *Config) error {
	if config.HWID != "" {
		return nil
	}
	value, err := hwid.DeviceHWID()
	if err != nil {
		return err
	}
	config.HWID = value
	return nil
}
