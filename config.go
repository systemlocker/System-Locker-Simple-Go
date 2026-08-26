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
	// (the default) derives a hardware ID according to HWIDMode. Supply a
	// custom value, or use "1" to explicitly disable device locking. An
	// explicit value always wins over both modes.
	HWID string

	// HWIDMode selects how the device identifier is derived when HWID is
	// empty. The default is "legacy": the plain hardware-factor hash from
	// the hwid package. Set "sl-hwid" to opt into the fault-tolerant
	// SL-HWID module (see the slhwid package) — the recommended choice for
	// launchers that gate access to a Bedrock-protected program, because
	// it reports the same device identity the Bedrock client reports.
	HWIDMode string

	// SLHwidStore optionally redirects the SL-HWID module's storage to a
	// directory (files on every platform). Empty uses the platform default
	// (the registry on Windows, an application-support directory
	// elsewhere) — the same location the Bedrock clients use, so a Simple
	// launcher and a Bedrock application share one device identity.
	SLHwidStore string

	// SLHwidExtraMandatory names additional hard-locked SL-HWID slots
	// beyond the module's own persisted value (for example
	// "machine_guid").
	SLHwidExtraMandatory []string

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
		HWIDMode:       "legacy",
		RequestTimeout: 15 * time.Second,
		BaseURL:        "https://systemlocker.net",
		UserAgent:      "systemlocker-simple-go/0.2",
	}
}

func resolveDefaultHWID(config *Config) error {
	if config.HWID != "" {
		return nil
	}
	// SL-HWID defers derivation to authentication time: the module enrolls
	// or recovers lazily (and refreshes only after a successful check), so
	// an eager call here would persist state for a client that never
	// authenticates.
	if config.HWIDMode == "sl-hwid" {
		return nil
	}
	value, err := hwid.DeviceHWID()
	if err != nil {
		return err
	}
	config.HWID = value
	return nil
}

func (c Config) clone() Config {
	cloned := c
	cloned.SLHwidExtraMandatory = append([]string(nil), c.SLHwidExtraMandatory...)
	return cloned
}
