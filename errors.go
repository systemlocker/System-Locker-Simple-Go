package simple

import "fmt"

// ErrorKind categorizes a Simple protocol failure.
type ErrorKind uint8

const (
	// ErrConfiguration means the local configuration is invalid.
	ErrConfiguration ErrorKind = iota
	// ErrTransport means the HTTP exchange failed or returned a non-2xx
	// status.
	ErrTransport
	// ErrServer means the server misbehaved: an internal database error
	// (reason "dbe") or — for the Invisible Folder module — a 2xx response
	// this library could not parse.
	ErrServer
	// ErrDenied means the server rejected the request for a known,
	// license-related reason (frozen key, banned HWID, bad credentials…).
	ErrDenied
	// ErrSSO means the account requires Google SSO handling; the portal
	// link is in the error.
	ErrSSO
	// ErrLocalFailure means a local subsystem needed by the request
	// failed — currently only the opt-in SL-HWID module (for example
	// hardware drifted past its recovery threshold, requiring
	// re-activation).
	ErrLocalFailure
	// ErrUnknownReason means the server returned a 2xx failure with a
	// reason this library does not recognize; the raw reason is carried.
	ErrUnknownReason
)

func (k ErrorKind) String() string {
	switch k {
	case ErrConfiguration:
		return "Configuration"
	case ErrTransport:
		return "Transport"
	case ErrServer:
		return "Server"
	case ErrDenied:
		return "Denied"
	case ErrSSO:
		return "SSO"
	case ErrLocalFailure:
		return "LocalFailure"
	case ErrUnknownReason:
		return "UnknownReason"
	default:
		return "UnknownReason"
	}
}

// Error is the error type returned by every client operation. Reason is the
// raw reason string from the server ("" for local failures).
type Error struct {
	Kind    ErrorKind
	Reason  string
	Message string
}

func (e *Error) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("%s: %s", e.Kind, e.Reason)
	}
	return e.Message
}

func configurationError(format string, args ...any) *Error {
	return &Error{Kind: ErrConfiguration, Message: fmt.Sprintf(format, args...)}
}

func transportError(format string, args ...any) *Error {
	return &Error{Kind: ErrTransport, Message: fmt.Sprintf(format, args...)}
}

// knownDeniedReasons maps the documented reason strings to a denial.
var knownDeniedReasons = map[string]bool{
	"no username":    true,
	"no password":    true,
	"no key":         true,
	"no sys":         true,
	"no hwid":        true,
	"false":          true, // missing version
	"not verified":   true,
	"bad u/p":        true,
	"bad key":        true,
	"bad keys":       true,
	"frozen":         true,
	"paused":         true,
	"destitute":      true,
	"user limit":     true,
	"hwid banned":    true,
	"spoofsuspected": true,
	"hwid":           true,
	"expired key":    true,
	"outdated":       true,
	"digest":         true,
	"exp err big":    true,
	"no var":         true,
}

// classify turns a server reason string into a typed error.
func classify(reason string) *Error {
	switch {
	case reason == "dbe":
		return &Error{Kind: ErrServer, Reason: reason, Message: "The server reported an internal error."}
	case reason == "sso" || len(reason) > 4 && reason[:4] == "sso ":
		return ssoError("sso", reason)
	case len(reason) > 6 && reason[:6] == "ssoexp":
		return ssoError("ssoexp", reason)
	case len(reason) > 8 && reason[:8] == "ssowrong":
		return ssoError("ssowrong", reason)
	case knownDeniedReasons[reason]:
		return &Error{Kind: ErrDenied, Reason: reason, Message: "The request was rejected: " + reason + "."}
	default:
		// Unknown reasons (including enforcement-layer failures) still
		// carry their raw string.
		return &Error{Kind: ErrUnknownReason, Reason: reason, Message: "The server returned an unrecognized failure: " + reason}
	}
}

func ssoError(stage, reason string) *Error {
	link := ""
	if idx := len(stage); len(reason) > idx && reason[idx] == ' ' {
		link = reason[idx+1:]
	}
	message := "This account signs in through Google."
	if stage == "sso" {
		message = "This account requires a Google SSO token; visit the link to create one."
	} else if stage == "ssoexp" {
		message = "The Google SSO token expired; visit the link to renew it."
	} else if stage == "ssowrong" {
		message = "The supplied password is not the Google SSO token; visit the link."
	}
	return &Error{Kind: ErrSSO, Reason: reason, Message: message + " Portal: " + link}
}

// SSOLink returns the portal URL from an sso/ssoexp/ssowrong error, or "".
func SSOLink(err error) string {
	if simpleErr, ok := err.(*Error); ok && simpleErr.Kind == ErrSSO {
		if idx := indexByte(simpleErr.Reason, ' '); idx >= 0 {
			return simpleErr.Reason[idx+1:]
		}
	}
	return ""
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
