# System Locker Simple — Go

Official Go client for the **System Locker Simple** protocol (`POST /auth`):
one request, one answer. No sessions, no heartbeats, no signatures — the
right fit when the machine running the check is one you control (Threat
Model 2). For software distributed to untrusted machines, use a **Bedrock**
client instead: it verifies an Ed25519 signature on every response.

## Install

```sh
go get github.com/systemlocker/system-locker-simple-go
```

No third-party dependencies — standard library only.

## Quickstart

```go
package main

import (
    "context"
    "fmt"

    "github.com/systemlocker/system-locker-simple-go"
)

func main() {
    config := simple.DefaultConfig()
    config.SystemID = "abcdefghijklmnopqrst" // from the dashboard
    config.Version = "1.0.0"
    // config.HWID stays "1" unless you want device locking.

    client, _ := simple.NewClient(config)

    ok, err := client.AuthenticateWithKey(context.Background(), "SL-XXXX-XXXX-XXXX")
    if err != nil {
        fmt.Println("check failed:", err) // transport / server error
        return
    }
    if !ok {
        return // rejected — block the action
    }
    // …run the gated action…
}
```

## Operations

| Operation                          | Method                                                                    |
| ---------------------------------- | ------------------------------------------------------------------------- |
| Check a license key                | `AuthenticateWithKey(ctx, key)`                                           |
| Check username + password          | `AuthenticateWithPassword(ctx, user, pass)`                               |
| Key expiry (`Never` or a UTC date) | `KeyExpirationForKey` / `KeyExpirationForPassword`                        |
| Server-side variable               | `GetVariable(ctx, name, key…)`                                            |
| Self-service HWID reset            | `ResetHwidForKey` / `ResetHwidForPassword` → `granted`/`denied`/`tooSoon` |

Errors are typed: `simple.ErrTransport` and `simple.ErrConfiguration` for
infrastructure problems, `simple.ErrDenied` with the server's raw reason
(`frozen`, `hwid banned`, `expired key`, …) for license denials,
`simple.ErrSSO` (with `simple.SSOLink(err)`) for Google-SSO accounts, and
`simple.ErrUnknownReason` carrying the raw string if the server emits
something new.

## Management API (server-side tooling)

```go
client, _ := simple.NewClient(config)
config.APIKey = "…" // management key — keep it on your server

count, _ := client.Management().RedeemedUserCount(ctx)
keys, _  := client.Management().GenerateKeys(ctx, simple.ExpiryOneMonth, 10, "june-batch")
```

`Management` wraps `POST /api/v1`: key status/expiration, HWID resets
(single/admin or whole-system), key generation, bans, expiry adjustment.

## Device identifiers (HWID)

The library derives a hardware ID by default. To provide your own stable ID:

```go
import "github.com/systemlocker/system-locker-simple-go/hwid"

config.HWID, _ = hwid.DeviceHWID()
```

The `hwid` package derives a stable identifier from the machine GUID,
hardware UUID, CPU id, and MAC (Windows and Linux). A developer-supplied
stable value works just as well. Set `config.HWID = "1"` only to explicitly
disable device locking.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately through the
System Locker support channels, not via public issues.
