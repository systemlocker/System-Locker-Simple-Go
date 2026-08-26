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
`simple.ErrSSO` (with `simple.SSOLink(err)`) for Google-SSO accounts,
`simple.ErrLocalFailure` when an opt-in SL-HWID device identity cannot be
produced (see below), and `simple.ErrUnknownReason` carrying the raw string
if the server emits something new.

## Management API (server-side tooling)

```go
client, _ := simple.NewClient(config)
config.APIKey = "…" // management key — keep it on your server

count, _ := client.Management().RedeemedUserCount(ctx)
keys, _  := client.Management().GenerateKeys(ctx, simple.ExpiryOneMonth, 10, "june-batch")
```

`Management` wraps `POST /api/v1`: key status/expiration, HWID resets
(single/admin or whole-system), key generation, bans, expiry adjustment.

## Google SSO (account authentication)

Accounts created through Google sign-in have no local password on the
server. A `username`/`password` check for such an account fails with an
`sso`, `ssoexp`, or `ssowrong` reason that embeds the portal URL where the
user completes Google sign-in and receives a system-specific password
(valid 180 days) to use as their account password. There is no callback;
the user transcribes the generated password into your login form and you
simply retry.

Deliver the portal link to your user through your own channel (API response,
email, chat).

```go
if _, err := client.AuthenticateWithPassword(ctx, username, password); err != nil {
    if simpleErr, isSso := err.(*simple.Error); isSso && simpleErr.Kind == simple.ErrSSO {
        // sso / ssoexp / ssowrong — the portal URL is embedded in the error.
        portal := simple.SSOLink(err)
        sendToUser(user, portal) // your channel: API response, email, chat…
        return
    }
    return // any other denial
}
```

`simple.GoogleSsoURL(systemID)` (or `client.GoogleSsoURL()`) builds the
same portal URL before any denial, if you already know the account signs in
through Google.

## Device identifiers (HWID)

The default derivation is a plain hardware hash:

```go
import "github.com/systemlocker/system-locker-simple-go/hwid"

config.HWID, _ = hwid.DeviceHWID()
```

The `hwid` package derives a stable identifier from the machine GUID,
hardware UUID, CPU id, and MAC (Windows and Linux). It stays available, but
it is the weaker option: the hash over-fits a handful of hardware values, so
swapping a disk or NIC — or cloning the machine into a VM — changes the HWID
and forces your user through a device reset. A developer-supplied stable
value works just as well. Set `config.HWID = "1"` only to explicitly disable
device locking.

### Fault-tolerant HWID (SL-HWID), opt-in

```go
config := simple.DefaultConfig()
config.HWIDMode = "sl-hwid" // default is "legacy"
```

SL-HWID derives the HWID from a random key locked behind threshold secret
sharing instead of hashing hardware directly. It is fault tolerant and cross
platform (Windows, macOS, Linux), combines **14 hardware factors**, and any
two of them can fail or change without changing the HWID; drifted factors
are quietly re-absorbed after each successful authentication. The module's
own persisted value is hard-locked, so copied state cannot stand in for
changed hardware.

Things to know before enabling it:

- **The HWID changes.** SL-HWID produces a new opaque identifier, so a
  deployment switching from the legacy hash (or a custom value) must reset
  its claimed HWIDs once, at rollout — per key, self-service, or
  system-wide through the management API — or users will hit `hwid`
  mismatches.
- **Storage is shared.** The enrollment lives in one per-machine location
  (the registry on Windows, an application-support directory elsewhere),
  shared by every System Locker client on the device. Configure
  `SLHwidStore` only when you deliberately need separate device state.
- **Re-activation exists.** If hardware drifts past the recovery threshold,
  requests fail with a `LOCAL_FAILURE` error and the user needs a reset.

SL-HWID is the right choice for a **launcher**: a Simple-based launcher that
opens a Bedrock-protected program reports exactly the HWID the Bedrock
client reports, because both share the same per-machine enrollment. The key
the user already activated in the launcher works for the protected program
too — one device, one HWID, no `hwid` mismatch between the two.

SL-HWID changes the device identifier only. It does not change what the
Simple protocol guarantees: responses are still unsigned, so only use this
client on machines you control.

An explicit `HWID` value (including `"1"`) always wins over both modes.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately through the
System Locker support channels, not via public issues.
