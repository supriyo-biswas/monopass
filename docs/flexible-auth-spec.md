# Flexible Auth Spec

Monopass clients discover unlock methods before attempting to authorize a
process lineage. This lets the agent advertise multiple authentication methods
without changing the shared client retry flow.

## Unlock Method Discovery

```http
GET /api/v1/auth/unlock/methods

HTTP/1.1 200 OK
Content-Type: application/json
```

macOS response:

```json
{
  "methods": [
    {
      "url": "/api/v1/auth/unlock/gui",
      "accepts_master_password": false
    }
  ]
}
```

Linux response:

```json
{
  "methods": [
    {
      "url": "/api/v1/auth/unlock/direct",
      "accepts_master_password": true
    }
  ]
}
```

`methods` is ordered by agent preference. Clients must use the first method they
support. Method URLs are full API paths rooted at `/api/v1`.

`accepts_master_password` tells a client whether the method accepts the master
password as `Authorization: Bearer <standard-base64 UTF-8 password>`. A client
must not prompt for or send the master password to a method that sets
`accepts_master_password` to `false`.

## GUI Unlock

```http
POST /api/v1/auth/unlock/gui

HTTP/1.1 200 OK
```

The GUI method is currently macOS-only. It prompts for the master password in a
native AppKit password dialog owned by the agent. The dialog identifies the
requesting application from the authorized process chain, selecting the nearest
caller after filtering out processes whose executable identity matches the
running agent binary. `.app` bundle callers are displayed by bundle name and use
the bundle icon when available; plain executables display their file name and
use the default alert icon.

The agent clears the native secure text field after reading the submitted
password and keeps Rust-owned password material in zeroizing buffers. AppKit and
Objective-C internals may still hold temporary copies outside Rust zeroization
control.

The agent prompts once per unlock request. A wrong password, cancelled dialog,
or closed dialog denies the unlock request without showing a retry prompt.
Concurrent GUI unlock requests are shown as separate dialogs.

Failures:
- `403 access_denied`

## Direct Unlock

```http
POST /api/v1/auth/unlock/direct
Authorization: Bearer <standard-base64 UTF-8 password>

HTTP/1.1 200 OK
```

The direct method is currently Linux-only. It is the migrated form of the older
`/auth/unlock` behavior. It validates the bearer master password, opens or
verifies the unlocked database, and authorizes the caller's process-lineage
scope.

Failures:
- `403 access_denied`
- `403 unlock_failed`

## CLI Flow

When an auth-required request returns `403 access_denied`, the CLI:

1. Requests `GET /api/v1/auth/unlock/methods`.
2. Selects the first advertised method.
3. Prompts for the master password only if `accepts_master_password` is `true`.
4. Calls the selected method URL, with a bearer password only when the method
   accepts one.
5. Zeroizes any CLI-owned password buffer and retries the original request once.

Secret-bearing item reads may still need the same bearer password on the retried
original request. That behavior is controlled by the command's auth mode, not by
method discovery.
