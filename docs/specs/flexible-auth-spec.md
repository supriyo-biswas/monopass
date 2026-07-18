# Flexible Auth Spec

Monopass clients discover unlock methods before attempting to authorize a
process lineage for either `items` or `settings`. The scopes are independent;
omitting `scope` defaults to `items` for backward compatibility.

## Unlock Method Discovery

```http
GET /api/v1/auth/unlock/methods?scope={items|settings}
X-Client-Capabilities: x-session=<display>

HTTP/1.1 200 OK
Content-Type: application/json
```

`X-Client-Capabilities` is optional. CLI clients running with `DISPLAY` set send
`x-session=<DISPLAY>`. If `DISPLAY` is unset and `WAYLAND_DISPLAY` is set, they
send `wayland-session=<WAYLAND_DISPLAY>`. Linux GUI-capable agents advertise
GUI unlock for either accepted GUI session capability.

When the discovery request explicitly includes `scope`, advertised method URLs
carry the same query. For example, settings discovery returns
`/api/v1/auth/unlock/gui?scope=settings`. Unqualified discovery preserves the
existing unqualified method URLs. Unknown scopes return `400 bad_request`.

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

Linux direct response:

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

Linux GUI-capable response with `x-session` or `wayland-session` capability:

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

`methods` is ordered by agent preference. Clients must use the first method they
support. Method URLs are full API paths rooted at `/api/v1`.

`accepts_master_password` tells a client whether the method accepts the master
password as `Authorization: Bearer <standard-base64 UTF-8 password>`. A client
must not prompt for or send the master password to a method that sets
`accepts_master_password` to `false`.

## GUI Unlock

```http
POST /api/v1/auth/unlock/gui?scope={items|settings}
X-Client-Capabilities: x-session=<display>

HTTP/1.1 200 OK
```

The GUI method is available on macOS and on Linux GUI-capable builds. It prompts
for the master password in a dialog owned by the agent. The dialog identifies
the requesting application from the authorized process chain, selecting the
nearest caller after filtering out processes whose executable identity matches
the running agent binary. The dialog shows the application name, executable path,
and an icon when the platform backend can resolve one. Item prompts retain the
requesting application icon. Settings prompts use a platform settings icon.
Window titles and prompt copy identify the requested scope.

Linux GUI unlock requires the same accepted GUI session capability on the GUI
unlock request that was used for method discovery. Linux GTK and Qt variants
force X11 backend usage.

The agent clears native password fields when supported by the backend and keeps
Rust-owned password material in zeroizing buffers. Native UI toolkit internals
may still hold temporary copies outside Rust zeroization control.

The agent prompts once per unlock request. A wrong password, cancelled dialog,
or closed dialog denies the unlock request without showing a retry prompt.
Concurrent GUI unlock requests are shown as separate dialogs.

Clicking the explicit **Deny** button returns `403 temporary_lockout` and caches
that result for the process-lineage and access-scope pair for
`user.denialTtlSeconds`. Later GUI unlock requests for that pair fail with the
same error without opening a dialog until the cache entry expires. Escape,
window close, backend failure, and
wrong-password submission do not populate the denial cache.

Failures:
- `403 access_denied`
- `403 temporary_lockout`

## Direct Unlock

```http
POST /api/v1/auth/unlock/direct?scope={items|settings}
Authorization: Bearer <standard-base64 UTF-8 password>

HTTP/1.1 200 OK
```

The direct method is the Linux fallback and the direct-only Linux agent behavior.
It is the migrated form of the older `/auth/unlock` behavior. It validates the
bearer master password, opens or verifies the unlocked database, and authorizes
the caller's process lineage for only the requested access scope.

Failures:
- `403 access_denied`
- `403 unlock_failed`

## CLI Flow

When an auth-required request returns `403 access_denied`, the CLI:

1. Requests `GET /api/v1/auth/unlock/methods`, including `X-Client-Capabilities`
   when running in an X11 or Wayland session.
2. Selects the first advertised method.
3. Prompts for the master password only if `accepts_master_password` is `true`.
4. Calls the selected method URL, with a bearer password only when the method
   accepts one.
5. Zeroizes any CLI-owned password buffer and retries the original request once.

Secret-bearing item reads may still need the same bearer password on the retried
original request. That behavior is controlled by the command's auth mode, not by
method discovery.

API clients accessing settings use the same retry sequence with
`scope=settings`, then retry the settings request without a bearer password.
The built-in `ls-settings`, `read-setting`, and `write-setting` commands use
settings API paths and therefore follow this settings-scoped flow. Other
built-in command flows remain item-scoped.
