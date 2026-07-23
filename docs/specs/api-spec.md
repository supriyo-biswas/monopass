# Agent API Spec

Base path: `/api/v1`

All database-backed routes require the agent database to be unlocked and the
caller process lineage to be authorized for the route's access scope. Settings
routes require `settings`; all other database routes require `items`.
Unauthorized or locked access returns `403 access_denied`.

Timestamps are stored as Unix seconds and returned as RFC3339 UTC strings.

## Auth

The agent derives an authorization scope from the Unix peer credentials and the
peer's process lineage. A scope contains the caller UID, the PID and start time
of the oldest accessible same-user process, and the ordered identity of every
process from that anchor through the direct client. The direct `monopass`
process is included. POSIX session IDs do not limit traversal or contribute to
the scope, so matching lineages remain stable when a terminal creates a new
session.

Each lineage element uses executable file identity (device, inode, available
generation, size, modification time, and change time) when available. If the
executable cannot be inspected, the element falls back to PID plus process
start time. A different scope, changed executable, changed ordered lineage, or
PID/start-time fallback from a new process requires reauthorization. Traversal
normally stops before a different-user ancestor and otherwise fails closed when
required same-user process identity cannot be resolved. On macOS, traversal may
skip exactly one root-owned local `/usr/bin/login` process and resume from its
same-user terminal host when the process name, effective, real, and saved UIDs,
process group, controlling terminal and session, parent relationship, and stable
process observations all corroborate the boundary. The `login` process itself
is excluded from the scope. If any evidence is missing or inconsistent,
traversal stops at the boundary and preserves the narrower per-shell scope.

Authorization is recorded independently for the `items` and `settings` access
scopes. Auth endpoints that accept `scope` default to `items` when it is omitted.
Unknown scope values return `400 bad_request`.

### Unlock

Unlock uses the method discovery flow described in
[`flexible-auth-spec.md`](flexible-auth-spec.md). The agent advertises the
preferred unlock method for the current platform, build variant, and client
capabilities.

```http
GET /api/v1/auth/unlock/methods?scope={items|settings}
X-Client-Capabilities: x-session=<display>

HTTP/1.1 200 OK
Content-Type: application/json
```

When `scope` was explicit, each advertised method URL carries the same query,
for example `/api/v1/auth/unlock/gui?scope=settings`. An omitted scope preserves
the existing unqualified method URLs.

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

On macOS and Linux GUI-capable builds, the GUI method is:

```http
POST /api/v1/auth/unlock/gui?scope={items|settings}
X-Client-Capabilities: x-session=<display>

HTTP/1.1 200 OK
```

The agent displays a scope-specific password dialog for the requesting
application and accepts one submitted password for the request. The nearest
confidently recognized GUI application in the parent ancestry is used as
presentation context. Same-user terminal hosts such as Visual Studio Code and
GNOME Terminal are part of the verified lineage even when a child terminal
creates a new process session. On macOS, the verified `/usr/bin/login` bridge
described above lets Terminal and iTerm2 participate in both authorization and
presentation. Other different-user boundaries remain excluded. For example, a
shell request can be shown as `bash (via Terminal)`. A direct GUI caller uses
its localized application name without redundant `via` text. The executable
path always describes the direct executable selected for display, not its GUI
host. All prompt scopes use the same application icon resolution: they prefer
the GUI application's icon, then use the existing generic icon fallback if GUI
application or icon discovery is missing or ambiguous. Linux resolves exact
unique desktop-entry executables and systemd desktop IDs from both randomized
application scopes and stable application slices. Its cached XDG desktop-entry
catalog is refreshed and the ancestry retried once after a complete miss, with
repeated miss-triggered refreshes briefly throttled. Dialogs do not display
executable modification timestamps. This GUI metadata is presentation-only and
is not part of process authorization or direct-unlock trust evaluation. Linux
GUI unlock requires an accepted GUI session capability (`x-session` or
`wayland-session`) and uses in-process GTK4 or Qt Quick/QML SDK dialogs with
forced X11 backend usage. A wrong password, cancelled dialog, or closed dialog
denies the request. Concurrent GUI unlock requests are displayed as separate
dialogs.

Clicking the explicit **Deny** button records a denial for the requesting
process-lineage and access-scope pair. Until `user.denialTtlSeconds` expires,
later GUI unlock requests for that pair return `403 temporary_lockout` without
displaying another dialog. The Deny-button response itself uses the same error. Other
scopes remain unaffected. Escape, window close, prompt backend
failure, and wrong-password submission do not create a cached denial. A
successful unlock clears any denial for that scope. Denials are memory-only,
survive database lock and idle unload, and are cleared when the agent exits.

Failure:
- `403 access_denied`
- `403 temporary_lockout`

On Linux direct-only builds or clients without an accepted GUI capability, the advertised method is:

```http
POST /api/v1/auth/unlock/direct?scope={items|settings}
Authorization: Bearer <standard-base64 UTF-8 password>

HTTP/1.1 200 OK
```

Both GUI and direct unlock open or reuse the encrypted database and authorize
only the requested access scope for the caller's process lineage. Direct unlock
uses the ultimate executable in the verified process lineage: the process
connected directly to the Unix socket, independently of the process selected
for GUI display. An executable with the same file identity as the running agent
is always allowed. Every other caller's executable path is canonicalized and
must match at least one glob in `user.trustedProgramPaths`.

The agent does not perform breaking schema migrations. When the supplied
password opens a database whose schema is behind a known breaking boundary,
the database remains locked and unlock returns `502 migration_needed` with the
message `database migration required; run \`monopass migrate\``. No
database-backed operation is allowed until the offline migration completes.

Missing ultimate-process identity or path metadata, canonicalization failures,
malformed persisted patterns, and unmatched paths fail closed with
`403 access_denied`. Password verification, database opening, trust evaluation,
and authorization commitment do not expose an intermediate authorized state.

Failures:
- `403 access_denied`
- `403 unlock_failed`
- `502 migration_needed`

### Lock

```http
POST /api/v1/auth/lock

HTTP/1.1 200 OK
```

Clears cached item and settings process-lineage authorizations immediately and
schedules the unlocked database for unload on the agent's next authorization-expiry sweep.
The request does not close the database synchronously; active database requests
and active jobs continue to delay unload as normal.

Failure:
- `403 access_denied`

### Status

```http
GET /api/v1/auth/status?scope={items|settings}

HTTP/1.1 200 OK
Content-Type: application/json

{
  "reauth_timestamp": "2026-06-07T01:38:45Z"
}
```

Returns `200 OK` only when the database is unlocked and the current process
lineage is authorized for the requested access scope. `reauth_timestamp` is an
RFC3339 UTC timestamp for when that authorization expires. Does not refresh the
process-lineage authorization expiry or database idle timer.

Failure:
- `403 access_denied`

## Settings

Settings routes are database-backed and require a cached `settings`
authorization for the caller's process lineage. An `items` authorization does
not grant settings access, even if the request includes a valid master-password
bearer. Settings requests do not consume bearer passwords.

Directories may carry internal bitmask flags. `DIR_HIDDEN = 1 << 0` hides a
directory from public directory lists, and `DIR_SYSTEM = 1 << 1` blocks public
item mutations. `DIR_DENY_OVERWRITE = 1 << 2` specifically blocks item PATCH
and version restoration with `403 access_denied`; item creation, copy, move,
read, listing, and permanent deletion retain their normal behavior.

Items may also carry internal bitmask flags. `ITEM_HIDDEN = 1 << 0` hides an
item from public item reads and lists. `ITEM_READ_MUSTAUTH = 1 << 1` adds a
per-request master-password check for secret-bearing reads: `GET Item` with
`reveal=true` or `raw=true`, and `GET Reference`. The password is supplied with
`Authorization: Bearer <standard-base64 UTF-8 password>`. Missing, malformed,
or wrong bearer passwords return
`403 access_denied` only when the target public item has `ITEM_READ_MUSTAUTH`;
masked `GET Item`, `List Items`, and `List Item Versions` do not enforce it.

User-configurable settings are stored as string values in `system_settings`
under `user.*` names:

| Name | Default | Allowed values |
| --- | --- | --- |
| `user.authTtlSeconds` | `900` | integer seconds, `1..=604800` |
| `user.settingsAuthTtlSeconds` | `300` | integer seconds, `1..=604800` |
| `user.denialTtlSeconds` | `60` | integer seconds, `1..=604800` |
| `user.gcSeconds` | `3600` | integer seconds, `60..=2592000` |
| `user.autoDeleteTrashItemsAfterSeconds` | `15552000` | integer seconds, `0..=157680000` |
| `user.autoDeleteOldVersionsAfterSeconds` | `15552000` | integer seconds, `0..=157680000` |
| `user.trustedProgramPaths` | `[]` | JSON-serialized array of valid path globs |

Opening a database inserts any missing registered user settings with their
defaults and leaves existing rows unchanged.

`user.authTtlSeconds` controls process-lineage authorization TTL. Changes take
effect immediately for new and existing cached item authorizations.
`user.settingsAuthTtlSeconds` independently controls settings authorization TTL
and likewise applies immediately to new and existing entries.
`user.denialTtlSeconds` controls explicit GUI denial TTL. The agent uses 60
seconds until the encrypted setting is first loaded by a successful unlock,
then keeps the loaded value in memory through later database unloads. Changes
take effect immediately for new and existing cached denials. `user.gcSeconds`
controls the best-effort idle cleanup cadence.
`user.autoDeleteTrashItemsAfterSeconds` controls how long items remain in
`Trash`, measured from its current `updated_at` timestamp. Moving or renaming
an item within `Trash` refreshes `updated_at` and postpones deletion.
`user.autoDeleteOldVersionsAfterSeconds`
controls retention of non-latest item versions. For either setting, `0`
disables that category of automatic deletion and positive values take effect
on the next eligible cleanup. `user.trustedProgramPaths`
controls which non-agent ultimate executables may use direct unlock. Patterns
are matched case-sensitively against canonical executable paths. `*` does not
cross path separators; `**` may match recursive path components. Empty,
relative, and duplicate patterns are allowed, while malformed glob syntax is
rejected. Paths are not required to be absolute, unique, non-empty, present, or
executable when the setting is written. The default `[]` allows only callers
whose executable file identity matches the running agent. Removing a pattern
affects future direct unlocks and does not revoke an authorization already
issued to a process lineage.

### List Settings

```http
GET /api/v1/settings

HTTP/1.1 200 OK
Content-Type: application/json

{
  "user.authTtlSeconds": "900",
  "user.autoDeleteOldVersionsAfterSeconds": "15552000",
  "user.autoDeleteTrashItemsAfterSeconds": "15552000",
  "user.settingsAuthTtlSeconds": "300",
  "user.denialTtlSeconds": "60",
  "user.gcSeconds": "3600",
  "user.trustedProgramPaths": "[]"
}
```

Returns all `user.*` settings currently stored in `system_settings`. Internal
`sys.*` rows are not returned.

### Update Setting

```http
PUT /api/v1/settings/{name}
Content-Type: application/json

{ "value": "900" }

HTTP/1.1 200 OK
{}
```

Known duration settings are upserted when `value` is an in-range integer string.
`user.trustedProgramPaths` accepts a JSON-serialized string array of valid globs
and stores it in canonical compact form. For example, its request body is
`{ "value": "[\"/usr/bin/example\",\"relative-program\"]" }`. Unknown
settings, including `sys.*`, return `404 not_found`. Malformed request JSON,
missing `value`, invalid setting JSON, non-string array elements, malformed glob
syntax, non-integer duration values, and out-of-range duration values return
`400 bad_request`.

## Dirs

Some directories are reserved for internal use. Internal hidden directories are
omitted from directory lists, and direct public dir metadata access returns
`404 not_found`. Hidden directories cannot be renamed or deleted through the
public API. Hidden directories may still list their non-hidden item names when
the directory name is known. Direct item read operations may access non-hidden
items in hidden directories, and item write operations may target hidden
directories unless the directory is also system-locked.

### Create Dir

```http
PUT /api/v1/dir/{dirName}

HTTP/1.1 200 OK
{}
```

Conflict if the dir already exists.

### Get Dir

```http
GET /api/v1/dir/{dirName}

HTTP/1.1 200 OK
{
  "name": "personal",
  "created_at": "2026-06-07T01:23:45Z",
  "updated_at": "2026-06-07T01:23:45Z",
  "items": 12
}
```

### List Dirs

```http
GET /api/v1/dirs?count=50&marker={next_marker}

HTTP/1.1 200 OK
{
  "entries": [
    {
      "name": "personal",
      "created_at": "2026-06-07T01:23:45Z",
      "updated_at": "2026-06-07T01:23:45Z",
      "items": 12
    }
  ],
  "next_marker": null,
  "count": 1
}
```

Dirs are sorted by `name`. `count` is optional, defaults to `50`, and must be
between `1` and `200`. `marker` is an optional opaque value returned as
`next_marker` from the previous page. Invalid `count` or `marker` values return
`400 bad_request`.

### Update Dir

```http
PATCH /api/v1/dir/{dirName}
Content-Type: application/json

{
  "name": "renamed"
}

HTTP/1.1 200 OK
{}
```

Renames the dir and updates `updated_at`.

### Delete Dir

```http
DELETE /api/v1/dir/{dirName}

HTTP/1.1 200 OK
{}
```

Deletes the dir only when it has no items. Returns `409 conflict` if the dir is
not empty.

## Contacts

Contacts are identified by `email` and store an optional display `name`, an age
public key, and an optional description.

### Create Contact

```http
PUT /api/v1/contact/{contactEmail}
Content-Type: application/json

{
  "name": "Alice",
  "age_public_key": "age1...",
  "description": "Personal laptop"
}

HTTP/1.1 200 OK
{}
```

Conflict if the contact already exists. Invalid or empty age public keys return
`400 bad_request`.

### Update Contact

```http
PATCH /api/v1/contact/{contactEmail}
Content-Type: application/json

{
  "email": "alice.renamed@example.com",
  "name": "Alice Renamed",
  "age_public_key": "age1..."
}

HTTP/1.1 200 OK
{}
```

The request updates the contact selected by the path email. `email` is required;
`name` and `age_public_key` are optional. Omitted optional fields keep their
current values. Duplicate target emails return `409 conflict`; missing contacts
return `404 not_found`.

### List Contacts

```http
GET /api/v1/contacts?count=50&marker={next_marker}

HTTP/1.1 200 OK
{
  "entries": [
    {
      "email": "alice@example.com",
      "name": "Alice",
      "age_public_key": "age1...",
      "description": "Personal laptop",
      "created_at": "2026-06-07T01:23:45Z"
    }
  ],
  "next_marker": null,
  "count": 1
}
```

Contacts are sorted by `email`. `count` is optional, defaults to `50`, and must
be between `1` and `200`. `marker` is an optional opaque value returned as
`next_marker` from the previous page. Invalid `count` or `marker` values return
`400 bad_request`.

### Delete Contact

```http
DELETE /api/v1/contact/{contactEmail}

HTTP/1.1 200 OK
{}
```

Returns `404 not_found` if the contact does not exist.

## Files

### Create file

```http
PUT /api/v1/file/upload
Content-Length: 123
<body>

HTTP/1.1 200 OK
{
  "id": "aaabbb101..."
}
```

Creates a pending file record and writes an encrypted external file blob. A
128-bit identifier is generated at random and returned as a 32-character
lowercase hex ID.

The request body is encrypted incrementally as it is received and written to
disk as fixed-size AES-256-GCM records. Uploads are limited to
35,184,372,080,640 bytes (`u32::MAX * 8192`); larger `Content-Length` values
are rejected with `400 bad_request`. The AES key is stored internally as the
hidden `_Internal/FileEncryptionKey` item created during database
initialization. The database stores the file ID, plaintext SHA-256, plaintext
size, 8-byte AES-GCM nonce prefix, last record tag, and creation timestamp.
Pending uploads have no rows in `item_version_file_mapping` until an item
creation or update request attaches them by ID and file name.

External blob format:
- each plaintext record is encrypted as an independent AES-GCM record
- plaintext records are 8192 bytes, except the final non-empty record may be
  shorter
- a record is `u32_be ciphertext_length || 16-byte tag || ciphertext`
- every non-final non-empty record has `ciphertext_length == 8192`
- the record nonce is `files.nonce || u32_be(record_counter)`, where
  `files.nonce` is the 8-byte random per-file prefix and `record_counter` is in
  `0..u32::MAX`
- empty files are represented on disk by one authenticated empty record

## Items

Some items are reserved for internal use. Internal hidden items are omitted
from item lists and direct public item/reference/version access returns
`404 not_found`. Hidden items cannot be copied, moved, updated, restored, or
deleted through the public API. Internal system directories reject public
create, copy, move, update, restore, and delete item operations with
`403 access_denied`.
Directories with `DIR_DENY_OVERWRITE` reject only update and restore operations
with `403 access_denied`.

### Create Item

```http
PUT /api/v1/dir/{dirName}/item/{itemName}
Content-Type: application/json

{
  "fields": [
    {
      "name": "password",
      "type": "string",
      "concealed": true,
      "data": "secret"
    }
  ],
  "files": [
    {
      "name": "ssh_key",
      "id": "aaabbb101..."
    }
  ]
}

HTTP/1.1 200 OK
{}
```

`fields` and `files` are optional arrays. Each entry must include a non-empty
`name`, and names must be unique within each array and across both arrays.

Field rules:
- `type` is one of `"string"`, `"file"`, `"totp"`.
- `concealed` is optional on input.
- If omitted, `concealed` defaults to true when the field name contains
  `password`, `secret`, or `private`, or contains `key` but not `public`.
- `totp` fields are always concealed.
- `totp` field `data` must be an `otpauth://totp/...` URL with a non-empty
  `secret` query parameter. The percent-decoded secret must be unpadded Base32;
  lowercase letters are accepted, but padding, spaces, invalid Base32
  characters, and invalid unpadded Base32 lengths are rejected.

File input rules:
- file values must be objects with exactly a `name` and uploaded file `id`
- file IDs are 32-character lowercase hex strings returned by `PUT /api/v1/file/upload`
- inline file content and local file path references are not accepted
- a file ID can only be attached once
- request files override source files with the same name in copy-item and
  update-item requests

Create stores one initial item version. Conflict if the item already exists.

### Copy Item Variant

```http
PUT /api/v1/dir/{dirName}/item/{itemName}?copy_from={sourceDirName}/{sourceItemName}
Content-Type: application/json
```

Copy behavior:
- Load fields/files from the source item.
- Apply request fields/files on top.
- Request values override same-name source values.
- Source files that are not overridden are attached to the destination item.
- Store the merged result as one initial destination item version. Source
  version history is not copied.

### Move Item Variant

```http
PUT /api/v1/dir/{dirName}/item/{itemName}?move_from={sourceDirName}/{sourceItemName}
```

Move behavior:
- The request body must be empty.
- Update the source item in place with the destination dir, destination item
  name, and a new `updated_at` timestamp.
- Do not create a new version and do not change fields/files.
- Conflict if any item already exists at the destination.

`copy_from` and `move_from` are mutually exclusive.

### Update Item

```http
PATCH /api/v1/dir/{dirName}/item/{itemName}
Content-Type: application/json

{
  "fields": [
    {
      "name": "password",
      "type": "string",
      "concealed": true,
      "data": "new secret"
    },
    {
      "name": "old_password",
      "remove": true
    }
  ],
  "files": [
    {
      "name": "ssh_key",
      "id": "aaabbb101..."
    },
    {
      "name": "old_key",
      "remove": true
    }
  ]
}

HTTP/1.1 200 OK
{}
```

Loads the existing item, applies request fields/files on top, writes the merged
fields and file mappings as a new item version, points the item at the new
latest version, and updates `updated_at`.

`fields` and `files` are optional arrays. Each entry must include a non-empty
unique `name`. Field names and file names must be unique within each array and
across both arrays in the resulting item version. Each field entry is either a
field object with the same shape and validation as create item, or
`{ "name": "...", "remove": true }`. Each file entry is either
`{ "name": "...", "id": "..." }` with the same validation as create item, or
`{ "name": "...", "remove": true }`.

Set entries override same-name existing values. Remove entries delete same-name
existing fields or file mappings from the new version; removing a missing field
or file succeeds without changing anything else. Existing fields/files that are
omitted from the request are retained. Mixed entries such as `{ "name": "...",
"remove": true, "id": "..." }`, `remove: false`, duplicate names, old
map-shaped `fields`/`files`, and removal entries in create, copy, or move
requests are rejected as `400 bad_request`.

If the target directory has `DIR_DENY_OVERWRITE`, update returns
`403 access_denied`.

### Get Item

```http
GET /api/v1/dir/{dirName}/item/{itemName}?version={n}

HTTP/1.1 200 OK
{
  "name": "github",
  "created_at": "2026-06-07T01:23:45Z",
  "updated_at": "2026-06-07T01:24:00Z",
  "total_versions": 3,
  "fields": [
    {
      "name": "password",
      "type": "string",
      "concealed": true,
      "data": "******"
    }
  ],
  "files": [
    {
      "name": "ssh_key",
      "size": 4096
    }
  ]
}
```

Concealed field values are masked as `"******"` by default. Use
`GET /api/v1/dir/{dirName}/item/{itemName}?reveal=true` to return stored
field data, except TOTP fields are rendered as current generated codes. Use
`GET /api/v1/dir/{dirName}/item/{itemName}?raw=true` to return stored field
data unchanged, including TOTP `otpauth://...` URLs. If both `reveal=true` and
`raw=true` are present, raw mode wins. Only the exact query values
`reveal=true` and `raw=true` enable those modes; absent, empty, `false`, or any
other value remains masked.

`version` is optional. When omitted, the latest version is returned. When
present, it must be a positive integer and selects that retained item version.
Empty, malformed, zero, or negative versions return `400 bad_request`;
well-formed but missing or cleaned-up versions return `404 not_found`.
`total_versions` is the current count of retained versions for the item,
including the latest version, after any cleanup.

### List Items

```http
GET /api/v1/dir/{dirName}/items?count=50&marker={next_marker}&glob=*github*&dir=asc

HTTP/1.1 200 OK
{
  "entries": [
    {
      "name": "github",
      "created_at": "2026-06-07T01:23:45Z",
      "updated_at": "2026-06-07T01:23:45Z"
    }
  ],
  "next_marker": null,
  "count": 1
}
```

List items intentionally returns metadata only: `name`, `created_at`,
`updated_at`. `glob` optionally filters item names using SQLite's case-sensitive
glob syntax (`*`, `?`, and bracket expressions). `dir` controls lexical name
ordering and accepts `asc` or `desc`, defaulting to `asc`. `count` is optional,
defaults to `50`, and must be between `1` and `200`. `marker` is an optional
opaque value returned as `next_marker` from the previous page and is scoped to
the directory, glob, and direction. Invalid `count`, `dir`, or `marker` values
return `400 bad_request`.

### List Item Versions

```http
GET /api/v1/dir/{dirName}/item/{itemName}/versions?count=50&marker={next_marker}

HTTP/1.1 200 OK
{
  "entries": [
    {
      "version": 3,
      "created_at": "2026-06-07T01:23:45Z"
    }
  ],
  "next_marker": null,
  "count": 1
}
```

Lists retained versions for an item, sorted newest first by version number.
`count` is optional, defaults to `50`, and must be between `1` and `200`.
`marker` is an optional opaque value returned as `next_marker` from the previous
page. Markers are scoped to the item. Invalid `count` or `marker` values return
`400 bad_request`.

### Restore Item Version

```http
PUT /api/v1/dir/{dirName}/item/{itemName}/restore?version={n}

HTTP/1.1 200 OK
{}
```

Restores a retained historical version by copying its fields and file mappings
into a new latest version. The restored version gets a fresh creation timestamp,
and the item `updated_at` timestamp is updated. `version` is required and must
be a positive integer. Missing, empty, malformed, zero, or negative versions
return `400 bad_request`; well-formed but missing or cleaned-up versions return
`404 not_found`. Restoring the current latest version returns
`400 bad_request`.
If the target directory has `DIR_DENY_OVERWRITE`, restore returns
`403 access_denied`.

### Delete Item

```http
DELETE /api/v1/dir/{dirName}/item/{itemName}

HTTP/1.1 200 OK
{}
```

Deletes the item. Attached file mappings are removed by cascade; encrypted
external file blobs and their `files` rows are retained until orphan cleanup
removes files that no longer have any item mappings.

### Import Item

```http
PUT /api/v1/jobs/import/{dirName}/{itemName}
Content-Type: application/octet-stream

<encrypted .export bytes>

HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "job_id": "00112233445566778899aabbccddeeff",
  "status": "queued"
}
```

Starts an agent-backed background import job for an age-encrypted share export.
The request body is spooled to a private temporary file; the background job
uses the local hidden age private identity, decrypts the payload, validates the
ZIP archive, verifies every `files/<sha256>` entry against its plaintext
SHA-256, uploads files with short file-write operations, and creates the target
item once all archive content is valid. Existing target items fail with a
failed job rather than replacing or merging.

The archive `fields.json` uses the same item shape as `GET Item`: `fields` and
`files` are arrays with unique `name` values. Export file entries replace item
file metadata with `{ "name": "...", "sha256": "..." }`.

The endpoint requires the same unlocked database and authorized process lineage
as other database routes. Initial submit errors use normal structured API
errors. Archive, decrypt, missing target directory, file write, and item
conflict failures after acceptance are recorded in the job status.

## Jobs

### Get Job

```http
GET /api/v1/jobs/status/{job_id}

HTTP/1.1 200 OK
Content-Type: application/json

{
  "job_id": "00112233445566778899aabbccddeeff",
  "type": "import",
  "status": "running",
  "target": {
    "dir": "Personal",
    "item": "github"
  },
  "created_at": "2026-06-07T01:23:45Z",
  "updated_at": "2026-06-07T01:23:46Z",
  "started_at": "2026-06-07T01:23:46Z",
  "finished_at": null,
  "error": null
}
```

Job records are stored in the encrypted database and remain available across
agent restarts. Supported statuses are `queued`, `running`, `succeeded`, and
`failed`. Failed jobs include a structured `error` object with `code` and
`message`. Missing or malformed job IDs return `404 not_found` or
`400 bad_request` respectively.

Completed and failed job records persist indefinitely in this version. While an
import job is active in the current agent process, authorization-expiry unload
does not unload the database handle, password verifier, authorization cache, or
last-access timestamp. Once the job reaches `succeeded` or `failed`, unload can
proceed normally.

## References

### Get reference

```http
GET /api/v1/ref/{dirName}/{itemName}/{fieldOrFileName}?version={n}

HTTP/1.1 200 OK
Content-Type: application/octet-stream
ETag: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

<raw file bytes>
```

For file responses, the encrypted external blob is decrypted incrementally and
the raw plaintext bytes are streamed back. Each AES-GCM record is authenticated
before its plaintext chunk is sent. The `ETag` header is the stored lowercase
hex SHA-256 of the plaintext file bytes. TOTP references return generated TOTP
bytes and do not include an `ETag`. Use
`GET /api/v1/ref/{dirName}/{itemName}/{fieldName}?raw=true` for TOTP references
to return the stored `otpauth://...` string bytes instead of a generated code.
Plain string field references return the stored field bytes directly and do not
include an `ETag`. If a field and file share the same name, the field is
returned by this endpoint.
`version` is optional and follows the same validation and retained-version
lookup rules as `GET /api/v1/dir/{dirName}/item/{itemName}?version={n}`.

## Retention And Orphan File Cleanup

Uploaded files can become orphaned when they are never attached to an item, when
their item is deleted, or when old item versions that referenced them are
deleted. Orphan file rows are `files` rows that have no matching rows in
`item_version_file_mapping`.

The authorization-expiry unload path performs best-effort cleanup while the
database is still unlocked and `user.gcSeconds` says cleanup is due. It
permanently deletes items joined to the reserved `Trash` directory whose
`updated_at` timestamp has reached the configured Trash retention period, then
deletes non-latest item versions whose
`created_at` timestamp has reached the configured old-version retention period
and repairs each affected item's `oldest_version_id`. The latest version of an
item is never deleted by version cleanup. Either category is skipped when its
setting is `0` or cannot be read as a valid duration.

Moving or renaming an item within Trash refreshes `updated_at`, postponing its
automatic deletion.

Cleanup then deletes orphan file rows and encrypted external blobs whose
`created_at` timestamp is more than 1 day old. Recent orphan files and files
still attached to remaining versions are retained. If deleting an external
blob fails, the database row is kept so a later cleanup pass can retry.

Item version listing and historical reads only expose retained rows. A version
that existed previously can return `404 not_found` after idle cleanup removes
old non-latest versions.

## Error Codes

Structured errors:

```json
{
  "error": {
    "code": "not_found",
    "message": "not found"
  }
}
```

Codes:
- `access_denied` -> 403
- `temporary_lockout` -> 403
- `unlock_failed` -> 403
- `bad_request` -> 400
- `not_found` -> 404
- `conflict` -> 409
- `internal_error` -> 500
- `migration_needed` -> 502

## Database Schema Requirements

Fresh databases may discard the old schema and use:

```sql
CREATE TABLE system_settings (
  name TEXT PRIMARY KEY,
  value TEXT
);

INSERT INTO system_settings (name, value)
VALUES
  ('user.authTtlSeconds', '900'),
  ('user.settingsAuthTtlSeconds', '300'),
  ('user.denialTtlSeconds', '60'),
  ('user.gcSeconds', '3600'),
  ('user.autoDeleteTrashItemsAfterSeconds', '15552000'),
  ('user.autoDeleteOldVersionsAfterSeconds', '15552000'),
  ('user.trustedProgramPaths', '[]');

-- Init also creates:
-- - dir `Trash` with bitmask `DIR_HIDDEN | DIR_DENY_OVERWRITE`
-- - dir `_Internal` with bitmask `DIR_HIDDEN | DIR_SYSTEM`
-- - normal dir `Personal`
-- - hidden item `_Internal/FileEncryptionKey` with bitmask
--   `ITEM_HIDDEN | ITEM_READ_MUSTAUTH` and a concealed string field named
--   `key`; its value is 32 random bytes encoded as 64 lowercase hex characters
--   and is used as the AES-256-GCM key for external file blobs.
-- - public item `_Internal/AgePublicKey` with bitmask `ITEM_READ_MUSTAUTH`
--   and hidden item
--   `_Internal/AgePrivateKey`, each with one string field named `key`; the
--   private key item has bitmask `ITEM_HIDDEN` and its key field is concealed.

CREATE TABLE dirs (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    bitmask INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE contacts (
    email TEXT PRIMARY KEY,
    name TEXT,
    age_public_key TEXT NOT NULL,
    description TEXT,
    created_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE items (
    id INTEGER PRIMARY KEY,
    dir_id INTEGER NOT NULL REFERENCES dirs (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    bitmask INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    oldest_version_id INTEGER,
    latest_version_id INTEGER,
    UNIQUE (dir_id, name),
    FOREIGN KEY (id, oldest_version_id) REFERENCES item_versions (item_id, version_id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (id, latest_version_id) REFERENCES item_versions (item_id, version_id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE item_versions (
    version_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (item_id, version_id)
) WITHOUT ROWID;

CREATE TABLE item_version_fields (
    item_id INTEGER NOT NULL,
    version_id INTEGER NOT NULL,
    field_name TEXT NOT NULL,
    field_type TEXT NOT NULL CHECK (field_type IN ('string', 'file', 'totp')),
    concealed INTEGER NOT NULL CHECK (concealed IN (0, 1)),
    data TEXT NOT NULL,
    PRIMARY KEY (item_id, version_id, field_name),
    FOREIGN KEY (item_id, version_id) REFERENCES item_versions (item_id, version_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE files (
    id BLOB PRIMARY KEY,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    nonce BLOB NOT NULL, -- 8-byte AES-GCM nonce prefix for file records
    tag BLOB NOT NULL, -- last 16-byte AES-GCM record tag
    created_at INTEGER NOT NULL,
    UNIQUE (sha256)
) WITHOUT ROWID;

CREATE TABLE item_version_file_mapping (
    item_id INTEGER NOT NULL,
    version_id INTEGER NOT NULL,
    file_id BLOB NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    PRIMARY KEY (item_id, version_id, file_id),
    UNIQUE (item_id, version_id, file_name),
    FOREIGN KEY (item_id, version_id) REFERENCES item_versions (item_id, version_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE jobs (
    job_id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    target_dir TEXT NOT NULL,
    target_item TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    error_code TEXT,
    error_message TEXT
) WITHOUT ROWID;

PRAGMA user_version = 3;
```

The schema-v2 migration leaves the table schema unchanged and adds
`DIR_DENY_OVERWRITE` to the reserved Trash directory bitmask while preserving
all existing directory flags and setting values.

Schema 3 is a breaking migration. It moves each entry from the schema-2
`item_versions.fields` JSON object into one `item_version_fields` row and then
removes the JSON column. The migration is transactional and is performed only
by `monopass migrate`, never while the agent is running.

Fresh databases store encrypted file blobs outside the SQLCipher database under
`files/` in the app data directory. This is the app XDG data directory, except
on macOS when `XDG_DATA_HOME` is not set, where it is
`~/Library/Application Support/monopass`. The blob filename is derived from the
lowercase hex file ID, and the database stores the metadata required to decrypt
and verify it.
