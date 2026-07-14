# Agent API Spec

Base path: `/api/v1`

All database-backed routes require the agent database to be unlocked and the
caller process to be authorized. Unauthorized or locked access returns
`403 access_denied`.

Timestamps are stored as Unix seconds and returned as RFC3339 UTC strings.

## Auth

The agent derives an authorization scope from the Unix peer credentials and the
peer's process lineage. A scope contains the caller UID and session ID, the PID
and start time of the oldest accessible same-user process in that session, and
the ordered identity of every process from that anchor through the direct
client. The direct `monopass` process is included.

Each lineage element uses executable file identity (device, inode, available
generation, size, modification time, and change time) when available. If the
executable cannot be inspected, the element falls back to PID plus process
start time. A different scope, changed executable, changed ordered lineage, or
PID/start-time fallback from a new process requires reauthorization. Traversal
stops before a different-user or different-session ancestor and otherwise
fails closed when required process identity cannot be resolved.

### Unlock

Unlock uses the method discovery flow described in
[`flexible-auth-spec.md`](flexible-auth-spec.md). The agent advertises the
preferred unlock method for the current platform, build variant, and client
capabilities.

```http
GET /api/v1/auth/unlock/methods
X-Client-Capabilities: x-session=<display>

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
POST /api/v1/auth/unlock/gui
X-Client-Capabilities: x-session=<display>

HTTP/1.1 200 OK
```

The agent displays a password dialog for the requesting application and accepts
one submitted password for the request. The dialog shows the application name,
executable path, and an icon when available. Linux GUI unlock requires an
accepted GUI session capability (`x-session` or `wayland-session`) and uses
in-process GTK4 or Qt Quick/QML SDK dialogs with forced X11 backend usage. A
wrong password, cancelled dialog, or closed dialog denies the request.
Concurrent GUI unlock requests are displayed as separate dialogs.

Failure:
- `403 access_denied`

On Linux direct-only builds or clients without an accepted GUI capability, the advertised method is:

```http
POST /api/v1/auth/unlock/direct
Authorization: Bearer <standard-base64 UTF-8 password>

HTTP/1.1 200 OK
```

Failures:
- `403 access_denied`
- `403 unlock_failed`

### Lock

```http
POST /api/v1/auth/lock

HTTP/1.1 200 OK
```

Clears cached process-lineage authorizations immediately and schedules the
unlocked database for unload on the agent's next authorization-expiry sweep.
The request does not close the database synchronously; active database requests
and active jobs continue to delay unload as normal.

Failure:
- `403 access_denied`

### Status

```http
GET /api/v1/auth/status

HTTP/1.1 200 OK
Content-Type: application/json

{
  "reauth_timestamp": "2026-06-07T01:38:45Z"
}
```

Returns `200 OK` only when the database is unlocked and the current process
lineage is authorized. `reauth_timestamp` is an RFC3339 UTC timestamp for when
the current process-lineage authorization expires. Does not refresh the
process-lineage authorization expiry or database idle timer.

Failure:
- `403 access_denied`

## Settings

Settings routes are database-backed and require the same unlocked database and
authorized process lineage as item, dir, and file routes. Every settings request
also requires `Authorization: Bearer <standard-base64 UTF-8 password>` with the
master password. Missing, malformed, invalid, or wrong settings passwords return
`403 access_denied`.

Items may also carry internal bitmask flags. `ITEM_HIDDEN = 1 << 0` hides an
item from public item reads and lists. `ITEM_READ_MUSTAUTH = 1 << 1` adds a
per-request master-password check for secret-bearing reads: `GET Item` with
`reveal=true` or `raw=true`, and `GET Reference`. The password is supplied with
the same `Authorization: Bearer <standard-base64 UTF-8 password>` header used
by settings. Missing, malformed, or wrong bearer passwords return
`403 access_denied` only when the target public item has `ITEM_READ_MUSTAUTH`;
masked `GET Item`, `List Items`, and `List Item Versions` do not enforce it.

User-configurable settings are stored as string values in `system_settings`
under `user.*` names:

| Name | Default | Allowed values |
| --- | --- | --- |
| `user.authTtlSeconds` | `900` | integer seconds, `1..=604800` |
| `user.gcSeconds` | `3600` | integer seconds, `60..=2592000` |

`user.authTtlSeconds` controls process-lineage authorization TTL. Changes take
effect immediately for new and existing cached authorizations. `user.gcSeconds`
controls the best-effort idle cleanup cadence.

### List Settings

```http
GET /api/v1/settings
Authorization: Bearer <standard-base64 UTF-8 password>

HTTP/1.1 200 OK
Content-Type: application/json

{
  "user.authTtlSeconds": "900",
  "user.gcSeconds": "3600"
}
```

Returns all `user.*` settings currently stored in `system_settings`. Internal
`sys.*` rows are not returned.

### Update Setting

```http
PUT /api/v1/settings/{name}
Authorization: Bearer <standard-base64 UTF-8 password>
Content-Type: application/json

{ "value": "900" }

HTTP/1.1 200 OK
{}
```

Known `user.*` settings are upserted when `value` is an in-range integer string.
Unknown settings, including `sys.*`, return `404 not_found`. Malformed JSON,
missing `value`, non-integer values, and out-of-range values return
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

## Orphan File Cleanup

Uploaded files can become orphaned when they are never attached to an item, when
their item is deleted, or when old item versions that referenced them are
deleted. Orphan file rows are `files` rows that have no matching rows in
`item_version_file_mapping`.

The authorization-expiry unload path also performs file cleanup while the
database is still unlocked. Immediately before unloading the database after all
cached process-lineage authorizations expire, the agent deletes non-latest item
versions whose `created_at` timestamp is more than 90 days old, repairs each
affected item's `oldest_version_id`, then deletes orphan file rows and encrypted
external blobs whose `created_at` timestamp is more than 1 day old. Recent
orphan files and files still attached to remaining versions are retained. If
deleting an external blob fails, the database row is kept so a later cleanup
pass can retry.

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
- `unlock_failed` -> 403
- `bad_request` -> 400
- `not_found` -> 404
- `conflict` -> 409
- `internal_error` -> 500

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
  ('user.gcSeconds', '3600');

-- Init also creates:
-- - hidden dir `Trash`
-- - hidden + system dir `_Internal`
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
    fields TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (item_id, version_id)
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

PRAGMA user_version = 1;
```

Fresh databases store encrypted file blobs outside the SQLCipher database under
`files/` in the app data directory. This is the app XDG data directory, except
on macOS when `XDG_DATA_HOME` is not set, where it is
`~/Library/Application Support/monopass`. The blob filename is derived from the
lowercase hex file ID, and the database stores the metadata required to decrypt
and verify it.
