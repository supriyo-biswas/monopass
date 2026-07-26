# monopass HTTP API reference

Base path: `/api/v1`

monopass exposes this API through its local Unix socket. JSON request and response bodies use `Content-Type: application/json` unless an endpoint says otherwise. Timestamps are RFC3339 UTC strings.

## Errors

Every unsuccessful response uses this shape:

```json
{
  "error": {
    "code": "not_found",
    "message": "not found"
  }
}
```

- `400 bad_request` — the path, query, headers, or request body is invalid.
- `403 access_denied` — monopass has not authorized this request.
- `403 temporary_lockout` — a recent GUI authorization request was denied.
- `403 unlock_failed` — the submitted master password did not unlock monopass.
- `404 not_found` — the requested resource does not exist.
- `409 conflict` — the request conflicts with existing data or state.
- `500 internal_error` — monopass could not complete the request.
- `502 migration_needed` — the user needs to run `monopass migrate` before being able to operate on the password vault.

## Authorization and scopes

monopass authorizes a specific same-user process lineage. It starts with the program that connected to the local socket, walks back through its same-user parents to the oldest process it can identify, and records that ordered chain. monopass recognizes the same chain when its programs and ancestry still match; starting the integration through a different executable, terminal, launcher, or process chain requires authorization again.

Successful unlocks are remembered for that lineage until their authorization expires. The default lifetime is 15 minutes for `items` and 5 minutes for `settings`, although a user can change both settings. A process must be authorized before monopass allows it to use endpoints in that scope.

Authorizations are separate for two scopes:

- `items` covers completions, directories, contacts, files, items, jobs, and references. It is the default when `scope` is omitted.
- `settings` covers only `/settings` routes. An `items` authorization does not grant settings access.

For an `items` request, either omit `scope` or pass `scope=items` explicitly:

```http
GET /api/v1/auth/unlock/methods HTTP/1.1
```

```http
GET /api/v1/auth/unlock/methods?scope=items HTTP/1.1
```

For a `/settings` request, use `scope=settings`:

```http
GET /api/v1/auth/unlock/methods?scope=settings HTTP/1.1
```

When you pass a scope explicitly, call the returned URL exactly as supplied because it carries the same scope query parameter.

The normal client pattern is deliberately request-first:

1. Make the item or settings request you need.
2. If it succeeds, use its response.
3. If it returns `403 access_denied`, call `GET /auth/unlock/methods` for that request's scope, call the first returned method, then retry the original request exactly once.
4. If the unlock or retry fails, surface that error instead of starting another authorization loop.

When a GUI session is available, include its capability while discovering an unlock method:

```http
X-Client-Capabilities: x-session=:0
```

or:

```http
X-Client-Capabilities: wayland-session=wayland-0
```

## Authentication

### Discover an unlock method

`GET /auth/unlock/methods?scope={items|settings}` returns the supported unlock method. Omit `scope` for the default `items` scope, pass `scope=items` to make that choice explicit, or pass `scope=settings` before a settings request.

```http
GET /api/v1/auth/unlock/methods HTTP/1.1
X-Client-Capabilities: x-session=:0

HTTP/1.1 200 OK
Content-Type: application/json

{
  "methods": [
    {
      "url": "/api/v1/auth/unlock/gui",
      "accepts_master_password": false
    }
  ]
}
```

Method discovery does not require an existing scope authorization. It can still return `403 access_denied` when monopass cannot accept the local caller.

Failures: `400 bad_request`, `403 access_denied`.

### Unlock with the GUI

`POST /auth/unlock/gui?scope={items|settings}` opens the password prompt.

```http
POST /api/v1/auth/unlock/gui HTTP/1.1
X-Client-Capabilities: x-session=:0

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `403 access_denied`, `403 temporary_lockout`.

Do not call this endpoint directly. Its URL may change; call it only as a URL returned by `GET /auth/unlock/methods`.

### Unlock with a master password

`POST /auth/unlock/direct?scope={items|settings}` unlocks a scope with the master password.

```http
POST /api/v1/auth/unlock/direct HTTP/1.1
Authorization: Bearer <standard-base64 UTF-8 master password>

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `403 access_denied`, `403 unlock_failed`, `502 migration_needed`.

Do not call this endpoint directly. Its URL may change; call it only as a URL returned by `GET /auth/unlock/methods`.

### Lock monopass

`POST /auth/lock` removes the current authorizations.

```http
POST /api/v1/auth/lock HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `403 access_denied`.

### Check authorization status

`GET /auth/status?scope={items|settings}` returns the expiry for a scope.

```http
GET /api/v1/auth/status?scope=items HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{
  "reauth_timestamp": "2026-06-07T01:38:45Z"
}
```

Failures: `403 access_denied`.

## Shell completions

### List completion candidates

`GET /shell/completions` returns names matching a prefix. `kinds` is a comma-separated list of `dir`, `item`, `field`, `file`, and `contact`.

```http
GET /api/v1/shell/completions?prefix=Personal/Git&kinds=item,field HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{
  "entries": [
    { "value": "Personal/GitHub", "kind": "item" },
    { "value": "Personal/GitHub/password", "kind": "field" }
  ],
  "truncated": false
}
```

Failures: `400 bad_request`, `403 access_denied`.

## Settings

### List settings

`GET /settings` returns user settings and uses the `settings` scope.

```http
GET /api/v1/settings HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{
  "user.authTtlSeconds": "900",
  "user.settingsAuthTtlSeconds": "300",
  "user.trustedProgramPaths": "[]"
}
```

Failures: `403 access_denied`.

### Update a setting

`PUT /settings/{name}` updates a user setting and uses the `settings` scope.

```http
PUT /api/v1/settings/user.authTtlSeconds HTTP/1.1
Content-Type: application/json

{ "value": "900" }

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`.

## Directories

### Create a directory

`PUT /dir/{dirName}` creates a directory.

```http
PUT /api/v1/dir/Archive HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `403 access_denied`, `409 conflict`.

### Get a directory

`GET /dir/{dirName}` returns a directory and its item count.

```http
GET /api/v1/dir/Personal HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{
  "name": "Personal",
  "created_at": "2026-06-07T01:23:45Z",
  "updated_at": "2026-06-07T01:23:45Z",
  "items": 12
}
```

Failures: `403 access_denied`, `404 not_found`.

### List directories

`GET /dirs` returns a page of directories. Pass `next_marker` as `marker` for the next page.

```http
GET /api/v1/dirs?count=50 HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{
  "entries": [
    {
      "name": "Personal",
      "created_at": "2026-06-07T01:23:45Z",
      "updated_at": "2026-06-07T01:23:45Z",
      "items": 12
    }
  ],
  "next_marker": null,
  "count": 1
}
```

Failures: `400 bad_request`, `403 access_denied`.

### Rename a directory

`PATCH /dir/{dirName}` renames a directory.

```http
PATCH /api/v1/dir/Personal HTTP/1.1
Content-Type: application/json

{ "name": "Archive" }

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`, `409 conflict`.

### Delete a directory

`DELETE /dir/{dirName}` deletes an empty directory.

```http
DELETE /api/v1/dir/Archive HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `403 access_denied`, `404 not_found`, `409 conflict`.

## Contacts

### Create a contact

`PUT /contact/{contactEmail}` creates a sharing contact.

```http
PUT /api/v1/contact/alice@example.com HTTP/1.1
Content-Type: application/json

{
  "name": "Alice",
  "age_public_key": "age1...",
  "description": "Personal laptop"
}

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `400 bad_request`, `403 access_denied`, `409 conflict`.

### Update a contact

`PATCH /contact/{contactEmail}` changes a contact.

```http
PATCH /api/v1/contact/alice@example.com HTTP/1.1
Content-Type: application/json

{
  "email": "alice@example.com",
  "name": "Alice",
  "age_public_key": "age1..."
}

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`, `409 conflict`.

### List contacts

`GET /contacts` returns a page of contacts.

```http
GET /api/v1/contacts?count=50 HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

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

Failures: `400 bad_request`, `403 access_denied`.

### Delete a contact

`DELETE /contact/{contactEmail}` removes a sharing contact.

```http
DELETE /api/v1/contact/alice@example.com HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `403 access_denied`, `404 not_found`.

## Files

### Upload a file

`PUT /file/upload` uploads raw bytes and returns a file ID for an item request.

```http
PUT /api/v1/file/upload HTTP/1.1
Content-Length: 123

<raw file bytes>

HTTP/1.1 200 OK
Content-Type: application/json

{ "id": "00112233445566778899aabbccddeeff" }
```

Failures: `400 bad_request`, `403 access_denied`.

## Items

### Create an item

`PUT /dir/{dirName}/item/{itemName}` creates an item. `fields` and `files` are optional arrays.

```http
PUT /api/v1/dir/Personal/item/GitHub HTTP/1.1
Content-Type: application/json

{
  "fields": [
    { "name": "username", "type": "string", "concealed": false, "data": "alice" },
    { "name": "password", "type": "string", "concealed": true, "data": "secret" }
  ],
  "files": [
    { "name": "ssh_key", "id": "00112233445566778899aabbccddeeff" }
  ]
}

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`, `409 conflict`.

### Copy an item

`PUT /dir/{dirName}/item/{itemName}?copy_from={sourceDirName}/{sourceItemName}` copies an item. Its optional `fields` and `files` body has the same shape as Create an item.

```http
PUT /api/v1/dir/Personal/item/GitHub-Backup?copy_from=Personal/GitHub HTTP/1.1
Content-Type: application/json

{ "fields": [], "files": [] }

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`, `409 conflict`.

### Move an item

`PUT /dir/{dirName}/item/{itemName}?move_from={sourceDirName}/{sourceItemName}` moves an item. Its request body is empty.

```http
PUT /api/v1/dir/Archive/item/GitHub?move_from=Personal/GitHub HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`, `409 conflict`.

### Update an item

`PATCH /dir/{dirName}/item/{itemName}` adds, replaces, or removes fields and files.

```http
PATCH /api/v1/dir/Personal/item/GitHub HTTP/1.1
Content-Type: application/json

{
  "fields": [
    { "name": "password", "type": "string", "concealed": true, "data": "new secret" },
    { "name": "old_password", "remove": true }
  ],
  "files": [
    { "name": "ssh_key", "id": "00112233445566778899aabbccddeeff" },
    { "name": "old_key", "remove": true }
  ]
}

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`.

### Get an item

`GET /dir/{dirName}/item/{itemName}` returns an item. Add `version={n}` for a retained version; add `reveal=true` or `raw=true` to return stored concealed field data.

```http
GET /api/v1/dir/Personal/item/GitHub HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{
  "name": "GitHub",
  "created_at": "2026-06-07T01:23:45Z",
  "updated_at": "2026-06-07T01:24:00Z",
  "total_versions": 3,
  "fields": [
    { "name": "password", "type": "string", "concealed": true, "data": "******" }
  ],
  "files": [
    { "name": "ssh_key", "size": 4096 }
  ]
}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`.

### List items

`GET /dir/{dirName}/items` returns item metadata. It accepts `count`, `marker`, `glob`, and `dir=asc|desc`.

```http
GET /api/v1/dir/Personal/items?count=50 HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{
  "entries": [
    {
      "name": "GitHub",
      "created_at": "2026-06-07T01:23:45Z",
      "updated_at": "2026-06-07T01:23:45Z"
    }
  ],
  "next_marker": null,
  "count": 1
}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`.

### List item versions

`GET /dir/{dirName}/item/{itemName}/versions` returns retained versions.

```http
GET /api/v1/dir/Personal/item/GitHub/versions?count=50 HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{
  "entries": [
    { "version": 3, "created_at": "2026-06-07T01:23:45Z" }
  ],
  "next_marker": null,
  "count": 1
}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`.

### Restore an item version

`PUT /dir/{dirName}/item/{itemName}/restore?version={n}` makes a retained version the latest version.

```http
PUT /api/v1/dir/Personal/item/GitHub/restore?version=2 HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`.

### Delete an item

`DELETE /dir/{dirName}/item/{itemName}` deletes an item.

```http
DELETE /api/v1/dir/Personal/item/GitHub HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{}
```

Failures: `403 access_denied`, `404 not_found`.

### Import an item

`PUT /jobs/import/{dirName}/{itemName}` starts an import from an encrypted `.export` file.

```http
PUT /api/v1/jobs/import/Personal/GitHub HTTP/1.1
Content-Type: application/octet-stream

<encrypted .export bytes>

HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "job_id": "00112233445566778899aabbccddeeff",
  "status": "queued"
}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`, `409 conflict`.

### Export an item

`PUT /jobs/export/{dirName}/{itemName}/{contactEmail}` starts an encrypted `.export` file for a sharing contact.

```http
PUT /api/v1/jobs/export/Personal/GitHub/alice@example.com HTTP/1.1

HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "job_id": "00112233445566778899aabbccddeeff",
  "status": "queued"
}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`.

## Jobs

### Get a job

`GET /jobs/status/{jobId}` returns an import or export job's current or final result. Successful export jobs include `output_path`, the path of the completed encrypted export file; import jobs return `null` for this field.

```http
GET /api/v1/jobs/status/00112233445566778899aabbccddeeff HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{
  "job_id": "00112233445566778899aabbccddeeff",
  "type": "import",
  "status": "running",
  "target": { "dir": "Personal", "item": "GitHub" },
  "created_at": "2026-06-07T01:23:45Z",
  "updated_at": "2026-06-07T01:23:46Z",
  "started_at": "2026-06-07T01:23:46Z",
  "finished_at": null,
  "output_path": null,
  "error": null
}
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`.

### Wait for a submitted job

After `PUT /jobs/import/...` or `PUT /jobs/export/...` returns `202 Accepted`, poll `GET /jobs/status/{job_id}` approximately every 250 milliseconds.

1. When `status` is `queued` or `running`, wait and poll again.
2. When `status` is `succeeded`, the import is complete. For an export, read or copy the completed file named by `output_path`, then remove that temporary output file when you no longer need it.
3. When `status` is `failed`, show the job's `error.code` and `error.message` to the user.

The built-in `monopass import` and `monopass share` commands use this same submit-and-poll flow.

## References

### Read a field or file

`GET /ref/{dirName}/{itemName}/{fieldOrFileName}` returns raw field or file bytes. Add `version={n}` for a retained version, and `raw=true` for the stored TOTP URL instead of a generated code.

```http
GET /api/v1/ref/Personal/GitHub/ssh_key HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/octet-stream
ETag: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

<raw file bytes>
```

Failures: `400 bad_request`, `403 access_denied`, `404 not_found`.
