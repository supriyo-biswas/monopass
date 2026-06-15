# Ground rules

- You must not touch the agent code. You must do everything using the APIs. If something cannot be implemented, do not implement it, and make a note of it at the end.
- Short/long handed options are always optional.
- The CLI implementation is agent-only. No command opens the SQLCipher database directly or calls helpers that decrypt database contents outside the agent.

# Shared implementation

The currently empty `vault` and `item` command placeholders will be replaced by
top-level subcommands matching this spec. Keep `src/commands/mod.rs` to CLI
wiring only and put implementation in focused modules, for example:

- `src/commands/client.rs`: Unix-socket HTTP client, auth retry, API error
  handling, pagination helpers.
- `src/commands/path.rs`: parsing `pass://`, `op://`, `<dir>/<item>`, and
  `<dir>/<item>/<fieldOrFile>` references.
- `src/commands/read.rs`, `run.rs`, `item.rs`, `dir.rs`, `contact.rs`,
  `share.rs`, `import.rs`, `pubkey.rs`: command-specific behavior.
- `src/commands/pwgen.rs`: password generation from `pwgenspec`.
- `src/commands/totp.rs`: TOTP input normalization, including QR image
  decoding. Add CLI dependencies such as `image` for image loading and `rqrr`
  for QR detection/decoding.

Implement a small blocking HTTP client over the Unix socket at
`Config::listen_path()`. The client should decode structured API errors and
preserve status codes for command-specific handling. On any auth-required
request that returns `403 access_denied`, prompt for the master password with
hidden terminal input, standard-base64 encode the UTF-8 password bytes, call
`POST /api/v1/auth/unlock`, zeroize the password buffer, then retry the
original request once. Treat `403 unlock_failed` and a second
`403 access_denied` as command failure. `GET /api/v1/auth/status` may be used
as a diagnostic, but never as a keepalive because it intentionally refreshes
neither authorization nor idle state.

Secret-bearing item reads can require the same bearer password on the original
read request, even after process-chain authorization succeeds. If `read`,
secret-bearing `show --reveal`, or any raw item read gets `403 access_denied`,
prompt/unlock as above and retry the original read once with
`Authorization: Bearer <standard-base64 UTF-8 password>`.

Use `zeroize` or `Zeroizing<T>` for owned sensitive values where practical,
including prompted passwords, decoded bearer material, generated passwords,
dotenv values that resolve to secrets, fetched field values, TOTP URLs, and
file contents that must be buffered. Prefer streaming file paths so large
secret files are not held in memory.

References accepted by `read` and `run` may be plain paths or prefixed with
`pass://` or `op://`; prefixes are stripped before parsing. The remaining path
forms are `<dir>/<item>` for item commands and `<dir>/<item>/<fieldOrFile>` for
reference reads. Reject empty components locally, and URL path encode
directory, item, field, and file names when inserting them into API routes.

Paginated commands request pages with `count=200` and follow `next_marker` until
it is null.

# Commands

## lock command

```
monopass lock
```

Use `POST /api/v1/auth/lock` to clear cached process authorizations and
schedule the unlocked database for unload on the agent's next authorization
expiry sweep. The command does not prompt for the master password when the
agent returns `403 access_denied`.

## init command

```
monopass init [--auto-start yes|no] [--skip-db-if-exists]
```

Initialize the database and configure agent auto-start. The command prompts for
the master password, creates the private storage directories, and creates the
encrypted database when it does not already exist.

On Linux, auto-start is configured with a user systemd socket unit at
`monopass-agent.socket`. The socket listens on the same Unix socket path used by
`Config::listen_path()`, and systemd starts `monopass-agent.service` on demand.
The agent must accept the inherited systemd listener when `LISTEN_PID` matches
the current process and `LISTEN_FDS=1`; without socket activation environment
variables, direct `monopass agent` startup falls back to binding the configured
socket path itself.

On macOS, auto-start is configured with a user LaunchAgent at
`~/Library/LaunchAgents/com.monopass.agent.plist`. The plist uses a `Sockets`
entry named `monopass-agent` with `SockPathName` set to `Config::listen_path()`.
The agent must accept the inherited launchd listener through
`launch_activate_socket("monopass-agent", ...)`; if launchd has not provided that
socket, direct `monopass agent` startup falls back to binding the configured
socket path itself.

If `--skip-db-if-exists` is set and the database already exists, skip the
database initialization branch and continue to the auto-start step. Without
that flag, an existing database is treated as an error.

Options:

- `--auto-start`: Configure whether agent auto-start is enabled.
- `--skip-db-if-exists`: Skip database initialization when the database file
  already exists.

## read command

```
monopass read <dir>/<item>/<fieldOrFile>
    --out-file
    --file-mode
    --force
```

Use `GET /api/v1/ref/{dirName}/{itemName}/{fieldOrFileName}` to stream a field
or file value to stdout or `--out-file`. The argument may be prefixed with
`pass://` or `op://` without changing behavior.

If the reference read returns `403 access_denied`, retry the original reference
request once with the prompted master password bearer after a successful unlock.

Options:

- `-o/--out-file`: Write to the given file instead of stdout, or `-` for stdout.
- `--file-mode`: File mode to use if writing to a file. Defaults to `0600`.
- `-f/--force`: Overwrite an existing output file.

When writing to a regular file, fail if the target exists unless `--force` is
set, create a temporary file in the destination directory with the requested
mode, stream into it, then rename on success. If the response has an `ETag`,
compute plaintext SHA-256 incrementally while streaming and verify it matches
the lowercase hex ETag before renaming. When writing to stdout, append a
newline only when stdout is a TTY.

## run command

```
monopass run [--] command arg1 ...
    --env-file
```

Run the command after resolving environment variable values that are
`pass://<dir>/<item>/<fieldOrFile>` or `op://<dir>/<item>/<fieldOrFile>`.

Options:

- `-e/--env-file`: Read additional environment variables from a dotenv file.

Build the child environment from the current process environment, then overlay
each dotenv file. For every reference value, use `GET Item` to classify the
name as a file or field, because `GET Reference` returns bytes for both. Fetch
fields with `GET Reference` and replace the env var value with the fetched
UTF-8 value. Fetch files with `GET Reference` into a private temporary
directory, replace the env var value with that temporary path, create files
with `0600`, and remove the directory after the child exits. Exit with the
child status code when available.

## mkdir command

```
monopass mkdir -p <dir>
```

Create a directory with `PUT /api/v1/dir/{dirName}`. With `-p`, treat
`409 conflict` as success. Without `-p`, surface the conflict.

## rmdir command

```
monopass rmdir <dir>
```

Remove an empty directory with `DELETE /api/v1/dir/{dirName}`. The API enforces
empty-directory semantics and returns `409 conflict` when the directory
contains items.

## add command

```
monopass add <dir>/<item>
    --username hello
    --password-prompt
    --generate-password [pwgenspec]
    --totp otpauth_url_or_qr_code_image_path
    --field fieldname=value
    --field fieldname2=value2
    --field fieldname3=value3
    --concealed-fields fieldname2,fieldname3
    --file id_rsa.pub=/absolute/path/to/other/file
    --file id_rsa=relative/path
```

Build a `CreateItemRequest` and send
`PUT /api/v1/dir/{dirName}/item/{itemName}` to create the item.

- `--username` creates a string field named `username`.
- `--password-prompt` and `--generate-password` are mutually exclusive. Both
  create a concealed string field named `password`; prompting asks for entry
  and confirmation.
- `--totp` creates a concealed `totp` field named `totp`. If the value starts
  with `otpauth://`, pass it through after local URL validation. Otherwise,
  treat the value as an image path, decode the image with an image loading
  dependency, decode QR codes with a QR dependency, extract the first
  `otpauth://` URL, and send that URL to the API. Fail if the image cannot be
  decoded, contains no QR code, contains multiple conflicting TOTP QR codes, or
  the decoded QR payload is not an `otpauth://` URL.
- `--field name=value` creates a string field. If `=value` is omitted, prompt
  once. If `--concealed-fields` is omitted, the CLI infers concealment from the
  field name using the same `password`/`secret`/`private`/`key` heuristic as
  the agent. If `--concealed-fields` is provided, fields listed there are sent
  with `concealed: true`; other fields are sent with `concealed: false`.
- `--file name=path` uploads each path with `PUT /api/v1/file/upload`, then
  attaches returned IDs in the item request.
- Duplicate field names or duplicate file names in one command fail locally.
- `pwgenspec` is a comma-separated password generation specification described
  later.

## edit command

```
monopass edit <dir>/<item>
    --username hello
    --password-prompt
    --generate-password [pwgenspec]
    --totp otpauth_url_or_qr_code_image_path
    --field fieldname=value
    --concealed-fields fieldname2,fieldname3
    --file id_rsa=relative/path
```

Build the same partial request shape as `add` and send
`PATCH /api/v1/dir/{dirName}/item/{itemName}` to update the item. The API
merges supplied fields and files with the existing item and stores a new
version. Omitted fields and files are retained. Fields or files deleted during
editing are sent as update-only removal entries, for example
`{ "name": "old_password", "remove": true }`.

## remove command

```
monopass rm <dir>[/<item>] --force --recursive
```

For item paths, the default behavior is a soft delete: move the item to
`Trash` with
`PUT /api/v1/dir/Trash/item/{itemName}?move_from={dirName}/{itemName}`.
If the source item is already in `Trash`, the command skips the move and
permanently deletes it instead.
With `--force`, permanently delete the item with
`DELETE /api/v1/dir/{dirName}/item/{itemName}`.

For directory paths, non-recursive removal uses `rmdir` behavior.
`--recursive` lists items with `GET /api/v1/dir/{dirName}/items`, soft-deletes
or permanently deletes each item depending on `--force`, then deletes the
directory with `DELETE /api/v1/dir/{dirName}`. `rm -r Trash` is the exception:
it permanently deletes the listed Trash items and leaves the reserved `Trash`
directory in place.

## copy command

```
monopass cp [-r|--recursive] <source>... <dest>
```

Copy item sources with
`PUT /api/v1/dir/{destDirName}/item/{destItemName}?copy_from={sourceDirName}/{sourceItemName}`.
The command sends an empty create-item JSON body and relies on the API to copy
the source item fields and files. Source version history is not copied.

Without `--recursive`, every source must be an item path in `<dir>/<item>`
form. With `--recursive`, a source may also be a directory path; directory
sources are expanded by listing non-hidden items through
`GET /api/v1/dir/{sourceDirName}/items?count=200...`.

Destination behavior:
- one item source plus `<dir>/<item>` destination copies to that exact item path
- one item source plus `<dir>` destination preserves the source item name
- multiple sources, or any recursive directory source, require a directory
  destination and preserve each source item name

Examples:

```sh
monopass cp Work/Github Personal/Github
monopass cp Work/Github Fun/Steam Personal
monopass cp -r Work Personal
```

No rollback is attempted. If a later copy fails, earlier copies remain applied.

## move command

```
monopass mv [-r|--recursive] <source>... <dest>
```

Move item sources with
`PUT /api/v1/dir/{destDirName}/item/{destItemName}?move_from={sourceDirName}/{sourceItemName}`.
The command sends an empty body. The API changes the item directory/name
without creating a new version.

Path handling is the same as `cp`: non-recursive sources must be item paths;
recursive directory sources are expanded by listing non-hidden items through
the agent; multiple sources or recursive directory sources require a directory
destination and preserve source item names. Recursive move moves the listed
items only and leaves source directories in place.

Examples:

```sh
monopass mv Work/Github Personal/Github
monopass mv Work/Github Fun/Steam Personal
monopass mv -r Work Personal
```

No rollback is attempted. If a later move fails, earlier moves remain applied.

## list command

```
monopass ls [<dir>]
```

Without an argument, list directories with `GET /api/v1/dirs`. With `<dir>`,
list item names with `GET /api/v1/dir/{dirName}/items`. Output is one name per
line.

## list versions command

```
monopass ls-versions <dir>/<item>
```

List item versions with
`GET /api/v1/dir/{dirName}/item/{itemName}/versions` and print each version
and timestamp.

## restore old version command

```
monopass restore <dir>/<item> <version>
```

Restore a retained version with
`PUT /api/v1/dir/{dirName}/item/{itemName}/restore?version={n}` so it becomes
the latest version.

## show item

```
monopass show <dir>/<item> [--reveal] [--format human|json]
```

Show item metadata with `GET /api/v1/dir/{dirName}/item/{itemName}` by default
and `GET /api/v1/dir/{dirName}/item/{itemName}?reveal=true` when `--reveal`
is set. Render fields and file metadata without making separate reference
requests.

The default `--format human` output renders the item response as:

```text
Name: github
Created: 2026-06-07T01:23:45Z
Updated: 2026-06-07T01:24:00Z
Versions: 3
Fields:
  password: ******
Files:
  ssh_key [4.0 KB]
```

Field and file entries are sorted by name. File sizes are rendered with
readable binary units. `--format json` writes the raw JSON response body from
the agent instead of the human-readable projection.

When `--reveal` is set and the request returns `403 access_denied`, retry the
original revealed item request once with the prompted master password bearer
after a successful unlock.

## list contacts

```
monopass ls-contacts
```

List contacts with `GET /api/v1/contacts` and print them.

## add contact

```
monopass add-contact email age_public_key [--name name]
```

Add a contact with `PUT /api/v1/contact/{contactEmail}` using the provided
`age_public_key` and optional `name`. The new contact starts with no
description.

## edit contact

```
monopass edit-contact email [--email new_email] [--name name] [--age-public-key key]
```

Edit a contact with `PATCH /api/v1/contact/{contactEmail}`. Omitted flags keep
the current value. `--email` changes the primary contact address.

## remove contact

```
monopass rm-contact email
```

Remove a contact with `DELETE /api/v1/contact/{contactEmail}`.

## public key command

```
monopass pubkey
```

Print the local age public key. Intended behavior is to query the public key
stored in the internal age public key item and print the key value to stdout
with a trailing newline.

Use `GET /api/v1/dir/_Internal/item/AgePublicKey?raw=true`, extract the string
field named `key`, and print it followed by a newline. `_Internal/AgePublicKey`
is non-hidden and does not require per-request master-password auth, so it can
be read through the public API; `_Internal` remains hidden from directory lists
and system-locked for writes.

## share command

```
monopass share <dir>/<item> <email>
    --out-file
```

Export an item as an age-encrypted ZIP for the contact by fetching the
contact, item, and file contents:

1. Request an agent export job for the requested contact email.
2. Fetch raw item metadata with
   `GET /api/v1/dir/{dirName}/item/{itemName}?raw=true`.
3. For every file entry in the item metadata, stream
   `GET /api/v1/ref/{dirName}/{itemName}/{fileName}` into the ZIP as
   `files/<sha256>`, using the response `ETag` as the plaintext SHA-256 and
   verifying it against the streamed bytes.
4. Write `fields.json` from the item response, replacing each file metadata
   entry with an importable entry containing the file `name` and plaintext
   SHA-256 from the `ETag`.
5. Encrypt the ZIP to the contact's age public key.

Options:

- `-o/--out-file`: Write the encrypted export to the given file, or `-` for
  stdout.

When `--out-file` is omitted, write to
`<contact>_<item>_<date-hms>.export`, where `<contact>` is the contact email,
`<item>` is the item name from `<dir>/<item>`, and `<date-hms>` is the local
timestamp used by the CLI at export time. For example, exporting
`Personal/github` to contact `alice@example.com` writes a file like
`alice@example.com_github_20260612-142533.export`.

## import command

```
monopass import <dir>/<item> <file>
```

Import an encrypted export with
`PUT /api/v1/jobs/import/{dirName}/{itemName}` using the encrypted `.export`
bytes as `application/octet-stream`. The agent uses the hidden local age
private identity to decrypt and validate the archive in a background import
job, then returns `202 Accepted` with a job ID.

After submit, poll `GET /api/v1/jobs/status/{job_id}` until the status is terminal.
Exit successfully only for `succeeded`. For `failed`, print/return the job's
structured error code and message as the command failure. The CLI must not open
the encrypted database directly and must not read the local age private key.

# `pwgenspec` specification

`pwgenspec` is optional. When omitted, generate three words from the EFF large
wordlist, capitalize them, join with hyphens, then append one symbol and one
digit.

Otherwise, provide a string like `20,upper,symbol`, which generates a password
with 20 characters using A-Z and symbols. Supported character types are
`upper`, `lower`, `digit`/`digits`, `alpha` (`upper` + `lower`), `hex`
lowercase, and `symbols`. Generated passwords are held in zeroizing storage
and are only sent to the agent as the concealed `password` field.
