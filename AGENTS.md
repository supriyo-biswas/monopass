# monopass Agent Guide

## Scope

`monopass` is a Rust password manager backed by an encrypted SQLCipher database.
The CLI starts in `src/main.rs`, command implementations live under
`src/commands/`, database setup helpers live in `src/db.rs`, shared secret
wrappers live in `src/secret.rs`, and the long-running Unix-socket agent lives
under `src/agent/`.

Prefer routing password-manager operations through the agent. Do not open the
encrypted database independently from ordinary client commands. Keep SQLCipher
access at the agent state/worker boundary; do not add decrypted copies or
blocking database work directly in Tokio request handlers.

## Code Organization

- Keep `src/commands/mod.rs` limited to CLI wiring. Put command behavior in
  focused modules such as `item.rs`, `read.rs`, `run.rs`, `share.rs`, or
  subdirectories such as `init/`.
- Keep client transport behavior in `src/commands/client.rs`. It owns Unix
  socket HTTP framing, unlock retry behavior, bearer password headers, response
  parsing, and zeroizing request/response buffers.
- Keep command API models in `src/commands/models.rs`. Secret-bearing field
  data uses `crate::secret::SecretString`.
- When modifying agent API routes, request/response models, or behavior, update
  `docs/api-spec.md`. When modifying CLI commands, flags, arguments, or command
  behavior, update `docs/cli-spec.md`.
- Keep agent behavior split by responsibility:
  - `server.rs`: routes and middleware
  - `auth.rs`: Unix peer credentials and request authorization
  - `process.rs`: process-lineage validation and authorization scope keys
  - `controller.rs`: HTTP handlers, body streaming, bearer parsing
  - `state.rs`: unlocked database state, workers, verifier, cache, file crypto,
    and authorization-expiry unload
  - `error.rs`: API error shapes
  - `models.rs`: request and response bodies
- Do not add tests that only verify CLI parser help text or argument parsing.
  Test behavior behind parsed arguments.

## Client And Agent Flow

Client commands talk to the agent over the local Unix socket. On `403
access_denied`, the shared client prompts for the master password, calls
`POST /api/v1/auth/unlock`, and then retries the original request. Commands that
need secret reads use `AuthMode::IncludePassword`; process-only routes use
`AuthMode::ProcessOnly`.

The shared client keeps JSON request bodies, file upload bodies, response bodies,
raw HTTP responses, and bearer request headers in `Zeroizing` buffers. Avoid
bypassing `Client` or reimplementing socket requests in individual commands.

The agent handles peer credentials and process-lineage authorization before route
handlers run. Controllers should validate request shape, stream bodies, and
delegate work to `AgentState`/`DbHandle`. Database reads and writes are executed
by state workers; handlers must not perform blocking SQLCipher work.

File upload and download plaintext crosses the agent/worker boundary as
`Zeroizing<Vec<u8>>`. `ReferenceBody` also uses zeroizing byte buffers for both
inline bytes and streamed decrypted chunks. Keep that property when adding new
file or reference flows.

## Agent Security Invariants

Fail closed. Deny requests when peer credentials are missing, peer PID is
unavailable, required same-user process identity cannot be resolved, or the
cached process-lineage authorization is absent or expired. Lineage traversal
continues across process session boundaries and stops successfully before a
different-user ancestor. On macOS, traversal may skip exactly one verified
root-owned `/usr/bin/login` boundary and resume from its same-user terminal host;
incomplete or inconsistent boundary evidence must preserve the narrower lineage.

Authorization must stay local to the Unix socket. Do not add network listeners,
bearer-only fallbacks, or route exceptions that bypass peer credential and
process-lineage checks.

Startup hardening must happen before binding the socket. Core dumps are disabled
with `setrlimit(RLIMIT_CORE, 0)`. Release builds also deny debugger attachment
on macOS and mark the process non-dumpable on Linux.

Do not reveal locked-vs-unauthorized state from auth-required endpoints. Except
for first unlock database open or SQLCipher validation failures, use the same
`403 access_denied` shape for missing credentials, malformed bearer headers,
invalid passwords, locked databases, expired authorization, and process
validation failures.

## Unlock And Idle Behavior

Unlock is two-stage:

1. The client connects over the Unix socket with matching UID/GID and a peer
   PID.
2. The agent validates the process lineage, then
   `POST /api/v1/auth/unlock` verifies the bearer password.

On first unlock, open and validate the SQLCipher database, store the handle,
create the in-memory PBKDF2-HMAC-SHA256 verifier, and cache the validated
process-lineage scope hash for 15 minutes. Later unlocks against an
already-unlocked database verify against the in-memory verifier and authorize
the new scope hash without replacing the database handle.

Database-backed routes and `GET /api/v1/auth/status` require both an unlocked
database and an unexpired process-lineage cache entry. Successful status responses
include `reauthTimestamp`, the RFC3339 UTC expiry timestamp for the current
process-lineage authorization.

Idle unload is the inverse of unlock. After 1 hour without successful
database-backed route access, unload the database handle, password verifier,
authorization cache, and last-access timestamp. `GET /api/v1/auth/status` must
not refresh the idle timer or extend authorization.

## Sensitive Material

Use `zeroize` for owned sensitive data: passwords, decoded bearer tokens,
derived keys, decrypted field values, TOTP URLs and seeds, secret-bearing JSON
bodies, decrypted file chunks, plaintext export ZIPs, and secret-bearing file
contents.

Prefer `zeroize::Zeroizing<T>` for scoped buffers and strings. Build or decode
secrets directly into zeroizing containers when practical. Avoid unnecessary
`to_string()`, `to_vec()`, and `clone()` calls; when an owned copy is unavoidable,
make the destination zeroizing too.

Use `crate::secret::SecretString` for model fields that can hold password
manager secrets. It serializes as a normal JSON string, zeroizes on drop, and
redacts `Debug`. Do not replace it with plain `String` in `CreateField`,
`UpdateFieldSet`, `Field`, or new secret-bearing model types.

Be careful with `Debug` derives. `Zeroizing<T>` does not redact its inner value
by itself, so any struct containing zeroizing secret buffers needs a manual
redacted `Debug` implementation or no `Debug` implementation.

Never log sensitive material, including request bodies, response bodies,
authorization headers, decrypted fields, TOTP URLs, file contents, or export
payloads. Avoid adding `tracing`/`println!`/`dbg!` output around secret-bearing
types.

Treat JSON serialization as a plaintext-copy boundary. If a JSON body can
contain secrets, serialize it into `Zeroizing<Vec<u8>>` and keep intermediate
structured values secret-aware. Prefer typed structs with `SecretString` fields
over `serde_json::Value` when the value can contain secrets.

Treat command integration points as intentional exposure boundaries. `read` may
write secrets to stdout or a user-selected file. `run` intentionally passes
resolved values to a child process environment or temporary files. Keep parent
process copies zeroizing, use private file modes for temporary files, and
document any new boundary that deliberately exposes plaintext outside monopass.

Zeroization is only one layer. It shortens the lifetime of secrets in ordinary
process memory, but it does not defend against a live compromised process,
arbitrary memory reads while a secret is in use, lower-level library copies,
kernel buffers, swap, hibernation, or crash dumps.
