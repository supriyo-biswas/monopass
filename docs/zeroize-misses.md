# Zeroize Audit Notes

This document records the remaining plaintext-copy points I found while reviewing the client and agent code. It is not a full security review; it focuses only on places where sensitive material is handled in ordinary `String`/`Vec` buffers or crosses a boundary without zeroization.

## Misses

1. Item field JSON is handled as plain `String` values inside the agent database layer.
   - [src/agent/state.rs](/home/supriyo/Developer/monopass/src/agent/state.rs#L3711)
   - [src/agent/state.rs](/home/supriyo/Developer/monopass/src/agent/state.rs#L3753)
   - [src/agent/state.rs](/home/supriyo/Developer/monopass/src/agent/state.rs#L3773)
   - [src/agent/state.rs](/home/supriyo/Developer/monopass/src/agent/state.rs#L4033)
   - Secret-bearing field data is modeled with `SecretString`, but the serialized `fields` JSON blob itself is copied into plain `String` locals before being parsed or written back to SQLite. That means plaintext secret values, TOTP URLs, and internal key fields exist outside a zeroizing wrapper during normal DB reads and writes.

2. Export builds the plaintext archive in a normal `Vec<u8>` before wrapping it in `Zeroizing`.
   - [src/agent/export.rs](/home/supriyo/Developer/monopass/src/agent/export.rs#L117)
   - [src/agent/export.rs](/home/supriyo/Developer/monopass/src/agent/export.rs#L170)
   - The ZIP contains revealed field values and decrypted file bytes. The final encrypted output is zeroized, but the archive buffer is not zeroized while it is being constructed.

3. File encryption key material has intermediate non-zeroizing copies.
   - [src/db.rs](/home/supriyo/Developer/monopass/src/db.rs#L174)
   - [src/agent/state.rs](/home/supriyo/Developer/monopass/src/agent/state.rs#L4106)
   - `key_hex` and the decoded `Vec<u8>` used by `decode_file_key` are plaintext copies of the file-encryption key material. They should be wrapped in `Zeroizing` or explicitly cleared after use.

4. Non-TTY master-password input leaves an unzeroized original `String`.
   - [src/db.rs](/home/supriyo/Developer/monopass/src/db.rs#L330)
   - [src/db.rs](/home/supriyo/Developer/monopass/src/db.rs#L333)
   - The trimmed copy is wrapped in `Zeroizing`, but the original buffer still contains the password plus newline until it is dropped.

5. TOTP parsing introduces plaintext seed copies.
   - [src/agent/state.rs](/home/supriyo/Developer/monopass/src/agent/state.rs#L4669)
   - [src/agent/state.rs](/home/supriyo/Developer/monopass/src/agent/state.rs#L4712)
   - `Url::parse(data)` owns the full otpauth URL, and `to_ascii_uppercase()` creates another ordinary `String` containing the base32 secret. This is harder to avoid completely, but it is still a sensitive plaintext-copy point.

6. `run` can leak bytes if a reference is not valid UTF-8.
   - [src/commands/run.rs](/home/supriyo/Developer/monopass/src/commands/run.rs#L68)
   - On success the decoded value is wrapped in `Zeroizing`, but on failure the `FromUtf8Error` owns the original `Vec<u8>` and that buffer is not zeroized before returning an error.

## Handled Well

1. Client request/response buffers are generally zeroized.
   - [src/commands/client.rs](/home/supriyo/Developer/monopass/src/commands/client.rs#L136)
   - [src/commands/client.rs](/home/supriyo/Developer/monopass/src/commands/client.rs#L178)
   - [src/commands/client.rs](/home/supriyo/Developer/monopass/src/commands/client.rs#L232)
   - [src/commands/client.rs](/home/supriyo/Developer/monopass/src/commands/client.rs#L252)
   - JSON request bodies, binary upload bodies, raw HTTP responses, and bearer request strings all use `Zeroizing`.

2. Agent file upload and reference streaming preserve zeroizing buffers across the worker boundary.
   - [src/agent/controller.rs](/home/supriyo/Developer/monopass/src/agent/controller.rs#L279)
   - [src/agent/controller.rs](/home/supriyo/Developer/monopass/src/agent/controller.rs#L738)
   - [src/agent/import.rs](/home/supriyo/Developer/monopass/src/agent/import.rs#L154)
   - [src/agent/import.rs](/home/supriyo/Developer/monopass/src/agent/import.rs#L196)
   - Uploaded file chunks, decrypted export bytes, and streamed reference chunks are all kept in `Zeroizing<Vec<u8>>` until the deliberate exposure boundary.

3. Secret-bearing model fields are consistently typed as `SecretString`.
   - [src/commands/models.rs](/home/supriyo/Developer/monopass/src/commands/models.rs)
   - [src/agent/models.rs](/home/supriyo/Developer/monopass/src/agent/models.rs)
   - `SecretString` redacts `Debug` and zeroizes on drop, which is the right baseline for field data.

4. Intentional exposure boundaries are explicit.
   - [src/commands/item.rs](/home/supriyo/Developer/monopass/src/commands/item.rs#L165)
   - [src/commands/run.rs](/home/supriyo/Developer/monopass/src/commands/run.rs#L55)
   - [src/agent/controller.rs](/home/supriyo/Developer/monopass/src/agent/controller.rs#L737)
   - Output to stdout, child-process environment variables, user-selected files, and HTTP response bodies are deliberate plaintext exits from the process. The parent-side buffers are still mostly zeroizing.

