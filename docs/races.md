# Auth Lock, GC, and Lockout Races

This note captures the race windows observed around `POST /api/v1/auth/lock`, the authorization-expiry sweep, and cleanup/unload behavior in `src/agent/state.rs`.

## Observations

1. `AgentState::unlock()` has a reauthorization race in the already-unlocked path.
   - The method clones the DB handle, drops the mutex, awaits `user_setting_duration()`, then reacquires the mutex and inserts the process hash.
   - A concurrent `POST /api/v1/auth/lock` can clear authorizations in the gap, and the unlock call can repopulate them after lock.
   - If the expiry sweep unloads the database in that same gap, the unlock call can still return success after writing authorization metadata against a state that no longer has the live database handle.
   - References: [`src/agent/state.rs`](../src/agent/state.rs) unlock and lock state transitions.

2. Import/export job admission previously had a registration gap.
   - `import_item()` and `export_item()` now register the generated job ID in `active_jobs` before creating the encrypted DB job record.
   - If job-record creation fails, the controller unregisters the job before returning the error.
   - The expiry sweep suppresses cleanup and unload while `active_jobs` is non-empty.
   - References: [`src/agent/controller.rs`](../src/agent/controller.rs) import/export job admission, [`src/agent/state.rs`](../src/agent/state.rs) authorization-expiry unload.

3. Ordinary admitted database requests are now tracked as active work.
   - Middleware authorizes a request, clones `DbHandle`, registers an active database request guard, and passes the handle to the handler.
   - The guard is attached to the response body, so streaming reference downloads remain active until the body is dropped.
   - `/api/v1/auth/lock` only clears authorization metadata; it does not synchronously close the DB.
   - The sweep suppresses cleanup and unload while any active database request guard is alive.
   - References: [`src/agent/auth.rs`](../src/agent/auth.rs) database-route middleware, [`src/agent/state.rs`](../src/agent/state.rs) authorization-expiry unload.

## Summary

The main issue is not a mutex data race inside a single field update. It is a time-of-check/time-of-use gap across:

- authorization reset in `lock()`
- delayed reauthorization in `unlock()`
- active jobs and active database requests
- cleanup/unload running outside the state mutex

The code should revalidate state after any awaited DB access that happens between reading and writing shared authorization state, and active work should be registered before the first awaited DB operation when unload suppression depends on it.
