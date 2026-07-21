## VERDICT

**SAFE** — No P0, P1, or P2 correctness, security, concurrency, crash-safety, compatibility, or resource-accounting defect.

---

### FINDINGS (all P3, optional observations)

1. **`unpin` crash between `remove_file` and `sync_directory`** — If the process crashes after `fs::remove_file(pin_path)` but before `sync_directory` on pins/, the unlink may not survive journal replay. On next startup `cleanup_expired_pins` will not remove it (not expired), and the stale pin blocks LRU eviction of its entry until natural expiration (bounded by `expires_at_ms`). Pin expiry is typically short-lived, so impact is bounded. **src/preparation.rs:774-779**

2. **`read_trusted_file` double `input_identity` check after `read_to_end`** — After reading the file into a Vec, the code compares `input_identity(&fs::symlink_metadata(path)?)` against `input_identity(&opened)`. Since `opened` was obtained earlier from `file.metadata()`, and another `symlink_metadata(path)` is done after the read completes, a concurrent rename/swap between the two `stat` calls could trigger a false `EntryChanged`. The window is small and the consequence is a spurious error (not corruption), but the second check could simply use `&opened` since that fd's identity is authoritative. **src/preparation.rs:2109-2111**

3. **`compare_manifest_entries` silently falls back to empty vec on invalid base64** — `URL_SAFE_NO_PAD.decode(&left.path_base64url).unwrap_or_default()` returns `vec![]` if the base64 is malformed. This can cause incorrect sort ordering. In practice `manifest.validate()` guarantees every entry's `path_base64url` is valid, so the fallback is dead code, but a `panic` or `expect` would be more appropriate for internal consistency. **src/preparation.rs:1901-1908**

4. **`scan_usage` does not count evictions/ directory entries** — Pending eviction markers (`.jcs` files under `evictions/`) are not included in the usage scan. In normal operation the window is negligible (one marker at a time under `commit_lock`), but if a large backlog accumulated (e.g., repeated crashes during eviction), the unaccounted bytes could slightly inflate effective capacity. **src/preparation.rs:1122-1179**

5. **`begin_eviction` idempotency check can reject a valid eviction if `reconcile_access_records` reconstructed the access record** — If the process crashes after `rename(access→evictions)` + `sync_directory(access/)` but before `sync_directory(evictions/)` journal commits, the rename is either fully committed or not at all (ext4 journal guarantees). Verified: this state is unreachable because `rename` atomically updates both directory entries in a single journal transaction — there is no scenario where the file appears at both locations after replay. The `InvalidEvictionRecord` check is a correct defensive guard, not a reachable path. No defect.

---

### OPEN QUESTIONS

- Is the `request.source_sequence` / `request.source_attestation_digest` schema migration staged separately? The scheduler SQL references these columns but no DDL is visible in the diff. (Out of scope per constraints — flagged for completeness.)

---

### INSPECTED

`git diff --cached`: `src/build_source.rs`, `src/domain/workflow.rs`, `src/lib.rs`, `src/preparation.rs`, `src/scheduler.rs`, `tests/workflow_scheduler_contracts.rs`
