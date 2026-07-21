Hash matches. Now let me read the core files for review.
Now let me verify some specific rust version and behavior details:
Let me now read the acquire function from the full operation_state code:
Let me verify the `remove_dir_all` safety in Rust 1.96:
**VERDICT: SAFE**

**FINDINGS**

| # | Severity | Symbol / Path | Evidence | Consequence | Recommendation | Confidence |
|---|----------|---------------|----------|-------------|----------------|------------|
| 1 | — | — | No P0/P1/P2 defect found in the 19-path, 3256-insertion diff. | — | — | High |
| 2 | P3 | `src/operation_state.rs` — `replayed_release` at `StateUsage::default()` | When `last_release` doesn't match the lease and the consumer is in `successful_consumers`, usage defaults to zero (line ~1200-1220 of generated code). | Evidence receipt loses historical byte/inode counts. Does not affect safety, replay, or cleanup. | Pass the cached usage from the successful-consumer path. | High |

**INSPECTED**
- Full staged diff: `src/operation_state.rs` (2176 lines), `src/domain/workflow.rs`, `src/scheduler.rs`, `src/store/control.rs`, `src/workflow_launcher.rs`, `src/workflow_launcher_socket.rs`, `src/workflow_worker.rs`, `src/bin/rdashboard-workflow-job.rs`, `src/bin/rdashboard-workflow-launcher.rs`, `deploy/systemd/*`, `tests/*`, `Cargo.toml`, `Cargo.lock`, `src/lib.rs`
- Hash verified: `7211b2140585ff30ef8034bab2958d3430a3849861988dbf5fd1d0d8a662ace3`
- Rust 1.96's `fs::remove_dir_all` is safe (uses `O_NOFOLLOW` since 1.68).
- `inspect_usage`/`open_accounted_entry` correctly pins each entry with `O_PATH|O_NOFOLLOW`, verifies identity after `"."` open — replaced paths cannot redirect traversal off the original inode.
- All acquire-before-spawn error paths eventually release state through `cleanup` → `begin_cleanup` (transitions accepted/running/reconcile to `CleanupPending`) → `operation_states.release`. The `spawn_waiter` failure path and `mark_running` failure path both journal their state and are resolved on retry/restart.
- `validate_launcher_lease` (line 1594) correctly requires `operation_state.is_some()`; `validate_launcher_cleanup_lease` does not — correct for rolling upgrades.
- Capability use (`CAP_CHOWN`, `CAP_DAC_OVERRIDE`) is scoped by `ReadWritePaths` and code logic; no caller-controlled paths reach `chown` or DAC-bypass operations.
- `InaccessiblePaths` format correctly uses `-` prefix per path, and `BindPaths` for `/operation` overrides correctly.
- Scheduler VPS binding properly serializes consumers on the same host, prevents migration to accelerator, and assigns independent single-node state to `BuildCompute`.
- Replayed release (`replayed_release`) correctly distinguishes matching `last_release`, terminal state, and successful consumers — `default()` usage loses evidence fidelity only.
- Nine operation-state tests pass including the path-replacement adversarial test for `inspect_usage`.

**OPEN QUESTIONS**
- None within the review boundary.
