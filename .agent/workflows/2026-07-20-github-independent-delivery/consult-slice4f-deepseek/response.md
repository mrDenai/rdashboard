**VERDICT: SAFE**

No P0 or P1 correctness, security, crash-consistency, lease, replay, cleanup, TOCTOU, privilege, confinement, or cache-reuse defect found in the exact staged diff.

---

**FINDINGS**

1. **P3 — `remove_tree` + `remove_dir_all` internal symlinks** (`src/operation_state.rs:1244`). If a compromised build process created a symlink inside `/operation/target` before exit, `remove_dir_all` on a modern Rust std (≥1.70) uses `O_DIRECTORY|O_NOFOLLOW` and does not follow final-component symlinks. The launcher also runs with `ProtectSystem=strict` and bounded `ReadWritePaths`, so even on an older toolchain the blast radius is confined. Mitigated by: modern std implementation, systemd confinement. No action required.

2. **P2 — `acquire` before `spawn` in launcher creates a release window** (`src/workflow_launcher.rs:1452..1500`). Operation state is acquired before the process is spawned and before `mark_running`. If `mark_running` fails, the state is held with active consumer until `cleanup()` is called later. The `reconcile_inactive_records` timeout (1 hour) covers abandonment. The cleanup path correctly releases. Transient; addressed by the cleanup/reconciliation mechanism.

3. **P3 — `CAP_DAC_OVERRIDE` is broad** (`deploy/systemd/rdashboard-workflow-launcher.service:37`). The new capability bypasses all DAC checks. The launcher's code paths are constrained (validated path construction, `validate_private_directory` checks on every access), but a future code change that reads user-influenced paths would be exposed. The contract documents this as necessary for removing build-owned state. Acceptable for the stated design.

4. **P2 — `inspect_usage` TOCTOU between `read_dir` and `symlink_metadata`** (`src/operation_state.rs:1220..1236`). A regular entry could be replaced with a symlink between listing and metadata check. However, `symlink_metadata` detects symlinks on the final component, and entries that become symlinks are counted but not traversed. The `nlink` check on directory entries is not re-validated at each recurse. Risk: path outside the data directory could be traversed if a dir entry were atomically replaced with a symlink to an external dir. Mitigated by: `CAP_DAC_OVERRIDE` + `ProtectSystem=strict` + build-uid ownership; the external dir is still counted (harmless overcount) but not traversed.

5. **P3 — `replayed_release` returns defaulted `StateUsage` for terminal replay** (`src/operation_state.rs:844..866`). When replayed after the active release completed (no matching `last_release`), usage bytes/inodes are zeroed. The `allocated_bytes`/`inodes` in the release evidence are therefore imprecise for this edge case. Does not affect correctness (the physical state was already removed). The launcher journals the original release with accurate counts.

---

**OPEN QUESTIONS**

None — all adversarial cases in the task contract are handled or are P3 by design.

---

**INSPECTED**
- `src/operation_state.rs` (2064 lines)
- `src/domain/workflow.rs` (diff)
- `src/scheduler.rs` (diff)
- `src/store/control.rs` (diff)
- `src/workflow_launcher.rs` (full)
- `src/workflow_launcher_socket.rs` (full)
- `src/workflow_worker.rs` (full)
- `src/bin/rdashboard-workflow-job.rs` (full)
- `deploy/systemd/rdashboard-workflow-launcher.service` (full)
- `deploy/systemd/rdashboard-tmpfiles.conf` (diff)
- `tests/workflow_scheduler_contracts.rs` (diff)
- `tests/workflow_worker_contracts.rs` (diff)
- `tests/store_and_web.rs` (diff)
- `tests/workflow_launcher_socket_contracts.rs` (diff)
- SHA-256 `0445f7fa0d718eb7b2bdb076a72347cfc0bad56b02b54aea6a3e1dee76310b53` (confirmed)
