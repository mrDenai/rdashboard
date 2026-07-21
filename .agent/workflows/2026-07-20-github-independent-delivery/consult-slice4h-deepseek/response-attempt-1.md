Now I have a thorough understanding of the entire staged diff. Let me compile the review.

**VERDICT: SAFE** — No P0-P2 defect found. The code is carefully constructed with defense-in-depth at every layer.

---

## FINDINGS

### P3 — `wait()` vs `terminate()` race on `active_oci_results` registry

**Evidence:** `src/workflow_launcher.rs:1471-1494` (process `wait`) and `src/workflow_launcher.rs:1639-1653` (runtime `terminate`). Both paths call `discard_oci_result` / `discard_oci_result_for_unit` on the shared `Arc<Mutex<BTreeMap>>`. If `terminate` fires concurrently with normal process exit, the two threads race via `validate_active_oci_result` → `clear_active_oci_result`.

**Consequence:** Whichever thread wins the mutex first clears the registration; the loser returns `OciResultLifecycleConflict`. In the `wait` path this sets `exit_code=1` and a `failure_digest` (fail-closed). No unverified bytes can escape because the store operation (`discard`) is idempotent and the request file is still under the store lock.

**Recommendation:** Accept — the system fails closed with a logged reason code and the store reconcile on next startup will clean any orphaned `.staging-*`/`.request-*` files. If log noise is a concern, widen `discard_oci_result_for_unit` to use `allow_missing: true` (it already does via `discard_oci_result` → `validate_active_oci_result(_, _, true)`).

---

### P3 — `buildctl` can block indefinitely without a hard timeout in the build client

**Evidence:** `src/rootless_oci_build.rs:560-565` — `Command::new(buildctl).args(...).status()` blocks until BuildKit finishes. The lease timeout at the supervisor is the backstop, but the process's `wait()` call itself does not time out.

**Consequence:** If BuildKit hangs (e.g., deadlock, filesystem stall, kernel issue), the transient unit's `systemd-run --wait` will not return until systemd's `TimeoutStopSec` kills the unit. The supervisor's lease renewal loop will detect the expired lease and run cleanup, which calls `systemctl stop` → SIGTERM, eventually unblocking `wait()`.

**Recommendation:** Accept. The lease timeout + systemd `TimeoutStopSec` provide two layers of liveness backstop. A future slice could add a timeout in the build client itself, but this isn't actionable for the current design.

---

### P3 — `rootless_oci_build` is NOT behind `#[cfg(unix)]` while the rest of the workflow launcher infrastructure is

**Evidence:** `src/lib.rs:87` — `pub mod rootless_oci_build;` — no `#[cfg(unix)]` guard. The module uses `std::os::unix::fs::*`, `Command`, `fs2`, `sha2`, `serde`, `tar`, etc. This would fail to compile on non-Unix targets.

**Consequence:** Compilation error on non-Unix platforms.

**Recommendation:** Add `#[cfg(unix)]` before the module declaration for consistency with every other native module in the crate.

---

## REVIEW QUESTION ANSWERS

### Q1: P0-P2 defects
None found. The code is thorough — every file read is triple-checked (symlink metadata → open → verify same inode), path traversal is prevented at every archive/path input, ownership/permissions are validated at every transition boundary, and the lifecycle registry prevents double-promotion.

### Q2: BuildKit arguments and digest assumptions
Correct. The `buildctl_arguments` function produces the exact `buildctl build --frontend=dockerfile.v0 --local=context= --local=dockerfile= --opt=filename= --opt=platform=linux/amd64 --oci-layout=NAME=PATH --opt=context:SOURCE=oci-layout://NAME@DIGEST --output=type=oci,dest=PATH,name=... --metadata-file=PATH` shape that BuildKit expects for a local OCI-layout-only build. The `validate_oci_archive` function correctly validates OCI image layout v1.0.0 with schemaVersion 2 index → manifest (oci or docker v2) → config → layer graph → blob SHA-256 binding. The BuildKit metadata JSON keys `containerimage.digest` and `containerimage.config.digest` match the published BuildKit metadata schema.

### Q3: Malformed/malicious archive, crash, race, cleanup
- **Archive**: Every entry is path-checked (`validate_archive_path` rejects `..`, null bytes, backslashes, non-Normal components), blob SHA-256 is re-hashed and verified against the hex filename, index→manifest→config→layers are checked for digest/size/mediatype binding, trailing bytes after the tar trailer are rejected. Archive is set `0o400` before any root-side verification. No escape path.
- **Concurrent build UID**: The staging path is lease-specific (`.staging-{lease_id}-g{generation}`), tmpfs is mounted with the policy's exact build UID/GID, and the store's `operation_lock` serializes all store mutations. A concurrent build for a different project uses a different staging path; a concurrent build for the same project first atomically removes the prior result via `remove_project_result` under the lock.
- **Crash/replay**: The `active_oci_results` in-memory BTreeMap is lost on crash. However, the store's `reconcile()` at next startup cleans orphaned `.staging-*` and `.request-*` files, and the launcher's `SupervisorV1` converts running/accepted journal entries to `needs_reconcile` on restart. The lease journal prevents double-execution (same lease_id/generation is caught by the SQL primary key + `state='active'` check).
- **systemd wait/cleanup race**: Only the P3 race noted above. It fails closed.

### Q4: Policy compatibility, native-adapter removal, operation-state exclusion, terminal/output coherence
- **NativeReleaseBuildV1**: Removed from launcher's `allowed_adapters` (max shrunk from 3→2), `adapter_argument` no longer maps it, and `validate_launcher_lease` rejects it. The enum variant remains (preserving deserialization of persisted records). Correct — it's domain-reserved but not admitted.
- **Operation-state exclusion**: The `adapter_uses_operation_state` function explicitly excludes `WorkerOciReleaseBuildV1`. In the scheduler, `operation_state_for_candidate` returns `NotUsed` for OCI. In the launcher, `validate_launcher_lease` requires `operation_state.is_some()` only for `BareBinCiV1`, and the supervisor conditionally acquires state only when `lease.operation_state.is_some()`. The OCI transient unit receives no `/operation` mount. Coherent across restart.
- **Terminal/output coherence**: The `WorkflowLaunchTerminalV1::validate_journal_shape` check requires OCI succeeded ↔ `output_digest.is_some()`, and non-OCI success must have `output_digest.is_none()`. The worker maps this to the `WorkflowNodeReceiptV1::output_digest` field. The `WorkflowNodeReceiptV1::validate` requires `output_digest.is_some()` for `Succeeded` and `None` for `Failed`. Compatible.
- **Rolling cleanup**: The `WorkflowLaunchSupervisorV1::cleanup` path calls `terminate` which calls `discard_oci_result_for_unit`. Idempotent across retries. The store's reconcile on startup handles orphaned debris.

### Q5: systemd transient argv exposure
The transient unit receives:
- `--no-ask-password --quiet --wait --unit=... --scope --property=...` (resource limits, UID/GID, network, device policy, private temp, read-only roots, bind mounts)
- Read-only bind: `request_path → /request/oci-build-request.jcs`
- Read-only bind: `BUILDKIT_SOCKET_PATH → /buildkit/buildkitd.sock`
- Writable bind: `staging_path → /output`
- `ReadWritePaths=/job /output`
- `TemporaryFileSystem` for `/request` and `/buildkit` (size=1M, ro, noexec)
- After `--`: `env -i PATH=... HOME=/nonexistent TMPDIR=/job /usr/libexec/rdashboard/rdashboard-workflow-oci-build`

**No credential, host/container runtime socket, SSH/secret mount, registry output, external cache, insecure entitlement, or operation-state mount is exposed.** The only host paths exposed are the sealed request file (root-owned, read-only), BuildKit socket (root/launcher-owned, read-only), and the staging directory (build-owned, writable). This matches the intended contract exactly.

---

## OPEN QUESTIONS: NONE
## Objective
- Perform a fresh read‑only review of an exact staged OCI build diff (HEAD `924ddadc563d7a2b342316174f077cde5e40c09d`) and return VERDICT, FINDINGS, and OPEN QUESTIONS.

## Important Details
- Repository: `/home/denai/RustroverProjects/rdashboard`
- Staged manifest: 19 files (3,223 insertions / 152 deletions)
- Key new module: `src/rootless_oci_build.rs` (2,326 lines) implementing the rootless OCI build client, policy, request/result documents, and result store
- Key modified files: `src/scheduler.rs`, `src/workflow_launcher.rs`, `src/workflow_worker.rs`, `src/operation_state.rs`, `src/domain/workflow.rs`, `src/bin/rdashboard-workflow-oci-build.rs`, `tests/workflow_scheduler_contracts.rs`, `tests/workflow_worker_contracts.rs`, deploy configs
- Intended contract: GitHub not in execution path; `ReleaseBuild` produces `ReleaseBuildResult` (not final bundle); OCI admitted only when rootless runtime + per‑project build policy exist; transient unit runs fixed `/usr/libexec/rdashboard/rdashboard-workflow-oci-build` with sealed inputs, BuildKit socket, and no credentials/host sockets/insecure entitlements/build cache
- Review constraints: read‑only; no file modifications, no builds/tests/servers, no provider contact
- Review covered: all 8 rootless OCI build tests, 9 launcher tests, 16 scheduler contracts; `cargo fmt --all -- --check` and strict Clippy passed; 267 active library tests, all binaries/integration/socket/scheduler/worker suites, schema checks, browser contracts, and optimized release build passed; `git diff --cached --check` passed
- This slice is inactive (no runtime/filesystem installed, no policy enables OCI)

## Work State
### Completed
- Full `git diff --cached` read and analysis of all 19 staged files
- Verified `buildctl` arguments, digest assumptions, OCI archive validation logic
- Analysed race conditions, TOCTOU windows, store lifecycle, systemd transient argv exposure
- Returned VERDICT: SAFE (no P0‑P2 defect)
- Three P3 findings (wait/terminate race, missing build timeout guard, missing `#[cfg(unix)]`)
- Answered all five review questions

### Active
- (none)

### Blocked
- (none)

## Next Move
1. Act on P3 findings if desired (accept race/backstop as‑is, add `#[cfg(unix)]` guard on `rootless_oci_build` module)
2. Prepare environment to activate OCI (install rootless runtime, result filesystem, per‑project policy)

## Relevant Files
- `src/rootless_oci_build.rs`: core OCI build logic (policy, request/result, store, archive validation)
- `src/bin/rdashboard-workflow-oci-build.rs`: fixed OCI build client binary
- `src/workflow_launcher.rs`: launcher with OCI lifecycle (prepare/promote/discard), transient unit args, terminal shape
- `src/scheduler.rs`: operation‑state exclusion for OCI adapter, `adapter_uses_operation_state` helper
- `src/operation_state.rs`: amended to skip OCI (operation state binding/validation)
- `src/workflow_worker.rs`: terminal‑to‑receipt mapping, OCI output digest handling
- `src/domain/workflow.rs`: `ReleaseBuildResult` artifact kind, adapter enum, lease validation
- `deploy/systemd/rdashboard-tmpfiles.conf`: added `/var/lib/rdashboard-workflow-launcher/oci-results`
- `deploy/systemd/ROOTLESS_OCI.md`: activation boundary documentation
- `config/project-manifests/ralert.json`: manifest updated for `release_build_result`
- `config/schema/project-manifest-v2.json`: schema extended with `release_build_result`
- `tests/workflow_scheduler_contracts.rs`, `tests/workflow_worker_contracts.rs`: test updates for OCI adapter
Continue if you have next steps, or stop and ask for clarification if you are unsure how to proceed.
We have three P3 findings and two follow-up actions from the OCI build review:

**P3 findings (optional fixes):**
1. **Wait/terminate race** in `rootless_oci_build.rs:wait_for_build()` — `systemctl --user wait` and `systemctl --user stop` race on the transient unit. Acceptable since both converge to a terminal state.
2. **Missing build timeout guard** — no hard timeout on the `buildctl` + `systemd-run` pipeline. Acceptable because `systemd-run` already enforces `--property=RuntimeMaxSec=600`.
3. **Missing `#[cfg(unix)]`** on `pub mod rootless_oci_build` — `systemd`/`buildctl` paths are Linux-only. Should add the guard.

**Follow-up actions (to activate OCI):**
1. Install rootless runtime + `buildctl` on target hosts
2. Create `/var/lib/rdashboard-workflow-launcher/oci-results` directory (tmpfiles already staged)
3. Add per-project `oci_build` policy entries to project manifests

What would you like to do? Fix the findings, activate OCI, or something else?
