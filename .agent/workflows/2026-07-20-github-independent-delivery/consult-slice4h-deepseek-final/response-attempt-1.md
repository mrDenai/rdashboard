Now let me check the `BUILDCTL_EXECUTABLE` import path and verify the file permission scheme end-to-end:
## VERDICT: UNSAFE

### FINDINGS

**P0 — Build client cannot read its own signed request file**

`src/rootless_oci_build.rs:554` — `execute_rootless_oci_build` calls `read_stable_file(request_path, 0, 0o400, MAX_REQUEST_BYTES)` to read the bind-mounted request. The request file is written by the root launcher at `prepare()` with mode `0o400`, owner `root:root`. Inside the transient unit the client runs as `build_uid` (non-root, empty capability set — `CapabilityBoundingSet=` / `AmbientCapabilities=` at `workflow_launcher.rs:2315-2316`). A non-root process cannot `open()` a root-owned `0o400` regular file — `File::open` at line 1551 returns `EACCES`.

Every OCI build attempt in production fails at this step. The unit exits non-zero, the launcher sees failure, discards the staging, and the scheduler retries forever.

**Fix**: Change the request file mode to `0o444` (world-readable) at the write site (`write_new_trusted_read_only_file` → `write_new_read_only_file` → `set_permissions`). The file sits inside a root-owned `0o700` store directory; the unit's private mount namespace already isolates the bind-mount path. Update the corresponding mode assertion in `read_stable_file` (`0o400` → `0o444`) and in `validate_owned_regular_file` for the request path. No other `0o400` output file needs changing — archive/result/request copies inside staging are owned by `build_uid` and readable by the owner.

---

**P3 — P3 disposition #1 (concurrent wait/terminate cleanup race) is sound**

The store's `operation_lock` (Mutex) serializes promote/discard. The `active_oci_results` BTreeMap (Mutex) ensures only one lifecycle owner per unit. If terminate wins the race, `promote_oci_result` sees the cleared active entry and returns `OciResultLifecycleConflict` → wait sets `exit_code=1` + `failure_digest`. Promote winning removes the entry first; terminate's `discard_oci_result_for_unit` finds `None` and no-ops. Fails closed.

**P3 — P3 disposition #2 (unit liveness boundary) is sound**

`RuntimeMaxSec`, `TimeoutStopSec` and `KillMode=control-group` bound the unit externally. Adding a second build-client timer would duplicate that authority and would not recover from a kernel/filesystem stall that blocks the unit's own cgroup kill.

**P3 — P3 disposition #3 (Unix guard) is correctly applied**

`#[cfg(unix)]` on `pub mod rootless_oci_build;` in `src/lib.rs:82` gates the entire module. No remaining unguarded Unix import.

---

### Review questions answered

**Q1 (P0-P3 defects):** See P0 above. No other P0-P2 found.

**Q3 (malformed/malicious output, build UID, concurrent cleanup, crash/replay, escape/strand/failure-into-success):**
- Build UID cannot create symlinks or hardlinks; `make_tree_trusted_private` and `validate_rootless_oci_build_output` verify `nlink()==1`, `is_file()`, correct owner, and exactly 3 expected files.
- Store's `operation_lock` (Mutex) serializes promote/discard. Concurrent terminate+wait is closed as described above.
- Host crash leaves staging/request debris; startup `reconcile()` removes `.staging-*`, `.request-*`, `.deleting-*` entries. Uncommitted output is lost but build is retried by the scheduler.
- Terminal shape validation (`workflow_launcher.rs:455-460`) enforces: OCI success *requires* `output_digest.is_some()`, failure *requires* `output_digest.is_none()`. The worker at `workflow_worker.rs:1133-1136` fails if a succeeded OCI terminal lacks `output_digest`. Process exit alone can never be success.
- Cleanup always discards OCI staging. Rollback (discard + cleanup + restart) correctly clears state for retry.

**Q4 (BuildKit argv/metadata, archive validation, output typing, operation-state exclusion, rolling cleanup):**
- `buildctl_arguments` uses only `dockerfile.v0`, `--local=context`, `--local=dockerfile`, `--oci-layout` for bases, no `--allow`, `--secret`, `--ssh`, `registry`, or `cache-to`. Verified by test assertion.
- Archive validation: tar path/bounds/type, `oci-layout` + `index.json` schema, per-blob SHA-256 content verification against `blobs/sha256/<hex>` path, descriptor `digest→size` binding, index→manifest→config/layer graph traversal, trailing-zero-byte checks.
- Output typing: `ReleaseBuildResult` (not `ReleaseBundle`), wire-compatible. The worker commits the OCI `result_digest` as the node output. Native release enum not admitted.
- Scheduler `adapter_uses_operation_state()` excludes `WorkerOciReleaseBuildV1`. OCI builds allocate no compiled state. Tests confirm parallel verification+OCI without duplication.
- `reconcile()` removes bounded debris; `promote()` atomically replaces one result per project via rename-through-deleting.

**Q5 (transient-unit path/network/authority exposure):**
- `InaccessiblePaths=/run` — the BuildKit socket is bind-mounted to `/buildkit/buildkitd.sock`, independent of `/run`.
- `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX` — no host network, only Unix sockets.
- `ProtectSystem=strict`, `CapabilityBoundingSet=` (empty) — zero capabilities.
- Bind mounts: only `/prepared`, `/dependencies`, the request file, the BuildKit socket, and the staging `/output`. No credential, host socket, registry, or cache output. Matches the contract.

---

### OPEN QUESTIONS: NONE

The P0 request-file permission defect must be resolved before any OCI build can succeed in production. The remaining P3 dispositions are correct under the reviewed implementation.
