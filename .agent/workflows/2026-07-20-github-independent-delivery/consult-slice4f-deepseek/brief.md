GOAL
Decide whether the exact staged Slice 4f product diff is safe and correct to commit as the inactive,
host-local, operation-owned compiled-state boundary for the repository-agnostic workflow worker.

QUESTION
Does the exact staged product diff contain any concrete P0, P1 or P2 correctness, security,
compatibility, scheduler, lease, replay, crash-consistency, cleanup, TOCTOU, filesystem-identity,
resource-accounting, privilege, systemd-confinement or cache-reuse defect? Return SAFE if none exists.
Otherwise cite the exact path/symbol, executable failure scenario, severity and smallest coherent fix.
Keep style-only notes P3 and call out any claim that the implementation or tests do not actually prove.

EXACT REVIEW BOUNDARY
- Review only `git diff --cached -- . ':(exclude).agent/workflows/**'`.
- It must contain exactly 19 paths, 3144 insertions and 55 deletions with binary-diff SHA-256
  `0445f7fa0d718eb7b2bdb076a72347cfc0bad56b02b54aea6a3e1dee76310b53`.
- The paths are Cargo.lock, Cargo.toml, deploy/systemd/README.md,
  deploy/systemd/rdashboard-tmpfiles.conf,
  deploy/systemd/rdashboard-workflow-launcher.service,
  src/bin/rdashboard-workflow-job.rs, src/bin/rdashboard-workflow-launcher.rs,
  src/domain/workflow.rs, src/lib.rs, src/operation_state.rs, src/scheduler.rs,
  src/store/control.rs, src/workflow_launcher.rs, src/workflow_launcher_socket.rs,
  src/workflow_worker.rs, tests/store_and_web.rs,
  tests/workflow_launcher_socket_contracts.rs, tests/workflow_scheduler_contracts.rs and
  tests/workflow_worker_contracts.rs.
- Ignore workflow artifacts and unrelated unstaged notification work. Do not review a broad worktree
  diff. Do not edit files, access secrets or `.env`, run services/jobs, contact providers or mutate
  external state.

INTENDED CONTRACT
- Compiled nodes may receive a canonical optional `WorkflowOperationStateV1` bound to the exact
  project, source, attempt, installed policy, adapter, host, state key and sorted consumer-node set.
  The state has hard byte/inode ceilings and is never a cross-operation or cross-host cache.
- A VPS binding is durable in scheduler schema V4. Once created, all VPS compiled consumers for that
  attempt use the same host/state and are serialized; a retry cannot migrate to an optional accelerator.
  An online i9 may receive only independent one-node state, never blocks the VPS path and transfers no
  compiled state back to the VPS.
- The root launcher exclusively creates, owns, reopens, accounts and removes state under the exact
  `/var/lib/rdashboard-build/operations` mount. The mount must be distinct and have an installed hard
  6-8 GiB/100,000-1,000,000-inode filesystem ceiling; each state is additionally capped at 6 GiB and
  500,000 inodes. `/operation` is the only writable host bind visible to a transient job; `/job` remains
  its private bounded tmpfs.
- Root metadata records are canonical and identity-bound. A singleton root lock serializes admission,
  acquire/release, startup reconciliation and terminal pruning. Reuse requires strict ownership/mode/
  identity validation; cleanup tolerates only the documented root/build-owned data-root transition.
  Physical allocation is counted as `max(logical length, st_blocks * 512)` and all filesystem entries
  count against the inode ceiling.
- First acquire durably records creation before publishing the data directory. Interrupted staging and
  exact unrecorded data directories are recognized only under the validated state root. Final release,
  limit breach, failure, uncertain cleanup and stale inactive partial state all use a persisted
  `data_removal_pending` phase before recursive unlink. Startup finishes either side of an interrupted
  unlink. Terminal-record pruning uses same-directory rename/fsync tombstones and bounded retention.
- Same-lease renewal/replay must not duplicate acquire/release. The launcher stops/observes the exact
  systemd unit before releasing state, journals the release disposition, and treats state lifecycle
  ambiguity as launch/cleanup failure rather than success. Rolling-upgrade cleanup still accepts legacy
  launches with no state.
- The fixed job copies sealed source to stable `/job/workspace` while preserving file and directory
  mtimes, then uses only `/operation/target` and `/operation/ccache` as reusable compiled state. Cargo
  remains offline and source/dependencies remain read-only. A successful process becomes a successful
  workflow receipt only when cleanup reports that state remains reusable; removed/failed/uncertain
  state produces deterministic `operation_state_unusable` failure evidence.
- No state survives terminal failure, cleanup uncertainty, resource overflow or abandonment. No raw
  host-root path, source selection, mount source, cleanup target, UID/GID or command is caller-selected.
  This slice installs nothing and activates no manifest, unit, project or deployment.

ADVERSARIAL CASES TO TRACE
- Crash after record creation but before directory publication; after `data_removal_pending` persistence
  but before/during/after unlink; and after terminal-record rename but before tombstone deletion.
- Symlink, rename, mount replacement, ownership/mode mutation, hard-link/block accounting and exact-limit
  behavior during validate, scan, create, acquire, release, reconcile and prune.
- A renewed lease replayed across worker or launcher restart; two consumers racing; process success
  followed by cleanup failure; timeout/abandonment before the next admission; and schema upgrade from V3.
- Accelerator appearance/disappearance around a persisted VPS binding, claim expiry/retry, and whether
  serialization can deadlock or leave a valid consumer permanently unclaimable.
- Whether launcher capabilities and systemd writable paths are sufficient for intended creation/chown/
  cleanup but expose a broader write or traversal authority than documented.
- Whether preserving source mtimes at a stable path is enough for valid Cargo target reuse without
  allowing stale output to authorize a result for changed source/policy/input identity.

VERIFICATION
- Base HEAD: `ef952c9355bd083ddd98f725a78d52bb227517d4`.
- `git diff --cached --check` passed.
- A fresh `git checkout-index` export of this exact staged product/config/test state passed bare
  `bin/ci` with formatting, Clippy warnings denied, all Rust unit/binary/integration/socket/scheduler/
  worker suites, both schema checks, 8 browser contracts and the optimized release build. The final
  release profile completed in 3 minutes 24 seconds.
- Focused tests cover reuse, terminal cleanup, failure/reset/limit removal, stale partial-state cleanup,
  interrupted removal and tombstone recovery; launcher replay/acquire/release counts; preserved source
  timestamps; process-success plus unusable-state failure; VPS binding expiry/no migration; schema V4;
  worker/launcher socket contracts and installed unit configuration.
- A prior sandboxed full test run compiled successfully and its only failures were existing temporary
  Unix-socket binds denied by the sandbox. The unchanged exact staged export then passed the required
  gate with local Unix-socket creation allowed.
- No dedicated filesystem was created, no unit/job was installed or started, no repository code was
  executed by the new launcher, no VPS/i9/provider/GitHub state changed, and no push/deploy occurred.

INSPECT FIRST
- `git diff --cached -- src/operation_state.rs`
- `git diff --cached -- src/domain/workflow.rs src/scheduler.rs src/store/control.rs`
- `git diff --cached -- src/workflow_launcher.rs src/workflow_launcher_socket.rs`
- `git diff --cached -- src/workflow_worker.rs src/bin/rdashboard-workflow-job.rs`
- `git diff --cached -- deploy/systemd/rdashboard-workflow-launcher.service`
- `git diff --cached -- tests/workflow_scheduler_contracts.rs tests/workflow_worker_contracts.rs`
- Existing scheduler, lease, launcher, preparation, journal and systemd code may be read only as needed
  to trace the exact staged interactions.
