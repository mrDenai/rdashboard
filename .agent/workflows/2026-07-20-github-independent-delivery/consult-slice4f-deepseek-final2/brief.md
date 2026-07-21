GOAL
Decide whether the final exact staged Slice 4f product diff is safe and correct to commit as the
inactive, host-local, operation-owned compiled-state boundary for the repository-agnostic worker.

QUESTION
Does the exact staged product diff contain any concrete P0, P1 or P2 correctness, security,
compatibility, scheduler, lease, replay, crash-consistency, cleanup, TOCTOU, filesystem-identity,
resource-accounting, file-descriptor, stack-depth, privilege, systemd-confinement or cache-reuse
defect? Return SAFE if none exists. Otherwise cite the exact path/symbol, executable failure scenario,
severity and smallest coherent fix. Keep style/evidence-fidelity-only notes P3.

EXACT REVIEW BOUNDARY
- Review only `git diff --cached -- . ':(exclude).agent/workflows/**'`.
- It must contain exactly 19 paths, 3291 insertions and 55 deletions with binary-diff SHA-256
  `9d424f47108c30e47ed4765c7a2d9736b83d65d4d6092ffa4e9847a267b3ad43`.
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
- Compiled leases carry canonical operation state bound to exact attempt/project/source/policy/
  preparation/adapter host identity, sorted consumers and byte/inode limits. State never crosses an
  operation or host.
- The scheduler persists one VPS binding in schema V4. VPS compiled consumers execute serially on the
  same state and cannot migrate to i9 after expiry/retry. Optional i9 receives independent one-node
  state, transfers nothing and never blocks the complete VPS path.
- The root launcher is the only state lifecycle owner. It requires an exact dedicated 6-8 GiB,
  100,000-1,000,000-inode mount at `/var/lib/rdashboard-build/operations`; each state is additionally
  capped at 6 GiB/500,000 inodes. Jobs see only exact state as `/operation`; `/job` is private tmpfs and
  source/dependencies stay read-only.
- Root canonical records make create/acquire/release/removal replayable. Success retains data only until
  all declared consumers complete; failure, uncertainty, over-limit state and stale abandoned partial
  state remove data. Two-phase `data_removal_pending`, root fsyncs and deletion tombstones recover
  crashes before/during/after unlink. Record count is bounded and terminal records are pruned oldest
  first.
- Reuse validation requires exact ownership/mode/identity. Cleanup tolerates only expected root/build
  ownership of the fixed data entry. Usage counts `max(logical size, st_blocks*512)` and every entry.
  The scanner opens the root with `O_DIRECTORY|O_NOFOLLOW`, pins every child with
  `O_PATH|O_NOFOLLOW`, opens directory `.` from that pinned inode, verifies identity and iterates only
  fd-relative paths. Rename/symlink replacement cannot redirect it outside state.
- Directory scanning is depth-first rather than retaining every sibling fd. An explicit 64-level
  maximum bounds recursion and at most two descriptors per level, leaving margin below the installed
  launcher `LimitNOFILE=256`. Excessive depth fails as `StateLimitExceeded`, routes through terminal
  cleanup and cannot publish a successful receipt. Wide sibling sets are processed one at a time.
- The launcher durably accepts before state acquisition, then starts a fixed transient systemd unit.
  Any later failure is terminal/reconcile evidence; cleanup stops/contains the unit before state release.
  It deliberately does not release early when stop certainty is absent. Restart cleanup debt and the
  one-hour stale partial-state fence prevent ambiguous reuse or permanent multi-GiB retention.
- Same-execution lease renewal updates authorization without spawning or acquiring twice. Cleanup and
  release replay exactly. Legacy no-state launches remain cleanup-compatible during rolling upgrade.
- The fixed job copies sealed source to stable `/job/workspace` while preserving file/directory mtimes;
  Cargo target and ccache alone live in `/operation`. Cargo remains offline. Process success becomes a
  successful receipt only if operation cleanup reports reusable state; otherwise it emits deterministic
  `operation_state_unusable` failure evidence.
- No raw state path, mount, identity, command or cleanup target is caller-selected. This slice installs,
  starts and deploys nothing.

SUPERSEDED REVIEWS AND REQUIRED RECHECK
- The initial review of hash
  `0445f7fa0d718eb7b2bdb076a72347cfc0bad56b02b54aea6a3e1dee76310b53` identified a theoretical
  path-based usage-walk race and an intentional acquire-before-spawn interval. It is superseded.
- Hash `7211b2140585ff30ef8034bab2958d3430a3849861988dbf5fd1d0d8a662ace3` fixed the path race with
  fd-relative traversal and received SAFE with no P0-P2. Subsequent self-review invalidated it as the
  acceptance review: the pending-directory `Vec<OwnedFd>` could retain one fd for every wide sibling
  and eventually collide with `LimitNOFILE=256`.
- The final diff replaces that stack with immediate recursive depth-first traversal and a 64-level
  bound. Inspect descriptor lifetime carefully: include the pinned directory fd, `Dir::read_from`
  duplicate, child O_PATH fd and child traversal fd at the deepest point, plus fixed launcher fds. Check
  whether wide or deep adversarial trees can still exhaust descriptors, overflow stack, escape state,
  skip accounting or leave active state indefinitely.
- Recheck acquire-before-spawn at waiter creation, runtime spawn, mark-running, handoff, worker failure,
  launcher restart and cleanup. No state may be released while a job could still write; no confirmed
  stopped job may retain multi-GiB data without bounded reconciliation.
- Recheck recursive deletion symlink behavior, launcher capability/path confinement, terminal replay
  semantics, sparse/hard-linked files, exact byte/inode/depth limits and Cargo compatibility.

VERIFICATION
- Base HEAD: `ef952c9355bd083ddd98f725a78d52bb227517d4`.
- `git diff --cached --check` passed.
- A fresh `git checkout-index` export of this exact final state passed bare `bin/ci`: formatting,
  Clippy with warnings denied, 234 active library tests with two credentialed live-provider tests
  ignored, every binary/integration/socket/scheduler/worker suite, both schema checks, 8 browser
  contracts and the optimized release build. The final release profile completed in 3 minutes 28
  seconds.
- Ten operation-state tests pass, including reuse/failure/reset/limit/stale/crash/tombstone paths, a
  deterministic rename-plus-external-symlink traversal test, and rejection of a 65-level adversarial
  tree before unbounded descriptor growth.
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
