GOAL
Decide whether the exact staged Slice 4b is safe and correct to commit as the inactive signed workflow-execution and fixed root-launcher boundary for a repository-agnostic deployment worker.

QUESTION
Does the exact staged diff contain any concrete P0, P1, or P2 correctness, security, concurrency, restart-safety, resource-bounding, or compatibility defect? Focus especially on whether an unprivileged worker can escape the fixed launch policy, substitute a lease/input/path/adapter/systemd property, replay or extend a grant, execute twice across renewal/restart, lose cleanup debt, or exploit a peer-authentication/TOCTOU gap. Return SAFE if no such defect exists; otherwise cite path/symbol, an executable failure scenario, severity, and the smallest coherent fix. List low-value style suggestions only as P3.

CONSTRAINTS
- Review only `git diff --cached`; the worktree intentionally contains unrelated unstaged notification work that is not part of this review.
- Do not edit files, run services, access secrets, read `.env`, contact providers, or mutate external state.
- GitHub remains only source storage/signal; no GitHub runner or registry may be required at runtime.
- The launcher is root-owned but accepts requests only from one configured unprivileged worker UID. It must derive all commands, paths, identities, mounts, limits, and isolation from root-owned policy plus exact signed lease data.
- This slice remains inactive: it must not install/start units, execute repository code, deploy, or mutate the VPS.
- Legacy persisted leases must remain decodable, but work lacking exact source and dependency-artifact identity must fail closed before execution.
- Renewing the same execution may update expiry/grant evidence but must never spawn a second unit. Ambiguous accepted/running state after launcher restart must become cleanup/reconciliation debt, never implicit replay.
- The generic worker loop and live systemd/quota drill are intentionally later work. Do not report their absence as a defect unless this staged boundary falsely claims or accidentally performs them.
- `allowed_adapters` deliberately gates native/OCI adapters until their fixed scripts and isolation are separately installed and reviewed.

KNOWN EVIDENCE
- Exact staged binary diff SHA-256: `ec99f71bf82f4ec71906ddbdedea19a873aa82538b3b19361f87760f0e33b49f` (19 paths, 5,094 insertions, 78 deletions).
- `git diff --cached --check` passed.
- Bare `bin/ci` passed in a `git checkout-index` export of the exact staged tree: formatting, Clippy with warnings denied, 188 active library tests (2 live-provider tests ignored), every binary/integration/socket suite, 14 scheduler contracts, 8 browser contracts, schema checks, and optimized release build in 3m03s.
- The first exact-export run exposed a parallel restart-test race: a forked child could briefly retain the journal directory lock until exec. `WorkflowLaunchJournalInner::drop` now explicitly unlocks before closing; the exact-export full gate passed after the correction.
- No unit was installed or started, no job launched through systemd, no GitHub/provider contacted, and no VPS/deployment state changed.

INSPECT IF NEEDED
- `git diff --cached -- src/domain/workflow.rs src/scheduler.rs src/worker_socket.rs tests/worker_socket_contracts.rs tests/workflow_scheduler_contracts.rs`
- `git diff --cached -- src/workflow_execution_grant.rs src/workflow_execution_authority.rs`
- `git diff --cached -- src/workflow_launcher.rs src/workflow_launcher_socket.rs tests/workflow_launcher_socket_contracts.rs`
- `git diff --cached -- src/bin/rdashboard-workflow-gateway.rs src/bin/rdashboard-workflow-launcher.rs src/bin/rdashboard-workflow-job.rs`
- `git diff --cached -- deploy/systemd/rdashboard-workflow-gateway.service deploy/systemd/rdashboard-workflow-launcher.service deploy/systemd/rdashboard-tmpfiles.conf deploy/systemd/README.md src/lib.rs`
- Existing exact contracts in `src/preparation.rs`, `src/domain/workflow.rs`, and the scheduler/worker socket tests may be read only as needed to trace staged behavior.
