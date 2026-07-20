GOAL
Confirm that the final staged Failure Capsule V2 and fixed-adapter receipt slice is safe for a local commit after addressing the first independent review.

QUESTION
Review the current `git diff --cached`, with special attention to the post-review changes: terminal receipts now bind the exact execution-start evidence digest, and emergency reserve evidence now records and validates required/remaining/deficit bytes. Determine whether either fix introduces a concrete P0/P1/P2 correctness, security, compatibility, canonicality, overflow, crash-consistency, or replay defect. Also identify any previously missed blocker in the complete staged slice. Give file/symbol, realistic scenario, impact, and smallest fix for every finding. If none remains, explicitly approve the exact staged diff for a local commit.

CONSTRAINTS
- Review only the staged manifest; unstaged notification/dashboard work is unrelated and out of scope.
- Do not edit files, run mutating commands, deploy, push, or access secrets.
- Existing Failure Capsule V1 JSON and legacy completed job directories without execution-start evidence remain compatible.
- New started jobs must not replay ambiguously; accepted new results require a successful start-bound terminal receipt and complete cleanup receipt.
- Missing measurements remain explicit gaps; reserve deficits must not be represented as fabricated zero remaining without the paired deficit.

KNOWN EVIDENCE
- First `deepseek-free` review status was `ANSWERED` and verdict `SAFE`, with no P0/P1 blocker.
- Accepted P2: `ExecutionTerminalReceiptV1` now includes `start_evidence_digest`; read/capture paths load and validate the exact start document and reject a substituted valid start. The cgroup fixture test exercises this rejection.
- Accepted P2: `ExecutionStorageUsageV1` now requires a consistent `(available, required, remaining, deficit)` tuple or explicit missing reserve evidence. A contract test proves a 5 GiB available / 8 GiB required state records a 3 GiB deficit and rejects inconsistent zero deficit.
- The other review observations were verified as correct/no-fix: ExecStopPost runs in the cumulative unit cgroup; unknown scratch cleanup remains an explicit gap; local token validators remain intentionally contract-specific.
- Post-fix bare `bin/ci` passed: Clippy, 181 library tests (2 credentialed tests ignored), all bin/integration suites, 4 failure/receipt contract tests, schema, 8 browser tests, and optimized release build.

INSPECT IF NEEDED
- `git diff --cached`
- `src/domain/execution.rs`
- `src/execution_receipt.rs`
- `src/domain/failure.rs`
- `src/adapter.rs`
- `src/adapter_phase.rs`
- `tests/failure_receipt_contracts.rs`
- `.agent/workflows/2026-07-20-github-independent-delivery/consult-slice1b-deepseek/response.md`
