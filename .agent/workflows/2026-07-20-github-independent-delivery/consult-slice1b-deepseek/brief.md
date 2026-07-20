GOAL
Decide whether the exact staged slice is safe to commit as the Failure Capsule V2 and fixed-adapter terminal/cleanup receipt foundation.

QUESTION
Review only `git diff --cached` and identify concrete P0/P1/P2 correctness, security, crash-consistency, compatibility, or evidence-integrity defects. Focus on realistic failure scenarios: systemd ExecStopPost/cgroup collection ordering, cancellation/deadline/launch crash windows, replay and legacy/new-job discrimination, receipt binding/canonicality, V1 JSON compatibility, secret/control redaction, and hard size bounds. For every finding give severity, exact file/symbol or line, a reproducible scenario, impact, and the smallest coherent fix. If no such defect remains, say explicitly that the staged slice is safe for a local commit. Do not propose unrelated architecture or style changes.

CONSTRAINTS
- The review target is exactly the staged manifest and `git diff --cached`; unstaged notification/dashboard work belongs to another task and is out of scope.
- GitHub remains only source storage/signal; no deployment, push, live systemd action, or external mutation is authorized.
- Existing V1 failure capsules and completed adapter job directories without execution-start evidence must remain readable.
- Every new execution-start must prohibit ambiguous re-execution; every accepted new completed result must have a bound successful terminal receipt and complete cleanup receipt.
- Missing measurements must be explicit gaps rather than fabricated zeroes.
- The adapter command remains fixed, shell-free, root-owned, bounded, and `systemd-run --wait --collect` based.
- Treat model output as review hypotheses only; do not edit files or run mutating commands.

KNOWN EVIDENCE
- Bare `bin/ci` passed after implementation: Clippy with `-D warnings`, 181 library tests (2 credentialed tests ignored), all bin/integration suites, 3 new failure/receipt contract tests, schema check, 8 browser tests, and release build.
- `src/adapter.rs` installs one fixed `ExecStopPost=/usr/libexec/rdashboard/rdashboard-adapter-receipt`, writes execution-start before spawn, and validates terminal/cleanup evidence before accepting new results.
- `src/execution_receipt.rs` captures cgroup v2 files and durable canonical JCS evidence in the root-owned job directory.
- `src/domain/execution.rs` and `src/domain/failure.rs` define strict digest-bound receipts and backward-compatible Failure Capsule V2.
- `tests/failure_receipt_contracts.rs` covers V1 exact JSON round-trip, V2 redaction/bounds/canonicality, gap tampering, and cleanup invariants.

INSPECT IF NEEDED
- `git diff --cached --stat` and `git diff --cached`
- `src/adapter.rs`
- `src/execution_receipt.rs`
- `src/domain/execution.rs`
- `src/domain/failure.rs`
- `src/domain/redaction.rs`
- `src/adapter_phase.rs`
- `tests/failure_receipt_contracts.rs`
- `.agent/workflows/2026-07-20-github-independent-delivery/{brief,research,plan,review}.md`
