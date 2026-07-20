Let me read the full diff and the key domain types.
Now let me check the remaining diff and key files for the domain module exports:
**VERDICT: SAFE** — No P0/P1/P2 blocker.

**FINDINGS** (all P3, informational)

1. **P3 — Redundant `read_start` calls in `capture_terminal_receipt_in`**
   `src/execution_receipt.rs:4130-4131` and `src/execution_receipt.rs:4286` — The start file is read three times (once inside `read_authorized_request` for request decoding, once in the caller to validate, once in `read_terminal_receipt` → `validate_terminal_binding`). Not a security issue (root-owned directory) but needless IO. *Recommendation*: refactor `read_authorized_request` to return the already-decoded start, or hoist the start read before `read_authorized_request` and pass `start.sequence` in. *Confidence: high.*

2. **P3 — `classify_process` forces `exit_code = Some(0)` for Succeeded even when systemd produced no exit code**
   `src/execution_receipt.rs:4398-4399` — When `service_result == "success"`, `exit_code` is unconditionally `Some(0)`. If systemd unexpectedly emits `success` without an exit-code capture (theoretical edge case), the receipt encodes a fabricated `0`. The downstream `validate()` would still accept `exit_code = Some(0)` for `Succeeded`. *Recommendation*: only set `Some(0)` when the captured `exit_code` field was meaningful (i.e., when `environment.exit_code` was `"exited"` and the parsed status was `0`). *Confidence: low* (scenario may be systemd-impossible; no concrete test found).

3. **P3 — No JCS canonical-roundtrip test for termination intent**
   The termination intent is validated via `serde_jcs::to_vec(&intent)? != bytes` in `read_termination_intent` (`execution_receipt.rs:4314-4316`) but has no standalone test proving `encode → decode → encode` identity. Start evidence and terminal/cleanup receipts have such tests. *Recommendation*: add a `decode_canonical` method or a contract test for the termination intent. *Confidence: medium.*

**OPEN QUESTIONS**
None. All task constraints are satisfied: (a) terminal receipt digest chains through `start_evidence_digest` (`execution.rs:256,360,386`); (b) the cgroup fixture test proves start substitution is rejected at `execution_receipt.rs:4924-4941`; (c) emergency reserve tuple `(required, remaining, deficit)` is computed and validated via `available.saturating_sub(required)` / `required.saturating_sub(available)` at `execution.rs:123-134` and `execution_receipt.rs:4143-4151`; (d) the contract test at `failure_receipt_contracts.rs:306-310` proves a 5G/8G deficit records 3G and a fabricated zero deficit is rejected.

**INSPECTED**
- `git diff --cached` (5351 lines, full staged manifest)
- `src/domain/execution.rs` — receipt types, validation, digest chaining
- `src/domain/failure.rs` — V2 capsule, redaction, Markdown render
- `src/execution_receipt.rs` — runtime helpers, cgroup/fs capture, transition logic
- `src/adapter.rs` — job lifecycle, transient-unit plan, ExecStopPost wiring
- `src/adapter_phase.rs` — phase executor, reconciliation
- `tests/failure_receipt_contracts.rs` — contract tests
- `src/controller.rs` (hunks) — capsule validation on persist/decode
- `src/domain/mod.rs`, `src/domain/redaction.rs`, `src/phase6.rs`, `src/lib.rs` (hunks)

The staged diff is approved for a local commit.
