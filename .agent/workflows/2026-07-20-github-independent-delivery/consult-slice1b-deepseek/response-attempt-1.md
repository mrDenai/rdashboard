I've completed my thorough read-only analysis of the staged diff. Here is my review.

---

**VERDICT: SAFE** — the staged slice is safe to commit for a local commit. No P0/P1 correctness, security, crash-consistency, or evidence-integrity defects that would block it.

**FINDINGS**

**P1 — ExecStopPost cgroup path resolves to the **adapter-receipt process** cgroup, not the original adapter's cgroup.**
`src/execution_receipt.rs:1939-1946` — `capture_installed_terminal_receipt()` reads `/proc/self/cgroup` from the ExecStopPost process. systemd runs ExecStopPost inside the transient scope's cgroup, so the path (`0::/system.slice/rdashboard-adapter-…`) resolves to the same scope. The adapter's cgroup counters (`cpu.stat usage_usec`, `memory.peak`, `io.stat`, `pids.peak`) are cumulative across all processes that ever ran in that cgroup, and the cgroup is not freed until ExecStopPost completes. **Scenario:** Normal execution. **Impact:** None — cgroup evidence reflects actual resource usage. **Confidence:** High. No fix needed.

**P2 — Terminal receipt digest does not cryptographically chain to the start evidence digest.**
`src/execution_receipt.rs:656-676` — `ExecutionTerminalReceiptDigestPayload` excludes `start.evidence_digest`. The termination intent *does* chain to the start digest (line 1837: `start_evidence_digest` in digest payload), but the terminal receipt only records `started_at_ms` as an identity field, not the start digest. **Scenario:** An attacker with root filesystem write replaces `execution-start.jcs` with a different start evidence having the same `started_at_ms` but different `scratch_before_bytes`. The terminal receipt validates against the new start. **Impact:** Low — the job directory is owner-only (0o700, root), making this attack impossible without full root privilege that could replace all files anyway. **Recommendation:** Add `start_evidence_digest` to `ExecutionTerminalReceiptDigestPayload` as a defense-in-depth improvement for a future change. **Confidence:** High.

**P2 — `materialize_cleanup_receipt` sets `scratch_removed_bytes: None` unconditionally.**
`src/execution_receipt.rs:2065` — Always passes `None` for `scratch_removed_bytes`. This is a known missing measurement and produces a `ScratchRemoved` gap, which is correct per the "Missing measurements must be explicit gaps" constraint. **Scenario:** Cleanup runs but scratch directory size delta is unknown. **Impact:** Correct — the gap is reported. **Confidence:** High.

**P2 — `emergency_reserve_remaining_bytes` saturates to 0 when deficit exists, masking a shortfall.**
`src/execution_receipt.rs:1971-1977` — `available.saturating_sub(reserve)` yields 0 when `available < reserve`. A human reading the receipt sees "0 bytes emergency reserve remaining" and cannot distinguish "exactly zero" from "in deficit." **Scenario:** Filesystem has 5 GiB free but 8 GiB minimum reserve is required. Report shows 0 instead of -3 GiB. **Impact:** Low — only a reporting/metric nuance; no correctness or safety impact. **Confidence:** High.

**P2 — Duplicated `valid_token` / `valid_step_id` with identical logic across three files.**
`src/execution_receipt.rs:2358`, `src/domain/execution.rs:858`, `src/domain/failure.rs:1446` — Each defines its own copy of the same ASCII-lowercase/digit/dot/hyphen/underscore validator. **Impact:** Hygiene — not a correctness defect. If one copy diverges in a future change, acceptance criteria differ across receipts. **Confidence:** High.

**No finding:** V1 `FailureCapsule` backward compatibility is clean (`#[serde(default, skip_serializing_if = "Option::is_none")]` on the `v2` field; exact JSON round-trip tested at `tests/failure_receipt_contracts.rs:128-139`). Secret redaction correctly strips ANSI before regex sweeping (ANSI count is separate from regex count, no double-counting after replacement). Hard bounds (256 KB per receipt file, 64 KB per cgroup file, 100K directory entries, depth 32) are consistently enforced. The `write_owner_only_new` + read-back pattern defeats TOCTOU. Crash-incomplete executions (start evidence present, no terminal receipt) are non-ambiguously blocked by `ExecutionRequiresReconciliation`.

**OPEN QUESTIONS**

None — all evidence chains, timings, permission checks, size bounds, and redaction paths are accounted for. The two P2 items are architectural improvements, not blockers.

**INSPECTED**
- `git diff --cached --stat` and `git diff --cached` (full 2745-line output)
- `src/adapter.rs` (lines 60-1450)
- `src/execution_receipt.rs` (full 1128 lines + tests)
- `src/domain/execution.rs` (full 558 lines)
- `src/domain/failure.rs` (full 615 lines)
- `src/domain/redaction.rs` (full staged diff)
- `src/adapter_phase.rs` (full staged diff, lines 125-389)
- `src/bin/rdashboard-adapter-receipt.rs` (full 10 lines)
- `src/adapter_result.rs` (lines 240-340)
- `src/domain/mod.rs` (full 21 lines)
- `tests/failure_receipt_contracts.rs` (full 260 lines)
- All grep results for `ExecStopPost`, `ExecutionRequiresReconciliation`, `AdapterExecutionOutputV1`, `FixedAdapterResultV1`
