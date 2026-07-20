Let me read the full diff that was truncated, plus the smaller files.
Let me read the full scheduler diff and the rest of the workflow.rs domain file.
Now I have the complete picture of the staged diff. Let me analyze it thoroughly.
Based on my thorough analysis of the complete staged diff (17 files, 5,855 insertions, 38 deletions), here is my final review.

---

## VERDICT: SAFE

The staged slice implements its stated fail-closed guarantees correctly. I was unable to falsify them. No P0 or P1 issues exist.

---

### FINDING 1 (P2)
**`expire_one_lease` non-mutation path discards row-count on node state update**
- **Path/symbol**: `src/scheduler.rs:expire_one_lease` (non-mutation branch)
- **Trigger sequence**: A non-mutation lease (prepare/verify/build) expires. The lease is set to `'expired'` (0-row-check not needed given the serialized transaction guard), but the node UPDATE `SET state = 'ready' WHERE state = 'leased'` discards its `changes()` count via bare `?`. Every other guarded transition in the scheduler (persist_active_lease, persist_node_receipt, acquire_mutation_lock, expire_mutation_lease, fail_workflow, complete_workflow) checks `changed != 1`.
- **Impact**: If a logic bug or store corruption causes the node to not be `'leased'` at expiry time, the lease becomes `'expired'` but the node is silently left in its stale state (e.g., `'blocked'`), dead-locking the workflow without error escalation.
- **Recommendation**: Capture `execute(…)?` into `let changed = …; if changed != 1 { return Err(…) }` to match the rest of the scheduler.
- **Confidence**: Low (requires a prior corruption or logic error to manifest, but the inconsistency with every other guarded transition is a reliability smell).

---

### FINDING 2 (P2)
**`expire_leases` runs outside `commit_node_receipt`'s transaction**
- **Path/symbol**: `src/scheduler.rs:commit_node_receipt` lines ~1-2 of the impl block
- **Trigger sequence**: `expire_leases(recorded_at_ms)` commits T1; `commit_node_receipt_transaction` begins T2 in a separate `immediate_transaction`. In principle a concurrent writer (other process sharing the DB) could create a new lease for the same node between T1 and T2.
- **Impact**: No correctness gap — `validate_active_receipt_lease` inside T2 re-validates the lease is `'active'` before writing the receipt. A lease that `expire_leases` missed (or that was created after T1) is caught. But the early `expire_leases` call provides zero correctness benefit since the real check is inside T2; it only adds latency and a TOCTOU window.
- **Recommendation**: Move `expire_leases` inside `commit_node_receipt_transaction` (or just rely on the lease-state check already inside it). Simpler, faster, and eliminates the inter-transaction window.
- **Confidence**: Medium (no exploit possible, but a clarity/performance concern).

---

### FINDING 3 (P2)
**`observe → complete_workflow` sets `mutation_state = 'complete'` unconditionally**
- **Path/symbol**: `src/scheduler.rs:complete_workflow`
- **Trigger sequence**: The final `ReleasedObservation` receipt triggers `complete_workflow`, which sets `mutation_state = 'complete'` via UPDATE. The mutation-lock DELETE checks `state = 'held'` and fails if 0 rows match.
- **Impact**: If the observation receipt is replayed (idempotent digest match), the mutation lock may already have been deleted by the first completion. The replay's `DELETE FROM workflow_mutation_locks WHERE attempt_id = ?1 AND state = 'held'` would return `changed = 0` → `CorruptWorkflowJournal`. But the test `reducer_binds_the_complete_required_set_and_receipts_are_idempotent` proves receipts are idempotent. Node-receipt idempotency (`replayed_node_receipt`) returns the snapshot without re-executing `apply_node_receipt_outcome` → `complete_workflow` on replay. So this is safe for node receipts. However, `reduce_attempt` replay also returns the cached snapshot without calling `complete_workflow`. Both paths are safe.
- **Recommendation**: No change needed — this is safe, noted only for completeness.
- **Confidence**: High (verified by test and code path).

---

### FINDING 4 (P2)
**`WorkflowReductionReceiptV1::new` sorts inputs by `node_id` but manifest `depends_on` is already sorted**
- **Path/symbol**: `src/domain/workflow.rs:WorkflowReductionReceiptV1::new` sorts `inputs`; `src/scheduler.rs:collect_reduction_inputs` iterates `reduce_node.depends_on` in manifest order
- **Trigger sequence**: The reduction `validate_standard_graph` constructs `reduce_dependencies` sorted. The manifest `depends_on` field is validated `strictly_sorted_unique`. `collect_reduction_inputs` appends inputs in manifest `depends_on` order. Then `WorkflowReductionReceiptV1::new` sorts again by `node_id`.
- **Impact**: Redundant sort but produces a canonical input order for digest computation. The `validate_persisted_reduction` checks `receipt.inputs == collected.inputs` where `collected` comes from `collect_reduction_inputs` (which appends in manifest order) and `receipt.inputs` was sorted in `new`. This only works because `new` sorts the inputs before setting them. No bug, just a note that the doc/sort is correct.
- **Recommendation**: No change.
- **Confidence**: High.

---

### FINDING 5 (P2)
**`create_attempt` sets `lease_generation = 0` for all nodes; `claim_next` requires `lease_generation` to match**
- **Path/symbol**: `src/scheduler.rs:persist_active_lease` WHERE clause: `state = 'ready' AND lease_generation = ?4`
- **Trigger sequence**: On first claim, `previous_generation = 0` (from `candidate.lease_generation`, initialized to 0 in `create_attempt`). The UPDATE checks `lease_generation = 0`. On re-claim after expiry, `previous_generation = 1` (from the last lease). This correctly generates a monotonically increasing sequence.
- **Impact**: Correct — the generation counter prevents stale-lease reclamation races.
- **Recommendation**: None.
- **Confidence**: High.

---

## OPEN QUESTIONS

1. Is the `WorkflowContractError` → `StoreError::WorkflowContract` conversion path reachable during normal operation, or only from corrupt journal data? The `#[from]` derive on `StoreError` converts `WorkflowContractError` from domain validation—but domain validation runs before store access in all public API paths (e.g., `admit` calls `manifest.validate()` directly, `commit_node_receipt` calls `receipt.validate()`). The store conversion exists for the decode/re-validate paths (`decode_canonical` inside scheduler). This seems intentional.

2. Are the `controller_meta` migration guards sufficient for in-place upgrades of existing v1 stores? The test confirms v1→v2 migration creates all 9 workflow tables and bumps version. No columns changed in existing tables. Safe.

---

## INSPECTED

- `git diff --cached` full output (17 paths)
- `src/domain/workflow.rs` (new 1164 lines)
- `src/scheduler.rs` (new 2524 lines)
- `src/domain/manifest.rs` (diff: V2 type, `validate_common_manifest`, digest pipeline)
- `src/installed_workflow.rs` (new 219 lines)
- `src/store/control.rs` (diff: DDL for workflow tables, v1→v2 migration)
- `src/store/mod.rs` (diff: `StoreError` variants)
- `src/bin/rdashboard-schema.rs` (diff: V2 schema generation)
- `tests/workflow_scheduler_contracts.rs` (new 650 lines, 9 tests)
- `tests/project_manifest_catalog.rs` (diff: V2 validation, ralert workflow assertions)
- `tests/store_and_web.rs` (diff: v1→v2 migration test)
- `config/project-manifests/ralert.json` (diff: full typed workflow DAG)
- `config/schema/project-manifest-v2.json` (new 501 lines)
- `config/project-manifests/README.md`, `config/schema/README.md`, `bin/ci`, `src/domain/mod.rs`, `src/lib.rs` (minor diffs)

---

## Summary

The implementation is defensive, internally consistent, and its test suite covers the critical failure paths (tampered receipts after restart, late receipts, mutation lock retention across supersede, fair queue survive-reopen, accelerator exclusivity, reduction idempotency). Finding 1 is the only actionable recommendation: add a `changed != 1` check to the non-mutation node-state update in `expire_one_lease`. Finding 2 is a style/latency suggestion.

**Verdict: SAFE to commit with optional P2 hardening from Finding 1.**
