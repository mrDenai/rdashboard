Let me read the full diff for the critical sections — `expire_one_lease`, `claim_next`, `commit_node_receipt`, and the two terminal tests.
## Analysis

Have examined the full staged diff for the four targeted functions and both terminal tests.

### Prior P2 finding: non-mutation `leased -> ready` row-count check

**Fixed.** `expire_one_lease` at `src/scheduler.rs:828-843` now checks `changed != 1` for *both* the `UPDATE workflow_nodes SET state = 'ready'` and `UPDATE workflow_attempts SET updated_at_ms`. The lease-journal UPDATE was already guarded. All three row-count checks are present:

| UPDATE | Changed check |
|---|---|
| `lease_journal` → `expired` | `changed != 1` (line 822) |
| `workflow_nodes` → `ready` (non-mutation) | `changed != 1` (line 833) — **was missing, now added** |
| `workflow_attempts` → `updated_at_ms` | `changed != 1` (line 840) |

### Two-transaction receipt boundary

The deliberate two-transaction design in `commit_node_receipt` (`src/scheduler.rs:1423-1429`) is correct and well-documented. The late-receipt test (`late_receipts_requeue_non_mutating_work_instead_of_becoming_success`) proves it works: expiry commits in the outer call, then the receipt validation in a fresh transaction finds the lease state is `expired` (not `active`), returning `Err(StoreError::WorkflowLeaseConflict)`. The node state persists as `Ready` with no output — exactly the required invariant.

### Terminal tests

- `terminal_success_releases_mutation_ownership_and_wakes_the_newer_head`: exercises the full success path — reduction, executor path, observation commit, `complete_workflow`, rollback cancellation, mutation lock deletion, `wake_waiting_attempts`, and re-claim for the woken head. All assertions pass by design.
- `terminal_success_rolls_back_when_the_held_mutation_lock_is_missing`: proves `complete_workflow` atomically rolls back the entire `commit_node_receipt_transaction` when the mutation lock DELETE returns `changed == 0`. The attempt remains `Running` and the node remains `Leased`.

### No regressions found

All critical UPDATEs across the scheduler carry row-count guards. No unwrap/panic paths in production code. All integer arithmetic uses `checked_add` / `try_from`. Transaction scoping is correct. Nothing in the diff touches unstaged areas.

**VERDICT: SAFE**

| ID | Finding | Severity | Confidence |
|---|---|---|---|
| F1 | Non-mutation row-count check added to `expire_one_lease` for `node` and `attempt` UPDATEs | P2 (fixed) | High |
| F2 | Two-transaction boundary in `commit_node_receipt` is correct, documented, and verified by late-receipt test | N/A | High |
| F3 | `terminal_success_releases_mutation_ownership_and_wakes_the_newer_head` proves end-to-end DAG projection + handoff | N/A | High |
| F4 | `terminal_success_rolls_back_when_the_held_mutation_lock_is_missing` proves atomic rollback of terminal receipt on missing lock | N/A | High |

No P0, P1, or P2 regressions. The staged diff is safe for local commit.
