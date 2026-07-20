**VERDICT: SAFE**

No P0, P1, or P2 correctness, security, concurrency, migration, durability, or contract-gap issue exists in the staged diff.

**FINDINGS**
None that meet the severity bar.

The diff enforces every stated contract through structural mechanisms:
- **DAG validation** (`src/domain/workflow.rs`): topology, standard-graph cardinality, artifact-contract matching, profile–kind consistency, resource bounds, and digest self-signing are all checked at admission/construction time, not lazily.
- **Channel deduplication + source high-water mark** (`src/scheduler.rs:393-438`, `:463-508`): `PRIMARY KEY(channel, delivery_id)` and monotonic `source_sequence` guards with `WorkflowStaleSource` / `WorkflowDeliveryConflict` errors.
- **Pre-mutation supersession** (`src/scheduler.rs:511-610`): mutation owners (`mutation_state != NotStarted`) are explicitly preserved; only pre-mutation attempts are superseded. The `WaitingForMutation` / `wake_waiting_attempts` hand-off is correct.
- **Mutation lock retention**: on expiry (`expire_mutation_lease` `:852-879`) and on failure (`fail_workflow` `:1856-1919`) the lock is set to `needs_reconcile` and never deleted except by `complete_workflow`.
- **Receipt validation** (`commit_node_receipt`: `:1627-1770`): validates lease state = `active`, cross-checks every field against the stored lease JCS, enforces `completed_at_ms < expires_at_ms` and `recorded_at_ms < expires_at_ms`, and rejects late/missing/conflicting receipts with `WorkflowLeaseConflict` or `WorkflowReceiptConflict`.
- **Reduction tamper detection** (`validate_reduction_evidence` `:1593-1625`): checks lease state = `committed`, node state = `Succeeded`, all receipt fields match, output digest chain, and receipt-dedup set.
- **Migration** (`src/store/control.rs:862-869`): v1→v2 is a single-statement schema-version bump after `CREATE TABLE IF NOT EXISTS` for all 12 new STRICT tables.
- **Private-file loader** (`src/installed_workflow.rs:151-198`): triple `symlink_metadata` + `File::metadata` TOCTOU verification with dev/ino/len matching.
- **Concurrency** (`store.immediate_transaction`): Rust `Mutex<Connection>` + SQLite `BEGIN IMMEDIATE` ensures serialized write transactions.

**OPEN QUESTIONS**
None.

**INSPECTED**
All 17 paths in the staged diff were read in full: `src/domain/workflow.rs`, `src/domain/manifest.rs`, `src/installed_workflow.rs`, `src/scheduler.rs`, `src/store/control.rs`, `src/store/mod.rs`, `src/domain/mod.rs`, `src/lib.rs`, `tests/workflow_scheduler_contracts.rs`, `tests/store_and_web.rs`, `tests/project_manifest_catalog.rs`, `bin/ci`, `config/project-manifests/ralert.json`, `config/project-manifests/README.md`, `config/schema/README.md`, `config/schema/project-manifest-v2.json`. `store.immediate_transaction` implementation was verified via separate task. No plan document found at the expected path.
