Now let me read the remaining scheduler.rs helper functions and the store/mod.rs store error types:
Now I have all the context needed. Let me analyze each invariant systematically.
**VERDICT: SAFE**

All required invariants are correctly implemented without a P0–P2 defect. Below are the supporting findings.

---

**FINDING 1 — Cleanup receipt binding (PASS)**
`WorkflowCleanupReceiptV1::new` (domain/workflow.rs:1042) anchors the receipt digest to `lease_digest`, `lease_id`, `lease_generation`, `attempt_id`, `project_id`, `node_id`, `worker_id`, `host_id`, `terminal_receipt_digest`, `cleanup_evidence_digest`, and `completed_at_ms`. `commit_cleanup_receipt_transaction` (scheduler.rs:2041) verifies all eight `cleanup_receipt_matches_lease` fields, checks `closed_at_ms` ordering, and for `committed` leases validates the terminal receipt digest and `cleanup_result == Pending`. Exact replay is idempotent via digest+JSON comparison; conflicting evidence returns `WorkflowCleanupConflict`. **Confidence: high.**

**FINDING 2 — Cleanup debt durability and restart (PASS)**
`workflow_cleanup_receipts` is part of schema V3 (`CONTROL_SCHEMA_VERSION = 3`, control.rs:14). `pending_cleanup` (scheduler.rs:815) and `worker_has_pending_cleanup` (scheduler.rs:1004) use the same three-way LEFT JOIN across `workflow_lease_journal`, `workflow_node_receipts`, and `workflow_cleanup_receipts`, finding leases where `cleanup.lease_id IS NULL` AND (`state IN ('expired','revoked')` OR (`state='committed' AND json_extract(...)='pending'`)). Both the V1→V3 and V2→V3 migration tests verify the table exists and version is 3. The `expired_cleanup_debt_is_durable_and_must_reconcile_before_reuse` test proves reopen → pending → blocked claim → commit → reissue with generation+2. **Confidence: high.**

**FINDING 3 — Cleanup-before-reuse in atomic scheduler transaction (PASS)**
`claim_next` (scheduler.rs:753) calls `expire_leases_transaction`, then `worker_has_pending_cleanup`, then `claim_next_transaction` — all inside one `immediate_transaction`. This prevents the race where a concurrent cleanup receipt could arrive between the check and the claim. The `poll` handler (worker_socket.rs:287) additionally calls `reconcile_controller_nodes` → `pending_cleanup` → `claim_next` sequentially (each in its own transaction), and `claim_next` re-verifies `worker_has_pending_cleanup` atomically. **Confidence: high.**

**FINDING 4 — Bounded idempotent lease renewal (PASS)**
`renew_lease_transaction` (scheduler.rs:901): decodes canonical lease from DB; `same_lease_assignment` normalizes expiry/digest for identity comparison; rejects `supplied.expires_at_ms > current.expires_at_ms` (foreign/newer lease). When `supplied.lease_digest != current.lease_digest`, returns `Ok(current)` (lost-response replay). `bounded_lease_expiry` (scheduler.rs:1237) computes `execution_deadline = leased_at_ms + timeout_ms` and caps at `min(requested_expiry, execution_deadline)`. UPDATE uses optimistic concurrency (`WHERE state='active' AND lease_digest=?5`). The `lease_renewal_is_bounded_idempotent_and_survives_reopen` test proves replay returns the canonical renewed lease, renewal survives restart, and a stale receipt is rejected. **Confidence: high.**

**FINDING 5 — Peer-authenticated least privilege (PASS)**
`serve_worker_connection` (worker_socket.rs:740) reads `peer_cred()` and rejects UID mismatch *before* the first `read_frame`. The handler (`SchedulerWorkflowWorkerHandlerV1::new`, worker_socket.rs:213) rejects `Controller` and `PrivilegedExecutor` pools via `validate_unprivileged`. The systemd unit has `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, no Docker/source/executor socket references, `ProtectSystem=strict`, and `CapabilityBoundingSet=` empty. The `BoundWorkflowWorkerSocketV1::bind` (worker_socket.rs:853) validates parent directory (0750, owner, group, no symlink) and stale-socket identity via device+inode checks. The `is_normalized_absolute_path` helper bounds path length to 512 bytes and rejects special components. **Confidence: high.**

**FINDING 6 — Schema V1/V2 → V3 atomic migration (PASS)**
`CREATE TABLE IF NOT EXISTS` for all workflow tables runs in one `TransactionBehavior::Immediate` batch. `initialize_control_schema_version` (control.rs:589) handles `Some(1 | 2)` by updating the version integer to 3; the new `workflow_cleanup_receipts` table is created by the DDL if absent. `validate_control_schema` (control.rs:621) enumerates 22 required tables and their columns. Both migration tests (`control_store_migrates_v1_to_the_durable_workflow_journal`, `control_store_migrates_v2_cleanup_debt_atomically`) verify version=3 and the cleanup table existence. **Confidence: high.**

---

**OPEN QUESTIONS**

None. Every invariant maps to a concrete code path and is exercised by a passing test.

---

**INSPECTED**
- `src/domain/workflow.rs` (1324 lines) — `WorkflowCleanupReceiptV1`, `WorkflowNodeReceiptV1`, `WorkflowLeaseV1` constructors/validators/digest chains, `node_receipt_matches_lease`.
- `src/scheduler.rs` (2987 lines) — `claim_next`, `renew_lease`, `pending_cleanup`, `commit_cleanup_receipt`, `commit_node_receipt`, `expire_leases_transaction`, `renew_lease_transaction`, `commit_cleanup_receipt_transaction`, `worker_has_pending_cleanup`, `unresolved_cleanup_count`, `same_lease_assignment`, `bounded_lease_expiry`, `cleanup_receipt_matches_lease`.
- `src/store/control.rs` (720 lines) — schema V3 DDL, `initialize_control_schema_version`, `validate_control_schema`, `immediate_transaction` with `TransactionBehavior::Immediate`.
- `src/store/mod.rs` (254 lines) — `StoreError` variants including `WorkflowCleanupConflict`, `WorkflowLeaseConflict`, `WorkflowReceiptConflict`.
- `src/worker_socket.rs` (1074 lines) — `serve_worker_connection` (peer UID before frame), `serve_worker_until` (semaphore bound, deadline, shutdown), `BoundWorkflowWorkerSocketV1::bind` (TOCTOU-safe stale detection), `SchedulerWorkflowWorkerHandlerV1::poll/renew_lease/complete_node/complete_cleanup`, `WorkflowWorkerClientV1::exchange/ensure_negotiated`, `is_normalized_absolute_path`.
- `src/bin/rdashboard-workflow-gateway.rs` (201 lines) — startup call to `reconcile_controller_nodes`, `validate_unprivileged`, `WORKER_SOCKET_PATH`.
- `deploy/systemd/rdashboard-workflow-gateway.service` (48 lines) — `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, `CapabilityBoundingSet=` empty, no Docker/source/executor socket paths.
- `deploy/systemd/README.md` — gateway section only.
- `src/lib.rs` (92 lines) — `pub mod worker_socket` addition.
- `tests/workflow_scheduler_contracts.rs` — `lease_renewal_is_bounded_idempotent_and_survives_reopen`, `expired_cleanup_debt_is_durable_and_must_reconcile_before_reuse`, `terminal_and_revoked_cleanup_obligations_bind_their_exact_evidence`.
- `tests/worker_socket_contracts.rs` — `one_authenticated_socket_serves_two_projects_and_recovers_cleanup_debt`, `peer_uid_is_rejected_before_the_scheduler_is_touched`, `protocol_and_handler_configuration_reject_privilege_or_ambiguity`.
- `tests/store_and_web.rs` — V1→V3 and V2→V3 migration tests.
