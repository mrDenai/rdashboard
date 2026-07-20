Let me read the key source files mentioned in the task.
Now let me read the critical `finish_delivery`, `reconcile_outbox_policy`, `pending_outbox`, and `acknowledge_outbox` methods in full context.
Let me do a final check on the reconcile_payload_digest version (v2 -> v3) and the broker epoch fencing.
I have now reviewed the complete staged diff comprehensively. Let me verify the product/test hash excluding workflow artifacts.
Hash verified: `0c5f01a1d2c32dc261e586cc8bac0d000275daf18cf7538eaa6ea4cc318c54a8`, 14 paths, 2,699 insertions, 76 deletions.

---

**VERDICT: SAFE**

**FINDINGS**

No actionable P0-P2 defects remain. The correction fully closes all identified paths.

**Stale-admission closure** (`src/source.rs:147-184`, `src/source.rs:2157-2169`): `reconcile_outbox_policy` runs in `DurableSourceBroker::new` under `TransactionBehavior::Immediate`, after `recover_source_state` binds the broker epoch but before any socket binds. It sets pending rows for disabled/removed projects to `superseded` with `settled_at_ms = MAX(enqueued_at_ms, reconciled_at_ms)`, then prunes the settled retention in the same transaction. The epoch-based fencing (`require_bound_broker_epoch`) prevents a stale broker from mutating the outbox.

**Safe replay on re-enable** (`src/source.rs:280-315`): `enqueue_deployable_outcome` reactivates superseded rows matching `(project_id, source_sequence, attestation_digest)` by setting `status='pending', settled_at_ms=NULL`. A previously delivered row remains delivered; a never-delivered row is not lost. The test `disabling_auto_deploy_revokes_pending_delivery_before_socket_bind` validates the full disable/reenable/replay cycle including source restart with sequence-1 preservation.

**Dispatcher admission** (`src/source_delivery.rs:75-130`): Every admission verifies entry validation, Ed25519 attestation signature/expiry, binding match (`project_id`, `source_sequence`, `attestation_digest`), `auto_deploy` enabled, source-project existence, workflow-project existence, `remote_url`/`repository_identity`/`workflow_policy_digest` binding, and `payload.repository_identity`/`installed_policy` match. One rejected project cannot block later batches via `rejected_sequences` tracking in the bounded drain cycle.

**Broker epoch fences all mutation** (`src/source.rs:570-578`): `require_bound_broker_epoch` is called in every store transaction (outbox policy reconciliation, pending read, ACK, finish_delivery). The broker additionally calls `require_current_lease` which validates the lock file, in-memory epoch, and DB epoch — defense-in-depth against lease theft.

**Durability and atomicity**: Accepted head and outbox entry commit in the same `finish_delivery` transaction (`src/source.rs:639-690`). SQLite `TransactionBehavior::Immediate` prevents write-skew. Lost-ACK idempotency (`acknowledge_outbox` treats `delivered`/`superseded` as success). Unknown/corrupt state fails closed via `SourceError::CorruptLedger`.

**Resource bounding**: `OUTBOX_BATCH=32`, `MAX_BATCHES_PER_CYCLE=8`, `MAX_PENDING_LIMIT=32`, `SETTLED_OUTBOX_RETENTION=2048`, `MAX_CONNECTIONS=64`, `MAX_OUTBOX_BATCH=64`. Dispatcher `TasksMax=32`, `MemoryMax=64M`, `CPUQuota=25%`, `LimitNOFILE=128`.

**Service isolation** (`deploy/systemd/rdashboard-source-dispatcher.service`): Dispatcher runs as `rdashboard`, has `PrivateNetwork=yes`, `ProtectSystem=strict`, `RestrictAddressFamilies=AF_UNIX`, no `LoadCredential=`, `CapabilityBoundingSet=` empty, single `ReadWritePaths=/var/lib/rdashboard`. Source unit does not belong to controller group. Delivery socket directory is `rdashboard-source:rdashboard` mode `2750`; socket is `0660`; each side authenticates the other's UID.

**Migration** (`src/source.rs:25`, `migrate_source_schema_v3`): V1+V2 migrate transactionally to V3 with empty `source_outbox` table. Config schema V3→V4 with new `controller_uid`, `controller_gid`, `delivery_socket_path`. Tests validate V2→V3 migration and V4 config generation.

**INSPECTED**: `src/source.rs`, `src/source_delivery.rs`, `src/source_delivery_socket.rs`, `src/installed_source.rs`, `src/installed_workflow.rs`, `src/bin/rdashboard-source.rs`, `src/bin/rdashboard-source-dispatcher.rs`, `src/bin/rdashboard-source-config.rs`, `src/lib.rs`, `deploy/systemd/rdashboard-source-dispatcher.service`, `deploy/systemd/rdashboard-source.service`, `deploy/systemd/rdashboard-tmpfiles.conf`, `deploy/systemd/README.md`, `tests/source_delivery_contracts.rs`.

**OPEN QUESTIONS**: None.
