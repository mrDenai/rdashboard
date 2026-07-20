GOAL
Perform the final exact-staged review of rdashboard source-to-scheduler delivery after a post-review
self-audit found and corrected pending-delivery revocation across an `auto_deploy` policy disable.

QUESTION
Does the correction fully close stale admission after disable/removal while preserving safe replay on
re-enable, and does the complete exact staged diff now have any actionable P0-P2 correctness,
security, concurrency, durability, resource-bounding, service-isolation, migration, or missing
high-signal test defect? Return SAFE only if no such defect remains.

CONSTRAINTS
- Review only `git diff --cached`. Ignore every unstaged change and untracked notification artifact;
  the exact staged snapshot was independently exported and verified without them.
- Read-only repository access only. Do not edit, stage, build, test, invoke agents, or mutate any
  external system.
- Exact current product/test diff SHA-256 (workflow artifacts excluded):
  `0c5f01a1d2c32dc261e586cc8bac0d000275daf18cf7538eaa6ea4cc318c54a8`; 14 paths,
  2,699 insertions, 76 deletions.
- Report only actionable P0-P2 findings. Avoid style-only, speculative, or later-scope requests.
- This is inactive slice 3a. HTTP webhook/forced-push ingress, multi-project config generation,
  service activation, VPS timing drills, workflow execution, provider writes and deployment remain
  later work and are not missing behavior in this review.

FIRST REVIEW AND CORRECTION
- The first `deepseek-free` exact-staged review returned `SAFE`, no P0-P2/open question, for product
  hash `dbe21b0364dcfacc5d51986989ae2efd1b9c230ca3b6dd5525893bc9cb3979da`.
- Subsequent self-review found a real stale-policy path: an outbox entry created while
  `auto_deploy=true` remained pending after source restarted with that project disabled or removed.
  A dispatcher still holding the old enabled config could therefore fetch and admit it after the
  source restart because `auto_deploy` is not part of the signed accepted-head payload.
- `DurableSourceBroker::new` now derives the exact enabled-project set and, after source recovery but
  before any socket can bind, calls `SourceStore::reconcile_outbox_policy` under the current broker
  epoch and one immediate transaction. Pending entries for disabled or removed projects become
  `superseded`; exact settled retention is pruned in the same transaction.
- Re-enabling the unchanged current head can reactivate the exact matching superseded outbox row as
  pending. A previously delivered row remains delivered, so a disable/enable cycle cannot invent a
  second scheduler operation; a never-delivered row is not lost.
- ACK now prunes settled retention as well, so the 2,048 settled-row limit remains exact even after a
  large pending batch is acknowledged without a later enqueue. Supersession timestamps cannot precede
  their row's enqueue timestamp.
- A new restart contract proves enabled pending -> disabled broker construction yields no pending
  delivery -> re-enabled reconciliation restores exactly source sequence 1/current SHA.

REQUIRED INVARIANTS
- Accepted head/outbox commit atomically; lost ACK is idempotent; newer heads supersede older pending
  only; V1/V2 source schemas migrate transactionally to V3; unknown/corrupt state fails closed.
- Broker epoch fences pending reads, policy reconciliation and ACK writes. Old brokers cannot deliver
  after singleton lease loss.
- Source server checks controller UID before decode; client checks source UID before write. Protocol,
  frames, requests, deadlines, connections and batches are bounded and request-bound.
- Dispatcher verifies canonical record, signature/expiry, current installed auto-deploy policy,
  repository identity and exact workflow digest before durable scheduler admission; it ACKs only a
  durable admission or a provably older scheduler sequence.
- One rejected project cannot block later batches. Healthy polling is 250ms; transient failure backoff
  is 2s and stable policy rejection backoff is 30s.
- Source and dispatcher remain separate least-privilege processes. No Git path/key, source DB,
  arbitrary command, root, Docker, network or mutation authority crosses the controller delivery
  boundary.

KNOWN EVIDENCE
- Final refreshed exact `git checkout-index` staged export passed bare `bin/ci`: 167 active library
  tests with 2 credentialed provider tests ignored, every binary/integration suite, 7 source-delivery
  contracts, 29 store/web, 14 scheduler, 8 browser contracts, schema checks, strict Clippy, and the
  optimized release build in 2m38s.
- `git diff --cached --check` passed.
- The earlier full live-worktree gate passed independently with 184 active library tests, every suite,
  30 store/web, 14 scheduler, 9 browser contracts and release build in 2m50s.

INSPECT IF NEEDED
- `src/source.rs:SourceStore::reconcile_outbox_policy`
- `src/source.rs:enqueue_deployable_outcome`
- `src/source.rs:prune_settled_outbox`
- `src/source.rs:DurableSourceBroker::new`
- `tests/source_delivery_contracts.rs:disabling_auto_deploy_revokes_pending_delivery_before_socket_bind`
- The remaining staged source delivery/socket/admitter/config/systemd paths from the first review.
