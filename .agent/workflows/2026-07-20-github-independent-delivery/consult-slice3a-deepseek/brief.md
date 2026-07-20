GOAL
Falsify the production-worthiness of the exact staged rdashboard slice that durably delivers signed
accepted source heads from the isolated source broker into the repository-agnostic workflow scheduler.

QUESTION
Does the exact staged diff have any actionable P0-P2 correctness, security, concurrency, durability,
resource-bounding, service-isolation, migration, or missing high-signal test defect? Return SAFE only
if no such defect remains; otherwise report each concrete failing path/sequence, impact, and smallest
production-worthy fix.

CONSTRAINTS
- Review only `git diff --cached`. Ignore every unstaged change and untracked notification artifact;
  those belong to another in-progress slice and were excluded from the independently verified staged
  export.
- Read-only repository access only. Do not edit, stage, build, test, invoke agents, or mutate any
  external system.
- Product/test diff SHA-256 (workflow artifacts excluded):
  `dbe21b0364dcfacc5d51986989ae2efd1b9c230ca3b6dd5525893bc9cb3979da`; 14 paths,
  2,561 insertions, 76 deletions.
- Report only actionable P0-P2 findings. Avoid style-only, speculative, or later-scope requests.
- This is slice 3a, intentionally inactive: it adds durable source outbox -> local dispatcher ->
  scheduler delivery, but does not install/start services, enable `auto_deploy`, add HTTP webhook or
  forced-push ingress, generalize the still-fixed rimg config generator, run a VPS timing drill, execute
  workflow jobs, call providers, push, or deploy.

REQUIRED INVARIANTS
- A deployable accepted head and its canonical signed outbox record are committed in the same source
  delivery transaction. Lost controller ACK replays one stable scheduler delivery identity; a newer
  source sequence supersedes only older pending records. Settled retention and request/batch sizes are
  bounded.
- Source schema V3 opens V1 and V2 stores transactionally and fails closed on unknown/corrupt state.
  Broker epoch fencing covers pending reads and ACK writes; an old broker cannot deliver after losing
  its singleton lease.
- An unchanged head observed through another channel does not corrupt delivery binding or duplicate
  the outbox. A root-owned disabled->enabled policy change and an expired signature both cause periodic
  reconciliation to re-enqueue/re-attest the current head, so controller downtime cannot lose it.
- The source server verifies the installed controller UID before decoding a frame. The client verifies
  the installed source UID before writing. The protocol is strict, versioned, request-bound,
  length/time/connection bounded, validates returned entries, and reconciles only an exact stale socket
  in the protected owner/group/mode directory.
- The dispatcher verifies canonical outbox binding, Ed25519 signature and expiry, configured
  auto-deploy, repository identity, source installed policy and exact workflow manifest digest before
  scheduler admission. ACK occurs only after durable admission or a provably older source sequence.
- Scheduler admission is idempotent under ACK loss. Permanent bad entries remain unacknowledged but
  back off for 30 seconds; transient scheduler/expiry/transport failures retry in two seconds. One bad
  project must not block other entries in later batches or create a 250 ms log/CPU loop.
- Root-owned source config V4 contains no secret bytes and binds both peer identities/socket paths.
  The workflow catalog is canonical root-owned group-readable input with exact directory/file modes.
- `rdashboard-source` never joins the controller group or opens `control.sqlite`;
  `rdashboard-source-dispatcher` has no network/source credential/source DB access and can write only
  the controller StateDirectory. No repository path, Git credential, arbitrary command, root or Docker
  authority crosses the delivery socket.

KNOWN EVIDENCE
- Full live-worktree bare `bin/ci` passed: 184 active library tests, every binary/integration suite,
  30 store/web, 14 scheduler, 9 browser contracts, schema checks, and optimized release build in 2m50s.
- A refreshed exact `git checkout-index` staged export independently passed bare `bin/ci`: 167 active
  library tests (2 credentialed provider tests ignored), every binary/integration suite, 6 new source
  delivery contracts, 29 store/web, 14 scheduler, 8 browser contracts, schema checks, and optimized
  release build in 2m38s.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` and
  `git diff --cached --check` passed.
- New tests cover V2->V3 source migration, outbox replay/supersession/ACK binding, same-head cross-channel
  replay, disabled->enabled recovery, prolonged controller outage plus expired-signature refresh,
  signature/policy/repository substitution, and both directions of Unix peer-UID authentication.

INSPECT IF NEEDED
- `src/source.rs`
- `src/source_delivery.rs`
- `src/source_delivery_socket.rs`
- `src/bin/rdashboard-source.rs`
- `src/bin/rdashboard-source-dispatcher.rs`
- `src/installed_source.rs`
- `src/installed_workflow.rs`
- `tests/source_delivery_contracts.rs`
- `deploy/systemd/rdashboard-source.service`
- `deploy/systemd/rdashboard-source-dispatcher.service`
- `deploy/systemd/rdashboard-tmpfiles.conf`
