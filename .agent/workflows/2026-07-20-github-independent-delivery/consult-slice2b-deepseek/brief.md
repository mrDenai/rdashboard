GOAL
Review the exact staged implementation of the inactive repository-agnostic workflow worker gateway,
lease renewal and durable cleanup reconciliation before a local commit.

QUESTION
Does the exact staged diff preserve scheduler journal correctness, cleanup-before-reuse, bounded
idempotent lease renewal, peer-authenticated least privilege and restart safety without a P0, P1 or
P2 defect? Return SAFE if yes. Otherwise report each concrete path/sequence, impact and smallest
production-worthy fix.

CONSTRAINTS
- Review only `git diff --cached`; exact SHA-256 is
  `6f34022a5bd8ec926e14183c713d7a6151f1cba18171c66aefec09aa280d48bb`, 12 paths, 2,711
  insertions and 31 deletions.
- Ignore every unstaged change: those are separate notification/dashboard work. Ignore other
  workflow directories, memory, conversations, credentials, `.env` files and external systems.
- Read-only repository access only. Do not edit, stage, build, test, invoke agents or mutate any
  external system.
- Report only actionable P0-P2 correctness, security, migration, concurrency, durability or missing
  high-signal test findings. Avoid style-only suggestions and features explicitly deferred below.
- This slice is inactive. It does not install or start a service, enable deployment, expose an HTTP
  endpoint, add the generic worker executor, prepare source/dependencies, grant Docker/root authority,
  or complete source ingress/controller UI projection. Those remain later implementation slices.

REQUIRED INVARIANTS
- A canonical cleanup receipt is bound to the exact lease and, for terminal-pending cleanup, the exact
  node receipt. Exact replay is idempotent; conflicting evidence fails closed.
- Expired, revoked and committed-but-cleanup-pending leases remain durable cleanup debt across restart.
  The scheduler itself, not merely one caller, prevents that worker/host from receiving new leases
  until all its cleanup debt is receipted.
- Renewal preserves lease ID and generation, changes only expiry/digest, never crosses the installed
  execution timeout, rejects a foreign/newer lease, and replays the current canonical lease after a
  lost renewal response.
- One fixed unprivileged worker identity may serve every installed project through one AF_UNIX socket,
  but cannot claim controller or privileged-executor pools and cannot select repositories, adapters,
  resources, network/cache classes, artifacts or host commands.
- Peer UID is checked before frame decoding; frames, request time, concurrency, paths and socket
  lifecycle are bounded. The systemd gateway has no network, Docker/source/executor socket,
  production volume, capability or credential authority.
- Control schema V1/V2 reopen atomically at V3 without losing prior scheduler state. SQLite replay,
  claim, expiry, cleanup and reducer transitions remain transactionally consistent under concurrent
  gateway requests.

KNOWN EVIDENCE
- Bare `bin/ci` passed after the exact staged implementation: formatting, Clippy with warnings denied,
  184 library tests (182 passed, 2 credentialed live tests ignored), every binary/integration suite,
  V1-to-V3 and V2-to-V3 migrations, 13 scheduler contracts, 3 worker-socket contracts, 8 browser tests
  and the optimized release build (2m50s).
- Self-review moved cleanup-before-reuse into the atomic scheduler claim transaction. The first full
  gate then exposed one old test that expected reissue without cleanup; the final test now proves
  restart, blocked claim, exact cleanup receipt and generation-2 reissue, and the full gate passes.
- Shared dirty files were staged by hunk. `src/lib.rs` contains only the worker module export;
  `tests/store_and_web.rs` contains only schema-V3 migration assertions; `deploy/systemd/README.md`
  contains only the generic workflow gateway section.

PRIMARY INSPECTION TARGETS
- `src/domain/workflow.rs`
- `src/scheduler.rs`
- `src/store/control.rs`
- `src/worker_socket.rs`
- `src/bin/rdashboard-workflow-gateway.rs`
- `deploy/systemd/rdashboard-workflow-gateway.service`
- `tests/workflow_scheduler_contracts.rs`
- `tests/worker_socket_contracts.rs`
