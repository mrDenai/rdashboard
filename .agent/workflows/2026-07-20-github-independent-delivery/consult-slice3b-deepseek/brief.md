GOAL
Perform an exact-staged production-readiness review of rdashboard slice 3b: strict multi-project
source installation plus bounded durable GitHub push ingress and webhook-priority fetch scheduling.

QUESTION
Does the complete staged product/test diff contain any actionable P0-P2 correctness, security,
concurrency, durability, availability, resource-bound, migration, systemd-isolation, or missing
high-signal test defect? Return SAFE only if no such defect remains. Pay particular attention to
cross-project fetch priority, webhook/reconcile races, restart recovery, raw-secret handling, and the
claim that periodic work cannot consume the <=3-second normal source-acceptance budget.

CONSTRAINTS
- Review only `git diff --cached`. Ignore every unstaged change and untracked notification artifact;
  the exact staged snapshot was independently exported and verified without them.
- Read-only repository access only. Do not edit, stage, build, test, invoke agents, or mutate any
  external system.
- Exact current product/test diff SHA-256 (workflow plan excluded):
  `5b2808f5e304074cced07397d5600c2b554d7c7af87e652fddcf4310ee5a62d3`; 21 paths,
  4,768 insertions and 406 deletions.
- Report only actionable P0-P2 findings. Avoid style-only, speculative, or later-scope requests.
- This is inactive slice 3b. Forced-command SSH ingress and an authorized live VPS/GitHub timing
  drill remain later parts of plan step 3. Generic worker/CAS/build/deploy/self-deploy work remains
  step 4 onward. Those are not missing behavior in this review.

IMPLEMENTED BOUNDARIES
- Installed source schema V5 is generated from the exact root-owned installed workflow catalog plus
  an exactly covering source-controls catalog. Each project binds GitHub owner/repository, repository
  identity, source/workflow policy, webhook-secret digest and optional distinct read-only SSH
  credential digests. Private bytes never enter the public installed document.
- One generated systemd credential drop-in replaces the fixed `rimg` list and supplies exactly the
  attestation seed, current project webhook secrets and only required SSH files. Credential reads
  recheck file identity/size/mode/digest; secret and private-key buffers are zeroized.
- The unprivileged HTTP process listens only on `127.0.0.1:3201`, recognizes only configured
  `/github/<project>` push routes, caps concurrency/headers/body, preserves exact raw body bytes and
  forwards a canonical base64url frame over a protected AF_UNIX socket. It has no secrets, Git,
  databases, writable filesystem, Docker, capability or controller authority.
- The source-side socket checks the configured ingress peer UID before decode. The ingress client
  checks the source UID before write. Both directions have bounded frames, deadlines, connections,
  version negotiation, request IDs, trailing-byte rejection, stale-socket and inode-safe cleanup.
- The broker verifies SHA-256 HMAC in constant time and exact repository binding before committing
  only delivery ID, payload digest, announced head, repository name and receive time to a
  `synchronous=FULL` SQLite queue. Raw bodies and signatures are not persisted or logged.
- Queue admission is content-bound/idempotent and capped at 2,048 pending globally, 128 per project;
  one 128-event project batch performs one remote fetch. Reordered events converge only through the
  fetched remote `main`; payload SHA never directly selects the accepted head.
- A durable per-project priority flag plus global generation cancels an active periodic network child
  when a webhook commits, blocks new periodic admission while any webhook queue remains, and prevents
  periodic try-lock work from queueing ahead of foreground fetches. The flag is cleared-before-
  durable-recheck to close enqueue/clear races. Periodic network fetch is bounded to two seconds,
  retries a busy shared slot at 250 ms, and webhook fetch retains the full one-minute provider bound.
  Pack promotion is intentionally not cancelled after it begins so canonical object state remains
  recoverable.
- Broker restart re-signals retained wake-ups and retires wake-ups for removed projects or repository
  rebinding before socket bind, without deleting accepted-head/source-delivery audit state. Per-project
  coordinators retry remote-visibility lag from 250 ms to five seconds and retain the 30-second plus
  <=5-second-jitter lost-webhook fallback.
- New source, ingress and private-Kamal bridge systemd units keep source secrets isolated. The bridge
  proxy itself is non-root under the ingress identity and may connect only to localhost. Checkout and
  this change install or enable nothing; `auto_deploy` remains false.

KNOWN EVIDENCE
- An exact `git checkout-index` export of the staged snapshot passed bare `bin/ci`: strict formatting
  and Clippy, 171 active library tests with 2 credentialed provider tests ignored, every binary and
  integration suite, 8 source-ingress contracts, 7 source-delivery contracts, 29 store/web contracts,
  14 scheduler contracts, 8 browser contracts, both manifest schema checks and optimized release
  build.
- Focused real-Git tests passed, including active background-child cancellation, durable-priority
  blocking, no background queue ahead of a foreground waiter, staged-fetch crash recovery and pack
  bounds. The AF_UNIX ingress suite passed outside the restricted sandbox.
- `git diff --cached --check` and `systemd-analyze verify` passed; the latter emitted only expected
  sandbox SO_PASSRIGHTS/SO_PASSCRED warnings.

INSPECT FIRST
- `src/source.rs`: source schema V4, wake-up admission/drain/policy reconciliation, priority hooks.
- `src/source/git_repository.rs`: foreground/background admission, generation cancellation, guarded
  child termination and promotion boundary.
- `src/bin/rdashboard-source.rs`: startup ordering, per-project coordinator, deferred periodic retry,
  remote-visibility retry and source export.
- `src/source_ingress_socket.rs` and `src/bin/rdashboard-source-ingress.rs`: protocol and HTTP bounds.
- `src/installed_source.rs` and `src/bin/rdashboard-source-config.rs`: exact catalog/credential binding.
- `tests/source_ingress_contracts.rs` and staged systemd units.
