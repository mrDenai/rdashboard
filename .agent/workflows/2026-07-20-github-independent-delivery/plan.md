# GitHub-independent delivery implementation plan

- Workflow directory: `.agent/workflows/2026-07-20-github-independent-delivery`
- Status: implementation in progress
- Last updated: 2026-07-20
- Depends on: `brief.md`, `research.md`

## Outcome

Complete `rdashboard` as the narrow authoritative workflow and deployment control plane for every
installed project. GitHub remains the canonical source host and a fast signal origin, but no GitHub
Actions scheduler, hosted job, self-hosted runner, package registry round trip, or GitHub check result
is required to accept, verify, build, deploy, roll back, observe, or recover a release.

One repository-agnostic worker service per host prepares an exact source/dependency input once and
shares its sealed read-only result across execution slots. The VPS is the complete authoritative path.
The i9 host is optional leased compute for CI/pre-deployment receipts only and never owns required
state or a deployment artifact. Docker remains an application runtime and bounded final-image import
boundary, not the workflow scheduler.

The implementation is complete only when the exact repository gate, local release build, candidate
health, traffic cutover, rollback, resource accounting, cleanup, failure evidence, and self-update
recovery are all proven through the staged gates below. Existing multi-minute paths remain in shadow or
manual mode until they meet the target; the plan does not obtain speed by skipping verification.

## Fixed decisions and service-level objectives

- The normal delivery clock starts when the client receives a successful `git push` acknowledgement
  from GitHub and stops when an external request through the stable production route proves the new
  healthy release is serving traffic.
- Normal webhook path: push acknowledgement to signed accepted source head is at most 3 seconds in
  the declared capacity envelope. A miss is recorded as an SLO violation; it is not relabeled as a
  lost webhook merely because it was slow.
- Lost webhook path: periodic source reconciliation accepts the exact reachable `main` head within 60
  seconds. The attempt is labeled `trigger_reconciled`; its downstream preparation, verification,
  build and cutover budgets remain unchanged. This degraded end-to-end path may use the exceptional
  two-to-three-minute envelope.
- Normal warm code-only delivery is less than 60 seconds end to end, with a planning target of at most
  50 seconds p95 so the system has operating margin. Cold dependency/native/base/schema work may take
  two to three minutes only with an explicit measured reason. Five minutes is not an accepted steady
  state.
- Post-cutover soak, old-release drain, reporting, off-host archival and cleanup are measured
  separately. The operation remains `released_observing` while rollback monitoring is active; this
  does not move the cutover timestamp.
- Every onboarded repository uses the same worker pool, queue, lease protocol, source store and
  content-addressed preparation store. Project-specific behavior is selected only by a root-owned
  installed manifest and a fixed adapter ID; there are no project-specific worker services,
  persistent runner workspaces or queues.
- Each repository's bare `bin/ci` is the canonical required gate. Distributed execution can authorize
  a deployment only after conformance proves that bare `bin/ci` and the installed graph require the
  same step IDs, exact inputs and reduction rule. Until that proof exists, the worker runs bare
  `bin/ci` as one bounded job.
- The VPS must finish without i9. i9 registration never raises guaranteed capacity, extends a
  deadline, or supplies the release/OCI artifact.
- No workflow code receives production secrets, the production Docker socket, controller/executor/
  source authority sockets, host networking, production volumes or caller-selected root commands.
- Preserve at least 12 GiB of filesystem recovery headroom in addition to the measured admitted
  operation peak. Initial persistent workflow/source/cache state is capped at 6 GiB; disposable
  BuildKit state starts at a measured 1-2 GiB ceiling. These are activation limits to validate, not
  permission to delete current state.

## Existing seams to preserve

- `rdashboard-source` already owns the canonical bare repository, accepted-head ledger, signed source
  attestations, immutable source archive publication, restart reconciliation and the root-only live
  source gate. Its current generator is fixed to `rimg`; webhook/direct-push front doors and durable
  controller delivery are missing.
- `ControlStore`, `DurableController`, the root executor, signed operation intents, security journal,
  release bundles, build attestations, OCI handoff, disk reservation, fixed transient adapters and
  restart-safe `rimg` deploy/rollback path already exist. The non-root candidate producer and generic
  workflow scheduler/worker do not.
- `rdashboard-rimg-resources@.service` currently starts a root process for every five-second sample and
  retains failed instances. Replace this lifecycle before using resource measurements as activation
  evidence.
- `FailureCapsule` schema v1 is persisted in existing operation records. Schema v2 must remain able to
  read and render v1 records; an in-place schema break is not acceptable.

## Ownership and change boundaries

- Primary repository: `/home/denai/RustroverProjects/rdashboard`.
- First application repository: `/home/denai/RustroverProjects/rimg`.
- Second application repository: `/home/denai/RubymineProjects/sartuli.ge`.
- The current `rdashboard` worktree contains user-owned notification work, including edits to
  `src/bin/rdashboardd.rs`, `src/lib.rs`, `README.md`, web/store/test files and systemd documentation.
  Implementation must preserve that work and begin integration from its settled state; it must not
  reset, overwrite or accidentally stage those changes. Prefer new workflow/source/worker modules and
  binaries until the final narrow wiring change.
- The untracked `.agent/` trees in all repositories are workflow state and remain outside product
  commits.
- No push, production install, service restart, webhook/provider write, runner unregistration, cache
  deletion, deployment or self-update is authorized by this plan. Each external activation boundary
  below requires fresh authorization after its local gate and review pass.
- Every implementation slice ends with bare `bin/ci` in each repository changed by that slice, a
  final owned-diff inspection, a fresh substantive review for `rdashboard` changes, and one
  task-scoped local commit per changed repository. Never amend, push, or stage unrelated paths.

## Implementation steps

Implementation progress:

| Step | Status | Current evidence |
| --- | --- | --- |
| 1. Lifecycle, resource and failure evidence | In progress | Slice 1a locally completes the persistent peer-authenticated observer migration. Slice 1b locally completes Failure Capsule V2 plus capture-before-collection terminal and cleanup receipts for the existing fixed transient adapter boundary. Only the separately authorized live baseline/comparison remains in this step. |
| 2. Installed workflow and scheduler journal | Complete locally | Slices 2a-2c implement the strict V2 installed DAG, durable scheduler, single peer-authenticated cross-project worker gateway, bounded restart-safe renewal, cleanup-before-reuse and a bounded read-only controller/dashboard projection. The actual generic worker and sealed preparation store remain step 4. |
| 3-12 | Pending | Dependency-ordered behind the unfinished local/runtime boundaries; external activation gates remain unchanged. |

Implementation ledger:

- Slice 1a owns the new observer protocol/server/client, fixed Docker collector binary, observer
  service, rimg resource-client migration, removal of the legacy resource socket/template, contract
  tests, and the narrow controller/unit/documentation wiring. It deliberately leaves the pre-existing
  notification work untouched and unowned.
- Local verification: bare `bin/ci` passed on 2026-07-20 after two implementation-only correction
  cycles. The successful pass covered formatting, clippy, 176 library tests (2 ignored live-provider
  tests), 5 observer binary tests, 5 observer protocol/socket integration tests, all other Rust suites,
  schema validation, 8 browser tests, and the release build. Production installation and the one-hour
  old/new observation comparison were not run because they require a later external authorization.
- Fresh DeepSeek review reported no P0 and four P1/P2 items. Invalid-snapshot diagnostics, blocking
  task lifetime and signal-registration failure were fixed; the cold-start `signal_lost` observation
  was retained as an explicitly non-regressive in-memory-state limitation. The post-fix bare `bin/ci`
  passed again, and `review.md` records the exact staged diff and finding dispositions. The task-owned
  change is committed locally as `64e64f2` (`Add persistent resource observer`).
- Slice 1b discovery found that `execution_resource_receipts` currently records only executor lock
  acquisition/release, while fixed adapter jobs use `systemd-run --wait --collect` and persist no
  process/cgroup/storage evidence before collection. The coherent local scope is therefore: a strict
  reusable terminal/cleanup receipt contract; an installed `ExecStopPost` capture helper that runs
  before systemd collection; adapter-side start binding, receipt validation and post-collection cleanup
  proof; and a backward-compatible Failure Capsule V2 with canonical JCS and deterministic Markdown.
  It does not add a second security-journal truth or touch the dirty notification web projection.
- Slice 1b implementation adds strict digest-bound execution start, terminal and cleanup evidence;
  a fixed root-owned `ExecStopPost` helper that captures cumulative cgroup v2 CPU, memory peak/events,
  OOM, IO and task peak before collection; explicit storage and measurement gaps; exact start-to-terminal
  and terminal-to-cleanup chains; and fail-closed replay rules. New result documents cannot reconcile
  without successful terminal and complete cleanup receipts, while completed pre-slice jobs remain
  legacy-compatible. Failure Capsule V2 is canonical, capped at 64 KiB, redacts secrets/ANSI/control
  text before persistence, renders deterministic cause-first Markdown and leaves V1 JSON unchanged.
- Final post-review bare `bin/ci` passed on 2026-07-20: Clippy with `-D warnings`, 181 library tests
  with 2 credentialed live-provider tests ignored, all binary and integration suites, 4 new failure/
  receipt contract tests, schema validation, 8 browser tests and the optimized release build. No live
  systemd installation, VPS mutation or authorized baseline observation was performed.
- Two fresh `deepseek-free` reviews returned `SAFE`. The first found no P0/P1 blocker and two useful
  P2 hardening opportunities: bind terminal evidence to the exact start digest and distinguish a zero
  reserve from a real reserve deficit. Both were implemented and tested. The final exact-manifest
  review found no P0-P2 issue and approved the staged slice for a local commit; its P3 observations
  were verified as non-blocking contract/test hygiene.
- Slice 2a preserves the legacy V1 manifest/schema and adds a strict canonical V2 manifest whose
  workflow policy is a finite typed DAG. Profiles name only fixed adapters, worker pools, network and
  cache classes, bounded timeouts/resources and typed artifact contracts. The committed `ralert`
  catalog fixture is upgraded to V2 without enabling a deploy; production installation requires a
  separately generated canonical `.jcs` mirror and later authorization.
- The new scheduler tables live in `control.sqlite` under schema version 2 and do not replace the
  existing privileged security/effect journal. They persist stable request identity, trigger replay,
  source high-water state, attempts, nodes/dependencies, preparation keys, fair claims, leases,
  receipts, reductions, mutation locks and transitions in immediate transactions. Newer heads cancel
  only pre-mutation work; a failed or expired mutation lease retains ownership as `needs_reconcile`.
- Self-review after the first independent `SAFE` response strengthened the exact contract further:
  leases now carry and digest-bind the complete network/cache/timeout/resource/artifact profile;
  authoritative preparation and release remain VPS-required while optional i9 compute may claim only
  verification; persisted reductions revalidate every source lease/receipt after restart and enforce a
  monotonic evidence time; and success cannot discard a missing mutation lock or a failed conditional
  journal update. These corrections are covered by the scheduler contract suite.
- The final bare `bin/ci` passed with 184 library tests (2 credentialed live-provider tests ignored),
  every binary/integration suite, strict V1-to-V2 migration and schema checks, 10 scheduler contracts,
  8 browser tests and the optimized release build. End-to-end scheduler evidence now covers both the
  successful lock-release/new-head handoff and atomic terminal-receipt rollback when the held mutation
  lock is missing.
- Three `deepseek-free` rounds were used because each material correction changed the exact staged
  manifest. The closing review verified the one actionable P2 was fixed: expiry now counts every
  guarded row. `claim_next` combines expiry and claim in one immediate transaction; receipt submission
  deliberately retains a preceding expiry transaction because the gate proved a late-receipt error
  otherwise rolls the expiry back. The final exact staged code/config/test hash is
  `cf105882140ff6d8b57806823ee6e27cbda9497fc9ee806099bc0df3a204b2df`, with no open P0-P2 finding.
- Slice 2b adds one fixed unprivileged worker identity and AF_UNIX protocol for every installed
  project, without repository-selected commands or controller/privileged-executor pools. A separate
  networkless gateway owns scheduler access; the worker receives only canonical leases, cleanup
  obligations and attempt snapshots through a peer-UID-checked, bounded socket. The inactive systemd
  unit grants no Docker, source, executor, production-volume, capability or credential authority.
- Lease renewal preserves assignment, ID and generation, is bounded by the installed execution
  timeout and replays the current durable lease after a lost response. Expired, revoked and
  terminal-pending leases become explicit digest-bound cleanup debt. The scheduler atomically blocks
  every new claim for that worker/host until all debt is receipted, including after process restart;
  control schema V3 adds the cleanup journal with tested V1 and V2 reopen migrations.
- The final bare `bin/ci` passed after self-review tightened cleanup-before-reuse at the scheduler
  boundary and corrected the prior reissue test to require cleanup. It covered 184 library tests
  (2 credentialed live tests ignored), every binary/integration suite, 13 scheduler contracts,
  3 worker-socket contracts, both schema migrations, 8 browser tests and the optimized release build
  in 2 minutes 50 seconds. A fresh exact-manifest `deepseek-free` review returned `SAFE` with no open
  P0-P2 finding for staged hash
  `6f34022a5bd8ec926e14183c713d7a6151f1cba18171c66aefec09aa280d48bb`.
- Slice 2c adds a narrow read-only scheduler journal reader over a consistent SQLite transaction and
  exposes at most 50 newest attempts through the authenticated controller surface. Ordering and
  truncation are deterministic, the response timestamp is captured after the snapshot read, and the
  HTTP surface has no workflow mutation authority.
- The dashboard polls 20 attempts every five seconds without overlapping requests, validates an exact
  versioned wire contract and preserves the last valid snapshot on failure. It renders loading, empty,
  bounded, success, recovery, cleanup and stale-error states in a semantic table with a native refresh
  button, keyboard-scrollable overflow and centralized announcements. Modern web guidance was applied
  for semantics, error announcements and real overflow scrolling; no experimental browser dependency
  or polyfill was introduced.
- The post-correction full-worktree bare `bin/ci` passed with 184 library tests (2 credentialed live
  tests ignored), every binary/integration suite, 29 store/web contracts, 14 scheduler contracts,
  9 browser contracts and the optimized release build in 2 minutes 51 seconds. A refreshed exact
  staged export passed bare `bin/ci` independently after the review fixes: 167 library tests (2
  ignored), every binary/integration suite, 29 store/web contracts, 14 scheduler contracts, 8 browser
  contracts and the optimized release build in 2 minutes 49 seconds.
- The first fresh `deepseek-free` review found two P2 error-boundary defects: journal failures used a
  mutation-oriented 400 response with internal SQLite detail, and the clock path exposed its internal
  display value. Both now log the real error server-side and return the same fixed generic 500 problem;
  a corrupt-journal regression proves an internal marker cannot escape. The final exact-staged review
  returned `SAFE` with no P0-P2 finding for product/test hash
  `c33ee2422411e306b023cb12f2f69ed5f5b3a907a72260237b1ebd7d52d261df`.
- The in-app browser-control surface was not available in this session, so visual browser QA remains
  explicitly unperformed; static semantic, Rust wire-contract and JavaScript state-contract checks
  passed.

### 1. Establish trustworthy lifecycle, resource and failure evidence

Dependencies: none.

Observable outcome:

- One persistent, bounded, root-owned observer replaces per-sample systemd activation. It exposes only
  typed allowlisted host/application/workflow measurements over a peer-credential Unix protocol and
  never exposes the Docker socket or arbitrary container identifiers to the controller.
- Every workflow attempt has a canonical timeline and terminal resource receipt containing cgroup CPU,
  memory peak/events/OOM, IO, task peak, wall time, exit/signal/timeout, scratch/cache/log deltas,
  cleanup delta and remaining filesystem reserve.
- Failure capsule v2 is canonical JSON/JCS with deterministic Markdown rendering, bounded redacted raw
  log reference, causal step/error, resource/artifact/release context and explicit gap/truncation
  markers. Existing v1 records still decode and render truthfully.
- A baseline snapshot records current GitHub timing, bare-gate timing, deploy phases, host capacity,
  storage categories, current/LKG ownership and rollback state before any migration.

Likely boundaries:

- `src/domain/{events,telemetry,budget,failure,operation}.rs`, `src/store/{control,metrics}.rs`,
  `src/metrics/`, a new observer protocol/module and `src/bin/rdashboard-observer.rs`.
- `src/web/`, `src/bin/rdashboardd.rs` only for the final typed projection after the current
  notification slice is reconciled.
- New `deploy/systemd/rdashboard-observer.{service,socket}`, updates to
  `rdashboard-rimg-resources.*`, `rdashboard-tmpfiles.conf`, systemd documentation and the existing
  domain/metrics/store/web tests.

Verification:

- Bare `bin/ci` in `rdashboard` proves schema migration/reopen, v1 compatibility, bounds/redaction,
  typed protocol peer authorization, OOM/timeout/exit classification, terminal capture-before-unit-
  collection and dashboard rendering.
- In an authorized observation-only install, compare one hour of old/new samples, restart the
  observer/controller, force a bounded sample failure, and prove no retained failed template units,
  no raw Docker access outside the observer and no unbounded metrics/log growth.

### 2. Add the installed workflow model and durable scheduler journal

Dependencies: step 1.

Observable outcome:

- A versioned root-owned project manifest describes a finite typed DAG: source acceptance, host
  preparation, required verification steps, release build, deterministic reduction, resource
  reservation, optional backup/migration, candidate health, cutover, released observation and
  rollback. It names fixed adapter IDs, input/output contracts, network/cache classes, timeouts,
  resource envelopes and artifact/health/rollback policy; it cannot contain arbitrary shell or
  repository-selected host paths/secrets.
- The controller persists stable request identity
  `(project, workflow-policy-digest, source-SHA, operation-kind)`, attempts, node states,
  preparation keys, worker leases, receipts, supersession, mutation ownership and cleanup state.
- Non-mutating work uses one fair cross-project queue. A project deploy is single-flight. A newer head
  can supersede only queued/preparation/testing/building work; mutation/recovery work always finishes
  or reconciles first.
- A deterministic reducer rejects missing, duplicate, expired, late, wrong-host, wrong-input or
  wrong-policy receipts and proves the complete required step set before candidate admission.

Likely boundaries:

- `src/domain/manifest.rs`, generated `config/schema/`, `config/project-manifests/`,
  `tests/project_manifest_catalog.rs` and repository-manifest documentation.
- New workflow domain/scheduler/protocol modules, `src/controller.rs`, `src/store/control.rs`,
  `src/protocol/`, authenticated local worker socket wiring and controller/web operation projection.
- Migrate the existing `ralert` manifest through the versioned loader as the non-`rimg` proof that
  catalog loading and scheduling are repository-agnostic; do not enable a deploy merely by loading a
  manifest.

Verification:

- Bare `bin/ci` in `rdashboard` proves strict manifest decoding, schema upgrades, request deduplication
  across all trigger channels, fair scheduling, single-flight deploy, safe supersession, crash/reopen,
  lease expiry, late/duplicate receipts and fail-closed reduction.
- A contract fixture with two different project manifests must use the same queue/worker protocol and
  must not introduce a project-specific worker path or service name.

### 3. Complete multi-project source ingress and durable controller delivery

Dependencies: steps 1-2.

Observable outcome:

- `rdashboard-source` loads an installed multi-project catalog rather than a fixed `rimg` document.
  Each project has its own read-only deploy key, pinned host keys, webhook secret, repository identity,
  installed policy and source controls; credentials are delivered by generated root-owned systemd
  drop-ins and are never serialized into the catalog.
- A separate bounded HTTP ingress accepts only configured GitHub push endpoints. It bounds headers and
  body, preserves the raw bytes, forwards through a dedicated peer-authorized broker socket, and
  returns promptly. The broker performs constant-time HMAC verification, delivery-ID deduplication,
  immediate high-priority `main` fetch and fast-forward acceptance; the payload never chooses the
  deployed SHA.
- The broker persists a signed accepted-source outbox. The controller consumes it through a separate
  least-privilege protocol, verifies source signature and installed policy, and idempotently creates
  the scheduler request. Controller outage or restart cannot lose the accepted head.
- Healthy reconciliation is scheduled so event-reachable `main` is fetched within a worst-case 60
  seconds (initial target: 30-second cadence, at most 5 seconds jitter, bounded concurrent per-project
  fetches). Prolonged GitHub outage is a distinct visible provider state; recovery resumes without
  inventing a stale success.
- Webhook-triggered work cannot sit behind a lower-priority periodic fetch. Each project has a
  generation-aware single-flight fetch coordinator: an in-progress reconcile may satisfy the webhook
  only if it observed that delivery's reachable head; otherwise the webhook schedules an immediate
  bounded follow-up before another periodic job. Cancellation/follow-up cleanup is explicit, and a
  held/slow reconcile is part of the <=3-second acceptance test rather than an unmeasured race.
- A forced-command SSH receiver admits only configured operator/project keys and
  `refs/heads/main`, uses quarantine, then calls the same acceptance/outbox path. GitHub/direct history
  disagreement remains `source_diverged_needs_owner`.

Likely boundaries:

- `src/source.rs`, `src/source/git_repository.rs`, `src/installed_source.rs`, `src/source_socket.rs`,
  `src/bin/rdashboard-source.rs`, and new source-ingress/outbox/forced-receive modules and binaries.
- Generalize `src/bin/rdashboard-source-config.rs`; add generated credential/drop-in inputs, dedicated
  ingress/receive sockets and units under `deploy/systemd/`; update `rdashboard-tmpfiles.conf` and
  `tests/source_build_contracts.rs`.
- Narrow controller event ingestion in the workflow modules from step 2. The controller still receives
  no repository path, deploy key, webhook secret or write access to source state.

Verification:

- Bare `bin/ci` in `rdashboard` proves bad/missing HMAC, oversized/unknown events, duplicate/reordered/
  stale delivery, fetch mismatch, fast-forward, rewind/divergence, lost webhook, broker/controller
  restart, outbox replay, multi-project credential separation, webhook arrival during a held periodic
  reconcile and direct-push quarantine/forced-command rejection.
- An authorized observation-only production drill keeps `auto_deploy=false`, records a real normal
  push acknowledgement -> accepted-head measurement of at most 3 seconds, drops one webhook and proves
  reconciliation acceptance within 60 seconds, then removes the test route without creating a deploy
  operation.

### 4. Implement the generic VPS worker, sealed preparation store and hard storage fence

Dependencies: steps 1-3.

Observable outcome:

- One non-root `rdashboard-worker` service serves every installed project and receives typed claims
  from the controller. A fixed root executor launcher starts only root-policy-listed job profiles under
  the build UID; neither the worker nor repository code can submit argv, mounts, units or credentials.
- Each host publishes atomic, checksum-verified immutable keys for
  `SourceSnapshot(repository, SHA)`,
  `DependencySnapshot(toolchain, lockfile, platform, policy)` and
  `PreparedRun(source, dependencies, workflow policy, generated inputs)`. Matching requests join one
  producer. Consumers mount shared entries read-only and receive only operation-owned COW/scratch/log
  state.
- The selected host storage backend enforces both bytes and inodes. Installation probes the live
  filesystem once: use project quotas when supported; otherwise mount a pre-sized dedicated worker
  filesystem. Activation fails closed if neither hard boundary can be proven. Preflight estimates and
  `du` sampling supplement but never replace enforcement.
- Shared CAS eviction is sealed-entry LRU/age based, pins in-flight/current/LKG/warm-window entries and
  refuses admission before the 6 GiB ceiling or 12 GiB emergency reserve is violated. Every transient
  unit, scratch tree, COW upper, rootless integration container/volume and OCI staging file has a
  durable ownership/cleanup receipt and startup reconciliation.
- Networked lockfile prefetch is a separate fixed step with allowlisted registries, integrity pins,
  disabled install hooks, no secrets and no private/loopback route. Verification/build are networkless.
  Rootless BuildKit assembles OCI output; rootless Podman is used only for declared disposable
  integration services. If the host cannot support the rootless boundary, automated build activation
  remains blocked until an equivalent fixed executor adapter is implemented and reviewed.

Likely boundaries:

- New `src/workflow/`, `src/worker/`, `src/preparation/`, worker protocol/store modules and
  `src/bin/rdashboard-worker.rs`; scheduler/controller integration from step 2.
- A new fixed workflow-job launcher adjacent to `src/adapter.rs`/`src/executor.rs`, not repository
  shell interpolation; installed worker/cache/quota configuration, service/socket/tmpfiles/sysusers
  inputs under `deploy/systemd/`.
- Extend `src/domain/budget.rs` and step-1 telemetry/failure contracts; add restart/concurrency/security
  integration tests.

Verification:

- Bare `bin/ci` in `rdashboard` proves same-key single-flight, atomic publication after crash,
  checksum/cache-poison rejection, read-only sharing, independent COW writes, fair multi-project slots,
  cancellation/TERM/KILL, output/scratch byte and inode exhaustion, cache eviction/pins, emergency-
  reserve rejection, orphan reconciliation, prohibited network/socket/mount access and captured
  terminal receipts.
- In authorized shadow mode, run two projects and four matching claims concurrently and prove exactly
  one source materialization/dependency preparation per host, no per-slot clone/cache, bounded peak
  disk/RAM/CPU and zero owned residue after the reconciler interval.

### 5. Produce and prove the `rimg` shadow candidate through the generic worker

Dependencies: step 4.

Observable outcome:

- `rimg` is the first installed adapter, but no `rimg`-named worker, queue or persistent checkout is
  created. The worker verifies the source archive, runs the exact unmodified bare `bin/ci` initially as
  one bounded shadow job, assembles a local OCI candidate, and publishes the existing canonical
  release-bundle/build-attestation/OCI handoff without admitting a mutation.
- The temporary compatibility path used to baseline the current Docker-requiring gate is isolated to
  shadow execution and cannot see deployment secrets or authorize release. It is removed once the
  artifact-native gate below is proven.
- Every shadow result binds the accepted head/sequence/attestation, source export, dependency and
  prepared-run digests, complete gate result, build inputs/base digests, OCI digest/size, resource
  receipt and cleanup receipt. It is compared with the current GitHub/Kamal output for exact SHA and
  runtime behavior.

Likely boundaries:

- `rdashboard`: generic worker adapter registry, `config/project-manifests/rimg.json`, installed source/
  workflow/build policy generation, existing `src/build*.rs`, `src/build_source.rs`,
  `src/oci_handoff.rs`, `src/installed_deploy.rs`, candidate-store tests and systemd documentation.
- `rimg`: no behavioral change is required for the first unmodified shadow baseline; preserve its
  unrelated `.agent/` tree.

Verification:

- Bare `bin/ci` in `rdashboard`; if any `rimg` product path changes in this item, bare `bin/ci` in
  `rimg` as well.
- Authorized shadow runs cover warm and completely cold preparation, worker/controller restart,
  killed build, corrupt source/cache/OCI, full cleanup and exact-source comparison. Record gate/build/
  image duration, artifact bytes, cgroup peaks and disk high water; no deployment request is admitted.

### 6. Refactor the `rimg` gate around shared preparation and meet the warm budget

Dependencies: step 5.

Observable outcome:

- `rimg` exposes a versioned internal CI contract consumed by both bare `bin/ci` and the installed
  worker adapter. Bare `bin/ci` still takes no shortcuts and remains the only repository gate.
- Native libvips, Cargo dependencies, test compilation, operational-script inputs, advisory data and
  the release binary are prepared once per key. Independent checks/test binaries may fan out from the
  same sealed input without rebuilding libraries. The production image consumes the verified native
  and release-binary artifacts and performs only minimal OCI assembly.
- A canonical required-step/input manifest and reducer prove equality between a bare invocation and
  distributed execution. Any tracked-source, Dockerfile or declared-generated-output mutation by a CI
  step fails instead of silently changing the frozen input.
- Candidate signing fails closed unless the attempt contains the current conformance receipt binding
  every required bare-`bin/ci` step ID and input digest to the installed distributed graph. The
  conformance contract itself is exercised by both repositories' bare gates, so it cannot be omitted
  from an activation-only test path.
- Verification and the exact VPS release build overlap only within the measured CPU/RAM/IO
  reservation. The resulting warm verification + release-build critical path is at most 35 seconds
  before deployment activation is eligible.

Likely boundaries:

- `rimg`: `bin/ci`, `bin/update`, native artifact/fingerprint/verifier scripts,
  `bin/build-runtime-image`, `Dockerfile.runtime`, a new versioned CI-contract file/driver and their
  existing operational contract tests.
- `rdashboard`: the fixed `rimg` prepare/step/reduce adapter, build evidence and conformance tests.

Verification:

- Bare `bin/ci` in both `rimg` and `rdashboard` proves the same complete required-step set, cold/warm
  preparation semantics, one native/Cargo preparation under four slots, deterministic reduction,
  mutation rejection, artifact/image digest binding and no task-owned residue.
- Authorized shadow evidence must show normal-source acceptance <=3 seconds, warm queue <=1 second,
  matching preparation <=3 seconds, verification + release build <=35 seconds, and enough measured
  remaining budget for candidate import/health/cutover. If not, keep deployment manual/shadow and
  optimize the measured gate; do not relax its required steps.

### 7. Activate `rimg` manual cutover, then code-only auto-deploy

Dependencies: step 6 and fresh production authorization.

Observable outcome:

- The signed accepted-source event creates the controller request, the generic worker publishes the
  exact candidate, and the existing root executor independently rechecks current source/policy/build/
  resource/backup evidence before any mutation.
- Immediately before the first mutation, the executor uses the existing root-only
  `/run/rdashboard-source/source.sock` `CheckLive` exchange to compare the operation's head, sequence
  and source-attestation digest and acquire the durable source mutation ticket. Broker unavailability
  blocks; it never substitutes a cached snapshot.
- The executor imports the local OCI once and uses the existing stable backend/router path: current
  stays live while candidate starts, health is proven through the stable route, traffic switches,
  then the attempt enters `released_observing`. No GHCR push/pull or GitHub check is consulted.
- Failure before mutation is retryable without rollback. Failure after switch returns the stable route
  to exact LKG and proves LKG health. Crash/restart at every durable boundary reconciles rather than
  repeats an ambiguous effect.
- Manual deploy is proven first with `auto_deploy=false`. Only code-only compatible releases become
  automatic after all gates below pass; stateful/breaking releases remain explicitly authorized.
- Before the first rdashboard-owned production mutation, quiesce the legacy GitHub mutation path
  reversibly: stop/disable its deploy runner or deploy job and remove its effective deploy credential/
  permission while retaining the installation needed to restore it deliberately. Comparison jobs may
  observe/build only and must have zero production-mutation authority. Permanent runner/workspace/cache
  removal remains step 11.

Likely boundaries:

- `rdashboard`: source-to-controller admission, worker-to-candidate completion, mutation admission,
  `src/deploy_driver.rs`, `src/kamal_adapter/runtime.rs`, operation states/web projection, installed
  rimg policies, systemd installation/runbook and existing executor/phase-6 tests.

Verification and activation gate:

- Bare `bin/ci` in `rdashboard` and `rimg`, then a fresh substantive review of the exact activation
  diff.
- With explicit authorization, drill pre-mutation failure, candidate health failure, switch failure,
  controller/worker/executor restart, host reboot at pending boundaries, automatic rollback, manual
  LKG rollback and clean-host restore. Confirm production traffic never uses an unverified release.
- Run the rdashboard path in parallel with the legacy GitHub workflow only for comparison; only the
  rdashboard result may mutate, and enforce that physically through the reversible legacy quiescence
  above rather than operator convention. Enable code-only `auto_deploy` after at least 20 consecutive
  correct shadow/manual attempts spanning at least 7 days, a current bare/distributed conformance
  receipt for every deployed step/input, every normal source acceptance <=3 seconds (p95 <=3 seconds),
  at least one deliberately dropped-webhook acceptance <=60 seconds, one successful rollback drill,
  zero unresolved cleanup receipts, the 12 GiB reserve and every normal warm end-to-end attempt below
  60 seconds (p95 <=50 seconds). A failed gate resets the acceptance window after its root cause is
  fixed.

### 8. Attach i9 as optional leased verification capacity

Dependencies: step 6. This item is optional and does not block steps 7, 9, 10 or 12.

Observable outcome:

- i9 runs the same repository-agnostic worker protocol and advertises temporary capabilities/slots
  through a mutually authenticated installed transport. It fetches and verifies the assigned exact
  SHA from GitHub, prepares its own host-local keys and receives only CI/pre-deployment shards.
- The controller assigns only work whose computed local latest-start deadline still preserves the VPS
  delivery budget. A short lease/heartbeat loss requeues locally; late duplicate receipts are
  idempotently ignored or recorded, never allowed to overwrite the authoritative result.
- i9 returns only bounded signed step/resource/failure receipts. OCI images, native release artifacts,
  caches, databases and deployment secrets are never transferred between i9 and VPS.

Likely boundaries:

- `rdashboard` worker registration/lease protocol, host-key policy, scheduler latest-start logic,
  receipt verification, optional remote transport configuration and operator documentation. Reuse
  the same worker binary and manifest vocabulary from step 4.

Verification:

- Bare `bin/ci` in `rdashboard` proves unauthorized host, wrong SHA/policy, lease expiry, disconnect
  during fetch/step, late/duplicate receipt, controller restart and local fallback.
- With separate authorization for the existing secure route/host key, drill i9 absent at admission,
  disconnect it in every phase, and prove equal final result/timing to VPS-only execution and zero
  artifact transfer. Do not expose a new public worker endpoint merely to enable this optional host.

### 9. Replace `sartuli.ge` duplicated setup with one prepared run and an exact distributed gate

Dependencies: steps 4 and 6; step 8 may improve latency but is not required.

Observable outcome:

- `sartuli.ge` uses one SourceSnapshot, one `bin/update`-equivalent dependency snapshot, one asset
  generation result and one schema-keyed database checkpoint per host/SHA key. Execution slots share
  pinned Ruby/native/Bun/gem/JS/base/database inputs read-only and receive only COW source, logs and
  isolated test namespaces.
- One rootless Postgres integration instance per PreparedRun clones separate test databases from the
  sealed template; Valkey namespaces are isolated. Four RSpec slots do not create four clones,
  `.titanium` trees, base builds, DB image preparations or complete Compose stacks.
- A versioned internal CI contract is shared by no-argument bare `bin/ci` and distributed execution.
  Assets, linters, Packwerk, JS/RSpec, audits and every currently authoritative security check are
  either in that exact gate or explicitly proven non-authoritative before GitHub jobs are removed.
  Fixing linters cannot silently modify the frozen deploy source.
- Only measured independent steps fan out. The full required step/input set and deterministic reducer
  remain identical with i9 absent. Verification and exact local production OCI build overlap within
  the VPS resource reservation.

Likely boundaries:

- `sartuli.ge`: `bin/ci`, `bin/update`, `docker-compose.ci.yml`, DB checkpoint tooling, Docker/base
  inputs, a versioned CI-contract driver/document, relevant CI/architecture/operational specs and
  `.github/workflows/pipeline.yml` only during coexistence/retirement.
- `rdashboard`: Sartuli manifest and fixed prepare/step/reduce/build adapter; generic worker code may
  change only for a capability that is not project-specific.

Verification:

- Bare `bin/ci` in both `sartuli.ge` and `rdashboard` proves bare/distributed step equality, one
  preparation under concurrent slots, database/Valkey cross-shard isolation, asset/input immutability,
  complete spec partition, shard loss/replay, deterministic reduction and local OCI binding.
- Authorized shadow runs with i9 disconnected must establish the cold/warm high water and the full
  push-to-candidate critical path. If the exact gate cannot fit the normal <60-second deployment SLO,
  Sartuli remains shadow/manual and work continues on measured test/runtime bottlenecks; it may not
  make every deployment an "exception" or authorize a partial suite.

### 10. Add the installed Sartuli deployment adapter and migrate production

Dependencies: step 9 and fresh production authorization.

Observable outcome:

- A root-owned Sartuli policy fixes roles, commands, health, proxy, mounts, environment/credential
  names, resource limits, data volumes, migration/checkpoint, backup, release classification and
  rollback. Repository `config/deploy.yml`, ERB and hooks are input for review only, never deployment
  authority.
- The worker publishes the exact local OCI; the executor imports it and uses a fixed local transport
  or direct local runtime path while preserving the current Kamal Proxy and application containers.
  No content is pushed to or pulled from GHCR, and i9 is never the artifact source.
- Candidate web/workers start without stopping current web traffic, migrations run only under the
  installed compatible policy, stable health/cutover is externally proven, and current/LKG images and
  rollback receipts remain independent of temporary registry/BuildKit state.
- Manual deployment and rollback are drilled before safe release classes are auto-admitted under the
  same acceptance window as `rimg`.
- Before the first rdashboard-owned Sartuli mutation, reversibly quiesce the existing GitHub deploy job,
  runner and effective registry/deploy permission. Keep only mutation-incapable comparison checks;
  permanent removal waits for step 11.

Likely boundaries:

- `rdashboard`: a dedicated installed Sartuli policy and fixed adapter profiles adjacent to, but not
  hidden inside, the rimg-specific phase-6 code; generic deployment/release interfaces are extracted
  only where both adapters genuinely share them. Extend executor intent/evidence/release-state and
  systemd/project policy inputs.
- `sartuli.ge`: production image/handoff metadata and deployment-health contract only; do not copy
  deployment authority back into repository scripts.

Verification and activation gate:

- Bare `bin/ci` in both repositories plus fresh review.
- With explicit authorization, drill compatible migration, migration rejection, each role failing to
  start, web health/cutover failure, rollback health, controller/worker/executor restart, reboot,
  accessory preservation and clean-host current/LKG restore.
- Enable safe automatic admission only after at least 20 consecutive correct shadow/manual attempts
  spanning 7 days, a current bare/distributed conformance receipt for every deployed step/input, every
  normal source acceptance <=3 seconds (p95 <=3 seconds), one deliberately dropped-webhook acceptance
  <=60 seconds, one rollback drill, zero cleanup debt, preserved disk reserve and every normal warm
  end-to-end attempt below 60 seconds (p95 <=50 seconds).

### 11. Retire only proven GitHub runner and oversized cache state

Dependencies: successful step 7 for rimg and step 10 for Sartuli; fresh destructive/external
authorization for each exact target.

Observable outcome:

- GitHub Actions may remain as optional hosted PR visibility, but no required branch/deploy status
  points at a self-hosted runner and no deployment workflow can race rdashboard. Direct source hosting,
  webhook and reconciliation remain.
- Each exact runner/deploy job is already reversibly quiesced by the applicable project activation
  step. After one successful rollback window it is unregistered and its explicit
  service/install/workspace is removed. Each image, container, volume and BuildKit entry is classified
  as current, LKG, application data, shared warm input or unreferenced before its owning engine removes
  it. Raw Docker/containerd directories are never deleted.
- Current + LKG + candidate remain per project, the off-host recovery copy is verified, shared worker
  state remains <=6 GiB, BuildKit remains within its measured 1-2 GiB bound, the filesystem reserve is
  >=12 GiB plus admitted peaks, and at least 14 GiB is measurably reclaimed without counting
  application data.

Likely boundaries:

- Repository GitHub workflow files and operational docs only after local authority is proven.
- Production runner services/registrations/workspaces, Docker/BuildKit engine-owned objects and
  rdashboard ownership/cleanup ledger. Exact live paths/IDs are resolved read-only immediately before
  every removal; stale research snapshots are not removal targets.

Verification:

- Bare `bin/ci` in every repository whose workflow files change.
- Before/after inventories and bytes, current/LKG restore, one push with GitHub Actions disabled, lost-
  webhook reconcile, controller/worker restart and no managed orphan after the bounded interval.
- Stop after each runner/cache class and retain its rollback procedure; never combine all removals into
  an unobservable global prune.

### 12. Implement `rdashboard` A/B self-update and controller-independent recovery last

Dependencies: steps 1-7, 9-11. i9 remains optional.

Observable outcome:

- The ordinary generic source/worker path builds a signed self-release bundle containing all versioned
  binaries, unit/config/schema metadata, compatibility rules, exact checksums and minimum bootstrap
  protocol. It cannot replace itself directly.
- A small root-owned `rdashboard-bootstrap` supervisor is installed outside versioned A/B release
  slots, runs persistently with `Restart=always`, owns a journal outside `control.sqlite`, verifies the
  pending signed descriptor, backs up/verifies every affected SQLite/config/security state, stages the
  inactive slot and validates it before stopping any component.
- The supervisor switches an atomic `current` pointer, starts source/observer/executor/worker/controller
  in dependency order and judges an external authenticated health contract. Failure, OOM, crash or
  reboot replays the same journal and restores the old pointer/database when allowed; ambiguity becomes
  `needs_reconcile`.
- A root-only non-networked recovery CLI can inspect/reconcile an existing operation, restore exact
  current/LKG, or admit an exact prebuilt signed candidate with current source/policy evidence. It
  cannot run shell, select mutable tags/paths or bypass backup/migration/rollback policy.
- Updating the bootstrap supervisor itself is a separate explicit dual-slot host-maintenance action
  with the old supervisor boot-selectable until a reboot drill passes.

Likely boundaries:

- New self-release/bootstrap/recovery domain and journal modules, `src/bin/rdashboard-bootstrap.rs`,
  root recovery CLI, versioned release store, systemd ordering/units/tmpfiles, installed policy and
  authenticated health endpoint.
- Existing source/build attestation, executor authorization and controller operation projection are
  reused; the web/controller process receives no new root or self-update credential.

Verification and activation gate:

- Bare `bin/ci` in `rdashboard`, exact release-manifest verification and a fresh security/concurrency
  review.
- In an authorized disposable/staging host, inject failure before/after every journal/pointer/database/
  service boundary; kill/OOM the new controller, executor and supervisor; reboot in every pending
  state; test incompatible schema, corrupt bundle, old-version rollback, root-only LKG recovery and a
  clean-host offline restore with GitHub and Docker unavailable.
- Enable production self-update only after all drills pass twice from the installed recovery kit and a
  separately authorized manual self-update succeeds. Keep the prior complete release and recovery kit
  until the new release survives the declared observation window.

## Rollout, rollback and cleanup order

| Stage | Production authority | Rollback/disable action | Cleanup allowed |
| --- | --- | --- | --- |
| Evidence/source observation | Existing GitHub workflows | Stop new observer/ingress and keep existing collection/source state | Only task-owned failed test units/files |
| Generic worker shadow | Existing GitHub workflows | Stop worker claims; source/controller ledgers remain replayable | Only operation-owned shadow scratch/CAS entries under policy |
| Manual project cutover | rdashboard for one explicit attempt | Stable route to exact LKG; set `auto_deploy=false` | Candidate scratch after terminal cleanup receipt |
| Parallel acceptance window | rdashboard is sole mutation authority; the legacy deploy job/runner/credential is reversibly quiesced and GitHub comparison is mutation-incapable | Disable local auto-admission and deliberately restore the retained legacy path only after rdashboard mutation is fenced off | No permanent runner/cache removal |
| Runner/cache retirement | rdashboard | Reinstall/re-register exact runner from retained config if acceptance regresses | Exact classified legacy state, one class at a time |
| Self-update | persistent bootstrap supervisor | Restore prior A/B pointer and compatible database | Prior self release only after observation/recovery retention expires |

## External authorization gates

These are action boundaries, not unresolved architecture choices:

- Register per-project GitHub deploy keys/webhook secrets and route the narrow webhook endpoint.
- Install/start source, observer, worker, quota/build services and their root-owned policies.
- Run shadow workloads or production failure/reboot drills that consume VPS/i9 resources.
- Admit a manual production candidate or change any project's `auto_deploy` flag.
- Register i9's host identity/transport.
- Disable/unregister runners or remove workspaces/cache/image state.
- Install or activate the bootstrap supervisor and execute self-update.

## Completion criteria

- All user decisions U001-U005 remain represented: GitHub source without runner dependence, one
  efficient all-repository worker pool, optional non-blocking i9, <=3-second normal source acceptance,
  <=60-second lost-webhook repair, <60-second normal end-to-end delivery, bounded resources/files and
  rdashboard-owned deploy/self-deploy/failure evidence.
- `rimg`, `sartuli.ge` and `rdashboard` each pass their exact bare gate and their respective shadow,
  rollback, restart and recovery gates without relying on i9 or GitHub Actions.
- No project is auto-enabled while its exact gate remains multi-minute or its resource high water,
  rollback, cleanup or failure evidence is unproven.
- Normal workflow state is within the installed disk/cgroup budgets, the 12 GiB reserve is preserved,
  managed orphan count returns to zero, and legacy runner/cache reclamation is measured rather than
  assumed.
- The dashboard shows accepted source, queue/preparation/verification/build/cutover/soak/cleanup
  timings, per-attempt resources, trigger class, current/LKG and deterministic failure capsule without
  requiring GitHub logs.
- Every substantive implementation diff has no unresolved P0-P2 review finding, all affected bare
  `bin/ci` gates are green, owned paths are committed locally, and all external mutations are recorded
  separately with exact rollback evidence.

## Plan audit ledger

- Route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`; dispatcher status `ANSWERED`, one
  attempt, 114 seconds. Draft repository fingerprint
  `a401ae85ed5c1a202cdcc4b2f288201d753bbfcff50c01501753726e849f2c05`; ignored artifact hashes were
  brief `a10a93d6abbcb40dda806eafdb7cbf789cc7b3c0cd6452ca40374e55a75c5e4f`, research
  `8b228e80e20cd8f21f478f8fdc84b03d7987410be16152480edcc042c26d3b5b`, and plan draft
  `822b984a0fbffcb31f097931022d6f3ba28843cc4ce86826af4cd6cffcaef721`. Response:
  `/tmp/rdashboard-delivery-plan-audit-response.md/response.md`.
- Accepted P1: the legacy deploy path cannot merely be called "comparison only" while its runner and
  credentials can still mutate. Steps 7 and 10 now require reversible physical quiescence before the
  first rdashboard mutation; step 11 performs only later permanent removal.
- Accepted P2: source <=3-second/<=60-second proofs are repeated across each project's activation
  window, not treated as a one-time source-pilot result.
- Accepted P2: a current bare/distributed step-and-input conformance receipt is now a candidate-signing
  and activation prerequisite exercised by both repositories' bare gates.
- Verified open question: the current executor already constructs `SourceBrokerClientV1` for the
  root-only source socket, calls `LiveSourceGate::check_live`, binds head/sequence/attestation evidence
  and holds a durable mutation ticket. Step 7 now names this existing protocol explicitly.
- Accepted open-question hardening: step 3 now requires generation-aware webhook priority/follow-up and
  a held-reconcile acceptance test so periodic work cannot silently consume the normal three-second
  budget.
- No remaining P0-P2 plan-audit finding is unresolved. No implementation gate was completed and no
  production drill or external mutation was run during planning. A final artifact-review command
  accidentally started bare `bin/ci`; it was stopped while Cargo was attempting to update its index,
  left no Cargo manifest/lockfile diff or running Cargo/Rust process, and is not verification evidence.
