# GitHub-independent delivery architecture research

- Workflow directory: `.agent/workflows/2026-07-20-github-independent-delivery`
- Status: complete
- Last updated: 2026-07-20

## Decision reached

Complete the narrow `rdashboard` control plane with one repository-agnostic worker pool, an
authoritative VPS path, optional non-blocking i9 capacity, host-level single-flight preparation,
artifact-first local deployment, hard resource fences, deterministic failure evidence, and a separate
self-update supervisor. Do not install a generic CI platform or retain GitHub runners in the
authoritative path.

The delivery SLO starts when GitHub accepts `git push` and ends when production traffic reaches the new
healthy release. Verification, release build, artifact handling, candidate startup, health validation,
and cutover are inside the less-than-60-second normal warm budget. Post-cutover soak, old-release drain,
asynchronous reporting, and cleanup are separate phases and cannot be used to redefine the cutover time.

## Executive recommendation

Finish the control-plane direction that is already implemented in this repository instead of
installing another CI product:

1. Treat a GitHub webhook as a low-latency hint, not durable truth. The isolated
   `rdashboard-source` broker fetches and validates `main`; a periodic fetch/reconcile repairs a lost,
   delayed, duplicated, or out-of-order webhook. Keep the already-designed direct `git push prod
   main` channel as an explicit emergency path, with divergence failing closed.
2. Add one repository-agnostic non-root `rdashboard-worker` pool, not one worker installation or
   workspace per repository. A host prepares each exact source/dependency/build input once, then its
   execution slots share those immutable inputs and receive only independent shards plus small
   copy-on-write scratch. Duplicate requests for the same preparation key join one in-flight producer
   instead of recloning or rebuilding libraries.
3. Keep privileged mutation in the existing fixed-argv executor. It admits only the exact current
   source head, signed project policy, signed build result, resource reservation, backup/rollback
   prerequisites, and idempotent operation state.
4. Use artifact-first builds. Persist the small verified native/application artifact and only a
   bounded dependency cache. Build or import the final OCI image locally; do not push it to GHCR and
   pull it back to the same VPS. Retain only current and last-known-good release artifacts plus a
   bounded encrypted off-host copy.
5. Keep Docker as an application runtime where the application actually benefits from containers,
   but stop using Docker containers and GitHub runners as the workflow scheduler. Do not replace the
   production runtime or Kamal Proxy during the first migration merely to change technology.
6. Self-update `rdashboard` through a separate executor-admitted A/B protocol. A tiny persistent
   bootstrap supervisor, installed outside the versioned release and restarted at boot, owns
   continuation, health arbitration, pointer switch, database backup, and rollback. A transient
   upgrader alone is not a sufficient liveness boundary.
7. Record cgroup and disk evidence for every workflow attempt, enforce hard scratch/cache storage
   fences and resource reservations before starting, clean operation-owned scratch deterministically,
   and reconcile labeled leftovers after a crash.
8. Upgrade the current failure capsule to a deterministic versioned JSON envelope with causal error,
   process outcome, resource peaks, artifact digests, redaction evidence, and bounded context. Render
   that same envelope as concise Markdown for an LLM or operator; an LLM summary remains optional and
   non-authoritative.

The VPS path is always authoritative. The intermittently available i9 host may advertise temporary
execution slots for CI/pre-deployment shards only; it never carries a deploy artifact, never owns a
required preparation result, and its disappearance causes a short lease expiry and local requeue.

This is a completion of the repository's existing trust boundaries, not a new architecture reset.
The `rimg` pilot should be completed first, then `sartuli.ge`, and only then `rdashboard` self-update.

## Success criteria

- A push is detected reliably even if any single notification is missed, duplicated, delayed, or
  reordered.
- GitHub is a source host and signal origin, not the workflow runtime or deployment authority.
- The critical path removes unnecessary checkout, image-build, registry, and container-restart work
  where project contracts allow it.
- Every admitted normal warm, code-only delivery targets less than 60 seconds from GitHub accepting the
  push until production traffic reaches the new healthy release. Genuinely irreducible
  cold/dependency/native/schema work is explicitly classified and normally targets two to three
  minutes rather than silently redefining five minutes as acceptable.
- One shared worker pool serves every onboarded repository. Parallelism never implies one persistent
  clone, dependency installation, native-library build, or base-image preparation per execution slot.
- CPU, RAM, disk, network, cache growth, queueing, timeouts, cancellation, and cleanup are explicitly
  bounded and observable per operation/project.
- Deploys detect partial failure, retain a known-good version, and roll back without relying on the
  process being replaced.
- `rdashboard` can update itself without granting its web/controller process unrestricted root,
  Docker-socket, repository, or secret access.
- Failure evidence is deterministic, redacted, bounded, correlated, and useful both to an operator
  and an LLM without dumping raw provider logs.
- The design supports heterogeneous repositories without becoming a full hosted-CI clone.
- Migration proceeds incrementally with fail-closed activation and measurable acceptance thresholds.

## Constraints and boundaries

- Research is read-only except for these workflow artifacts.
- Canonical source remains hosted on GitHub.
- No GitHub-hosted or self-hosted Actions runner may remain in the deployment execution critical path.
- Existing `rdashboard` broker, authorizer, executor, notification, and operation-journal boundaries
  must be reused or deliberately superseded based on source evidence.
- Current production/runtime facts are volatile and were rechecked live on 2026-07-20 where safe.
- No production mutation, provider write, push, deployment, service restart, cache deletion, or secret
  disclosure is authorized by this research.
- Each repository's bare `bin/ci` remains its required verification gate. The orchestrator may remove
  duplicated setup around it, but must not weaken or replace it with selected checks.
- Repository contents and dependency downloads are untrusted relative to root, production secrets,
  the production network, and deployment authority even when all repositories are operator-owned.

## Evidence ledger

### Existing `rdashboard` direction and implementation

- `PLAN.md:388-470` already specifies the core source contract: an isolated bare repository, HMAC
  webhook hint, deduplication, fetch-before-enqueue, fast-forward-only accepted head, periodic
  reconciliation, optional forced-command direct push, signed accepted-head attestation, immutable
  source export, isolated `CI=true bin/ci`, and local OCI handoff.
- `PLAN.md:475-495` says source admission, durable source journals, immutable export, signed build and
  OCI contracts, fixed executor effects, and restart-safe first bootstrap exist locally. It also says
  the webhook/quarantine front doors, constrained producer service, installed upgrades, and rollback
  activation remain incomplete.
- `deploy/systemd/README.md` says the source unit generator deliberately sets `auto_deploy=false`, and
  that webhook and forced-push ingress are not yet routed. `rdashboard-source.service` exists in the
  repository but was not installed on production in the live check.
- The controller and executor are installed and active on production. The source broker is
  `not-found`; therefore the source-to-build-to-deploy loop is not operational even though much of its
  contract exists locally.
- `src/kamal_adapter/runtime.rs:976-1062` already implements the important steady-state `rimg` shape:
  verified local OCI import, stable backend, stable router, health-based switch, old backend stop, and
  rollback. The ephemeral registry/Kamal path at approximately `1157-1192` is a bootstrap boundary,
  not required for every stable release.
- `PLAN.md:1034-1038` correctly excludes `rdashboard` from the generic controller-driven project path:
  executor-owned continuation and rollback must remain alive while the controller is stopped.
- `src/domain/failure.rs` currently persists only schema version, failing step, a small structured
  error, a redacted excerpt, and truncation. The intended contract in `PLAN.md:712-735` is richer and
  includes project/SHA/operation, exit or signal, timeout/OOM, causal error, versions, releases, and
  health evidence. The implementation is therefore a useful base but not yet sufficient for the
  requested LLM-readable operational diagnosis.

### Current GitHub workflow evidence

Read-only `gh` inspection on 2026-07-20 found:

- `rimg` maintenance run `29736435680` took 10m18s end to end. Hosted verification took 4m05s and the
  self-hosted deploy job took 6m06s. Inside deploy, storage preparation took 1m28s and Kamal deploy
  took 4m28s.
- The same run's logs attribute about 114.234s to Docker build/push, about 7.5s to manifest push, and
  then 2.957s to deleting the local tag and pulling that exact image back from GHCR on the same VPS.
  Pre-app work took 12.099s, candidate boot/health approximately 7s, and a deliberate post-app soak
  125.567s. The soak is safety policy; it should become an explicit `released_observing` phase rather
  than be mistaken for transport or startup time.
- `rimg` run `29580086966` was created at 12:23:57, but its first hosted job started at 12:47:38: a
  23m41s scheduler wait before useful work. The self-hosted deploy started approximately 35m30s after
  the trigger. The deploy itself took only 2m32s. This is direct evidence that GitHub scheduling can
  dominate delivery latency independently of project execution time.
- `sartuli.ge` warm push run `29745064094` completed in 5m43s. A base-refresh run `29742371302` took
  13m37s, with 8m50s in base-image preparation and 10m53s in the image-build branch. Its current
  workflow also provisions/uses multiple persistent self-hosted runner workspaces and repeats checkout
  and update/setup work across jobs.
- The duplication is contractual, not incidental. In `sartuli.ge/.github/workflows/pipeline.yml:67-140`,
  database preparation and the main CI job each perform their own checkout and `bin/update`.
  `pipeline.yml:190-240` explicitly says each RSpec shard runs on a potentially different machine,
  performs another checkout and `bin/update`, and creates a distinct `COMPOSE_PROJECT_NAME`.
  `bin/ci:208-212,239-254,377-432` then creates/migrates a database per test worker, partitions specs,
  and gives every worker a separate Compose stack. `pipeline.yml:246-317` performs yet another checkout
  and update for the production image. Parallel execution currently multiplies preparation rather than
  sharing it.
- GitHub can remain useful for optional PR/check visibility, but no GitHub check conclusion should be
  required to authorize production deploy. The `rdashboard` workflow result is authoritative; a GitHub
  status update, if later added, is an asynchronous mirror only.

### Current VPS resource evidence

A read-only production snapshot on 2026-07-20 found:

- Host capacity: 4 vCPU, 15.61 GiB RAM, 67 GiB root filesystem, 51 GiB used, 17 GiB available (76%
  used).
- Actual directory usage: `/var/lib/containerd` 8.9 GiB, `/var/lib/docker` 7.8 GiB, and
  `/home/deploy/runners` 10 GiB. These independent paths total approximately 26.7 GiB before other
  language and application build directories, so the user's 30-40 GiB concern is directionally
  supported.
- Docker's logical accounting reported 9.397 GiB of images (3.61 GiB reclaimable), 7.687 GiB of
  volumes, 1.98 GiB of build cache, and 254.6 MiB of containers. These categories are not safe to
  delete by raw filesystem removal and should not be added to `du` as if they were independent.
- The largest Docker volume was the long-lived BuildKit state volume at 6.169 GiB. PostgreSQL data was
  approximately 1.4 GiB and is not cleanup residue.
- Four GitHub runner installations plus their workspaces occupy most of the 10 GiB runner tree:
  `rimg-deploy`, `sartuli-ci-1`, `sartuli-ci-2`, and `sartuli-deploy`. Three Sartuli workspaces alone
  contain independent `.titanium` trees of approximately 855 MiB, 860 MiB, and 1.1 GiB; the deploy
  workspace is approximately 3.9 GiB, including a 2.8 GiB `.git` directory.
- Current Docker retention includes two approximately 1.1 GiB Sartuli app images, an approximately
  2.22 GiB development/base bundle, an approximately 1.54 GiB gem builder, and a 1.52 GiB Semgrep
  image. These may be legitimate caches or rollback inputs; ownership and reachability must be proven
  before deletion.
- Only one stopped old Sartuli worker container (about 31 MiB) was visible. The current large footprint
  is therefore mainly retained images, BuildKit state, volumes, and duplicated runner workspaces, not
  a large present population of orphan containers.
- The four runner cgroups showed sizeable `MemoryCurrent` values, but process RSS was small. Cgroup
  memory can include charged file cache, so this snapshot does not prove a runner memory leak. The
  disk and scheduling costs are established without making that claim.
- Native `rdashboard` binaries are small (roughly 5.8-11 MiB each), and live controller/executor
  process RSS was roughly 14 MiB and 3.8 MiB. A native controller/worker control plane does not need a
  CI server-sized resident footprint.

### Cache boundary evidence

- Prior production evidence in
  `.agent/workflows/2026-07-19-dashboard-automation/research.md:79-84` showed approximately 6.431 GiB
  of reclaimable BuildKit state. Keeping the full graph reduced an unchanged native image build from
  about 19 minutes to about 14 seconds; simply lowering GC would cause repeated expensive cold builds.
- The verified native application artifact is 76,461,440 bytes and the optimized local runtime image
  is 49,851,164 bytes
  (`.agent/workflows/2026-07-19-dashboard-automation/review.md:52-57`). The retained multi-gigabyte
  compilation graph, not the release payload, is the dominant issue.
- The local `rdashboard` repository itself illustrates the same risk: its `target` tree is about 35
  GiB, with roughly 33 GiB under debug output. Language-level caches also require quotas and cannot be
  treated as harmless merely because Docker is removed.
- Conclusion: cache is valuable, but the cache boundary is wrong. Preserve lockfile/toolchain-keyed
  dependency and verified artifact reuse; make intermediate compilation/build graphs replaceable and
  bounded.

### Resource collector defect discovered during research

- The socket-activated `rdashboard-rimg-resources@.service` has been activated approximately 49,000
  times over roughly 2.8 days (one collection path every five seconds).
- Exactly 370 failed template instances were retained in systemd at inspection time. Earlier
  commentary described this as "thousands of failed instances"; that was incorrect. The correct
  distinction is approximately 49,000 total activations and 370 retained failures.
- The failures are expected fail-closed observation gaps, but the unit lacks
  `CollectMode=inactive-or-failed`, so expected failures remain loaded until reset. One retained sample
  used about 10.1 MiB peak and ran 1.923s.
- This is not the VPS's main disk problem, but it is unnecessary lifecycle churn and operational
  clutter. A persistent bounded observer is preferable for five-second sampling. If per-connection
  activation remains, capture the result first and set `CollectMode=inactive-or-failed` or use
  `systemd-run --collect` so failed transient state is collected too.

### Primary documentation checks

- GitHub documents that webhook receivers should authenticate with a secret, reply within ten seconds,
  process asynchronously, deduplicate by `X-GitHub-Delivery`, and redeliver missed events. GitHub also
  explicitly says failed deliveries are not automatically redelivered. Therefore a webhook alone is
  not a durable trigger; local periodic source reconciliation is required.
- Git's official hook documentation confirms that `post-receive` runs after successful remote ref
  updates and receives the old object, new object, and ref. This supports a direct-push wake-up
  channel, but not bypassing the same broker admission rules.
- Docker documents local OCI/Docker exporters and a `local` exporter for minimal build artifacts. A
  local OCI archive is a supported first-class output; a same-host registry round trip is not required
  by the build tool.
- Docker documents periodic BuildKit garbage collection with configurable reserved, maximum-used, and
  minimum-free space. GC can enforce a bound, but it cannot choose the correct application artifact
  boundary on its own.
- systemd documents transient services, cgroup accounting, `MemoryHigh`, `MemoryMax`, `CPUQuota`, and
  aggressive collection of failed transient units through `--collect` / `CollectMode=inactive-or-failed`.
  It also warns that collected unit result fields disappear except for information persisted in the
  log subsystem, so `rdashboard` must capture its own terminal receipt before collection.

## Root causes

| Symptom | Established cause | Correct boundary |
| --- | --- | --- |
| Pipeline sometimes starts tens of minutes late | GitHub scheduler and runner availability are in the critical path | Local durable queue keyed by accepted source SHA |
| Pipeline does not trigger reliably | Webhooks are hints and GitHub does not auto-redeliver failed deliveries | Webhook plus periodic fetch/reconcile, with direct push as explicit fallback |
| 10 GiB runner tree | Four runner installations and duplicated persistent workspaces/caches | One bare repository, immutable export, one operation scratch tree, one shared bounded cache |
| Four-way tests repeat checkout, dependencies, generated assets, DB setup, and Compose lifecycle | GitHub jobs are isolated by runner/workspace and each shard self-prepares | Single-flight preparation once per host; immutable prepared input shared by execution slots; only independent tests fan out |
| 6+ GiB BuildKit volume | Full native compilation graph retained to buy warm speed | Persist small verified artifact; keep BuildKit only for final assembly under GC limits |
| Same image is pushed and pulled on one host | Registry-centric workflow inherited from GitHub/Kamal path | Local OCI archive/import with digest verification |
| Slow workflow teardown and leftovers | General runner/container lifecycle with weak ownership reconciliation | Operation ledger, exact resource labels, bounded stop/kill, startup reconciler |
| No concise causal error | Raw logs and current capsule V1 omit operation/resource/artifact context | Deterministic failure capsule V2 plus bounded raw-log reference |
| Self-deploy trust loop | Controller cannot safely replace the authority and database it owns | Immutable persistent bootstrap supervisor with its own journal and A/B slots |

## Viable alternatives

### A. Complete the narrow `rdashboard` control plane — recommended

**Advantages**

- Reuses implemented source, attestation, executor, rollback, backup, telemetry, and notification
  contracts.
- Removes all GitHub runners and repeated workspace copies from the critical path.
- Can choose artifact-native execution per repository instead of forcing every step into a container.
- Keeps one operator surface and one durable operation journal.
- Adds only the missing broker ingress, build producer, scheduler policy, and self-upgrade protocol.

**Costs and risks**

- `rdashboard` becomes production infrastructure and needs conservative upgrade/recovery discipline.
- Isolation, cancellation, cache ownership, and workflow schemas must be deliberately implemented.
- It should support a small installed workflow vocabulary, not arbitrary GitHub Actions compatibility.

### B. Install Woodpecker, Forgejo Actions, or Concourse

**Advantages**

- Mature generic workflow parsing, queues, logs, multi-worker support, and existing ecosystem.
- Faster route if arbitrary third-party workflow features are more important than resource minimalism.

**Costs and risks**

- Official documentation confirms these systems still consist of a server plus agents/runners or
  workers; Forgejo hands jobs to runners, Woodpecker agents poll the server over gRPC, and Concourse
  workers run container/containerd infrastructure and a worker data directory.
- This recreates the exact server/runner/container/cache estate the task is trying to remove, while
  `rdashboard` would still need separate deploy authority, resource accounting, and self-update.
- It either makes `rdashboard` a passive UI or duplicates scheduling truth across two systems.

**When to reconsider**

- Only if the scope expands to many teams, unreviewed third-party repositories, arbitrary matrix
  workflows, or a worker fleet where a purpose-built project manifest is no longer sufficient.

### C. Bare Git hooks plus shell scripts and systemd units

**Advantages**

- Smallest install and fastest notification path.
- Direct `post-receive` can operate during a GitHub webhook outage.

**Costs and risks**

- A hook is not a durable scheduler, authorization journal, rollback coordinator, resource budget, or
  self-update bootstrap supervisor.
- Shell hooks easily mix untrusted repository state with deploy privileges and make crash recovery or
  duplicate delivery ambiguous.
- Adding the missing correctness eventually reconstructs the existing broker/executor design badly.

**Disposition**

- Keep a forced-command direct push only as an input channel to `rdashboard-source`; do not let the hook
  run CI or deploy.

### D. Pure periodic polling without a public webhook

**Advantages**

- No public webhook ingress or dependency on GitHub delivery behavior.
- Very simple recovery semantics.

**Costs and risks**

- Adds bounded trigger latency (up to 60 seconds in the selected degraded-path policy) and repeated
  remote fetches.
- A total GitHub outage still prevents fetching new code.

**Disposition**

- Polling is mandatory as the repair path. Keep the authenticated webhook as the fast path because it
  is cheap once isolated, but correctness must not depend on it.

### E. Keep GitHub-hosted CI and only move deploy local

**Advantages**

- Lowest migration effort and preserves GitHub's familiar PR UI.

**Costs and risks**

- Hosted scheduling delays and missed workflows still block the authoritative result.
- It does not meet the requirement that delivery be independent of GitHub runner infrastructure.

**Disposition**

- GitHub checks may remain as optional redundant signals during migration, never as deploy admission.

### Shared worker pool and opportunistic i9

Worker placement is no longer an operator decision. The VPS provides the complete authoritative path;
the i9 machine is optional burst capacity and its absence cannot prevent a workflow from starting or
finishing.

- Run one `rdashboard-worker` service per available host with multiple leased execution slots. It is
  repository-agnostic: a worker advertises toolchain, isolation, CPU/RAM, and network capabilities, not
  repository names. Any slot can execute any onboarded repository whose installed task requirements
  match those capabilities.
- The VPS capability set must cover every required task for every onboarded repository. i9 may advertise
  only a subset because it is an accelerator, but no repository is admitted whose complete workflow
  cannot run in the VPS pool alone.
- The controller schedules across all repositories with deploy-critical priority, per-project
  concurrency limits, and weighted fairness. There are no `rimg-worker`, `sartuli-worker`, or persistent
  per-repository runner installations.
- Every host owns a small content-addressed preparation store. The first request for an exact key
  materializes source, dependencies, generated inputs, test executables/assets, and an optional database
  checkpoint once. Concurrent requests for the same key join that in-flight producer instead of causing
  a cache stampede. Execution slots mount prepared content read-only and receive only a small
  copy-on-write upper layer, private database/schema namespace, logs, and scratch.
- Preparation is shared per host, not transferred blindly between machines. When online, i9 fetches the
  exact admitted SHA from GitHub into its own host cache, verifies the expected object/digests, executes
  leased CI or pre-deployment checks, and returns only bounded receipts/log evidence. It never builds or
  transports the deployment artifact and never receives deploy authority or production secrets.
- i9 registration is soft state. Work is offered to it only while heartbeats are healthy and the
  estimated saving exceeds fetch/setup cost. A lost lease makes that shard runnable on the VPS; no DAG
  gate depends on i9 registration, and no source/dependency preparation result exists only on i9.
- Every i9 shard has a local latest-start deadline derived from the end-to-end latency budget. If its
  receipt has not arrived by that point, the VPS starts the shard even if the remote lease has not yet
  expired and safely ignores a later duplicate receipt. This permits short bounded overlap only during
  failure/slowdown; it prevents an intermittent accelerator from consuming the delivery deadline.
- The local profile shares the production kernel, so hard cgroup and filesystem fences are mandatory.
  This is appropriate only for the operator-owned repository threat model; it is not multi-tenant
  isolation. If stronger containment is later required, add a separate always-on build host without
  changing the worker protocol or making intermittent i9 authoritative.

## Recommended architecture

```text
developer git push
      |
      +--> GitHub repository (source host)
      |       | webhook hint (fast, non-durable)
      |       +-------------------------------+
      |                                       |
      +--> optional `prod` remote              v
             forced receive command --> rdashboard-source <-- periodic fetch/reconcile
                                             |
                                   signed accepted head +
                                   immutable source export
                                             |
                                             v
                              durable controller job journal
                                             |
                          root-owned installed workflow policy
                                             |
                                             v
                         repository-agnostic worker scheduler
                          /                             \
              VPS worker (required)          i9 worker (optional)
                    |                                  |
         single-flight host prepare         exact-SHA host prepare
                    |                                  |
          shared read-only inputs              leased CI shards
             /              \                         /
       local CI shards   local release build          /
             \              /                        /
              +---- deterministic reduce <----------+
                              |
                 signed verification evidence +
                    local deployment artifact
                                             |
                                             v
                            narrow privileged executor protocol
                    reserve -> backup -> deploy -> health -> switch
                                             |
                           current/LKG receipts and rollback bundle
```

### 1. Source admission and trigger semantics

- Webhook receiver performs only request/body bounds, HMAC validation, event/ref filtering,
  delivery-ID deduplication, durable wake-up insertion, and a prompt 2xx response.
- The payload does not select the deploy SHA. The broker fetches `main` itself and compares the fetched
  head with the payload and its accepted-head ledger.
- Broker restart replays its durable ledger and reconciles the remote before advertising readiness.
  An operation waiting at the first-mutation gate remains visibly blocked/retryable while the broker is
  unavailable; the executor must not substitute a cached head and proceed, because that would defeat
  the live TOCTOU check. Measure warm recovery and set an availability SLO instead of weakening this
  fail-closed boundary.
- Reconcile on a jittered schedule whose reachable-state worst case is at most 60 seconds, using
  adaptive backoff during a prolonged GitHub outage. This bounds a missed-webhook delay without
  depending on GitHub's manual/API redelivery mechanism. A reconciliation-triggered attempt is an
  explicit degraded trigger class rather than part of the normal less-than-60-second end-to-end SLO.
- Stable request identity is `(project, workflow-policy-digest, source-SHA, operation-kind)`. Duplicate
  webhook, poll, or direct-push signals converge on the same request.
- Fast-forward only. A force push or disagreement between GitHub and a direct push pauses that project
  as `source_diverged/needs_owner`; never guess which side wins.
- Newer heads may cancel or supersede queued/testing/building attempts before the first mutation.
  Never cancel an attempt while backup, migration, cutover, health arbitration, or rollback is in a
  mutation phase; finish/reconcile it, then evaluate the newer head.

### 2. Workflow model: deliberately smaller than GitHub Actions

Each installed, root-owned project manifest declares a versioned finite DAG from typed step kinds.
The scheduler and workers are generic; only the manifest and repository-owned verification adapter vary
by project:

```text
source admission -> host prepare
                       |-> verification shards -|
                       |-> release build -------|-> deterministic reduce
                                                    -> reserve -> backup/migrate
                                                    -> candidate health -> cutover
                                                    -> released_observing -> complete/rollback
```

- Repository workflow YAML, arbitrary `uses:`, shell interpolation, and repository-provided deploy
  hooks are not authority.
- Root policy supplies fixed executable IDs, input/output paths, timeouts, network class, cache class,
  resource envelope, release class, health contract, and rollback contract.
- The repository can supply code and reviewed project scripts such as `bin/ci`; it cannot supply root
  command paths, host mounts, Docker privileges, production environment, or secret names.
- The controller journal persists request, attempt, preparation keys, leases, phase, transition,
  cancellation/supersession, shard receipts, reduction result, and terminal outcome. Per-project deploy
  is single-flight; non-mutating work is scheduled from one global fair queue across repositories.
- `prepare` is a first-class single-flight node, never an implicit preamble repeated by every shard.
  Its outputs are sealed before fan-out. A reduce node rejects missing, duplicate, stale, or
  input-digest-mismatched shard receipts and proves that the complete required step set passed.
- Each repository's bare `bin/ci` remains the canonical verification gate. Distributed execution is not
  allowed to replace it with a hand-picked subset. The repository adapter must make bare `bin/ci` use
  the same prepare/shard/reduce primitives locally, and a conformance test must prove that its required
  step IDs and input digests equal the installed distributed graph before that graph can authorize a
  deployment. Until then, run bare `bin/ci` as one bounded job and optimize only the setup around it.
- On the current 4-vCPU VPS, only one heavy preparation/compile/image operation runs at a time until
  measured headroom supports more. Independent low-cost checks may overlap, and the release build may
  run beside verification when their combined reservation fits.

### 3. Execution, reuse, and isolation

- Each host runs the same fixed-protocol `rdashboard-worker`. It creates transient jobs through the
  systemd D-Bus API (or an equivalent fixed adapter), not an interpolated shell command, under a
  dedicated `rdashboard-build` UID. Slots are concurrency tokens inside this service, not long-lived
  clones or separate repository-specific daemons.
- Use a three-level immutable key hierarchy:
  `SourceSnapshot(repository, SHA)`,
  `DependencySnapshot(toolchain_digest, lockfile_digest, platform, policy_version)`, and
  `PreparedRun(source_digest, dependency_digest, workflow_policy_digest, generated_input_digest)`.
  The preparation store publishes an entry only after validation and atomic sealing; interrupted
  producers leave no readable cache entry.
- A keyed single-flight lock makes all matching requests wait on one preparation producer. Once sealed,
  every shard receives the same read-only lower layers and its own bounded copy-on-write upper/scratch.
  This preserves isolation for tools that rewrite files while avoiding another clone or dependency
  installation. Cache population is single-writer; execution slots cannot mutate shared entries.
- For Rust, populate one toolchain/dependency snapshot and one shared target/test-artifact preparation;
  compile test binaries once where the test harness supports it, then run independent binaries or test
  partitions without rebuilding libraries. `fmt`, `clippy`, audit, operational tests, and release build
  may overlap only when Cargo locking and measured CPU/RAM show a real critical-path gain.
- For Rails/Sartuli, run one exact-source `bin/update`, asset generation, and schema-keyed database
  checkpoint per host. Test slots share pinned base/database images and generated assets, use separate
  database names or cloned checkpoint namespaces, and receive separate writable uppers/logs. Do not
  start a complete dependency build or database container stack per RSpec shard.
- Start with explicit `MemoryHigh`, `MemoryMax`, `CPUQuota`/weight, `TasksMax`, `RuntimeMaxSec`, IO
  accounting/weight, output quota, scratch quota, and an operation-specific working directory.
- Mount immutable source and checksum-verified dependency caches read-only. Redirect compiler output,
  temp files, and generated output to the operation scratch tree. Copy out only allowlisted artifact
  paths with type/count/size/digest checks.
- Put every writable COW upper, compiler target, cache-population staging area, image staging directory,
  and temp tree on a filesystem boundary with an enforced byte/inode quota. Use an ext4/XFS project
  quota, a bounded subvolume, or a fixed-size dedicated build filesystem according to the live mount's
  supported mechanism; a preflight estimate and `du` polling are observability, not enforcement.
- Separate networked dependency prefetch from networkless verification/build. Prefetch accepts only
  reviewed lockfiles, allowlisted registries, integrity-pinned packages, and disabled install hooks.
- Give workflow code no production secret, controller/executor/source socket, Docker socket, host
  network, loopback/RFC1918 route, or production volume.
- Use rootless Podman only where disposable integration services are required. Host-native execution
  in a hardened systemd sandbox is faster and smaller for trusted toolchains, but neither systemd
  sandboxing nor a rootless container is a separate-kernel boundary. A compromised dependency with a
  kernel escape could reach the production failure domain; do not describe the VPS profile as safe for
  unrelated tenants.
- Persist terminal exit/signal/OOM/resource evidence before unloading the transient service; then use
  `CollectMode=inactive-or-failed`/`--collect`.

The hard storage fence is not an operator-facing product choice. It is one shared project-quota-backed
build domain, not one filesystem per storage category or worker. A runaway job can consume only the
remaining global build quota and its operation envelope; it cannot consume the filesystem space
reserved for the running release, last-known-good rollback, database, logs, or recovery. Shared caches
use one LRU/age policy, so slots and repositories do not create private toolchain/cache copies.

### 4. Artifact, cache, and disk policy

- One source bare repository per project and one immutable snapshot per exact SHA on each active host;
  no persistent checkout per runner or slot.
- One content-addressed preparation/cache store and one immutable host toolchain installation per host,
  shared across every repository when keys are
  identical. Dependency entries are keyed by toolchain digest + lockfile digest + target platform +
  policy version; prepared-run entries additionally bind source and workflow-policy digests. Cache
  entries are untrusted, checksum-verified on read, and never deployment authority.
- Eviction operates on sealed CAS entries, not arbitrary directories. Pin only entries referenced by an
  in-flight attempt, current release, or measured warm window; evict unpinned least-recently-used entries
  before admission reaches the hard cache ceiling.
- One immutable application artifact per accepted release. For `rimg`, retain the approximately 76 MiB
  native artifact rather than the approximately 6 GiB BuildKit compilation graph.
- Assemble the runtime image from that artifact with a minimal context. Export OCI locally, verify its
  digest, and import/load it once. The Docker OCI exporter supports this directly.
- Retain current and last-known-good application artifacts/images/release bundles. Keep an encrypted
  off-host OCI/artifact copy for disaster recovery. Never rely on a live local registry as rollback
  state.
- BuildKit remains disposable final-assembly machinery. Configure GC with an explicit maximum, minimum
  free disk, age policy, and no cache reservation larger than the measured warm benefit justifies.
- Cleanup is ownership-based: every scratch tree, transient unit, optional build container/volume, OCI
  staging file, and candidate image has operation/project labels and a durable creation receipt. The
  terminal cleanup receipt proves removal; startup reconciliation handles crash leftovers.
- Docker/containerd directories are cleaned only through their owning engine after current/LKG/data
  reachability is proven. Never `rm` their storage directories.

Initial capacity targets to validate during the pilot, not promises:

- begin deterministic engine/store GC below 30 GiB available and preserve a hard 20 GiB filesystem
  reserve at every admitted build/deploy peak;
- measure a completely cold build's scratch and inode high water before admitting local automated
  builds; required free space is the reserve plus measured/padded build, backup, image, and log peaks;
- bound persistent workflow/source/cache state, excluding current/LKG runtime images and application
  data, to 6 GiB total;
- bound disposable BuildKit state to approximately 1-2 GiB after the artifact-first boundary proves
  warm performance;
- bound raw captured logs to the existing 2 GiB total / 256 MiB per project policy and 64 MiB per
  operation;
- retain at most current + LKG + one in-progress candidate per project in the active runtime store;
- reject new build/deploy work before its measured reservation would cross the 20 GiB floor.

The 20 GiB value is a recovery floor, not an assertion that a cold build fits in the remaining space.
If measured local cold scratch plus all simultaneous mutation peaks cannot fit above that floor, local
automation is inadmissible until build storage/capacity is increased or an always-available dedicated
host is introduced. Intermittent i9 capacity is not a substitute for that requirement. Do not lower the
emergency reserve to make a build pass.

Removing the four runner trees offers approximately 10 GiB. Replacing the 6.169 GiB BuildKit volume
with a 1-2 GiB assembly cache offers roughly another 4-5 GiB. Docker reports 3.61 GiB of reclaimable
images, but shared layers and rollback ownership make that an opportunity signal, not guaranteed free
space. A staged migration should target at least 14 GiB of measured reclaimed space without counting
application data or deleting rollback state.

### 5. Deployment path

#### `rimg` pilot

- Activate the already-designed source broker and immutable export.
- Implement the generic shared worker/preparation protocol with `rimg` as its first manifest; do not
  create an `rimg`-specific worker. Initially run bare `bin/ci` as one bounded job. Then refactor bare
  `bin/ci` to use the same Rust preparation, independent checks, release-build, and reduce primitives so
  dependency/test compilation happens once and the exact gate remains reproducible locally.
- Produce the verified native artifact and runtime OCI on the VPS in parallel with independent
  verification when resource reservations allow, then sign one combined evidence receipt. i9 may return
  a CI/pre-deploy receipt but never supplies this deployment artifact.
- Use the existing stable backend/router path instead of the current GitHub-runner/Kamal/GHCR loop.
- Keep the current release serving while the candidate starts and becomes healthy, switch the stable
  router, then drain/remove only the prior owned backend after the rollback policy permits it.
- Represent the two-minute safety soak as `released_observing`; user-visible cutover is complete while
  automatic rollback monitoring remains active. Do not silently delete the soak.

#### `sartuli.ge`

- Preserve its application container and stable proxy initially. Replace GitHub's runner/setup DAG with
  immutable source and the same repository-agnostic scheduler.
- Replace the current per-job/per-shard checkout and `bin/update` contract with one
  `SourceSnapshot`/`DependencySnapshot`/`PreparedRun` per host. Share the pinned `.titanium` base and DB
  images, generated assets, gem/JS dependencies, and schema-keyed checkpoint read-only.
- Fan out only RSpec file groups and other genuinely independent checks. Give each shard a small COW
  upper plus a separate database name/schema cloned from the one checkpoint; do not give every shard a
  complete Compose dependency stack or mutable private cache.
- Keep shards only where measurement shows elapsed-time benefit after shared preparation. Four test
  slots must not imply four clones, four dependency builds, four asset builds, or four database-image
  preparations.
- Build the exact production OCI on the VPS concurrently with verification and hand its local
  archive/digest to the executor. Do not route deployment content through i9 or GHCR. If i9 is online it
  may fetch the exact SHA and run eligible RSpec/security/pre-deployment shards, returning only receipts.

#### Other projects

- Onboard only after each manifest declares source, bare `bin/ci`, artifact, health, data, migration,
  backup, resource, and rollback contracts. Install capabilities into the shared worker pool; do not add
  project-specific controller code, worker services, clones, or queues.

### 6. `rdashboard` self-deployment

Self-deployment needs a separate protocol because controller health and its database cannot be
authoritatively judged by the controller being replaced:

1. The ordinary source/build path produces a signed self-release bundle containing versioned native
   binaries, unit/config schema metadata, database compatibility, checksums, and minimum bootstrap
   protocol.
2. The executor verifies the exact current accepted head, policy, build evidence, and disk reserve,
   then writes a sealed pending-operation descriptor for a small root-owned
   `rdashboard-bootstrap.service`. The bootstrap supervisor is a persistent `Restart=always` service,
   installed outside the A/B application release and ordered before the controller at boot. It cannot
   accept arbitrary paths or commands.
3. The bootstrap supervisor persists its own journal outside `control.sqlite`, backs up and verifies
   the controller database/config/security projection required by policy, stages a versioned A/B
   release directory, and validates binaries/config before stopping anything.
4. It stops the controller/executor components being replaced, switches an atomic `current` pointer,
   starts the new version in dependency order, and judges process readiness plus an external
   authenticated health contract. The supervisor process and executable are not replaced by that
   operation.
5. On deadline, incompatible schema, or failed health, it restores the old pointer and database when
   the migration contract permits, then proves old health. If the supervisor crashes, is OOM-killed,
   or the host reboots, systemd/boot restarts the same immutable supervisor, which replays the pending
   journal before starting an unconfirmed slot. Ambiguous state becomes `needs_reconcile`, never
   success.
6. Keep the previous complete release and an offline recovery kit. A clean-host restore must not require
   GitHub, the old Docker store, or a healthy dashboard.

The bootstrap supervisor should be intentionally small and change rarely. Do not update it in the same
transaction whose recovery it arbitrates. A supervisor update is a separate dual-slot, explicit host
maintenance protocol in which the old version remains boot-selectable until the new supervisor has
survived a reboot drill. This is the minimum process/reboot-safe boundary. It still cannot recover a
dead VPS, corrupt root filesystem, or provider outage; off-host health alerting/provider reboot control
is a separate availability layer, not a reason to put deployment authority back in GitHub CI.

### 6a. Controller-independent break-glass recovery

The controller is the normal scheduler, but it must not be the only way to recover deployment
capability. Install a root-only, non-networked recovery CLI that talks directly to the executor/security
journal and bootstrap supervisor. It may only:

- inspect and reconcile an already-journaled operation;
- restart or roll back to a retained, independently verified current/LKG release bundle;
- admit an exact pre-built signed candidate with a current source-broker ticket and installed-policy
  match, using a separate offline-signed recovery intent;
- append the outcome to the executor's authoritative audit journal for later controller projection.

It cannot accept shell commands, repository paths, mutable tags, unsigned artifacts, or skip required
backup/migration/rollback policy. A controller-independent `rdashboard` LKG restore is the first
recovery goal; arbitrary new project delivery while the controller database is corrupt is not. This
escape hatch must be drilled from SSH and from the offline recovery kit before automated self-update is
enabled.

### 7. Resource monitoring and lifecycle

- Collect per-attempt cgroup CPU time, memory current/peak/events, OOM count, IO bytes/operations,
  process/task peak, wall time, and exit status. Sample during execution and capture final systemd
  properties before collection.
- Record disk before reservation, predicted peak, observed high water, artifact/cache/log delta,
  cleanup delta, and remaining emergency reserve.
- Use a persistent minimal observer for five-second application/container telemetry. The executor can
  publish the exact allowlisted current container IDs; the observer reads fixed cgroup/Docker stats and
  exposes only typed metrics. This avoids starting a root service for every sample.
- Sample slow storage categories separately (for example every minute/five minutes): source, scratch,
  caches, OCI staging, Docker images/volumes/build cache, application data, logs, runner legacy, and
  unknown/unattributed bytes.
- Alert on growth rate and budget violations, not only absolute host use. Unknown/unattributed growth is
  a first-class fault.
- Use bounded TERM/grace/KILL deadlines for task and container shutdown. An operation cannot be marked
  complete until its cleanup receipt exists or it is explicitly `cleanup_pending` with retained
  ownership metadata.
- Reconcile every managed unit/container/image/scratch item from desired current/LKG/in-progress state
  after controller/executor restart. Never use a global prune as normal operation.

### 8. Failure capsule V2

Persist one schema-validated canonical JSON/JCS object. Any evidence digest or signature covers only
those canonical structured bytes. Render concise Markdown through a versioned deterministic template;
the rendering is derived presentation and never separately treated as signed authority. Suggested
required fields:

```text
schema_version, failure_id
project, workflow_kind, source_sha, policy_digest
request_id, operation_id, attempt_id
phase, step_id, step_display_name
started_at, failed_at, duration_ms
process: exit_code, signal, timed_out, oom_killed
error: code, summary, first_causal_event, retryability, runbook_id
resources: cpu_usec, memory_peak_bytes, io_read/write_bytes, disk_peak/delta_bytes
artifacts: kind, digest, size (bounded list)
context_events: bounded structured events before/after the cause
raw_log: digest, compressed_size, retained_until, gap/truncation markers
redaction: ruleset_digest, replacement_count
previous_release, attempted_release, health_evidence
```

- Store command/adapter IDs, not secret-bearing argv or environment.
- Include `render_template_version` in the structured object so an operator can reproduce the exact
  Markdown presentation without making Markdown byte layout part of the evidence signature.
- Deterministically strip ANSI/control sequences, bound lines/events/bytes, redact before persistence,
  and record explicit gaps/truncation.
- Prefer tool-specific causal parsers (test runner, compiler, package manager, Docker/systemd) plus a
  generic fallback. Keep the original bounded compressed log by digest for operator drill-down.
- The operator/LLM summary should answer: what failed, first cause, affected SHA/release, whether a
  mutation occurred, retry safety, resource limit involvement, rollback result, and next runbook step.
- Optional LLM classification receives only this redacted capsule, never raw logs or secrets. It may
  propose a hypothesis but cannot change retry, rollback, deploy, or incident state.

In practical terms this is an incident card, not another workflow engine. For example: repository and
SHA; `verify/rspec/shard-3`; first causal test failure; exit code; `production_mutated=false`;
`resource_limit=none`; `retry=safe`; `rollback=not_required`; exact runbook ID; and the digest/location
of the bounded redacted raw log. The deterministic fields let `rdashboard` act and let an LLM explain
the incident without asking it to infer state from thousands of interleaved log lines. The LLM neither
creates these facts nor authorizes a retry/deploy.

## Quantitative acceptance targets

These are pilot validation thresholds based on current evidence, not claims that implementation has
already achieved them. The user requirement is a normal warm code-only deployment in less than 60
seconds, with rare, evidenced cold/native/dependency/schema or lost-webhook paths normally limited to
two or three minutes. A five-minute steady-state target is rejected. The confirmed normal-path
end-to-end clock starts at GitHub's successful push acceptance and stops at the first successful health
observation through the stable production route after cutover.

| Measure | Acceptance target | Rationale |
| --- | --- | --- |
| GitHub push acceptance to accepted source on the normal webhook path | <= 3s p95 | Webhook is only a wake-up; broker still fetches and verifies the exact head |
| Lost-webhook source discovery | <= 60s | Reconciliation is the durable repair path; this attempt is labeled as a degraded trigger class rather than silently counted as a normal webhook-path delivery |
| Warm local scheduler queue | <= 1s p95 | The VPS owns guaranteed capacity; no hosted-runner wait |
| Warm matching host preparation | <= 3s p95 | Source/dependency/generated inputs are already sealed and reused |
| Verification plus release-build critical path | <= 35s p95 for code-only changes | They run concurrently from one prepared snapshot; current 3-4m bare verification means the scripts themselves must be restructured and proven equivalent |
| Local candidate import/start/health/cutover | <= 10s p95 | Current candidate boot/health is approximately 7s; no registry round trip |
| Normal warm end-to-end delivery | < 60s for every attempt inside the declared normal capacity envelope; p95 <= 50s | Hard product target for `rimg`, `sartuli.ge`, `rdashboard`, and later onboarded repositories; soak is post-cutover observation |
| Rare cold dependency/toolchain/native/base/schema path | 2-3 min target, explicit reason code | Cold work should be prepared ahead or reused; anything slower needs measured proof that it cannot be moved off the deploy path, not a relaxed default |
| i9 loss before result | local fallback starts by its computed latest-start deadline | i9 can save time but cannot own required capacity or silently extend the deadline |
| Steady shared worker/source/cache state on VPS | <= 6 GiB initially | Replaces 10 GiB runner tree plus the oversized compilation graph; exact ecosystem shares follow measurement |
| Production filesystem emergency reserve | GC target >=30 GiB; hard floor >=20 GiB after every admitted local build/mutation peak | Prevent build/deploy from consuming recovery headroom |
| Orphaned managed resources | zero after bounded reconciler interval | Ownership ledger makes leftovers actionable |
| Failure capsule | <= 64 KiB rendered, cause retained | Existing policy limit; raw log remains separately bounded |

Measure GitHub push acceptance, webhook receipt or reconcile discovery, source acceptance, queue wait,
prefetch, verification, artifact build, OCI
assembly/import, backup/migration, candidate health, cutover, soak, cleanup, and total separately. A
single "deploy duration" hides the exact optimization opportunity.

For acceptance tests, record the client-observed successful `git push` acknowledgement and correlate it
to the source SHA and controller request. In production telemetry, use an authenticated provider event
push timestamp when available and always retain webhook-receipt/reconcile time separately; never use a
commit author timestamp as the start of this SLO. The end marker is an external request succeeding
through the stable production route on the candidate release, not merely a process becoming ready.

The normal capacity envelope must be declared per host and includes its supported level of concurrent
pushes. If simultaneous accepted work cannot meet the deadline, the controller preempts optional work,
supersedes stale same-project heads where safe, or classifies an explicit capacity exception; it must
not hide the miss as ordinary queueing. i9 registration never increases the declared guaranteed
capacity because the host may disappear.

For a lost webhook, source acceptance may consume up to 60 seconds; once the SHA is accepted, the same
warm preparation, verification/build, and cutover sub-budgets apply. The resulting end-to-end attempt
is expected to remain within the rare two-to-three-minute degraded envelope and carries an explicit
`trigger_reconciled` reason rather than weakening the normal-path SLO.

The sub-budgets are intentionally tighter than their simple sum because source admission, host prepare,
verification, and release build overlap. If a repository cannot meet the end-to-end target without
skipping its exact verification contract, it stays in shadow/manual mode while the measured critical
path is redesigned; the system does not make the dashboard green by weakening `bin/ci`.

## Migration and proof sequence

1. **Freeze baseline evidence.** Record current GitHub run distributions, runner/disk categories,
   BuildKit cache, Docker images/volumes, bare `bin/ci` duration, build artifact size, deploy phases,
   and rollback state.
2. **Fix observation lifecycle first.** Replace the five-second per-sample root activation with the
   persistent bounded observer (or collect failed units after persisting results), stop accumulating
   expected failed template units, and add bounded job/resource accounting. This makes later
   comparisons trustworthy and precedes disk-admission decisions.
3. **Install source broker in observation-only mode.** Enable periodic reconcile, then webhook ingress;
   keep `auto_deploy=false`. Drill missed, duplicate, reordered, stale, force-push, broker restart, and
   GitHub-unavailable cases.
4. **Install the generic VPS worker pool in shadow mode.** Implement host-level single-flight
   `SourceSnapshot`/`DependencySnapshot`/`PreparedRun`, shared read-only inputs, per-slot COW scratch,
   fair cross-repository scheduling, hard byte/inode quotas, and a deterministic reducer. Measure a
   completely cold scratch high water. Run immutable export -> bare `bin/ci` -> artifact/OCI without
   deployment and compare exact SHA, required-step set, artifact/image digest, duration, peak resources,
   and cleanup against the existing path.
5. **Restructure and prove the `rimg` verification adapter.** Make bare `bin/ci` and distributed mode
   invoke the same prepare/shard/reduce contract. Prove required-step and result equivalence, then
   measure whether verification plus the concurrent VPS release build can meet the warm latency budget.
6. **Activate manual `rimg` candidate deployment.** Prove backup, stable cutover, health, crash at
   every receipt boundary, automatic rollback, and clean-host recovery before automation.
7. **Enable `rimg` auto-admission for safe release classes.** Run `rdashboard` and GitHub workflows in
   parallel temporarily, but only the `rdashboard` result authorizes deploy. After a defined
   consecutive green window and rollback drills, disable/remove the `rimg` runner.
8. **Remove only proven legacy state.** Archive required evidence, unregister/stop the exact runner,
   remove its exact workspace, and use Docker/BuildKit's APIs to prune only unreferenced, non-LKG
   resources. Measure reclaimed bytes after each step.
9. **Attach i9 as an optional worker.** Use the same generic protocol for CI/pre-deploy shards only.
   Drill absent-at-start, disconnect during fetch, disconnect during a shard, late duplicate receipt,
   local latest-start fallback, and zero-artifact-transfer behavior. Do not change the VPS admission or
   capacity requirement when i9 registers.
10. **Migrate `sartuli.ge`.** First replace repeated checkout/update/assets/DB/Compose preparation with
   one per-host prepared run, then prove the exact bare-`bin/ci` step set, warm/cold latency, i9 loss,
   and local OCI deployment before retiring its three runner workspaces.
11. **Implement and drill self-update last.** Install the persistent bootstrap supervisor, then test new
   controller failure, new executor failure, supervisor crash/OOM, database incompatibility, full
   reboot at every pending phase, rollback, controller-independent LKG recovery, and offline restore
   before enabling automated self-deploy.

## Risks and controls

| Risk | Required control |
| --- | --- |
| GitHub webhook lost or late | Periodic fetch/reconcile; webhook only wakes work |
| GitHub fully unavailable | Existing accepted releases continue; direct push is explicit fallback; no deploy guesses from stale source |
| Malicious/compromised commit | Operator-owned repositories only on the VPS; immutable export, non-root sandbox, no secrets/Docker socket, fixed installed workflow policy; if stronger isolation is required, add an always-on separate host and never claim same-kernel containment |
| Source changes during build | SHA/policy/digest binding and live head/sequence check immediately before first mutation |
| Cache poisoning or cross-repository contamination | Full content/toolchain/lockfile/policy keys, atomic single-writer publication, integrity checks, read-only consumption, COW writable state, cache never grants authority |
| Four slots stampede the same preparation | Keyed single-flight producer; other slots join it and consume the sealed result |
| i9 disappears or returns late | Soft registration, short leases, local latest-start deadline, idempotent receipt identity, no deployment artifact or required-only state on i9 |
| Disk exhaustion | One shared hard byte/inode project quota plus measured reservation and 20 GiB floor; GC starts below 30 GiB; one heavy job; fail before build |
| OOM/CPU starvation of production | cgroup `MemoryHigh/Max`, CPU/IO weights, task limits, global scheduler budget |
| New push during deploy | Supersede only before mutation; serialize/reconcile mutation phases |
| Controller compromised | Executor independently verifies signed policy/source/build/receipts; no arbitrary shell |
| Executor/controller replaced during self-update | Immutable persistent bootstrap supervisor, boot replay, separate journal, A/B rollback |
| Controller database/binary unusable | Root-only fixed recovery CLI can reconcile or restore verified LKG through executor/bootstrap authority |
| Cleanup crash | Durable creation/cleanup receipts plus startup reconciliation |
| LLM misdiagnosis or prompt injection | Deterministic capsule first; hostile text rendering; LLM output non-authoritative |
| Removing useful cache harms latency | Shadow measurement and artifact-boundary replacement before lowering/removing cache |

## Residual measurements and validation

- Exact per-project cache and scratch budgets require shadow-run high-water measurements. The proposed
  6 GiB/1-2 GiB targets are starting limits, not deletion instructions.
- `sartuli.ge` may continue to benefit from selected parallel test shards; only measured critical-path
  benefit should justify them after preparation is shared; duplicated warmup is not an acceptable cost
  of parallelism.
- The delivery clock is resolved: GitHub push acceptance to externally healthy production cutover.
  Meeting it requires restructuring the current multi-minute `bin/ci` critical path, not merely
  replacing GitHub and Docker transport. Shadow measurements must determine the exact critical path and
  whether each repository fits the declared normal capacity envelope without weakening verification.
- i9 placement is resolved: it is intermittent, repository-agnostic CI/pre-deployment acceleration
  only. The complete workflow, build artifact, deploy, retry, and capacity plan remains valid without it.
- GitHub-hosted PR checks may remain for developer convenience during migration, but their absence or
  failure must not block the local authoritative main workflow.
- Replacing Docker as the production application runtime is a separate high-risk migration and is not
  justified by the current evidence. Most measured waste can be removed without it.

No user-owned architecture decision remains. Cache/scratch numbers, shard counts, per-repository
resource reservations, and exact worker capability images are implementation measurements governed by
the constraints above, not choices to push back to the operator.

## Research closure

- **Recommendation:** complete the existing narrow `rdashboard` source/controller/executor direction;
  add the generic shared worker/preparation layer and persistent self-update supervisor; keep GitHub as
  source/signal only and Docker only where it remains useful as an application/runtime boundary.
- **Decisive evidence:** GitHub scheduling has added more than 23 minutes before useful work; the VPS
  currently holds approximately 26.7 GiB across containerd, Docker, and runners; Sartuli parallel jobs
  explicitly repeat checkout/update/DB/Compose preparation; and the actual retained release artifact is
  tens of MiB while compilation state is multiple GiB.
- **Strongest rejected alternative:** Woodpecker/Forgejo Actions/Concourse provide mature generic CI,
  but reintroduce a server plus agents/runners/container state while leaving `rdashboard`'s deploy,
  resource, rollback, and self-update authority necessary. They add a second operational truth rather
  than remove the measured causes.
- **Residual risk:** the less-than-60-second SLO is not demonstrated today. Current `bin/ci` paths are
  multi-minute, and same-VPS execution shares the production kernel. Implementation must remain
  shadow/manual until exact gate equivalence, resource high-water bounds, failure drills, and the full
  push-ack-to-cutover clock pass for each repository.
- **Smallest coherent next engineering step:** implement the persistent bounded resource observer and
  install the source broker in observation-only mode, then measure one generic VPS worker's
  single-flight preparation and unmodified bare `bin/ci` path before changing verification scripts or
  enabling any deployment.
- **Closure verification:** U001-U005 and this research were reconciled; no unresolved user decision
  remains. The complete operator-facing explanation is delivered in chat rather than delegated to this
  artifact. No implementation tests, deployment, service mutation, cache deletion, GitHub write, or
  production change was run because this phase was explicitly read-only.

## Consultation ledger

- Route/model: `deepseek-free` / `opencode/deepseek-v4-flash-free`.
- Question: falsify completion of the narrow control plane versus an external CI server, focusing on
  self-update liveness, repository-code isolation, cache/disk bounds, event-loss recovery, monitoring,
  and crash cleanup.
- Repository fingerprint: `a401ae85ed5c1a202cdcc4b2f288201d753bbfcff50c01501753726e849f2c05`;
  brief SHA-256: `545fe47266000255751f743de2daf44fc85f2435a62f6e21c28c5661af97d3a2`.
- Status: `ANSWERED`. Primary output:
  `/tmp/rdashboard-github-independent-delivery-consult/out/response.md`. A second fresh output with the
  same question/fingerprint completed at
  `/tmp/rdashboard-github-independent-delivery-consult/out2/response.md` because the still-running
  first dispatcher session was initially mistaken for an empty result; both were read as adversarial
  perspectives, not independent evidence.
- Accepted: replace a transient self-upgrader with an immutable persistent boot supervisor; add a
  controller-independent constrained LKG recovery path; enforce disk byte/inode quotas; measure cold
  scratch before choosing reserve/cache limits; capture/sign only canonical structured failure data;
  implement the persistent observer before resource-based admission.
- Accepted with qualification: the consultation correctly identified that same-VPS sandboxing shares
  the production kernel. Its proposed preference for a separate build host is superseded by the
  clarified operating constraint: i9 is intermittent and cannot be authoritative. The retained control
  is hard local isolation for operator-owned repositories; stronger isolation would require a separate
  always-on host. Rootless Podman alone is not described as a kernel security boundary.
- Rejected: proceeding with a cached accepted head while the source broker is unavailable. This would
  weaken the executor's live TOCTOU gate. The safe behavior is a visible retryable block until the
  broker has replayed/reconciled and is ready.
- Not adopted: install an external generic CI product. Its server/agent/worker estate does not remove
  the need for the existing deploy executor, self-update supervisor, resource policy, or recovery
  contracts, and therefore adds rather than replaces operational truth for the current scope.

## Primary sources

- GitHub, [Best practices for using webhooks](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks)
- GitHub, [Handling failed webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries)
- GitHub, [Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- Git, [githooks documentation](https://git-scm.com/docs/githooks)
- Docker, [Exporters overview](https://docs.docker.com/build/exporters/)
- Docker, [OCI and Docker exporters](https://docs.docker.com/build/exporters/oci-docker/)
- Docker, [Build garbage collection](https://docs.docker.com/build/cache/garbage-collection/)
- systemd, [`systemd.unit` source manual](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.unit.xml)
- systemd, [`systemd.resource-control` source manual](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.resource-control.xml)
- systemd, [`systemd-run` source manual](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd-run.xml)
- Woodpecker CI, [Architecture](https://woodpecker-ci.org/docs/development/architecture)
- Forgejo, [Actions overview](https://forgejo.org/docs/latest/user/actions/overview/)
- Concourse, [Running a worker node](https://concourse-ci.org/docs/install/running-worker/)
