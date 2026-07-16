# rdashboard: production implementation plan

Status: Phase 1 contracts, the early Phase 3 dashboard slice, Phase 4/5 durable mutation contracts,
the Phase 6 privileged adapters, source broker/export, backup worker, controller mutation/status API
and first-bootstrap deploy worker are implemented locally. The constrained CI/BuildKit candidate
producer, authorizer, installed upgrades, rollback, remaining ingress/console paths and production
installation are not complete.

Last updated: 2026-07-16.

## Outcome

Build a low-resource Rust operations dashboard for the production VPS, exposed at `dev.4u.ge`. The first complete pilot is `rimg`; after the pilot passes deploy, rollback, backup and recovery drills, the same manifest-driven control plane will onboard the remaining projects.

The initial production version includes:

- dense desktop dashboard for 1720×1280 and 1920×1080;
- host and per-project metrics;
- service health, incidents and Telegram notifications;
- application/deploy logs and compact deterministic failure capsules;
- GlitchTip aggregates and deep links;
- local CI triggered by pushes to `main`, without GitHub Actions in the production path;
- Kamal 2 deploys, code rollback and explicit manual data restore;
- local and Google Drive backups with integrity verification;
- live SSE updates with one active browser tab per authenticated user;
- Cloudflare Access authentication and origin-side authorization;
- optional non-authoritative summaries through DeepSeek V4 Flash Free.

Mobile UI is not in scope.

## Confirmed decisions

| Area | Decision |
| --- | --- |
| Active browser tab | One active tab per authenticated user, not one global tab for all operators. A newer tab revokes the older tab's lease. |
| Passkey fallback | First test the real Cloudflare/passkey flow on Linux and Windows. Do not enable TOTP automatically; decide on fallback only if the test fails. |
| Data restore | Never automatic. Restore is a distinct manual recovery operation. |
| Backup verification | Checksums, SQLite and domain-integrity checks and regular restore drills are mandatory. A successful upload alone is not a successful backup. |
| First `rimg` deploy | Treat it as bootstrap. Gapless cutover and rollback availability are not required; a simple declared stop/start is acceptable. |
| Backup policy | Migration deploy requires a fresh verified offsite backup. A code-only deploy may proceed when the last verified backup is less than 24 hours old. Initial RPO is 24 hours and RTO is 2 hours. |
| Offsite limitation | Google Drive is the first encrypted offsite copy, not an immutable or ransomware-resistant backup. A second independently credentialed provider is a later acceptance requirement for that stronger claim. |
| AI provider | `providerID=opencode`, `modelID=deepseek-v4-flash-free`, with paid fallback disabled. |
| Secrets and identities | Exact operator emails, OpenCode base URL and credential names are supplied before the corresponding implementation phase. Secrets are never committed to this repository. |

## Explicit non-goals

- Grafana, Loki or another general-purpose observability stack.
- Basic Auth as the production authentication boundary.
- GitHub-hosted or self-hosted Actions runners in the final deploy path.
- A custom replacement for all GlitchTip functionality in the first version.
- Automatic database restore.
- A mobile layout.
- An independent external watchdog in this repository. It will run on another VPS later; the dashboard must expose a stable external health contract for it.

## Target architecture

```text
Cloudflare
├── /                         → Access → rdashboardd
├── actions.dev.4u.ge         → separate Access audience → rdashboard-authorizer
└── /hooks/github             → HMAC + rate limits → rdashboard-source

rdashboardd — unprivileged controller, web UI, SSE and collectors
├── control.sqlite — operations, incidents, audit and notification outbox
├── metrics.sqlite — measurements and rollups
└── control Unix socket
      └── rdashboard-executor — minimal effective-root helper
          ├── signed root-owned policy and security journal
          ├── systemd transient units
          ├── sandboxed rbuild / isolated BuildKit
          ├── generated Kamal configuration and Docker
          └── bounded backup and observation primitives

rdashboard-authorizer — isolated action-grant service
└── on a separate browser origin, displays an executor-signed canonical
    intent and signs a one-use, operation-bound grant after explicit approval

rdashboard-source — isolated source broker and canonical bare repository owner
├── GitHub HMAC/fetch/reconciliation
├── forced-command direct-push quarantine
└── signed accepted-head attestations

sudo rdashboard-recover — local SSH-only recovery CLI
└── root-only recovery Unix socket → staged data-restore primitives
```

### Process boundaries

`rdashboardd` is the sole writer of `control.sqlite` and `metrics.sqlite`. It runs without root, a Docker socket or arbitrary shell access.

`rdashboard-executor` performs only typed operations declared by the installed root-owned policy under `/etc/rdashboard`. Docker daemon access is treated as effective root access; this is an explicit trust boundary, not a nominally unprivileged `deploy` user. The executor does not trust controller SQLite state, a mutable checkout, repository-owned Kamal files or caller-supplied paths when authorizing a mutation.

The executor independently verifies the canonical project, signed source attestation, immutable SHA/digest, allowed security transition, resource reservation, idempotency/attempt identity and, for interactive actions, a signed one-use action grant. Its root-owned `security.sqlite` journal is authoritative for privileged transitions and records operation/attempt ID, signed policy-bundle digest, release class, current security phase, step receipts for backup/migration/image/cutover/health/rollback, grant nonce, fencing epoch and current/last-known-good release identities. `rdashboardd` stores the product/audit projection of those receipts rather than a second security truth. Controller compromise therefore cannot turn a typed call into arbitrary root execution, invent a completed prerequisite or replay a mutation. Automated push deploys are limited to an attested current canonical `main` head and installed auto-deploy policy; they cannot select another SHA or configuration.

`rdashboard-authorizer` is served only from `https://actions.dev.4u.ge`, with no CORS access from `dev.4u.ge`, no shared Service Worker scope, `frame-ancestors 'none'` and a strict self-only CSP. The controller may ask the executor to prepare a non-mutating intent, but the executor resolves it against signed policy/source/security state and returns a signed canonical intent containing the exact project, release/migration/rollback target, consequences, policy digest, expiry and opaque intent ID. The browser performs a top-level navigation to the authorizer; that service validates the intent signature, distinct Cloudflare audience, actor/role, recent-auth claim and active lease, renders the canonical payload itself, and requires explicit confirmation before returning a short-lived one-use grant bound to the intent hash. The browser POSTs that grant to the controller's normal `/api/operations` endpoint. Controller HTML/JavaScript never controls the trusted confirmation content and never receives the stronger Access JWT or authorizer signing key. If Cloudflare cannot provide a trustworthy recent-auth signal, the authorizer verifies an application-local WebAuthn assertion bound to the same intent instead.

`rdashboard-source` runs under a dedicated UID, owns the canonical bare object database, quarantine and accepted-head ledger, and is the only writer of those paths. Remote URL/ref and allowed direct-push identities come from signed root policy. A webhook is only a wake-up hint: the broker verifies HMAC, fetches and evaluates the remote itself. Direct pushes land in quarantine before the same checks. It issues a signed accepted-head attestation bound to project, previous/new head, monotonic per-project head sequence, source channel, policy digest and short expiry. Controller and build identities receive read-only exports/attestations. Immediately before the first mutation, the executor queries the broker's peer-authenticated read-only socket for current `(head, sequence)` and requires an exact match; an unavailable broker fails an automated deploy closed.

Data restore is not exposed on the controller socket or any HTTP route. The dashboard can inspect backups and generate a recovery checklist, but execution requires an SSH session and an exact sudoers rule for `sudo rdashboard-recover`. The recovery socket is `root:root 0600`, requires peer effective UID 0 and has a separate audited protocol. The executor independently rechecks policy, backup identity, fence and staged-restore prerequisites; it does not trust that a client displayed a confirmation.

`rdashboard-notify` is a separate minimal service/binary used for typed notification delivery and systemd `OnFailure`. The controller persists a bounded outbox fact packet and receives a delivery receipt, but never receives the bot bearer token. The notifier validates the schema/project/chat allowlist, renders/rate-limits the compact message, tries `telegram-gateway`, then uses the direct Bot API fallback. It can notify when the main web/controller process is down, but cannot help when the entire VPS or its network is unavailable; that remains the future external watchdog's responsibility.

### Expected repository structure

Keep shared domain code together, but preserve the concrete security boundaries as separate processes. Start with one shared library and six binary targets:

```text
Cargo.toml
bin/ci
src/
  lib.rs
  bin/
    rdashboardd.rs
    rdashboard-executor.rs
    rdashboard-authorizer.rs
    rdashboard-source.rs
    rdashboard-recover.rs
    rdashboard-notify.rs
  domain/
  protocol/
  store/
  metrics/
  deploy/
  backup/
  incidents/
  auth/
web/
config/
  schema/
  projects/
  kamal-templates/
deploy/
  systemd/
tests/
```

The exact modules may be consolidated while implementing if two modules do not represent separate contracts.

## Phase 1 — contracts, quality gate and threat model

Create the Rust workspace, `bin/ci` and the domain contracts before adapters.

Define:

- versioned project manifest schema;
- operation, transition, event and structured error types;
- stable SSE envelope and monotonic sequence;
- failure capsule schema;
- audit fields and actor identity;
- roles: `viewer`, `operator`, `admin`;
- redaction rules for logs, environment values and AI inputs;
- retention, cardinality and resource budgets;
- root-equivalent operations and privilege matrix;
- per-project health, backup, migration and rollback policies;
- release-class transition tables with required/skipped phases, mutation boundary, required executor receipt and legal terminal outcome for code-only, stateful-compatible, stateful-breaking and rollback workflows.

Keep orthogonal state in separate typed fields rather than inventing compound pseudo-states:

- `operation_phase`: queued, source sync, test, build, preflight, backup, migration, deploy, health, soak, rollback and reconciliation;
- `operation_result`: running, succeeded, failed, rolled back, rollback failed, cancelled or manual recovery required;
- `blocking_reason`: none, disk reserve, source divergence, source broker unavailable, source head superseded, source attestation invalid, policy unavailable, policy invalid, policy stale, security state invalid, backup policy, stale telemetry, clock unsynchronized, maintenance conflict or operator hold;
- `project_condition`: healthy, degraded, down, maintenance, migrating, unknown or signal lost;
- `backup_status`: absent, pending, verified local, verified offsite, unverified, corrupt or provider degraded;
- `rollback_capability`: unavailable, eligible, ineligible, consumed or unsafe after migration.
- `notification_delivery`: pending, sending, delivered, delivery unknown, retry scheduled, delivered possible duplicate or permanently failed;
- `notification_path`: healthy, gateway degraded/direct available or unavailable.

Define and test the valid combinations and transitions. UI labels such as `preflight_blocked` are projections of these fields, not extra persistence states.

Every non-`none` blocking reason has typed retryability (`automatic`, `after_external_recovery` or `operator_runbook`), a safe operator explanation and a root-owned runbook identifier. Recovery from a source-broker outage or policy refresh reruns admission and transitions the same attempt without crossing the mutation boundary; it never creates an implicit retry after side effects.

Initial manifest fields include:

- project ID and display name;
- canonical repository and branch;
- fixed `bin/ci` command;
- build context and image identity policy;
- health, smoke and soak checks;
- data volumes and backup classes;
- migration and write-fence commands;
- rollback compatibility policy;
- notification routing and maintenance windows.

The repository copy of a manifest is reviewable source material only. A policy bundle contains the manifests, Kamal templates/hooks, transition tables and their hashes. It is signed with a dedicated Ed25519/minisign key kept off the VPS; the executor pins the public key and rejects unsigned, wrongly signed, rolled-back or internally inconsistent bundles. Mutation policy is installed atomically as root-owned, non-writable-by-controller files under `/etc/rdashboard/projects`; the installer and executor both verify the signature, bundle digest and monotonic policy version. Policy installation is an explicit host administration action, not a web action and not part of deploying a managed project.

Set conservative enforceable pilot budgets before adapters exist; Phase 12 may tune them only from recorded measurements:

- preserve `max(8 GiB, 15% of the data filesystem)` as an emergency disk reserve after the calculated operation peak;
- cap `control.sqlite` at 512 MiB, `metrics.sqlite` at 2 GiB, hot raw logs at 2 GiB total and 256 MiB per project, and captured CI/build output at 64 MiB per operation;
- cap a rendered failure capsule at 64 KiB and every persisted individual log event at 256 KiB before compression;
- initial service `MemoryMax`: controller 256 MiB, source broker 192 MiB, authorizer 64 MiB, executor 128 MiB excluding its transient child scopes, notifier 32 MiB;
- a heavy transient job may reserve only memory above `max(1 GiB, 25% of physical RAM)` left for production services and the kernel;
- initial `TasksMax=256` and `LimitNOFILE=4096` per long-lived service; tighter values are preferred after measurement;
- quota eviction never removes audit transitions, incident transitions, the current release or last-known-good artifacts.

Bound non-evictable data rather than letting it deadlock the hot stores:

- keep 90 days of audit/incident transitions in `control.sqlite`; seal older rows into hash-chained, indexed, encrypted archive segments and delete hot rows only after local and offsite verification;
- retain at least two verified local backup generations and offsite 7 daily, 4 weekly and 12 monthly generations per stateful project, subject to stricter project policy;
- never delete the last verified local or offsite copy, a snapshot referenced by current/LKG recovery, or a release/security bundle needed for rollback;
- GC/compaction runs only after a newer copy is verified, has its own scratch reservation and cannot run concurrently with mutation/heavy-I/O work.

Hitting a cap produces a visible blocking/degraded state and deterministic cleanup; it never silently disables collection or consumes the emergency reserve.

The Unix-socket protocol must have:

- explicit version negotiation;
- bounded frame and field sizes;
- deadlines;
- peer credential verification;
- allowlisted project IDs, SHAs and operation enums;
- no caller-provided executable, path, environment or command string.

Use length-prefixed UTF-8 JSON with concrete Serde structs, an explicit protocol version and `deny_unknown_fields`; do not deserialize requests through `serde_json::Value`. Limit normal request/response frames to 64 KiB and bounded observation snapshots to 512 KiB. Reject duplicate fields, excessive nesting, invalid Unicode, trailing frames and version downgrade. Fuzz every request variant and the frame decoder.

The controller socket exposes policy-constrained deploy/rollback/backup operations and bounded read-only observations such as `ObserveDockerSnapshot` and `ObserveSystemdUnits`. The recovery socket uses a separate message enum and peer allowlist and contains data-restore operations only.

### Phase 1 gate

`bin/ci` verifies signed policy bundles and rollback rejection, manifest round trips, per-release transition tables, valid cross-field state combinations, invalid transitions, unknown fields/operations, path traversal, oversized/deep input, parser fuzz targets, delivery/request/attempt idempotency, provisional budget/retention enforcement and secret-shaped redaction fixtures. A malicious managed checkout containing ERB, Kamal hooks, host paths, volume changes or command substitution cannot affect the generated executor plan.

## Phase 2 — make `rimg` deploy-safe

The dashboard must not automate the existing deployment until `rimg` exposes honest operational contracts.

Current blockers:

- worker heartbeats are initialized before the first successful iteration and refreshed around failed work: [`queue.rs`](/home/denai/RustroverProjects/rimg/src/queue.rs);
- readiness checks queue freshness, `SELECT 1` and directory existence, but not writable storage or the webhook loop: [`health.rs`](/home/denai/RustroverProjects/rimg/src/routes/health.rs);
- migrations run during application initialization: [`db.rs`](/home/denai/RustroverProjects/rimg/src/db.rs);
- migration 002 changes existing data and statuses: [`002_reliability.sql`](/home/denai/RustroverProjects/rimg/migrations/002_reliability.sql);
- `/sources/umove` is declared but not mounted: [`deploy.yml`](/home/denai/RustroverProjects/rimg/config/deploy.yml);
- `proxy: false` provides no proven gapless internal cutover.

Required `rimg` changes:

- mark each critical worker ready only after its first successful iteration;
- never refresh a success heartbeat after an error;
- expose webhook-loop health and last successful progress;
- verify database and storage writability;
- add idempotent `rimg migrate` and schema compatibility inspection;
- stop running migrations implicitly during normal application startup;
- add a temporary explicit pre-deploy `rimg migrate` step to the current runner/Kamal path before removing startup migration; retire that step only after the Phase 6 executor path passes acceptance;
- test empty, current, upgrade-required and unsupported-newer schema behavior in both the temporary and final paths;
- add maintenance, intake stop, worker drain and write-fence controls whose epoch/token persist across process restart and are reported by readiness;
- fix the missing read-only source mount;
- add smoke checks from the real consumer Docker network;
- use a soak interval longer than the previous false-green heartbeat window.

The current bundled SQLite used by `rimg` is 3.53.2 and therefore includes the fix for the 2026 WAL-reset corruption bug. `rdashboard` must also pin a fixed bundled SQLite version and report it in diagnostics.

### First deploy rule

The first `rimg` deploy is a bootstrap operation. It may use an explicit maintenance window and simple stop/start. It does not need to prove zero downtime or provide a previous rollback target.

Later deploys must use a tested stable internal routing/cutover mechanism. Evaluate kamal-proxy or a small stable internal proxy without assuming that two containers sharing one Docker network alias are safe.

### Phase 2 gate

The `rimg` repository passes its own `bin/ci`; the temporary production deploy still performs the explicit migration safely, and empty/current/upgrade-required/unsupported-newer schema, maintenance, persisted fence, failed worker, unwritable storage and failed webhook-loop scenarios produce truthful results.

## Phase 3 — early real read-only vertical slice

Do not postpone UI and SSE validation until deployment automation is complete.

Build a local-only vertical slice using real data:

- actual host CPU, memory, load and disk measurements;
- actual `rimg` health;
- one persisted operation record;
- SSE snapshot, sequence and reconnect;
- initial desktop layout;
- loading, empty, partial, stale, disconnected and no-data states.

No mock metrics, fake services or placeholder success states. The web process listens only on loopback or a Unix socket during this phase.

Current implementation note: the local collector persists real host samples and bounded HTTP
observations from the configured `rimg` origin, publishes them through snapshot/SSE and preserves
the last real HTTP response time across signal loss. Until the Phase 2 contract is
implemented in `rimg`, two legacy `204` responses are classified as `degraded`, never `healthy`.
An unconfigured origin is explicit `unknown`; it is not silently replaced with fixture data.

### Phase 3 gate

At both target desktop resolutions the current host/project picture is usable without scrolling the primary region. SSE disconnect and sequence gaps become visible and recover through a fresh snapshot.

## Phase 4 — durable controller and executor

External side effects are not SQLite transactions. Every step follows:

```text
persist intent → execute → observe actual state → verify → commit result
```

The system promises at-least-once execution with idempotency and reconciliation, not fictional exactly-once Docker, backup or migration operations.

The following is a superset of persisted operation phases; the signed release-class transition tables decide which phases are required, skipped or paused and which receipt permits the next phase:

```text
queued
→ syncing_source
→ verifying_source
→ testing
→ building
→ preflight
→ backing_up
→ draining
→ cutover_snapshotting
→ migrating
→ deploying
→ health_checking
→ soaking
→ terminal result
```

Rollback and reconciliation are explicit phases selected after a failed or ambiguous observation; terminal outcome remains a separate `operation_result`. Each operation records its stable deployment-request ID, unique attempt ID, installed signed-policy digest/version, source SHA/attestation, build-context hash, generated-output hashes, image/base digests, schema version, backup ID, previous release bundle, health evidence, actor/action-grant hash, fencing epoch, transition timestamps and failure capsule.

`security.sqlite` is root-owned and uses durable transactions (`synchronous=FULL`) for security-phase intent and receipt commits. External write fences use an executor-owned monotonically increasing epoch and an operation-scoped random token, persisted both in the journal and the managed application's fence store. Acquire, inspect and release are idempotent and follow intent → application action → observation → receipt. The application must report the active epoch in its maintenance/readiness contract; a release with the wrong owner/token fails closed.

On restart the executor reads the security journal and queries the application before accepting work. Matching held state resumes reconciliation. Any missing/mismatched owner, epoch, token or phase blocks mutation as `needs_reconcile`; it is never released by timeout. An observed release may be committed automatically only when the journal proves the operation had already passed the release-safe health/rollback receipt; every other mismatch requires the audited root-only recovery path.

Concurrency policy:

- one global build;
- one deploy lock per project;
- one default global heavy-I/O reservation on the VPS;
- queued SHAs may be superseded before external side effects;
- transport delivery IDs deduplicate webhook/SSH events, while a stable deployment request is `(project, immutable target, operation kind)` across all source channels;
- each execution has a unique `attempt_id`; an active/succeeded request returns its existing operation, while a new attempt after terminal failure requires an explicit retry grant or bounded installed retry policy and never deletes prior replay evidence;
- cancellation is allowed before the mutation boundary;
- a newer push never cancels an operation after migration or cutover starts;
- current `last_known_good` artifacts cannot be pruned to make room for a new deploy.

Use systemd transient units for CI/build/deploy process trees so timeouts kill descendants and CPU, memory, tasks, open files, scratch bytes and journal/output bytes have enforceable limits.

Interactive mutation admission is atomic: validate the current tab lease identity/generation without consuming it, consume the one-use action-grant nonce, persist the request/attempt record, then return the operation ID. Every accepted request returns an operation ID even if execution is queued. Takeover atomically increments lease generation; a request using an older generation returns `LEASE_REVOKED` and cannot create an operation. The executor independently consumes the grant nonce and keys every privileged step receipt by attempt/phase before the first side effect. Automated source events use a distinct `automation` actor, require an installed auto-deploy policy and exact signed canonical-head attestation, and never masquerade as an interactive grant.

### Phase 4 gate

At this phase use a deterministic model/fake executor and injected crashes at every modeled side-effect boundary. Recovery converges to one legal continuation or `needs_reconcile`; duplicate deliveries do not start duplicate mutations; an explicitly authorized retry creates a new attempt without replaying old receipts; lease generation, fence ownership, security-journal projection and grant replay fail closed. Real Docker, backup, migration and reboot crash drills belong to the adapter phases and Phase 12 rather than being a hidden prerequisite here.

Current implementation note: `control.sqlite` now atomically validates tab-lease generation,
deduplicates stable requests and transport deliveries, consumes controller grant nonces and retains
every retry attempt. Root-owned `security.sqlite` separately binds authorization to attempt/project,
persists intents, artifact-bearing canonical receipts, global/project resource locks and monotonic
fence epochs/tokens. The deterministic coordinator replays every phase boundary, integrates the
stateful migration fence through soak, supports an explicit rollback branch and blocks work until
startup fence reconciliation succeeds. The Phase 4 tests inject crashes after intent, effect,
observation, verification, security receipt, controller projection and fence acquire/release
boundaries.

The 2026-07-15 cross-model implementation review used all configured routes: `deepseek-free`,
`gemini-flash`, `gemini-pro` and `deepseek-pro`. Verified findings fixed here include fence epoch
history collisions, cross-project authorization, incomplete artifact binding/projection, leaked
locks on direct abort, a missing deploy-to-rollback branch, disconnected migration fences and
non-idempotent blocked reconciliation. Suggestions to expire an already consumed attempt mid-run or
to treat the `BEGIN IMMEDIATE` delivery insert as an unlocked SELECT/INSERT race were rejected after
local verification.

A second post-implementation review repeated all four model routes and split three independent
agent reviews across build/filesystem, executor/controller and source/security. Confirmed fixes bind
the selected Dockerfile and base-registry allowlist into immutable build identity, reject repository
`VOLUME`, sweep crash-orphaned bundle temporaries under an OS singleton, reject cross-filesystem Git
repository layouts, compensate source tickets that fail before proof persistence, reserve disk for
backup-only work, serialize recovery and effects per project, preserve distinct candidate/rollback
health evidence, validate the complete canonical receipt before fence release and make rollback
takeover crash-safe without erasing the forward journal. Docker positional-option, SSE replay and
lease/data-race claims that did not match the actual grammar or durable invariants were rejected
after local tracing rather than patched speculatively.

The final Phase 5 hardening pass upgrades the security journal to schema v5. Rollback is seal-first,
receipt digests bind their primary or rollback-recovery branch, and the project execution gate spans
effect execution through fence release and controller projection. Reservation claims retain and bind
their observation timestamp so the executor can recompute the digest at authorization and load;
legacy live claims and branchless receipts migrate fail-closed. Incremental Git fetch uses the
canonical objects only as a read-only negotiation alternate, pins pack/index/ref fsync semantics and
owner-only canonical directories and mutation-file modes, rejects external alternates, loose
canonical objects, common-directory redirects and config includes, and holds an exact
operation-bound pack keep marker until durable ref publication. Canonical config is immutable for
the adapter lifetime. Git 2.36 is the
minimum and canonical repositories must use the `files` ref backend; staging explicitly pins the
same backend. Initialized staging metadata is file- and directory-synced, damaged pack metadata is
recovered from its durable token, and orphaned markers are released only after the matching durable
ref exists. Prefetch
evidence binds the exact exported source and current lockfile, while OCI provenance binds the raw
requested manifest/index, selected platform manifest and image config.

## Phase 5 — source, CI and image build without GitHub Actions

The canonical accepted branch lives in a dedicated local bare repository owned only by the `rdashboard-source` UID. Controller and build users cannot write its objects, refs, quarantine or accepted-head ledger.

### GitHub path

- Route only the narrow webhook endpoint to `rdashboard-source`; verify the raw body with HMAC-SHA256 and constant-time comparison before parsing.
- Deduplicate by delivery ID.
- Fetch before enqueueing.
- For a push event require `after` to equal the freshly fetched remote `main` head; an older reachable ancestor is a stale no-op, not a deploy request.
- Advance the canonical accepted head only by fast-forward and emit a signed accepted-head attestation. A rewind or unrelated remote history becomes `source_diverged/needs_owner` and pauses reconciliation.
- Respond quickly and process asynchronously.
- Periodically reconcile remote `main` to repair lost webhooks.

### Direct fallback path

- `git push prod main` enters `rdashboard-source` quarantine through a forced SSH command.
- Keys are mapped to an operator/project identity and provide no interactive shell.
- Accept only `refs/heads/main` and fast-forward updates.
- Advance the same canonical local branch used by the webhook path.
- GitHub/local divergence becomes `source_diverged/needs_owner`; never guess which history wins.

Webhook, periodic reconciliation and direct push all feed the source broker's canonical-head compare-and-swap and signed attestation. They then resolve the same stable deployment request `(project, SHA, operation kind)`; a stale delivery can acknowledge the already-known request/attempt but cannot enqueue new work.

`AcceptedHeadV1` uses canonical signed fields and a monotonic sequence plus short expiry. A signature or merely increasing sequence is insufficient by itself: after CI/build and immediately before the first backup/migration/deploy side effect, the executor obtains the live current head/sequence directly from the source broker socket and compares both. If a newer head exists, the still-pre-mutation attempt is superseded/blocked; if the broker is unavailable, automated deploy waits fail-closed. Explicit code rollback uses the retained LKG release-bundle contract rather than pretending an old SHA is current `main`.

Those admission failures project as `source_head_superseded`, `source_attestation_invalid` or `source_broker_unavailable`, never as a generic hang or source divergence. A recovered broker wakes the blocked attempt for a fresh admission check; a superseded head terminates the old delivery without mutation and lets normal reconciliation create the new delivery.

Support project-level `blocked_sha` and `reconcile_paused_until` controls so the reconciler cannot deploy a known-bad commit.

### CI isolation and TOCTOU prevention

1. Verify the source-broker attestation, then export the immutable Git object tree into a fresh read-only source tree; derive and hash the Dockerfile and base source context before any repository code runs.
2. A fixed package-specific prefetch adapter parses reviewed lockfiles, uses sanitized tool configuration, forbids repository credential helpers/install/build scripts, and downloads only integrity-pinned artifacts from allowlisted registries. If a package manager must participate, it runs without secrets/private-network access, with egress restricted to those registries and all scripts disabled. The resulting cache is untrusted, checksum-verified and mounted read-only later.
3. Run any separately declared generator without network using the immutable source and read-only dependency cache. Copy only allowlisted outputs with size/type/path limits and individual hashes into a new context; reject tracked-source/Dockerfile changes and undeclared paths.
4. Resolve every Dockerfile `FROM` through a trusted adapter, inject the selected digests, then freeze and hash the final context. Run `CI=true bin/ci` against a disposable writable clone of that same context, with compiler/temp outputs redirected outside context-relevant paths and without production secrets, Docker, loopback/RFC1918 access or either executor socket. Reject any CI change to source, Dockerfile or declared generated outputs.
5. The build identity builds the untouched frozen final context that CI just validated, never the CI clone or a mutable checkout.

Egress deny, scratch/cache byte quotas, journal/output quotas and process limits are mandatory, not best effort. Future CI that needs Postgres, Redis or similar integration dependencies receives an isolated rootless Podman network and throwaway volumes; it never receives the production Docker socket or production service network.

Rootless BuildKit is the preferred pilot target. If Kamal compatibility prevents it, record and constrain the remaining root build boundary explicitly; the immutable-context and no-repository-config rules still apply.

Production accepts only allowlisted registries and digest-pinned bases; a mutable tag is either rejected or resolved once before the context freeze. Record all base digests in build evidence and the release bundle.

### Image and registry contract

- image tag is the full immutable source SHA;
- record registry digest and local image ID;
- verify the image before cutover;
- use `localhost:5555` as an ephemeral Kamal registry transport;
- import and verify the candidate in the local Docker image store before registry teardown; registry state itself is never a rollback dependency;
- retain current and last-known-good images locally and as encrypted offsite OCI layouts until the release retention policy permits deletion;
- recover or remove a stale registry after controller restart;
- never prune rollback artifacts after an operation begins.

For the current and last-known-good releases retain an immutable root-owned release bundle outside `/run`: signed policy/template digest, source attestation, frozen context/generated-output/base/image digests, sanitized generated Kamal configuration, schema/rollback contract and credential-version references without secret values. A bundle and every still-authorized credential version remain until the release stops being a rollback target. Security rotation may deliberately revoke a credential version; that makes the affected rollback explicitly ineligible rather than silently changing its runtime contract.

### Kamal execution contract

- Ignore managed-repository `config/deploy.yml`, `.kamal`, hooks, destinations and ERB when executing a dashboard deploy.
- Generate the complete Kamal configuration from the installed root-owned project policy and fixed root-owned templates into an operation-scoped directory under `/run/rdashboard`.
- Disable repository hooks and command/ERB substitution. Resolve and validate every host path, bind mount, network, port and secret name against an allowlist before invoking Kamal.
- Permit the repository to influence only its immutable source/build context and declared generated outputs; it cannot add Docker privileges, host volumes, environment, commands or accessories.
- Persist the generated plan hash and sanitized diff as operation evidence. An executor dry run must match that plan before mutation.

### Resource preflight

Required free space is calculated from:

```text
emergency reserve
+ backup snapshot and upload staging
+ new image/build peak
+ local registry transport peak
+ current last-known-good image
+ projected control/metrics/log growth
```

Insufficient reservation sets `blocking_reason=disk_reserve` while the operation remains in preflight; it does not create a second state enum.

### Phase 5 gate

A GitHub webhook, a missed-webhook reconciliation and a direct push all reach the same attested immutable queue. Tests include controller attempts to rewrite canonical refs, quarantine bypass, bad/expired source attestation, replay of a formerly valid attestation after a newer accepted head, broker outage at mutation admission, stale ancestor events, force-push/rewind, cross-channel duplicate delivery, prefetch install-script/credential-helper execution, generated artifacts that fail CI, CI attempts to rewrite the Dockerfile/source, mutable base-tag digest changes, malicious checkout Kamal files, network/RFC1918 access and scratch/log quota exhaustion. CI/build failure capsules identify the causal step without requiring the full raw log.

Current implementation note: source admission has a real bounded Git command adapter, durable
ref/update/divergence/mutation journals and an OS singleton lock backed by a monotonic SQLite epoch.
The adapter negotiates repeated and divergent fetches against canonical objects as a read-only
alternate, stages all writes, handles a zero-pack same-head result, pins pack/index/ref fsync
semantics and protects promoted packs from concurrent repack until durable publication or recovery.
Startup retains unknown-project staging, safely replays a missing marker from a valid staged pack and
reports unresolved orphan markers rather than deleting recovery evidence.
Build contracts bind the immutable context through CI, image, generated Kamal plan and release
bundle. Prefetch cannot be replayed across source exports or a changed `Cargo.lock`, and base-image
resolution verifies the raw registry index/manifest, selected platform manifest and config chain.
Disk admission is filesystem-bound, rechecks a fresh local observation on every acquire,
counts the emergency floor once across concurrent operations and migrates fail-closed. Release
bundles have canonical independent verification and atomic owner-only persistence. The installed
source/executor sockets, hardened transient units, fixed privileged backup/Kamal/health effects and
restart-safe first-bootstrap worker are implemented locally. Bootstrap consumes a signed candidate
through an exact non-root owner/read-group handoff. The source broker now publishes the accepted
immutable Git tree itself; the constrained producer remains responsible for consuming that export,
isolated `CI=true bin/ci`, the rootless BuildKit image/OCI archive and signature. The release bundle
binds that archive, the executor promotes it privately, and the Kamal adapter imports and re-verifies
it through a bounded digest-pinned ephemeral registry. The controller exposes versioned fail-closed
prepare/execute/status endpoints and browser operation observation. Webhook and quarantine front
doors, the producer service, authorizer, installed upgrades and rollback remain unimplemented and
must not be inferred from the bootstrap executor tests.

## Phase 6 — backup, migration, deploy and rollback protocol

Phase 6 starts with a typed adapter foundation, not by exposing the existing repository Kamal
command. A root-owned `InstalledRimgPolicyV1` binds the exact service/network/alias, UID, mounts,
clear environment, health command, timeouts, logging, schema/fence versions, backup units,
consumer-network smoke target and bootstrap/rollback capability. The executor resolves each
`PhaseIntent` to an `AuthorizedPhaseSpecV1`; fixed-argv backup, rimg-admin and Kamal runtime adapters
execute that spec and prove the result from observed state. Controller input, repository Kamal YAML,
exit status and log text never become authority for a privileged command or proof of success.

Before mutation is enabled, `rimg` must expose machine-readable schema inspect/migrate and persisted
admin status/fence/drain operations, stop migrating during normal startup, report worker/webhook and
storage-write readiness truthfully, and support coherent verified SQLite plus masters backup.
Bootstrap may use declared downtime and has no rollback target. A second deploy remains disabled
until stable routing/cutover and rollback compatibility pass their drills.

Classify every release before preflight:

- `code_only_compatible`: no schema/data-contract change; keep the current release serving while the candidate starts and passes checks, then perform a gapless cutover;
- `stateful_compatible`: explicit migration with proven old/new read-write compatibility, but still requires the stateful protocol;
- `stateful_breaking`: irreversible or old-image-incompatible migration; requires an operation-bound operator confirmation and has no automatic code rollback after migration.

Repository metadata may propose a class but cannot authorize it. The installed owner-reviewed policy and executor-side schema/migration inspection decide the effective class. An automated `stateful_breaking` deploy pauses before mutation until it receives a valid interactive action grant. For stateful projects use this bounded protocol:

```text
brief consistency boundary when required
→ create and verify encrypted local base snapshot
→ release the consistency boundary
→ upload and verify the base snapshot offsite with a deadline
→ stop intake and drain workers
→ acquire operation-owned write-fence epoch
→ create and verify the exact local cutover snapshot/delta
→ migrate and deploy
→ readiness, smoke and soak
→ release the write fence and intake
→ upload the exact cutover snapshot asynchronously
```

The final maintenance/write fence is never held while waiting for the initial offsite upload. Initial migration-backup freshness is at most 60 minutes at the mutation boundary unless a stricter project policy applies. If the base upload misses its deadline, abort before final maintenance. If a deadline/crash occurs after migration starts, keep the fence fail-closed and enter reconciliation/manual recovery rather than reopening writes blindly.

### Backup contract

- Use the SQLite Online Backup API for live WAL databases, never a plain copy of only the main `.db` file.
- Run SQLite `PRAGMA integrity_check` against the completed snapshot.
- Run `PRAGMA foreign_key_check`, project-declared domain invariants, database-to-master/blob reconciliation and a staged boot/read smoke check.
- Record cryptographic checksums for the database, masters/blobs and canonical manifest; record missing and unexpected files explicitly.
- Encrypt locally before provider upload using authenticated encryption. The pilot uses age/X25519 recipients, stores the ciphertext hash outside and plaintext hashes inside the encrypted manifest, and never sends a plaintext archive or recovery key to Drive.
- Upload versioned encrypted artifacts to Google Drive through the backup-provider interface.
- Keep provider, object ID, size, checksum, timestamps and encryption metadata.
- A successful upload without integrity evidence is `backup_unverified`, not success.
- Run scheduled restore drills into new paths and record duration, ownership/mode checks, schema/invariant evidence and result.
- Back up `control.sqlite`, root security-journal snapshots, signed policy/release bundles, source-broker accepted-head ledger and encrypted Git bundles containing canonical/direct-only commits, current/LKG OCI layouts and dashboard configuration as well as managed application state.

The decryption recovery key and a minimal signed recovery kit (binary/checksum, pinned policy/source/intent public keys, policy/schema, restore runbook and credential inventory without secret values) live outside both the VPS and the Drive account. A clean-host drill must prove that a fresh machine can retrieve, decrypt, validate and start a staged copy without trusting `control.sqlite`, the old Docker store or GitHub availability.

Separate an availability-only disaster from suspected host compromise. Both bootstraps rotate executor-intent, authorizer-grant and source-attestation signing-key epochs, install their new public keys through a newly offline-signed policy bundle, invalidate every pre-disaster grant/attestation session, restore or formally reseed the security journal, and choose a new fence epoch above every value found in recovered journal and application state. Retired public keys remain verify-only for historical evidence and cannot authorize new intents. The executor accepts a grant only when its intent ID is an unexpired current-epoch receipt in the recovered `security.sqlite`. Any operation lacking a complete trusted receipt chain becomes `needs_reconcile`; it is never inferred successful from controller history alone.

If compromise cannot be excluded, external revocation precedes connecting the replacement host to any provider. Revoke and replace every private or bearer credential available to the old VPS: Git fetch/deploy credentials and webhook HMAC, origin TLS key/certificate, Drive/rclone and registry credentials, Telegram Bot API token, OpenCode key, dashboard session/service secrets and every managed-project runtime secret reachable from the host. Provision the replacement host only with new versions, update release/policy credential-version references, and mark rollback bundles that require revoked versions ineligible. The recovery audit records every credential-inventory row as rotated, proven absent or explicitly out of scope; a drill must demonstrate that old credentials fail against their providers. An availability-only recovery may retain an external credential only after documented proof that the old host is destroyed or isolated and its secret was not exposed.

The Drive credential can delete Drive objects, so this provider is explicitly not ransomware-resistant. Dashboard copy and audit text must not imply immutability. Add a second independently credentialed provider before claiming protection from credential compromise or destructive deletion.

Initial policy:

- migration deploy: fresh verified local and offsite backup required;
- code-only deploy: last verified backup may be up to 24 hours old;
- RPO: 24 hours;
- RTO: 2 hours;
- derived artifacts may be excluded only after a timed regeneration drill proves the RTO.

### Migration and deploy

- Migrations are explicit, idempotent and recorded separately from application startup.
- Detect and display irreversible/destructive steps before mutation; a `stateful_breaking` deploy requires the operator to type the project name and migration identifier in the action grant flow.
- Deploy uses immutable SHA-tag and verifies the recorded digest/local image ID.
- A release becomes `last_known_good` only after readiness, consumer-network smoke and soak pass.
- The first install has `rollback_unavailable`; this is expected.

Before the second/post-bootstrap deploy, select and install the stable routing component. Its gate proves candidate isolation, consumer-network health, atomic switch, connection drain, failed-switch rollback and proxy restart/reconciliation. Gapless `code_only_compatible` deployment is not enabled until this gate passes.

Current implementation note: Phase 6A now provides canonical, deny-unknown-field contracts for
the installed rimg/Kamal policy, owner-reviewed schema transitions, executor-derived release
classification, runtime release state, operation-bound mutation grants, fixed adapter profiles and
authorized phase specifications. Only exact protocol version 1 is accepted by the current fixed
argv adapters.
Migration-plan and data-compatibility results are typed evaluation envelopes rather than bare
caller-provided digests. They bind the evaluated owner-installed contract to the exact intent,
policy, project, schema pair, migration identifier, verdict, observation and time, and are checked
again when release classification is derived.
The inspected current and candidate schemas must also match the exact verified release bundles,
including project ownership. Phase resolution accepts a derived
`ReleaseClassificationAuthorityV1`, revalidates its complete inspection/classification input and
does not treat a serialized, self-digested classification document as authority. Release bundles,
backup evidence and Phase 6 authorization share one bounded ASCII schema-version validator.

Backup evidence is one canonical verified chain: base snapshots bind manifest, local encryption,
provider receipt and offsite readback; cutover snapshots bind the fenced local manifest and
encryption evidence. Freshness is recalculated against a new synchronized clock, and the base
upload/readback deadline is enforced before drain. Stateful execution now orders
`backing_up → draining → cutover_snapshotting → migrating`; the live source ticket is acquired for
the exact accepted head before the base backup starts and remains owned through drain and the
pre-fence refresh. A temporary broker outage at that boundary keeps the ticket, project lock and
disk reservation for an explicit retry; any non-transient mismatch enters reconciliation without
silently undraining or releasing ownership. Only a matching refreshed proof can acquire the write
fence. The exact fence receipt, epoch, base chain and cutover chain are bound into later privileged
specifications.
An ambiguous first admission or failed pre-effect abort stays on the original source-retryable
phase with the owners held. Replaying that phase idempotently reacquires the same ticket and avoids
a receipt-less reconciliation state that could never converge.

The root-side security journal is schema v14. It stores canonical phase specifications and verified
backup-chain documents, revalidates prerequisite chains and the active secret-bound fence before a
permit, expires stale authority, consumes stateful-breaking grants exactly once and records a
durable per-project bootstrap reservation/receipt. A `NeverInstalled` bootstrap intentionally
requires neither a backup of nonexistent state nor a fence; any later installed deploy requires a
fresh verified base chain and stateful deploys require the active fence. Data restore remains a
separate manual operation. Authorized phase specifications also bind the exact expected build,
reservation, source, fence, classified migration target schema, deployment and rollback artifact
identities. Observations reject both
substitution and evidence owned by another phase, reservation evidence is internally revalidated
before release-bundle sealing, and even an idempotent fence acquisition rechecks committed base
backup and drain receipts. The journal independently resolves an artifact's source proof to the
persisted `BackingUp` proof for base/drain or the persisted `Deploying` proof for code-only deploys.
That binding is an exact optional comparison: a persisted proof cannot be omitted by the executor,
and a proof is rejected on phases that authorize none. Rejection or an invalid source sequence
commits `needs_reconcile` in the security journal before the typed admission error is returned.
For stateful work it reserves one executor-owned epoch/token before drain and atomically promotes
that same identity into fence acquisition after the committed drain receipt, so application drain
and fence recovery cannot diverge onto different operation identities.
It also stores the complete audited claims of every consumed Ed25519 action grant and enforces
durable nonce uniqueness. Only an exact replay by the same attempt is idempotent; nonce reuse by a
different attempt fails closed, and an unconsumed expired grant cannot enter the journal.
Prepared operation intents are separate five-minute Ed25519 receipts under the executor intent key.
They bind the exact request, project, operation, immutable target, proposed and executor-derived
release class, installed policy, source authority, migration/rollback target and canonical
confirmation consequences. The executor persists its own signed intent before returning it and
rejects any conflicting request/intent/token/digest identity after restart.
The intent derives a minimum role (`admin` for stateful-breaking deploys and code rollback,
`operator` otherwise). The root journal authenticates the grant signature first and then consumes
the persisted intent, nonce and attempt in one immediate transaction. Failure, restart or role
rejection leaves both ledgers unconsumed; exact delivery replay is idempotent only for the same
intent, grant and attempt.

The separate `rimg` repository now supplies the Phase 2 machine APIs. A live read-only root
executor implements bounded single-request framing, strict version negotiation, peer-UID
authorization, deadlines, safe socket lifecycle and truthful host observations; the controller can
consume it through the fixed production socket and records `signal_lost` on failure. Hardened
systemd units preserve that process boundary. Mutation requests and project Docker/systemd
observations still fail closed: no real backup/Kamal effect or production deployment is enabled
until the signed-grant, fixed-adapter and recovery drills pass.

### Rollback and restore

- Code rollback and data restore are different operations.
- Data restore is never automatic.
- Manual restore is SSH-only through `sudo rdashboard-recover`; it requires maintenance/write fence, a fresh safety snapshot of current state, typed project/backup confirmation, a verified source snapshot and post-restore integrity/health checks.
- Restore always targets new database/file paths first. Validate schema, project identity, UID/GID/modes and domain invariants, then switch by atomic rename/symlink or a documented reversible multi-volume cutover. Never overwrite the only current copy in place.
- Automatic code rollback is allowed only when owner-reviewed policy proves an unchanged data contract or bidirectional read/write compatibility.
- Deploy-commit metadata alone cannot grant rollback compatibility.
- Permit at most one automatic code rollback attempt.
- Failure becomes `rollback_failed/manual_recovery_required`; never loop.

### Phase 6 gate

Drills cover CI failure, disk preflight failure, backup corruption, offsite timeout before maintenance, crash around every security-journal/fence acquire/snapshot/migration/release boundary, routing switch/restart failure, failed health/soak, successful compatible code rollback, rollback-ineligible schema, migration succeeds followed by an old-image-incompatible application failure, rollback failure, staged atomic restore and clean-host recovery with the external recovery kit. Destructive migration/restore drills run first on a production snapshot clone in isolated paths and networks; live production exercises only approval/fence/abort until a separate owner-approved maintenance event is justified by a successful clean-copy drill.

## Phase 7 — host and project telemetry

### Host metrics

- CPU usage, load and PSI;
- memory, swap and OOM;
- disk capacity, inodes and IO;
- filesystem status;
- network throughput, drops and errors;
- TCP/socket summaries;
- Docker/cgroup resources and restarts;
- systemd unit state;
- temperature where available;
- controller/source/authorizer/executor/notifier CPU, RSS, storage and loop progress;
- notification outbox depth, oldest-undelivered age, last delivery-receipt age and gateway/direct-path availability;
- wall-clock synchronization state and estimated offset.

### Project metrics

- internal and external health;
- source age and collector age;
- request latency and error quantiles;
- container restarts and resources;
- queue/worker progress;
- active and last-known-good release;
- deploy phase and duration;
- database/volume growth;
- last backup, checksum, offsite state and last restore drill.

Use mergeable quantile sketches for median/percentile rollups; never compute a median of medians.

Initial retention:

- raw samples: 24 hours;
- one-minute rollups: 30 days;
- fifteen-minute rollups for one year only after measuring actual cardinality and database size.

The unprivileged controller obtains Docker/cgroup and protected systemd facts only through bounded read-only executor calls such as `ObserveDockerSnapshot` and `ObserveSystemdUnits`. Responses contain a sanitized fixed schema, never raw environment, mount secrets, arbitrary unit properties or daemon API access.

Docker/system events are reconciled with periodic snapshots so dropped events self-heal. Every source declares `expected_interval`, `stale_after` and `dead_after`; every measurement carries source/receive time and one of `fresh`, `stale`, `signal_lost`, `partial`, `unsupported` or `unknown`. Missing evidence never becomes healthy. Incident recovery/resolution requires a fresh positive observation rather than elapsed time or a reconnect alone.

Viewing remains available with a clock warning, but JWT/action grants and mutations fail closed when the host reports unsynchronized time or an estimated offset above 30 seconds. Offset above 10 seconds opens a warning incident; above 25 seconds is critical and notifies through the outbox before the hard block. The external watchdog health contract exposes clock status separately from application liveness.

The controller systemd watchdog is refreshed only when all critical controller loops continue to progress. The notifier has its own watchdog tied to socket/outbox progress rather than mere process liveness; systemd restarts it on crash or hang, and the durable controller outbox is replayed with the original idempotency key. This detects a stuck collector or notifier rather than merely a live process.

Expose a versioned minimal `/health/external` contract for the future independent VPS watchdog. It reports only dashboard build ID, critical control-plane loop/storage status, clock status and age of the last complete critical collection; it reveals no project, log or incident detail. Return non-2xx when a critical loop is dead, persistence is unavailable, the clock is unsynchronized/critical or the observation is older than its `dead_after`. Production access will use a dedicated Cloudflare service-token audience unless an explicit later decision makes this minimal endpoint public.

### Phase 7 gate

Tests cover counter reset, clock skew/unsynchronized time, missing sensors, process restart, dropped events, delayed and permanently missing sources, stale-to-signal-lost transitions, fresh-positive recovery, notifier loop/receipt staleness, sanitized privileged observations, retention compaction and storage-cap enforcement.

## Phase 8 — logs, GlitchTip and failure capsules

Store bounded raw logs as compressed zstd segments with per-project quotas. SQLite stores indexes, correlation metadata and structured events, not unlimited log bodies.

Expose logs through a cursor-and-time-range protocol with bounded page size, server-side query deadline and result-byte cap. Retention eviction or a dropped live-tail segment emits a typed gap marker containing the missing time range and estimated/known event count. Follow mode pauses when the operator scrolls away from the tail and resumes only on an explicit control; the browser buffer remains bounded.

Correlate by project, release SHA, operation ID, request/trace ID and incident where available.

GlitchTip remains the application error/performance backend. `rdashboard` displays aggregates, release correlation and deep links instead of duplicating GlitchTip's full event store.

Every failure capsule is deterministic and contains:

```text
project
source SHA
operation and step
exit code or signal
timeout/OOM flags
first causal error
bounded surrounding context
tool/runtime versions
previous and attempted release
health evidence
```

Redact before persistence and before any external AI call.

Treat every log, exception, AI summary and deep-link label as hostile text. Render through text nodes, never raw HTML. Use a strict nonce/hash Content Security Policy without inline/event-handler execution, disallow SVG/HTML injection in log content, and allow deep-link schemes/hosts from root-owned project policy only.

### Phase 8 gate

Adversarial logs, multiline compiler failures, secrets, ANSI output, very long lines and prompt-injection-shaped input produce bounded redacted capsules while retaining the actual failure cause. Browser fixtures include `<script>`, SVG event handlers, `javascript:` links and malformed markup; quota eviction during live tail produces a visible gap rather than silently joining unrelated lines.

## Phase 9 — incidents, Telegram and AI summaries

### Incident lifecycle

```text
condition:   pending → firing → recovering → resolved
ack:         unacknowledged ↔ acknowledged(actor, time)
suppression: none ↔ manual_until(time) | maintenance(window)
```

Acknowledgement never changes whether the fault is firing, and suppression never fabricates recovery. On suppression expiry, notification policy is recalculated from the current condition/severity. Use persisted deduplication keys, debounce/flap policy, escalation timers and recovery events.

Each incident also carries severity, operator urgency, dependency/root-cause links, inhibition reason and a correlation group. Dependency policy suppresses symptom spam without hiding evidence: for example, filesystem exhaustion is the primary incident while derived database-write, log-ingest and container-health failures remain visible as inhibited children in one timeline.

### Notification delivery

Persist every notification in an outbox:

1. the controller persists only a typed fact packet plus notification/idempotency identity and submits that bounded packet to `rdashboard-notify`;
2. the notifier validates the schema, project and allowlisted chat, renders and rate-limits the compact message, then sends through `telegram-gateway`;
3. on gateway failure, the notifier alone uses the existing `@sartulibot` Bot API token to send to chat/channel ID `5057084213`;
4. the notifier keeps a bounded durable delivery journal keyed by notification ID and stores only route/state, rendered-payload hash and provider receipt metadata, never the bearer token;
5. delivery is explicitly at-least-once: local dedup returns a known receipt without resending, but a timeout or crash after provider acceptance is `delivery_unknown` and a severity-policy retry may create a duplicate carrying the same visible notification ID; never claim exactly-once delivery;
6. use bounded retry, backoff and rate-limit handling inside the notifier and return a safe delivery receipt to the controller without exposing bearer credentials;
7. keep the deterministic message if AI is unavailable;
8. use the separate systemd notifier for dashboard service failure.

Messages include the stable short notification ID, affected project, incident start/duration, release correlation, compact cause, attempted action/result and dashboard link.

Every attempt records the stable notification ID, route, attempt number, start/end time and safe provider receipt metadata. The dashboard exposes those fields and warns on `delivery_unknown`: “the message may already have been delivered; retry keeps the same ID.” A retry scheduled from that state is `retry_scheduled`; if it later succeeds, the terminal state is `delivered_possible_duplicate`, never plain `delivered`, so the ambiguity survives process restarts and operator handoff.

### DeepSeek adapter

```toml
provider_id = "opencode"
model_id = "deepseek-v4-flash-free"
allow_paid = false
```

Rules:

- presentation-only, never authoritative;
- input is only the redacted deterministic fact packet;
- strict JSON/Serde response schema;
- bounded input/output, timeout and cancellation;
- no tools, shell, deploy or rollback decisions;
- no raw unbounded logs, environment dump or secrets;
- store provider/model/prompt version, input/output hashes, latency and usage;
- record success, fallback, rate-limit and empty-response metrics;
- render deterministic summary immediately and AI text asynchronously;
- visually label generated text;
- use a deterministic template on every failure;
- never switch to a paid model automatically.

### Phase 9 gate

Gateway outage, bot rate limiting, duplicate incidents, flapping, process restart, AI timeout, malformed JSON, empty AI response and prompt-injection input preserve correct incident and notification behavior. Notifier crash, hang and restart replay the durable backlog with local idempotency; a fault injected immediately before and after provider acceptance proves the documented `delivery_unknown`/possible-duplicate boundary and stable visible notification ID. UI fixtures show attempt/route/time and the ambiguity warning, then prove `delivery_unknown → retry_scheduled → delivered_possible_duplicate` survives notifier/controller restart without collapsing to `delivered`. A controller `OnFailure` fixture proves delivery while the controller is down. UI and incidents distinguish `notification_degraded` (gateway failed but direct path works) from `notification_unavailable` (notifier or both paths unavailable). Tests prove that the controller cannot read the Bot API token, choose a non-allowlisted chat or smuggle an untyped/oversized message through the notifier, while notifier receipts remain safe to persist. A disk-full cascade produces one ordered root-cause notification plus correlated inhibited symptoms and resolves only after fresh evidence for the root and affected dependants.

## Phase 10 — TLS, Cloudflare Access and action authorization

Do not expose the dashboard before this phase passes.

### Origin and edge

- Fix the current TLS/525 condition.
- Put only the root-owned origin reverse proxy on public 443; dashboard processes listen on Unix sockets/loopback.
- Use Cloudflare `Full (strict)` plus per-hostname Authenticated Origin Pulls with account-specific client certificates for `dev.4u.ge` and `actions.dev.4u.ge`.
- Require the AOP client certificate at the reverse proxy and allow public 443 only from Cloudflare's published IP ranges; update the allowlist atomically and fail closed. Keep SSH policy independent.
- AOP is currently documented for the Free plan, but re-check account availability during deployment. Its purpose is origin provenance; origin JWT validation remains mandatory authorization.
- Keep `/hooks/github` isolated from browser endpoints.

### Access surfaces

- `dev.4u.ge/`: exact-email allowlist for normal dashboard access;
- `actions.dev.4u.ge/`: separate application/audience with shorter and stronger MFA policy, routed only to `rdashboard-authorizer`;
- `/hooks/github`: narrow Access Bypass because GitHub cannot perform interactive Access authentication; rely on HMAC, request limits and application audit.

Never use `Login Methods = One-time PIN` as the only allow condition because that permits any valid email address. Use exact allowed identities.

At the origin validate `Cf-Access-Jwt-Assertion`:

- signature and allowed algorithm;
- issuer;
- application audience;
- expiry/not-before;
- JWKS rotation;
- exact identity and role mapping.

Header presence alone is never authorization.

Both `rdashboardd` and `rdashboard-authorizer` validate their own exact audience. The authorizer also requires a recent MFA authentication context and emits only an intent-bound action grant; the controller cannot exchange its normal dashboard JWT for such a grant or read the separate-origin confirmation DOM.

`ActionGrantV1` uses deterministic CBOR and a fixed Ed25519 signature, never caller-selected algorithms. Its signed fields include version, issuer, executor audience, `kid`, issued/not-before/expiry (maximum two minutes), nonce, actor/role, lease ID/generation, executor-signed intent ID/hash, signed-policy digest and request/idempotency key. The executor holds a root-owned public-key set with explicit activation, overlap, retirement and emergency revocation epochs. Tests cover non-canonical encoding, wrong key/issuer/audience/policy/intent/lease, future/expired time, nonce replay and rotation/revocation. Executor intent receipts use a separate pinned signing key and equally canonical structure.

### Passkey decision gate

Before choosing a fallback, test on the real Free account:

1. Linux desktop Chrome: determine whether Cloudflare actually accepts a Google Password Manager passkey protected by its PIN without biometric hardware;
2. Windows desktop: determine whether the Cloudflare WebAuthn/Windows Hello path works with a Windows Hello PIN and no biometric requirement;
3. enrollment, login, recovery and revocation;
4. action reauthentication without losing dashboard context;
5. availability and behavior of Independent MFA for the actual account.

Do not enable TOTP merely because it is easy. The test must also establish whether Cloudflare provides a passkey-first access flow or only a second factor after email/IdP login. If either desktop path or the resulting access journey is unacceptable, stop and explicitly choose between a Cloudflare recovery method and application-local WebAuthn for primary sign-in plus action step-up; never silently fall back to Basic Auth.

Cloudflare currently documents independent MFA categories as hardware security keys and built-in device authenticators, so the Linux synced-passkey behavior is an empirical gate, not an architectural assumption.

For action reauthentication, first test the separate short-duration Access application/audience. If Access cannot provide a reliable recent-auth contract without destructive full-page context loss, add application-local WebAuthn for sensitive actions. If the earlier primary-access gate also rejects the Cloudflare journey, the same vetted credential subsystem may become primary sign-in only after an explicit architecture decision that replaces the `/` Access identity boundary while retaining Cloudflare edge/AOP protection; do not stack two ambiguous account systems. Its action challenge is bound to the signed-in user and exact action; `allowCredentials` contains only that user's registered credentials, verification requires matching credential ownership and user verification, and at least two credentials or an explicitly chosen recovery method are required before relying on it.

### Browser action protection

- authenticated actor and role;
- current active-tab lease token;
- CSRF and Origin checks;
- action idempotency key;
- recent-auth gate;
- top-level separate-origin canonical confirmation, never a controller-controlled dialog or iframe;
- typed project-name and migration/release identity confirmation for manual code rollback and stateful-breaking deploy actions;
- no grants in URLs/referrers: after confirmation the authorizer sends a one-time POST from its origin to the controller operation endpoint;
- on auth/lease loss close any confirmation UI, destroy the grant and local mutation draft, reload a fresh snapshot, and require new recent-auth plus full confirmation; preserve only read-only navigation context;
- append-only audit event.

### Secrets

Use root-owned systemd credentials as the single source of production secrets. Prefer `LoadCredentialEncrypted`; otherwise use root-owned `0400` credential files outside project trees and backups. Long-lived services receive only named credentials through `$CREDENTIALS_DIRECTORY`.

Minimum credential inventory and isolation:

| Material | Recipient | Explicit exclusion |
| --- | --- | --- |
| Offline policy-signing private key | operator-controlled system outside VPS | every VPS process; executor receives only pinned public key |
| Executor intent-signing key | executor only | controller, authorizer and source broker |
| Authorizer action-grant key | authorizer only | controller, executor private-key store and source broker |
| Source-attestation key and GitHub webhook HMAC | source broker only | controller, build and authorizer |
| Origin TLS server private key | root-owned reverse proxy only | all dashboard services; the AOP trust anchor is public, and the AOP client private key is provisioned to Cloudflare rather than stored on the VPS |
| Backup age recipient public key | executor backup path | no decryption key on the VPS during normal operation |
| Backup recovery identity | off-VPS recovery custody; supplied only to root recovery session | Drive, controller and long-lived service credentials |
| Drive/rclone and registry credentials | executor operation-scoped credential set | controller, source, build and AI |
| Telegram bot token | `telegram-gateway` and `rdashboard-notify` only | controller, executor, build, source, authorizer and AI input |
| OpenCode API key | controller AI adapter only | executor, source, authorizer, logs and fact packets |

For Kamal, the executor materializes only the operation's required variables into a root-owned `0600` directory on `/run` tmpfs, points the generated root-owned Kamal configuration at it, redacts command output and removes the directory after the transient unit exits. Kamal-created host env files are inventoried root-owned runtime artifacts, excluded from backups/logs and replaced on rotation. Rotation is an audited credential update plus controlled redeploy; no secret value enters repository manifests, SQLite, the browser or AI packets.

Systemd and filesystem tests prove each service cannot read another service's credential directory, `/proc` environment or runtime secret files. Credential versions referenced by a release bundle are retained only while policy permits; emergency revocation takes precedence and makes incompatible rollback unavailable.

### Phase 10 gate

Direct-origin/AOP failures, missing/forged/expired/wrong-audience JWTs, controller iframe/CORS/Service-Worker attempts against the action origin, forged executor intents, controller attempts to mint or replay action grants, payload substitution, stale action authentication, role bypass, lease race, CSRF, signer/JWKS rotation and cross-service credential reads fail closed. Real Linux and Windows enrollment results are a gate output recorded before production exposure, not a prerequisite value assumed in advance.

## Phase 11 — complete desktop operations console

The early read-only slice evolves alongside backend phases instead of receiving all UI work at the end.

### Layout

- compact global/status bar;
- host metric strip;
- project health/deploy matrix as the main workspace;
- incident/deploy rail;
- lower drill-down panels for metrics, logs, backups, releases and audit;
- incident focus mode that collapses unrelated secondary panels and prioritizes the causal timeline and safe actions.

The primary operational picture fits both target resolutions. Secondary regions may scroll.

### Required states

- loading, empty, partial, stale, disconnected and retrying;
- telemetry signal lost/unknown and clock unsynchronized;
- session expiring and reauthentication required;
- permission denied;
- active-tab lease revoked and takeover available;
- operation queued/running and cancellation boundary;
- source diverged, broker unavailable, head superseded, attestation invalid, blocked SHA and reconciliation paused;
- policy unavailable, invalid or stale and security state invalid, each with retryability and its safe runbook;
- preflight blocked and storage quota exhausted;
- backup pending, unverified, corrupt or offsite degraded;
- maintenance and migrating;
- rollback unavailable, ineligible, failed and manual restore required;
- incident firing/recovering independently from acknowledged/suppressed state;
- notification path degraded/unavailable plus per-notification pending, delivery unknown, retry scheduled, delivered possible duplicate and permanently failed;
- AI unavailable/fallback active;
- long-content truncation and archived-log retrieval.

### SSE and tab lease

- snapshot plus monotonic sequence;
- resume from last event where possible;
- every stream exposes a committed watermark; a sequence gap, server queue overflow or retention gap emits `resync_required` and forces a clean snapshot;
- one active lease per authenticated user;
- a new tab revokes the prior lease;
- a same-tab reload/reconnect reuses a `sessionStorage` tab instance ID within a short server grace period and must not revoke itself; duplicated-tab ID collisions are detected and one tab receives a new instance ID before lease arbitration;
- the revoked tab visibly pauses updates, disables mutation controls and offers takeover;
- backend collection and active operations continue regardless of browser tabs;
- mutation requests must carry the current lease token.

Server and browser queues are bounded to the smaller of 512 events or 2 MiB per connection. Replaceable metric updates may coalesce by series, but operation, audit, incident, lease and notification transitions never coalesce or drop silently. A takeover/reconnect snapshot includes all active operations so the new tab cannot mistake an in-flight mutation for an idle system.

Permit at most two simultaneous SSE transports per authenticated user during reconnect/takeover grace and 32 globally for the pilot; excess connections receive a typed capacity response and visible retry state. This cap is independent from the one-active-lease rule and is measured against `LimitNOFILE`.

On a reference laptop with 4 logical cores and 8 GiB RAM in current stable Chromium at both target viewports, the initial browser acceptance budget is: at most 160 MiB steady/220 MiB burst JS heap, return below 180 MiB within 60 seconds, at most 5,000 live DOM nodes, p95 input-to-visible-feedback below 100 ms and resync within 5 seconds on the controlled 100 ms/10 Mbit test network. Sustained overload first pauses live logs and progressively coalesces/lowers metric paint frequency while preserving incident, operation, auth and lease transitions; it must not enter a resnapshot loop.

Terminate or reauthenticate SSE no later than Access JWT expiry and on local role/session revocation; periodic short stream renewal bounds revocation delay. The browser presents `auth_expired` separately from a network outage and restores filters/selection after successful reauthentication.

### Accessibility and browser behavior

- semantic headings, landmarks and data tables;
- a skip link and meaningful table captions/row and column headers;
- data-table alternative for complex charts;
- native buttons and `<dialog>` for ordinary in-origin confirmations; mutation authorization remains the separate action-origin flow;
- logical keyboard order and visible focus;
- one centralized polite and one assertive live region without announcing every metric update;
- no status communicated by color alone;
- virtualized logs with a bounded in-browser buffer;
- initial browser log budget: 5,000 entries or 8 MiB, whichever comes first; eviction is represented by the same visible gap marker as server retention;
- preserve filters, selected incident and relevant scroll state across reauthentication;
- return focus to the invoking control after dialogs, reauthentication and cancelled takeover; move it to a clear status heading after a completed navigation/state replacement;
- honor `prefers-reduced-motion` and meet text/UI contrast requirements;
- test keyboard-only operation, 200% zoom and the accessibility tree rather than relying only on visual screenshots or automated scores.

Live-region mapping is explicit: a new critical incident, rollback failure, auth loss or lease loss is assertive; ordinary operation/connection transitions are deduplicated/coalesced polite announcements; metric refreshes are silent. Bursts collapse by semantic key while preserving critical-before-routine ordering.

Incident focus mode is a defined workflow: entry selects a root incident; a pinned header fixes project, release, severity and age; the chronological timeline combines health evidence, deploy/backup changes, log gaps and inhibited children; actions are filtered by role plus orthogonal condition/ack/suppression state. Concurrent critical incidents remain switchable without changing the action target. Resolution keeps a read-only post-incident view until explicit exit, then returns focus to the invoking incident row.

### Phase 11 gate

Browser tests cover same-tab reload without self-revocation, duplicated/new-tab takeover for one user, independent sessions for two users, atomic lease-generation/action races, stream global/per-user capacity and queue overflow/resync, overload shedding without loss of critical transitions, session expiry/revocation with destruction of mutation drafts, stale and signal-lost telemetry, the complete incident-focus workflow, live-tail pause/gaps, stored-XSS fixtures, measured browser budgets, disabled actions and all destructive confirmation paths. Add manual smoke checks with Orca/Firefox on Linux and Narrator/Edge on Windows, including focus return and live-region urgency/burst ordering.

## Phase 12 — pilot rollout and acceptance

Roll out in increasing-risk stages:

1. shadow host/project metrics;
2. read-only local dashboard;
3. authenticated read-only dashboard;
4. backup-only and restore into a clean location;
5. source sync and CI;
6. build and ephemeral registry without deploy;
7. full state machine in dry-run mode;
8. first `rimg` bootstrap deploy with declared downtime allowed;
9. bootstrap health, smoke and soak;
10. deploy a second compatible release and establish it as a distinct last-known-good target;
11. deploy a controlled rollback-eligible failing release and prove automatic code rollback to that target;
12. incompatible migration/application-failure and SSH-only manual recovery drill on an isolated production snapshot clone; live production proves approval/fence/abort only;
13. notification gateway outage and direct bot fallback, followed by notifier crash/hang/restart with durable backlog replay/local dedup, the ambiguous-provider duplicate boundary and controller-down `OnFailure` delivery;
14. recorded operator game day at both target viewports: root-cause cascade, inhibited symptoms, live-log gap, SSE resync, action reauthentication, acknowledgement, safe action and fresh-evidence recovery;
15. controller/source/authorizer/executor/notifier restart and VPS reboot reconciliation;
16. clean-host offsite Git/data/OCI/security-state decrypt/restore drill within the two-hour RTO;
17. suspected-compromise bootstrap drill that revokes every old-host credential, installs only new versions and proves the retired credentials fail at each external provider.

Before canary, measure and record:

- cold-build duration and peak RAM/disk/IO;
- image and registry transport peak;
- per-service and aggregate control-plane steady RSS and idle CPU;
- metric cardinality and database growth;
- log growth and compression ratio;
- backup duration, size and upload throughput;
- alert delivery latency and false-positive rate;
- reference-browser steady/peak heap, DOM nodes, input latency, SSE backlog and resync duration under expected and 10× burst;
- health/smoke/soak duration;
- remaining emergency disk reserve.

Validate the provisional Phase 1 caps against those measurements and tighten them where possible. Any relaxation requires recorded peak evidence and must preserve the emergency reserve; do not rely on the previous VPS snapshot without re-measuring current state.

### Pilot completion gate

- `rdashboard` passes its `bin/ci` with no arguments;
- `rimg` passes its `bin/ci` with no arguments;
- every required drill has linked evidence;
- no unresolved `needs_reconcile`, corrupt backup or rollback-safety issue remains;
- no web/controller path can invoke data restore or supply repository-controlled Kamal policy;
- executor security receipts, source attestations and signed policy/release bundles form a complete recoverable chain for current and LKG;
- Drive backups are labelled as encrypted offsite copies, not immutable backups;
- GitHub Actions runner is removed from the `rimg` production path only after the local path passes all gates;
- the future external watchdog has a stable authenticated or intentionally public health endpoint contract.

## Later project onboarding

After the `rimg` pilot, onboard projects through manifests rather than project-specific dashboard code:

- `sartuli.ge`;
- `keyroom`;
- `telegram-gateway`;
- `umove`;
- additional services added later.

Each project must declare its own health, CI, migration, data, backup, smoke, rollback and notification policy before mutation actions are enabled.

### `rdashboard` self-upgrade

Do not onboard `rdashboard` through the generic controller-driven project path. Its self-upgrade is a later, separate protocol because the controller is the operation-state writer and owns its own database backup. The executor must own upgrade continuation, old/new binary health arbitration and automatic binary rollback while the controller is stopped. A clean-host/offline runbook must restore `control.sqlite`, policy and binaries without requiring the dashboard to be healthy.

## Reference documentation

- [Cloudflare Access JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Cloudflare Access application paths](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/)
- [Cloudflare Access policies and Bypass](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [Cloudflare Independent MFA](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/independent-mfa/)
- [Cloudflare Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/)
- [GitHub webhook signature validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [SQLite Online Backup API](https://www.sqlite.org/backup.html)
- [SQLite WAL](https://sqlite.org/wal.html)
- [Google Drive delete semantics](https://developers.google.com/workspace/drive/api/guides/delete)
- [Kamal environment and secret handling](https://kamal-deploy.org/docs/configuration/environment-variables/)
- [Kamal local registry](https://kamal-deploy.org/docs/configuration/docker-registry/)
- [Kamal proxy](https://kamal-deploy.org/docs/configuration/proxy/)
- [Kamal rollback](https://kamal-deploy.org/docs/commands/rollback/)

## Inputs required before their implementation phases

Do not put these values in this document or commit them:

- exact Cloudflare operator email allowlist;
- Cloudflare team domain, both application audiences, action hostname DNS and AOP material;
- access to the real Cloudflare Free account and the Linux/Windows test devices for the passkey decision gate;
- offline policy-signing public key and custody procedure for its private key;
- systemd credential names/rotation epochs for executor intent, authorizer grant and source-attestation keys;
- age backup recipient public key and off-VPS recovery-key custody procedure;
- OpenCode API base URL and systemd credential name;
- Telegram bot credential location;
- Google Drive/rclone credential location;
- per-project production secret locations;
- SSH public keys authorized for direct deploy pushes.
