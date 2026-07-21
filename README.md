# rdashboard

Low-resource Rust operations dashboard and deployment control plane.

The implementation is being built in gated vertical slices described in
[PLAN.md](PLAN.md). The browser process remains deliberately bound to loopback: it records real Linux
host and `rimg` health observations in SQLite, exposes resumable SSE updates and presents current
host resources beside one-hour, one-day, one-week and 30-day medians. The controller mutation API can
acquire a tab lease, prepare a root-signed intent, admit an authorizer grant and follow the resulting
operation; it remains fail-closed when the separate authorizer or executor mutation authority is not
installed. The durable control plane, bounded Git source adapter and Phase 6A typed backup/deploy
authority are implemented locally. A fail-closed root executor exposes bounded host observations
over an exact peer-UID Unix socket; when its optional mutation authority is installed, the same
socket admits policy-bound `rimg` backups and the first bootstrap deploy. Backup runs through the
fixed backup/age/Google Drive adapter chain. Bootstrap accepts only a build-key-signed immutable
candidate, rechecks the live source and installed policies, promotes its exact signed OCI archive,
imports and verifies that image, then drives fixed Kamal deploy, readiness, consumer-network smoke
and soak adapters through hardened transient units. A separate non-root `rdashboard-source` process
owns the canonical Git/source ledger, reconciles remote main before opening its root-only socket,
and atomically exports each accepted tree for the build identity while supplying root with signed
snapshots and live mutation tickets. The constrained CI/BuildKit candidate producer, webhook and
direct-push ingress, installed upgrades, rollback and the separate authorizer service remain
disabled.

## Development

The only supported verification command is:

```sh
bin/ci
```

It accepts no arguments. Production deployment, credentials and VPS configuration are not part of
the local development command.

Run the local dashboard after a successful build:

```sh
RDASHBOARD_LISTEN=127.0.0.1:3100 \
RDASHBOARD_RIMG_BASE_URL=http://127.0.0.1:8080 \
cargo run --locked --bin rdashboardd
```

Runtime databases default to `./var`. Override this with `RDASHBOARD_DATA_DIR`.

## Production browser access

An external route must be protected twice: Cloudflare Access decides who may reach the application,
and `rdashboardd` independently verifies the signed Access assertion at the origin. Configure all
three variables together in `/etc/rdashboard/controller.env`:

```sh
RDASHBOARD_ACCESS_TEAM_DOMAIN=https://example.cloudflareaccess.com
RDASHBOARD_ACCESS_AUDIENCE=replace-with-the-application-aud
RDASHBOARD_ACCESS_ALLOWED_EMAILS=operator@example.com
```

The team domain must be the exact lower-case HTTPS origin shown by Cloudflare, the audience must be
the exact Application Audience tag for this self-hosted application, and the comma-separated email
list is an additional exact origin-side allowlist. Partial or invalid configuration prevents
startup. The production systemd unit also sets `RDASHBOARD_ACCESS_REQUIRED=true`, so removing all
three values cannot silently disable authorization. With Access configured, every route except the
deliberately minimal `/health` probe
requires a valid RS256 Access token with the exact issuer, audience and allowed email. Signing keys
are fetched only from the fixed team-domain JWKS endpoint; an unknown key triggers one bounded
refresh. Event streams close at token expiry or after five minutes, whichever comes first, so a
long-lived browser connection must be reauthorized.

Do not publish a proxy route until the Access application and policy exist and the origin
configuration is active. The production host uses the existing Kamal Proxy, not nginx. The
dashboard itself stays on `127.0.0.1:3100`; the supplied systemd socket bridge exposes it only on
the host address of the private `kamal` Docker network for Kamal Proxy to reach. Direct origin
requests still fail closed because `rdashboardd`, rather than the proxy, validates the Access JWT.
See [`deploy/systemd/README.md`](deploy/systemd/README.md) for the exact boundary and activation
order.

Production-style host collection can be routed through the fixed executor boundary by setting
`RDASHBOARD_EXECUTOR_SOCKET=/run/rdashboard/executor.sock`. The executor reads its strict,
root-owned `/etc/rdashboard/executor.json`; see
[`deploy/systemd/README.md`](deploy/systemd/README.md). If that configured executor becomes
unavailable, the dashboard records a `signal_lost` host observation with empty values rather than
falling back silently or reporting stale metrics as fresh.

The executor can load its Ed25519 mutation authority from a fixed systemd credential and a bounded
public keyring in the root-owned configuration. It verifies credential ownership, permissions,
identity and the expected public key before retaining the signer. With that authority omitted it
remains observation-only. With it present, prepare/execute accepts only the installed backup-only
policy or an exact signed first-bootstrap candidate; grant acknowledgement records durable
admission, while a separate worker resumes the operation from root-owned
authorization/spec/receipt journals outside the socket deadline. Each queued job receives a fresh
wall-clock boundary when it actually starts, and executor shutdown cancels and terminates an active
transient adapter unit without starting the next queued job. The bootstrap handoff and required
build-owner/read-group filesystem contract are documented in
[`deploy/systemd/README.md`](deploy/systemd/README.md).

The controller exposes `POST /api/v1/mutations/lease`,
`POST /api/v1/mutations/prepare`, `POST /api/v1/mutations/execute`,
`GET /api/v1/mutations/status` and `GET /api/v1/mutations/capabilities` only on the configured
loopback listener. Preparation never mutates production state. Execution still requires the exact
one-use grant for the executor-signed intent; the dashboard does not mint or weaken that authority.
The HTTP mutation surface remains available to the future project-specific deploy journey, but the
browser does not expose the old manual intent/attempt-ID form. That prototype did not explain an
operator task and has been removed until the project view can start an admitted operation and follow
its exact persisted state without manual identifier copying.

The project overview reads bounded, project-scoped operation history from
`GET /api/v1/projects/{project_id}/operations`. Deploy, rollback and backup entries come from the
same durable controller journal that drives execution; the browser does not infer success from a
workflow or container state and retains the recorded failure summary when an attempt fails.

`GET /api/v1/projects/{project_id}/notifications` reports bounded delivery history from the optional
isolated notifier. Without the notifier systemd drop-in it truthfully returns `configured=false` and
the browser shows `Не настроено`; the controller neither receives a Telegram credential nor creates
an undeliverable queue. When configured, integration transitions and their local handoff are committed
atomically, while the notifier owns asynchronous gateway polling, deduplication and explicit unknown,
retry, possible-duplicate and permanent-failure states. Activation inputs and service boundaries are
documented in [`deploy/systemd/README.md`](deploy/systemd/README.md).

`GET /api/v1/projects/{project_id}/resource-history` returns CPU and memory medians plus network
and block-I/O counter deltas for the same completed hour, day, week and 30-day windows as the host
overview. Raw per-project observations share the host collection transaction and are compacted into
the same durable minute buckets. Repeated stale last-known values are not counted as new samples,
and counter resets omit the unknowable interval instead of fabricating activity.

Production source reconciliation uses the fixed `/etc/rdashboard/source.json`, private
`/var/lib/rdashboard-source` state and `/run/rdashboard-source/source.sock`. The source process
validates its installed policy and Ed25519 credential, refuses to serve until its first bounded
remote reconciliation succeeds, and enforces exact peer UID, framing, response binding and request
deadlines. Private SSH remotes additionally require a fixed systemd-loaded read-only key and pinned
known-hosts file whose SHA-256 identities are part of the canonical installed source document; Git
cannot inherit an operator key, SSH agent, password prompt or global host configuration. Root-side
snapshot verification independently checks signature expiry, repository and
owner-policy identity, target SHA, sequence, attestation digest, blocked-SHA and pause controls.
See [`deploy/systemd/README.md`](deploy/systemd/README.md) for the installation boundary.

The source broker also exposes a versioned read-only observation of the accepted Git tree to the
root executor. It counts every regular tracked file and sums its logical blob size at the exact
accepted commit, rechecking that the accepted ref did not change during measurement. The
controller never receives a repository path or Git command surface. `metrics.sqlite` records at
most one such observation per project per hour and
`GET /api/v1/projects/{project_id}/repository-history` returns the 30-day comparison window plus
one day for its oldest baseline (up to 745 points), including a last collection error without
discarding earlier valid samples. The browser shows the latest file count, logical size and commit
plus covered changes for one hour, one day, one week and 30 days; periods without a complete
baseline remain explicitly incomplete.

`metrics.sqlite` assigns every collection an independent monotonic sample ID, so an NTP clock step
cannot collide with an earlier observation. Raw samples are retained for 24 hours and compacted in
the same SQLite transaction into mergeable one-minute relative-log sketches retained for 30 days;
raw rows are deleted only after both host and project rollups are durable. Databases created by the
earlier timestamp-key schema are migrated transactionally on first open. `GET /api/v1/host-history`
combines the remaining raw samples and durable rollups into aligned completed-minute windows. It
returns resource medians, monotonic-counter receive/send traffic totals and explicit
covered/expected-minute counts for one hour, one day, one week and 30 days. Network counter resets
leave the unknowable interval out of both the total and its traffic-specific coverage instead of
inventing bytes. A newly installed or interrupted collector therefore cannot display a partial
period as complete.

The browser keeps the production overview dense: host pressure diagnostics remain collected but
are not part of the primary resource table, and every project occupies one semantic table row with
state, resources, deploys, backups, repository, dependency updates and errors as columns. Raw health
contracts and executor/source diagnostics stay out of that summary; unavailable integrations use a
bounded operator-facing state.

Project integration snapshots live in a separate `integrations.sqlite` journal. The controller
collects unresolved GlitchTip groups for the fixed organization `4u` and numeric project `4`, stores
only bounded aggregate metadata, and preserves the last successful snapshot when a provider fails.
For a non-empty set, the OpenCode Zen request is structurally restricted to counts, levels and opaque
ranks; issue titles, culprit strings, paths, event bodies, stack traces, issue IDs and links never
enter the model packet. An empty set is resolved locally without calling a model. A strict bounded
DeepSeek JSON result is advisory: malformed or unavailable analysis leaves the deterministic facts
visible as a partial state. The dependency-update collector separately reads only Renovate/dependency
pull requests and observed check-run conclusions from `mrDenai/rimg`; it does not claim review,
approval or mergeability.

The authenticated browser APIs are `GET /api/v1/projects/{project_id}/errors` and
`GET /api/v1/projects/{project_id}/updates`. Their records expose the latest attempt, last successful
collection, safe data and a bounded collection/analysis failure. The browser distinguishes loading,
unconfigured, empty, fresh, partial, stale and failed states rather than erasing last-known data.

The notification boundary is deliberately separate from provider collection. Typed events derive a
deterministic deduplication key, and `NotificationStore` provides durable enqueue, bounded delivery
leases, exact replay after ambiguous transport and terminal delivery/failure states. Its outbound
`TelegramGatewayMessageV1` matches the gateway's project/chat/event-key/dedup-key contract. The
controller does not open this outbox or possess a Telegram secret until a dedicated notifier identity,
gateway project and destination are installed; consequently the unconfigured build queues no messages.

`RDASHBOARD_RIMG_BASE_URL` is optional and must be a bare internal `http://` origin without
credentials, path, query or fragment. When it is absent, the `rimg` row remains visible as
`Unknown`; transport loss, HTTP failure and contradictory liveness/readiness results remain
distinct states. The collector requests fixed `/health/live` and `/health/ready` paths in parallel
with a two-second bound and never follows redirects.

The production unit fixes that origin to the loopback-only
`rdashboard-rimg-health.socket` at `127.0.0.1:18080`. Its short-lived companion resolves the newest
running healthy Kamal container with exact `service=rimg` and `role=web` labels, revalidates its
private IPv4 address on the `kamal` network, and forwards only the health connection to port 8080.
The controller receives neither Docker socket access nor a public rimg route; nginx is not part of
this path.

A separate persistent `rdashboard-observer` root service owns the Docker observation boundary. It
authenticates the controller through Unix peer credentials, accepts only the typed allowlisted
`project_resources` request, performs fixed deadline-bounded discovery and `docker stats` calls, and
returns only numeric CPU, memory, network and block-I/O evidence. The controller receives neither a
Docker command surface nor Docker socket access; on a transient failure it marks the last successful
values stale rather than recording them again as fresh history. This replaces the previous
five-second `rdashboard-rimg-resources@.service` activation lifecycle.

The collector reads the exact versioned `rimg` `/health/status` contract alongside liveness and
readiness. It renders `Healthy` only when operational mode, worker progress, webhook progress,
writable database/storage probes and the readiness endpoint agree. Legacy endpoints remain
visible as `Degraded`; missing or contradictory evidence cannot become green.

## Durable execution model

`control.sqlite` owns tab-lease generations, stable deployment requests, unique attempts,
transport-delivery deduplication and the user-visible operation projection. A separate
root-owned `/var/lib/rdashboard-executor/security.sqlite` uses WAL plus `synchronous=FULL` for
executor authorization, phase intents, observations, canonical receipts, resource locks and
write-fence epochs/tokens.

The executor follows `persist intent -> execute -> observe -> verify -> commit receipt`. Its
deterministic adapter and crash-injection tests cover every modeled boundary, controller/security
projection replay, explicit retry, cross-channel delivery deduplication, project/global lock
ownership, rollback branching and fence acquisition/release. Executor authorization expiry gates
its one-time consumption; after consumption it remains bound to that exact attempt and project so a
long deploy is not invalidated merely because the original short-lived grant expires.

For stateful deploys the live source ticket is acquired before base backup, not at drain or deploy.
It spans base backup, drain and the final pre-fence source refresh. A transient broker outage keeps
the source ticket, project lock and disk reservation for retry; ambiguous source state stays in
reconciliation with those owners retained. Fence acquisition, including idempotent recovery,
requires committed base-backup and drain receipts.
If a pre-effect source check or compensating abort loses contact with the broker, the operation
stays on its original retryable phase with ownership retained; it does not enter an unrecoverable
receipt-less reconciliation state. Retrying the same phase replays the ticket idempotently.

The hardened model also serializes recovery with privileged effects per project, preserves the
abandoned forward health/soak journal during rollback takeover, keeps candidate and rollback health
evidence separate, fully revalidates canonical receipts before releasing a fence, and compensates a
durable source-mutation ticket when admission fails before proof persistence. Immutable build
identity includes the selected Dockerfile and installed base-registry policy; release-bundle startup
reconciliation runs only while holding the store's OS singleton lock.

Security schema v14 seals every rollback before the controller projection, binds the primary versus
rollback-recovery branch into each receipt digest, and holds the per-project execution gate through
effect, fence release and projection. It also stores canonical authorized phase specifications and
whole verified backup chains, revalidates active fence/chain prerequisites immediately before a
permit, consumes stateful-breaking grants once and durably reserves the one allowed bootstrap per
project. Before a stateful drain it durably reserves the executor-owned epoch/token and later
atomically promotes that exact identity into the write fence after the drain receipt. Disk
authorization preserves the observation timestamp needed to recompute its canonical
reservation digest; legacy live claims or branchless receipts that cannot be reconstructed safely
require explicit reconciliation instead of migration guesses.
It also durably consumes each verified Ed25519 action-grant nonce once, permits only an exact
idempotent replay by the same attempt, and records the complete actor, role, lease, intent, policy,
key and lifetime bindings needed for security audit. A reused nonce with any other attempt fails
closed.
The executor also signs a five-minute canonical operation intent after deriving the effective
release class, exact source/policy identities and operator-visible consequences. That token is
bound to its request/project/operation/SHA and is persisted in the root journal before it can be
shown by the separate authorizer. Conflicting request, intent, token or digest identities are
rejected across restarts.
The signed intent also fixes the minimum accepted role. Consuming it and the authorizer grant is
one immediate transaction, so a crash cannot spend the grant without binding the intent (or bind
the intent without its audited nonce). Stateful-breaking deploys and code rollbacks require an
`admin` grant at the root boundary; an `operator` grant cannot be promoted by the controller.
Authorized phase specifications carry exact expected observation artifacts, including the
classification-derived target schema for migration. The security journal rejects substituted
migration/deploy/release identities and cross-phase evidence before accepting a receipt. It also
resolves every observed source proof back to the exact persisted admission phase instead of
trusting the executor-supplied artifact alone. Schema and migration decisions carry typed contract
evaluation envelopes bound to the intent, installed policy, project, schema pair, migration,
verdict and evaluation time; both inspection and classification revalidate those bindings.
Release-bundle sealing independently rejects forged or impossible reservation evidence.

Authorized phase-spec schema v2 additionally materializes each fixed adapter step as one bounded
canonical `request.jcs`. Its digest covers the attempt, request, project, operation, phase/branch,
step sequence, fixed profile/result schema, policy and authorization identities, classification,
backup/fence/grant/runtime prerequisites and expected artifacts. Root-owned adapter job directories
are replay-stable and owner-only; a conflicting request or any pre-existing result blocks execution
until explicit reconciliation instead of being overwritten.

Application schema versions now use one canonical validator across release-bundle sealing,
backup evidence and Phase 6 authorization. Classification also binds the inspected current and
candidate schemas to the exact verified release bundles and exposes only a revalidated
`ReleaseClassificationAuthorityV1` to phase resolution; a self-digested classification document
alone is not privileged authority. Source-proof admission compares the complete optional persisted
proof with the observed proof. A rejected or out-of-range proof durably commits
`needs_reconcile` before returning its typed error, so restart cannot reopen privileged execution.

The Git adapter negotiates incremental and divergent fetches against the canonical object store as a
read-only alternate, promotes only the staged pack, fsyncs pack bytes, metadata and refs with pinned
Git settings, keeps the canonical repository behind owner-only directories independently of the
process umask, and holds an operation-bound `.keep` until durable ref publication and recovery.
Canonical refs and pack artifacts are revalidated before use; loose objects, external object
alternates, common-directory redirects and repository-local config includes are rejected. The
validated canonical config is immutable for the lifetime of the adapter.
The adapter requires Git 2.36 or newer and the `files` ref backend, pins staging repositories to the
same backend, retains staging for temporarily unconfigured projects, and reconciles its orphaned
keep markers only when their durable fetched ref already exists. Reftable repositories are rejected
until their live table files can be kept inside the same validated filesystem trust boundary.
Prefetch evidence is bound to the exact source export and current `Cargo.lock`; OCI base resolution
verifies the requested registry document, selected platform manifest and config bytes/digests before
the build context can be frozen.

The adjacent `rimg` checkout now supplies explicit schema inspection/migration, persisted
drain/fence control, truthful worker/webhook/storage readiness and a coherent SQLite-plus-masters
backup protocol. The fixed-argv effect adapters, signed-grant authority, backup worker,
first-bootstrap deploy worker and controller mutation/status surface are implemented locally. The
bootstrap worker consumes only the documented build-candidate handoff, including the exact signed
OCI archive, and has restart coverage through terminal release-state commit. Internal candidate
production, installed upgrades and rollback remain disabled. Mutable repository Kamal files remain
non-authoritative.
