# systemd deployment inputs

## Controller and browser boundary

Install `rdashboard.service` and the controller binary at
`/usr/libexec/rdashboard/rdashboardd`. The service binds only `127.0.0.1:3100` and reads optional
browser-access settings from `/etc/rdashboard/controller.env`. For a public route, create the
Cloudflare Access self-hosted application first, then install all three values together in that
file, owned by `root:rdashboard` and mode `0640` or stricter:

```sh
RDASHBOARD_ACCESS_TEAM_DOMAIN=https://example.cloudflareaccess.com
RDASHBOARD_ACCESS_AUDIENCE=replace-with-the-application-aud
RDASHBOARD_ACCESS_ALLOWED_EMAILS=operator@example.com
```

The values are identifiers rather than credentials, but they define the authorization boundary.
The production unit sets `RDASHBOARD_ACCESS_REQUIRED=true`: `rdashboardd` therefore refuses missing,
partial or malformed configuration and fetches the team's public signing keys before it starts
listening. All browser, asset, snapshot, event and mutation routes then require an
origin-verified Access JWT whose signature, issuer, application audience and email allowlist match.
Only the minimal `/health` route remains unauthenticated for the upstream health check; it never
returns internal collection or retention error text.

The production path is Cloudflare -> the existing Kamal Proxy -> the private bridge -> loopback
`rdashboardd`. nginx is neither installed nor part of this deployment. Kamal Proxy runs in the
`kamal` Docker network and cannot reach host loopback directly, so install
`rdashboard-kamal-bridge.socket` and `rdashboard-kamal-bridge.service`. The socket is intentionally
bound to the host gateway address `172.19.0.1:3100`, not `0.0.0.0`; verify the installed `kamal`
network gateway before enabling it and adjust the unit if the gateway differs. The bridge forwards
only to `127.0.0.1:3100` using systemd's fixed socket proxy and carries no TLS or authorization
logic.

Activation order is fail-closed:

1. Create the Cloudflare Access application and exact allow policy for the dashboard hostname.
2. Install `controller.env`, restart `rdashboard.service`, and verify an unauthenticated protected
   request is rejected locally while `/health` succeeds.
3. Enable `rdashboard-kamal-bridge.socket` and verify the same behavior from the `kamal` network.
4. Add the TLS host route to the already-running Kamal Proxy, targeting `172.19.0.1:3100` with
   `/health` as its health path.
5. Verify authorized browser access, then verify direct-origin and missing/invalid-token requests
   cannot retrieve the dashboard or API.

Removing the Kamal Proxy host route and disabling the bridge socket closes external reachability
without changing the observation services or their local data.

## Generic workflow worker gateway

`rdashboard-workflow-gateway.service` is the controller-side boundary for the single generic worker
pool. It is repository-agnostic: one installed worker identity can lease `vps_required` and
`build_compute` nodes for every installed project, while project selection, adapter IDs, resources,
network class, cache class and artifact contracts remain fixed by the root-owned workflow manifest.
The worker does not open `control.sqlite`; it can reach only
`/run/rdashboard-workflow/worker.sock`, and every connection is checked against its exact Unix UID
before a request is decoded. The gateway has no network namespace, Docker socket, source/executor
socket, production volume or credential.

The gateway runs as the existing `rdashboard` user with primary group `rdashboard-worker`. Its
`UMask=0077` keeps SQLite, WAL and shared-memory files owner-only even when the gateway creates them;
the explicitly mode-`0660` socket is the only group-readable object. Before any activation, create a
dedicated non-login `rdashboard-worker` user and matching group, then place these non-secret installed
values in root-owned `/etc/rdashboard/workflow-gateway.env`, mode `0644` or stricter:

```sh
RDASHBOARD_WORKER_UID=992
RDASHBOARD_WORKER_ID=shared-vps-worker-1
RDASHBOARD_WORKER_HOST_ID=production-vps
RDASHBOARD_WORKFLOW_GRANT_ISSUER=workflow-gateway
RDASHBOARD_WORKFLOW_GRANT_LAUNCHER_AUDIENCE=workflow-launcher
RDASHBOARD_WORKFLOW_GRANT_KEY_ID=workflow-key-1
RDASHBOARD_WORKFLOW_GRANT_KEY_EPOCH=1
RDASHBOARD_WORKFLOW_GRANT_PUBLIC_KEY=<unpadded-base64url-ed25519-public-key>
```

Use the actual numeric worker UID; the example is not an installation default. IDs are stable
lowercase workflow identities, not repository names. A lease is short and renewable but can never
extend past the installed node timeout. Lost renewal responses replay the current canonical lease.
Expired, revoked or terminal-pending work becomes explicit cleanup debt; the gateway offers that debt
before new execution, accepts only a digest-bound cleanup receipt, and preserves it across restart.

The gateway loads the matching raw 32-byte Ed25519 seed only through the systemd credential named
`workflow-grant-seed`. Keep `/etc/rdashboard/credentials/workflow-grant-seed` root-owned, mode `0600`,
and never put the seed in the environment file. Startup verifies that the configured public key is the
one derived from that seed. Rotation installs a new higher key epoch in the launcher policy before the
gateway starts signing with it; old verification keys remain only for their bounded verification
window and an emergency revocation takes effect at the configured millisecond.

## Fixed workflow launcher

`rdashboard-workflow-launcher.service` is the only root-side boundary for non-mutating workflow jobs.
The generic worker reaches its mode-`0660` Unix socket as the single configured worker UID. The
launcher checks peer credentials before decoding, verifies a short-lived Ed25519 grant against the
exact canonical lease, revalidates the named sealed `PreparedRun`, and derives the unit name, mounts,
UID/GID, command and resource limits itself. A request cannot supply argv, a host path, a credential,
a network mode or a systemd property.

Install `/etc/rdashboard/workflow-launcher.jcs` as canonical JCS, root-owned, mode `0600`. It contains
schema version `1`; the exact worker/build numeric identities and stable worker/host IDs; the matching
grant issuer and launcher audience; the minimum accepted key epoch and bounded verification-key
lifecycle list; the sorted, duplicate-free `allowed_adapters`; and `max_concurrent_jobs` plus
`max_journal_records`. The build UID must differ from the worker UID. The public key is non-secret; no
signing seed is present in this policy. Keep an adapter absent until its fixed executable, isolation and
output contract have been installed and reviewed; a signed lease alone cannot enable it.

Before systemd starts an authorized unit, the launcher atomically records the exact execution identity
under `/var/lib/rdashboard-workflow-launcher/jobs`. A renewed lease for the same execution updates the
authorization record but never starts a second unit. A launcher restart converts any accepted/running
record into explicit `needs_reconcile` state, so an uncertain launch is stopped and cleaned rather than
silently replayed. Cleanup is itself journaled before `systemctl stop`; exact repeats return the same
evidence. Per-job writable state is an isolated tmpfs with the lease byte and inode ceilings, while the
sealed prepared input is bind-mounted read-only. The fixed `rdashboard-workflow-job` maps only the
three installed adapter IDs to fixed script paths and receives an empty, reconstructed environment.
Cargo state, targets, compiler cache and temporary files live only below `/job`; the launcher forces
Cargo offline so a verification job cannot turn a cache miss into undeclared network access.

The launcher deliberately has no network namespace, Docker/containerd socket, controller/executor/
source socket, production volume or credential access. Its only retained capability is read-only DAC
traversal so it can revalidate the worker-owned mode-`0700` preparation-store root; transient jobs have
an empty capability set. Installing the binary, policy and unit does not enable or start it, activate a
worker, change `auto_deploy`, or run a shadow job.

## Generic workflow worker and preparation store

`rdashboard-worker.service` is the one non-root worker for every installed project. It polls the
gateway with one stable worker/host identity, runs up to the configured number of typed leases, and
never creates a repository-specific service, checkout or dependency cache. A `host_prepare` lease
copies the exact attested source archive into the shared content-addressed store once; matching leases
join the same publication. Verification leases pin that sealed `PreparedRun`, ask the root launcher to
run only the installed fixed adapter, then clean the transient unit and release the pin before
committing the terminal receipt. Restart cleanup obligations are served before new work by the
gateway and are idempotent at the launcher and store boundaries.

Create the non-login `rdashboard-worker` user/group and add that user to the existing
`rdashboard-build-readers` group. Install these non-secret values in root-owned
`/etc/rdashboard/workflow-worker.env`, mode `0644` or stricter:

```sh
RDASHBOARD_WORKER_UID=992
RDASHBOARD_WORKER_ID=shared-vps-worker-1
RDASHBOARD_WORKER_HOST_ID=production-vps
RDASHBOARD_WORKER_SLOTS=2
RDASHBOARD_SOURCE_UID=993
RDASHBOARD_BUILD_READER_GID=994
```

All numeric IDs are examples and must match the installed accounts. `RDASHBOARD_WORKER_UID`, worker
ID and host ID must exactly match both the gateway and launcher policies. The source UID and reader GID
must match the owner/group of `/var/lib/rdashboard-build/source-exports`; the service receives only
read access to that tree. Set worker slots no higher than the launcher's `max_concurrent_jobs` or the
measured CPU/RAM/IO capacity. The worker accepts 1-16 slots, but that protocol maximum is not a safe
installation default. It has no network namespace, capabilities, Docker/containerd/Podman socket,
credential, controller state or production volume.

Mount a dedicated filesystem at `/var/lib/rdashboard-build/preparation` before starting the worker.
Its total size must be at least 6 GiB; using an approximately 8 GiB filesystem leaves metadata margin
while the store itself still refuses more than 6 GiB or 100,000 inodes. Keep at least 12 GiB free on
the host root filesystem. The worker refuses startup when this path is not the exact mount point, the
filesystem is too small, ownership/mode is wrong, the store exceeds either cap, or the root reserve is
missing. The tmpfiles entry creates the mode-`0700` mountpoint, but it does not create or mount the
filesystem; installation must provide and persist that hard boundary first.

The only implemented host-preparation policy is `source_tree_v1`. It is deliberately offline and is
valid only for a dependency-free repository or one whose complete gate dependencies are already
vendored in the source tree. It publishes a typed no-external-dependency marker, not a populated Cargo,
Ruby, npm or system-package cache. Networked lockfile prefetch remains a separate future fixed adapter
with registry allowlists and integrity checks. The catalog `ralert` manifest remains inactive and must
not be installed until that repository satisfies the source-tree contract or the appropriate
dependency adapter exists.

Installing the binary, service, environment file or mount does not enable or start shadow work,
change `auto_deploy`, or grant production mutation authority. Before activation, verify the mount and
IDs, install the matching gateway/launcher policy, keep only reviewed adapters allowlisted, and run the
separately authorized live storage/quota and cleanup drill.

## GlitchTip, DeepSeek and GitHub metadata

The base controller unit intentionally starts without external integration credentials. After each
dedicated least-privilege identity has been provisioned, install its matching
`rdashboard-glitchtip.conf`, `rdashboard-opencode.conf` or `rdashboard-github-metadata.conf` as a
systemd drop-in for `rdashboard.service`, together with the corresponding root-owned mode-`0600`
regular file:

- `/etc/rdashboard/credentials/glitchtip-read-token`, a token for a dedicated GlitchTip user with
  read-only scopes and access limited to the required project;
- `/etc/rdashboard/credentials/opencode-api-key`, the OpenCode Zen key used only for anonymous
  aggregate error facts;
- `/etc/rdashboard/credentials/github-metadata-token`, a GitHub App or fine-grained token limited to
  pull-request and check-run metadata for `mrDenai/rimg`.

Do not install an operator-wide GlitchTip token, reuse the source deploy key for GitHub API access or
put any token in `controller.env`. systemd copies only the named files into the service credential
directory. Missing credentials remain a visible `not_configured` record; a present malformed file
fails startup. Provider responses are time/body/count bounded, redirects are refused, and a failure
preserves the last successful integration record. The OpenCode route receives no issue title,
culprit, path, event body, stack trace, issue ID or deep link. The free provider is therefore not an
incident authority and never gates collection, backup or deployment.

Telegram delivery is a separate activation boundary. The repository contains a durable idempotent
outbox and the exact `telegram-gateway` request contract, but `rdashboard.service` neither opens that
outbox nor receives a gateway API secret. Before enabling delivery, register a dedicated gateway
project, choose the exact chat and optional thread, install a separate notifier user/service with its
own credential, and grant it only the narrow outbox transport needed for claiming and completing
messages. Until those values exist, do not enqueue notifications: an accumulating undeliverable queue
would be a false success state rather than useful monitoring.

For private rimg health collection, also install
`rdashboard-rimg-health.socket`, `rdashboard-rimg-health.service` and the
`rdashboard-rimg-health-proxy` binary. For container resources, install the separate persistent
`rdashboard-observer` binary and `rdashboard-observer.service`.
Install `rdashboard-rimg-health.env` as root-owned mode `0644`
at `/usr/lib/rdashboard/rdashboard-rimg-health.env`; it is deliberately loaded after the optional
operator environment so the controller's health origin stays fixed. The socket listens only on
`127.0.0.1:18080`, and the controller never receives Docker access. On each
socket-activated burst the short-lived root helper queries only the fixed local Docker socket,
requires exact Kamal labels `service=rimg` and `role=web`, revalidates `running` plus Docker
`healthy`, selects the newest eligible container, and accepts only its private IPv4 address from
the named `kamal` network. It then replaces itself with the fixed systemd socket proxy to that
address on rimg port 8080 and exits after one idle second, forcing the next collection burst to
resolve a post-deploy container again. No rimg port is published on the host or through Kamal
Proxy. A missing, starting, unhealthy, non-private or ambiguously encoded target fails closed and
is recorded by the controller as health signal loss. The helper unit disables systemd's start-rate
limit because the collector deliberately opens three parallel health connections every five
seconds: during a rolling gap those expected fail-closed activations must not permanently fail the
listening socket. Each activation remains deadline- and resource-bounded, and the next collection
automatically resolves the replacement container once it becomes healthy.

Before starting the observer, write the controller's actual non-root numeric UID as
`RDASHBOARD_OBSERVER_ALLOWED_UID=<uid>` in root-owned `/etc/rdashboard/observer.env`; no other value
belongs in that file. The persistent root observer creates
`/run/rdashboard-observer/observer.sock` as `root:rdashboard` mode `0660`, verifies every connecting
peer UID, and accepts only the versioned `project_resources` request for an installed project. The
current installed handler recognizes only `rimg`; the request cannot select a container, Docker
command, label, socket or host path. The observer performs fixed, one-second-bounded Docker queries,
requires exact Kamal labels `service=rimg` and `role=web`, revalidates running/healthy state and a
private `kamal` address, then returns only a bounded numeric resource record. Its service has fixed
CPU, memory, task and descriptor limits and no network namespace. A stale socket left by a crash is
reconciled only when its protected owner/group/mode/inode contract still matches; a live socket or
changed path fails closed.

This persistent process replaces `rdashboard-rimg-resources.socket` and
`rdashboard-rimg-resources@.service`; those legacy units must be stopped and removed only during a
separately authorized installation. Missing, malformed, oversized, timed-out or contradictory Docker
output fails closed. The controller keeps a last-known sample as stale for display but does not roll
repeated stale values into resource history. It never receives Docker socket access.

The source path has three deliberately separate identities. `rdashboard-source` owns the canonical
Git repositories, source ledger, webhook HMAC secrets and attestation key.
`rdashboard-source-ingress` owns only the bounded loopback HTTP front door. The existing
`rdashboard` controller identity runs the signed-outbox dispatcher. Create those non-login users and
groups plus `rdashboard-build-readers`, install `rdashboard-source.service`,
`rdashboard-source-ingress.service`, both `rdashboard-source-ingress-bridge` units and
`rdashboard-source-dispatcher.service`, then apply `rdashboard-tmpfiles.conf`. Repository checkout
alone installs or enables nothing.

The source StateDirectory and repository root are owner-only. Neither the controller, ingress nor
executor can write the canonical Git object store. The source identity receives the build-reader
group only so it can publish immutable source archives; it receives no candidate signing credential
or builder-owned output path. `ProtectSystem=strict` leaves only the build-source export store and
the two dedicated runtime transports writable outside its private StateDirectory.

The three Unix transports do not share authority:

- `/run/rdashboard-source/source.sock` is source-owned and accepts only peer UID 0. The root executor
  gets transport group membership only with mutation authority; the controller never joins it.
- `/run/rdashboard-source-delivery/delivery.sock` is source-to-controller only. The broker accepts
  the installed controller UID and the dispatcher verifies the source UID, signed head, installed
  source policy and workflow manifest before writing `control.sqlite`.
- `/run/rdashboard-source-ingress/ingress.sock` is created mode `0660` below the protected setgid
  `rdashboard-source:rdashboard-source-ingress` directory. The broker accepts only the installed
  ingress UID and the ingress verifies the source UID. The HTTP process has no credential, Git
  directory, source database, controller database or writable filesystem path; it can submit only a
  versioned, length-bounded GitHub push frame.

Install the canonical workflow manifest catalog first at
`/etc/rdashboard/project-manifests`. The directory must be `root:rdashboard` mode `0750`; every
`<project>.jcs` must be canonical JCS, `root:rdashboard` mode `0640`. Repository checkout JSON is not
read directly in production. The source generator and dispatcher both require the exact installed
catalog, preventing their repository and workflow-policy identities from drifting apart.

Review the repository candidate `config/source-projects.json`, render it as canonical JCS, then install it as
`/etc/rdashboard/source-projects.jcs`, root-owned mode `0600`. It must cover the workflow catalog
exactly and contains only owner-controlled deployment values:

```json
{"projects":[{"auto_deploy":false,"installed_policy_version":1,"maximum_attempts":3,"project_id":"ralert","release_class":"stateful_compatible"}],"purpose":"rdashboard.source-project-controls.v1","schema_version":1}
```

Render the reviewed candidate without accepting trailing whitespace or noncanonical installed bytes:

```sh
/usr/libexec/rdashboard/rdashboard-source-config canonicalize-controls \
  < config/source-projects.json > /etc/rdashboard/source-projects.jcs.new
```

Atomically install the result as `/etc/rdashboard/source-projects.jcs` with the ownership and mode
above before running the source-document build command.

Keep `auto_deploy=false` until the complete worker/build/deploy path for that project has passed its
activation review. Each project gets its remote URL and workflow-policy digest from the installed
manifest, so adding or removing a repository is one exact catalog-and-controls change, not a new
worker implementation.

Install these root-owned mode-`0600` credentials under `/etc/rdashboard/credentials`:

- `source-attestation-seed`, exactly 32 random Ed25519 seed bytes;
- `source-webhook-<project>-secret`, a distinct random GitHub webhook secret of 16-4096 bytes for
  every project;
- for each `ssh://` remote only, `source-git-<project>-private-key` containing an unencrypted,
  repository-read-only OpenSSH deploy key and `source-git-<project>-known-hosts` containing the
  reviewed provider host key.

HTTPS remotes forbid SSH bindings. Startup rejects symlinks, wrong ownership or mode, size changes,
credential digest changes, reused project secrets or SSH private keys, malformed key material, a
missing hostname pin and any remote not bound to the exact GitHub `owner/repository`. Git runs with
no ambient environment, HOME, credential helper, agent, password prompt, mutable host-key update or
global known-hosts fallback.

Install `rdashboard-source-config` at `/usr/libexec/rdashboard/rdashboard-source-config`. Generate
the public, digest-covered schema-v5 source document without putting a secret in argv or stdout:

```sh
/usr/libexec/rdashboard/rdashboard-source-config build \
  SOURCE_UID INGRESS_UID INGRESS_GID CONTROLLER_UID CONTROLLER_GID BUILD_READER_GID \
  > /etc/rdashboard/source.json.new
```

Validate and atomically install it as `/etc/rdashboard/source.json`, `root:root` mode `0644`. It
binds all fixed paths and peer identities, the exact project set, repository and policy identities,
per-project credential names and digests, the attestation public key, connection/deadline bounds and
the 30-second reconciliation interval. It contains no private bytes. Then generate the complete
systemd credential drop-in from that installed document:

```sh
/usr/libexec/rdashboard/rdashboard-source-config systemd-credentials \
  > /etc/systemd/system/rdashboard-source.service.d/credentials.conf.new
```

Atomically install the drop-in as `root:root` mode `0644`. The base unit intentionally has no
`LoadCredential=` line; this generated file is the single exact list for the attestation seed, every
webhook secret and only the SSH credentials required by the current project catalog. Regenerate it
whenever the installed project set changes.

Initialize every canonical bare repository at
`/var/lib/rdashboard-source/repositories/<project>.git` as `rdashboard-source`, using the reviewed
`files` ref backend and owner-only modes. Before sending systemd `READY=1`, the broker recovers its
durable webhook/delivery journals and completes a bounded remote-main reconciliation for every
project. An unavailable or divergent startup source therefore fails closed under systemd restart.

`rdashboard-source-ingress` listens only on `127.0.0.1:3201`. The socket-activated bridge exposes
only `172.19.0.1:3201` to the private `kamal` Docker network; verify that gateway before enabling the
socket. Add a dedicated TLS host or an exact `/github/<project>` Kamal Proxy route to that bridge.
Do not put Cloudflare Access browser authentication in front of this GitHub callback route: the
per-project HMAC is its authentication boundary. Configure each GitHub repository with content type
`application/json`, the exact URL `https://<webhook-host>/github/<project>`, push events only and its
matching project secret. Expose no other ingress route; `/health` returns only `204` for local proxy
health checks.

The HTTP boundary accepts at most eight concurrent requests, 32 headers/16 KiB of header data and a
1 MiB body. It requires the exact GitHub event, delivery and SHA-256 signature headers. The source
broker verifies HMAC and repository binding, then commits only delivery ID, payload digest,
announced head and repository identity to a SQLite `FULL`-synchronous queue before returning `202`.
Raw webhook bytes and signatures are never persisted or logged. Duplicate deliveries are
content-bound; conflicting reuse is rejected. The queue is bounded to 2048 pending globally and 128
per project, so overload returns a retryable response instead of growing disk without limit.

Webhook acknowledgement does not wait for Git fetch, archive export or a project already reconciling.
A per-project coordinator prioritizes the durable wake-up, shares one fetch across its batch and
retries remote-visibility lag from 250 ms up to five seconds. While any project has durable webhook
work, periodic fetches cannot enter the shared fetch slot; a newly committed wake-up interrupts an
active periodic network fetch, and periodic work never queues ahead of a waiting webhook fetch.
Periodic fetches have a two-second network bound, while webhook fetches retain the full one-minute
provider bound. Once pack promotion starts it completes instead of leaving an ambiguous canonical
object state. A missed webhook is recovered by the 30-second reconciliation loop with at most five
seconds of deterministic startup jitter, keeping the fallback below one minute without synchronized
fetch bursts. On restart, wake-ups for a removed project or a project rebound to a different GitHub
repository are retired before ingress binds; accepted-source and completed-delivery audit history is
retained. Rewinds or divergence cannot bypass the existing accepted-head guard and enter
`source_diverged_needs_owner`; a direct-push SSH front door is not installed by this slice.

After each accepted ready head, the broker runs fixed `git archive` itself and atomically publishes
a source-owned, reader-group mode-`0440` tar plus canonical manifest below
`/var/lib/rdashboard-build/source-exports/<project>`. The manifest binds the exact head, sequence,
source attestation, repository and installed policy to archive size and SHA-256. Symlinks, hard links,
special Git entries and `.gitattributes` archive rewriting are rejected; the build identity never
sees the private repository. Accepted deployable heads enter a bounded signed outbox atomically. The
dispatcher polls locally at 250 ms, retries lost acknowledgements with the same scheduler identity
and acknowledges only after scheduler admission is durable. A newer head supersedes older pending
delivery, while periodic reconciliation refreshes an expired current-head attestation.

The executor always serves the bounded observation protocol and can optionally enable the admitted
backup and installed-deployment mutation paths described below. Install the binary at
`/usr/libexec/rdashboard/rdashboard-executor`, create the
system group `rdashboard`, keep `/etc/rdashboard` root-owned and not group/other writable, and
install a root-owned `/etc/rdashboard/executor.json` with mode `0640` or stricter:

```json
{
  "schema_version": 1,
  "controller_uid": 991,
  "socket_path": "/run/rdashboard/executor.sock",
  "metrics_disk_path": "/",
  "max_connections": 16,
  "request_timeout_ms": 2000
}
```

`controller_uid` is an installation value, not a reusable default: replace `991` with the actual
non-root UID assigned to `rdashboardd`. The socket group permits the controller to connect, while
the executor independently requires the configured peer UID on every accepted connection.

Do not add Docker, arbitrary command, writable project-tree or adapter credential access to this
long-running unit. Its base `rdashboard-source` supplementary group permits only the source
broker's versioned, root-peer-authenticated snapshot and accepted-tree observation protocol; no
repository path or Git command is exposed. Admitted backup and deployment effects run only in
separately constrained transient units.

The root executor configuration accepts an optional `mutation_authority` object. Omitting it keeps
the current read-only behavior and does not require a signing credential. When mutation authority
is staged, the object must contain the exact action-grant issuer/audience, a bounded Ed25519 public
verification keyring with lifecycle timestamps and minimum epoch, plus the executor-intent
issuer/audience, active key ID/epoch and expected public key. Public keys use canonical unpadded
base64url encoding of exactly 32 bytes.

Install the executor-intent private seed as exactly 32 raw bytes at
`/etc/rdashboard/credentials/executor-intent-seed`, owned by root and mode `0600`. Then install
`rdashboard-executor-mutation-authority.conf` as a systemd drop-in for
`rdashboard-executor.service`. systemd exposes the secret only through the fixed
`executor-intent-seed` service credential; the executor rejects symlinks, wrong ownership or mode,
size changes, inode replacement and a seed that does not match the configured public key. Do not
put the private seed in `executor.json` or an environment variable. The same drop-in grants only
the two additional read/connect groups needed by deployment: `rdashboard-build-readers` and the
host's `chrony` group. The base unit already carries `rdashboard-source` for read-only accepted-tree
observation. These groups must exist before the unit is reloaded.

Loading this authority enables the installed backup resolver plus the installed deploy
resolver and their shared sequential worker. The service opens its root-only journal at
`/var/lib/rdashboard-executor/security.sqlite`, acknowledges a grant only after durable
intent/grant admission, then runs the long operation outside the two-second socket request. Startup
and a 30-second recovery scan reconstruct pending work from exact accepted records and phase
receipts, with a fresh start time for each sequential job. On executor shutdown, the worker cancels
the blocking adapter wait and explicitly kills/stops the active transient unit; the scan stops
before starting another queued job, and the intent-persisted journal remains replayable on the next
start. Omitting the authority keeps mutation unavailable.

Install the repository-built `rdashboard-adapter-receipt` executable at
`/usr/libexec/rdashboard/rdashboard-adapter-receipt` as a root-owned, non-symlinked executable that
is not group- or world-writable. Every fixed adapter transient unit binds this exact path through
`ExecStopPost=`. The helper runs before `systemd-run --collect` can discard the unit cgroup and
atomically writes owner-only `terminal-receipt.jcs` evidence beside the job request. The root
executor validates that receipt and then writes `cleanup-receipt.jcs`; a durable
`execution-start.jcs` without a completed result is reconciliation-only and must never be executed
again. Completed legacy job directories without `execution-start.jcs` remain readable, while every
new completed job requires matching successful terminal and complete cleanup receipts.

The backup intent resolver additionally defines one canonical root-owned input at
`/etc/rdashboard/projects/rimg/backup-mutation-policy.jcs`, mode `0600`. It binds exactly the `rimg`
project, `backup_only`, the owner policy identity, the installed rimg policy digest, exact backup
unit and age-recipient fingerprints, backup staging/growth byte budgets, a 30-second to five-minute
intent lifetime and its own canonical document digest. The signed intent/action grant bind that
complete document digest rather than only its nested owner identity. Every non-replayed preparation
reopens this file and requires the same project and rimg-policy digest in both
`adapter-runtime.jcs` and `backup-runtime.jcs`. That resolver rejects deploy and rollback requests;
deploy is handled by the separate exact-candidate boundary below, while rollback remains disabled.

The full root policy is installed separately as canonical
`/etc/rdashboard/projects/rimg/installed-rimg-policy.jcs`, mode `0600`. Loading it reconstructs the
Kamal policy and then the rimg policy through their validating constructors, recomputes the
credential, Kamal and rimg policy digests, and rejects a noncanonical document or any substituted
derived field. The backup driver must compare this policy's owner identity and rimg digest with the
backup mutation policy before authorizing a phase.

The backup-capture slice additionally requires these root-owned installed files:

- `/usr/libexec/rdashboard/backup-adapter`, built from this repository;
- `/usr/libexec/rdashboard/rimg-cli`, the exact rimg executable whose SHA-256 is pinned by
  `/etc/rdashboard/projects/rimg/adapter-runtime.jcs`;
- `rdashboard-tmpfiles.conf` installed under `/usr/lib/tmpfiles.d/` and applied before starting the
  executor, creating the journal, backup, lock and release-bundle directories under the separate
  root-owned mode-`0700` `/var/lib/rdashboard-executor` tree. Privileged data must not be placed
  below the controller-owned `/var/lib/rdashboard` StateDirectory.

The installed rimg backup unit must describe the two root-owned snapshot artifacts produced by
this adapter: the SQLite object and the deterministic masters bundle, both mode `0600`. The
adapter reads live masters only from `/var/lib/rimg/masters`; it never receives a caller-selected
source or output path. Base capture drains and resumes the exact durable epoch/token. Cutover
capture requires the already-held fence and deliberately leaves it held.

The encryption and Google Drive slices additionally require these root-owned, non-symlinked
installed inputs:

- `/usr/libexec/rdashboard/age` and `/usr/libexec/rdashboard/rclone`, executable only through the
  fixed adapter profiles and pinned by SHA-256 in the runtime document;
- `/etc/rdashboard/projects/rimg/backup-runtime.jcs`, canonical JCS, mode `0600`, binding the exact
  rimg policy, age X25519 recipient and fingerprint, tool digests, Google Drive root folder,
  provider credential version and service-account digest;
- `/etc/rdashboard/projects/rimg/rclone.conf`, canonical and secret-free, mode `0600`, containing
  only the configured Drive remote, `type = drive`, `scope = drive.file`, and the pinned
  `root_folder_id`;
- `/etc/rdashboard/credentials/rimg-drive-service-account.json`, root-owned and mode `0600`.

The service-account file is loaded only into the upload and independent-readback transient units
with systemd `LoadCredential=`. It is read inside the unit from
`/run/credentials/<transient-unit>.service/rimg-drive-service-account.json`; it must never be put
in rclone configuration, an environment variable or an adapter job directory. The transient
sandbox makes the source `/etc/rdashboard/credentials` directory inaccessible after systemd has
loaded the selected credential. Encryption streams the deterministic archive directly into age
through a pre-created mode-`0600` output descriptor, fsyncs it, and publishes only ciphertext plus
its canonical state. Upload uses a content-addressed object key and fail-closed duplicate
detection. A replay after a successful remote write but before local receipt publication
independently reads and hashes the existing object before accepting it.

## Candidate handoff and installed deployment

Create a dedicated `rdashboard-build` system user and a separate
`rdashboard-build-readers` system group. Make `rdashboard-build` the owner of the candidate tree and
add only `rdashboard-executor.service` to the reader group through the installed unit's
`SupplementaryGroups=` setting. Do not add `rdashboardd` or its controller account to this group.
Apply `rdashboard-tmpfiles.conf` after both identities exist. It creates the candidate stores with
these exact ownership and access boundaries:

- `/var/lib/rdashboard-build/source-exports/rimg`, owned by
  `rdashboard-source:rdashboard-build-readers`, mode `2750`;
- `/var/lib/rdashboard-build/release-bundles/rimg` and
  `/var/lib/rdashboard-build/attestations/rimg`, owned by
  `rdashboard-build:rdashboard-build-readers`, mode `2750`;
- `/var/lib/rdashboard-build/oci-archives/rimg`, owned by
  `rdashboard-build:rdashboard-build-readers`, mode `2750`;
- `/var/lib/rdashboard-executor/oci-archives/rimg`, owned by `root:root`, mode `0700`.

After every successful accepted-head reconciliation, `rdashboard-source` exports the exact Git tree
as `<head>-<sequence>.tar` plus a canonical manifest in the source-export store. Both files are
source-owned, reader-group-readable, immutable publications. The build identity must reopen and
verify that manifest, archive hash, accepted head, sequence, source attestation, repository identity
and installed policy before using any byte.

Install canonical `/etc/rdashboard/projects/rimg/deploy-mutation-policy.jcs`, root-owned and mode
`0600`. Schema v2 binds the installed owner/rimg policies, numeric `build_uid`, numeric
`build_reader_gid`, build signing key ID/epoch/public key, exact `/usr/bin/chronyc` SHA-256, disk
budgets and intent lifetime. The numeric group must be the installed
`rdashboard-build-readers` GID. The executor has no DAC-bypass capability: it can consume a
candidate only through this exact read-only group handoff.

The candidate producer remains an external non-root integration point in this milestone; no
`rdashboard-build` service is shipped. It is responsible for consuming the verified source export,
running the fixed isolated `CI=true bin/ci` and immutable-context image build, exporting the exact
result as an OCI archive, and using the policy-pinned build signing key. It must publish only these
final files atomically, without symlinks or retained hard links:

- release bundle:
  `/var/lib/rdashboard-build/release-bundles/rimg/<release-bundle-sha256>`, canonical JCS, at most
  64 KiB, owner `rdashboard-build`, group `rdashboard-build-readers`, mode `0440`;
- build attestation:
  `/var/lib/rdashboard-build/attestations/rimg/<full-git-commit>.jcs`, canonical JCS, at most
  256 KiB, the same owner/group, mode `0440`;
- OCI archive:
  `/var/lib/rdashboard-build/oci-archives/rimg/<release-bundle-sha256>.oci.tar`, at most 16 GiB,
  plus `<release-bundle-sha256>.manifest.jcs`, both the same owner/group and mode `0440`.

The attestation uses domain `rdashboard.build-release-attestation.v1`, has a maximum 24-hour
validity window, names the exact bundle digest and source head/sequence/attestation, binds the
installed policy and rimg-policy digest, and carries the Testing, Building and Preflight artifacts.
Release-bundle schema v3 binds the OCI archive SHA-256 in addition to the registry digest and local
Docker image ID. The OCI manifest independently binds those identities, project, full source head,
bundle digest, byte count and publication time. The executor reopens the live source snapshot and
every installed policy, verifies the signature and exact file identities before and after reading,
rebinds only the live root disk reservation, copies the verified archive into its private root-owned
store and rejects a stale, substituted, permissively readable or multiply linked candidate. A
producer that merely signs caller-supplied evidence does not satisfy this contract.

Before the first accepted deploy, install canonical
`/var/lib/rdashboard-executor/releases/rimg.jcs`, root-owned and mode `0600`, as generation 1 with
both `current_release_bundle_digest` and `last_known_good_release_bundle_digest` absent and with the
same installed policy/rimg-policy identities. The first deploy permits only this `NeverInstalled`
state. After a terminal Soak receipt it promotes the exact bundle to the root store and atomically
advances release state; restart after either durable boundary replays receipts without reapplying
Kamal, health or soak effects.

Once a current release exists, only an exact `CodeOnlyCompatible` candidate with the installed
stable-routing and automatic-code-rollback capabilities may proceed. The Deploying authorization
reuses the latest committed, still-fresh verified base backup for the project; it never treats a
receipt-less or foreign-project backup as authority. A successful terminal soak atomically moves
the old current digest into `last_known_good_release_bundle_digest`. A failed candidate health
check or soak durably takes over the same attempt as a rollback branch, routes back to the exact old
bundle, verifies rollback health and soak, and leaves release state unchanged. Restart projects both
the primary and rollback journals before deciding whether any external effect must run again.

The host must run a synchronized local chrony daemon exposing `/run/chrony/chronyd.sock`. The
executor calls only the policy-pinned `/usr/bin/chronyc` with fixed tracking arguments and rejects a
changed binary, stale reference time, unsynchronized leap state or ambiguous/non-finite report.
The installed mutation drop-in includes the host's `chrony` group because the capability-free
executor cannot otherwise traverse the daemon's mode-`0750` runtime directory. On a distribution
using a different chrony group name, replace that one group token with the actual group owning
`/run/chrony` and verify the socket remains non-world-accessible.

The Kamal deploy and rollback profiles additionally require these root-owned installed inputs:

- `/usr/libexec/rdashboard/kamal` at exactly Kamal `2.12.0`, `/usr/bin/docker` and
  `/usr/bin/skopeo`, all pinned by SHA-256 in
  `/etc/rdashboard/projects/rimg/kamal-adapter-runtime.jcs`;
- a registry image referenced by an exact digest and its exact local Docker image ID, plus a bounded
  128 MiB to 16 GiB registry tmpfs budget;
- a `kamal-proxy` image referenced by an exact digest and its exact local Docker image ID for the
  private stable router, all in canonical
  `rdashboard.installed-kamal-adapter-runtime.v3` schema;
- the immutable release bundle store at `/var/lib/rdashboard-executor/release-bundles`;
- the private OCI archive store at `/var/lib/rdashboard-executor/oci-archives`;
- `/etc/rdashboard/credentials/rimg-kamal-secrets.env`, containing exactly the authorized dotenv
  keys with substitution-free bounded values, and
  `/etc/rdashboard/credentials/rimg-kamal-ssh-key`, both root-owned and mode `0600`.

Only Kamal profiles receive the two credentials through `LoadCredential=`. Before Kamal starts, the
adapter verifies the promoted archive digest, imports it into the local Docker store with `skopeo`,
checks the exact signed local image ID, starts a bounded read-only digest-pinned registry only on
`127.0.0.1:5555`, copies and re-verifies the archive through that registry, and removes only a
container carrying the exact owned image ID and ownership label. A foreign container using the
reserved name fails closed. Registry cleanup is mandatory on both success and failure; registry
state is never release or rollback authority. `skopeo` TLS verification is disabled only for this
exact loopback transport; OCI archive inspection and every non-loopback reference retain their
normal verification behavior. The adapter then generates the complete secret-free JSON
configuration in its operation directory, binds it to the embedded
deployment plan and installed template/policy/credential digests, rejects ERB markers, disables
hooks, SSH agent forwarding and user SSH configuration, and accepts only the fixed `kamal` Docker
network. The only published service ports bind to loopback. It independently observes the running
full Git SHA afterward; an already matching
SHA is treated as crash replay rather than a second deployment. Repository `config/deploy.yml`,
`.kamal`, hooks, destinations and the managed checkout are never read.

Installed updates do not publish a backend port and do not give release containers the `rimg`
network alias. The sole long-lived alias belongs to the exact owned
`rdashboard-rimg-router` container on the `kamal` network. Its only persisted state lives in the
exact labelled `rdashboard-rimg-router-state` Docker volume. Each release runs as
`rdashboard-rimg-backend-<full-git-sha>` with exact image, bundle and deployment-plan labels. The
adapter starts and verifies the candidate, asks the private router to health-check
`/health/ready`, switches and drains through the same `rimg-internal` service, then stops only the
exact old owned backend. Reconciliation verifies router image, label, network and alias, waits for
the proxy command endpoint, reads its persisted active target and idempotently reapplies the
expected route when state is absent or corrupt. A foreign reserved container, volume, backend or
route fails closed.

This deployment profile is deliberately single-host: the installed Kamal `target_host` must SSH
back to the same VPS whose executor owns the Docker daemon and loopback registry. In Kamal's
generated configuration, `localhost:5555` is therefore the registry on that target's own Docker
host. A remote Docker target or multi-host fleet is unsupported by this milestone and must not be
installed until it has a separately authenticated registry transport and rollout design.

`rdashboard.service` enables the fixed executor socket. It starts and remains available if an
individual executor observation fails; that sample is persisted as `signal_lost` with no invented
metric values. Its rimg origin is the source-controlled loopback health socket described above,
not an operator-supplied container address. The controller unit has no Docker socket, production
credentials, project checkout write access or privileged capabilities.
