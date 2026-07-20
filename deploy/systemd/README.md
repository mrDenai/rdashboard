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
```

Use the actual numeric worker UID; the example is not an installation default. IDs are stable
lowercase workflow identities, not repository names. A lease is short and renewable but can never
extend past the installed node timeout. Lost renewal responses replay the current canonical lease.
Expired, revoked or terminal-pending work becomes explicit cleanup debt; the gateway offers that debt
before new execution, accepts only a digest-bound cleanup receipt, and preserves it across restart.

The generic worker executable, hard storage fence and preparation store belong to the later worker
activation boundary. Installing this unit or repository checkout alone must not start shadow work,
change `auto_deploy`, or grant production mutation authority.

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

The dedicated source broker runs as `rdashboard-source` from
`/usr/libexec/rdashboard/rdashboard-source`. Install `rdashboard-source.service` and
`rdashboard-source-dispatcher.service`, create the matching source system user/group plus the
`rdashboard-build-readers` group, and apply `rdashboard-tmpfiles.conf`.
Its StateDirectory and repository root are owned only by that account; the controller and executor
never receive write access to the canonical Git object store. The source process receives the build
reader group only so its setgid export directory can publish immutable archives to the non-root
builder; it receives no access to candidate signing credentials or builder-owned output paths.
`ProtectSystem=strict` remains enabled; the unit's external writable paths are the immutable build
export store and its dedicated delivery runtime directory. Its private `StateDirectory` is managed
separately by systemd. It is not a member of the controller's `rdashboard` group.

The source runtime directory is the narrow transport exception: systemd creates
`/run/rdashboard-source` as `rdashboard-source:rdashboard-source` mode `0750`, and the broker creates
`source.sock` as the same owner/group mode `0660`. The capability-free executor receives the
`rdashboard-source` supplementary group only with the mutation-authority drop-in. The protocol
still authenticates every connection as peer UID 0, so group membership grants transport access,
not source authority. The controller must not be a member of `rdashboard-source`.

The second transport is deliberately separate. `rdashboard-tmpfiles.conf` creates
`/run/rdashboard-source-delivery` as `rdashboard-source:rdashboard`, mode `2750`; the source owner
creates `delivery.sock` mode `0660` and accepts only the installed controller UID. The client verifies
the source UID before writing any frame. `rdashboard-source-dispatcher` runs as `rdashboard`, has no
network or source credential, and can write only the controller StateDirectory. It verifies every
signed accepted-head record against the installed source and workflow policies before idempotently
admitting it to `control.sqlite`. The source ledger and scheduler journal are never opened by the
other process.

Install one canonical-JCS `/etc/rdashboard/source.json`, root-owned mode `0644`. It contains public
policy metadata and credential identities, never credential bytes, and must not be writable by any
service identity. `InstalledSourceConfigV1` schema v4 binds both fixed sockets, database, repository
and build-source export paths, the numeric source/controller UIDs, controller/build-reader GIDs, root
executor peer UID, connection/time limits, reconcile interval, attestation key identity and public
key, and each project's exact
remote-derived repository identity and owner-policy identity. Its `document_digest` covers the
complete document. Each project using an `ssh://` remote also requires its own exact installed
credential names and SHA-256 identities for a read-only SSH private key and pinned known-hosts file.
HTTPS projects forbid an SSH credential binding. The service refuses path overrides, incomplete Git SSH
credentials, duplicate projects, mutable policy versions, rollback release classes, key
substitution and a remote URL whose derived repository identity differs from the installed value.

Install the corresponding 32-byte Ed25519 seed at
`/etc/rdashboard/credentials/source-attestation-seed`; systemd exposes it only as the fixed
`source-attestation-seed` service credential. The broker checks file type, ownership, mode, inode,
exact size and derived non-weak Ed25519 public key, and zeroizes the raw seed buffer after
constructing the signer.

For a private SSH remote, install an unencrypted, repository-read-only OpenSSH key at
`/etc/rdashboard/credentials/source-git-<project>-private-key` and the provider's reviewed host key
lines at `/etc/rdashboard/credentials/source-git-<project>-known-hosts`; both must be root-owned mode
`0600`. Record their exact credential names and SHA-256 digests in that project's `source.json`
entry, then add the same two credential names to
`rdashboard-source-git-ssh.conf` as the service's `git-ssh.conf` systemd drop-in. The base source
unit does not request Git credentials, so an HTTPS-only installation does not depend on absent SSH
files. The drop-in exposes only credential copies at the two fixed
`/run/credentials/rdashboard-source.service/` paths. Startup rejects symlinks, wrong
owners/modes, oversized files, non-OpenSSH private-key framing, malformed host-key lines, a missing
pin for any configured SSH hostname or any digest change. Git runs with no ambient environment,
HOME, credential helper, agent, password, keyboard-interactive prompt, mutable host-key update or
global known-hosts fallback; each SSH project uses only its own exact identity and pinned file.
Adding a future repository requires its own deploy key plus an explicit installed unit/config
change rather than silently borrowing an operator account or reusing another project's authority.

Install `rdashboard-source-config` at `/usr/libexec/rdashboard/rdashboard-source-config`. After the
three rimg credential files exist, generate the canonical document without placing any secret in
argv or stdout:

```sh
/usr/libexec/rdashboard/rdashboard-source-config \
  SOURCE_UID CONTROLLER_UID CONTROLLER_GID BUILD_READER_GID \
  INSTALLED_POLICY_SHA256 INSTALLED_POLICY_VERSION \
  > /etc/rdashboard/source.json.new
```

The tool has a fixed `rimg` project/remote and fixed root credential paths. It derives the
attestation public key, project-specific credential digests and key ID, emits only canonical JCS,
sets `auto_deploy=false`, and never serializes private bytes. Validate and atomically install the
new document as `root:root` mode `0644`; do not generate it until the exact installed owner-policy
identity is known. Future multi-project generation should extend this typed builder rather than
hand-editing digest-covered JSON.

Install the canonical workflow manifest catalog at `/etc/rdashboard/project-manifests`: the
directory must be `root:rdashboard` mode `0750`, and each `<project>.jcs` must be canonical JCS,
`root:rdashboard` mode `0640`. The dispatcher rejects unexpected entries, filename/project
mismatches, noncanonical manifests, unsafe ownership or modes, and any auto-deploy source project
whose repository or workflow-policy digest does not match this catalog. Repository checkout JSON is
not read directly in production; install its canonical encoding under the `.jcs` name.

Initialize each canonical bare repository below
`/var/lib/rdashboard-source/repositories/<project>.git` as the `rdashboard-source` account using the
reviewed `files` ref backend and owner-only modes before starting the service. Startup validates the
repository identity/configuration and durable source ledger before serving root-only requests on
`/run/rdashboard-source/source.sock`.

The broker must complete a bounded remote-main reconciliation for every configured project before
it binds the socket and sends systemd `READY=1` through the fixed `/usr/bin/systemd-notify`; an
unavailable or divergent startup source therefore fails closed under systemd restart rather than
serving a stale local head or releasing ordered dependents early. After each successful ready-head
reconciliation it also runs a fixed `git archive` itself and atomically publishes a source-owned,
reader-group `0440` tar plus canonical manifest below
`/var/lib/rdashboard-build/source-exports/<project>`. The manifest binds the exact head, sequence,
source attestation, repository and installed policy to the archive byte count and SHA-256. The
broker rejects symlinks, hard links, special Git entries and `.gitattributes` archive rewriting;
the build identity never sees the private bare repository. It then repeats reconciliation at the
installed interval. Shutdown waits for an already-running bounded Git fetch/export before dropping
the owned socket, keeping process and socket lifecycle aligned. Its Unix protocol is
length-bounded, versioned, request-bound and restricted to UID 0 by peer credentials. Synchronous
broker work runs outside the async reactor, while the full read/handle/write exchange remains
subject to the configured deadline. It exposes only the current signed snapshot and exact
live-ticket check/complete/abort operations; it does not expose Git paths or arbitrary commands.
Accepted deployable heads are committed atomically with a bounded signed outbox. A newer source head
supersedes older pending delivery, while lost acknowledgements replay the same scheduler identity.
The dispatcher polls locally at 250 ms, backs off boundedly on transport or policy failures, and
acknowledges only after the scheduler admission is durable. Periodic reconciliation refreshes an
expired current-head attestation, so a prolonged controller outage does not lose that head.
Webhook and forced-push ingress are not yet routed by this unit and remain disabled until their
dedicated HTTP/SSH front doors are installed and tested.

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
