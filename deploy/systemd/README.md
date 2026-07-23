# systemd deployment inputs

## Controller and browser boundary

Install `rdashboard.service`; its controller binary is supplied by the verified A/B release at
`/var/lib/rdashboard-bootstrap/current/bin/rdashboardd`. The service binds only `127.0.0.1:3100` and
reads optional browser-access settings from `/etc/rdashboard/controller.env`. For a public route, create the
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

The controller unit explicitly wants and orders itself after the bridge socket, so every controller
boot transaction includes the private listener rather than relying only on the socket's enable
symlink. Keep the socket enabled as well; the controller remains loopback-only and never replaces the
bridge by listening on a public or all-interface address.

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
exact canonical lease, revalidates the named sealed `PreparedRun` composition and its exact
`DependencySnapshot`, and derives the unit name, mounts, UID/GID, command and resource limits itself.
A request cannot supply argv, a host path, a credential, a network mode or a systemd property.

Install `/etc/rdashboard/workflow-launcher.jcs` as canonical JCS, root-owned, mode `0600`. It contains
schema version `1`; the exact worker/build numeric identities and stable worker/host IDs; the matching
grant issuer and launcher audience; the minimum accepted key epoch and bounded verification-key
lifecycle list; the sorted, duplicate-free `allowed_adapters`; and `max_concurrent_jobs` plus
`max_journal_records`. The build UID must differ from the worker UID. The public key is non-secret; no
signing seed is present in this policy. Keep an adapter absent until its fixed executable, isolation and
output contract have been installed and reviewed; a signed lease alone cannot enable it.

Before systemd starts an authorized unit, the launcher atomically records the exact execution identity
under `/var/lib/rdashboard-workflow-launcher/jobs` and returns that durable `accepted` state. Complete
PreparedRun and Titanium closure verification then continues in the launcher's bounded starter task;
the worker polls the journal and renews the same lease while that potentially cold-disk integrity pass
is running. Only a fully resolved launch can be pinned and passed to `systemd-run`, and an input or
spawn failure becomes terminal journal evidence. A renewed lease for the same execution updates the
authorization record but never starts a second unit. A launcher restart converts any accepted/running
record into explicit `needs_reconcile` state, so an uncertain launch is stopped and cleaned rather than
silently replayed. Cleanup is itself journaled before `systemctl stop`; exact repeats return the same
evidence. Per-node workspace, Cargo configuration, logs and temporary files remain in an isolated
tmpfs with the lease byte and inode ceilings. The sealed composition is mounted read-only at
`/prepared`, its dependency snapshot at `/dependencies`, and the fixed job copies only
`/prepared/source` once into `/job/workspace`; the internal composition document never changes the
repository-visible tree. A separate exact operation-owned directory is mounted at `/operation` only
for adapters that consume the target and compiler cache. Matching compiled consumers on the VPS
execute serially against that directory; different attempts and hosts never share writable state. A
native self-release keeps verification and packaging on the same VPS-owned operation state, so an
optional build-only host cannot strand the required binaries or block the release. An OCI policy
without `verified_output` neither mounts nor allocates operation state, so its independently bounded
build can run beside verification. A policy such as rimg with `verified_output` instead keeps the
verification state on the same VPS and mounts it read-only for final assembly; the OCI consumer extends
the state's lifetime but does not increase its byte or inode capacity. For OCI projects an optional
build-only host gets a one-node local verification state and neither blocks the VPS nor causes its
files to be transferred.
Each verification source copy preserves the sealed tree's modification times and stable
`/job/workspace` path, which lets Cargo reuse the operation target instead of invalidating it merely
because the tmpfs workspace was recreated.

The fixed `rdashboard-workflow-job` maps the verification adapter to repository `bin/ci`. The native
self-release adapter never invokes a repository packaging script: after the exact verification receipt
exists, the launcher runs the installed `rdashboard-workflow-self-release-build` client against the
same read-only operation state. The client packages only policy-listed `target/release` binaries and
writes an unsigned typed result. Root independently validates every archive entry and digest, signs the
release with the systemd credential, and atomically publishes the complete SHA-named handoff directory
for the bootstrap reader. Install `rdashboard-workflow-self-release.conf` as a launcher drop-in only
when the matching native policy and root-owned `self-release-seed` credential are installed; OCI-only
and verification-only launchers do not require that credential. The generic job receives an empty,
reconstructed environment. The launcher forces Cargo offline so verification cannot turn a cache miss
into undeclared network access. Failed or uncertain execution removes partial operation and handoff
state; all declared successful consumers remove operation data after the last use. The retained
root-owned canonical tombstone and per-node launcher journal make cleanup replayable without retaining
repository-writable bytes. Operation records have a hard cap of 1,024; startup and capacity admission
prune terminal tombstones back to the newest 512. A non-active partial operation that receives no next
consumer for one hour is failed and stripped on the next admission before capacity is checked, so a
superseded attempt cannot pin a multi-gigabyte target indefinitely.

Generate the base launcher plus gateway/worker environments as one digest-bound workflow bootstrap
bundle, then generate the native launcher addition and bootstrap policy as a second digest-bound
bundle with the stable `rdashboard-self-update-config`; never type their duplicated identity, key,
runtime or payload fields by hand.
The same root-only tool initializes the first immutable slot from the exact fixed initial payload and
publishes LKG before `current`, which removes the startup cycle created by moving the launcher itself
below `current/bin`. The full inactive procedure and fixed paths are in `SELF_UPDATE.md`. Repository
checkout, bundle generation and initial-plan generation do not install, reload, enable or start a unit.

The OCI adapter never executes a repository script. The launcher derives a canonical request from the
signed lease and the root-owned per-project build policy, exposes only the sealed source, dependency
snapshot, one BuildKit Unix socket and one lease-owned output directory, and starts the installed
`rdashboard-workflow-oci-build` client directly. That client constructs fixed `buildctl` arguments,
permits only policy-listed build arguments and local OCI-layout base inputs, and exports a local OCI
archive with BuildKit metadata. Root re-hashes the archive, validates its OCI index, manifest, config
and layer graph, then atomically retains one typed result per project. External `# syntax=` frontends
are rejected before BuildKit starts because the daemon is intentionally offline. A root-owned
mode-`0444` non-secret request is individually read-only-bound from the otherwise untraversable
mode-`0700` result store, so the unrelated build UID can read it without gaining host-path or write
authority. A root-owned unit-to-request lifecycle registry lets cleanup discard incomplete staging even
after an ambiguous `systemd-run` wait. The result digest—not process exit evidence—is committed as the
release-build node output. It is deliberately a
`release_build_result`; CI evidence, reservation and deployment policy are still required before a
later step can seal a `ReleaseBundle`.

The launcher deliberately has no host network access, Docker/containerd socket, controller/executor/
source socket, production volume or credential access. Its DAC/chown capabilities are constrained by
the service mount namespace to the launcher journal, OCI-result mount and exact operation-state mount:
they let it create build-owned state and remove hostile or partial build output after the transient
unit stops. Transient jobs have an empty capability set and see only the binds required by their exact
adapter, while the host roots remain inaccessible. Installing the binary, policy and unit does not
enable or start it, activate a worker, change `auto_deploy`, or run a shadow job.

## Generic workflow worker and preparation store

`rdashboard-worker.service` is the one non-root worker for every installed project. It polls the
gateway with one stable worker/host identity, runs up to the configured number of typed leases, and
never creates a repository-specific service, checkout or dependency cache. A `host_prepare` lease
copies the exact attested source archive into the shared content-addressed store once; matching leases
join the same publication. Each `PreparedRun` has one canonical composition document binding its
source, content-derived dependency snapshot, exact Titanium toolchain artifact and versioned
generated-input layout. The signed lease/grant authorizes that immutable composition separately; a
policy rotation therefore does not copy identical source or dependency bytes. Verification pins
that sealed composition and transitively protects both referenced snapshots from eviction, asks the
root launcher to run only the installed fixed adapter, then cleans the transient unit and releases the
pin before committing the terminal receipt. Restart cleanup obligations are served before new work by
the gateway and are idempotent at the launcher and store boundaries.

Create the non-login `rdashboard-worker` user/group, the separate non-login
`rdashboard-dependency-fetcher` user and a shared `rdashboard-dependency-fetch` group. Add the worker
to both `rdashboard-build-readers` and `rdashboard-dependency-fetch`; the fetcher belongs only to
`rdashboard-dependency-fetch`, so it cannot connect to the worker gateway or launcher sockets. Install
these non-secret values in root-owned
`/etc/rdashboard/workflow-worker.env`, mode `0644` or stricter:

```sh
RDASHBOARD_WORKER_UID=992
RDASHBOARD_WORKER_ID=shared-vps-worker-1
RDASHBOARD_WORKER_HOST_ID=production-vps
RDASHBOARD_WORKER_SLOTS=2
RDASHBOARD_SOURCE_UID=993
RDASHBOARD_BUILD_READER_GID=994
RDASHBOARD_DEPENDENCY_FETCHER_UID=991
RDASHBOARD_DEPENDENCY_FETCH_GID=995
```

All numeric IDs are examples and must match the installed accounts. `RDASHBOARD_WORKER_UID`, worker
ID and host ID must exactly match both the gateway and launcher policies. The source UID and reader GID
must match the owner/group of `/var/lib/rdashboard-build/source-exports`; the service receives only
read access to that tree. Set worker slots no higher than the launcher's `max_concurrent_jobs` or the
measured CPU/RAM/IO capacity. The worker accepts 1-16 slots, but that protocol maximum is not a safe
installation default. It has no network namespace, capabilities, Docker/containerd/Podman socket,
credential, controller state or production volume.

Create one shared root-owned directory at `/var/lib/rdashboard-build` on the existing host filesystem
before starting any build service. Its backing filesystem must provide at least 16 GiB total.
Preparation CAS, operation state, BuildKit state and OCI results use owned child directories in this
same domain; the shared root is mode `0711` so services can traverse only to an explicitly permitted
child without listing or reading sibling stores. Projects share immutable toolchains and
content-addressed dependencies instead of keeping private copies. Do not create a separate filesystem
per service, project or cache.

### Titanium registry and native release contract

`/var/lib/rdashboard-build/titanium` is the single logical registry for Rust, Ruby, native libraries
and future build ecosystems. Projects do not own a `.titanium` cache and do not select tools by a
mutable host path. The on-disk layers are:

```text
/var/lib/rdashboard-build/titanium/
  trees/<content-digest>/{manifest.jcs,payload/}
  artifacts/<artifact-digest>.jcs
  actions/<compatibility-key>.jcs
  roots/
    installed-artifact/<logical-name>.jcs
    installed-toolchain/<logical-name>.jcs
    candidate-release/<artifact-digest>.jcs
    current-release/<project>.jcs
    last-known-good-release/<project>.jcs
    active-operation/<operation>.jcs
    publication-recovery/<publication>.jcs
    warm-action/<recipe-and-target>.jcs
  staging/
  registry.lock
```

`trees` deduplicates identical bytes globally. An `artifact` gives one tree a typed purpose, target,
provenance, acquisition class and dependency closure; therefore the same bytes can be trusted for two
different purposes without being copied or conflating their provenance. An `action` maps the complete
compatibility input (recipe, source and dependency artifacts, compiler/linker/sysroot artifacts,
target, CPU/ABI, normalized environment and output contract) to one output artifact. Project ID,
attempt ID, workflow-policy version, clock time and scratch path are deliberately absent from that
key. The signed workflow lease/grant separately authorizes whether a project may consume the action.

Acquisition class is installed policy, never a filename guess. A reviewed upstream compiler, linker
or other build-only tool may enter as `verified_upstream_prebuilt` after its official checksum and
provenance are verified; its exact artifact digest still participates in every action identity. A
locally tuned compiler or linker, and every native runtime library whose produced bytes determine
runtime performance or quality, enters as `controlled_source_build`. Both are immutable after
publication and are reused only through their exact artifact digest. `installed-artifact` roots name reusable build/runtime components;
`installed-toolchain` roots name complete language build environments. These names are immutable
version identifiers rather than pointers: a later upgrade publishes a new name and then updates the
project catalog. An in-flight preparation records the exact resolved artifact digest, so that catalog
change cannot change or poison an existing action.

Downloaded dependency bytes are not keyed by the compiler version. An unchanged lockfile and
dependency layout therefore remain reusable after a Rust or Ruby upgrade; the `PreparedRun` and
subsequent build action bind the new compiler artifact without downloading or copying those
dependencies again.

Publication copies into `staging`, verifies the complete portable tree manifest, promotes the object
atomically and only then exposes an artifact/action document. A crash before the final seal leaves no
readable valid object; retry removes only the invalid exact digest path and republishes it. GC walks
all explicit roots through action inputs/outputs and artifact dependencies, then removes unreachable
actions, artifacts and byte trees. Current, last-known-good, active-operation, recovery and installed
toolchain closures therefore remain runnable regardless of age. Size/age thresholds decide when GC
runs, not what it is safe to delete.

Every `host_preparation` manifest names a versioned `toolchain_root`, exact interface, target, CPU
baseline, ABI and normalized build environment. Before a production workflow can prepare that
project, the root must exist, contain exactly one `compiler_toolchain` artifact and match the declared
target/interface. CPU, ABI and environment become action inputs; values such as `native`, mutable
compiler channels and inherited shell flags are not accepted as compatibility identities. The generic
worker opens the registry read-only and fails closed on a missing, corrupt, wrong-kind or wrong-target
closure. This is intentional: falling back to `/usr/bin` or a mutable `stable` compiler would make
action-cache hits untrustworthy.

One toolchain may reference named components without copying them. Its main payload contains the
compiler/package-manager executables and empty mount points; `.titanium-toolchain.jcs` binds every
mount name to an exact `build_tool`, `runtime_library` or `runtime_support` artifact. Before
`systemd-run`, the root launcher verifies that complete closure, creates an `active-operation` root,
bind-mounts the main payload at `/toolchain`, then mounts each exact component at its declared child
path. For example, rimg can consume one shared Rust compiler at `/toolchain/bin` and one shared native
library artifact at `/toolchain/rimg-native` without embedding either in the other. The fixed job sees
only that composed view; it never sees the mutable import area or every installed toolchain. Cleanup
removes the active root only after the transient unit and operation state are settled, so GC cannot
remove any component while it is executing.

The root-only `rdashboard-titanium` utility supplies the bounded bootstrap/maintenance surface. It
imports only one direct child of `/var/lib/rdashboard-build/imports`, publishes and revalidates the
tree, and creates an immutable typed installed root; callers cannot select another registry or an
arbitrary source path. An installed root name is a version identifier, not a mutable channel: replay
with the same bytes is idempotent, while different bytes under the same name are rejected. Upgrading
therefore creates a new root name and changes the project catalog only after the new closure has been
inspected. `/var/lib/rdashboard-build/imports` is a transient admission inbox, not a cache. Its parent
is root-owned mode `0711`, and each admitted direct child must be a sealed root-owned mode-`0555`
directory. Remove that child only after the resulting artifact/root has been inspected. The fixed
`deploy/titanium/bootstrap-rust-v1` command assembles the initial shared `rust-v1` closure once. It
verifies the published SHA-256 values for the exact official Rust 1.96.1, Zig 0.16.0 and Node 22.22.2
archives, imports Node and Zig as reusable build-tool components, creates the Rust toolchain
descriptor with their exact artifact digests, imports the immutable toolchain and then removes only
its three fixed admission-inbox directories. Zig supplies the pinned C/C++ compiler, archiver,
linker and glibc 2.39 sysroot; Node is pinned for the JavaScript portion of `bin/ci`. Consequently
`cc`, `ar`, `ranlib` or `node` cannot silently fall through to a mutable host package while the
action key still claims the same toolchain. Run the command from the exact reviewed source checkout,
then inspect the installed root:

```sh
sudo deploy/titanium/bootstrap-rust-v1
rdashboard-titanium inspect-toolchain \
  rust-1.96.1-znver3-linux-x86_64-gnu-v1 linux-x86_64 rust-v1
rdashboard-titanium gc
```

Additional strictly sorted dependency digests after the source name bind named toolchain components declared
inside `.titanium-toolchain.jcs`. `import-artifact` admits reviewed `build-tool`, `runtime-library` or
`runtime-support` trees under the same immutable-name rule. `import-release` creates a
`candidate-release/<artifact-digest>` GC root and is a bounded
bootstrap/recovery command for an already verified release tree; normal workflow publication uses
the registry `publish_candidate_release_action` API so the recipe, external source content digests,
typed dependency-snapshot artifacts, exact toolchain artifacts and verification provenance are
recorded with the release rather than treating a manual import as a cache hit. If an admitted release
will not be activated, run `rdashboard-titanium discard-release <artifact-digest>` before GC. Discard
is rejected while that candidate has an active publication-recovery root.

Use `verified-upstream-prebuilt` only when installed policy has classified the component as
build-only and its upstream checksum/provenance has been independently verified. Importing a path is
not itself permission to classify it. `gc` is safe only because the import creates the installed root
in the same locked transaction sequence before any unreferenced sweep can run.

The imported main toolchain payload is an environment root: selected executables live under `bin/`.
Its canonical `.titanium-toolchain.jcs` declares the versioned interface, target, sorted required
executables and sorted component mounts; import rejects a missing executable, a non-empty mount point,
a wrong-kind component or a dependency closure that differs from the descriptor. Project manifests
request that exact interface (the current Rust catalog uses `rust-v1`). Populate and inspect every
`toolchain_root` referenced by the installed catalog before starting the worker or launcher; there is
deliberately no host-tool fallback for the Rust compiler, Cargo subcommands, C/C++ compilation,
archive construction, linking or Node verification. The fixed `rust-v1` interface rejects a closure
that omits any of those executable surfaces.

Managed native releases use two coordinated immutable closures rather than a Docker image. A release
tree contains project-owned files and `.titanium-release.jcs`; that descriptor binds the project,
target, interface, entrypoint, runtime contract and named exact runtime artifacts. Activation creates
an immutable view without copying bytes:

```text
/var/lib/rdashboard-managed/<project>/
  views/<release-artifact-digest>/
    release -> /var/lib/rdashboard-build/titanium/trees/<release-tree>/payload
    runtime/<mount> -> /var/lib/rdashboard-build/titanium/trees/<runtime-tree>/payload
  current -> views/<release-artifact-digest>
  activation.lock
  activation.jcs                 # present only while activation/recovery is unfinished
```

The installed service always executes
`/var/lib/rdashboard-managed/<project>/current/release/<entrypoint>` and refers to shared libraries or
support data through stable absolute `current/runtime/<mount>/...` paths. A dynamically linked binary
must bind that installed path in its policy-pinned runtime contract (for example through its reviewed
RPATH); `$ORIGIN` must not assume that executing through the `release` symlink changes the CAS
location reported by the loader. The view changes, but the referenced CAS objects never do. A first
deployment or upgrade performs this exact sequence under one project lock: validate the release
closure and fixed systemd-unit hash; create the candidate and publication-recovery roots; persist the
activation journal; materialize/verify the candidate view; atomically switch `current`; restart;
prove the loopback health contract; atomically advance registry `current-release` and
`last-known-good-release`; durably remove the activation journal; then remove candidate and recovery
roots in replay-safe order. A failed candidate restores the
previous view, restarts and proves it before reporting rollback. Every phase is replayable after a
crash; boot recovery also finishes the narrow journal-removed/root-finalization window, and a
divergent link/root state fails closed. If even the last-known-good view fails its health contract,
the durable journal is intentionally retained and further activations stay blocked: discarding that
evidence automatically would turn an unknown production state into an unaudited release decision.
The failed recovery unit is the operator-visible alert until the service or host dependency is
repaired and `recover` succeeds.

Run `rdashboard-native-release collect-installed-views` before `rdashboard-titanium gc`. The first
command removes only view directories not named by current/LKG roots and refuses an unfinished
activation; the second then marks complete artifact/action dependency closures from every registry
root and sweeps unreachable CAS objects. Release count and current byte sizes are therefore operating
policy, not path structure or cache identity.

Install and enable `rdashboard-native-release-recovery.service`; it requires the persistent
`rdashboard-bootstrap.service`, so the atomic current self-release exists before recovery starts.
Make each managed service declare
`Requires=rdashboard-native-release-recovery.service` and
`After=rdashboard-native-release-recovery.service`. Initialization, activation and recovery verify
the resolved systemd `Requires` and `After` sets as well as the exact unit-file digest, so a service
cannot silently bypass boot recovery. The managed service itself must also be enabled;
this is what makes it return after a host reboot. Generate a canonical root-owned policy, initialize
its state once, and activate only an exact release artifact:

```sh
rdashboard-native-release render-policy \
  rimg linux-x86_64 native-service-v1 bin/rimg \
  <runtime-contract-sha256> <installed-rimg.service-sha256> \
  http://127.0.0.1:8080/health/ready 204 30000
rdashboard-native-release initialize rimg
rdashboard-native-release activate rimg <release-artifact-sha256>
```

Store the rendered canonical document at `/etc/rdashboard/native-runtimes/rimg.jcs`, owned by root
and mode `0644`, before `initialize`. `recover-installed` is the boot-time command and touches only
projects already initialized under `/var/lib/rdashboard-managed`. `rimg` and `telegram-gateway` remain
on their existing catalog entries until their workflow release producers emit the complete descriptor
and action provenance; changing JSON first would describe a build result the controller cannot yet
publish. The native activation mechanism itself no longer depends on Docker, BuildKit, an image
registry, Kamal or GitHub Actions.

The preparation CAS itself refuses more than 6 GiB or 1,000,000 inodes. Every generated payload is
further clipped by its signed execution profile, so the global store boundary cannot bypass a
project-specific byte or inode limit.

The worker and launcher refuse startup unless their fixed child directory remains on the same backing
filesystem as `/var/lib/rdashboard-build` and ownership/mode is correct. New work is rejected unless
its conservative maximum still leaves the 5 GiB hard emergency margin for the operating system,
databases, logs and running services. Replaceable preparation entries begin eager LRU reclamation below
the 30 GiB free-space target; that target describes the desired normal state and is not added to each
operation's admission requirement. Start with one worker slot and one launcher job on the production
VPS so independent components cannot race their filesystem observations. The tmpfiles entries create
the complete owned hierarchy on the existing filesystem; no extra mount is a prerequisite.

`source_tree_v1` remains deliberately offline and is valid only for a dependency-free repository or
one whose complete gate dependencies are already vendored in the source tree. The additional
`cargo_crates_io_v1` adapter accepts only a bounded version-4 `Cargo.lock`: local workspace packages
plus SHA-256-pinned packages from the two canonical crates.io index identities. Git dependencies,
alternate registries, missing checksums and repository-selected URLs are rejected before any network
request.

`rdashboard-dependency-fetcher.service` is the only networked component in that path. Its binary
constructs one fixed `https://static.crates.io/crates/{name}/{name}-{version}.crate` URL, disables
redirects and proxy environment use, filters DNS answers to public addresses, and returns bytes only
to the exact worker UID over its mode-`0660` Unix socket. It cannot read source exports, the preparation
CAS, controller/launcher state, credentials or container sockets. The worker verifies every archive
checksum again, rejects links and unsafe archive paths, generates Cargo directory-source checksums and
publishes one immutable `DependencySnapshot`; matching requests therefore fetch and unpack once per
host. A Cargo preparation policy may additionally name sorted exact `docker.io` manifest-digest base
inputs. For those inputs the same isolated process derives only the fixed Docker Hub registry and
anonymous-token URLs, follows at most the registry-issued HTTPS blob redirect to Docker's public CDN,
returns the exact manifest/config/layer objects, and the worker verifies every descriptor, byte count,
SHA-256 and the `linux/amd64` config before publishing a canonical OCI layout inside that same snapshot.
Other redirects, foreign layer URLs, mutable-only references, alternate registry hosts and private DNS
results fail closed. Verification and release-build jobs remain networkless and
receive the sealed vendor and OCI-layout directories read-only. Installing these files does not enable
either service or activate a manifest. The catalog `ralert` manifest remains inactive under
`source_tree_v1`.

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

Telegram delivery is a separate, inactive activation boundary. The controller never receives the
gateway secret or opens the delivery database. `rdashboard-notify.service` runs the
`/usr/libexec/rdashboard/rdashboard-notify` binary as a dedicated `rdashboard-notify` user with the
matching dedicated group. The optional controller drop-in adds only that transport group to
`rdashboard.service`; the runtime directory is not group-writable, and every request is also bound to
the installed controller UID through peer credentials. The notifier is not a member of `rdashboard`
and cannot read the controller StateDirectory. It owns its mode-`0700` StateDirectory, submits a
content-bound deduplication key to the fixed HTTPS gateway, follows the gateway's asynchronous message
status, and retains explicit `delivery_unknown` and `delivered_possible_duplicate` states across
retries and restarts.

Do not install the controller drop-in until all installation values exist. Create the matching
`rdashboard-notify` system user and group without a login shell or home, install
`rdashboard-notify.service`, and place these
non-secret values in root-owned `/etc/rdashboard/notifier.env`, mode `0644` or stricter:

```sh
RDASHBOARD_NOTIFY_CONTROLLER_UID=991
RDASHBOARD_NOTIFY_GATEWAY_PROJECT=replace_with_dedicated_gateway_project
RDASHBOARD_NOTIFY_CHAT_ID=-1000000000000
RDASHBOARD_NOTIFY_THREAD_ID=0
```

`RDASHBOARD_NOTIFY_CONTROLLER_UID` must be the actual numeric UID of `rdashboard`, not the example.
The gateway project must be dedicated to this route; the chat ID must identify the reviewed operator
chat, and thread `0` means no topic. Install its bearer secret as the root-owned, mode-`0600` regular
file `/etc/rdashboard/credentials/telegram-gateway-secret`. The service receives only the systemd
credential copy and never reads the source credential directory.

Start and inspect `rdashboard-notify.service` first. Then install
`rdashboard-notifier.conf` as a drop-in for `rdashboard.service` and restart the controller. The
drop-in adds the exact `/run/rdashboard-notify/notify.sock` path plus a hard service dependency. Once
active, each integration transition and its notifier handoff are committed atomically in
`integrations.sqlite`; a controller crash or unavailable notifier leaves a bounded durable handoff
for retry instead of losing the event. The notifier's separate outbox then owns gateway retry and
terminal delivery state. Removing the controller drop-in and restarting the controller disables new
notification planning without exposing the secret or fabricating a configured dashboard state.

No unit or credential is installed or enabled by repository checkout alone. Production activation
requires a reviewed gateway project, chat/thread, numeric UID, credential, binary installation,
daemon reload and service restarts; those are deployment actions outside the local verification
workflow.

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

Install `rdashboard-telegram-gateway.env` as root-owned mode `0644` at
`/usr/lib/rdashboard/rdashboard-telegram-gateway.env`. It fixes the operator-visible stable health
route at `https://tg.4u.ge/health` and reuses the same peer-authenticated observer socket for resource
attribution. The controller follows no redirects and treats only HTTP 200 as healthy; this deliberately
checks the real Cloudflare/Kamal Proxy route rather than only container reachability.

Before starting the observer, write the controller's actual non-root numeric UID as
`RDASHBOARD_OBSERVER_ALLOWED_UID=<uid>` in root-owned `/etc/rdashboard/observer.env`; no other value
belongs in that file. The persistent root observer creates
`/run/rdashboard-observer/observer.sock` as `root:rdashboard` mode `0660`, verifies every connecting
peer UID, and accepts only the versioned `project_resources` request for an installed project. The
installed handler recognizes exact compiled profiles for `rimg` and `telegram-gateway`; the request
cannot select a container, Docker command, label, socket or host path. The observer performs fixed,
two-second-bounded Docker queries and requires the profile's exact Kamal service/role labels, running
state and private `kamal` address. `rimg` additionally requires Docker `healthy`.
`telegram-gateway` has no image-level Docker `HEALTHCHECK`, so its profile accepts only the explicit
`missing` health field while the independent stable HTTP probe remains the availability authority.
The observer returns only a bounded numeric resource record. Its service has fixed
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
`rdashboard-source-dispatcher.service`, install `rdashboard-source-tmpfiles.conf` under
`/usr/lib/tmpfiles.d/`, then apply that source-specific tmpfiles configuration before starting any
source unit. It creates the two volatile cross-service transport directories on every boot without
depending on the still-inactive worker/BuildKit identities referenced by `rdashboard-tmpfiles.conf`.
The full shared-build tmpfiles configuration is installed only with that contour. Repository checkout
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

Render each reviewed repository manifest through the strict domain type before atomic installation;
do not copy the pretty JSON directly into the installed JCS catalog:

```sh
/usr/libexec/rdashboard/rdashboard-source-config canonicalize-manifest \
  < config/project-manifests/rdashboard.json \
  > /etc/rdashboard/project-manifests/rdashboard.jcs.new
```

Repeat for every catalog member, set the ownership/mode above and rename the complete reviewed set
into place together. The `rdashboard` member declares `self_update_handoff`: native verification and
packaging stay on the required VPS, and the graph ends after signed handoff evidence instead of
entering the ordinary privileged-executor mutation graph.

Review the repository candidate `config/source-projects.json`, render it as canonical JCS, then install it as
`/etc/rdashboard/source-projects.jcs`, root-owned mode `0600`. It must cover the workflow catalog
exactly and contains only owner-controlled deployment values:

```json
{"projects":[{"auto_deploy":false,"installed_policy_version":2,"maximum_attempts":3,"project_id":"ralert","release_class":"stateful_compatible"},{"auto_deploy":true,"installed_policy_version":2,"maximum_attempts":2,"project_id":"rdashboard","release_class":"code_only_compatible"},{"auto_deploy":false,"installed_policy_version":2,"maximum_attempts":2,"project_id":"rimg","release_class":"code_only_compatible"},{"auto_deploy":false,"installed_policy_version":2,"maximum_attempts":2,"project_id":"telegram-gateway","release_class":"stateful_compatible"}],"purpose":"rdashboard.source-project-controls.v1","schema_version":1}
```

Render the reviewed candidate without accepting trailing whitespace or noncanonical installed bytes:

```sh
/usr/libexec/rdashboard/rdashboard-source-config canonicalize-controls \
  < config/source-projects.json > /etc/rdashboard/source-projects.jcs.new
```

Atomically install the result as `/etc/rdashboard/source-projects.jcs` with the ownership and mode
above before running the source-document build command.

Keep `auto_deploy=false` until the complete worker/build/deploy path for that project has passed its
activation review. The repository candidate enables it only for `rdashboard`; install those controls
only after a successful shadow of the exact candidate head. Each project gets its remote URL and
workflow-policy digest from the installed manifest, so adding or removing a repository is one exact
catalog-and-controls change, not a new worker implementation.

An explicitly authorized non-mutating activation check uses the same installed source and workflow
policies without enabling automatic deployment:

```sh
sudo -u rdashboard /var/lib/rdashboard-bootstrap/current/bin/rdashboard-source-dispatcher shadow rdashboard
```

The source service returns only its current, unblocked, unexpired signed head. The dispatcher rejects
the command unless it runs as the installed controller UID and `auto_deploy` is still false. The
durable scheduler records a distinct `shadow` request, runs source preparation, verification, release
build and deterministic reduction, then succeeds with every reservation/backup/migration/health/
cutover/observation/rollback node already terminally cancelled. The command prints a canonical
admission receipt; it does not fake safety by stopping the executor and the same source SHA remains
independently deployable later.

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
the 30-second reconciliation interval. It contains no private bytes. When `/etc/rdashboard` remains
the required `root:rdashboard` mode `0750`, grant only traversal to the two isolated readers with
`setfacl -m u:rdashboard-source:--x,u:rdashboard-source-ingress:--x /etc/rdashboard`. Do not add
either identity to the controller group or grant either identity directory listing; the root-owned
mode-`0600` credential files remain unreadable through this ACL. Then generate the complete systemd
credential drop-in from that installed document:

```sh
/usr/libexec/rdashboard/rdashboard-source-config systemd-credentials \
  > /etc/systemd/system/rdashboard-source.service.d/credentials.conf.new
```

Atomically install the drop-in as `root:root` mode `0644`. The base unit intentionally has no
`LoadCredential=` line; this generated file is the single exact list for the attestation seed, every
webhook secret and only the SSH credentials required by the current project catalog. Regenerate it
whenever the installed project set changes. The source validates systemd's root-owned mode-`0440`
credential projection as read-only service input; the originals under `/etc/rdashboard/credentials`
remain root-owned mode `0600`.

Initialize every canonical bare repository at
`/var/lib/rdashboard-source/repositories/<project>.git` as `rdashboard-source`, using the reviewed
`files` ref backend and owner-only modes. Apply `rdashboard-tmpfiles.conf` after every catalog change:
each installed project must already have a source-owned, `rdashboard-build-readers` group,
mode-`2750` directory at `/var/lib/rdashboard-build/source-exports/<project>`. The hardened source
service cannot create a new setgid handoff directory itself, and startup fails closed when the
catalog and tmpfiles provisioning differ. Before sending systemd `READY=1`, the broker recovers its
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
object state. A production fetch starts only with room for two bounded 1 GiB staging copies plus the
larger of a 4 GiB or five-percent filesystem emergency reserve; the resulting floor is 6 GiB without
borrowing the separate build/deploy safety budgets. A missed webhook is recovered by the 30-second
reconciliation loop with at most five seconds of deterministic startup jitter, keeping the fallback
below one minute without synchronized fetch bursts. On restart, wake-ups for a removed project or a
project rebound to a different GitHub repository are retired before ingress binds; accepted-source
and completed-delivery audit history is retained. Rewinds or divergence cannot bypass the existing
accepted-head guard and enter
`source_diverged_needs_owner`; a direct-push SSH front door is not installed by this slice.

After each accepted ready head, the broker runs fixed `git archive` itself and atomically publishes
a source-owned, reader-group mode-`0440` tar plus canonical manifest below
`/var/lib/rdashboard-build/source-exports/<project>`. The manifest binds the exact head, sequence,
source attestation, repository and installed policy to archive size and SHA-256. Symlinks, hard links,
special Git entries and `.gitattributes` archive rewriting are rejected; the build identity never
sees the private repository. The immutable tar is keyed only by head and source sequence, while each
refreshed source attestation gets its own small digest-keyed manifest that reuses those exact tar
bytes; readers also accept the original unversioned manifest name during migration. Accepted
deployable heads enter a bounded signed outbox atomically. The
dispatcher polls locally at 250 ms, retries lost acknowledgements with the same scheduler identity
and acknowledges only after scheduler admission is durable. A newer head supersedes older pending
delivery, while periodic reconciliation refreshes an expired current-head attestation.

The executor always serves the bounded observation protocol and can optionally enable the admitted
backup and installed-deployment mutation paths described below. Its verified release binary is
`/var/lib/rdashboard-bootstrap/current/bin/rdashboard-executor`; create the
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

The repository-built `rdashboard-adapter-receipt` executable is part of the verified A/B payload at
`/var/lib/rdashboard-bootstrap/current/bin/rdashboard-adapter-receipt`. Every fixed adapter transient
unit binds this exact path through `ExecStopPost=`. The helper runs before `systemd-run --collect` can discard the unit cgroup and
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

The backup pipeline is project-scoped. A non-rimg project reads the same encryption/upload contract
from `/etc/rdashboard/projects/<project-id>/backup-runtime.jcs` and `rclone.conf`, and only its
`/etc/rdashboard/credentials/projects/<project-id>/drive-service-account.json` is eligible for the
transient upload/readback units. The installed document still binds the exact project and mutation
policy digest, so a project-specific path cannot authorize a foreign backup.

A non-rimg SQLite service additionally installs canonical mode-`0600`
`/etc/rdashboard/projects/<project-id>/sqlite-backup-runtime.jcs`. Its purpose is
`rdashboard.installed-sqlite-backup-runtime.v1`; it binds the exact project and installed mutation
policy digest, one absolute source database path, and the sorted table allowlist that defines the
service's domain/staged-read check. The source is accepted only below either the existing Docker
named-volume root `/var/lib/docker/volumes/<project-id>-data/_data` or the managed data root
`/var/lib/rdashboard/projects/<project-id>/data`. The path and database must contain no symlink,
must be root-owned with no group/world access and must have exactly one hard link. Telegram Gateway
therefore uses `/var/lib/docker/volumes/telegram-gateway-data/_data/gateway.db` during adoption.

For this profile the adapter performs SQLite's online backup API against the live WAL database; it
does not copy `-wal` or `-shm`, drain the service, or grant the transient unit write access to the
source volume. It publishes the snapshot through an fsynced pending file and hard link, validates
integrity, foreign keys, the required-table domain contract and staged reads, then derives the
application schema identity from the canonical `sqlite_schema` inventory. The immutable database is
paired with `sqlite-capture-state.jcs`, which binds its digest, schema identity, original capture
time and authorized backup digest. Replay accepts only the complete pair; a crash that published
only one member causes a fresh online capture rather than invented timing evidence. This generic
profile intentionally supports base snapshots only; cutover snapshots still require a real write
fence and remain rimg-specific. The encrypted archive enumerates the signed manifest objects, while
the rimg two-object archive retains its exact legacy `database.sqlite`/`masters.bundle` layout.

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

The Kamal deploy and rollback profiles additionally require these root-owned installed inputs. The
legacy rimg installation remains byte-for-byte compatible with its original paths and schema:

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

Other projects use the canonical
`/etc/rdashboard/projects/<project-id>/kamal-adapter-runtime.jcs` path and the canonical
`rdashboard.installed-kamal-adapter-runtime.v4` schema. V4 adds one bounded HTTP health policy:
an absolute query-free path, an expected 2xx status, a 100-5000 ms connect/read timeout and retry
interval, and 1-120 attempts. Its credentials are isolated under
`/etc/rdashboard/credentials/projects/<project-id>/kamal-secrets.env` and `kamal-ssh-key`; a
transient unit receives only the credentials for the project bound into its authorized phase spec.
The adapter connects only to the inspected private address of the candidate on the fixed `kamal`
network, caps the HTTP response at 16 KiB and rejects unspecified, loopback or multicast addresses.
V4 currently supports only an already-installed deploy or rollback. First-install bootstrap remains
the legacy rimg path and fails closed for V4 until a separately reviewed adoption/bootstrap
contract can create the initial release authority without guessing from a live container.

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

Installed updates do not publish a backend port and do not give release containers the application's
network alias. The sole long-lived alias belongs to the exact owned
`rdashboard-<project-id>-router` container on the `kamal` network. Its only persisted state lives in
the exact labelled `rdashboard-<project-id>-router-state` Docker volume. Each release runs as
`rdashboard-<project-id>-backend-<full-git-sha>` with exact image, bundle and deployment-plan
labels. The adapter derives the router port and alias from the signed deployment plan, starts and
verifies the candidate with either the legacy Docker health state or the installed V4 HTTP probe,
switches and drains through `<project-id>-internal`, then stops only the exact old owned backend.
For rimg these derived identities remain exactly `rdashboard-rimg-router`,
`rdashboard-rimg-router-state`, port 8080, alias `rimg`, service `rimg-internal` and health path
`/health/ready`. Reconciliation verifies router image, label, network and project alias, waits for
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
