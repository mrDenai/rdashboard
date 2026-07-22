# Rootless OCI activation boundary

The `worker_oci_release_build_v1` adapter is disabled unless the root-owned launcher policy contains
one matching `rootless_oci` contract and every live readiness check succeeds. This keeps verification
and host preparation available when OCI assembly is unavailable; it does not silently substitute
Docker or Podman. Native self-release has a separate installed client, policy, signing credential and
atomic handoff store; enabling it does not enable OCI, and neither adapter invokes an optional
repository packaging script.

Install one reviewed, root-owned copy of `buildkitd`, `buildctl`, `rootlesskit` and `runc` at the fixed
paths under `/usr/libexec/rdashboard`; projects never carry private copies of these tools. Bind their
SHA-256 values and the SHA-256 of the installed
`/etc/rdashboard/buildkitd.toml` to the launcher policy. Keep
`kernel.apparmor_restrict_unprivileged_userns=1`: install
`usr.libexec.rdashboard.rootlesskit` as the root-owned mode-`0644`
`/etc/apparmor.d/usr.libexec.rdashboard.rootlesskit`, load it with
`apparmor_parser -r`, and bind its SHA-256 to the same launcher policy. The reviewed profile attaches
the `unconfined` AppArmor exception only to the exact fixed rootlesskit executable and explicitly
allows it to create the user namespace needed by BuildKit. This preserves the host-wide restriction
for other unprofiled applications; it is not an AppArmor sandbox for RootlessKit. Do not replace this
with a host-wide sysctl override. The dedicated `rdashboard-buildkit` account
must differ from the controller worker and transient build accounts, use `rdashboard-build` as its
service group, and own non-overlapping ranges of at least 65,536 IDs in both `/etc/subuid` and
`/etc/subgid`. Every range in both host files must start at 65,536 or higher and no ranges may overlap;
otherwise a setuid mapping helper could expose a reserved host identity through an unrelated account.
`newuidmap` and `newgidmap` must remain root-owned mode `04755`.

Before any build service starts, create `/var/lib/rdashboard-build` on the existing host filesystem.
The backing filesystem must be at least 16 GiB and the directory contains the preparation CAS,
operation state, one root-owned `toolchains` tree, BuildKit state and OCI results for every project.
Their child directories keep distinct owners and modes; the mode-`0711` root permits traversal without
granting BuildKit the source-reader group. They share capacity so toolchains and content-addressed
inputs are stored once. Do not mount a filesystem per component or per project. An admitted write must
leave the 5 GiB hard emergency margin for the operating system, databases, logs and running services.
Replaceable CAS data starts eager LRU reclamation below the 30 GiB desired-normal-state target; that
target is not reserved for each operation. The production VPS starts with one worker slot and one
launcher job, making these admissions serial rather than racing independent capacity observations.

BuildKit owns `/var/lib/rdashboard-build/buildkit`, group `rdashboard-build`, mode `0700`. Its own GC
keeps at most 1.5 GB and begins reclaiming when the shared store has less than 4 GB free; these are
cache controls inside the host-wide 5 GiB emergency-margin and 30 GiB eager-GC policy. OCI results live at
the root-owned mode-`0700` `/var/lib/rdashboard-build/oci-results`. An individual policy may admit at
most a 3 GiB OCI archive, and one atomically promoted pre-release result is retained per project.

Install `rdashboard-buildkitd.toml` as `/etc/rdashboard/buildkitd.toml`, root-owned mode `0644`. The
service inherits a private systemd network namespace, and RootlessKit's `--net=host` therefore means
the service's isolated namespace rather than the VPS network. BuildKit receives no production
credentials, application state, Docker/containerd/Podman socket, source store or executor socket.
The OCI worker uses process sandboxing, permits no insecure entitlements, runs one build vertex at a
time and keeps at most 1.5 GB before garbage collection in the shared store.

Start `rdashboard-buildkit.service` only after the shared directory hierarchy and child ownership are
installed, then install a launcher policy that allows the OCI adapter.
The service has a 6 GiB memory ceiling, matching rimg's 6 GiB preparation, gate and final-image
profiles on the resized production host. This is a cgroup ceiling rather than preallocated resident
memory; other services retain the unused capacity.
On launcher startup the read-only preflight verifies pinned binaries and configuration, subordinate ID
ranges, kernel/AppArmor user-namespace switches, the exact shared storage boundary, the 5 GiB emergency margin,
the exact root-owned profile bytes, its loaded `unconfined` kernel profile, runtime ownership and a
live peer-restricted mode-`0660` Unix socket. Failure is logged with a stable
`reason_code`, a concise summary and a specific remediation. Do not enable the OCI adapter by removing
a check or lowering a boundary; leave the adapter absent while fixing the host.

The launcher-policy member has this shape; use measured local IDs and `sha256sum` output rather than
the placeholders:

```json
"rootless_oci": {
  "schema_version": 2,
  "daemon_uid": 996,
  "daemon_user": "rdashboard-buildkit",
  "buildkitd_sha256": "<64 lowercase hex>",
  "buildctl_sha256": "<64 lowercase hex>",
  "rootlesskit_sha256": "<64 lowercase hex>",
  "runtime_sha256": "<64 lowercase hex>",
  "buildkit_config_sha256": "<64 lowercase hex>",
  "rootlesskit_apparmor_profile_sha256": "<64 lowercase hex>",
  "max_parallelism": 1
},
"rootless_oci_builds": [{
  "schema_version": 1,
  "project_id": "example",
  "dockerfile_path": "Dockerfile",
  "target": "release",
  "platform": "linux/amd64",
  "build_args": [{"key": "RUBY_VERSION", "value": "4.0.0"}],
  "base_inputs": [{
    "source": "docker.io/library/debian:trixie-slim@sha256:9bb8a3626890e084ab54e888fdd7c4b6d2f119071cd4c5dc5fecb4d73062aa5f",
    "layout_name": "debian-trixie",
    "dependency_path": "oci-layouts/debian-trixie",
    "manifest_digest": "sha256:9bb8a3626890e084ab54e888fdd7c4b6d2f119071cd4c5dc5fecb4d73062aa5f"
  }],
  "local_inputs": [
    {
      "source": "native",
      "local_name": "native",
      "toolchain_path": "rimg-native/opt/4u"
    },
    {
      "source": "runtime-support",
      "local_name": "runtime-support",
      "toolchain_path": "rimg-native/runtime-support"
    }
  ],
  "verified_output": {
    "context_name": "verified-release",
    "directory": "release",
    "max_bytes": 134217728,
    "max_files": 1
  },
  "max_archive_bytes": 2147483648
}]
```

The adapter invokes the installed client directly; repository `bin/build-oci-release` scripts are not
part of the authority boundary. Every non-scratch base must already exist as a sealed OCI layout in the
dependency snapshot and be named by `base_inputs`; the daemon's private network intentionally cannot
fetch it on demand. The source name must match the digest-pinned `FROM` reference byte for byte; the
layout manifest digest is the same pinned linux/amd64 manifest. Dockerfiles that request an external
`# syntax=` frontend fail before `buildctl`
starts. No secret, SSH mount, entitlement, registry output or external cache argument can be supplied.
The `cargo_crates_io_v1` host-preparation policy may declare the same sorted exact Docker Hub base
inputs. The isolated public dependency fetcher derives only the fixed anonymous-token and registry
routes plus the registry-issued HTTPS blob redirect to Docker's public CDN, while the worker verifies
the exact manifest/config/layer graph and publishes the canonical layout under
`oci-layouts/<layout_name>` in the content-addressed dependency snapshot. The build client
revalidates that layout and its complete blob set against installed `base_inputs` before starting
BuildKit.
`local_inputs` name exact root-owned, non-group/world-writable subtrees below the single
`/var/lib/rdashboard-build/toolchains` store. The launcher exposes only that store read-only; project
Dockerfiles do not install their own Rust, Cargo or native compiler stack. For rimg the additional
`rimg-native` tree is published once under its checked fingerprint and manifest. Its `opt/4u` subtree
contains the pruned native runtime while `runtime-support` contains the separately verified CA bundle;
the final offline assembly consumes both sealed inputs and does not run a package manager.
The canonical non-secret build request remains root-owned inside the mode-`0700` result store and is
mode `0444` so the unrelated unprivileged build UID can open its individual read-only bind mount; the
host path is otherwise untraversable and the transient mount namespace exposes only that exact file.
The client verifies BuildKit metadata plus every referenced OCI blob, and root verifies it again before
atomically promoting the result. Process success without that typed result is workflow failure. An OCI
policy without `verified_output` allocates no operation state and may run independently beside
verification. A policy with `verified_output` must wait for the exact verification receipt, reuse that
attempt's operation state on the same VPS, expose only the declared sealed directory as a named
context, and record its stable content digest before removing it. That directory is deliberately flat:
only bounded regular single-link files are accepted; nested directories and extra entries fail before
BuildKit starts. The root-owned unit/request registry retries staging cleanup after an ambiguous
process wait. This result
is not a `ReleaseBundle`: final sealing still waits for CI evidence, resource reservation and installed
deployment policy.

Installing these files does not enable or start BuildKit, allow an OCI adapter, run a build, or change
deployment admission. Keep both `rootless_oci` and `rootless_oci_builds` absent until the runtime,
sealed bases, result filesystem and exact project policy have been reviewed together.
