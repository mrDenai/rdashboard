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
`/etc/rdashboard/buildkitd.toml` to the launcher policy. The dedicated `rdashboard-buildkit` account
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
inputs are stored once. Do not mount a filesystem per component or per project. The host filesystem
must retain 20 GiB after an admitted write; replaceable CAS data starts LRU reclamation below the
30 GiB target. The production VPS starts with one worker slot and one launcher job, making these
admissions serial rather than racing independent capacity observations.

BuildKit owns `/var/lib/rdashboard-build/buildkit`, group `rdashboard-build`, mode `0700`. Its own GC
keeps at most 1.5 GB and begins reclaiming when the shared store has less than 4 GB free; these are
cache controls inside the host-wide 20/30 GiB admission policy. OCI results live at
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
On launcher startup the read-only preflight verifies pinned binaries and configuration, subordinate ID
ranges, kernel/AppArmor user-namespace switches, the exact shared storage boundary, the 20 GiB recovery reserve,
runtime ownership and a live peer-restricted mode-`0660` Unix socket. Failure is logged with a stable
`reason_code`, a concise summary and a specific remediation. Do not enable the OCI adapter by removing
a check or lowering a boundary; leave the adapter absent while fixing the host.

The launcher-policy member has this shape; use measured local IDs and `sha256sum` output rather than
the placeholders:

```json
"rootless_oci": {
  "schema_version": 1,
  "daemon_uid": 996,
  "daemon_user": "rdashboard-buildkit",
  "buildkitd_sha256": "<64 lowercase hex>",
  "buildctl_sha256": "<64 lowercase hex>",
  "rootlesskit_sha256": "<64 lowercase hex>",
  "runtime_sha256": "<64 lowercase hex>",
  "buildkit_config_sha256": "<64 lowercase hex>",
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
    "source": "docker.io/library/debian:trixie-slim",
    "layout_name": "debian-trixie",
    "dependency_path": "oci-layouts/debian-trixie",
    "manifest_digest": "sha256:<64 lowercase hex>"
  }],
  "local_inputs": [{
    "source": "native",
    "local_name": "native",
    "toolchain_path": "rimg-native/opt/4u"
  }],
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
fetch it on demand. Dockerfiles that request an external `# syntax=` frontend fail before `buildctl`
starts. No secret, SSH mount, entitlement, registry output or external cache argument can be supplied.
`local_inputs` name exact root-owned, non-group/world-writable subtrees below the single
`/var/lib/rdashboard-build/toolchains` store. The launcher exposes only that store read-only; project
Dockerfiles do not install their own Rust, Cargo or native compiler stack. For rimg the additional
`rimg-native` tree is published once under its checked fingerprint and manifest.
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
