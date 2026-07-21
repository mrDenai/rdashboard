# Rootless OCI activation boundary

The `worker_oci_release_build_v1` adapter is disabled unless the root-owned launcher policy contains
one matching `rootless_oci` contract and every live readiness check succeeds. This keeps verification
and host preparation available when OCI assembly is unavailable; it does not silently substitute
Docker or Podman. Native self-release has a separate installed client, policy, signing credential and
atomic handoff store; enabling it does not enable OCI, and neither adapter invokes an optional
repository packaging script.

Install reviewed, root-owned `buildkitd`, `buildctl`, `rootlesskit` and `runc` binaries at the fixed
paths under `/usr/libexec/rdashboard`. Bind their SHA-256 values and the SHA-256 of the installed
`/etc/rdashboard/buildkitd.toml` to the launcher policy. The dedicated `rdashboard-buildkit` account
must differ from the controller worker and transient build accounts, use `rdashboard-build` as its
service group, and own non-overlapping ranges of at least 65,536 IDs in both `/etc/subuid` and
`/etc/subgid`. Every range in both host files must start at 65,536 or higher and no ranges may overlap;
otherwise a setuid mapping helper could expose a reserved host identity through an unrelated account.
`newuidmap` and `newgidmap` must remain root-owned mode `04755`.

Before the service is started, mount a dedicated filesystem at `/var/lib/rdashboard-buildkit`. The
launcher accepts only a 1.5-2.5 GiB filesystem with 50,000-500,000 inodes, owned by the BuildKit UID,
group `rdashboard-build`, mode `0700`. This filesystem is the hard fence; BuildKit garbage collection
is an additional policy, not the capacity boundary. Root filesystem free space must remain at least
12 GiB.

Before the OCI adapter is admitted, also mount a dedicated filesystem at
`/var/lib/rdashboard-workflow-launcher/oci-results`. The launcher accepts only a root-owned mode-`0700`
4-6 GiB filesystem with 10,000-100,000 inodes while `/` still has at least 12 GiB free. An individual
policy may admit at most a 3 GiB OCI archive. One atomically promoted pre-release result is retained per
project; a newer pre-mutation attempt replaces the older pre-release result, and the filesystem is the
hard cross-project bound. BuildKit cache, operation state and OCI result bytes therefore have distinct
owners and limits rather than sharing an unbounded Docker data root.

Install `rdashboard-buildkitd.toml` as `/etc/rdashboard/buildkitd.toml`, root-owned mode `0644`. The
service inherits a private systemd network namespace, and RootlessKit's `--net=host` therefore means
the service's isolated namespace rather than the VPS network. BuildKit receives no production
credentials, application state, Docker/containerd/Podman socket, source store or executor socket.
The OCI worker uses process sandboxing, permits no insecure entitlements, runs one build vertex at a
time and keeps at most 1.5 GB before garbage collection on the smaller hard-bounded filesystem.

Start `rdashboard-buildkit.service` and mount the bounded result store before installing a launcher
policy that allows the OCI adapter.
On launcher startup the read-only preflight verifies pinned binaries and configuration, subordinate ID
ranges, kernel/AppArmor user-namespace switches, exact storage bounds, the 12 GiB recovery reserve,
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
  "max_archive_bytes": 2147483648
}]
```

The adapter invokes the installed client directly; repository `bin/build-oci-release` scripts are not
part of the authority boundary. Every non-scratch base must already exist as a sealed OCI layout in the
dependency snapshot and be named by `base_inputs`; the daemon's private network intentionally cannot
fetch it on demand. Dockerfiles that request an external `# syntax=` frontend fail before `buildctl`
starts. No secret, SSH mount, entitlement, registry output or external cache argument can be supplied.
The canonical non-secret build request remains root-owned inside the mode-`0700` result store and is
mode `0444` so the unrelated unprivileged build UID can open its individual read-only bind mount; the
host path is otherwise untraversable and the transient mount namespace exposes only that exact file.
The client verifies BuildKit metadata plus every referenced OCI blob, and root verifies it again before
atomically promoting the result. Process success without that typed result is workflow failure. OCI
builds allocate no shared operation-state cache and can run independently beside verification. The
root-owned unit/request registry retries staging cleanup after an ambiguous process wait. This result
is not a `ReleaseBundle`: final sealing still waits for CI evidence, resource reservation and installed
deployment policy.

Installing these files does not enable or start BuildKit, allow an OCI adapter, run a build, or change
deployment admission. Keep both `rootless_oci` and `rootless_oci_builds` absent until the runtime,
sealed bases, result filesystem and exact project policy have been reviewed together.
