# Project manifest catalog

This directory stores reviewed `ProjectManifestV2` workflow contracts. `tests/project_manifest_catalog.rs` discovers every JSON file, deserializes it through the strict Rust domain type, runs semantic validation, rejects duplicate IDs, and binds each filename to its project ID. The generated V1 schema remains available only for compatibility with already signed policy bundles.

A catalog entry describes source, a finite typed workflow DAG, fixed adapter and worker classes,
resource/network/cache envelopes, host preparation, verification, release build, health, data,
migration and rollback policy. Host preparation names only a fixed adapter and platform plus optional
exact digest-pinned Docker Hub base inputs; it cannot select a command, arbitrary registry, host path
or secret. `source_tree_v1` is offline and supports only
dependency-free or fully vendored source. `cargo_crates_io_v1` is the reviewed fixed Cargo adapter: it
accepts only SHA-256-pinned packages from the canonical crates.io identities in a version-4
`Cargo.lock`; git dependencies, alternate registries and repository-selected URLs are rejected. Its
optional OCI inputs must be exact `docker.io/...@sha256:...` references and are materialized as sealed
OCI layouts after manifest, descriptor, blob and linux/amd64 config verification. The networked
fetcher is isolated from source, CAS, credentials and verification jobs.

A manifest cannot select a shell command, host path, secret or project-specific worker service. It is
not an installed signed mutation policy and does not grant executor authority. Runtime activation
remains subject to the separately installed, signed, project-specific privilege boundary.

The `ralert.json` entry is the first V2 catalog migration and remains inactive. Before activation, its
reviewed source-side mirror must be upgraded, its dependency model must satisfy the declared
`source_tree_v1` policy (or explicitly move to `cargo_crates_io_v1`), and both repositories' bare gates
must pass; loading this controller catalog alone never enables a deploy.

The `rdashboard.json` entry is also inactive. It uses the explicit `self_update_handoff` delivery mode:
the generic VPS worker prepares pinned Cargo inputs once, runs the exact bare `bin/ci`, packages the
verified native binaries and publishes the root-validated signed handoff. Its finite graph ends at the
controller evidence reduction and contains no privileged-executor deployment nodes, because the
separately installed persistent bootstrap is the only A/B pointer, service-health and rollback owner.
The source controls keep `auto_deploy=false`; installing or validating this catalog cannot create a
release, start the bootstrap or mutate a host.

The `rimg.json` entry records the private source, existing `Dockerfile.runtime`, one verified release
output reused by minimal OCI assembly, two stateful paths,
derived uploads, exact liveness/readiness endpoints and the fenced application-migration position in
the generic deployment graph. It deliberately remains `auto_deploy=false`. The fixed preparer now
combines its Cargo vendor tree with the exact digest-pinned Debian base OCI layout in one immutable
dependency snapshot. Activation additionally requires publishing the already-built Titanium native
toolchain once under the shared root-owned toolchain store and supplying its runtime and CA support as
the Dockerfile's read-only local contexts. Until those boundaries are provisioned and reviewed, the
catalog may observe and archive `rimg` source but cannot truthfully claim a runnable worker or
deployment path.
