# Project manifest catalog

This directory stores reviewed `ProjectManifestV2` workflow contracts. `tests/project_manifest_catalog.rs` discovers every JSON file, deserializes it through the strict Rust domain type, runs semantic validation, rejects duplicate IDs, and binds each filename to its project ID. The generated V1 schema remains available only for compatibility with already signed policy bundles.

A catalog entry describes source, a finite typed workflow DAG, fixed adapter and worker classes,
resource/network/cache envelopes, host preparation, verification, release build, health, data,
migration and rollback policy. Host preparation names only a fixed adapter and platform; it cannot
select a command, registry, host path or secret. `source_tree_v1` is offline and supports only
dependency-free or fully vendored source. `cargo_crates_io_v1` is the reviewed fixed Cargo adapter: it
accepts only SHA-256-pinned packages from the canonical crates.io identities in a version-4
`Cargo.lock`; git dependencies, alternate registries and repository-selected URLs are rejected. Its
networked fetcher is isolated from source, CAS, credentials and verification jobs.

A manifest cannot select a shell command, host path, secret or project-specific worker service. It is
not an installed signed mutation policy and does not grant executor authority. Runtime activation
remains subject to the separately installed, signed, project-specific privilege boundary.

The `ralert.json` entry is the first V2 catalog migration and remains inactive. Before activation, its
reviewed source-side mirror must be upgraded, its dependency model must satisfy the declared
`source_tree_v1` policy (or explicitly move to `cargo_crates_io_v1`), and both repositories' bare gates
must pass; loading this controller catalog alone never enables a deploy.
