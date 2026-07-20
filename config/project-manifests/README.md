# Project manifest catalog

This directory stores reviewed `ProjectManifestV2` workflow contracts. `tests/project_manifest_catalog.rs` discovers every JSON file, deserializes it through the strict Rust domain type, runs semantic validation, rejects duplicate IDs, and binds each filename to its project ID. The generated V1 schema remains available only for compatibility with already signed policy bundles.

A catalog entry describes source, a finite typed workflow DAG, fixed adapter and worker classes, resource/network/cache envelopes, verification, release build, health, data, migration and rollback policy. It cannot select a shell command, host path, secret or project-specific worker service. It is not an installed signed mutation policy and does not grant executor authority. Runtime activation remains subject to the separately installed, signed, project-specific privilege boundary.

The `ralert.json` entry is the first V2 catalog migration and remains inactive. Before activation, its reviewed source-side mirror must be upgraded and both repositories' bare gates must pass; loading this controller catalog alone never enables a deploy.
