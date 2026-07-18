# Project manifest catalog

This directory stores reviewed `ProjectManifestV1` deployment contracts. `tests/project_manifest_catalog.rs` discovers every JSON file, deserializes it through the strict Rust domain type, runs semantic validation, rejects duplicate IDs, and binds each filename to its project ID.

A catalog entry describes source, verification, image build, health, data, migration and rollback policy. It is not an installed signed policy bundle and does not grant the executor mutation authority. Runtime activation remains subject to the separately installed, signed, project-specific privilege boundary.

The `ralert.json` entry is mirrored in the ralert repository at `deploy/rdashboard/project-manifest.json` so the deploy contract travels with the application. Changes must update both copies and pass both repositories' gates.
