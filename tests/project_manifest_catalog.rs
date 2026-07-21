use std::{collections::BTreeSet, fs, path::PathBuf};

use rdashboard::domain::{
    DataClass, MigrationEntrypoint, ProjectManifestV2, WorkflowAdapterIdV1,
    WorkflowHostPreparationAdapterV1, WorkflowNetworkClassV1, WorkflowNodeKindV1,
    WorkflowWorkerPoolV1, WriteFencePolicy,
};

fn catalog_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/project-manifests")
}

fn catalog() -> Vec<(String, ProjectManifestV2)> {
    let root = catalog_root();
    let mut files = fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("read project manifest catalog {}: {error}", root.display()))
        .map(|entry| entry.unwrap_or_else(|error| panic!("read catalog entry: {error}")))
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    files.sort();
    assert!(
        !files.is_empty(),
        "project manifest catalog must not be empty"
    );

    files
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path)
                .unwrap_or_else(|error| panic!("read manifest {}: {error}", path.display()));
            let manifest: ProjectManifestV2 =
                serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                    panic!("decode strict manifest {}: {error}", path.display())
                });
            manifest
                .validate()
                .unwrap_or_else(|error| panic!("validate manifest {}: {error}", path.display()));
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_else(|| panic!("manifest filename is not UTF-8: {}", path.display()))
                .to_owned();
            assert_eq!(
                stem,
                manifest.project_id.to_string(),
                "manifest filename must equal project_id"
            );
            (stem, manifest)
        })
        .collect()
}

#[test]
fn every_catalog_manifest_is_strict_valid_and_unique() {
    let manifests = catalog();
    let ids = manifests
        .iter()
        .map(|(id, _)| id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ids.len(),
        manifests.len(),
        "catalog project IDs must be unique"
    );
}

#[test]
fn ralert_contract_separates_stateful_templates_from_disposable_images() {
    let (_, manifest) = catalog()
        .into_iter()
        .find(|(id, _)| id == "ralert")
        .unwrap_or_else(|| panic!("ralert manifest is required"));

    assert_eq!(
        manifest.source.remote_url.as_str(),
        "https://github.com/mrDenai/ralert.git"
    );
    assert_eq!(manifest.migration.entrypoint, MigrationEntrypoint::None);
    assert_eq!(
        manifest.migration.write_fence,
        WriteFencePolicy::Unsupported
    );
    assert_eq!(manifest.data_volumes.len(), 2);
    assert_eq!(manifest.data_volumes[0].path.as_str(), "/data/templates");
    assert_eq!(manifest.data_volumes[0].class, DataClass::Stateful);
    assert!(manifest.data_volumes[0].backup_required);
    assert_eq!(manifest.data_volumes[1].path.as_str(), "/data/images");
    assert_eq!(manifest.data_volumes[1].class, DataClass::Derived);
    assert!(!manifest.data_volumes[1].backup_required);

    let endpoints = manifest
        .health_checks
        .iter()
        .map(|check| check.endpoint.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        endpoints,
        BTreeSet::from([
            "http://ralert:8080/health/live",
            "http://ralert:8080/health/ready",
        ])
    );

    let verification = manifest
        .workflow
        .nodes
        .iter()
        .find(|node| node.kind == WorkflowNodeKindV1::Verification)
        .unwrap_or_else(|| panic!("ralert verification node is required"));
    let verification_profile = manifest
        .workflow
        .profile(&verification.profile_id)
        .unwrap_or_else(|| panic!("ralert verification profile is required"));
    assert_eq!(
        verification_profile.adapter_id,
        WorkflowAdapterIdV1::WorkerBareBinCiV1
    );
    assert_eq!(
        verification_profile.worker_pool,
        WorkflowWorkerPoolV1::BuildCompute
    );
    assert_eq!(
        manifest
            .workflow
            .nodes
            .iter()
            .filter(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
            .count(),
        1,
        "preparation is one first-class node, not a shard preamble"
    );
    let preparation = manifest
        .workflow
        .nodes
        .iter()
        .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
        .unwrap_or_else(|| panic!("ralert preparation node is required"));
    let preparation_profile = manifest
        .workflow
        .profile(&preparation.profile_id)
        .unwrap_or_else(|| panic!("ralert preparation profile is required"));
    assert_eq!(
        preparation_profile.worker_pool,
        WorkflowWorkerPoolV1::VpsRequired,
        "the authoritative preparation cannot be owned only by optional compute"
    );
    assert_eq!(
        preparation_profile.network_class,
        WorkflowNetworkClassV1::Offline,
        "source-tree preparation has no dependency-network authority"
    );
    let host_preparation = manifest
        .host_preparation
        .as_ref()
        .unwrap_or_else(|| panic!("ralert host-preparation policy is required"));
    assert_eq!(
        host_preparation.adapter_id,
        WorkflowHostPreparationAdapterV1::SourceTreeV1
    );
    assert_eq!(host_preparation.platform, "linux-x86_64");
}

#[test]
fn source_tree_host_preparation_rejects_dependency_network_authority() {
    let (_, mut manifest) = catalog()
        .into_iter()
        .find(|(id, _)| id == "ralert")
        .unwrap_or_else(|| panic!("ralert manifest is required"));
    let preparation_profile_id = manifest
        .workflow
        .nodes
        .iter()
        .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
        .unwrap_or_else(|| panic!("ralert preparation node is required"))
        .profile_id
        .clone();
    manifest
        .workflow
        .execution_profiles
        .iter_mut()
        .find(|profile| profile.profile_id == preparation_profile_id)
        .unwrap_or_else(|| panic!("ralert preparation profile is required"))
        .network_class = WorkflowNetworkClassV1::DependencyEgress;

    assert!(
        manifest.validate().is_err(),
        "an offline source-only adapter must not inherit dependency egress"
    );
}
