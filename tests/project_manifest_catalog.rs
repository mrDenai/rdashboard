use std::{collections::BTreeSet, fs, path::PathBuf};

use rdashboard::domain::{
    BuildKind, DataClass, MigrationEntrypoint, ProjectManifestV2, WorkflowAdapterIdV1,
    WorkflowDeliveryModeV1, WorkflowHostPreparationAdapterV1, WorkflowNetworkClassV1,
    WorkflowNodeKindV1, WorkflowWorkerPoolV1, WriteFencePolicy,
};

fn catalog_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/project-manifests")
}

#[test]
fn rdashboard_contract_ends_at_the_signed_self_update_handoff() {
    let (_, manifest) = catalog()
        .into_iter()
        .find(|(id, _)| id == "rdashboard")
        .unwrap_or_else(|| panic!("rdashboard manifest is required"));

    assert_eq!(
        manifest.source.remote_url.as_str(),
        "https://github.com/mrDenai/rdashboard.git"
    );
    assert_eq!(manifest.build.kind, BuildKind::Native);
    assert_eq!(
        manifest.workflow.delivery_mode,
        WorkflowDeliveryModeV1::SelfUpdateHandoff
    );
    assert!(manifest.data_volumes.is_empty());
    assert_eq!(manifest.migration.entrypoint, MigrationEntrypoint::None);
    assert_eq!(manifest.workflow.nodes.len(), 5);
    assert!(manifest.workflow.nodes.iter().all(|node| {
        manifest
            .workflow
            .profile(&node.profile_id)
            .is_some_and(|profile| profile.worker_pool != WorkflowWorkerPoolV1::PrivilegedExecutor)
    }));

    let preparation = manifest
        .workflow
        .nodes
        .iter()
        .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
        .unwrap_or_else(|| panic!("rdashboard preparation node is required"));
    let preparation_profile = manifest
        .workflow
        .profile(&preparation.profile_id)
        .unwrap_or_else(|| panic!("rdashboard preparation profile is required"));
    assert_eq!(
        preparation_profile.network_class,
        WorkflowNetworkClassV1::DependencyEgress
    );
    assert_eq!(
        manifest
            .host_preparation
            .as_ref()
            .unwrap_or_else(|| panic!("rdashboard host preparation policy is required"))
            .adapter_id,
        WorkflowHostPreparationAdapterV1::CargoCratesIoV1
    );

    let release = manifest
        .workflow
        .nodes
        .iter()
        .find(|node| node.kind == WorkflowNodeKindV1::ReleaseBuild)
        .unwrap_or_else(|| panic!("rdashboard release node is required"));
    assert!(
        release
            .depends_on
            .iter()
            .any(|node| node.as_str() == "verify")
    );
    assert_eq!(
        manifest
            .workflow
            .profile(&release.profile_id)
            .unwrap_or_else(|| panic!("rdashboard release profile is required"))
            .adapter_id,
        WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1
    );

    let mut wrong_project = manifest.clone();
    wrong_project.project_id = "rdashboard-copy"
        .parse()
        .unwrap_or_else(|error| panic!("project fixture: {error}"));
    assert!(wrong_project.validate().is_err());

    let mut executor_mode = manifest;
    executor_mode.workflow.delivery_mode = WorkflowDeliveryModeV1::ExecutorMutation;
    assert!(executor_mode.validate().is_err());
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
fn rimg_contract_records_native_build_state_and_fenced_migration_without_activation() {
    let (_, manifest) = catalog()
        .into_iter()
        .find(|(id, _)| id == "rimg")
        .unwrap_or_else(|| panic!("rimg manifest is required"));

    assert_eq!(
        manifest.source.remote_url.as_str(),
        "ssh://git@github.com/mrDenai/rimg.git"
    );
    assert_eq!(manifest.build.kind, BuildKind::Oci);
    assert_eq!(
        manifest
            .build
            .dockerfile
            .as_ref()
            .unwrap_or_else(|| panic!("rimg Dockerfile is required"))
            .as_str(),
        "Dockerfile.runtime"
    );
    assert_rimg_verified_output(&manifest);
    assert_eq!(manifest.data_volumes.len(), 3);
    assert_eq!(manifest.data_volumes[0].path.as_str(), "/app/data");
    assert_eq!(manifest.data_volumes[0].class, DataClass::Stateful);
    assert!(manifest.data_volumes[0].backup_required);
    assert_eq!(manifest.data_volumes[1].path.as_str(), "/app/masters");
    assert_eq!(manifest.data_volumes[1].class, DataClass::Stateful);
    assert!(manifest.data_volumes[1].backup_required);
    assert_eq!(manifest.data_volumes[2].path.as_str(), "/app/uploads");
    assert_eq!(manifest.data_volumes[2].class, DataClass::Derived);
    assert!(!manifest.data_volumes[2].backup_required);
    assert_eq!(
        manifest.migration.entrypoint,
        MigrationEntrypoint::ApplicationMigrate
    );
    assert_eq!(
        manifest.migration.write_fence,
        WriteFencePolicy::ApplicationProtocolV1
    );

    let endpoints = manifest
        .health_checks
        .iter()
        .map(|check| (check.endpoint.as_str(), check.expected_status))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        endpoints,
        BTreeSet::from([
            ("http://rimg:8080/health/live", 204),
            ("http://rimg:8080/health/ready", 204),
        ])
    );

    let migration = manifest
        .workflow
        .nodes
        .iter()
        .find(|node| node.kind == WorkflowNodeKindV1::Migration)
        .unwrap_or_else(|| panic!("rimg migration node is required"));
    assert_eq!(
        manifest
            .workflow
            .profile(&migration.profile_id)
            .unwrap_or_else(|| panic!("rimg migration profile is required"))
            .adapter_id,
        WorkflowAdapterIdV1::ExecutorMigrationV1
    );
    let candidate = manifest
        .workflow
        .nodes
        .iter()
        .find(|node| node.kind == WorkflowNodeKindV1::CandidateHealth)
        .unwrap_or_else(|| panic!("rimg candidate-health node is required"));
    assert_eq!(
        candidate
            .depends_on
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["migration"]
    );

    assert_rimg_host_preparation(&manifest);
}

fn assert_rimg_host_preparation(manifest: &ProjectManifestV2) {
    let preparation = manifest
        .workflow
        .nodes
        .iter()
        .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
        .unwrap_or_else(|| panic!("rimg preparation node is required"));
    assert_eq!(
        manifest
            .workflow
            .profile(&preparation.profile_id)
            .unwrap_or_else(|| panic!("rimg preparation profile is required"))
            .network_class,
        WorkflowNetworkClassV1::DependencyEgress
    );
    let host_preparation = manifest
        .host_preparation
        .as_ref()
        .unwrap_or_else(|| panic!("rimg host preparation is required"));
    assert_eq!(
        host_preparation.adapter_id,
        WorkflowHostPreparationAdapterV1::CargoCratesIoV1
    );
    assert_eq!(host_preparation.oci_bases.len(), 1);
    let base = &host_preparation.oci_bases[0];
    assert_eq!(
        base.source,
        "docker.io/library/debian:trixie-slim@sha256:9bb8a3626890e084ab54e888fdd7c4b6d2f119071cd4c5dc5fecb4d73062aa5f"
    );
    assert_eq!(base.layout_name, "debian-trixie");
    assert_eq!(
        base.manifest_digest.as_str(),
        "sha256:9bb8a3626890e084ab54e888fdd7c4b6d2f119071cd4c5dc5fecb4d73062aa5f"
    );
}

fn assert_rimg_verified_output(manifest: &ProjectManifestV2) {
    let verified_output = manifest
        .build
        .verified_output
        .as_ref()
        .unwrap_or_else(|| panic!("rimg verified OCI output is required"));
    assert_eq!(verified_output.context_name, "verified-release");
    assert_eq!(verified_output.directory.as_str(), "release");
    assert_eq!(verified_output.max_files, 1);
    let release = manifest
        .workflow
        .nodes
        .iter()
        .find(|node| node.kind == WorkflowNodeKindV1::ReleaseBuild)
        .unwrap_or_else(|| panic!("rimg release node is required"));
    assert!(
        release
            .depends_on
            .iter()
            .any(|node| node.as_str() == "verify")
    );
}

#[test]
fn telegram_gateway_contract_preserves_state_and_uses_the_generic_worker() {
    let (_, manifest) = catalog()
        .into_iter()
        .find(|(id, _)| id == "telegram-gateway")
        .unwrap_or_else(|| panic!("telegram-gateway manifest is required"));

    assert_eq!(
        manifest.source.remote_url.as_str(),
        "ssh://git@github.com/mrDenai/telegram-gateway.git"
    );
    assert_eq!(manifest.build.kind, BuildKind::Oci);
    assert_eq!(manifest.data_volumes.len(), 1);
    assert_eq!(manifest.data_volumes[0].path.as_str(), "/data");
    assert_eq!(manifest.data_volumes[0].class, DataClass::Stateful);
    assert!(manifest.data_volumes[0].backup_required);
    assert_eq!(manifest.migration.entrypoint, MigrationEntrypoint::None);
    assert_eq!(
        manifest.migration.write_fence,
        WriteFencePolicy::Unsupported
    );
    assert_eq!(manifest.health_checks.len(), 1);
    assert_eq!(
        manifest.health_checks[0].endpoint.as_str(),
        "http://telegram-gateway:8081/health"
    );

    let preparation = manifest
        .workflow
        .nodes
        .iter()
        .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
        .unwrap_or_else(|| panic!("gateway preparation node is required"));
    let preparation_profile = manifest
        .workflow
        .profile(&preparation.profile_id)
        .unwrap_or_else(|| panic!("gateway preparation profile is required"));
    assert_eq!(
        preparation_profile.worker_pool,
        WorkflowWorkerPoolV1::VpsRequired
    );
    assert_eq!(
        preparation_profile.network_class,
        WorkflowNetworkClassV1::DependencyEgress
    );
    assert_eq!(
        manifest
            .host_preparation
            .as_ref()
            .unwrap_or_else(|| panic!("gateway host preparation is required"))
            .adapter_id,
        WorkflowHostPreparationAdapterV1::CargoCratesIoV1
    );
    assert_eq!(
        manifest
            .workflow
            .nodes
            .iter()
            .filter(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
            .count(),
        1
    );
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
