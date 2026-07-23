use std::{collections::BTreeSet, str::FromStr};

use rdashboard::{
    domain::{
        AbsolutePolicyPath, BuildKind, EvidenceDigest, GitCommitId, HttpEndpoint, ManifestError,
        ProjectId, ProjectManifestV2, RemoteUrl, WorkflowAdapterIdV1, WorkflowArtifactKindV1,
        WorkflowCleanupReceiptV1, WorkflowCleanupResultV1, WorkflowNodeKindV1,
        WorkflowNodeOutcomeV1, WorkflowNodeReceiptV1, WorkflowWorkerPoolV1,
    },
    installed_workflow::InstalledWorkflowCatalogV1,
    scheduler::{
        DurableWorkflowScheduler, WorkflowAdmissionV1, WorkflowAttemptStateV1,
        WorkflowCleanupReasonV1, WorkflowCleanupStateV1, WorkflowExecutionModeV1,
        WorkflowJournalReaderV1, WorkflowMutationStateV1, WorkflowNodeStateV1,
        WorkflowTriggerChannelV1, WorkflowWorkerRegistrationV1,
    },
    store::{ControlStore, StoreError},
};
use tempfile::tempdir;

fn digest(label: impl AsRef<[u8]>) -> EvidenceDigest {
    EvidenceDigest::sha256(label)
}

fn manifest(project: &str, fairness_weight: u16) -> ProjectManifestV2 {
    let mut manifest: ProjectManifestV2 =
        serde_json::from_str(include_str!("../config/project-manifests/ralert.json"))
            .unwrap_or_else(|error| panic!("decode base workflow manifest: {error}"));
    manifest.project_id =
        ProjectId::from_str(project).unwrap_or_else(|error| panic!("project ID fixture: {error}"));
    manifest.display_name = format!("{project} workflow fixture");
    manifest.source.remote_url =
        RemoteUrl::from_str(&format!("https://github.com/example/{project}.git"))
            .unwrap_or_else(|error| panic!("remote fixture: {error}"));
    for check in &mut manifest.health_checks {
        check.endpoint =
            HttpEndpoint::from_str(&format!("http://{project}:8080/health/{}", check.name))
                .unwrap_or_else(|error| panic!("health fixture: {error}"));
    }
    manifest.data_volumes[0].path =
        AbsolutePolicyPath::from_str(&format!("/var/lib/{project}/templates"))
            .unwrap_or_else(|error| panic!("data path fixture: {error}"));
    manifest.data_volumes[1].path =
        AbsolutePolicyPath::from_str(&format!("/var/lib/{project}/images"))
            .unwrap_or_else(|error| panic!("data path fixture: {error}"));
    manifest.workflow.fairness_weight = fairness_weight;
    manifest
        .validate()
        .unwrap_or_else(|error| panic!("workflow fixture: {error}"));
    manifest
}

fn native_manifest(project: &str) -> ProjectManifestV2 {
    let mut manifest = manifest(project, 1);
    manifest.build.kind = BuildKind::Native;
    manifest.build.dockerfile = None;
    let release = manifest
        .workflow
        .nodes
        .iter_mut()
        .find(|node| node.kind == WorkflowNodeKindV1::ReleaseBuild)
        .unwrap_or_else(|| panic!("release node"));
    let release_profile_id = release.profile_id.clone();
    release.depends_on = vec![
        "prepare"
            .parse()
            .unwrap_or_else(|error| panic!("prepare node: {error}")),
        "verify"
            .parse()
            .unwrap_or_else(|error| panic!("verification node: {error}")),
    ];
    release.input_contracts = vec![
        WorkflowArtifactKindV1::PreparedRun,
        WorkflowArtifactKindV1::VerificationReceipt,
    ];
    manifest
        .workflow
        .execution_profiles
        .iter_mut()
        .find(|profile| profile.profile_id == release_profile_id)
        .unwrap_or_else(|| panic!("release profile"))
        .adapter_id = WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1;
    manifest
        .validate()
        .unwrap_or_else(|error| panic!("native workflow fixture: {error}"));
    manifest
}

fn self_update_manifest() -> ProjectManifestV2 {
    let manifest: ProjectManifestV2 =
        serde_json::from_str(include_str!("../config/project-manifests/rdashboard.json"))
            .unwrap_or_else(|error| panic!("decode self-update manifest: {error}"));
    manifest
        .validate()
        .unwrap_or_else(|error| panic!("self-update workflow fixture: {error}"));
    manifest
}

fn rimg_manifest() -> ProjectManifestV2 {
    let manifest: ProjectManifestV2 =
        serde_json::from_str(include_str!("../config/project-manifests/rimg.json"))
            .unwrap_or_else(|error| panic!("decode rimg manifest: {error}"));
    manifest
        .validate()
        .unwrap_or_else(|error| panic!("rimg workflow fixture: {error}"));
    manifest
}

fn admission(
    manifest: &ProjectManifestV2,
    sha_byte: char,
    sequence: u64,
    channel: WorkflowTriggerChannelV1,
    delivery_id: &str,
) -> WorkflowAdmissionV1 {
    WorkflowAdmissionV1 {
        project_id: manifest.project_id.clone(),
        workflow_policy_digest: manifest
            .workflow_policy_digest()
            .unwrap_or_else(|error| panic!("policy digest: {error}")),
        source_sha: GitCommitId::from_str(&sha_byte.to_string().repeat(40))
            .unwrap_or_else(|error| panic!("source SHA fixture: {error}")),
        execution_mode: WorkflowExecutionModeV1::Deploy,
        source_sequence: sequence,
        source_attestation_digest: digest(format!("attestation-{delivery_id}")),
        trigger_channel: channel,
        delivery_id: delivery_id.to_owned(),
        payload_digest: digest(format!("payload-{delivery_id}")),
        priority: 2,
    }
}

fn build_worker() -> WorkflowWorkerRegistrationV1 {
    WorkflowWorkerRegistrationV1 {
        worker_id: "vps-build-1".to_owned(),
        host_id: "vps-1".to_owned(),
        pools: BTreeSet::from([
            WorkflowWorkerPoolV1::BuildCompute,
            WorkflowWorkerPoolV1::VpsRequired,
        ]),
    }
}

fn accelerator_worker() -> WorkflowWorkerRegistrationV1 {
    WorkflowWorkerRegistrationV1 {
        worker_id: "i9-optional-1".to_owned(),
        host_id: "i9-1".to_owned(),
        pools: BTreeSet::from([WorkflowWorkerPoolV1::BuildCompute]),
    }
}

fn executor_worker() -> WorkflowWorkerRegistrationV1 {
    WorkflowWorkerRegistrationV1 {
        worker_id: "executor-1".to_owned(),
        host_id: "vps-1".to_owned(),
        pools: BTreeSet::from([WorkflowWorkerPoolV1::PrivilegedExecutor]),
    }
}

fn success_receipt(
    lease: &rdashboard::domain::WorkflowLeaseV1,
    label: &str,
) -> WorkflowNodeReceiptV1 {
    WorkflowNodeReceiptV1::new(
        lease,
        WorkflowNodeOutcomeV1::Succeeded,
        Some(digest(format!("output-{label}"))),
        digest(format!("execution-{label}")),
        digest(format!("cleanup-{label}")),
        WorkflowCleanupResultV1::Complete,
        lease.leased_at_ms + 10,
    )
    .unwrap_or_else(|error| panic!("success receipt: {error}"))
}

fn claim(
    scheduler: &DurableWorkflowScheduler,
    worker: &WorkflowWorkerRegistrationV1,
    now_ms: i64,
) -> rdashboard::domain::WorkflowLeaseV1 {
    scheduler
        .claim_next(worker, now_ms, 1_000)
        .unwrap_or_else(|error| panic!("claim workflow node: {error}"))
        .unwrap_or_else(|| panic!("expected a workflow lease"))
}

fn commit_success(
    scheduler: &DurableWorkflowScheduler,
    lease: &rdashboard::domain::WorkflowLeaseV1,
    label: &str,
) -> WorkflowNodeReceiptV1 {
    let receipt = success_receipt(lease, label);
    scheduler
        .commit_node_receipt(&receipt, lease.leased_at_ms + 11)
        .unwrap_or_else(|error| panic!("commit workflow receipt: {error}"));
    receipt
}

fn complete_reduction(
    scheduler: &DurableWorkflowScheduler,
    start_ms: i64,
) -> (uuid::Uuid, rdashboard::domain::WorkflowReductionReceiptV1) {
    let worker = build_worker();
    let prepare = claim(scheduler, &worker, start_ms);
    assert_eq!(prepare.node_kind, WorkflowNodeKindV1::HostPrepare);
    commit_success(scheduler, &prepare, "prepare");

    let mut completed = BTreeSet::new();
    for (offset, label) in [(20, "first"), (40, "second")] {
        let lease = claim(scheduler, &worker, start_ms + offset);
        assert!(completed.insert(lease.node_kind));
        commit_success(scheduler, &lease, label);
    }
    assert_eq!(
        completed,
        BTreeSet::from([
            WorkflowNodeKindV1::Verification,
            WorkflowNodeKindV1::ReleaseBuild,
        ])
    );

    let reduction = scheduler
        .reduce_attempt(prepare.attempt_id, start_ms + 60)
        .unwrap_or_else(|error| panic!("reduce required evidence: {error}"));
    (prepare.attempt_id, reduction)
}

fn complete_executor_path_to_observation(
    scheduler: &DurableWorkflowScheduler,
    start_ms: i64,
) -> rdashboard::domain::WorkflowLeaseV1 {
    let expected = [
        WorkflowNodeKindV1::ResourceReservation,
        WorkflowNodeKindV1::Backup,
        WorkflowNodeKindV1::CandidateHealth,
        WorkflowNodeKindV1::Cutover,
    ];
    for (index, kind) in expected.into_iter().enumerate() {
        let now_ms = start_ms + i64::try_from(index).unwrap_or(0) * 20;
        let lease = claim(scheduler, &executor_worker(), now_ms);
        assert_eq!(lease.node_kind, kind);
        commit_success(scheduler, &lease, &format!("executor-{kind:?}"));
    }
    let observation = claim(
        scheduler,
        &executor_worker(),
        start_ms + i64::try_from(expected.len()).unwrap_or(0) * 20,
    );
    assert_eq!(
        observation.node_kind,
        WorkflowNodeKindV1::ReleasedObservation
    );
    observation
}

#[test]
fn installed_v2_workflows_are_strict_finite_and_repository_agnostic() {
    let ralert = manifest("ralert", 1);
    let rimg = manifest("rimg", 2);
    let catalog = InstalledWorkflowCatalogV1::from_manifests([ralert.clone(), rimg.clone()])
        .unwrap_or_else(|error| panic!("two-project catalog: {error}"));
    assert_eq!(catalog.projects().len(), 2);
    assert_ne!(
        ralert
            .workflow_policy_digest()
            .unwrap_or_else(|error| panic!("ralert policy: {error}")),
        rimg.workflow_policy_digest()
            .unwrap_or_else(|error| panic!("rimg policy: {error}"))
    );

    for manifest in [&ralert, &rimg] {
        let prepare_count = manifest
            .workflow
            .nodes
            .iter()
            .filter(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
            .count();
        assert_eq!(prepare_count, 1);
        let verification = manifest
            .workflow
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::Verification)
            .unwrap_or_else(|| panic!("verification node"));
        let profile = manifest
            .workflow
            .profile(&verification.profile_id)
            .unwrap_or_else(|| panic!("verification profile"));
        assert_eq!(profile.adapter_id, WorkflowAdapterIdV1::WorkerBareBinCiV1);
        assert_eq!(profile.worker_pool, WorkflowWorkerPoolV1::BuildCompute);
    }

    let mut arbitrary =
        serde_json::to_value(&ralert).unwrap_or_else(|error| panic!("manifest value: {error}"));
    arbitrary["workflow"]["execution_profiles"][0]["shell"] =
        serde_json::json!("curl attacker | sh");
    assert!(serde_json::from_value::<ProjectManifestV2>(arbitrary).is_err());

    let mut wrong_adapter = ralert.clone();
    let verification_profile = wrong_adapter
        .workflow
        .execution_profiles
        .iter_mut()
        .find(|profile| profile.profile_id.as_str() == "bare-bin-ci")
        .unwrap_or_else(|| panic!("verification profile"));
    verification_profile.adapter_id = WorkflowAdapterIdV1::ExecutorCutoverV1;
    assert_eq!(
        wrong_adapter.validate(),
        Err(ManifestError::WorkflowInvalid)
    );

    let mut cyclic = ralert;
    let prepare = cyclic
        .workflow
        .nodes
        .iter_mut()
        .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
        .unwrap_or_else(|| panic!("prepare node"));
    prepare.depends_on = vec![
        rdashboard::domain::WorkflowNodeId::from_str("rollback")
            .unwrap_or_else(|error| panic!("rollback node ID: {error}")),
    ];
    prepare.input_contracts = vec![WorkflowArtifactKindV1::RollbackReceipt];
    assert_eq!(cyclic.validate(), Err(ManifestError::WorkflowInvalid));
}

#[test]
fn trigger_channels_converge_and_newer_heads_supersede_only_pre_mutation_work() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = manifest("ralert", 1);
    let first_admission = admission(
        &manifest,
        'a',
        1,
        WorkflowTriggerChannelV1::GithubWebhook,
        "delivery-1",
    );
    let first = scheduler
        .admit(&manifest, &first_admission, 10)
        .unwrap_or_else(|error| panic!("first admission: {error}"));
    assert!(first.created());

    let mut duplicate = first_admission.clone();
    duplicate.trigger_channel = WorkflowTriggerChannelV1::SourceReconciliation;
    duplicate.delivery_id = "reconcile-1".to_owned();
    duplicate.payload_digest = digest("reconcile payload");
    let duplicate = scheduler
        .admit(&manifest, &duplicate, 11)
        .unwrap_or_else(|error| panic!("cross-channel duplicate: {error}"));
    assert!(!duplicate.created());
    assert_eq!(duplicate.attempt().request_id, first.attempt().request_id);

    let mut conflicting_delivery = first_admission.clone();
    conflicting_delivery.payload_digest = digest("conflicting payload");
    assert!(matches!(
        scheduler.admit(&manifest, &conflicting_delivery, 12),
        Err(StoreError::WorkflowDeliveryConflict)
    ));

    let newer = admission(
        &manifest,
        'b',
        2,
        WorkflowTriggerChannelV1::DirectPush,
        "direct-2",
    );
    let newer = scheduler
        .admit(&manifest, &newer, 20)
        .unwrap_or_else(|error| panic!("newer head: {error}"));
    assert!(newer.created());
    let superseded = scheduler
        .attempt(first.attempt().attempt_id)
        .unwrap_or_else(|error| panic!("load superseded attempt: {error}"))
        .unwrap_or_else(|| panic!("superseded attempt exists"));
    assert_eq!(superseded.state, WorkflowAttemptStateV1::Superseded);

    let mut stale = first_admission;
    stale.delivery_id = "late-old-head".to_owned();
    stale.payload_digest = digest("late old head");
    assert!(matches!(
        scheduler.admit(&manifest, &stale, 21),
        Err(StoreError::WorkflowStaleSource)
    ));
}

#[test]
fn fair_queue_and_lease_generation_survive_reopen() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("control.sqlite");
    let store =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store.clone());
    let ralert = manifest("ralert", 1);
    let rimg = manifest("rimg", 1);
    scheduler
        .admit(
            &ralert,
            &admission(
                &ralert,
                'a',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "ralert-1",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit ralert: {error}"));
    scheduler
        .admit(
            &rimg,
            &admission(
                &rimg,
                'b',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "rimg-1",
            ),
            2,
        )
        .unwrap_or_else(|error| panic!("admit rimg: {error}"));

    let first = claim(&scheduler, &build_worker(), 10);
    assert_eq!(first.project_id.as_str(), "ralert");
    assert_eq!(first.lease_generation, 1);
    let first_source = first
        .required_source_identity()
        .unwrap_or_else(|error| panic!("exact first source identity: {error}"));
    assert_eq!(first_source.sequence, 1);
    assert_eq!(
        first_source.attestation_digest,
        digest("attestation-ralert-1")
    );
    let [first_input] = first
        .required_input_artifacts()
        .unwrap_or_else(|error| panic!("exact first input artifacts: {error}"))
    else {
        panic!("host preparation must bind exactly one source input");
    };
    assert_eq!(first_input.node_id.as_str(), "source");
    assert_eq!(
        first_input.artifact_kind,
        WorkflowArtifactKindV1::SourceSnapshot
    );
    assert_eq!(first_input.output_digest, first_source.attestation_digest);
    drop(scheduler);
    drop(store);

    let reopened_store =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("reopen control store: {error}"));
    let reopened = DurableWorkflowScheduler::new(reopened_store);
    let second = claim(&reopened, &build_worker(), 20);
    assert_eq!(second.project_id.as_str(), "rimg");
    let second_source = second
        .required_source_identity()
        .unwrap_or_else(|error| panic!("exact second source identity: {error}"));
    assert_eq!(second_source.sequence, 1);
    assert_eq!(
        second_source.attestation_digest,
        digest("attestation-rimg-1")
    );

    assert_eq!(
        reopened
            .expire_leases(first.expires_at_ms)
            .unwrap_or_else(|error| panic!("expire first lease: {error}")),
        1
    );
    assert!(
        reopened
            .claim_next(&build_worker(), first.expires_at_ms + 1, 1_000)
            .unwrap_or_else(|error| panic!("block lease before cleanup: {error}"))
            .is_none()
    );
    let cleanup = WorkflowCleanupReceiptV1::new(
        &first,
        None,
        digest("reopened-expired-cleanup"),
        first.expires_at_ms + 1,
    )
    .unwrap_or_else(|error| panic!("cleanup receipt: {error}"));
    reopened
        .commit_cleanup_receipt(&cleanup, first.expires_at_ms + 2)
        .unwrap_or_else(|error| panic!("commit cleanup after reopen: {error}"));
    let replayed = claim(&reopened, &build_worker(), first.expires_at_ms + 3);
    assert_eq!(replayed.project_id.as_str(), "ralert");
    assert_eq!(replayed.node_id, first.node_id);
    assert_eq!(replayed.lease_generation, 2);
    assert_eq!(replayed.source_identity, first.source_identity);
    assert_eq!(replayed.input_artifacts, first.input_artifacts);
}

#[test]
fn liveness_expiry_retries_but_the_execution_deadline_is_terminal() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = manifest("ralert", 1);
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '9',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "ralert-expiry-boundary",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));
    let worker = build_worker();

    let short = claim(&scheduler, &worker, 10);
    let execution_timeout_ms = i64::try_from(short.timeout_ms)
        .unwrap_or_else(|error| panic!("execution timeout: {error}"));
    assert!(short.expires_at_ms < short.leased_at_ms + execution_timeout_ms);
    scheduler
        .expire_leases(short.expires_at_ms)
        .unwrap_or_else(|error| panic!("expire liveness lease: {error}"));
    let short_cleanup = WorkflowCleanupReceiptV1::new(
        &short,
        None,
        digest("short-lease-cleanup"),
        short.expires_at_ms + 1,
    )
    .unwrap_or_else(|error| panic!("short cleanup receipt: {error}"));
    scheduler
        .commit_cleanup_receipt(&short_cleanup, short.expires_at_ms + 2)
        .unwrap_or_else(|error| panic!("commit short cleanup: {error}"));

    let deadline = scheduler
        .claim_next(&worker, short.expires_at_ms + 3, 900_000)
        .unwrap_or_else(|error| panic!("claim deadline lease: {error}"))
        .unwrap_or_else(|| panic!("expected a retried workflow lease"));
    assert_eq!(deadline.node_id, short.node_id);
    assert_eq!(deadline.lease_generation, short.lease_generation + 1);
    assert_eq!(
        deadline.expires_at_ms,
        deadline.leased_at_ms
            + i64::try_from(deadline.timeout_ms)
                .unwrap_or_else(|error| panic!("deadline timeout: {error}"))
    );
    scheduler
        .expire_leases(deadline.expires_at_ms)
        .unwrap_or_else(|error| panic!("expire execution deadline: {error}"));

    let failed = scheduler
        .attempt(deadline.attempt_id)
        .unwrap_or_else(|error| panic!("load failed attempt: {error}"))
        .unwrap_or_else(|| panic!("failed attempt exists"));
    assert_eq!(failed.state, WorkflowAttemptStateV1::Failed);
    assert_eq!(failed.cleanup_state, WorkflowCleanupStateV1::Pending);
    assert_eq!(failed.mutation_state, WorkflowMutationStateV1::NotStarted);
    assert_eq!(
        failed
            .nodes
            .iter()
            .find(|node| node.node_id == deadline.node_id)
            .unwrap_or_else(|| panic!("expired node"))
            .state,
        WorkflowNodeStateV1::Failed
    );
    assert!(
        scheduler
            .claim_next(&worker, deadline.expires_at_ms + 1, 900_000)
            .unwrap_or_else(|error| panic!("claim after terminal deadline: {error}"))
            .is_none()
    );

    let deadline_cleanup = WorkflowCleanupReceiptV1::new(
        &deadline,
        None,
        digest("deadline-cleanup"),
        deadline.expires_at_ms + 1,
    )
    .unwrap_or_else(|error| panic!("deadline cleanup receipt: {error}"));
    let cleaned = scheduler
        .commit_cleanup_receipt(&deadline_cleanup, deadline.expires_at_ms + 2)
        .unwrap_or_else(|error| panic!("commit deadline cleanup: {error}"));
    assert_eq!(cleaned.state, WorkflowAttemptStateV1::Failed);
    assert_eq!(cleaned.cleanup_state, WorkflowCleanupStateV1::Complete);
    assert!(
        scheduler
            .claim_next(&worker, deadline.expires_at_ms + 3, 900_000)
            .unwrap_or_else(|error| panic!("claim after deadline cleanup: {error}"))
            .is_none()
    );
}

#[test]
fn optional_accelerator_can_verify_but_cannot_own_required_preparation_or_release() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = manifest("rimg", 1);
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                'c',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "rimg-accelerator",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));
    assert!(
        scheduler
            .claim_next(&accelerator_worker(), 10, 1_000)
            .unwrap_or_else(|error| panic!("accelerator pre-prepare claim: {error}"))
            .is_none(),
        "optional compute cannot own the authoritative prepared run"
    );
    let prepare = claim(&scheduler, &build_worker(), 11);
    assert_eq!(prepare.node_kind, WorkflowNodeKindV1::HostPrepare);
    assert_eq!(prepare.worker_pool, WorkflowWorkerPoolV1::VpsRequired);
    assert!(prepare.resources.is_some());
    assert_eq!(prepare.host_preparation, manifest.host_preparation);
    commit_success(&scheduler, &prepare, "vps-prepare");

    let verification = claim(&scheduler, &accelerator_worker(), 30);
    assert_eq!(verification.node_kind, WorkflowNodeKindV1::Verification);
    let accelerator_state = verification
        .operation_state
        .as_ref()
        .unwrap_or_else(|| panic!("accelerator verification has host-local state"));
    assert_eq!(
        accelerator_state.consumer_nodes,
        vec![verification.node_id.clone()]
    );
    assert!(
        scheduler
            .claim_next(&accelerator_worker(), 40, 1_000)
            .unwrap_or_else(|error| panic!("accelerator second claim: {error}"))
            .is_none(),
        "VPS-required release build must not be leased to intermittent i9 capacity"
    );
    let release = claim(&scheduler, &build_worker(), 41);
    assert_eq!(release.node_kind, WorkflowNodeKindV1::ReleaseBuild);
    assert!(
        release.operation_state.is_none(),
        "OCI output is isolated by its result store and must not allocate compiled state"
    );
    assert_ne!(release.host_id, verification.host_id);
}

#[test]
fn native_release_keeps_verification_and_packaging_on_the_same_required_host() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = native_manifest("rdashboard");
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                'e',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "rdashboard-native-release",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));
    let worker = build_worker();
    let prepare = claim(&scheduler, &worker, 10);
    assert_eq!(prepare.node_kind, WorkflowNodeKindV1::HostPrepare);
    commit_success(&scheduler, &prepare, "native-prepare");

    assert!(
        scheduler
            .claim_next(&accelerator_worker(), 30, 1_000)
            .unwrap_or_else(|error| panic!("optional accelerator claim: {error}"))
            .is_none(),
        "native verification cannot strand compiled outputs on an intermittent host"
    );
    let verification = claim(&scheduler, &worker, 31);
    assert_eq!(verification.node_kind, WorkflowNodeKindV1::Verification);
    let state = verification
        .operation_state
        .as_ref()
        .unwrap_or_else(|| panic!("shared native operation state"));
    assert_eq!(
        state.consumer_nodes,
        vec![
            "release-build"
                .parse()
                .unwrap_or_else(|error| panic!("release node: {error}")),
            verification.node_id.clone(),
        ]
    );
    assert!(
        scheduler
            .claim_next(&worker, 32, 1_000)
            .unwrap_or_else(|error| panic!("premature release claim: {error}"))
            .is_none(),
        "native packaging must wait for the exact verification receipt"
    );
    commit_success(&scheduler, &verification, "native-verification");
    let release = claim(&scheduler, &worker, 50);
    assert_eq!(release.node_kind, WorkflowNodeKindV1::ReleaseBuild);
    assert_eq!(release.host_id, verification.host_id);
    assert_eq!(
        release
            .operation_state
            .as_ref()
            .unwrap_or_else(|| panic!("release operation state"))
            .state_key,
        state.state_key
    );
    assert_eq!(
        release
            .input_artifacts
            .iter()
            .map(|input| input.artifact_kind)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            WorkflowArtifactKindV1::PreparedRun,
            WorkflowArtifactKindV1::VerificationReceipt,
        ])
    );
}

#[test]
fn verified_oci_reuses_the_exact_gate_output_on_the_same_vps() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = rimg_manifest();
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '7',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "rimg-vps-state",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));
    let worker = build_worker();
    let prepare = claim(&scheduler, &worker, 10);
    commit_success(&scheduler, &prepare, "prepare-state");

    let verification = claim(&scheduler, &worker, 30);
    assert_eq!(verification.node_kind, WorkflowNodeKindV1::Verification);
    let verification_state = verification
        .operation_state
        .as_ref()
        .unwrap_or_else(|| panic!("verification compiled state"));
    assert_eq!(verification_state.max_bytes, 4 * 1024 * 1024 * 1024);
    assert_eq!(
        verification_state.consumer_nodes,
        vec![
            "release-build"
                .parse()
                .unwrap_or_else(|error| panic!("release node: {error}")),
            verification.node_id.clone(),
        ]
    );
    assert!(
        scheduler
            .claim_next(&worker, 31, 1_000)
            .unwrap_or_else(|error| panic!("premature release claim: {error}"))
            .is_none(),
        "OCI packaging must wait for the exact verification receipt"
    );
    commit_success(&scheduler, &verification, "verified-rimg");
    let release = claim(&scheduler, &worker, 50);
    assert_eq!(release.node_kind, WorkflowNodeKindV1::ReleaseBuild);
    assert_eq!(release.host_id, verification.host_id);
    assert_eq!(
        release
            .operation_state
            .as_ref()
            .unwrap_or_else(|| panic!("release operation state"))
            .state_key,
        verification_state.state_key
    );
    assert_eq!(
        release
            .input_artifacts
            .iter()
            .map(|input| input.artifact_kind)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            WorkflowArtifactKindV1::PreparedRun,
            WorkflowArtifactKindV1::VerificationReceipt,
        ])
    );
}

#[test]
fn vps_operation_binding_survives_expiry_and_cannot_migrate_to_accelerator() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = manifest("rimg", 1);
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '8',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "rimg-vps-state-expiry",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));
    let worker = build_worker();
    let prepare = claim(&scheduler, &worker, 10);
    commit_success(&scheduler, &prepare, "prepare-expiry-state");

    let first = claim(&scheduler, &worker, 30);
    let expired = if first.node_kind == WorkflowNodeKindV1::Verification {
        first
    } else {
        assert_eq!(first.node_kind, WorkflowNodeKindV1::ReleaseBuild);
        assert!(first.operation_state.is_none());
        commit_success(&scheduler, &first, "release-before-expiry-state");
        claim(&scheduler, &worker, 50)
    };
    assert_eq!(expired.node_kind, WorkflowNodeKindV1::Verification);
    let state_key = expired
        .operation_state
        .as_ref()
        .unwrap_or_else(|| panic!("compiled state"))
        .state_key
        .clone();
    assert_eq!(
        scheduler
            .expire_leases(expired.expires_at_ms)
            .unwrap_or_else(|error| panic!("expire compiled lease: {error}")),
        1
    );
    let cleanup = WorkflowCleanupReceiptV1::new(
        &expired,
        None,
        digest("compiled-expiry-cleanup"),
        expired.expires_at_ms + 1,
    )
    .unwrap_or_else(|error| panic!("cleanup receipt: {error}"));
    scheduler
        .commit_cleanup_receipt(&cleanup, cleanup.completed_at_ms + 1)
        .unwrap_or_else(|error| panic!("commit cleanup: {error}"));

    assert!(
        scheduler
            .claim_next(&accelerator_worker(), expired.expires_at_ms + 3, 1_000)
            .unwrap_or_else(|error| panic!("accelerator retry claim: {error}"))
            .is_none(),
        "an existing VPS state must never split across an intermittent host"
    );
    let retry = claim(&scheduler, &worker, expired.expires_at_ms + 4);
    assert_eq!(retry.node_id, expired.node_id);
    assert_eq!(retry.lease_generation, expired.lease_generation + 1);
    assert_eq!(
        retry
            .operation_state
            .as_ref()
            .unwrap_or_else(|| panic!("retry state"))
            .state_key,
        state_key
    );
}

#[test]
fn reducer_binds_the_complete_required_set_and_receipts_are_idempotent() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let first_manifest = manifest("ralert", 1);
    scheduler
        .admit(
            &first_manifest,
            &admission(
                &first_manifest,
                'd',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "reduce-1",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));

    let worker = build_worker();
    let prepare = claim(&scheduler, &worker, 10);
    let prepare_receipt = success_receipt(&prepare, "prepare-idempotent");
    let first_commit = scheduler
        .commit_node_receipt(&prepare_receipt, 21)
        .unwrap_or_else(|error| panic!("first receipt commit: {error}"));
    let replay_commit = scheduler
        .commit_node_receipt(&prepare_receipt, 22)
        .unwrap_or_else(|error| panic!("receipt replay: {error}"));
    assert_eq!(first_commit, replay_commit);

    let conflicting = WorkflowNodeReceiptV1::new(
        &prepare,
        WorkflowNodeOutcomeV1::Succeeded,
        Some(digest("different-output")),
        digest("different-execution"),
        digest("different-cleanup"),
        WorkflowCleanupResultV1::Complete,
        20,
    )
    .unwrap_or_else(|error| panic!("conflicting receipt fixture: {error}"));
    assert!(matches!(
        scheduler.commit_node_receipt(&conflicting, 23),
        Err(StoreError::WorkflowReceiptConflict)
    ));

    let build = claim(&scheduler, &worker, 30);
    assert_eq!(build.node_kind, WorkflowNodeKindV1::ReleaseBuild);
    commit_success(&scheduler, &build, "build");
    let verify = claim(&scheduler, &worker, 50);
    assert_eq!(verify.node_kind, WorkflowNodeKindV1::Verification);
    commit_success(&scheduler, &verify, "verify");
    assert!(matches!(
        scheduler.reduce_attempt(prepare.attempt_id, 0),
        Err(StoreError::WorkflowReductionConflict)
    ));
    let reduction = scheduler
        .reduce_attempt(prepare.attempt_id, 70)
        .unwrap_or_else(|error| panic!("reduce evidence: {error}"));
    assert_eq!(reduction.inputs.len(), 2);
    assert_eq!(
        reduction
            .inputs
            .iter()
            .map(|input| input.node_kind)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            WorkflowNodeKindV1::Verification,
            WorkflowNodeKindV1::ReleaseBuild,
        ])
    );
    let replayed = scheduler
        .reduce_attempt(prepare.attempt_id, 999)
        .unwrap_or_else(|error| panic!("replay reduction: {error}"));
    assert_eq!(replayed, reduction);
}

#[test]
fn late_receipts_requeue_non_mutating_work_instead_of_becoming_success() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = manifest("ralert", 1);
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                'e',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "late-1",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));
    let lease = claim(&scheduler, &build_worker(), 10);
    let receipt = success_receipt(&lease, "late");
    assert!(matches!(
        scheduler.commit_node_receipt(&receipt, lease.expires_at_ms),
        Err(StoreError::WorkflowLeaseConflict)
    ));
    let attempt = scheduler
        .attempt(lease.attempt_id)
        .unwrap_or_else(|error| panic!("load expired attempt: {error}"))
        .unwrap_or_else(|| panic!("expired attempt exists"));
    let node = attempt
        .nodes
        .iter()
        .find(|node| node.node_id == lease.node_id)
        .unwrap_or_else(|| panic!("expired node exists"));
    assert_eq!(node.state, WorkflowNodeStateV1::Ready);
    assert!(node.output_digest.is_none());
}

#[test]
fn mutation_owner_survives_newer_head_and_expiry_requires_reconciliation() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = manifest("ralert", 1);
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                'a',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "mutation-1",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit first workflow: {error}"));
    let (attempt_id, _) = complete_reduction(&scheduler, 10);
    let reserve = claim(&scheduler, &executor_worker(), 100);
    assert_eq!(reserve.node_kind, WorkflowNodeKindV1::ResourceReservation);
    commit_success(&scheduler, &reserve, "reserve");
    let backup = claim(&scheduler, &executor_worker(), 120);
    assert_eq!(backup.node_kind, WorkflowNodeKindV1::Backup);

    let newer = admission(
        &manifest,
        'b',
        2,
        WorkflowTriggerChannelV1::GithubWebhook,
        "mutation-2",
    );
    let newer = scheduler
        .admit(&manifest, &newer, 130)
        .unwrap_or_else(|error| panic!("admit newer workflow: {error}"));
    assert_eq!(
        newer.attempt().state,
        WorkflowAttemptStateV1::WaitingForMutation
    );
    let active = scheduler
        .attempt(attempt_id)
        .unwrap_or_else(|error| panic!("load mutation owner: {error}"))
        .unwrap_or_else(|| panic!("mutation owner exists"));
    assert_eq!(active.state, WorkflowAttemptStateV1::Running);
    assert_eq!(active.mutation_state, WorkflowMutationStateV1::Owned);

    assert_eq!(
        scheduler
            .expire_leases(backup.expires_at_ms)
            .unwrap_or_else(|error| panic!("expire mutation lease: {error}")),
        1
    );
    let ambiguous = scheduler
        .attempt(attempt_id)
        .unwrap_or_else(|error| panic!("load ambiguous attempt: {error}"))
        .unwrap_or_else(|| panic!("ambiguous attempt exists"));
    assert_eq!(ambiguous.state, WorkflowAttemptStateV1::NeedsReconcile);
    assert_eq!(
        ambiguous.mutation_state,
        WorkflowMutationStateV1::NeedsReconcile
    );
    assert_eq!(
        scheduler
            .attempt(newer.attempt().attempt_id)
            .unwrap_or_else(|error| panic!("load waiting attempt: {error}"))
            .unwrap_or_else(|| panic!("waiting attempt exists"))
            .state,
        WorkflowAttemptStateV1::WaitingForMutation
    );
    assert!(
        scheduler
            .claim_next(&executor_worker(), backup.expires_at_ms + 1, 1_000)
            .unwrap_or_else(|error| panic!("claim behind reconcile lock: {error}"))
            .is_none()
    );
}

#[test]
fn terminal_success_releases_mutation_ownership_and_wakes_the_newer_head() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = manifest("ralert", 1);
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '1',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "terminal-success-1",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit first workflow: {error}"));
    let (attempt_id, _) = complete_reduction(&scheduler, 10);
    let observation = complete_executor_path_to_observation(&scheduler, 100);

    let newer = scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '2',
                2,
                WorkflowTriggerChannelV1::GithubWebhook,
                "terminal-success-2",
            ),
            181,
        )
        .unwrap_or_else(|error| panic!("admit waiting workflow: {error}"));
    assert_eq!(
        newer.attempt().state,
        WorkflowAttemptStateV1::WaitingForMutation
    );

    commit_success(&scheduler, &observation, "released-observation");
    let completed = scheduler
        .attempt(attempt_id)
        .unwrap_or_else(|error| panic!("load completed workflow: {error}"))
        .unwrap_or_else(|| panic!("completed workflow exists"));
    assert_eq!(completed.state, WorkflowAttemptStateV1::Succeeded);
    assert_eq!(completed.mutation_state, WorkflowMutationStateV1::Complete);
    assert_eq!(
        completed
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::Rollback)
            .unwrap_or_else(|| panic!("rollback node exists"))
            .state,
        WorkflowNodeStateV1::Cancelled
    );

    let woken = scheduler
        .attempt(newer.attempt().attempt_id)
        .unwrap_or_else(|error| panic!("load woken workflow: {error}"))
        .unwrap_or_else(|| panic!("woken workflow exists"));
    assert_eq!(woken.state, WorkflowAttemptStateV1::Queued);
    let preparation = claim(&scheduler, &build_worker(), 200);
    assert_eq!(preparation.attempt_id, woken.attempt_id);
    assert_eq!(preparation.node_kind, WorkflowNodeKindV1::HostPrepare);
}

#[test]
fn self_update_handoff_finishes_without_claiming_executor_mutation_nodes() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = self_update_manifest();
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '7',
                7,
                WorkflowTriggerChannelV1::GithubWebhook,
                "self-update-7",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit self-update workflow: {error}"));
    let worker = build_worker();
    let prepare = claim(&scheduler, &worker, 10);
    assert_eq!(prepare.node_kind, WorkflowNodeKindV1::HostPrepare);
    commit_success(&scheduler, &prepare, "self-update-prepare");
    let verify = claim(&scheduler, &worker, 30);
    assert_eq!(verify.node_kind, WorkflowNodeKindV1::Verification);
    commit_success(&scheduler, &verify, "self-update-verify");
    let release = claim(&scheduler, &worker, 50);
    assert_eq!(release.node_kind, WorkflowNodeKindV1::ReleaseBuild);
    assert_eq!(release.host_id, verify.host_id);
    let newer = scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '8',
                8,
                WorkflowTriggerChannelV1::GithubWebhook,
                "self-update-8",
            ),
            51,
        )
        .unwrap_or_else(|error| panic!("admit newer self-update workflow: {error}"));
    assert_eq!(
        newer.attempt().state,
        WorkflowAttemptStateV1::WaitingForMutation
    );
    commit_success(&scheduler, &release, "self-update-release");
    scheduler
        .reduce_attempt(prepare.attempt_id, 70)
        .unwrap_or_else(|error| panic!("reduce self-update evidence: {error}"));

    let completed = scheduler
        .attempt(prepare.attempt_id)
        .unwrap_or_else(|error| panic!("load completed self-update: {error}"))
        .unwrap_or_else(|| panic!("completed self-update exists"));
    assert_eq!(completed.state, WorkflowAttemptStateV1::Succeeded);
    assert_eq!(completed.mutation_state, WorkflowMutationStateV1::Complete);
    assert!(completed.nodes.iter().all(|node| node.kind
        != WorkflowNodeKindV1::ResourceReservation
        && !node.kind.is_mutation()));
    assert!(
        scheduler
            .claim_next(&executor_worker(), 80, 1_000)
            .unwrap_or_else(|error| panic!("probe executor queue: {error}"))
            .is_none()
    );
    assert_eq!(
        scheduler
            .attempt(newer.attempt().attempt_id)
            .unwrap_or_else(|error| panic!("load woken self-update: {error}"))
            .unwrap_or_else(|| panic!("woken self-update exists"))
            .state,
        WorkflowAttemptStateV1::Queued
    );
}

#[test]
fn failed_self_update_publication_stays_reconcile_debt_after_job_cleanup() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = self_update_manifest();
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '5',
                5,
                WorkflowTriggerChannelV1::GithubWebhook,
                "self-update-failure-5",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit self-update workflow: {error}"));
    let worker = build_worker();
    let prepare = claim(&scheduler, &worker, 10);
    commit_success(&scheduler, &prepare, "failed-self-update-prepare");
    let verify = claim(&scheduler, &worker, 30);
    commit_success(&scheduler, &verify, "failed-self-update-verify");
    let release = claim(&scheduler, &worker, 50);
    assert_eq!(release.node_kind, WorkflowNodeKindV1::ReleaseBuild);
    let newer = scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '6',
                6,
                WorkflowTriggerChannelV1::GithubWebhook,
                "self-update-failure-6",
            ),
            51,
        )
        .unwrap_or_else(|error| panic!("admit newer self-update workflow: {error}"));
    assert_eq!(
        newer.attempt().state,
        WorkflowAttemptStateV1::WaitingForMutation
    );

    let failed = WorkflowNodeReceiptV1::new(
        &release,
        WorkflowNodeOutcomeV1::Failed,
        None,
        digest("failed-self-update-execution"),
        digest("complete-self-update-cleanup"),
        WorkflowCleanupResultV1::Complete,
        60,
    )
    .unwrap_or_else(|error| panic!("failed self-update receipt: {error}"));
    let terminal = scheduler
        .commit_node_receipt(&failed, 61)
        .unwrap_or_else(|error| panic!("commit failed self-update receipt: {error}"));
    assert_eq!(terminal.state, WorkflowAttemptStateV1::NeedsReconcile);
    assert_eq!(
        terminal.mutation_state,
        WorkflowMutationStateV1::NeedsReconcile
    );
    assert_eq!(terminal.cleanup_state, WorkflowCleanupStateV1::Complete);
    assert_eq!(
        terminal
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::ReleaseBuild)
            .unwrap_or_else(|| panic!("self-update release node exists"))
            .state,
        WorkflowNodeStateV1::NeedsReconcile
    );
    assert_eq!(
        scheduler
            .attempt(newer.attempt().attempt_id)
            .unwrap_or_else(|error| panic!("load blocked self-update: {error}"))
            .unwrap_or_else(|| panic!("blocked self-update exists"))
            .state,
        WorkflowAttemptStateV1::WaitingForMutation
    );
}

#[test]
fn expired_self_update_publication_stays_reconcile_debt_and_blocks_newer_heads() {
    let store = ControlStore::open(":memory:")
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = self_update_manifest();
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '3',
                3,
                WorkflowTriggerChannelV1::GithubWebhook,
                "self-update-expiry-3",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit self-update workflow: {error}"));
    let worker = build_worker();
    let prepare = claim(&scheduler, &worker, 10);
    commit_success(&scheduler, &prepare, "expired-self-update-prepare");
    let verify = claim(&scheduler, &worker, 30);
    commit_success(&scheduler, &verify, "expired-self-update-verify");
    let release = claim(&scheduler, &worker, 50);
    let newer = scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '4',
                4,
                WorkflowTriggerChannelV1::GithubWebhook,
                "self-update-expiry-4",
            ),
            51,
        )
        .unwrap_or_else(|error| panic!("admit newer self-update workflow: {error}"));

    assert_eq!(
        scheduler
            .expire_leases(release.expires_at_ms)
            .unwrap_or_else(|error| panic!("expire self-update release lease: {error}")),
        1
    );
    let ambiguous = scheduler
        .attempt(prepare.attempt_id)
        .unwrap_or_else(|error| panic!("load ambiguous self-update: {error}"))
        .unwrap_or_else(|| panic!("ambiguous self-update exists"));
    assert_eq!(ambiguous.state, WorkflowAttemptStateV1::NeedsReconcile);
    assert_eq!(
        ambiguous.mutation_state,
        WorkflowMutationStateV1::NeedsReconcile
    );
    assert_eq!(ambiguous.cleanup_state, WorkflowCleanupStateV1::Pending);
    assert_eq!(
        ambiguous
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::ReleaseBuild)
            .unwrap_or_else(|| panic!("self-update release node exists"))
            .state,
        WorkflowNodeStateV1::NeedsReconcile
    );
    assert_eq!(
        scheduler
            .attempt(newer.attempt().attempt_id)
            .unwrap_or_else(|error| panic!("load blocked self-update: {error}"))
            .unwrap_or_else(|| panic!("blocked self-update exists"))
            .state,
        WorkflowAttemptStateV1::WaitingForMutation
    );
}

#[test]
fn terminal_success_rolls_back_when_the_held_mutation_lock_is_missing() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("missing-mutation-lock.sqlite");
    let store =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store.clone());
    let manifest = manifest("ralert", 1);
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                '3',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "missing-lock-1",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));
    complete_reduction(&scheduler, 10);
    let observation = complete_executor_path_to_observation(&scheduler, 100);
    let observation_receipt = success_receipt(&observation, "missing-lock-observation");
    drop(scheduler);
    drop(store);

    let raw = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open raw control store: {error}"));
    assert_eq!(
        raw.execute(
            "DELETE FROM workflow_mutation_locks WHERE attempt_id = ?1",
            [observation.attempt_id.to_string()],
        )
        .unwrap_or_else(|error| panic!("remove mutation lock fixture: {error}")),
        1
    );
    drop(raw);

    let reopened = DurableWorkflowScheduler::new(
        ControlStore::open(&path).unwrap_or_else(|error| panic!("reopen control store: {error}")),
    );
    assert!(matches!(
        reopened.commit_node_receipt(&observation_receipt, 191),
        Err(StoreError::CorruptWorkflowJournal(
            "completed mutation without held project lock"
        ))
    ));
    let unchanged = reopened
        .attempt(observation.attempt_id)
        .unwrap_or_else(|error| panic!("load rolled-back workflow: {error}"))
        .unwrap_or_else(|| panic!("rolled-back workflow exists"));
    assert_eq!(unchanged.state, WorkflowAttemptStateV1::Running);
    assert_eq!(
        unchanged
            .nodes
            .iter()
            .find(|node| node.node_id == observation.node_id)
            .unwrap_or_else(|| panic!("observation node exists"))
            .state,
        WorkflowNodeStateV1::Leased
    );
}

#[test]
fn persisted_reduction_revalidates_its_source_receipts_after_restart() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("tampered-control.sqlite");
    let store =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store.clone());
    let manifest = manifest("ralert", 1);
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                'f',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "tamper-1",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));

    let worker = build_worker();
    let prepare = claim(&scheduler, &worker, 10);
    commit_success(&scheduler, &prepare, "tamper-prepare");
    let build = claim(&scheduler, &worker, 30);
    commit_success(&scheduler, &build, "tamper-build");
    let verify = claim(&scheduler, &worker, 50);
    commit_success(&scheduler, &verify, "tamper-verify");
    let attempt_id = prepare.attempt_id;
    scheduler
        .reduce_attempt(attempt_id, 70)
        .unwrap_or_else(|error| panic!("persist reduction before restart: {error}"));
    drop(scheduler);
    drop(store);

    let raw = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open raw control store: {error}"));
    let changed = raw
        .execute(
            "UPDATE workflow_node_receipts
             SET receipt_json = replace(receipt_json, '\"host_id\":\"vps-1\"',
                 '\"host_id\":\"evil-1\"')
             WHERE attempt_id = ?1 AND node_id = 'verify'",
            [attempt_id.to_string()],
        )
        .unwrap_or_else(|error| panic!("tamper receipt: {error}"));
    assert_eq!(changed, 1);
    drop(raw);

    let reopened = DurableWorkflowScheduler::new(
        ControlStore::open(&path).unwrap_or_else(|error| panic!("reopen control store: {error}")),
    );
    assert!(matches!(
        reopened.reduce_attempt(attempt_id, 70),
        Err(StoreError::WorkflowContract(_))
    ));
}

#[test]
fn lease_renewal_is_bounded_idempotent_and_survives_reopen() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("renewed-control.sqlite");
    let store =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store.clone());
    let manifest = manifest("ralert", 1);
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                'a',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "renew-1",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));
    let worker = build_worker();
    let original = claim(&scheduler, &worker, 10);
    let renewed = scheduler
        .renew_lease(&worker, &original, 500, 1_000)
        .unwrap_or_else(|error| panic!("renew lease: {error}"));
    assert_eq!(renewed.lease_id, original.lease_id);
    assert_eq!(renewed.lease_generation, original.lease_generation);
    assert!(renewed.expires_at_ms > original.expires_at_ms);
    assert_ne!(renewed.lease_digest, original.lease_digest);

    let replay = scheduler
        .renew_lease(&worker, &original, 501, 1_000)
        .unwrap_or_else(|error| panic!("recover lost renewal response: {error}"));
    assert_eq!(replay, renewed);
    drop(scheduler);
    drop(store);

    let reopened = DurableWorkflowScheduler::new(
        ControlStore::open(&path).unwrap_or_else(|error| panic!("reopen control store: {error}")),
    );
    let renewed_again = reopened
        .renew_lease(&worker, &renewed, 1_000, 1_000)
        .unwrap_or_else(|error| panic!("renew after reopen: {error}"));
    assert!(renewed_again.expires_at_ms > renewed.expires_at_ms);
    let receipt = success_receipt(&renewed_again, "renewed-prepare");
    reopened
        .commit_node_receipt(&receipt, receipt.completed_at_ms + 1)
        .unwrap_or_else(|error| panic!("commit receipt against latest lease: {error}"));
    assert!(matches!(
        reopened.commit_node_receipt(
            &success_receipt(&original, "stale-renewal"),
            original.leased_at_ms + 21,
        ),
        Err(StoreError::WorkflowReceiptConflict | StoreError::WorkflowLeaseConflict)
    ));
}

#[test]
fn expired_cleanup_debt_is_durable_and_must_reconcile_before_reuse() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("cleanup-control.sqlite");
    let store =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store.clone());
    let manifest = manifest("ralert", 1);
    scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                'b',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "cleanup-expired-1",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));
    let worker = build_worker();
    let expired = claim(&scheduler, &worker, 10);
    assert_eq!(
        scheduler
            .expire_leases(expired.expires_at_ms)
            .unwrap_or_else(|error| panic!("expire lease: {error}")),
        1
    );
    let attempt = scheduler
        .attempt(expired.attempt_id)
        .unwrap_or_else(|error| panic!("load cleanup debt: {error}"))
        .unwrap_or_else(|| panic!("attempt exists"));
    assert_eq!(attempt.cleanup_state, WorkflowCleanupStateV1::Pending);
    assert!(
        scheduler
            .claim_next(&worker, expired.expires_at_ms + 1, 1_000)
            .unwrap_or_else(|error| panic!("claim while cleanup is pending: {error}"))
            .is_none(),
        "a worker with unresolved cleanup debt must not receive another lease"
    );
    drop(scheduler);
    drop(store);

    let reopened = DurableWorkflowScheduler::new(
        ControlStore::open(&path).unwrap_or_else(|error| panic!("reopen control store: {error}")),
    );
    let obligations = reopened
        .pending_cleanup(&worker, 4)
        .unwrap_or_else(|error| panic!("load cleanup obligation: {error}"));
    assert_eq!(obligations.len(), 1);
    assert_eq!(obligations[0].lease, expired);
    assert_eq!(obligations[0].reason, WorkflowCleanupReasonV1::LeaseExpired);
    assert!(obligations[0].terminal_receipt.is_none());
    let cleanup = WorkflowCleanupReceiptV1::new(
        &expired,
        None,
        digest("expired-cleanup-proof"),
        expired.expires_at_ms + 1,
    )
    .unwrap_or_else(|error| panic!("cleanup receipt: {error}"));
    let cleaned = reopened
        .commit_cleanup_receipt(&cleanup, cleanup.completed_at_ms + 1)
        .unwrap_or_else(|error| panic!("commit cleanup: {error}"));
    assert_eq!(cleaned.cleanup_state, WorkflowCleanupStateV1::Complete);
    assert_eq!(
        reopened
            .commit_cleanup_receipt(&cleanup, cleanup.completed_at_ms + 2)
            .unwrap_or_else(|error| panic!("replay cleanup: {error}")),
        cleaned
    );
    let conflicting = WorkflowCleanupReceiptV1::new(
        &expired,
        None,
        digest("different-cleanup-proof"),
        expired.expires_at_ms + 1,
    )
    .unwrap_or_else(|error| panic!("conflicting cleanup fixture: {error}"));
    assert!(matches!(
        reopened.commit_cleanup_receipt(&conflicting, conflicting.completed_at_ms + 1),
        Err(StoreError::WorkflowCleanupConflict)
    ));
    let next = claim(&reopened, &worker, expired.expires_at_ms + 10);
    assert_eq!(next.node_id, expired.node_id);
    assert_eq!(next.lease_generation, expired.lease_generation + 1);
}

#[test]
fn terminal_and_revoked_cleanup_obligations_bind_their_exact_evidence() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let store = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let first_manifest = manifest("ralert", 1);
    scheduler
        .admit(
            &first_manifest,
            &admission(
                &first_manifest,
                'c',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "cleanup-terminal-1",
            ),
            1,
        )
        .unwrap_or_else(|error| panic!("admit failed workflow: {error}"));
    let worker = build_worker();
    let failed_lease = claim(&scheduler, &worker, 10);
    let failed = WorkflowNodeReceiptV1::new(
        &failed_lease,
        WorkflowNodeOutcomeV1::Failed,
        None,
        digest("failed-execution"),
        digest("pending-cleanup"),
        WorkflowCleanupResultV1::Pending,
        20,
    )
    .unwrap_or_else(|error| panic!("failed receipt: {error}"));
    scheduler
        .commit_node_receipt(&failed, 21)
        .unwrap_or_else(|error| panic!("commit failed receipt: {error}"));
    let terminal = scheduler
        .pending_cleanup(&worker, 4)
        .unwrap_or_else(|error| panic!("terminal cleanup: {error}"));
    assert_eq!(terminal.len(), 1);
    assert_eq!(
        terminal[0].reason,
        WorkflowCleanupReasonV1::TerminalReceiptPending
    );
    assert_eq!(terminal[0].terminal_receipt.as_ref(), Some(&failed));
    let terminal_cleanup = WorkflowCleanupReceiptV1::new(
        &failed_lease,
        Some(&failed),
        digest("terminal-cleanup-proof"),
        22,
    )
    .unwrap_or_else(|error| panic!("terminal cleanup receipt: {error}"));
    let cleaned = scheduler
        .commit_cleanup_receipt(&terminal_cleanup, 23)
        .unwrap_or_else(|error| panic!("commit terminal cleanup: {error}"));
    assert_eq!(cleaned.cleanup_state, WorkflowCleanupStateV1::Complete);

    let newer_manifest = manifest("second", 1);
    scheduler
        .admit(
            &newer_manifest,
            &admission(
                &newer_manifest,
                'd',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "cleanup-revoked-1",
            ),
            30,
        )
        .unwrap_or_else(|error| panic!("admit revocation workflow: {error}"));
    let revoked = claim(&scheduler, &worker, 40);
    scheduler
        .admit(
            &newer_manifest,
            &admission(
                &newer_manifest,
                'e',
                2,
                WorkflowTriggerChannelV1::GithubWebhook,
                "cleanup-revoked-2",
            ),
            50,
        )
        .unwrap_or_else(|error| panic!("supersede leased workflow: {error}"));
    let revoked_obligations = scheduler
        .pending_cleanup(&worker, 4)
        .unwrap_or_else(|error| panic!("revoked cleanup: {error}"));
    assert!(revoked_obligations.iter().any(|obligation| {
        obligation.lease.lease_id == revoked.lease_id
            && obligation.reason == WorkflowCleanupReasonV1::LeaseRevoked
            && obligation.terminal_receipt.is_none()
    }));
}

#[test]
fn workflow_overview_is_bounded_ordered_and_consistent_after_reopen() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("overview-control.sqlite");
    let store =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("open control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store.clone());
    let first_manifest = manifest("ralert", 1);
    let second_manifest = manifest("second", 1);
    let first = scheduler
        .admit(
            &first_manifest,
            &admission(
                &first_manifest,
                'a',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "overview-first",
            ),
            10,
        )
        .unwrap_or_else(|error| panic!("admit first workflow: {error}"));
    let second = scheduler
        .admit(
            &second_manifest,
            &admission(
                &second_manifest,
                'b',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "overview-second",
            ),
            20,
        )
        .unwrap_or_else(|error| panic!("admit second workflow: {error}"));
    let reader = WorkflowJournalReaderV1::new(store.clone());
    let page = reader
        .recent_attempts(1)
        .unwrap_or_else(|error| panic!("read bounded overview: {error}"));
    assert!(page.truncated);
    assert_eq!(page.attempts.len(), 1);
    assert_eq!(page.attempts[0], second.attempt().clone());
    assert!(matches!(
        reader.recent_attempts(0),
        Err(StoreError::InvalidWorkflowSchedulerInput(
            "workflow overview limit"
        ))
    ));
    drop(reader);
    drop(scheduler);
    drop(store);

    let reopened_store =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("reopen control store: {error}"));
    let reopened = WorkflowJournalReaderV1::new(reopened_store);
    let page = reopened
        .recent_attempts(2)
        .unwrap_or_else(|error| panic!("read overview after reopen: {error}"));
    assert!(!page.truncated);
    assert_eq!(
        page.attempts
            .iter()
            .map(|attempt| attempt.attempt_id)
            .collect::<Vec<_>>(),
        vec![second.attempt().attempt_id, first.attempt().attempt_id]
    );
}

#[test]
fn shadow_stops_after_reduction_and_the_same_source_can_still_deploy() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("shadow-control.sqlite");
    let store = ControlStore::open(&path)
        .unwrap_or_else(|error| panic!("open shadow control store: {error}"));
    let scheduler = DurableWorkflowScheduler::new(store);
    let manifest = rimg_manifest();
    let mut shadow = admission(
        &manifest,
        'a',
        1,
        WorkflowTriggerChannelV1::ManualShadow,
        "shadow-source-a",
    );
    shadow.execution_mode = WorkflowExecutionModeV1::Shadow;
    let admitted = scheduler
        .admit(&manifest, &shadow, 10)
        .unwrap_or_else(|error| panic!("admit shadow: {error}"));
    assert!(admitted.created());
    assert_eq!(
        admitted.attempt().execution_mode,
        WorkflowExecutionModeV1::Shadow
    );
    assert!(admitted.attempt().nodes.iter().all(|node| {
        if matches!(
            node.kind,
            WorkflowNodeKindV1::SourceAdmission
                | WorkflowNodeKindV1::HostPrepare
                | WorkflowNodeKindV1::Verification
                | WorkflowNodeKindV1::ReleaseBuild
                | WorkflowNodeKindV1::DeterministicReduce
        ) {
            node.state != WorkflowNodeStateV1::Cancelled
        } else {
            node.state == WorkflowNodeStateV1::Cancelled
        }
    }));

    let (attempt_id, _) = complete_reduction(&scheduler, 20);
    let completed = scheduler
        .attempt(attempt_id)
        .unwrap_or_else(|error| panic!("read completed shadow: {error}"))
        .unwrap_or_else(|| panic!("completed shadow missing"));
    assert_eq!(completed.state, WorkflowAttemptStateV1::Succeeded);
    assert_eq!(
        completed.mutation_state,
        WorkflowMutationStateV1::NotStarted
    );
    assert!(
        scheduler
            .claim_next(&executor_worker(), 100, 1_000)
            .unwrap_or_else(|error| panic!("claim after shadow: {error}"))
            .is_none(),
        "a completed shadow must never expose a privileged executor node"
    );

    let deploy = scheduler
        .admit(
            &manifest,
            &admission(
                &manifest,
                'a',
                1,
                WorkflowTriggerChannelV1::GithubWebhook,
                "deploy-source-a",
            ),
            110,
        )
        .unwrap_or_else(|error| panic!("admit deploy after shadow: {error}"));
    assert!(deploy.created());
    assert_ne!(deploy.attempt().request_id, completed.request_id);
    assert_eq!(
        deploy.attempt().execution_mode,
        WorkflowExecutionModeV1::Deploy
    );
    assert!(deploy.attempt().nodes.iter().any(|node| {
        node.kind == WorkflowNodeKindV1::ResourceReservation
            && node.state == WorkflowNodeStateV1::Blocked
    }));
}
