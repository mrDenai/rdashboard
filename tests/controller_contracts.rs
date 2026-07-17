use std::{path::Path, str::FromStr};

use rdashboard::{
    controller::{
        ActionGrantClaims, AdmissionOutcome, DurableController, NewOperation, TabLeaseClaim,
    },
    domain::{
        AuthorizedDiskReservation, EvidenceDigest, ExecutorPhaseBranch, FailureCapsule,
        GitCommitId, InstalledPolicyIdentity, OperationKind, OperationPhase, OperationResult,
        PhaseArtifacts, PhaseReceipt, ProjectId, ReleaseClass, Retryability, StructuredError,
    },
    executor::{
        CoordinatorError, DeterministicModelEffects, DurableCoordinator, DurableExecutor,
        executor_authorization_digest,
    },
    source::{
        DeterministicSourceRepository, DurableSourceBroker, InstalledSourceProjectPolicy,
        SourceChannel, SourceError, SourceIngressOutcome, SourceStore,
    },
    store::{
        ControlStore, ExecutorAuthorization, ExecutorPhasePlan, PhaseIntentRequest, SecurityStore,
        StoreError,
    },
};
use tempfile::tempdir;
use uuid::Uuid;

fn project(value: &str) -> ProjectId {
    ProjectId::from_str(value).unwrap_or_else(|error| panic!("project fixture: {error}"))
}

fn commit(byte: char) -> GitCommitId {
    GitCommitId::from_str(&byte.to_string().repeat(40))
        .unwrap_or_else(|error| panic!("commit fixture: {error}"))
}

fn digest(label: &str) -> EvidenceDigest {
    EvidenceDigest::sha256(label)
}

fn deploy(project_id: ProjectId, target_commit: GitCommitId) -> NewOperation {
    NewOperation {
        project_id,
        operation_kind: OperationKind::Deploy,
        target_commit: Some(target_commit),
        release_class: Some(ReleaseClass::CodeOnlyCompatible),
        installed_policy: InstalledPolicyIdentity {
            digest: digest("policy-v1"),
            version: 1,
        },
    }
}

fn backup(project_id: ProjectId) -> NewOperation {
    NewOperation {
        project_id,
        operation_kind: OperationKind::BackupOnly,
        target_commit: None,
        release_class: None,
        installed_policy: InstalledPolicyIdentity {
            digest: digest("policy-v1"),
            version: 1,
        },
    }
}

fn source_broker(
    source_path: &Path,
    operation: &NewOperation,
    delivery_id: &str,
    maximum_attempts: u32,
    now_ms: i64,
) -> (
    DurableSourceBroker<DeterministicSourceRepository>,
    DeterministicSourceRepository,
) {
    let repository = DeterministicSourceRepository::default();
    repository
        .set_repository_identity(&operation.project_id, digest("repository identity"))
        .unwrap_or_else(|error| panic!("set source repository identity: {error}"));
    let head = operation
        .target_commit
        .as_ref()
        .unwrap_or_else(|| panic!("source fixture requires a deploy target"));
    repository
        .insert_commit(&operation.project_id, head, None)
        .unwrap_or_else(|error| panic!("insert source fixture: {error}"));
    let broker = DurableSourceBroker::new(
        SourceStore::open(source_path)
            .unwrap_or_else(|error| panic!("source store fixture: {error}")),
        repository.clone(),
        "test-source-key",
        ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]),
        60_000,
        vec![InstalledSourceProjectPolicy {
            project_id: operation.project_id.clone(),
            repository_identity: digest("repository identity"),
            installed_policy: operation.installed_policy.clone(),
            auto_deploy: true,
            maximum_attempts,
            release_class: operation
                .release_class
                .unwrap_or_else(|| panic!("source fixture requires a release class")),
        }],
        now_ms,
    )
    .unwrap_or_else(|error| panic!("source broker fixture: {error}"));
    broker
        .process_direct_push(
            &operation.project_id,
            delivery_id,
            "refs/heads/main",
            None,
            head.clone(),
            now_ms + 1,
        )
        .unwrap_or_else(|error| panic!("accept source fixture: {error}"));
    (broker, repository)
}

fn admit_source_interactive(
    broker: &DurableSourceBroker<DeterministicSourceRepository>,
    controller: &DurableController,
    operation: &NewOperation,
    lease: &rdashboard::controller::TabLease,
    action_grant: &ActionGrantClaims,
    delivery_id: &str,
    now_ms: i64,
) -> rdashboard::domain::OperationRecord {
    broker
        .admit_recorded_interactive_deploy(
            controller,
            &operation.project_id,
            SourceChannel::DirectPush,
            delivery_id,
            &claim(lease),
            action_grant,
            now_ms,
        )
        .unwrap_or_else(|error| panic!("admit source-backed deploy: {error}"))
        .operation()
        .clone()
}

fn grant(
    operation: &NewOperation,
    user_id: Uuid,
    nonce: Uuid,
    retry_request_id: Option<Uuid>,
    label: &str,
) -> ActionGrantClaims {
    ActionGrantClaims {
        nonce,
        digest: digest(label),
        user_id,
        project_id: operation.project_id.clone(),
        operation_kind: operation.operation_kind,
        target_commit: operation.target_commit.clone(),
        retry_request_id,
        expires_at_ms: 10_000,
    }
}

fn claim(lease: &rdashboard::controller::TabLease) -> TabLeaseClaim {
    TabLeaseClaim {
        user_id: lease.user_id,
        lease_id: lease.lease_id,
        generation: lease.generation,
    }
}

fn failure_capsule() -> FailureCapsule {
    FailureCapsule {
        schema_version: 1,
        failing_step: "testing".to_owned(),
        error: StructuredError {
            code: "test_failed".to_owned(),
            summary: "The deterministic test adapter failed".to_owned(),
            retryability: Retryability::OperatorRunbook,
            runbook_id: None,
        },
        excerpt: "synthetic failure evidence".to_owned(),
        truncated: false,
    }
}

fn assert_project_operation_history(
    controller: &DurableController,
    project_id: &ProjectId,
    expected_latest_attempt: Uuid,
) {
    let recent = controller
        .recent_project_operations(project_id, 1)
        .unwrap_or_else(|error| panic!("recent project operations: {error}"));
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].attempt_id, expected_latest_attempt);
    assert!(
        controller
            .recent_project_operations(&project("another-project"), 10)
            .unwrap_or_else(|error| panic!("foreign project operations: {error}"))
            .is_empty()
    );
    assert!(matches!(
        controller.recent_project_operations(project_id, 0),
        Err(StoreError::InvalidControllerInput(_))
    ));
}

fn recovered_executor(
    security: SecurityStore,
    project_id: &ProjectId,
) -> DurableExecutor<DeterministicModelEffects> {
    let executor = DurableExecutor::new(security, DeterministicModelEffects::default());
    executor
        .recover_security_state(std::slice::from_ref(project_id), 99)
        .unwrap_or_else(|error| panic!("recover executor: {error}"));
    executor
}

fn fail_automated_attempt(
    controller: &DurableController,
    security_path: &Path,
    operation: &rdashboard::domain::OperationRecord,
    now_ms: i64,
) {
    let security = SecurityStore::open(security_path)
        .unwrap_or_else(|error| panic!("automation security store: {error}"));
    security
        .authorize_attempt(
            &ExecutorAuthorization {
                authorization_id: Uuid::new_v4(),
                digest: executor_authorization_digest(operation)
                    .unwrap_or_else(|error| panic!("automation authorization digest: {error}")),
                attempt_id: operation.attempt_id,
                project_id: operation.project_id.clone(),
                expires_at_ms: 10_000,
                disk_reservation: None,
            },
            now_ms - 1,
        )
        .unwrap_or_else(|error| panic!("authorize automation attempt: {error}"));
    DurableCoordinator::new(
        controller.clone(),
        recovered_executor(security, &operation.project_id),
    )
    .fail_before_mutation(operation.attempt_id, failure_capsule(), now_ms)
    .unwrap_or_else(|error| panic!("fail automated attempt: {error}"));
}

fn commit_synthetic_phase(
    controller: &DurableController,
    operation: &rdashboard::domain::OperationRecord,
    clock: i64,
) -> rdashboard::domain::OperationRecord {
    let marker = format!("{:?}-{clock}", operation.state.phase);
    let branch = if operation.evidence.recovery_mode
        == Some(rdashboard::domain::OperationRecoveryMode::Rollback)
    {
        ExecutorPhaseBranch::RollbackRecovery
    } else {
        ExecutorPhaseBranch::Primary
    };
    controller
        .commit_phase_receipt(
            &PhaseReceipt::new(
                operation.attempt_id,
                operation.state.phase,
                branch,
                digest(&format!("intent-{marker}")),
                digest(&format!("observation-{marker}")),
                synthetic_artifacts(operation.state.phase),
                clock,
            )
            .unwrap_or_else(|error| panic!("construct synthetic receipt: {error}")),
            clock,
        )
        .unwrap_or_else(|error| panic!("commit synthetic phase: {error}"))
}

fn commit_security_deploy_receipt(
    security: &SecurityStore,
    operation: &rdashboard::domain::OperationRecord,
    authorization_digest: &EvidenceDigest,
    clock: i64,
) -> PhaseReceipt {
    let intent_digest = digest("security deploy intent");
    let observation_digest = digest("security deploy observation");
    let artifacts = synthetic_artifacts(OperationPhase::Deploying);
    security
        .begin_phase_intent(PhaseIntentRequest {
            attempt_id: operation.attempt_id,
            project_id: &operation.project_id,
            phase: OperationPhase::Deploying,
            branch: ExecutorPhaseBranch::Primary,
            phase_plan: ExecutorPhasePlan::new(&[OperationPhase::Deploying], false),
            intent_digest: &intent_digest,
            authorization_digest,
            started_at_ms: clock,
        })
        .unwrap_or_else(|error| panic!("begin security deploy receipt: {error}"));
    security
        .record_phase_observation(
            operation.attempt_id,
            OperationPhase::Deploying,
            &intent_digest,
            &observation_digest,
            &artifacts,
            clock + 1,
        )
        .unwrap_or_else(|error| panic!("observe security deploy receipt: {error}"));
    security
        .mark_phase_verified(operation.attempt_id, OperationPhase::Deploying, clock + 2)
        .unwrap_or_else(|error| panic!("verify security deploy receipt: {error}"));
    security
        .commit_phase_receipt(operation.attempt_id, OperationPhase::Deploying, clock + 3)
        .unwrap_or_else(|error| panic!("commit security deploy receipt: {error}"))
}

fn synthetic_artifacts(phase: OperationPhase) -> PhaseArtifacts {
    match phase {
        OperationPhase::Testing => PhaseArtifacts {
            source_export_digest: Some(digest("synthetic source export")),
            prefetch_evidence_digest: Some(digest("synthetic prefetch")),
            ci_evidence_digest: Some(digest("synthetic CI")),
            build_context_digest: Some(digest("synthetic context")),
            resource_reservation_digest: Some(digest("synthetic reservation")),
            base_image_digests: vec![digest("synthetic base")],
            ..PhaseArtifacts::default()
        },
        OperationPhase::Building => PhaseArtifacts {
            build_context_digest: Some(digest("synthetic context")),
            build_plan_digest: Some(digest("synthetic build plan")),
            image_digest: Some(digest("synthetic image")),
            image_id_digest: Some(digest("synthetic image ID")),
            base_image_digests: vec![digest("synthetic base")],
            ..PhaseArtifacts::default()
        },
        OperationPhase::Preflight => PhaseArtifacts {
            resource_reservation_digest: Some(digest("synthetic reservation")),
            ..PhaseArtifacts::default()
        },
        OperationPhase::Deploying => PhaseArtifacts {
            deployment_plan_digest: Some(digest("synthetic deploy plan")),
            release_bundle_digest: Some(digest("synthetic release bundle")),
            ..PhaseArtifacts::default()
        },
        OperationPhase::HealthChecking => PhaseArtifacts {
            health_evidence_digest: Some(digest("synthetic health evidence")),
            ..PhaseArtifacts::default()
        },
        OperationPhase::Soaking => PhaseArtifacts {
            health_evidence_digest: Some(digest("synthetic soak evidence")),
            ..PhaseArtifacts::default()
        },
        _ => PhaseArtifacts::default(),
    }
}

#[test]
fn interactive_admission_is_atomic_and_old_lease_generation_fails_closed() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let user_id = Uuid::new_v4();
    let old_lease = controller
        .takeover_lease(user_id, Uuid::new_v4(), 100, 1_000)
        .unwrap_or_else(|error| panic!("old lease: {error}"));
    let current_lease = controller
        .takeover_lease(user_id, Uuid::new_v4(), 101, 1_001)
        .unwrap_or_else(|error| panic!("current lease: {error}"));
    assert_eq!(current_lease.generation, old_lease.generation + 1);
    assert!(matches!(
        controller.validate_tab_lease(&claim(&old_lease), 102),
        Err(StoreError::LeaseRevoked)
    ));
    controller
        .validate_tab_lease(&claim(&current_lease), 102)
        .unwrap_or_else(|error| panic!("validate current lease: {error}"));
    assert!(matches!(
        controller.validate_tab_lease(&claim(&current_lease), current_lease.expires_at_ms),
        Err(StoreError::LeaseExpired)
    ));

    let operation = backup(project("rimg"));
    let action_grant = grant(&operation, user_id, Uuid::new_v4(), None, "initial grant");
    assert!(matches!(
        controller.admit_interactive(&operation, &claim(&old_lease), &action_grant, 102),
        Err(StoreError::LeaseRevoked)
    ));

    let created = controller
        .admit_interactive(&operation, &claim(&current_lease), &action_grant, 102)
        .unwrap_or_else(|error| panic!("admit current lease: {error}"));
    assert!(created.created());
    assert_eq!(created.operation().attempt_number, 1);

    let replay = controller
        .admit_interactive(&operation, &claim(&current_lease), &action_grant, 103)
        .unwrap_or_else(|error| panic!("idempotent admission replay: {error}"));
    assert!(!replay.created());
    assert_eq!(
        replay.operation().attempt_id,
        created.operation().attempt_id
    );

    let conflicting_grant = ActionGrantClaims {
        digest: digest("different signed grant"),
        ..action_grant.clone()
    };
    assert!(matches!(
        controller.admit_interactive(&operation, &claim(&current_lease), &conflicting_grant, 104),
        Err(StoreError::GrantReplay)
    ));

    let duplicate_request_grant = grant(
        &operation,
        user_id,
        Uuid::new_v4(),
        None,
        "duplicate request grant",
    );
    let duplicate = controller
        .admit_interactive(
            &operation,
            &claim(&current_lease),
            &duplicate_request_grant,
            105,
        )
        .unwrap_or_else(|error| panic!("stable request replay: {error}"));
    assert!(matches!(duplicate, AdmissionOutcome::Existing(_)));
    assert_eq!(
        duplicate.operation().attempt_id,
        created.operation().attempt_id
    );
}

#[test]
fn explicit_retry_creates_a_new_attempt_and_preserves_failed_evidence() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let user_id = Uuid::new_v4();
    let lease = controller
        .takeover_lease(user_id, Uuid::new_v4(), 100, 1_000)
        .unwrap_or_else(|error| panic!("lease: {error}"));
    let operation = backup(project("rimg"));
    let initial_grant = grant(&operation, user_id, Uuid::new_v4(), None, "first attempt");
    let first = controller
        .admit_interactive(&operation, &claim(&lease), &initial_grant, 101)
        .unwrap_or_else(|error| panic!("first admission: {error}"))
        .operation()
        .clone();
    let security = SecurityStore::open(directory.path().join("security.sqlite"))
        .unwrap_or_else(|error| panic!("security store: {error}"));
    security
        .authorize_attempt(
            &ExecutorAuthorization {
                authorization_id: initial_grant.nonce,
                digest: initial_grant.digest.clone(),
                attempt_id: first.attempt_id,
                project_id: first.project_id.clone(),
                expires_at_ms: initial_grant.expires_at_ms,
                disk_reservation: None,
            },
            102,
        )
        .unwrap_or_else(|error| panic!("authorize first attempt: {error}"));
    let coordinator = DurableCoordinator::new(
        controller.clone(),
        recovered_executor(security.clone(), &first.project_id),
    );
    let failed = coordinator
        .fail_before_mutation(first.attempt_id, failure_capsule(), 110)
        .unwrap_or_else(|error| panic!("fail first attempt: {error}"));
    assert_eq!(failed.state.result, OperationResult::Failed);
    assert!(failed.failure_capsule.is_some());

    let unbound_retry = grant(&operation, user_id, Uuid::new_v4(), None, "unbound retry");
    assert!(matches!(
        controller.admit_interactive(&operation, &claim(&lease), &unbound_retry, 111),
        Err(StoreError::RetryGrantRequired(request_id)) if request_id == first.request_id
    ));

    let retry_grant = grant(
        &operation,
        user_id,
        Uuid::new_v4(),
        Some(first.request_id),
        "authorized retry",
    );
    let second = controller
        .admit_interactive(&operation, &claim(&lease), &retry_grant, 112)
        .unwrap_or_else(|error| panic!("retry admission: {error}"))
        .operation()
        .clone();
    assert_eq!(second.request_id, first.request_id);
    assert_ne!(second.attempt_id, first.attempt_id);
    assert_eq!(second.attempt_number, 2);
    assert_eq!(second.state.result, OperationResult::Running);

    let attempts = controller
        .attempts_for_request(first.request_id)
        .unwrap_or_else(|error| panic!("attempt history: {error}"));
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].state.result, OperationResult::Failed);
    assert!(attempts[0].failure_capsule.is_some());
    assert_eq!(attempts[1].state.result, OperationResult::Running);

    assert_project_operation_history(&controller, &operation.project_id, second.attempt_id);

    let authorization = ExecutorAuthorization {
        authorization_id: retry_grant.nonce,
        digest: retry_grant.digest.clone(),
        attempt_id: second.attempt_id,
        project_id: second.project_id.clone(),
        expires_at_ms: retry_grant.expires_at_ms,
        disk_reservation: None,
    };
    security
        .authorize_attempt(&authorization, 113)
        .unwrap_or_else(|error| panic!("authorize retry: {error}"));
    security
        .authorize_attempt(&authorization, 114)
        .unwrap_or_else(|error| panic!("idempotent executor authorization: {error}"));
    let replayed_for_old_attempt = ExecutorAuthorization {
        attempt_id: first.attempt_id,
        ..authorization
    };
    assert!(matches!(
        security.authorize_attempt(&replayed_for_old_attempt, 115),
        Err(StoreError::ExecutorAuthorizationReplay)
    ));
    assert!(matches!(
        security.begin_fence_acquire(&project("keyroom"), second.attempt_id, 116),
        Err(StoreError::ExecutorAuthorizationBinding)
    ));
}

#[test]
fn executor_authorization_reloads_the_exact_disk_claim() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security = SecurityStore::open(directory.path().join("security.sqlite"))
        .unwrap_or_else(|error| panic!("security store: {error}"));
    let operation_digest = digest("authorized backup");
    let filesystem_identity = digest("backup filesystem");
    let disk_reservation = AuthorizedDiskReservation {
        operation_digest: operation_digest.clone(),
        reservation_digest: AuthorizedDiskReservation::calculate_reservation_digest(
            &operation_digest,
            9_000,
            10_000,
            8_000,
            &filesystem_identity,
            100,
        )
        .unwrap_or_else(|error| panic!("reservation digest: {error}")),
        required_bytes: 9_000,
        available_bytes: 10_000,
        emergency_reserve_bytes: 8_000,
        filesystem_identity,
        observed_at_ms: 100,
    };
    let authorization = ExecutorAuthorization {
        authorization_id: Uuid::new_v4(),
        digest: operation_digest,
        attempt_id: Uuid::new_v4(),
        project_id: project("rimg"),
        expires_at_ms: 10_000,
        disk_reservation: Some(disk_reservation),
    };
    security
        .authorize_attempt(&authorization, 101)
        .unwrap_or_else(|error| panic!("authorize attempt: {error}"));
    assert_eq!(
        security
            .executor_authorization(authorization.attempt_id)
            .unwrap_or_else(|error| panic!("reload authorization: {error}")),
        Some(authorization)
    );
}

#[test]
fn automation_deduplicates_transport_and_stable_request_identities() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let operation = deploy(project("rimg"), commit('c'));
    let source_path = directory.path().join("source.sqlite");
    let (broker, repository) = source_broker(&source_path, &operation, "delivery-1", 1, 90);
    let first = broker
        .admit_recorded_deploy(
            &controller,
            &operation.project_id,
            SourceChannel::DirectPush,
            "delivery-1",
            100,
        )
        .unwrap_or_else(|error| panic!("first automation admission: {error}"));
    assert!(first.created());

    let duplicate = broker
        .admit_recorded_deploy(
            &controller,
            &operation.project_id,
            SourceChannel::DirectPush,
            "delivery-1",
            101,
        )
        .unwrap_or_else(|error| panic!("duplicate delivery: {error}"));
    assert!(!duplicate.created());
    assert_eq!(
        duplicate.operation().attempt_id,
        first.operation().attempt_id
    );

    assert!(matches!(
        broker.process_direct_push(
            &operation.project_id,
            "delivery-1",
            "refs/heads/main",
            Some(&commit('d')),
            commit('c'),
            102,
        ),
        Err(SourceError::DeliveryConflict)
    ));

    repository
        .set_remote_head(&operation.project_id, commit('c'))
        .unwrap_or_else(|error| panic!("set reconciliation head: {error}"));
    let reconciliation = broker
        .reconcile_remote_main(&operation.project_id, 103)
        .unwrap_or_else(|error| panic!("reconcile source: {error}"));
    let SourceIngressOutcome::Deployable(delivery) = reconciliation else {
        panic!("reconciliation did not preserve the deployable head");
    };
    let reconciliation_delivery_id = delivery.delivery_id().to_owned();
    let cross_channel = broker
        .admit_recorded_deploy(
            &controller,
            &operation.project_id,
            SourceChannel::SourceReconciliation,
            &reconciliation_delivery_id,
            103,
        )
        .unwrap_or_else(|error| panic!("cross-channel stable request: {error}"));
    assert!(!cross_channel.created());
    assert_eq!(
        cross_channel.operation().attempt_id,
        first.operation().attempt_id
    );
}

#[test]
fn automation_retry_budget_comes_only_from_installed_source_policy() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let operation = deploy(project("rimg"), commit('c'));
    let source_path = directory.path().join("source.sqlite");
    let (broker, repository) = source_broker(&source_path, &operation, "delivery-1", 1, 90);
    let first = broker
        .admit_recorded_deploy(
            &controller,
            &operation.project_id,
            SourceChannel::DirectPush,
            "delivery-1",
            100,
        )
        .unwrap_or_else(|error| panic!("first automation admission: {error}"));

    fail_automated_attempt(
        &controller,
        &directory.path().join("security.sqlite"),
        first.operation(),
        104,
    );
    broker
        .process_direct_push(
            &operation.project_id,
            "delivery-2",
            "refs/heads/main",
            Some(&commit('c')),
            commit('c'),
            105,
        )
        .unwrap_or_else(|error| panic!("record exhausted retry delivery: {error}"));
    assert!(matches!(
        broker.admit_recorded_deploy(
            &controller,
            &operation.project_id,
            SourceChannel::DirectPush,
            "delivery-2",
            105,
        ),
        Err(SourceError::Controller(
            StoreError::AutomationAdmissionRejected
        ))
    ));

    let retry_store = broker.store().clone();
    drop(broker);
    let retry_broker = DurableSourceBroker::new(
        retry_store,
        repository,
        "test-source-key",
        ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]),
        60_000,
        vec![InstalledSourceProjectPolicy {
            project_id: operation.project_id.clone(),
            repository_identity: digest("repository identity"),
            installed_policy: operation.installed_policy.clone(),
            auto_deploy: true,
            maximum_attempts: 2,
            release_class: ReleaseClass::CodeOnlyCompatible,
        }],
        106,
    )
    .unwrap_or_else(|error| panic!("updated source policy: {error}"));
    retry_broker
        .process_direct_push(
            &operation.project_id,
            "delivery-3",
            "refs/heads/main",
            Some(&commit('c')),
            commit('c'),
            106,
        )
        .unwrap_or_else(|error| panic!("record bounded retry: {error}"));
    let retried = retry_broker
        .admit_recorded_deploy(
            &controller,
            &operation.project_id,
            SourceChannel::DirectPush,
            "delivery-3",
            106,
        )
        .unwrap_or_else(|error| panic!("bounded automation retry: {error}"));
    assert!(retried.created());
    assert_eq!(retried.operation().attempt_number, 2);
    assert_eq!(retried.operation().request_id, first.operation().request_id);
}

#[test]
fn cancellation_stops_at_the_persisted_mutation_boundary() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let user_id = Uuid::new_v4();
    let lease = controller
        .takeover_lease(user_id, Uuid::new_v4(), 100, 1_000)
        .unwrap_or_else(|error| panic!("lease: {error}"));
    let operation = NewOperation {
        release_class: Some(ReleaseClass::StatefulCompatible),
        ..deploy(project("rimg"), commit('f'))
    };
    let first_grant = grant(&operation, user_id, Uuid::new_v4(), None, "cancel fixture");
    let (broker, _repository) = source_broker(
        &directory.path().join("cancel-source.sqlite"),
        &operation,
        "cancel-source",
        3,
        90,
    );
    let first = admit_source_interactive(
        &broker,
        &controller,
        &operation,
        &lease,
        &first_grant,
        "cancel-source",
        101,
    );
    let security = SecurityStore::open(directory.path().join("security.sqlite"))
        .unwrap_or_else(|error| panic!("cancellation security store: {error}"));
    security
        .authorize_attempt(
            &ExecutorAuthorization {
                authorization_id: first_grant.nonce,
                digest: first_grant.digest.clone(),
                attempt_id: first.attempt_id,
                project_id: first.project_id.clone(),
                expires_at_ms: first_grant.expires_at_ms,
                disk_reservation: None,
            },
            101,
        )
        .unwrap_or_else(|error| panic!("authorize cancellation fixture: {error}"));
    let coordinator = DurableCoordinator::new(
        controller.clone(),
        recovered_executor(security, &first.project_id),
    );
    let cancelled = coordinator
        .cancel_before_mutation(first.attempt_id, 102)
        .unwrap_or_else(|error| panic!("cancel queued operation: {error}"));
    assert_eq!(cancelled.state.result, OperationResult::Cancelled);

    let retry_grant = grant(
        &operation,
        user_id,
        Uuid::new_v4(),
        Some(first.request_id),
        "retry after cancellation",
    );
    let mut running = admit_source_interactive(
        &broker,
        &controller,
        &operation,
        &lease,
        &retry_grant,
        "cancel-source",
        103,
    );
    let mut clock = 104;
    while running.state.phase != OperationPhase::BackingUp {
        let marker = format!("{:?}-{clock}", running.state.phase);
        let receipt = PhaseReceipt::new(
            running.attempt_id,
            running.state.phase,
            ExecutorPhaseBranch::Primary,
            digest(&format!("intent-{marker}")),
            digest(&format!("observation-{marker}")),
            synthetic_artifacts(running.state.phase),
            clock,
        )
        .unwrap_or_else(|error| panic!("construct boundary receipt: {error}"));
        running = controller
            .commit_phase_receipt(&receipt, clock)
            .unwrap_or_else(|error| panic!("advance to mutation boundary: {error}"));
        clock += 1;
    }
    assert!(running.state.phase.crosses_mutation_boundary());
    assert!(matches!(
        coordinator.cancel_before_mutation(running.attempt_id, clock),
        Err(CoordinatorError::Store(
            StoreError::CancellationAfterMutation
        ))
    ));
    assert!(matches!(
        coordinator.fail_before_mutation(running.attempt_id, failure_capsule(), clock),
        Err(CoordinatorError::Store(
            StoreError::FailureAfterMutationRequiresReconcile
        ))
    ));
}

#[test]
fn backup_only_has_a_release_class_free_execution_plan() {
    assert_eq!(
        OperationKind::BackupOnly
            .required_phases(None)
            .unwrap_or_else(|error| panic!("backup plan: {error}")),
        &[
            OperationPhase::Queued,
            OperationPhase::Preflight,
            OperationPhase::BackingUp
        ]
    );
    assert!(
        OperationKind::BackupOnly
            .required_phases(Some(ReleaseClass::StatefulCompatible))
            .is_err()
    );
}

#[test]
fn receipts_are_canonical_and_project_immutable_artifact_evidence() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let user_id = Uuid::new_v4();
    let lease = controller
        .takeover_lease(user_id, Uuid::new_v4(), 100, 1_000)
        .unwrap_or_else(|error| panic!("lease: {error}"));
    let operation_request = deploy(project("rimg"), commit('3'));
    let action_grant = grant(
        &operation_request,
        user_id,
        Uuid::new_v4(),
        None,
        "artifact fixture",
    );
    let (broker, _repository) = source_broker(
        &directory.path().join("artifact-source.sqlite"),
        &operation_request,
        "artifact-source",
        2,
        90,
    );
    let operation = admit_source_interactive(
        &broker,
        &controller,
        &operation_request,
        &lease,
        &action_grant,
        "artifact-source",
        101,
    );
    let mut projected = operation;
    let mut clock = 102;
    for _ in 0..3 {
        projected = commit_synthetic_phase(&controller, &projected, clock);
        clock += 1;
    }
    assert_eq!(projected.state.phase, OperationPhase::Testing);

    let build_context = digest("frozen build context");
    let mut testing_artifacts = synthetic_artifacts(OperationPhase::Testing);
    testing_artifacts.build_context_digest = Some(build_context.clone());
    let receipt = PhaseReceipt::new(
        projected.attempt_id,
        OperationPhase::Testing,
        ExecutorPhaseBranch::Primary,
        digest("artifact intent"),
        digest("artifact observation"),
        testing_artifacts,
        clock,
    )
    .unwrap_or_else(|error| panic!("construct artifact receipt: {error}"));
    let projected = controller
        .commit_phase_receipt(&receipt, clock)
        .unwrap_or_else(|error| panic!("project artifact receipt: {error}"));
    assert_eq!(
        projected.evidence.build_context_digest,
        Some(build_context.clone())
    );

    let mut tampered = PhaseReceipt::new(
        projected.attempt_id,
        projected.state.phase,
        ExecutorPhaseBranch::Primary,
        digest("next intent"),
        digest("next observation"),
        PhaseArtifacts::default(),
        clock + 1,
    )
    .unwrap_or_else(|error| panic!("construct next receipt: {error}"));
    tampered.receipt_digest = digest("forged receipt digest");
    assert!(matches!(
        controller.commit_phase_receipt(&tampered, clock + 1),
        Err(StoreError::ReceiptDigestMismatch)
    ));

    let mut conflicting_artifacts = synthetic_artifacts(projected.state.phase);
    conflicting_artifacts.build_context_digest = Some(digest("different build context"));
    let conflict = PhaseReceipt::new(
        projected.attempt_id,
        projected.state.phase,
        ExecutorPhaseBranch::Primary,
        digest("conflicting intent"),
        digest("conflicting observation"),
        conflicting_artifacts,
        clock + 2,
    )
    .unwrap_or_else(|error| panic!("construct conflicting receipt: {error}"));
    assert!(matches!(
        controller.commit_phase_receipt(&conflict, clock + 2),
        Err(StoreError::ArtifactEvidenceConflict("build_context_digest"))
    ));
}

#[test]
fn deploy_rollback_is_a_durable_branch_with_health_and_soak() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let user_id = Uuid::new_v4();
    let lease = controller
        .takeover_lease(user_id, Uuid::new_v4(), 100, 1_000)
        .unwrap_or_else(|error| panic!("lease: {error}"));
    let operation_request = deploy(project("rimg"), commit('2'));
    let action_grant = grant(
        &operation_request,
        user_id,
        Uuid::new_v4(),
        None,
        "rollback fixture",
    );
    let (broker, _repository) = source_broker(
        &directory.path().join("rollback-source.sqlite"),
        &operation_request,
        "rollback-source",
        2,
        90,
    );
    let mut operation = admit_source_interactive(
        &broker,
        &controller,
        &operation_request,
        &lease,
        &action_grant,
        "rollback-source",
        101,
    );
    let security = SecurityStore::open(directory.path().join("rollback-security.sqlite"))
        .unwrap_or_else(|error| panic!("rollback security store: {error}"));
    let authorization_digest = executor_authorization_digest(&operation)
        .unwrap_or_else(|error| panic!("rollback authorization digest: {error}"));
    security
        .authorize_attempt(
            &ExecutorAuthorization {
                authorization_id: action_grant.nonce,
                digest: authorization_digest.clone(),
                attempt_id: operation.attempt_id,
                project_id: operation.project_id.clone(),
                expires_at_ms: action_grant.expires_at_ms,
                disk_reservation: None,
            },
            101,
        )
        .unwrap_or_else(|error| panic!("authorize rollback fixture: {error}"));
    let coordinator = DurableCoordinator::new(
        controller.clone(),
        recovered_executor(security, &operation.project_id),
    );
    let mut clock = 102;
    while operation.state.phase != OperationPhase::Deploying {
        operation = commit_synthetic_phase(&controller, &operation, clock);
        clock += 1;
    }
    let deploy_receipt = commit_security_deploy_receipt(
        coordinator.executor().security(),
        &operation,
        &authorization_digest,
        clock,
    );
    operation = controller
        .commit_phase_receipt(&deploy_receipt, clock + 3)
        .unwrap_or_else(|error| panic!("project security deploy receipt: {error}"));
    assert_eq!(operation.state.phase, OperationPhase::HealthChecking);
    clock += 4;
    operation = coordinator
        .begin_rollback(operation.attempt_id, None, clock)
        .unwrap_or_else(|error| panic!("begin rollback: {error}"));
    assert_eq!(operation.state.phase, OperationPhase::Rollback);
    assert_eq!(
        operation.evidence.recovery_mode,
        Some(rdashboard::domain::OperationRecoveryMode::Rollback)
    );

    for expected in [OperationPhase::HealthChecking, OperationPhase::Soaking] {
        clock += 1;
        operation = commit_synthetic_phase(&controller, &operation, clock);
        assert_eq!(operation.state.phase, expected);
        assert_eq!(operation.state.result, OperationResult::Running);
    }
    clock += 1;
    operation = commit_synthetic_phase(&controller, &operation, clock);
    assert_eq!(operation.state.phase, OperationPhase::Soaking);
    assert_eq!(operation.state.result, OperationResult::RolledBack);
    assert_eq!(
        operation.evidence.rollback_health_evidence_digest,
        Some(digest("synthetic soak evidence"))
    );
    assert_ne!(
        operation.evidence.rollback_health_evidence_digest,
        Some(digest("synthetic health evidence"))
    );
}
