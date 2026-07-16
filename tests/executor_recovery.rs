use std::{
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Condvar, Mutex, mpsc},
    thread,
    time::Duration,
};

use rdashboard::{
    controller::{ActionGrantClaims, DurableController, NewOperation, TabLeaseClaim},
    domain::{
        AuthorizedDiskReservation, BlockingReason, DiskAvailabilityObservation, EvidenceDigest,
        FailureCapsule, GitCommitId, InstalledPolicyIdentity, OperationKind, OperationPhase,
        OperationRecord, OperationResult, PhaseArtifacts, PhaseReceipt, ProjectId, ReleaseClass,
        Retryability, StructuredError,
    },
    executor::{
        CoordinatorCrashPoint, CoordinatorError, DeterministicModelEffects, DiskSpaceProbe,
        DurableCoordinator, DurableExecutor, ExternalEffects, FenceCrashPoint, FenceExecutionError,
        PhaseCrashPoint, PhaseExecutionError, executor_authorization_digest,
    },
    source::{
        DeterministicSourceRepository, DurableSourceBroker, InstalledSourceProjectPolicy,
        LiveSourceGate, SourceChannel, SourceGateError, SourceGateProof, SourceStore,
    },
    store::{
        ControlStore, ExecutionResource, ExecutorAuthorization, ExecutorPhaseBranch,
        ExecutorPhasePlan, FenceJournalState, FenceObservation, FenceProjection,
        PhaseIntentRequest, PhaseJournalStatus, SecurityStore, SourceGateProofRecord, StoreError,
    },
};
use tempfile::{TempDir, tempdir};
use uuid::Uuid;

fn project() -> ProjectId {
    named_project("rimg")
}

fn named_project(value: &str) -> ProjectId {
    ProjectId::from_str(value).unwrap_or_else(|error| panic!("project fixture: {error}"))
}

fn commit(byte: char) -> GitCommitId {
    GitCommitId::from_str(&byte.to_string().repeat(40))
        .unwrap_or_else(|error| panic!("commit fixture: {error}"))
}

fn digest(label: &str) -> EvidenceDigest {
    EvidenceDigest::sha256(label)
}

fn test_filesystem_identity() -> EvidenceDigest {
    digest("test filesystem identity")
}

fn disk_observation(available_bytes: u64, observed_at_ms: i64) -> DiskAvailabilityObservation {
    DiskAvailabilityObservation {
        filesystem_identity: test_filesystem_identity(),
        available_bytes,
        observed_at_ms,
    }
}

fn authorized_disk_claim(
    operation_digest: EvidenceDigest,
    required_bytes: u64,
    available_bytes: u64,
    emergency_reserve_bytes: u64,
    observed_at_ms: i64,
) -> AuthorizedDiskReservation {
    let filesystem_identity = test_filesystem_identity();
    let reservation_digest = AuthorizedDiskReservation::calculate_reservation_digest(
        &operation_digest,
        required_bytes,
        available_bytes,
        emergency_reserve_bytes,
        &filesystem_identity,
        observed_at_ms,
    )
    .unwrap_or_else(|error| panic!("calculate disk reservation digest: {error}"));
    AuthorizedDiskReservation {
        operation_digest,
        reservation_digest,
        required_bytes,
        available_bytes,
        emergency_reserve_bytes,
        filesystem_identity,
        observed_at_ms,
    }
}

#[derive(Debug)]
struct TestDiskSpaceProbe;

impl DiskSpaceProbe for TestDiskSpaceProbe {
    fn observe(
        &self,
        _project_id: &ProjectId,
        now_ms: i64,
    ) -> Result<DiskAvailabilityObservation, StoreError> {
        Ok(disk_observation(100, now_ms))
    }
}

#[derive(Debug)]
struct FixedDiskSpaceProbe {
    available_bytes: u64,
}

#[derive(Debug)]
struct BlockingApplyState {
    entered: bool,
    released: bool,
}

#[derive(Clone, Debug)]
struct BlockingProjectEffects {
    inner: DeterministicModelEffects,
    blocked_project: ProjectId,
    state: Arc<(Mutex<BlockingApplyState>, Condvar)>,
}

impl BlockingProjectEffects {
    fn new(blocked_project: ProjectId) -> Self {
        Self {
            inner: DeterministicModelEffects::default(),
            blocked_project,
            state: Arc::new((
                Mutex::new(BlockingApplyState {
                    entered: false,
                    released: false,
                }),
                Condvar::new(),
            )),
        }
    }

    fn wait_until_blocked(&self) {
        let (lock, changed) = &*self.state;
        let mut state = lock
            .lock()
            .unwrap_or_else(|_| panic!("blocking effects state poisoned"));
        while !state.entered {
            state = changed
                .wait(state)
                .unwrap_or_else(|_| panic!("blocking effects wait poisoned"));
        }
    }

    fn release(&self) {
        let (lock, changed) = &*self.state;
        let mut state = lock
            .lock()
            .unwrap_or_else(|_| panic!("blocking effects state poisoned"));
        state.released = true;
        changed.notify_all();
    }
}

impl ExternalEffects for BlockingProjectEffects {
    fn observe_phase(
        &self,
        intent: &rdashboard::executor::PhaseIntent,
    ) -> Result<rdashboard::executor::EffectObservation, rdashboard::executor::ExternalEffectError>
    {
        self.inner.observe_phase(intent)
    }

    fn apply_phase(
        &self,
        intent: &rdashboard::executor::PhaseIntent,
    ) -> Result<(), rdashboard::executor::ExternalEffectError> {
        if intent.project_id == self.blocked_project {
            let (lock, changed) = &*self.state;
            let mut state = lock
                .lock()
                .map_err(|_| rdashboard::executor::ExternalEffectError::StatePoisoned)?;
            state.entered = true;
            changed.notify_all();
            while !state.released {
                state = changed
                    .wait(state)
                    .map_err(|_| rdashboard::executor::ExternalEffectError::StatePoisoned)?;
            }
        }
        self.inner.apply_phase(intent)
    }

    fn observe_fence(
        &self,
        project_id: &ProjectId,
    ) -> Result<FenceObservation, rdashboard::executor::ExternalEffectError> {
        self.inner.observe_fence(project_id)
    }

    fn acquire_fence(
        &self,
        lease: &rdashboard::store::FenceLease,
    ) -> Result<(), rdashboard::executor::ExternalEffectError> {
        self.inner.acquire_fence(lease)
    }

    fn release_fence(
        &self,
        lease: &rdashboard::store::FenceLease,
    ) -> Result<(), rdashboard::executor::ExternalEffectError> {
        self.inner.release_fence(lease)
    }
}

impl DiskSpaceProbe for FixedDiskSpaceProbe {
    fn observe(
        &self,
        _project_id: &ProjectId,
        now_ms: i64,
    ) -> Result<DiskAvailabilityObservation, StoreError> {
        Ok(disk_observation(self.available_bytes, now_ms))
    }
}

fn deploy_authorization(
    operation: &OperationRecord,
    authorization_id: Uuid,
    expires_at_ms: i64,
) -> ExecutorAuthorization {
    let operation_digest = executor_authorization_digest(operation)
        .unwrap_or_else(|error| panic!("executor authorization digest: {error}"));
    ExecutorAuthorization {
        authorization_id,
        digest: operation_digest.clone(),
        attempt_id: operation.attempt_id,
        project_id: operation.project_id.clone(),
        expires_at_ms,
        disk_reservation: Some(authorized_disk_claim(operation_digest, 30, 100, 10, 100)),
    }
}

fn configure_reservation_artifacts(
    effects: &DeterministicModelEffects,
    operation: &OperationRecord,
    reservation_digest: &EvidenceDigest,
) {
    let release_evidence = |label: &str| {
        EvidenceDigest::sha256(format!(
            "rdashboard.deterministic-release.v1:{label}:{}:{}",
            operation.project_id, operation.attempt_id
        ))
    };
    effects
        .set_phase_artifacts(
            operation.attempt_id,
            OperationPhase::Testing,
            PhaseArtifacts {
                source_export_digest: Some(release_evidence("source-export")),
                prefetch_evidence_digest: Some(release_evidence("prefetch")),
                ci_evidence_digest: Some(release_evidence("ci")),
                build_context_digest: Some(release_evidence("context")),
                resource_reservation_digest: Some(reservation_digest.clone()),
                base_image_digests: vec![release_evidence("base-image")],
                ..PhaseArtifacts::default()
            },
        )
        .unwrap_or_else(|error| panic!("configure testing reservation evidence: {error}"));
    effects
        .set_phase_artifacts(
            operation.attempt_id,
            OperationPhase::Preflight,
            PhaseArtifacts {
                resource_reservation_digest: Some(reservation_digest.clone()),
                ..PhaseArtifacts::default()
            },
        )
        .unwrap_or_else(|error| panic!("configure preflight reservation evidence: {error}"));
}

fn disk_test_authorization(
    project_id: ProjectId,
    attempt_id: Uuid,
    label: &str,
    required_bytes: u64,
    available_bytes: u64,
) -> ExecutorAuthorization {
    let operation_digest = digest(&format!("{label} operation"));
    ExecutorAuthorization {
        authorization_id: Uuid::new_v4(),
        digest: operation_digest.clone(),
        attempt_id,
        project_id,
        expires_at_ms: 10_000,
        disk_reservation: Some(authorized_disk_claim(
            operation_digest,
            required_bytes,
            available_bytes,
            if required_bytes > 10 {
                10
            } else {
                required_bytes / 2
            },
            100,
        )),
    }
}

fn operation(target_commit: GitCommitId) -> NewOperation {
    operation_for(project(), target_commit)
}

fn operation_for(project_id: ProjectId, target_commit: GitCommitId) -> NewOperation {
    NewOperation {
        project_id,
        operation_kind: OperationKind::Deploy,
        target_commit: Some(target_commit),
        release_class: Some(ReleaseClass::CodeOnlyCompatible),
        installed_policy: InstalledPolicyIdentity {
            digest: digest("installed policy"),
            version: 1,
        },
    }
}

fn source_broker(
    source_path: PathBuf,
    operation: &NewOperation,
    delivery_id: &str,
    started_at_ms: i64,
) -> DurableSourceBroker<DeterministicSourceRepository> {
    source_broker_with_repository(source_path, operation, delivery_id, started_at_ms).0
}

fn source_broker_with_repository(
    source_path: PathBuf,
    operation: &NewOperation,
    delivery_id: &str,
    started_at_ms: i64,
) -> (
    DurableSourceBroker<DeterministicSourceRepository>,
    DeterministicSourceRepository,
) {
    let repository = DeterministicSourceRepository::default();
    repository
        .set_repository_identity(
            &operation.project_id,
            digest("executor repository identity"),
        )
        .unwrap_or_else(|error| panic!("set executor repository identity: {error}"));
    let target = operation
        .target_commit
        .as_ref()
        .unwrap_or_else(|| panic!("executor source fixture requires a target"));
    repository
        .insert_commit(&operation.project_id, target, None)
        .unwrap_or_else(|error| panic!("insert executor source: {error}"));
    let broker = DurableSourceBroker::new(
        SourceStore::open(source_path)
            .unwrap_or_else(|error| panic!("executor source store: {error}")),
        repository.clone(),
        "executor-test-source",
        ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]),
        60_000,
        vec![InstalledSourceProjectPolicy {
            project_id: operation.project_id.clone(),
            repository_identity: digest("executor repository identity"),
            installed_policy: operation.installed_policy.clone(),
            auto_deploy: true,
            maximum_attempts: 3,
            release_class: operation
                .release_class
                .unwrap_or_else(|| panic!("executor source fixture requires release class")),
        }],
        started_at_ms,
    )
    .unwrap_or_else(|error| panic!("executor source broker: {error}"));
    broker
        .process_direct_push(
            &operation.project_id,
            delivery_id,
            "refs/heads/main",
            None,
            target.clone(),
            started_at_ms + 1,
        )
        .unwrap_or_else(|error| panic!("accept executor source: {error}"));
    (broker, repository)
}

#[derive(Debug)]
struct DeterministicLiveSourceGate;

impl LiveSourceGate for DeterministicLiveSourceGate {
    fn check_live(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<SourceGateProof, SourceGateError> {
        let sequence = operation
            .evidence
            .source_sequence
            .ok_or(SourceGateError::AttestationInvalid)?;
        let attestation_digest = operation
            .evidence
            .source_attestation_digest
            .clone()
            .ok_or(SourceGateError::AttestationInvalid)?;
        Ok(SourceGateProof {
            digest: digest(&format!(
                "test-live-source-proof-{}-{sequence}",
                operation.attempt_id
            )),
            project_id: operation.project_id.clone(),
            sequence,
            attestation_digest,
            checked_at_ms: now_ms,
        })
    }
}

#[derive(Debug)]
struct FailCompletionSourceGate;

impl LiveSourceGate for FailCompletionSourceGate {
    fn check_live(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<SourceGateProof, SourceGateError> {
        DeterministicLiveSourceGate.check_live(operation, now_ms)
    }

    fn complete_live(&self, _operation: &OperationRecord) -> Result<(), SourceGateError> {
        Err(SourceGateError::Unavailable)
    }
}

#[derive(Debug)]
struct FailCompleteOnceSourceGate {
    inner: DurableSourceBroker<DeterministicSourceRepository>,
    fail_next_completion: Mutex<bool>,
}

impl FailCompleteOnceSourceGate {
    fn new(inner: DurableSourceBroker<DeterministicSourceRepository>) -> Self {
        Self {
            inner,
            fail_next_completion: Mutex::new(true),
        }
    }
}

impl LiveSourceGate for FailCompleteOnceSourceGate {
    fn check_live(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<SourceGateProof, SourceGateError> {
        self.inner.check_live(operation, now_ms)
    }

    fn complete_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        let should_fail = {
            let mut fail_next = self
                .fail_next_completion
                .lock()
                .map_err(|_| SourceGateError::Unavailable)?;
            std::mem::replace(&mut *fail_next, false)
        };
        if should_fail {
            return Err(SourceGateError::Unavailable);
        }
        self.inner.complete_live(operation)
    }

    fn abort_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        self.inner.abort_live(operation)
    }
}

#[derive(Debug)]
struct CountingCompletionSourceGate {
    inner: DurableSourceBroker<DeterministicSourceRepository>,
    completions: Mutex<u32>,
}

impl CountingCompletionSourceGate {
    fn new(inner: DurableSourceBroker<DeterministicSourceRepository>) -> Self {
        Self {
            inner,
            completions: Mutex::new(0),
        }
    }

    fn completions(&self) -> u32 {
        *self
            .completions
            .lock()
            .unwrap_or_else(|_| panic!("completion counter poisoned"))
    }
}

impl LiveSourceGate for CountingCompletionSourceGate {
    fn check_live(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<SourceGateProof, SourceGateError> {
        self.inner.check_live(operation, now_ms)
    }

    fn complete_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        let mut completions = self
            .completions
            .lock()
            .map_err(|_| SourceGateError::Unavailable)?;
        *completions += 1;
        drop(completions);
        self.inner.complete_live(operation)
    }

    fn abort_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        self.inner.abort_live(operation)
    }
}

#[derive(Debug)]
struct FailSecondCheckSourceGate {
    inner: DurableSourceBroker<DeterministicSourceRepository>,
    checks: Mutex<u32>,
    failure: SourceGateError,
}

impl FailSecondCheckSourceGate {
    fn new(
        inner: DurableSourceBroker<DeterministicSourceRepository>,
        failure: SourceGateError,
    ) -> Self {
        Self {
            inner,
            checks: Mutex::new(0),
            failure,
        }
    }
}

impl LiveSourceGate for FailSecondCheckSourceGate {
    fn check_live(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<SourceGateProof, SourceGateError> {
        let check_number = {
            let mut checks = self
                .checks
                .lock()
                .map_err(|_| SourceGateError::Unavailable)?;
            *checks += 1;
            *checks
        };
        if check_number == 2 {
            Err(self.failure)
        } else {
            self.inner.check_live(operation, now_ms)
        }
    }

    fn complete_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        self.inner.complete_live(operation)
    }

    fn abort_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        self.inner.abort_live(operation)
    }
}

#[derive(Debug)]
struct AmbiguousFirstAdmissionSourceGate {
    inner: DurableSourceBroker<DeterministicSourceRepository>,
    fail_next_check_after_ticket: Mutex<bool>,
    fail_next_abort: Mutex<bool>,
}

impl AmbiguousFirstAdmissionSourceGate {
    fn new(inner: DurableSourceBroker<DeterministicSourceRepository>) -> Self {
        Self {
            inner,
            fail_next_check_after_ticket: Mutex::new(true),
            fail_next_abort: Mutex::new(true),
        }
    }
}

impl LiveSourceGate for AmbiguousFirstAdmissionSourceGate {
    fn check_live(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<SourceGateProof, SourceGateError> {
        let fail_after_ticket = {
            let mut fail_next = self
                .fail_next_check_after_ticket
                .lock()
                .map_err(|_| SourceGateError::Unavailable)?;
            std::mem::replace(&mut *fail_next, false)
        };
        let proof = self.inner.check_live(operation, now_ms)?;
        if fail_after_ticket {
            Err(SourceGateError::Unavailable)
        } else {
            Ok(proof)
        }
    }

    fn complete_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        self.inner.complete_live(operation)
    }

    fn abort_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        let should_fail = {
            let mut fail_next = self
                .fail_next_abort
                .lock()
                .map_err(|_| SourceGateError::Unavailable)?;
            std::mem::replace(&mut *fail_next, false)
        };
        if should_fail {
            Err(SourceGateError::Unavailable)
        } else {
            self.inner.abort_live(operation)
        }
    }
}

#[derive(Debug)]
struct RejectFirstProofAbortOnceSourceGate {
    inner: DurableSourceBroker<DeterministicSourceRepository>,
    reject_next_proof: Mutex<bool>,
    fail_next_abort: Mutex<bool>,
}

impl RejectFirstProofAbortOnceSourceGate {
    fn new(inner: DurableSourceBroker<DeterministicSourceRepository>) -> Self {
        Self {
            inner,
            reject_next_proof: Mutex::new(true),
            fail_next_abort: Mutex::new(true),
        }
    }
}

impl LiveSourceGate for RejectFirstProofAbortOnceSourceGate {
    fn check_live(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<SourceGateProof, SourceGateError> {
        let mut proof = self.inner.check_live(operation, now_ms)?;
        let should_reject = {
            let mut reject_next = self
                .reject_next_proof
                .lock()
                .map_err(|_| SourceGateError::Unavailable)?;
            std::mem::replace(&mut *reject_next, false)
        };
        if should_reject {
            proof.sequence = 0;
        }
        Ok(proof)
    }

    fn complete_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        self.inner.complete_live(operation)
    }

    fn abort_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        let should_fail = {
            let mut fail_next = self
                .fail_next_abort
                .lock()
                .map_err(|_| SourceGateError::Unavailable)?;
            std::mem::replace(&mut *fail_next, false)
        };
        if should_fail {
            Err(SourceGateError::Unavailable)
        } else {
            self.inner.abort_live(operation)
        }
    }
}

struct ExecutionFixture {
    _directory: TempDir,
    controller: DurableController,
    security_path: PathBuf,
    effects: DeterministicModelEffects,
    operation: OperationRecord,
    source_broker: DurableSourceBroker<DeterministicSourceRepository>,
    source_repository: DeterministicSourceRepository,
}

fn execution_fixture_with_class(target: char, release_class: ReleaseClass) -> ExecutionFixture {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let user_id = Uuid::new_v4();
    let lease = controller
        .takeover_lease(user_id, Uuid::new_v4(), 100, 10_000)
        .unwrap_or_else(|error| panic!("tab lease: {error}"));
    let mut operation_request = operation(commit(target));
    operation_request.release_class = Some(release_class);
    let grant = ActionGrantClaims {
        nonce: Uuid::new_v4(),
        digest: digest(&format!("grant-{target}")),
        user_id,
        project_id: operation_request.project_id.clone(),
        operation_kind: operation_request.operation_kind,
        target_commit: operation_request.target_commit.clone(),
        retry_request_id: None,
        expires_at_ms: 10_000,
    };
    let (broker, source_repository) = source_broker_with_repository(
        directory.path().join("source.sqlite"),
        &operation_request,
        "fixture-source",
        90,
    );
    let admitted = broker
        .admit_recorded_interactive_deploy(
            &controller,
            &operation_request.project_id,
            SourceChannel::DirectPush,
            "fixture-source",
            &TabLeaseClaim {
                user_id,
                lease_id: lease.lease_id,
                generation: lease.generation,
            },
            &grant,
            101,
        )
        .unwrap_or_else(|error| panic!("admit operation: {error}"))
        .operation()
        .clone();
    let security_path = directory.path().join("security.sqlite");
    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("security store: {error}"));
    let authorization = deploy_authorization(&admitted, grant.nonce, grant.expires_at_ms);
    security
        .authorize_attempt(&authorization, 102)
        .unwrap_or_else(|error| panic!("executor authorization: {error}"));
    let effects = DeterministicModelEffects::default();
    configure_reservation_artifacts(
        &effects,
        &admitted,
        &authorization
            .disk_reservation
            .as_ref()
            .unwrap_or_else(|| panic!("deploy reservation claim is missing"))
            .reservation_digest,
    );
    drop(security);
    ExecutionFixture {
        _directory: directory,
        controller,
        security_path,
        effects,
        operation: admitted,
        source_broker: broker,
        source_repository,
    }
}

fn execution_fixture(target: char) -> ExecutionFixture {
    execution_fixture_with_class(target, ReleaseClass::CodeOnlyCompatible)
}

fn backup_preflight_fixture(
    project_id: ProjectId,
    disk_claim: Option<(u64, u64)>,
    live_available_bytes: Option<u64>,
) -> (
    TempDir,
    DurableExecutor<DeterministicModelEffects>,
    OperationRecord,
) {
    let directory = tempdir().unwrap_or_else(|error| panic!("backup temp dir: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("backup control store: {error}")),
    );
    let user_id = Uuid::new_v4();
    let lease = controller
        .takeover_lease(user_id, Uuid::new_v4(), 100, 10_000)
        .unwrap_or_else(|error| panic!("backup tab lease: {error}"));
    let request = NewOperation {
        project_id,
        operation_kind: OperationKind::BackupOnly,
        target_commit: None,
        release_class: None,
        installed_policy: InstalledPolicyIdentity {
            digest: digest("backup installed policy"),
            version: 1,
        },
    };
    let grant = ActionGrantClaims {
        nonce: Uuid::new_v4(),
        digest: digest("backup action grant"),
        user_id,
        project_id: request.project_id.clone(),
        operation_kind: request.operation_kind,
        target_commit: None,
        retry_request_id: None,
        expires_at_ms: 10_000,
    };
    let admitted = controller
        .admit_interactive(
            &request,
            &TabLeaseClaim {
                user_id,
                lease_id: lease.lease_id,
                generation: lease.generation,
            },
            &grant,
            101,
        )
        .unwrap_or_else(|error| panic!("admit backup: {error}"))
        .operation()
        .clone();
    let operation_digest = executor_authorization_digest(&admitted)
        .unwrap_or_else(|error| panic!("backup authorization digest: {error}"));
    let disk_reservation = disk_claim.map(|(required_bytes, available_bytes)| {
        authorized_disk_claim(
            operation_digest.clone(),
            required_bytes,
            available_bytes,
            10,
            100,
        )
    });
    let security = SecurityStore::open(directory.path().join("security.sqlite"))
        .unwrap_or_else(|error| panic!("backup security store: {error}"));
    security
        .authorize_attempt(
            &ExecutorAuthorization {
                authorization_id: grant.nonce,
                digest: operation_digest,
                attempt_id: admitted.attempt_id,
                project_id: admitted.project_id.clone(),
                expires_at_ms: grant.expires_at_ms,
                disk_reservation: disk_reservation.clone(),
            },
            102,
        )
        .unwrap_or_else(|error| panic!("authorize backup: {error}"));
    let effects = DeterministicModelEffects::default();
    if let Some(claim) = &disk_reservation {
        configure_reservation_artifacts(&effects, &admitted, &claim.reservation_digest);
    }
    let mut executor = DurableExecutor::new(security, effects);
    if let Some(available_bytes) = live_available_bytes {
        executor =
            executor.with_disk_space_probe(Arc::new(FixedDiskSpaceProbe { available_bytes }));
    }
    executor
        .recover_security_state(std::slice::from_ref(&admitted.project_id), 103)
        .unwrap_or_else(|error| panic!("recover backup executor: {error}"));
    let queued = executor
        .execute_phase(&admitted, None, 104)
        .unwrap_or_else(|error| panic!("execute backup queue: {error}"));
    let preflight = controller
        .commit_phase_receipt(&queued, 105)
        .unwrap_or_else(|error| panic!("project backup preflight: {error}"));
    (directory, executor, preflight)
}

fn reopen_security(path: &PathBuf) -> SecurityStore {
    SecurityStore::open(path).unwrap_or_else(|error| panic!("reopen security store: {error}"))
}

fn security_journal_status(path: &PathBuf, attempt_id: Uuid, phase: &str) -> String {
    rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("inspect security journal: {error}"))
        .query_row(
            "SELECT status FROM executor_phase_journal
             WHERE attempt_id = ?1 AND phase = ?2",
            rusqlite::params![attempt_id.to_string(), phase],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("read security journal status: {error}"))
}

fn recovered_executor(
    security: SecurityStore,
    effects: DeterministicModelEffects,
    project_id: &ProjectId,
) -> DurableExecutor<DeterministicModelEffects> {
    recovered_executor_for_projects(security, effects, std::slice::from_ref(project_id))
}

fn recovered_executor_for_projects(
    security: SecurityStore,
    effects: DeterministicModelEffects,
    project_ids: &[ProjectId],
) -> DurableExecutor<DeterministicModelEffects> {
    let executor = DurableExecutor::new(security, effects)
        .with_source_gate(Arc::new(DeterministicLiveSourceGate))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(project_ids, 103)
        .unwrap_or_else(|error| panic!("recover executor security state: {error}"));
    executor
}

#[test]
fn security_recovery_is_project_scoped_and_failed_reruns_revoke_the_project() {
    let (directory, _coordinator, first, second) =
        two_operation_coordinator(&[named_project("rimg"), named_project("keyroom")]);
    let effects = DeterministicModelEffects::default();
    let executor = DurableExecutor::new(
        SecurityStore::open(directory.path().join("security.sqlite"))
            .unwrap_or_else(|error| panic!("reopen security store: {error}")),
        effects.clone(),
    )
    .with_source_gate(Arc::new(DeterministicLiveSourceGate))
    .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&first.project_id), 200)
        .unwrap_or_else(|error| panic!("recover first project: {error}"));

    assert!(matches!(
        executor.execute_phase(&second, None, 201),
        Err(PhaseExecutionError::Store(
            StoreError::SecurityRecoveryRequired
        ))
    ));

    effects
        .force_fence(first.project_id.clone(), Uuid::new_v4(), 1, Uuid::new_v4())
        .unwrap_or_else(|error| panic!("force conflicting fence: {error}"));
    assert!(matches!(
        executor.recover_security_state(std::slice::from_ref(&first.project_id), 202),
        Err(FenceExecutionError::NeedsReconcile)
    ));
    assert!(matches!(
        executor.execute_phase(&first, None, 203),
        Err(PhaseExecutionError::Store(
            StoreError::SecurityRecoveryRequired
        ))
    ));
}

#[test]
fn recovering_one_project_ignores_another_projects_bad_fence_until_global_reconcile() {
    let (directory, _coordinator, first, second) =
        two_operation_coordinator(&[named_project("rimg"), named_project("keyroom")]);
    let security = SecurityStore::open(directory.path().join("security.sqlite"))
        .unwrap_or_else(|error| panic!("reopen security store: {error}"));
    prepare_fence_prerequisites(&security, &second, 200);
    let effects = DeterministicModelEffects::default();
    let executor = DurableExecutor::new(security.clone(), effects.clone())
        .with_source_gate(Arc::new(DeterministicLiveSourceGate))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(&[first.project_id.clone(), second.project_id.clone()], 201)
        .unwrap_or_else(|error| panic!("initial project recovery: {error}"));
    executor
        .acquire_write_fence(&second.project_id, second.attempt_id, None, 202)
        .unwrap_or_else(|error| panic!("acquire second-project fence: {error}"));
    executor
        .recover_security_state(&[first.project_id.clone(), second.project_id.clone()], 203)
        .unwrap_or_else(|error| panic!("recover held second-project fence: {error}"));
    effects
        .force_fence(
            second.project_id.clone(),
            Uuid::new_v4(),
            9_999,
            Uuid::new_v4(),
        )
        .unwrap_or_else(|error| panic!("force second-project fence mismatch: {error}"));

    executor
        .recover_security_state(std::slice::from_ref(&first.project_id), 204)
        .unwrap_or_else(|error| panic!("recover only unaffected project: {error}"));
    executor
        .execute_phase(&first, None, 205)
        .unwrap_or_else(|error| panic!("execute unaffected project: {error}"));

    assert!(matches!(
        executor.reconcile_active_fences(206),
        Err(FenceExecutionError::NeedsReconcile)
    ));
    assert!(matches!(
        executor.execute_phase(&second, None, 207),
        Err(PhaseExecutionError::Store(
            StoreError::SecurityRecoveryRequired
        ))
    ));
}

#[test]
fn project_gate_blocks_same_project_recovery_without_serializing_other_projects() {
    let (directory, existing_coordinator, first, second) =
        two_operation_coordinator(&[named_project("gate-first"), named_project("gate-second")]);
    drop(existing_coordinator);
    let effects = BlockingProjectEffects::new(first.project_id.clone());
    let executor = DurableExecutor::new(
        SecurityStore::open(directory.path().join("security.sqlite"))
            .unwrap_or_else(|error| panic!("gate security store: {error}")),
        effects.clone(),
    )
    .with_source_gate(Arc::new(DeterministicLiveSourceGate))
    .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(&[first.project_id.clone(), second.project_id.clone()], 200)
        .unwrap_or_else(|error| panic!("recover gate projects: {error}"));

    let first_executor = executor.clone();
    let first_operation = first.clone();
    let first_worker = thread::spawn(move || {
        first_executor
            .execute_phase(&first_operation, None, 201)
            .map(|_| ())
            .map_err(|error| error.to_string())
    });
    effects.wait_until_blocked();

    let (started_sender, started_receiver) = mpsc::channel();
    let (recovered_sender, recovered_receiver) = mpsc::channel();
    let recovery_executor = executor.clone();
    let recovery_project = first.project_id.clone();
    let recovery_worker = thread::spawn(move || {
        started_sender
            .send(())
            .unwrap_or_else(|error| panic!("signal recovery start: {error}"));
        let result = recovery_executor
            .recover_security_state(std::slice::from_ref(&recovery_project), 202)
            .map_err(|error| error.to_string());
        recovered_sender
            .send(result)
            .unwrap_or_else(|error| panic!("signal recovery result: {error}"));
    });
    started_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("recovery worker did not start: {error}"));

    executor
        .execute_phase(&second, None, 203)
        .unwrap_or_else(|error| panic!("execute other project while first is blocked: {error}"));
    assert!(matches!(
        recovered_receiver.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));

    effects.release();
    first_worker
        .join()
        .unwrap_or_else(|_| panic!("first project worker panicked"))
        .unwrap_or_else(|error| panic!("first project execution failed: {error}"));
    recovered_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("same-project recovery did not finish: {error}"))
        .unwrap_or_else(|error| panic!("same-project recovery failed: {error}"));
    recovery_worker
        .join()
        .unwrap_or_else(|_| panic!("recovery worker panicked"));
}

#[test]
fn every_phase_crash_boundary_recovers_without_duplicate_mutation() {
    let crash_points = [
        PhaseCrashPoint::AfterIntentPersisted,
        PhaseCrashPoint::AfterEffectApplied,
        PhaseCrashPoint::AfterObservationPersisted,
        PhaseCrashPoint::AfterVerificationPersisted,
        PhaseCrashPoint::AfterReceiptCommitted,
    ];
    for (index, crash_point) in crash_points.into_iter().enumerate() {
        let target = char::from(b'a' + u8::try_from(index).unwrap_or(0));
        let fixture = execution_fixture(target);
        let executor = recovered_executor(
            reopen_security(&fixture.security_path),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        );
        assert!(matches!(
            executor.execute_phase(&fixture.operation, Some(crash_point), 200),
            Err(PhaseExecutionError::InjectedCrash(actual)) if actual == crash_point
        ));
        drop(executor);

        let recovered_security = reopen_security(&fixture.security_path);
        let recovered = recovered_executor(
            recovered_security.clone(),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        );
        let receipt = recovered
            .execute_phase(&fixture.operation, None, 201)
            .unwrap_or_else(|error| panic!("recover {crash_point:?}: {error}"));
        assert_eq!(receipt.phase, OperationPhase::Queued);
        let projected = fixture
            .controller
            .commit_phase_receipt(&receipt, 202)
            .unwrap_or_else(|error| panic!("project recovered receipt: {error}"));
        assert_eq!(projected.state.phase, OperationPhase::SyncingSource);
        assert_eq!(
            fixture
                .effects
                .phase_mutations(fixture.operation.attempt_id, OperationPhase::Queued)
                .unwrap_or_else(|error| panic!("mutation count: {error}")),
            1
        );
        assert_eq!(
            recovered_security
                .phase_entry(fixture.operation.attempt_id, OperationPhase::Queued)
                .unwrap_or_else(|error| panic!("phase journal: {error}"))
                .map(|entry| entry.status),
            Some(PhaseJournalStatus::Committed)
        );
    }
}

#[test]
fn crash_after_live_effect_keeps_source_ticket_until_recovery_completes() {
    let fixture = execution_fixture('e');
    let mut operation = fixture.operation.clone();
    let effects = fixture.effects.clone();
    let executor = DurableExecutor::new(reopen_security(&fixture.security_path), effects.clone())
        .with_source_gate(Arc::new(fixture.source_broker.clone()))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&operation.project_id), 200)
        .unwrap_or_else(|error| panic!("recover executor: {error}"));
    let mut now_ms = 201;
    while operation.state.phase != OperationPhase::Deploying {
        let receipt = executor
            .execute_phase(&operation, None, now_ms)
            .unwrap_or_else(|error| panic!("execute {:?}: {error}", operation.state.phase));
        operation = fixture
            .controller
            .commit_phase_receipt(&receipt, now_ms + 1)
            .unwrap_or_else(|error| panic!("project {:?}: {error}", operation.state.phase));
        now_ms += 2;
    }
    assert!(matches!(
        executor.execute_phase(
            &operation,
            Some(PhaseCrashPoint::AfterEffectApplied),
            now_ms,
        ),
        Err(PhaseExecutionError::InjectedCrash(
            PhaseCrashPoint::AfterEffectApplied
        ))
    ));

    let old_head = operation
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("deploy target is missing"));
    let new_head = commit('f');
    fixture
        .source_repository
        .insert_commit(&operation.project_id, &new_head, Some(old_head.clone()))
        .unwrap_or_else(|error| panic!("insert next source: {error}"));
    assert!(matches!(
        fixture.source_broker.process_direct_push(
            &operation.project_id,
            "after-effect-source",
            "refs/heads/main",
            Some(&old_head),
            new_head.clone(),
            now_ms + 1,
        ),
        Err(rdashboard::source::SourceError::MutationAdmissionBusy)
    ));

    drop(executor);
    let recovered = DurableExecutor::new(reopen_security(&fixture.security_path), effects)
        .with_source_gate(Arc::new(fixture.source_broker.clone()))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    recovered
        .recover_security_state(std::slice::from_ref(&operation.project_id), now_ms + 2)
        .unwrap_or_else(|error| panic!("recover after effect crash: {error}"));
    recovered
        .execute_phase(&operation, None, now_ms + 3)
        .unwrap_or_else(|error| panic!("complete recovered deploy: {error}"));
    assert!(matches!(
        fixture
            .source_broker
            .process_direct_push(
                &operation.project_id,
                "after-effect-source",
                "refs/heads/main",
                Some(&old_head),
                new_head,
                now_ms + 4,
            )
            .unwrap_or_else(|error| panic!("accept source after recovery: {error}")),
        rdashboard::source::SourceIngressOutcome::Deployable(_)
    ));
}

#[test]
fn committed_live_receipt_replay_releases_the_source_ticket_idempotently() {
    let fixture = execution_fixture('8');
    let mut operation = fixture.operation.clone();
    let executor = DurableExecutor::new(
        reopen_security(&fixture.security_path),
        fixture.effects.clone(),
    )
    .with_source_gate(Arc::new(fixture.source_broker.clone()))
    .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&operation.project_id), 200)
        .unwrap_or_else(|error| panic!("recover executor: {error}"));
    let mut now_ms = 201;
    while operation.state.phase != OperationPhase::Deploying {
        let receipt = executor
            .execute_phase(&operation, None, now_ms)
            .unwrap_or_else(|error| panic!("execute {:?}: {error}", operation.state.phase));
        operation = fixture
            .controller
            .commit_phase_receipt(&receipt, now_ms + 1)
            .unwrap_or_else(|error| panic!("project {:?}: {error}", operation.state.phase));
        now_ms += 2;
    }
    assert!(matches!(
        executor.execute_phase(
            &operation,
            Some(PhaseCrashPoint::AfterReceiptCommitted),
            now_ms,
        ),
        Err(PhaseExecutionError::InjectedCrash(
            PhaseCrashPoint::AfterReceiptCommitted
        ))
    ));

    let old_head = operation
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("deploy target is missing"));
    let new_head = commit('9');
    fixture
        .source_repository
        .insert_commit(&operation.project_id, &new_head, Some(old_head.clone()))
        .unwrap_or_else(|error| panic!("insert next source: {error}"));
    assert!(matches!(
        fixture.source_broker.process_direct_push(
            &operation.project_id,
            "after-receipt-source",
            "refs/heads/main",
            Some(&old_head),
            new_head.clone(),
            now_ms + 1,
        ),
        Err(rdashboard::source::SourceError::MutationAdmissionBusy)
    ));

    drop(executor);
    let recovered = DurableExecutor::new(
        reopen_security(&fixture.security_path),
        fixture.effects.clone(),
    )
    .with_source_gate(Arc::new(fixture.source_broker.clone()))
    .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    recovered
        .recover_security_state(std::slice::from_ref(&operation.project_id), now_ms + 2)
        .unwrap_or_else(|error| panic!("recover after receipt crash: {error}"));
    recovered
        .execute_phase(&operation, None, now_ms + 3)
        .unwrap_or_else(|error| panic!("replay committed deploy receipt: {error}"));
    assert!(matches!(
        fixture
            .source_broker
            .process_direct_push(
                &operation.project_id,
                "after-receipt-source",
                "refs/heads/main",
                Some(&old_head),
                new_head,
                now_ms + 4,
            )
            .unwrap_or_else(|error| panic!("accept source after receipt replay: {error}")),
        rdashboard::source::SourceIngressOutcome::Deployable(_)
    ));
}

#[test]
fn reconciliation_retries_ticket_completion_after_the_receipt_is_committed() {
    let fixture = execution_fixture('7');
    let security = reopen_security(&fixture.security_path);
    let executor = DurableExecutor::new(security, fixture.effects.clone())
        .with_source_gate(Arc::new(FailCompleteOnceSourceGate::new(
            fixture.source_broker.clone(),
        )))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&fixture.operation.project_id), 200)
        .unwrap_or_else(|error| panic!("recover executor: {error}"));
    let coordinator = DurableCoordinator::new(fixture.controller.clone(), executor);
    let mut operation = fixture.operation.clone();
    let mut now_ms = 201;
    while operation.state.phase != OperationPhase::Deploying {
        operation = coordinator
            .advance_once(operation.attempt_id, None, None, now_ms)
            .unwrap_or_else(|error| panic!("advance {:?}: {error}", operation.state.phase));
        now_ms += 1;
    }
    operation = coordinator
        .advance_once(operation.attempt_id, None, None, now_ms)
        .unwrap_or_else(|error| panic!("commit deploy receipt: {error}"));
    assert_eq!(operation.state.phase, OperationPhase::Reconciliation);

    let old_head = operation
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("deploy target is missing"));
    let new_head = commit('8');
    fixture
        .source_repository
        .insert_commit(&operation.project_id, &new_head, Some(old_head.clone()))
        .unwrap_or_else(|error| panic!("insert next source: {error}"));
    assert!(matches!(
        fixture.source_broker.process_direct_push(
            &operation.project_id,
            "after-reconciliation-completion",
            "refs/heads/main",
            Some(&old_head),
            new_head.clone(),
            now_ms + 1,
        ),
        Err(rdashboard::source::SourceError::MutationAdmissionBusy)
    ));

    let reconciled = coordinator
        .advance_once(operation.attempt_id, None, None, now_ms + 2)
        .unwrap_or_else(|error| panic!("retry committed source completion: {error}"));
    assert_eq!(reconciled.state.phase, OperationPhase::HealthChecking);
    assert_eq!(reconciled.state.blocking_reason, BlockingReason::None);
    assert_eq!(reconciled.evidence.recovery_mode, None);
    assert_eq!(reconciled.failure_capsule, None);
    assert!(matches!(
        fixture
            .source_broker
            .process_direct_push(
                &operation.project_id,
                "after-reconciliation-completion",
                "refs/heads/main",
                Some(&old_head),
                new_head,
                now_ms + 3,
            )
            .unwrap_or_else(|error| panic!("accept source after reconciliation cleanup: {error}")),
        rdashboard::source::SourceIngressOutcome::Deployable(_)
    ));
    assert_eq!(
        fixture
            .effects
            .phase_application_attempts(operation.attempt_id, OperationPhase::Deploying)
            .unwrap_or_else(|error| panic!("deploy attempts: {error}")),
        1
    );
}

#[test]
fn later_reconciliation_does_not_replay_a_stale_source_completion_receipt() {
    let fixture = execution_fixture('8');
    let security = reopen_security(&fixture.security_path);
    let source_gate = Arc::new(CountingCompletionSourceGate::new(
        fixture.source_broker.clone(),
    ));
    let executor = DurableExecutor::new(security.clone(), fixture.effects.clone())
        .with_source_gate(source_gate.clone())
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&fixture.operation.project_id), 200)
        .unwrap_or_else(|error| panic!("recover executor: {error}"));
    let coordinator = DurableCoordinator::new(fixture.controller.clone(), executor);
    let mut operation = fixture.operation.clone();
    let mut now_ms = 201;
    while operation.state.phase != OperationPhase::HealthChecking {
        operation = coordinator
            .advance_once(operation.attempt_id, None, None, now_ms)
            .unwrap_or_else(|error| panic!("advance {:?}: {error}", operation.state.phase));
        now_ms += 1;
    }
    assert_eq!(source_gate.completions(), 1);
    let deploy_receipt = security
        .phase_receipt(operation.attempt_id, OperationPhase::Deploying)
        .unwrap_or_else(|error| panic!("load deploy receipt: {error}"))
        .unwrap_or_else(|| panic!("deploy receipt is missing"));
    let reconciled = fixture
        .controller
        .mark_needs_reconcile(
            operation.attempt_id,
            FailureCapsule {
                schema_version: 1,
                failing_step: "health_checking".to_owned(),
                error: StructuredError {
                    code: "health_observation_ambiguous".to_owned(),
                    summary: "Health evidence requires reconciliation".to_owned(),
                    retryability: Retryability::OperatorRunbook,
                    runbook_id: None,
                },
                excerpt: "Reconcile the later health phase without replaying deploy completion."
                    .to_owned(),
                truncated: false,
            },
            now_ms,
        )
        .unwrap_or_else(|error| panic!("mark later reconciliation: {error}"));
    assert_eq!(reconciled.state.phase, OperationPhase::Reconciliation);
    assert!(matches!(
        fixture
            .controller
            .commit_reconciled_phase_receipt(&deploy_receipt, now_ms + 1),
        Err(StoreError::ReceiptMismatch)
    ));

    let still_reconciling = coordinator
        .advance_once(operation.attempt_id, None, None, now_ms + 2)
        .unwrap_or_else(|error| panic!("settle later reconciliation: {error}"));
    assert_eq!(
        still_reconciling.state.phase,
        OperationPhase::Reconciliation
    );
    assert_eq!(source_gate.completions(), 1);
}

#[test]
fn missing_post_apply_observation_keeps_source_ticket_and_forbids_retry() {
    let fixture = execution_fixture('a');
    let mut operation = fixture.operation.clone();
    let security = reopen_security(&fixture.security_path);
    let executor = DurableExecutor::new(security.clone(), fixture.effects.clone())
        .with_source_gate(Arc::new(fixture.source_broker.clone()))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&operation.project_id), 200)
        .unwrap_or_else(|error| panic!("recover executor: {error}"));
    let mut now_ms = 201;
    while operation.state.phase != OperationPhase::Deploying {
        let receipt = executor
            .execute_phase(&operation, None, now_ms)
            .unwrap_or_else(|error| panic!("execute {:?}: {error}", operation.state.phase));
        operation = fixture
            .controller
            .commit_phase_receipt(&receipt, now_ms + 1)
            .unwrap_or_else(|error| panic!("project {:?}: {error}", operation.state.phase));
        now_ms += 2;
    }
    fixture
        .effects
        .hide_next_applied_phase_observation(operation.attempt_id, OperationPhase::Deploying)
        .unwrap_or_else(|error| panic!("hide post-apply observation: {error}"));

    assert!(matches!(
        executor.execute_phase(&operation, None, now_ms),
        Err(PhaseExecutionError::NeedsReconcile)
    ));
    assert_eq!(
        security
            .phase_entry(operation.attempt_id, OperationPhase::Deploying)
            .unwrap_or_else(|error| panic!("deploy journal: {error}"))
            .map(|entry| entry.status),
        Some(PhaseJournalStatus::NeedsReconcile)
    );
    assert_eq!(
        fixture
            .effects
            .phase_application_attempts(operation.attempt_id, OperationPhase::Deploying)
            .unwrap_or_else(|error| panic!("deploy attempts: {error}")),
        1
    );
    assert_eq!(
        fixture
            .effects
            .phase_mutations(operation.attempt_id, OperationPhase::Deploying)
            .unwrap_or_else(|error| panic!("deploy mutations: {error}")),
        1
    );
    assert!(matches!(
        executor.execute_phase(&operation, None, now_ms + 1),
        Err(PhaseExecutionError::NeedsReconcile)
    ));
    assert_eq!(
        fixture
            .effects
            .phase_application_attempts(operation.attempt_id, OperationPhase::Deploying)
            .unwrap_or_else(|error| panic!("deploy retry attempts: {error}")),
        1
    );

    let old_head = operation
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("deploy target is missing"));
    let new_head = commit('b');
    fixture
        .source_repository
        .insert_commit(&operation.project_id, &new_head, Some(old_head.clone()))
        .unwrap_or_else(|error| panic!("insert next source: {error}"));
    assert!(matches!(
        fixture.source_broker.process_direct_push(
            &operation.project_id,
            "after-ambiguous-observation",
            "refs/heads/main",
            Some(&old_head),
            new_head,
            now_ms + 2,
        ),
        Err(rdashboard::source::SourceError::MutationAdmissionBusy)
    ));
}

#[test]
fn pre_effect_failure_aborts_the_live_source_ticket_only_after_absence_is_observed() {
    let fixture = execution_fixture('6');
    let mut operation = fixture.operation.clone();
    let executor = DurableExecutor::new(
        reopen_security(&fixture.security_path),
        fixture.effects.clone(),
    )
    .with_source_gate(Arc::new(fixture.source_broker.clone()))
    .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&operation.project_id), 200)
        .unwrap_or_else(|error| panic!("recover executor: {error}"));
    let mut now_ms = 201;
    while operation.state.phase != OperationPhase::Deploying {
        let receipt = executor
            .execute_phase(&operation, None, now_ms)
            .unwrap_or_else(|error| panic!("execute {:?}: {error}", operation.state.phase));
        operation = fixture
            .controller
            .commit_phase_receipt(&receipt, now_ms + 1)
            .unwrap_or_else(|error| panic!("project {:?}: {error}", operation.state.phase));
        now_ms += 2;
    }
    fixture
        .effects
        .fail_next_phase_before_effect(operation.attempt_id, OperationPhase::Deploying)
        .unwrap_or_else(|error| panic!("configure pre-effect failure: {error}"));
    assert!(matches!(
        executor.execute_phase(&operation, None, now_ms),
        Err(PhaseExecutionError::External(
            rdashboard::executor::ExternalEffectError::ConflictingState
        ))
    ));

    let old_head = operation
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("deploy target is missing"));
    let new_head = commit('7');
    fixture
        .source_repository
        .insert_commit(&operation.project_id, &new_head, Some(old_head.clone()))
        .unwrap_or_else(|error| panic!("insert next source: {error}"));
    assert!(matches!(
        fixture
            .source_broker
            .process_direct_push(
                &operation.project_id,
                "after-aborted-effect",
                "refs/heads/main",
                Some(&old_head),
                new_head,
                now_ms + 1,
            )
            .unwrap_or_else(|error| panic!("accept source after abort: {error}")),
        rdashboard::source::SourceIngressOutcome::Deployable(_)
    ));
}

#[test]
fn ambiguous_first_source_admission_retries_the_original_phase_without_reconciliation() {
    let fixture = execution_fixture('8');
    let security = reopen_security(&fixture.security_path);
    let executor = DurableExecutor::new(security.clone(), fixture.effects.clone())
        .with_source_gate(Arc::new(AmbiguousFirstAdmissionSourceGate::new(
            fixture.source_broker.clone(),
        )))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&fixture.operation.project_id), 200)
        .unwrap_or_else(|error| panic!("recover ambiguous-admission executor: {error}"));
    let coordinator = DurableCoordinator::new(fixture.controller.clone(), executor);
    let mut clock = 200;
    let deploying = advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::Deploying,
        &mut clock,
    );

    clock += 1;
    let blocked = coordinator
        .advance_once(deploying.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("record ambiguous source admission: {error}"));
    assert_eq!(blocked.state.phase, OperationPhase::Deploying);
    assert_eq!(
        blocked.state.blocking_reason,
        BlockingReason::SourceBrokerUnavailable
    );
    assert_eq!(
        security
            .phase_entry(blocked.attempt_id, OperationPhase::Deploying)
            .unwrap_or_else(|error| panic!("load blocked deploy journal: {error}"))
            .unwrap_or_else(|| panic!("blocked deploy journal is missing"))
            .status,
        PhaseJournalStatus::IntentPersisted
    );

    let old_head = blocked
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("blocked deploy target is missing"));
    let new_head = commit('9');
    fixture
        .source_repository
        .insert_commit(&blocked.project_id, &new_head, Some(old_head.clone()))
        .unwrap_or_else(|error| panic!("insert source during ambiguous admission: {error}"));
    assert!(matches!(
        fixture.source_broker.process_direct_push(
            &blocked.project_id,
            "ambiguous-first-admission",
            "refs/heads/main",
            Some(&old_head),
            new_head.clone(),
            clock + 1,
        ),
        Err(rdashboard::source::SourceError::MutationAdmissionBusy)
    ));

    clock += 1;
    let health_checking = coordinator
        .advance_once(blocked.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("retry ambiguous source admission: {error}"));
    assert_eq!(health_checking.state.phase, OperationPhase::HealthChecking);
    assert_eq!(health_checking.state.blocking_reason, BlockingReason::None);
    assert!(matches!(
        fixture
            .source_broker
            .process_direct_push(
                &health_checking.project_id,
                "ambiguous-first-admission",
                "refs/heads/main",
                Some(&old_head),
                new_head,
                clock + 1,
            )
            .unwrap_or_else(|error| panic!("accept source after admission retry: {error}")),
        rdashboard::source::SourceIngressOutcome::Deployable(_)
    ));
}

#[test]
fn retry_after_ticket_only_crash_aborts_when_the_target_sha_becomes_blocked() {
    let fixture = execution_fixture('1');
    let mut operation = fixture.operation.clone();
    let executor = DurableExecutor::new(
        reopen_security(&fixture.security_path),
        fixture.effects.clone(),
    )
    .with_source_gate(Arc::new(fixture.source_broker.clone()))
    .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&operation.project_id), 200)
        .unwrap_or_else(|error| panic!("recover executor: {error}"));
    let mut now_ms = 201;
    while operation.state.phase != OperationPhase::Deploying {
        let receipt = executor
            .execute_phase(&operation, None, now_ms)
            .unwrap_or_else(|error| panic!("execute {:?}: {error}", operation.state.phase));
        operation = fixture
            .controller
            .commit_phase_receipt(&receipt, now_ms + 1)
            .unwrap_or_else(|error| panic!("project {:?}: {error}", operation.state.phase));
        now_ms += 2;
    }
    fixture
        .source_broker
        .check_live(&operation, now_ms)
        .unwrap_or_else(|error| panic!("acquire crash-only source ticket: {error}"));
    let old_head = operation
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("deploy target is missing"));
    fixture
        .source_broker
        .set_controls(&operation.project_id, Some(&old_head), None, now_ms + 1)
        .unwrap_or_else(|error| panic!("block in-flight source SHA: {error}"));

    assert!(matches!(
        executor.execute_phase(&operation, None, now_ms + 2),
        Err(PhaseExecutionError::Source(SourceGateError::BlockedSha))
    ));
    let new_head = commit('2');
    fixture
        .source_repository
        .insert_commit(&operation.project_id, &new_head, Some(old_head.clone()))
        .unwrap_or_else(|error| panic!("insert post-block source: {error}"));
    assert!(matches!(
        fixture
            .source_broker
            .process_direct_push(
                &operation.project_id,
                "after-blocked-ticket-retry",
                "refs/heads/main",
                Some(&old_head),
                new_head,
                now_ms + 3,
            )
            .unwrap_or_else(|error| panic!("accept source after blocked retry: {error}")),
        rdashboard::source::SourceIngressOutcome::Deployable(_)
    ));
}

#[test]
fn retry_after_ticket_only_crash_aborts_when_the_installed_policy_changed() {
    let ExecutionFixture {
        _directory: directory,
        controller,
        security_path,
        effects,
        operation: admitted,
        source_broker,
        source_repository,
    } = execution_fixture('5');
    let mut operation = admitted;
    let executor = DurableExecutor::new(reopen_security(&security_path), effects.clone())
        .with_source_gate(Arc::new(source_broker.clone()))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&operation.project_id), 200)
        .unwrap_or_else(|error| panic!("recover executor: {error}"));
    let mut now_ms = 201;
    while operation.state.phase != OperationPhase::Deploying {
        let receipt = executor
            .execute_phase(&operation, None, now_ms)
            .unwrap_or_else(|error| panic!("execute {:?}: {error}", operation.state.phase));
        operation = controller
            .commit_phase_receipt(&receipt, now_ms + 1)
            .unwrap_or_else(|error| panic!("project {:?}: {error}", operation.state.phase));
        now_ms += 2;
    }
    source_broker
        .check_live(&operation, now_ms)
        .unwrap_or_else(|error| panic!("acquire pre-policy-change ticket: {error}"));
    drop(executor);
    drop(source_broker);

    let changed_broker = DurableSourceBroker::new(
        SourceStore::open(directory.path().join("source.sqlite"))
            .unwrap_or_else(|error| panic!("reopen changed-policy source store: {error}")),
        source_repository.clone(),
        "executor-test-source",
        ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]),
        60_000,
        vec![InstalledSourceProjectPolicy {
            project_id: operation.project_id.clone(),
            repository_identity: digest("executor repository identity"),
            installed_policy: InstalledPolicyIdentity {
                digest: digest("changed installed policy"),
                version: 2,
            },
            auto_deploy: true,
            maximum_attempts: 3,
            release_class: operation
                .release_class
                .unwrap_or_else(|| panic!("release class is missing")),
        }],
        now_ms + 1,
    )
    .unwrap_or_else(|error| panic!("start changed-policy source broker: {error}"));
    let retry = DurableExecutor::new(reopen_security(&security_path), effects)
        .with_source_gate(Arc::new(changed_broker.clone()))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    retry
        .recover_security_state(std::slice::from_ref(&operation.project_id), now_ms + 2)
        .unwrap_or_else(|error| panic!("recover changed-policy executor: {error}"));
    assert!(matches!(
        retry.execute_phase(&operation, None, now_ms + 3),
        Err(PhaseExecutionError::Source(
            SourceGateError::AttestationInvalid
        ))
    ));

    let old_head = operation
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("deploy target is missing"));
    let new_head = commit('6');
    source_repository
        .insert_commit(&operation.project_id, &new_head, Some(old_head.clone()))
        .unwrap_or_else(|error| panic!("insert changed-policy source: {error}"));
    assert!(matches!(
        changed_broker
            .process_direct_push(
                &operation.project_id,
                "after-policy-ticket-retry",
                "refs/heads/main",
                Some(&old_head),
                new_head,
                now_ms + 4,
            )
            .unwrap_or_else(|error| panic!("accept changed-policy source: {error}")),
        rdashboard::source::SourceIngressOutcome::Deployable(_)
    ));
}

#[test]
fn proof_persistence_failure_aborts_the_ticket_and_releases_phase_resources() {
    let fixture = execution_fixture('3');
    let mut operation = fixture.operation.clone();
    let security = reopen_security(&fixture.security_path);
    let executor = DurableExecutor::new(security.clone(), fixture.effects.clone())
        .with_source_gate(Arc::new(fixture.source_broker.clone()))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&operation.project_id), 200)
        .unwrap_or_else(|error| panic!("recover executor: {error}"));
    let mut now_ms = 201;
    while operation.state.phase != OperationPhase::Deploying {
        let receipt = executor
            .execute_phase(&operation, None, now_ms)
            .unwrap_or_else(|error| panic!("execute {:?}: {error}", operation.state.phase));
        operation = fixture
            .controller
            .commit_phase_receipt(&receipt, now_ms + 1)
            .unwrap_or_else(|error| panic!("project {:?}: {error}", operation.state.phase));
        now_ms += 2;
    }
    assert!(matches!(
        executor.execute_phase(
            &operation,
            Some(PhaseCrashPoint::AfterIntentPersisted),
            now_ms,
        ),
        Err(PhaseExecutionError::InjectedCrash(
            PhaseCrashPoint::AfterIntentPersisted
        ))
    ));
    security
        .record_source_gate_proof(&SourceGateProofRecord {
            attempt_id: operation.attempt_id,
            phase: OperationPhase::Deploying,
            proof_digest: digest("conflicting persisted source proof"),
            project_id: operation.project_id.clone(),
            source_sequence: operation
                .evidence
                .source_sequence
                .unwrap_or_else(|| panic!("source sequence is missing")),
            attestation_digest: operation
                .evidence
                .source_attestation_digest
                .clone()
                .unwrap_or_else(|| panic!("source attestation is missing")),
            checked_at_ms: now_ms + 1,
        })
        .unwrap_or_else(|error| panic!("persist conflicting source proof: {error}"));

    assert!(matches!(
        executor.execute_phase(&operation, None, now_ms + 2),
        Err(PhaseExecutionError::Store(
            StoreError::SourceGateProofMismatch
        ))
    ));
    let inspected = rusqlite::Connection::open(&fixture.security_path)
        .unwrap_or_else(|error| panic!("inspect released proof resources: {error}"));
    let held_resources: i64 = inspected
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM active_disk_reservations WHERE attempt_id = ?1)
              + (SELECT COUNT(*) FROM execution_resources WHERE owner_attempt_id = ?1)",
            [operation.attempt_id.to_string()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count released proof resources: {error}"));
    assert_eq!(held_resources, 0);
    assert_eq!(
        security_journal_status(&fixture.security_path, operation.attempt_id, "deploying"),
        "intent_persisted"
    );
    executor
        .execute_phase(&operation, None, now_ms + 3)
        .unwrap_or_else(|error| panic!("retry original phase after proof compensation: {error}"));

    let old_head = operation
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("deploy target is missing"));
    let new_head = commit('4');
    fixture
        .source_repository
        .insert_commit(&operation.project_id, &new_head, Some(old_head.clone()))
        .unwrap_or_else(|error| panic!("insert source after proof failure: {error}"));
    assert!(matches!(
        fixture
            .source_broker
            .process_direct_push(
                &operation.project_id,
                "after-proof-persistence-failure",
                "refs/heads/main",
                Some(&old_head),
                new_head,
                now_ms + 4,
            )
            .unwrap_or_else(|error| panic!("accept source after proof failure: {error}")),
        rdashboard::source::SourceIngressOutcome::Deployable(_)
    ));
}

#[test]
fn rejected_source_proof_retries_abort_and_restores_the_original_phase() {
    let fixture = execution_fixture('4');
    let mut operation = fixture.operation.clone();
    let security = reopen_security(&fixture.security_path);
    let source_gate = Arc::new(RejectFirstProofAbortOnceSourceGate::new(
        fixture.source_broker.clone(),
    ));
    let executor = DurableExecutor::new(security.clone(), fixture.effects.clone())
        .with_source_gate(source_gate)
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&operation.project_id), 200)
        .unwrap_or_else(|error| panic!("recover executor: {error}"));
    let mut now_ms = 201;
    while operation.state.phase != OperationPhase::Deploying {
        let receipt = executor
            .execute_phase(&operation, None, now_ms)
            .unwrap_or_else(|error| panic!("execute {:?}: {error}", operation.state.phase));
        operation = fixture
            .controller
            .commit_phase_receipt(&receipt, now_ms + 1)
            .unwrap_or_else(|error| panic!("project {:?}: {error}", operation.state.phase));
        now_ms += 2;
    }

    assert!(matches!(
        executor.execute_phase(&operation, None, now_ms),
        Err(PhaseExecutionError::Source(SourceGateError::Unavailable))
    ));
    assert_eq!(
        security_journal_status(&fixture.security_path, operation.attempt_id, "deploying"),
        "needs_reconcile"
    );
    assert!(
        security
            .source_gate_rejection_pending(
                operation.attempt_id,
                &operation.project_id,
                OperationPhase::Deploying,
                ExecutorPhaseBranch::Primary,
            )
            .unwrap_or_else(|error| panic!("inspect pending source rejection: {error}"))
    );

    let receipt = executor
        .execute_phase(&operation, None, now_ms + 1)
        .unwrap_or_else(|error| panic!("retry compensated source proof: {error}"));
    assert_eq!(receipt.phase, OperationPhase::Deploying);
    assert_eq!(
        security_journal_status(&fixture.security_path, operation.attempt_id, "deploying"),
        "committed"
    );
    assert!(
        !security
            .source_gate_rejection_pending(
                operation.attempt_id,
                &operation.project_id,
                OperationPhase::Deploying,
                ExecutorPhaseBranch::Primary,
            )
            .unwrap_or_else(|error| panic!("inspect compensated source rejection: {error}"))
    );
}

#[test]
fn executor_rejects_phase_skips_and_immutable_authorization_mutation_before_resources() {
    let fixture = execution_fixture('8');
    let executor = recovered_executor(
        reopen_security(&fixture.security_path),
        fixture.effects.clone(),
        &fixture.operation.project_id,
    );
    let mut skipped = fixture.operation.clone();
    skipped.state.phase = OperationPhase::Deploying;
    skipped.evidence.deployment_plan_digest = Some(digest("forged deployment plan"));
    assert!(matches!(
        executor.execute_phase(&skipped, None, 200),
        Err(PhaseExecutionError::Store(StoreError::ExecutorPhaseOrder))
    ));
    assert_eq!(
        fixture
            .effects
            .phase_application_attempts(skipped.attempt_id, OperationPhase::Deploying)
            .unwrap_or_else(|error| panic!("skipped phase attempts: {error}")),
        0
    );

    let mut mutated = fixture.operation.clone();
    mutated.target_commit = Some(commit('9'));
    assert!(matches!(
        executor.execute_phase(&mutated, None, 201),
        Err(PhaseExecutionError::Store(
            StoreError::ExecutorAuthorizationBinding
        ))
    ));
    let connection = rusqlite::Connection::open(&fixture.security_path)
        .unwrap_or_else(|error| panic!("inspect security journal: {error}"));
    let resources: i64 = connection
        .query_row("SELECT COUNT(*) FROM execution_resources", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("count execution resources: {error}"));
    let phases: i64 = connection
        .query_row("SELECT COUNT(*) FROM executor_phase_journal", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("count phase journal: {error}"));
    assert_eq!(resources, 0);
    assert_eq!(phases, 0);
}

#[test]
fn controller_and_security_projection_crashes_are_independently_replayable() {
    let fixture = execution_fixture('f');
    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            reopen_security(&fixture.security_path),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    assert!(matches!(
        coordinator.advance_once(
            fixture.operation.attempt_id,
            None,
            Some(CoordinatorCrashPoint::AfterSecurityReceipt),
            200
        ),
        Err(CoordinatorError::InjectedCrash(
            CoordinatorCrashPoint::AfterSecurityReceipt
        ))
    ));
    let still_queued = fixture
        .controller
        .operation(fixture.operation.attempt_id)
        .unwrap_or_else(|error| panic!("read queued operation: {error}"))
        .unwrap_or_else(|| panic!("queued operation disappeared"));
    assert_eq!(still_queued.state.phase, OperationPhase::Queued);
    assert!(
        reopen_security(&fixture.security_path)
            .phase_receipt(fixture.operation.attempt_id, OperationPhase::Queued)
            .unwrap_or_else(|error| panic!("security receipt: {error}"))
            .is_some()
    );

    let recovered = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            reopen_security(&fixture.security_path),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let projected = recovered
        .advance_once(fixture.operation.attempt_id, None, None, 201)
        .unwrap_or_else(|error| panic!("replay security receipt: {error}"));
    assert_eq!(projected.state.phase, OperationPhase::SyncingSource);
    assert_eq!(
        fixture
            .effects
            .phase_mutations(fixture.operation.attempt_id, OperationPhase::Queued)
            .unwrap_or_else(|error| panic!("mutation count: {error}")),
        1
    );

    let second = execution_fixture('7');
    let second_coordinator = DurableCoordinator::new(
        second.controller.clone(),
        recovered_executor(
            reopen_security(&second.security_path),
            second.effects.clone(),
            &second.operation.project_id,
        ),
    );
    assert!(matches!(
        second_coordinator.advance_once(
            second.operation.attempt_id,
            None,
            Some(CoordinatorCrashPoint::AfterControllerProjection),
            300
        ),
        Err(CoordinatorError::InjectedCrash(
            CoordinatorCrashPoint::AfterControllerProjection
        ))
    ));
    let durable_projection = second
        .controller
        .operation(second.operation.attempt_id)
        .unwrap_or_else(|error| panic!("read projected operation: {error}"))
        .unwrap_or_else(|| panic!("projected operation disappeared"));
    assert_eq!(
        durable_projection.state.phase,
        OperationPhase::SyncingSource
    );
    assert_eq!(durable_projection.evidence.transitions.len(), 1);
}

#[test]
fn conflicting_external_evidence_enters_reconciliation_and_stays_fenced() {
    let fixture = execution_fixture('8');
    let executor = recovered_executor(
        reopen_security(&fixture.security_path),
        fixture.effects.clone(),
        &fixture.operation.project_id,
    );
    assert!(matches!(
        executor.execute_phase(
            &fixture.operation,
            Some(PhaseCrashPoint::AfterIntentPersisted),
            200
        ),
        Err(PhaseExecutionError::InjectedCrash(
            PhaseCrashPoint::AfterIntentPersisted
        ))
    ));
    fixture
        .effects
        .force_phase_effect(
            fixture.operation.attempt_id,
            OperationPhase::Queued,
            digest("foreign external effect"),
        )
        .unwrap_or_else(|error| panic!("force conflict: {error}"));

    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            reopen_security(&fixture.security_path),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let reconciled = coordinator
        .advance_once(fixture.operation.attempt_id, None, None, 201)
        .unwrap_or_else(|error| panic!("project reconciliation: {error}"));
    assert_eq!(reconciled.state.phase, OperationPhase::Reconciliation);
    assert_eq!(reconciled.state.result, OperationResult::Running);
    assert!(reconciled.failure_capsule.is_some());
    assert_eq!(
        reopen_security(&fixture.security_path)
            .phase_entry(fixture.operation.attempt_id, OperationPhase::Queued)
            .unwrap_or_else(|error| panic!("phase journal: {error}"))
            .map(|entry| entry.status),
        Some(PhaseJournalStatus::NeedsReconcile)
    );
}

#[test]
fn foreign_deploy_effect_is_journaled_before_artifact_authority_checks() {
    let fixture = execution_fixture('9');
    let mut operation = fixture.operation.clone();
    let executor = recovered_executor(
        reopen_security(&fixture.security_path),
        fixture.effects.clone(),
        &operation.project_id,
    );
    let mut now_ms = 200;
    while operation.state.phase != OperationPhase::Deploying {
        let receipt = executor
            .execute_phase(&operation, None, now_ms)
            .unwrap_or_else(|error| panic!("execute {:?}: {error}", operation.state.phase));
        operation = fixture
            .controller
            .commit_phase_receipt(&receipt, now_ms + 1)
            .unwrap_or_else(|error| panic!("project {:?}: {error}", operation.state.phase));
        now_ms += 2;
    }
    assert!(matches!(
        executor.execute_phase(
            &operation,
            Some(PhaseCrashPoint::AfterIntentPersisted),
            now_ms,
        ),
        Err(PhaseExecutionError::InjectedCrash(
            PhaseCrashPoint::AfterIntentPersisted
        ))
    ));
    let foreign_intent = digest("foreign deploy effect");
    fixture
        .effects
        .force_phase_effect(
            operation.attempt_id,
            OperationPhase::Deploying,
            foreign_intent.clone(),
        )
        .unwrap_or_else(|error| panic!("force foreign deploy effect: {error}"));

    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            reopen_security(&fixture.security_path),
            fixture.effects.clone(),
            &operation.project_id,
        ),
    );
    let reconciled = coordinator
        .advance_once(operation.attempt_id, None, None, now_ms + 1)
        .unwrap_or_else(|error| panic!("journal foreign deploy effect: {error}"));
    assert_eq!(reconciled.state.phase, OperationPhase::Reconciliation);
    let entry = reopen_security(&fixture.security_path)
        .phase_entry(operation.attempt_id, OperationPhase::Deploying)
        .unwrap_or_else(|error| panic!("load foreign deploy journal: {error}"))
        .unwrap_or_else(|| panic!("foreign deploy journal disappeared"));
    assert_eq!(entry.status, PhaseJournalStatus::NeedsReconcile);
    assert_eq!(
        entry.observation_digest,
        Some(EvidenceDigest::sha256(format!(
            "forced-observation:{foreign_intent}"
        )))
    );
    assert_eq!(entry.artifacts, PhaseArtifacts::default());
}

#[test]
fn source_proof_rejection_cannot_rewrite_a_committed_phase() {
    let fixture = execution_fixture('5');
    let security = reopen_security(&fixture.security_path);
    let executor = recovered_executor(
        security.clone(),
        fixture.effects.clone(),
        &fixture.operation.project_id,
    );
    executor
        .execute_phase(&fixture.operation, None, 200)
        .unwrap_or_else(|error| panic!("commit queued security receipt: {error}"));
    assert!(matches!(
        security.record_source_gate_proof(&SourceGateProofRecord {
            attempt_id: fixture.operation.attempt_id,
            phase: OperationPhase::Queued,
            proof_digest: digest("foreign committed proof"),
            project_id: named_project("foreign-project"),
            source_sequence: 1,
            attestation_digest: digest("foreign committed attestation"),
            checked_at_ms: 201,
        }),
        Err(StoreError::ExecutorPhaseState)
    ));
    let entry = security
        .phase_entry(fixture.operation.attempt_id, OperationPhase::Queued)
        .unwrap_or_else(|error| panic!("load committed queued journal: {error}"))
        .unwrap_or_else(|| panic!("committed queued journal disappeared"));
    assert_eq!(entry.status, PhaseJournalStatus::Committed);
    assert!(
        security
            .phase_receipt(fixture.operation.attempt_id, OperationPhase::Queued)
            .unwrap_or_else(|error| panic!("load committed queued receipt: {error}"))
            .is_some()
    );
}

#[test]
fn executor_artifacts_are_receipted_and_projected_for_the_next_phase() {
    let fixture = execution_fixture('5');
    let build_context = digest("executor-produced build context");
    let reservation_digest = deploy_authorization(&fixture.operation, Uuid::new_v4(), 10_000)
        .disk_reservation
        .unwrap_or_else(|| panic!("artifact fixture reservation is missing"))
        .reservation_digest;
    fixture
        .effects
        .set_phase_artifacts(
            fixture.operation.attempt_id,
            OperationPhase::Testing,
            PhaseArtifacts {
                source_export_digest: Some(digest("artifact source export")),
                prefetch_evidence_digest: Some(digest("artifact prefetch")),
                ci_evidence_digest: Some(digest("artifact CI")),
                build_context_digest: Some(build_context.clone()),
                resource_reservation_digest: Some(reservation_digest),
                base_image_digests: vec![digest("artifact base image")],
                ..PhaseArtifacts::default()
            },
        )
        .unwrap_or_else(|error| panic!("configure model artifacts: {error}"));
    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            reopen_security(&fixture.security_path),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let mut clock = 200;
    let testing = advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::Testing,
        &mut clock,
    );
    clock += 1;
    let projected = coordinator
        .advance_once(testing.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("execute artifact phase: {error}"));
    assert_eq!(projected.state.phase, OperationPhase::Building);
    assert_eq!(projected.evidence.build_context_digest, Some(build_context));
}

fn two_operation_coordinator(
    projects: &[ProjectId; 2],
) -> (
    TempDir,
    DurableCoordinator<DeterministicModelEffects>,
    OperationRecord,
    OperationRecord,
) {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let controller = DurableController::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let user_id = Uuid::new_v4();
    let lease = controller
        .takeover_lease(user_id, Uuid::new_v4(), 100, 10_000)
        .unwrap_or_else(|error| panic!("tab lease: {error}"));
    let claim = TabLeaseClaim {
        user_id,
        lease_id: lease.lease_id,
        generation: lease.generation,
    };
    let security = SecurityStore::open(directory.path().join("security.sqlite"))
        .unwrap_or_else(|error| panic!("security store: {error}"));
    let effects = DeterministicModelEffects::default();
    let mut operations = Vec::new();
    for (target, project_id) in ['9', 'a'].into_iter().zip(projects) {
        let request = operation_for(project_id.clone(), commit(target));
        let grant = ActionGrantClaims {
            nonce: Uuid::new_v4(),
            digest: digest(&format!("grant-{target}")),
            user_id,
            project_id: request.project_id.clone(),
            operation_kind: request.operation_kind,
            target_commit: request.target_commit.clone(),
            retry_request_id: None,
            expires_at_ms: 10_000,
        };
        let delivery_id = format!("two-operation-{target}");
        let broker = source_broker(
            directory.path().join(format!("source-{target}.sqlite")),
            &request,
            &delivery_id,
            90,
        );
        let admitted = broker
            .admit_recorded_interactive_deploy(
                &controller,
                &request.project_id,
                SourceChannel::DirectPush,
                &delivery_id,
                &claim,
                &grant,
                101,
            )
            .unwrap_or_else(|error| panic!("admit {target}: {error}"))
            .operation()
            .clone();
        let authorization = deploy_authorization(&admitted, grant.nonce, grant.expires_at_ms);
        security
            .authorize_attempt(&authorization, 102)
            .unwrap_or_else(|error| panic!("authorize {target}: {error}"));
        configure_reservation_artifacts(
            &effects,
            &admitted,
            &authorization
                .disk_reservation
                .as_ref()
                .unwrap_or_else(|| panic!("deploy reservation claim is missing"))
                .reservation_digest,
        );
        operations.push(admitted);
    }
    let coordinator = DurableCoordinator::new(
        controller,
        recovered_executor_for_projects(security, effects, projects),
    );
    (
        directory,
        coordinator,
        operations.remove(0),
        operations.remove(0),
    )
}

fn advance_to(
    coordinator: &DurableCoordinator<DeterministicModelEffects>,
    attempt_id: Uuid,
    target: OperationPhase,
    clock: &mut i64,
) -> OperationRecord {
    loop {
        let operation = coordinator
            .controller()
            .operation(attempt_id)
            .unwrap_or_else(|error| panic!("load operation: {error}"))
            .unwrap_or_else(|| panic!("operation disappeared"));
        if operation.state.phase == target || operation.state.result != OperationResult::Running {
            return operation;
        }
        *clock += 1;
        coordinator
            .advance_once(attempt_id, None, None, *clock)
            .unwrap_or_else(|error| panic!("advance toward {target:?}: {error}"));
    }
}

#[test]
fn global_build_lock_survives_a_crash_and_blocks_competitors() {
    let (_directory, coordinator, first, second) =
        two_operation_coordinator(&[named_project("rimg"), named_project("keyroom")]);
    let mut clock = 200;
    advance_to(
        &coordinator,
        first.attempt_id,
        OperationPhase::Testing,
        &mut clock,
    );
    advance_to(
        &coordinator,
        second.attempt_id,
        OperationPhase::Testing,
        &mut clock,
    );
    clock += 1;
    assert!(matches!(
        coordinator.advance_once(
            first.attempt_id,
            Some(PhaseCrashPoint::AfterIntentPersisted),
            None,
            clock
        ),
        Err(CoordinatorError::Executor(
            PhaseExecutionError::InjectedCrash(PhaseCrashPoint::AfterIntentPersisted)
        ))
    ));
    clock += 1;
    assert!(matches!(
        coordinator.advance_once(second.attempt_id, None, None, clock),
        Err(CoordinatorError::Executor(PhaseExecutionError::Store(
            StoreError::ExecutionResourceBusy
        )))
    ));
    clock += 1;
    coordinator
        .advance_once(first.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("recover build owner: {error}"));
    clock += 1;
    coordinator
        .advance_once(second.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("run released build slot: {error}"));
}

#[test]
fn known_reconciliation_is_detected_before_acquiring_new_phase_resources() {
    let (_directory, coordinator, first, second) =
        two_operation_coordinator(&[named_project("rimg"), named_project("keyroom")]);
    let mut clock = 200;
    let first = advance_to(
        &coordinator,
        first.attempt_id,
        OperationPhase::Testing,
        &mut clock,
    );
    let second = advance_to(
        &coordinator,
        second.attempt_id,
        OperationPhase::Testing,
        &mut clock,
    );
    let ordered_phases = first
        .operation_kind
        .required_phases(first.release_class)
        .unwrap_or_else(|error| panic!("phase plan: {error}"));
    let authorization_digest = executor_authorization_digest(&first)
        .unwrap_or_else(|error| panic!("authorization digest: {error}"));
    coordinator
        .executor()
        .security()
        .begin_phase_intent(PhaseIntentRequest {
            attempt_id: first.attempt_id,
            project_id: &first.project_id,
            phase: OperationPhase::Testing,
            branch: ExecutorPhaseBranch::Primary,
            phase_plan: ExecutorPhasePlan::new(ordered_phases, true),
            intent_digest: &digest("foreign testing intent"),
            authorization_digest: &authorization_digest,
            started_at_ms: clock + 1,
        })
        .unwrap_or_else(|error| panic!("persist foreign phase intent: {error}"));

    assert!(matches!(
        coordinator
            .executor()
            .execute_phase(&first, None, clock + 2),
        Err(PhaseExecutionError::NeedsReconcile)
    ));
    let competitor = coordinator
        .advance_once(second.attempt_id, None, None, clock + 3)
        .unwrap_or_else(|error| panic!("run unblocked build competitor: {error}"));
    assert_eq!(competitor.state.phase, OperationPhase::Building);
}

#[test]
fn committed_receipt_replay_does_not_require_a_new_disk_admission() {
    let fixture = execution_fixture('4');
    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            reopen_security(&fixture.security_path),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let mut clock = 200;
    let testing = advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::Testing,
        &mut clock,
    );
    clock += 1;
    let expected = coordinator
        .executor()
        .execute_phase(&testing, None, clock)
        .unwrap_or_else(|error| panic!("commit testing receipt: {error}"));

    let replay = DurableExecutor::new(
        reopen_security(&fixture.security_path),
        fixture.effects.clone(),
    )
    .with_source_gate(Arc::new(DeterministicLiveSourceGate));
    replay
        .recover_security_state(std::slice::from_ref(&testing.project_id), clock + 1)
        .unwrap_or_else(|error| panic!("recover receipt replay executor: {error}"));
    let actual = replay
        .execute_phase(&testing, None, clock + 2)
        .unwrap_or_else(|error| panic!("replay committed testing receipt: {error}"));
    assert_eq!(actual, expected);
}

#[test]
fn disk_reservations_enforce_a_durable_global_capacity_ledger() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("security.sqlite");
    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("security store: {error}"));
    let first_project = named_project("rimg");
    let second_project = named_project("keyroom");
    let first_attempt = Uuid::new_v4();
    let second_attempt = Uuid::new_v4();
    let first = disk_test_authorization(first_project.clone(), first_attempt, "first", 70, 100);
    let second = disk_test_authorization(second_project.clone(), second_attempt, "second", 70, 100);
    security
        .authorize_attempt(&first, 100)
        .unwrap_or_else(|error| panic!("authorize first reservation: {error}"));
    security
        .authorize_attempt(&second, 100)
        .unwrap_or_else(|error| panic!("authorize second reservation: {error}"));
    security
        .acquire_disk_reservation(
            &first_project,
            first_attempt,
            &disk_observation(100, 101),
            101,
        )
        .unwrap_or_else(|error| panic!("acquire first reservation: {error}"));
    drop(security);

    let recovered = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("recover security store: {error}"));
    assert!(matches!(
        recovered.acquire_disk_reservation(
            &second_project,
            second_attempt,
            &disk_observation(100, 102),
            102
        ),
        Err(StoreError::DiskReservationCapacity {
            required: 130,
            available: 100
        })
    ));
    assert!(matches!(
        recovered.acquire_disk_reservation(
            &first_project,
            first_attempt,
            &disk_observation(60, 103),
            103
        ),
        Err(StoreError::DiskReservationCapacity {
            required: 70,
            available: 60
        })
    ));
    recovered
        .release_disk_reservation_if_owned(&first_project, first_attempt, 104)
        .unwrap_or_else(|error| panic!("release first reservation: {error}"));
    recovered
        .acquire_disk_reservation(
            &second_project,
            second_attempt,
            &disk_observation(100, 105),
            105,
        )
        .unwrap_or_else(|error| panic!("acquire second reservation: {error}"));

    let invalid_attempt = Uuid::new_v4();
    let mut invalid = disk_test_authorization(
        named_project("telegram-gateway"),
        invalid_attempt,
        "invalid",
        10,
        100,
    );
    invalid
        .disk_reservation
        .as_mut()
        .unwrap_or_else(|| panic!("disk claim fixture"))
        .operation_digest = digest("mismatched operation");
    assert!(matches!(
        recovered.authorize_attempt(&invalid, 106),
        Err(StoreError::DiskReservationAuthorizationInvalid)
    ));
}

#[test]
fn disk_reservation_digest_rejects_forged_and_persisted_quantities() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("security.sqlite");
    let project_id = named_project("disk-integrity");
    let attempt_id = Uuid::new_v4();
    let authorization =
        disk_test_authorization(project_id.clone(), attempt_id, "disk integrity", 70, 100);

    let mut forged = authorization.clone();
    let forged_claim = forged
        .disk_reservation
        .as_mut()
        .unwrap_or_else(|| panic!("forged disk claim fixture"));
    forged_claim.required_bytes = 30;
    assert!(matches!(
        SecurityStore::open(directory.path().join("forged.sqlite"))
            .and_then(|store| store.authorize_attempt(&forged, 100)),
        Err(StoreError::DiskReservationAuthorizationInvalid)
    ));

    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("security store: {error}"));
    security
        .authorize_attempt(&authorization, 100)
        .unwrap_or_else(|error| panic!("authorize valid disk claim: {error}"));
    drop(security);

    let persisted = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open persisted security store: {error}"));
    let json: String = persisted
        .query_row(
            "SELECT disk_reservation_json FROM executor_authorizations WHERE attempt_id = ?1",
            [attempt_id.to_string()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("load persisted disk claim: {error}"));
    let mut claim: serde_json::Value = serde_json::from_str(&json)
        .unwrap_or_else(|error| panic!("decode persisted disk claim: {error}"));
    claim["required_bytes"] = serde_json::json!(30);
    persisted
        .execute(
            "UPDATE executor_authorizations SET disk_reservation_json = ?2 WHERE attempt_id = ?1",
            rusqlite::params![attempt_id.to_string(), claim.to_string()],
        )
        .unwrap_or_else(|error| panic!("forge persisted disk claim: {error}"));
    drop(persisted);

    let recovered = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("reopen tampered security store: {error}"));
    assert!(matches!(
        recovered.acquire_disk_reservation(
            &project_id,
            attempt_id,
            &disk_observation(100, 101),
            101,
        ),
        Err(StoreError::DiskReservationAuthorizationInvalid)
    ));
}

#[test]
fn backup_only_preflight_requires_a_live_authorized_disk_reservation() {
    let (_missing_probe_directory, missing_probe, missing_probe_operation) =
        backup_preflight_fixture(named_project("backup-probe"), Some((30, 100)), None);
    assert!(matches!(
        missing_probe.execute_phase(&missing_probe_operation, None, 106),
        Err(PhaseExecutionError::Store(
            StoreError::DiskObservationUnavailable
        ))
    ));

    let (_missing_claim_directory, missing_claim, missing_claim_operation) =
        backup_preflight_fixture(named_project("backup-claim"), None, Some(100));
    assert!(matches!(
        missing_claim.execute_phase(&missing_claim_operation, None, 106),
        Err(PhaseExecutionError::Store(
            StoreError::DiskReservationAuthorizationMissing
        ))
    ));

    let (_capacity_directory, insufficient_capacity, capacity_operation) =
        backup_preflight_fixture(named_project("backup-capacity"), Some((80, 100)), Some(70));
    assert!(matches!(
        insufficient_capacity.execute_phase(&capacity_operation, None, 106),
        Err(PhaseExecutionError::Store(
            StoreError::DiskReservationCapacity {
                required: 80,
                available: 70,
            }
        ))
    ));
}

#[test]
fn security_store_migrates_unversioned_authorizations_before_serving_work() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("legacy-security.sqlite");
    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open legacy security store: {error}"));
    legacy
        .execute_batch(
            "CREATE TABLE security_meta (
                key TEXT PRIMARY KEY,
                integer_value INTEGER NOT NULL
             ) STRICT;
             INSERT INTO security_meta(key, integer_value) VALUES ('fence_epoch', 0);
             CREATE TABLE executor_authorizations (
                authorization_id TEXT PRIMARY KEY,
                digest TEXT NOT NULL,
                attempt_id TEXT NOT NULL UNIQUE,
                project_id TEXT NOT NULL,
                expires_at_ms INTEGER NOT NULL,
                consumed_at_ms INTEGER NOT NULL
             ) STRICT;",
        )
        .unwrap_or_else(|error| panic!("create legacy security schema: {error}"));
    drop(legacy);

    let migrated = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("migrate security store: {error}"));
    let authorization = disk_test_authorization(project(), Uuid::new_v4(), "migrated", 30, 100);
    migrated
        .authorize_attempt(&authorization, 100)
        .unwrap_or_else(|error| panic!("authorize after migration: {error}"));
    drop(migrated);

    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect migrated security store: {error}"));
    let version: i64 = inspected
        .query_row(
            "SELECT integer_value FROM security_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("read security schema version: {error}"));
    assert_eq!(version, 14);
    let disk_column: i64 = inspected
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('executor_authorizations')
             WHERE name = 'disk_reservation_json'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("inspect migrated disk column: {error}"));
    assert_eq!(disk_column, 1);
}

#[test]
fn security_store_migrates_v10_through_the_action_grant_and_intent_ledgers() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("v10-security.sqlite");
    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("create current security store: {error}")),
    );
    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open v10 security store: {error}"));
    legacy
        .execute_batch(
            "DROP TABLE executor_operation_intents;
             DROP TABLE executor_action_grants;
             UPDATE security_meta SET integer_value = 10 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade action-grant schema: {error}"));
    drop(legacy);

    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("migrate v10 security store: {error}")),
    );
    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect migrated v10 store: {error}"));
    let (version, grant_tables, intent_tables, audit_columns): (i64, i64, i64, i64) = inspected
        .query_row(
            "SELECT
                (SELECT integer_value FROM security_meta WHERE key = 'schema_version'),
                (SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'executor_action_grants'),
                (SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'executor_operation_intents'),
                (SELECT COUNT(*) FROM pragma_table_info('executor_action_grants')
                 WHERE name IN ('grant_digest', 'intent_digest', 'role', 'key_epoch'))",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap_or_else(|error| panic!("inspect migrated v10 schema: {error}"));
    assert_eq!(
        (version, grant_tables, intent_tables, audit_columns),
        (14, 1, 1, 4)
    );
}

#[test]
fn security_store_migrates_v11_to_the_prepared_intent_ledger() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("v11-security.sqlite");
    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("create current security store: {error}")),
    );
    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open v11 security store: {error}"));
    legacy
        .execute_batch(
            "DROP TABLE executor_operation_intents;
             UPDATE security_meta SET integer_value = 11 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade prepared-intent schema: {error}"));
    drop(legacy);

    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("migrate v11 security store: {error}")),
    );
    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect migrated v11 store: {error}"));
    let (version, intent_tables, state_columns): (i64, i64, i64) = inspected
        .query_row(
            "SELECT
                (SELECT integer_value FROM security_meta WHERE key = 'schema_version'),
                (SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'executor_operation_intents'),
                (SELECT COUNT(*) FROM pragma_table_info('executor_operation_intents')
                 WHERE name IN ('state', 'attempt_id', 'action_grant_nonce'))",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|error| panic!("inspect migrated v11 schema: {error}"));
    assert_eq!((version, intent_tables, state_columns), (14, 1, 3));
}

#[test]
fn security_store_migrates_v12_to_the_backup_boundary_ledger() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("v12-security.sqlite");
    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("create current security store: {error}")),
    );
    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open v12 security store: {error}"));
    legacy
        .execute_batch(
            "DROP TABLE backup_boundary_journal;
             UPDATE security_meta SET integer_value = 12 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade backup-boundary schema: {error}"));
    drop(legacy);

    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("migrate v12 security store: {error}")),
    );
    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect migrated v12 store: {error}"));
    let (version, boundary_tables, boundary_columns): (i64, i64, i64) = inspected
        .query_row(
            "SELECT
                (SELECT integer_value FROM security_meta WHERE key = 'schema_version'),
                (SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'backup_boundary_journal'),
                (SELECT COUNT(*) FROM pragma_table_info('backup_boundary_journal')
                 WHERE name IN ('epoch', 'project_id', 'attempt_id', 'token', 'state'))",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|error| panic!("inspect migrated v12 schema: {error}"));
    assert_eq!((version, boundary_tables, boundary_columns), (14, 1, 5));
}

#[test]
fn security_store_migrates_an_empty_v2_disk_ledger_to_v14() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("v2-security.sqlite");
    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("create current security store: {error}")),
    );
    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open v2 security store: {error}"));
    downgrade_disk_ledger_to_v2(&legacy);
    drop(legacy);

    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("migrate v2 security store: {error}")),
    );
    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect migrated v2 store: {error}"));
    let version: i64 = inspected
        .query_row(
            "SELECT integer_value FROM security_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("read migrated v2 version: {error}"));
    assert_eq!(version, 14);
    let new_columns: i64 = inspected
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('active_disk_reservations')
             WHERE name IN (
                'emergency_reserve_bytes', 'filesystem_identity', 'observed_at_ms'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("inspect migrated disk columns: {error}"));
    assert_eq!(new_columns, 3);
}

#[test]
fn security_store_migrates_v8_source_rejection_state_to_v14() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("v8-security.sqlite");
    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("create current security store: {error}")),
    );
    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open v8 security store: {error}"));
    legacy
        .execute_batch(
            "DROP TABLE source_gate_rejections;
             UPDATE security_meta SET integer_value = 8 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade source rejection schema: {error}"));
    drop(legacy);

    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("migrate v8 security store: {error}")),
    );
    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect migrated v8 store: {error}"));
    let (version, rejection_tables): (i64, i64) = inspected
        .query_row(
            "SELECT
                (SELECT integer_value FROM security_meta WHERE key = 'schema_version'),
                (SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'source_gate_rejections')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| panic!("inspect migrated v8 schema: {error}"));
    assert_eq!((version, rejection_tables), (14, 1));
}

#[test]
fn security_store_refuses_to_guess_unresolved_v8_phase_reconciliation() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("v8-unresolved-security.sqlite");
    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("create current security store: {error}"));
    let project_id = named_project("v8-unresolved");
    let attempt_id = Uuid::new_v4();
    let authorization =
        disk_test_authorization(project_id.clone(), attempt_id, "v8 unresolved", 30, 100);
    security
        .authorize_attempt(&authorization, 100)
        .unwrap_or_else(|error| panic!("authorize unresolved v8 fixture: {error}"));
    security
        .begin_phase_intent(PhaseIntentRequest {
            attempt_id,
            project_id: &project_id,
            phase: OperationPhase::Queued,
            branch: ExecutorPhaseBranch::Primary,
            phase_plan: ExecutorPhasePlan::new(&[OperationPhase::Queued], false),
            intent_digest: &digest("v8 unresolved intent"),
            authorization_digest: &authorization.digest,
            started_at_ms: 101,
        })
        .unwrap_or_else(|error| panic!("begin unresolved v8 phase: {error}"));
    security
        .mark_phase_needs_reconcile(attempt_id, OperationPhase::Queued, 102)
        .unwrap_or_else(|error| panic!("mark unresolved v8 phase: {error}"));
    drop(security);

    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open unresolved v8 store: {error}"));
    legacy
        .execute_batch(
            "DROP TABLE source_gate_rejections;
             UPDATE security_meta SET integer_value = 8 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade unresolved v8 schema: {error}"));
    drop(legacy);

    assert!(matches!(
        SecurityStore::open(&security_path),
        Err(StoreError::SecurityPhaseMigrationRequiresReconciliation)
    ));
}

#[test]
fn security_store_migrates_v3_journal_rows_before_enabling_rollback_takeover() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("v3-security.sqlite");
    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("create current security store: {error}"));
    let project_id = named_project("v3-migration");
    let attempt_id = Uuid::new_v4();
    let authorization =
        disk_test_authorization(project_id.clone(), attempt_id, "v3 migration", 30, 100);
    security
        .authorize_attempt(&authorization, 100)
        .unwrap_or_else(|error| panic!("authorize v3 journal fixture: {error}"));
    let intent = digest("v3 queued intent");
    security
        .begin_phase_intent(PhaseIntentRequest {
            attempt_id,
            project_id: &project_id,
            phase: OperationPhase::Queued,
            branch: ExecutorPhaseBranch::Primary,
            phase_plan: ExecutorPhasePlan::new(&[OperationPhase::Queued], false),
            intent_digest: &intent,
            authorization_digest: &authorization.digest,
            started_at_ms: 101,
        })
        .unwrap_or_else(|error| panic!("persist v3 journal fixture: {error}"));
    drop(security);

    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open v3 security store: {error}"));
    legacy
        .execute_batch(
            "DROP TABLE executor_rollback_takeovers;
             UPDATE executor_authorizations SET disk_reservation_json = NULL;
             UPDATE security_meta SET integer_value = 3 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade rollback takeover schema: {error}"));
    drop(legacy);

    let migrated = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("migrate v3 security store: {error}"));
    assert_eq!(
        migrated
            .phase_entry(attempt_id, OperationPhase::Queued)
            .unwrap_or_else(|error| panic!("reload migrated v3 journal: {error}"))
            .map(|entry| (entry.status, entry.intent_digest)),
        Some((PhaseJournalStatus::IntentPersisted, intent))
    );
    drop(migrated);
    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect migrated v3 store: {error}"));
    let (version, takeover_tables): (i64, i64) = inspected
        .query_row(
            "SELECT
                (SELECT integer_value FROM security_meta WHERE key = 'schema_version'),
                (SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'executor_rollback_takeovers')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| panic!("inspect migrated v3 schema: {error}"));
    assert_eq!((version, takeover_tables), (14, 1));
}

#[test]
fn security_store_migrates_v4_takeovers_to_v14() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("v4-security.sqlite");
    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("create current security store: {error}")),
    );
    let project_id = named_project("v4-migration");
    let attempt_id = Uuid::new_v4();
    let authorization_digest = digest("v4 authorization");
    let forward_intent = digest("v4 forward health");
    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open v4 security store: {error}"));
    legacy
        .execute_batch(
            "DROP TABLE executor_rollback_takeovers;
             CREATE TABLE executor_rollback_takeovers (
                attempt_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                forward_phase TEXT NOT NULL CHECK(forward_phase IN (
                    'health_checking', 'soaking'
                )),
                forward_status TEXT NOT NULL CHECK(forward_status IN (
                    'intent_persisted', 'observed', 'verified', 'needs_reconcile'
                )),
                forward_intent_digest TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                FOREIGN KEY(attempt_id, forward_phase)
                    REFERENCES executor_phase_journal(attempt_id, phase)
             ) STRICT;
             UPDATE security_meta SET integer_value = 4 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade v4 takeover schema: {error}"));
    legacy
        .execute(
            "INSERT INTO executor_authorizations(
                authorization_id, digest, attempt_id, project_id,
                expires_at_ms, consumed_at_ms, disk_reservation_json
             ) VALUES (?1, ?2, ?3, ?4, 10000, 100, NULL)",
            rusqlite::params![
                Uuid::new_v4().to_string(),
                authorization_digest.as_str(),
                attempt_id.to_string(),
                project_id.as_str(),
            ],
        )
        .unwrap_or_else(|error| panic!("insert v4 authorization: {error}"));
    legacy
        .execute(
            "INSERT INTO executor_phase_journal(
                attempt_id, phase, project_id, intent_digest, observation_digest,
                artifacts_json, status, started_at_ms, updated_at_ms
             ) VALUES (?1, 'health_checking', ?2, ?3, ?4, '{}', 'observed', 101, 102)",
            rusqlite::params![
                attempt_id.to_string(),
                project_id.as_str(),
                forward_intent.as_str(),
                digest("v4 observation").as_str(),
            ],
        )
        .unwrap_or_else(|error| panic!("insert v4 phase journal: {error}"));
    legacy
        .execute(
            "INSERT INTO executor_rollback_takeovers(
                attempt_id, project_id, forward_phase, forward_status,
                forward_intent_digest, created_at_ms
             ) VALUES (?1, ?2, 'health_checking', 'observed', ?3, 103)",
            rusqlite::params![
                attempt_id.to_string(),
                project_id.as_str(),
                forward_intent.as_str(),
            ],
        )
        .unwrap_or_else(|error| panic!("insert v4 takeover: {error}"));
    drop(legacy);

    let migrated = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("migrate v4 security store: {error}"));
    let preserved = migrated
        .rollback_takeover(attempt_id)
        .unwrap_or_else(|error| panic!("load migrated v4 takeover: {error}"))
        .unwrap_or_else(|| panic!("migrated v4 takeover disappeared"));
    assert_eq!(preserved.forward_phase, OperationPhase::HealthChecking);
    assert_eq!(preserved.forward_status, PhaseJournalStatus::Observed);
    drop(migrated);
    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect migrated v4 store: {error}"));
    let version: i64 = inspected
        .query_row(
            "SELECT integer_value FROM security_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("read migrated v4 version: {error}"));
    assert_eq!(version, 14);
}

#[test]
fn rollback_takeover_seals_a_committed_deploy_without_a_pending_phase() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("committed-deploy-security.sqlite");
    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("create committed deploy store: {error}"));
    let committed_project = named_project("committed-deploy-seal");
    let committed_attempt = Uuid::new_v4();
    let committed_digest = digest("committed deploy authorization");
    security
        .authorize_attempt(
            &ExecutorAuthorization {
                authorization_id: Uuid::new_v4(),
                digest: committed_digest.clone(),
                attempt_id: committed_attempt,
                project_id: committed_project.clone(),
                expires_at_ms: 10_000,
                disk_reservation: None,
            },
            200,
        )
        .unwrap_or_else(|error| panic!("authorize committed deploy seal: {error}"));
    let direct = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open committed deploy fixture: {error}"));
    direct
        .execute(
            "INSERT INTO executor_phase_journal(
                attempt_id, phase, project_id, intent_digest, observation_digest,
                artifacts_json, status, started_at_ms, updated_at_ms
             ) VALUES (?1, 'deploying', ?2, ?3, ?4, '{}', 'committed', 201, 202)",
            rusqlite::params![
                committed_attempt.to_string(),
                committed_project.as_str(),
                digest("committed deploy intent").as_str(),
                digest("committed deploy observation").as_str(),
            ],
        )
        .unwrap_or_else(|error| panic!("insert committed deploy journal: {error}"));
    drop(direct);
    let committed_seal = security
        .begin_rollback_takeover(
            committed_attempt,
            &committed_project,
            &committed_digest,
            203,
        )
        .unwrap_or_else(|error| panic!("seal committed deploy: {error}"))
        .unwrap_or_else(|| panic!("committed deploy seal is missing"));
    assert_eq!(committed_seal.forward_phase, OperationPhase::Deploying);
    assert_eq!(committed_seal.forward_status, PhaseJournalStatus::Committed);
}

#[test]
fn security_store_refuses_to_guess_legacy_receipt_branches() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("legacy-receipt-security.sqlite");
    drop(
        SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("create receipt migration store: {error}")),
    );
    let attempt_id = Uuid::new_v4();
    let project_id = named_project("legacy-receipt");
    let intent = digest("legacy receipt intent");
    let observation = digest("legacy receipt observation");
    let receipt = PhaseReceipt::new(
        attempt_id,
        OperationPhase::Queued,
        ExecutorPhaseBranch::Primary,
        intent.clone(),
        observation.clone(),
        PhaseArtifacts::default(),
        103,
    )
    .unwrap_or_else(|error| panic!("construct legacy receipt fixture: {error}"));
    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open receipt migration store: {error}"));
    legacy
        .execute(
            "INSERT INTO executor_authorizations(
                authorization_id, digest, attempt_id, project_id,
                expires_at_ms, consumed_at_ms, disk_reservation_json
             ) VALUES (?1, ?2, ?3, ?4, 10000, 100, NULL)",
            rusqlite::params![
                Uuid::new_v4().to_string(),
                digest("legacy receipt authorization").as_str(),
                attempt_id.to_string(),
                project_id.as_str(),
            ],
        )
        .unwrap_or_else(|error| panic!("insert legacy receipt authorization: {error}"));
    legacy
        .execute(
            "INSERT INTO executor_phase_journal(
                attempt_id, phase, project_id, intent_digest, observation_digest,
                artifacts_json, status, started_at_ms, updated_at_ms
             ) VALUES (?1, 'queued', ?2, ?3, ?4, '{}', 'committed', 101, 103)",
            rusqlite::params![
                attempt_id.to_string(),
                project_id.as_str(),
                intent.as_str(),
                observation.as_str(),
            ],
        )
        .unwrap_or_else(|error| panic!("insert legacy receipt journal: {error}"));
    legacy
        .execute(
            "INSERT INTO executor_phase_receipts(
                attempt_id, phase, receipt_digest, receipt_json, committed_at_ms
             ) VALUES (?1, 'queued', ?2, ?3, 103)",
            rusqlite::params![
                attempt_id.to_string(),
                receipt.receipt_digest.as_str(),
                serde_json::to_string(&receipt)
                    .unwrap_or_else(|error| panic!("encode legacy receipt: {error}")),
            ],
        )
        .unwrap_or_else(|error| panic!("insert legacy receipt: {error}"));
    legacy
        .execute(
            "UPDATE security_meta SET integer_value = 4 WHERE key = 'schema_version'",
            [],
        )
        .unwrap_or_else(|error| panic!("downgrade receipt schema version: {error}"));
    drop(legacy);

    assert!(matches!(
        SecurityStore::open(&security_path),
        Err(StoreError::SecurityReceiptMigrationRequiresReconciliation)
    ));
    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect refused receipt migration: {error}"));
    let version: i64 = inspected
        .query_row(
            "SELECT integer_value FROM security_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("read refused receipt version: {error}"));
    assert_eq!(version, 4);
}

#[test]
fn security_store_refuses_to_guess_live_v2_disk_reservations() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("live-v2-security.sqlite");
    let security = SecurityStore::open(&security_path)
        .unwrap_or_else(|error| panic!("create current security store: {error}"));
    let project_id = project();
    let attempt_id = Uuid::new_v4();
    let authorization = disk_test_authorization(project_id.clone(), attempt_id, "live v2", 70, 100);
    let reservation_digest = authorization
        .disk_reservation
        .as_ref()
        .unwrap_or_else(|| panic!("disk claim fixture"))
        .reservation_digest
        .clone();
    security
        .authorize_attempt(&authorization, 100)
        .unwrap_or_else(|error| panic!("authorize live v2 reservation: {error}"));
    drop(security);

    let legacy = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open live v2 store: {error}"));
    downgrade_disk_ledger_to_v2(&legacy);
    legacy
        .execute(
            "INSERT INTO active_disk_reservations(
                attempt_id, project_id, required_bytes, available_bytes,
                reservation_digest, acquired_at_ms
             ) VALUES (?1, ?2, 70, 100, ?3, 101)",
            rusqlite::params![
                attempt_id.to_string(),
                project_id.as_str(),
                reservation_digest.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("insert live v2 reservation: {error}"));
    drop(legacy);

    assert!(matches!(
        SecurityStore::open(&security_path),
        Err(StoreError::SecurityDiskMigrationRequiresReconciliation)
    ));
    let inspected = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("inspect refused v2 store: {error}"));
    let (version, active): (i64, i64) = inspected
        .query_row(
            "SELECT
                (SELECT integer_value FROM security_meta WHERE key = 'schema_version'),
                (SELECT COUNT(*) FROM active_disk_reservations)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| panic!("inspect preserved v2 state: {error}"));
    assert_eq!((version, active), (2, 1));
}

fn downgrade_disk_ledger_to_v2(connection: &rusqlite::Connection) {
    connection
        .execute_batch(
            "DROP TABLE active_disk_reservations;
             CREATE TABLE active_disk_reservations (
                attempt_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL UNIQUE,
                required_bytes INTEGER NOT NULL CHECK(required_bytes > 0),
                available_bytes INTEGER NOT NULL CHECK(available_bytes >= required_bytes),
                reservation_digest TEXT NOT NULL,
                acquired_at_ms INTEGER NOT NULL,
                FOREIGN KEY(attempt_id) REFERENCES executor_authorizations(attempt_id)
             ) STRICT;
             UPDATE security_meta SET integer_value = 2 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade disk ledger fixture: {error}"));
}

#[test]
fn security_store_rejects_unknown_schema_versions_at_open() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let security_path = directory.path().join("future-security.sqlite");
    let future = rusqlite::Connection::open(&security_path)
        .unwrap_or_else(|error| panic!("open future security store: {error}"));
    future
        .execute_batch(
            "CREATE TABLE security_meta (
                key TEXT PRIMARY KEY,
                integer_value INTEGER NOT NULL
             ) STRICT;
             INSERT INTO security_meta(key, integer_value) VALUES ('schema_version', 99);",
        )
        .unwrap_or_else(|error| panic!("create future security schema: {error}"));
    drop(future);
    assert!(matches!(
        SecurityStore::open(&security_path),
        Err(StoreError::UnsupportedSecuritySchemaVersion {
            actual: 99,
            supported: 14
        })
    ));
}

#[test]
fn coordinator_persists_disk_capacity_blocks_and_requires_an_explicit_recheck() {
    let fixture = execution_fixture('b');
    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            reopen_security(&fixture.security_path),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let mut clock = 200;
    advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::Testing,
        &mut clock,
    );

    let blocker_project = named_project("disk-blocker");
    let blocker_attempt = Uuid::new_v4();
    let blocking_claim = disk_test_authorization(
        blocker_project.clone(),
        blocker_attempt,
        "disk blocker",
        90,
        100,
    );
    let security = reopen_security(&fixture.security_path);
    security
        .authorize_attempt(&blocking_claim, clock + 1)
        .unwrap_or_else(|error| panic!("authorize blocker: {error}"));
    security
        .acquire_disk_reservation(
            &blocker_project,
            blocker_attempt,
            &disk_observation(100, clock + 2),
            clock + 2,
        )
        .unwrap_or_else(|error| panic!("acquire blocker: {error}"));

    let disk_blocked_operation = coordinator
        .advance_once(fixture.operation.attempt_id, None, None, clock + 3)
        .unwrap_or_else(|error| panic!("project disk block: {error}"));
    assert_eq!(disk_blocked_operation.state.phase, OperationPhase::Testing);
    assert_eq!(
        disk_blocked_operation.state.blocking_reason,
        BlockingReason::DiskReserve
    );
    assert_eq!(
        fixture
            .controller
            .operation(fixture.operation.attempt_id)
            .unwrap_or_else(|error| panic!("reload blocked operation: {error}"))
            .unwrap_or_else(|| panic!("blocked operation disappeared"))
            .state
            .blocking_reason,
        BlockingReason::DiskReserve
    );

    security
        .release_disk_reservation_if_owned(&blocker_project, blocker_attempt, clock + 4)
        .unwrap_or_else(|error| panic!("release blocker: {error}"));
    let restarted = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            reopen_security(&fixture.security_path),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let cleared = restarted
        .retry_disk_reservation(fixture.operation.attempt_id, clock + 5)
        .unwrap_or_else(|error| panic!("request disk recheck: {error}"));
    assert_eq!(cleared.state.blocking_reason, BlockingReason::None);
    let projected = restarted
        .advance_once(fixture.operation.attempt_id, None, None, clock + 6)
        .unwrap_or_else(|error| panic!("retry after disk recovery: {error}"));
    assert_eq!(projected.state.phase, OperationPhase::Building);
}

#[test]
fn project_deploy_lock_spans_health_and_soak_until_terminal_result() {
    let (directory, coordinator, first, second) =
        two_operation_coordinator(&[project(), project()]);
    let security = SecurityStore::open(directory.path().join("security.sqlite"))
        .unwrap_or_else(|error| panic!("project lock security store: {error}"));
    let resource = ExecutionResource::ProjectDeploy(first.project_id.clone());
    let mut clock = 400;
    advance_to(
        &coordinator,
        first.attempt_id,
        OperationPhase::Deploying,
        &mut clock,
    );
    assert!(matches!(
        security.begin_fence_acquire(&first.project_id, second.attempt_id, clock),
        Err(StoreError::ExecutionResourceOwnership)
    ));
    assert!(matches!(
        security.begin_fence_acquire(&first.project_id, first.attempt_id, clock),
        Err(StoreError::FencePhaseInvalid)
    ));
    clock += 1;
    assert!(matches!(
        coordinator.advance_once(
            first.attempt_id,
            Some(PhaseCrashPoint::AfterIntentPersisted),
            None,
            clock
        ),
        Err(CoordinatorError::Executor(
            PhaseExecutionError::InjectedCrash(PhaseCrashPoint::AfterIntentPersisted)
        ))
    ));
    clock += 1;
    assert!(matches!(
        security.acquire_resource(&resource, second.attempt_id, clock),
        Err(StoreError::ExecutionResourceBusy)
    ));
    clock += 1;
    let first_health = coordinator
        .advance_once(first.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("recover deploy owner: {error}"));
    assert_eq!(first_health.state.phase, OperationPhase::HealthChecking);
    clock += 1;
    assert!(matches!(
        security.acquire_resource(&resource, second.attempt_id, clock),
        Err(StoreError::ExecutionResourceBusy)
    ));
    let first_terminal = advance_to(
        &coordinator,
        first.attempt_id,
        OperationPhase::Soaking,
        &mut clock,
    );
    assert_eq!(first_terminal.state.phase, OperationPhase::Soaking);
    clock += 1;
    assert!(matches!(
        security.acquire_resource(&resource, second.attempt_id, clock),
        Err(StoreError::ExecutionResourceBusy)
    ));
    clock += 1;
    let first_terminal = coordinator
        .advance_once(first.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("finish first deploy: {error}"));
    assert_eq!(first_terminal.state.result, OperationResult::Succeeded);
    clock += 1;
    security
        .acquire_resource(&resource, second.attempt_id, clock)
        .unwrap_or_else(|error| panic!("run released project slot: {error}"));
    security
        .release_resource(&resource, second.attempt_id, clock + 1)
        .unwrap_or_else(|error| panic!("release project slot fixture: {error}"));
}

#[test]
fn stateful_coordinator_holds_fence_from_migration_through_successful_soak() {
    let fixture = execution_fixture_with_class('4', ReleaseClass::StatefulCompatible);
    let security = reopen_security(&fixture.security_path);
    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            security.clone(),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let mut clock = 500;
    let cutover = advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::CutoverSnapshotting,
        &mut clock,
    );
    let drain_identity = security
        .active_drain_identity(&cutover.project_id)
        .unwrap_or_else(|error| panic!("load reserved drain identity: {error}"))
        .unwrap_or_else(|| panic!("drain identity was not reserved before cutover"));
    assert_eq!(drain_identity.attempt_id, cutover.attempt_id);
    clock += 1;
    let migrating = coordinator
        .advance_once(cutover.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("promote drain identity into write fence: {error}"));
    assert_eq!(migrating.state.phase, OperationPhase::Migrating);
    let epoch = migrating
        .evidence
        .fencing_epoch
        .unwrap_or_else(|| panic!("cutover fencing epoch was not projected"));
    let held = security
        .active_fence(&migrating.project_id)
        .unwrap_or_else(|error| panic!("load cutover fence: {error}"))
        .unwrap_or_else(|| panic!("cutover fence is missing"));
    assert_eq!(held.attempt_id, migrating.attempt_id);
    assert_eq!(held.epoch, epoch);
    assert_eq!(held.epoch, drain_identity.epoch);
    assert_eq!(held.token, drain_identity.token);
    assert_eq!(held.state, FenceJournalState::Held);
    assert!(
        security
            .active_drain_identity(&migrating.project_id)
            .unwrap_or_else(|error| panic!("load promoted drain identity: {error}"))
            .is_none()
    );
    clock += 1;
    let deploying = coordinator
        .advance_once(fixture.operation.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("execute fenced migration: {error}"));
    assert_eq!(deploying.state.phase, OperationPhase::Deploying);
    assert_eq!(deploying.evidence.fencing_epoch, Some(epoch));

    advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::Soaking,
        &mut clock,
    );
    clock += 1;
    let succeeded = coordinator
        .advance_once(fixture.operation.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("finish fenced soak: {error}"));
    assert_eq!(succeeded.state.result, OperationResult::Succeeded);
    assert!(
        security
            .active_fence(&succeeded.project_id)
            .unwrap_or_else(|error| panic!("load released migration fence: {error}"))
            .is_none()
    );
    assert_eq!(
        fixture
            .effects
            .observe_fence(&succeeded.project_id)
            .unwrap_or_else(|error| panic!("observe released application fence: {error}")),
        FenceObservation::Released
    );
}

fn assert_stateful_resources_held(path: &PathBuf, operation: &OperationRecord) {
    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("open resource ownership store: {error}"));
    let project_owner = connection
        .query_row(
            "SELECT owner_attempt_id FROM execution_resources WHERE resource_key = ?1",
            [format!("project:deploy:{}", operation.project_id)],
            |row| row.get::<_, String>(0),
        )
        .unwrap_or_else(|error| panic!("load project resource owner: {error}"));
    assert_eq!(project_owner, operation.attempt_id.to_string());
    let disk_owner = connection
        .query_row(
            "SELECT attempt_id FROM active_disk_reservations WHERE project_id = ?1",
            [operation.project_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .unwrap_or_else(|error| panic!("load disk reservation owner: {error}"));
    assert_eq!(disk_owner, operation.attempt_id.to_string());
}

#[test]
fn stateful_source_ticket_spans_base_backup_drain_and_cutover() {
    let fixture = execution_fixture_with_class('4', ReleaseClass::StatefulCompatible);
    let security = reopen_security(&fixture.security_path);
    let executor = DurableExecutor::new(security, fixture.effects.clone())
        .with_source_gate(Arc::new(fixture.source_broker.clone()))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&fixture.operation.project_id), 500)
        .unwrap_or_else(|error| panic!("recover stateful executor: {error}"));
    let coordinator = DurableCoordinator::new(fixture.controller.clone(), executor);
    let mut clock = 500;
    let backing_up = advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::BackingUp,
        &mut clock,
    );
    clock += 1;
    let draining = coordinator
        .advance_once(backing_up.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("execute base backup under source ticket: {error}"));
    assert_eq!(draining.state.phase, OperationPhase::Draining);

    let old_head = draining
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("stateful deploy target is missing"));
    let new_head = commit('5');
    fixture
        .source_repository
        .insert_commit(&draining.project_id, &new_head, Some(old_head.clone()))
        .unwrap_or_else(|error| panic!("insert next stateful source: {error}"));
    assert!(matches!(
        fixture.source_broker.process_direct_push(
            &draining.project_id,
            "stateful-ticket-span",
            "refs/heads/main",
            Some(&old_head),
            new_head.clone(),
            clock + 1,
        ),
        Err(rdashboard::source::SourceError::MutationAdmissionBusy)
    ));

    clock += 1;
    let cutover = coordinator
        .advance_once(draining.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("commit drain under source ticket: {error}"));
    assert_eq!(cutover.state.phase, OperationPhase::CutoverSnapshotting);
    assert!(matches!(
        fixture.source_broker.process_direct_push(
            &cutover.project_id,
            "stateful-ticket-span",
            "refs/heads/main",
            Some(&old_head),
            new_head.clone(),
            clock + 1,
        ),
        Err(rdashboard::source::SourceError::MutationAdmissionBusy)
    ));

    clock += 1;
    let migrating = coordinator
        .advance_once(cutover.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("complete cutover source ticket: {error}"));
    assert_eq!(migrating.state.phase, OperationPhase::Migrating);
    assert!(matches!(
        fixture
            .source_broker
            .process_direct_push(
                &migrating.project_id,
                "stateful-ticket-span",
                "refs/heads/main",
                Some(&old_head),
                new_head,
                clock + 1,
            )
            .unwrap_or_else(|error| panic!("accept source after cutover ticket: {error}")),
        rdashboard::source::SourceIngressOutcome::Deployable(_)
    ));
}

#[test]
fn transient_pre_fence_source_failure_retains_ticket_resources_and_retries() {
    let fixture = execution_fixture_with_class('6', ReleaseClass::StatefulCompatible);
    let security = reopen_security(&fixture.security_path);
    let executor = DurableExecutor::new(security.clone(), fixture.effects.clone())
        .with_source_gate(Arc::new(FailSecondCheckSourceGate::new(
            fixture.source_broker.clone(),
            SourceGateError::Unavailable,
        )))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&fixture.operation.project_id), 600)
        .unwrap_or_else(|error| panic!("recover transient-source executor: {error}"));
    let coordinator = DurableCoordinator::new(fixture.controller.clone(), executor);
    let mut clock = 600;
    let cutover = advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::CutoverSnapshotting,
        &mut clock,
    );

    clock += 1;
    let blocked = coordinator
        .advance_once(cutover.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("persist transient source block: {error}"));
    assert_eq!(blocked.state.phase, OperationPhase::CutoverSnapshotting);
    assert_eq!(
        blocked.state.blocking_reason,
        BlockingReason::SourceBrokerUnavailable
    );
    assert!(
        security
            .active_fence(&blocked.project_id)
            .unwrap_or_else(|error| panic!("load absent blocked fence: {error}"))
            .is_none()
    );
    assert_stateful_resources_held(&fixture.security_path, &blocked);

    let old_head = blocked
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("blocked stateful target is missing"));
    let new_head = commit('7');
    fixture
        .source_repository
        .insert_commit(&blocked.project_id, &new_head, Some(old_head.clone()))
        .unwrap_or_else(|error| panic!("insert blocked stateful source: {error}"));
    assert!(matches!(
        fixture.source_broker.process_direct_push(
            &blocked.project_id,
            "transient-pre-fence",
            "refs/heads/main",
            Some(&old_head),
            new_head.clone(),
            clock + 1,
        ),
        Err(rdashboard::source::SourceError::MutationAdmissionBusy)
    ));

    clock += 1;
    let migrating = coordinator
        .advance_once(blocked.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("retry transient pre-fence source check: {error}"));
    assert_eq!(migrating.state.phase, OperationPhase::Migrating);
    assert_eq!(migrating.state.blocking_reason, BlockingReason::None);
    assert_eq!(
        security
            .active_fence(&migrating.project_id)
            .unwrap_or_else(|error| panic!("load retried fence: {error}"))
            .map(|fence| fence.state),
        Some(FenceJournalState::Held)
    );
    assert!(matches!(
        fixture
            .source_broker
            .process_direct_push(
                &migrating.project_id,
                "transient-pre-fence",
                "refs/heads/main",
                Some(&old_head),
                new_head,
                clock + 1,
            )
            .unwrap_or_else(|error| panic!("accept source after transient retry: {error}")),
        rdashboard::source::SourceIngressOutcome::Deployable(_)
    ));
}

#[test]
fn ambiguous_pre_fence_source_failure_keeps_ownership_during_reconciliation() {
    let fixture = execution_fixture_with_class('8', ReleaseClass::StatefulCompatible);
    let security = reopen_security(&fixture.security_path);
    let executor = DurableExecutor::new(security.clone(), fixture.effects.clone())
        .with_source_gate(Arc::new(FailSecondCheckSourceGate::new(
            fixture.source_broker.clone(),
            SourceGateError::HeadSuperseded,
        )))
        .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    executor
        .recover_security_state(std::slice::from_ref(&fixture.operation.project_id), 700)
        .unwrap_or_else(|error| panic!("recover ambiguous-source executor: {error}"));
    let coordinator = DurableCoordinator::new(fixture.controller.clone(), executor);
    let mut clock = 700;
    let cutover = advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::CutoverSnapshotting,
        &mut clock,
    );

    clock += 1;
    let reconciliation = coordinator
        .advance_once(cutover.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("enter source reconciliation: {error}"));
    assert_eq!(reconciliation.state.phase, OperationPhase::Reconciliation);
    assert_eq!(reconciliation.state.result, OperationResult::Running);
    assert_stateful_resources_held(&fixture.security_path, &reconciliation);
    assert!(
        security
            .active_fence(&reconciliation.project_id)
            .unwrap_or_else(|error| panic!("load absent reconciliation fence: {error}"))
            .is_none()
    );

    clock += 1;
    let still_reconciling = coordinator
        .advance_once(reconciliation.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("revisit source reconciliation: {error}"));
    assert_eq!(
        still_reconciling.state.phase,
        OperationPhase::Reconciliation
    );
    assert_stateful_resources_held(&fixture.security_path, &still_reconciling);

    let old_head = still_reconciling
        .target_commit
        .clone()
        .unwrap_or_else(|| panic!("reconciling stateful target is missing"));
    let new_head = commit('9');
    fixture
        .source_repository
        .insert_commit(
            &still_reconciling.project_id,
            &new_head,
            Some(old_head.clone()),
        )
        .unwrap_or_else(|error| panic!("insert reconciling stateful source: {error}"));
    assert!(matches!(
        fixture.source_broker.process_direct_push(
            &still_reconciling.project_id,
            "ambiguous-pre-fence",
            "refs/heads/main",
            Some(&old_head),
            new_head,
            clock + 1,
        ),
        Err(rdashboard::source::SourceError::MutationAdmissionBusy)
    ));
}

fn safe_soak_receipt(
    security: &SecurityStore,
    operation: &OperationRecord,
    now_ms: i64,
) -> EvidenceDigest {
    commit_test_receipt(
        security,
        operation,
        OperationPhase::Soaking,
        &[
            OperationPhase::BackingUp,
            OperationPhase::Draining,
            OperationPhase::Soaking,
        ],
        "safe soak",
        now_ms,
    )
}

fn assert_committed_rollback_branch(
    security: &SecurityStore,
    effects: &DeterministicModelEffects,
    operation: &OperationRecord,
) -> PhaseReceipt {
    for phase in [
        OperationPhase::Rollback,
        OperationPhase::HealthChecking,
        OperationPhase::Soaking,
    ] {
        assert_eq!(
            security
                .phase_entry_in_branch(
                    operation.attempt_id,
                    phase,
                    ExecutorPhaseBranch::RollbackRecovery,
                )
                .unwrap_or_else(|error| panic!("load rollback branch {phase:?}: {error}"))
                .map(|entry| entry.status),
            Some(PhaseJournalStatus::Committed)
        );
        assert!(
            security
                .phase_receipt_in_branch(
                    operation.attempt_id,
                    phase,
                    ExecutorPhaseBranch::RollbackRecovery,
                )
                .unwrap_or_else(|error| panic!("load rollback receipt {phase:?}: {error}"))
                .is_some()
        );
        assert_eq!(
            effects
                .phase_mutations_in_branch(
                    operation.attempt_id,
                    phase,
                    ExecutorPhaseBranch::RollbackRecovery,
                )
                .unwrap_or_else(|error| panic!("rollback mutation count {phase:?}: {error}")),
            1
        );
    }
    security
        .phase_receipt_in_branch(
            operation.attempt_id,
            OperationPhase::HealthChecking,
            ExecutorPhaseBranch::RollbackRecovery,
        )
        .unwrap_or_else(|error| panic!("reload rollback health receipt: {error}"))
        .unwrap_or_else(|| panic!("rollback health receipt is missing"))
}

fn crash_with_pending_forward_health(
    coordinator: &DurableCoordinator<DeterministicModelEffects>,
    security: &SecurityStore,
    attempt_id: Uuid,
    clock: &mut i64,
) -> OperationRecord {
    let forward_health = advance_to(
        coordinator,
        attempt_id,
        OperationPhase::HealthChecking,
        clock,
    );
    *clock += 1;
    assert!(matches!(
        coordinator.advance_once(
            forward_health.attempt_id,
            Some(PhaseCrashPoint::AfterIntentPersisted),
            None,
            *clock,
        ),
        Err(CoordinatorError::Executor(
            PhaseExecutionError::InjectedCrash(PhaseCrashPoint::AfterIntentPersisted)
        ))
    ));
    assert_eq!(
        security
            .phase_entry(forward_health.attempt_id, OperationPhase::HealthChecking)
            .unwrap_or_else(|error| panic!("load pending forward health: {error}"))
            .map(|entry| entry.status),
        Some(PhaseJournalStatus::IntentPersisted)
    );
    forward_health
}

fn crash_after_controller_rollback_projection(
    coordinator: &DurableCoordinator<DeterministicModelEffects>,
    fixture: &ExecutionFixture,
    security: &SecurityStore,
    operation: &OperationRecord,
    clock: &mut i64,
) {
    *clock += 1;
    assert!(matches!(
        coordinator.begin_rollback(
            operation.attempt_id,
            Some(CoordinatorCrashPoint::AfterControllerProjection),
            *clock,
        ),
        Err(CoordinatorError::InjectedCrash(
            CoordinatorCrashPoint::AfterControllerProjection
        ))
    ));
    assert_eq!(
        fixture
            .controller
            .operation(operation.attempt_id)
            .unwrap_or_else(|error| panic!("load projected rollback: {error}"))
            .unwrap_or_else(|| panic!("projected rollback disappeared"))
            .state
            .phase,
        OperationPhase::Rollback
    );
    assert!(
        security
            .rollback_takeover(operation.attempt_id)
            .unwrap_or_else(|error| panic!("load pre-takeover state: {error}"))
            .is_some()
    );
}

#[test]
fn rollback_seal_precedes_controller_projection_and_blocks_stale_primary_work() {
    let fixture = execution_fixture('d');
    let security = reopen_security(&fixture.security_path);
    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            security.clone(),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let mut clock = 560;
    let forward_health = crash_with_pending_forward_health(
        &coordinator,
        &security,
        fixture.operation.attempt_id,
        &mut clock,
    );

    clock += 1;
    assert!(matches!(
        coordinator.begin_rollback(
            forward_health.attempt_id,
            Some(CoordinatorCrashPoint::AfterSecurityReceipt),
            clock,
        ),
        Err(CoordinatorError::InjectedCrash(
            CoordinatorCrashPoint::AfterSecurityReceipt
        ))
    ));
    assert_eq!(
        fixture
            .controller
            .operation(forward_health.attempt_id)
            .unwrap_or_else(|error| panic!("load pre-projection controller state: {error}"))
            .unwrap_or_else(|| panic!("pre-projection operation disappeared"))
            .state
            .phase,
        OperationPhase::HealthChecking
    );
    let takeover = security
        .rollback_takeover(forward_health.attempt_id)
        .unwrap_or_else(|error| panic!("load seal-first takeover: {error}"))
        .unwrap_or_else(|| panic!("seal-first takeover is missing"));
    assert_eq!(takeover.forward_phase, OperationPhase::HealthChecking);
    assert_eq!(takeover.forward_status, PhaseJournalStatus::IntentPersisted);
    assert!(matches!(
        coordinator
            .executor()
            .execute_phase(&forward_health, None, clock + 1),
        Err(PhaseExecutionError::Store(StoreError::ExecutorPhaseOrder))
    ));

    let rollback = coordinator
        .begin_rollback(forward_health.attempt_id, None, clock + 2)
        .unwrap_or_else(|error| panic!("project sealed rollback: {error}"));
    assert_eq!(rollback.state.phase, OperationPhase::Rollback);
}

#[test]
fn committed_primary_receipt_cannot_cross_a_rollback_seal_or_release_its_fence() {
    let fixture = execution_fixture_with_class('e', ReleaseClass::StatefulCompatible);
    let security = reopen_security(&fixture.security_path);
    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            security.clone(),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let mut clock = 580;
    let soaking = advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::Soaking,
        &mut clock,
    );
    clock += 1;
    let stale_primary_receipt = coordinator
        .executor()
        .execute_phase(&soaking, None, clock)
        .unwrap_or_else(|error| panic!("commit stale primary soak: {error}"));
    assert_eq!(stale_primary_receipt.branch, ExecutorPhaseBranch::Primary);

    clock += 1;
    let rollback = coordinator
        .begin_rollback(soaking.attempt_id, None, clock)
        .unwrap_or_else(|error| panic!("seal rollback after primary receipt: {error}"));
    let takeover = security
        .rollback_takeover(soaking.attempt_id)
        .unwrap_or_else(|error| panic!("load committed-primary takeover: {error}"))
        .unwrap_or_else(|| panic!("committed-primary takeover is missing"));
    assert_eq!(takeover.forward_phase, OperationPhase::Soaking);
    assert_eq!(takeover.forward_status, PhaseJournalStatus::Committed);
    assert!(matches!(
        coordinator.executor().release_write_fence(
            &soaking.project_id,
            soaking.attempt_id,
            &stale_primary_receipt.receipt_digest,
            None,
            clock + 1,
        ),
        Err(FenceExecutionError::Store(StoreError::FenceReleaseUnsafe))
    ));
    assert!(matches!(
        fixture
            .controller
            .commit_phase_receipt(&stale_primary_receipt, clock + 1),
        Err(StoreError::ReceiptMismatch)
    ));
    assert_eq!(
        security
            .active_fence(&rollback.project_id)
            .unwrap_or_else(|error| panic!("load rollback fence: {error}"))
            .map(|fence| fence.state),
        Some(FenceJournalState::Held)
    );
}

#[test]
fn rollback_from_soaking_uses_distinct_executor_journal_and_effect_identities() {
    let fixture = execution_fixture_with_class('c', ReleaseClass::StatefulCompatible);
    let security = reopen_security(&fixture.security_path);
    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            security.clone(),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let mut clock = 600;
    let soaking = advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::Soaking,
        &mut clock,
    );
    let primary_health = security
        .phase_receipt(soaking.attempt_id, OperationPhase::HealthChecking)
        .unwrap_or_else(|error| panic!("load primary health receipt: {error}"))
        .unwrap_or_else(|| panic!("primary health receipt is missing"));
    clock += 1;
    let rollback = coordinator
        .begin_rollback(soaking.attempt_id, None, clock)
        .unwrap_or_else(|error| panic!("begin rollback from soaking: {error}"));
    assert_eq!(rollback.state.phase, OperationPhase::Rollback);

    let mut rolled_back = rollback;
    for _ in 0..3 {
        clock += 1;
        rolled_back = coordinator
            .advance_once(rolled_back.attempt_id, None, None, clock)
            .unwrap_or_else(|error| panic!("advance rollback recovery: {error}"));
    }
    assert_eq!(rolled_back.state.result, OperationResult::RolledBack);
    assert!(
        security
            .active_fence(&rolled_back.project_id)
            .unwrap_or_else(|error| panic!("load released rollback fence: {error}"))
            .is_none()
    );

    let rollback_health =
        assert_committed_rollback_branch(&security, &fixture.effects, &rolled_back);
    assert_ne!(primary_health.intent_digest, rollback_health.intent_digest);
    assert_eq!(
        rolled_back.evidence.health_evidence_digest,
        primary_health.artifacts.health_evidence_digest
    );
    assert_eq!(
        rolled_back.evidence.rollback_health_evidence_digest,
        rollback_health.artifacts.health_evidence_digest
    );
    assert_ne!(
        rolled_back.evidence.health_evidence_digest,
        rolled_back.evidence.rollback_health_evidence_digest
    );
    assert_eq!(
        security
            .phase_receipt(rolled_back.attempt_id, OperationPhase::HealthChecking)
            .unwrap_or_else(|error| panic!("reload primary health receipt: {error}"))
            .map(|receipt| receipt.receipt_digest),
        Some(primary_health.receipt_digest)
    );
}

#[test]
fn rollback_takeover_preserves_the_forward_journal_and_recovers_both_crash_windows() {
    let fixture = execution_fixture('d');
    let security = reopen_security(&fixture.security_path);
    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            security.clone(),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let mut clock = 700;
    let forward_health = crash_with_pending_forward_health(
        &coordinator,
        &security,
        fixture.operation.attempt_id,
        &mut clock,
    );
    crash_after_controller_rollback_projection(
        &coordinator,
        &fixture,
        &security,
        &forward_health,
        &mut clock,
    );

    drop(coordinator);
    let recovered = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            reopen_security(&fixture.security_path),
            fixture.effects.clone(),
            &forward_health.project_id,
        ),
    );
    clock += 1;
    let rollback = recovered
        .begin_rollback(forward_health.attempt_id, None, clock)
        .unwrap_or_else(|error| panic!("recover rollback transition: {error}"));
    let takeover = security
        .rollback_takeover(forward_health.attempt_id)
        .unwrap_or_else(|error| panic!("load rollback takeover: {error}"))
        .unwrap_or_else(|| panic!("rollback takeover is missing"));
    assert_eq!(takeover.forward_phase, OperationPhase::HealthChecking);
    assert_eq!(takeover.forward_status, PhaseJournalStatus::IntentPersisted);
    assert_eq!(takeover.project_id, forward_health.project_id);
    assert!(matches!(
        recovered
            .executor()
            .execute_phase(&forward_health, None, clock + 1),
        Err(PhaseExecutionError::Store(StoreError::ExecutorPhaseOrder))
    ));

    clock += 2;
    assert!(matches!(
        recovered.advance_once(
            rollback.attempt_id,
            Some(PhaseCrashPoint::AfterIntentPersisted),
            None,
            clock,
        ),
        Err(CoordinatorError::Executor(
            PhaseExecutionError::InjectedCrash(PhaseCrashPoint::AfterIntentPersisted)
        ))
    ));
    drop(recovered);

    let recovered_again = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            reopen_security(&fixture.security_path),
            fixture.effects.clone(),
            &forward_health.project_id,
        ),
    );
    clock += 1;
    let rollback_health = recovered_again
        .advance_once(rollback.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("recover rollback executor intent: {error}"));
    assert_eq!(rollback_health.state.phase, OperationPhase::HealthChecking);
    assert_eq!(
        security
            .phase_entry(forward_health.attempt_id, OperationPhase::HealthChecking)
            .unwrap_or_else(|error| panic!("reload preserved forward health: {error}"))
            .map(|entry| entry.status),
        Some(PhaseJournalStatus::IntentPersisted)
    );
    assert_eq!(
        security
            .phase_entry_in_branch(
                rollback.attempt_id,
                OperationPhase::Rollback,
                ExecutorPhaseBranch::RollbackRecovery,
            )
            .unwrap_or_else(|error| panic!("reload rollback journal: {error}"))
            .map(|entry| entry.status),
        Some(PhaseJournalStatus::Committed)
    );
}

#[test]
fn rollback_takeover_accepts_an_ambiguous_forward_soak_from_reconciliation() {
    let fixture = execution_fixture('e');
    let security = reopen_security(&fixture.security_path);
    let coordinator = DurableCoordinator::new(
        fixture.controller.clone(),
        recovered_executor(
            security.clone(),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        ),
    );
    let mut clock = 800;
    let soaking = advance_to(
        &coordinator,
        fixture.operation.attempt_id,
        OperationPhase::Soaking,
        &mut clock,
    );
    fixture
        .effects
        .hide_next_applied_phase_observation(soaking.attempt_id, OperationPhase::Soaking)
        .unwrap_or_else(|error| panic!("hide forward soak observation: {error}"));
    clock += 1;
    let reconciliation = coordinator
        .advance_once(soaking.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("enter reconciliation from ambiguous soak: {error}"));
    assert_eq!(reconciliation.state.phase, OperationPhase::Reconciliation);
    assert_eq!(
        security
            .phase_entry(soaking.attempt_id, OperationPhase::Soaking)
            .unwrap_or_else(|error| panic!("load ambiguous forward soak: {error}"))
            .map(|entry| entry.status),
        Some(PhaseJournalStatus::NeedsReconcile)
    );

    clock += 1;
    let late_phase_executor = DurableExecutor::new(
        reopen_security(&fixture.security_path),
        fixture.effects.clone(),
    )
    .with_source_gate(Arc::new(FailCompletionSourceGate))
    .with_disk_space_probe(Arc::new(TestDiskSpaceProbe));
    late_phase_executor
        .recover_security_state(std::slice::from_ref(&soaking.project_id), clock)
        .unwrap_or_else(|error| panic!("recover late-phase rollback executor: {error}"));
    let late_phase = DurableCoordinator::new(fixture.controller.clone(), late_phase_executor);
    let rollback = late_phase
        .begin_rollback(soaking.attempt_id, None, clock)
        .unwrap_or_else(|error| panic!("take over ambiguous forward soak: {error}"));
    assert_eq!(rollback.state.phase, OperationPhase::Rollback);
    let takeover = security
        .rollback_takeover(soaking.attempt_id)
        .unwrap_or_else(|error| panic!("load ambiguous-soak takeover: {error}"))
        .unwrap_or_else(|| panic!("ambiguous-soak takeover is missing"));
    assert_eq!(takeover.forward_phase, OperationPhase::Soaking);
    assert_eq!(takeover.forward_status, PhaseJournalStatus::NeedsReconcile);
    clock += 1;
    let rollback_health = coordinator
        .advance_once(rollback.attempt_id, None, None, clock)
        .unwrap_or_else(|error| panic!("execute rollback after ambiguous soak: {error}"));
    assert_eq!(rollback_health.state.phase, OperationPhase::HealthChecking);
}

fn prepare_fence_prerequisites(security: &SecurityStore, operation: &OperationRecord, now_ms: i64) {
    security
        .acquire_resource(
            &ExecutionResource::ProjectDeploy(operation.project_id.clone()),
            operation.attempt_id,
            now_ms,
        )
        .unwrap_or_else(|error| panic!("acquire project lock fixture: {error}"));
    let ordered_phases = [OperationPhase::BackingUp, OperationPhase::Draining];
    commit_test_receipt(
        security,
        operation,
        OperationPhase::BackingUp,
        &ordered_phases,
        "safe backup",
        now_ms + 1,
    );
    commit_test_receipt(
        security,
        operation,
        OperationPhase::Draining,
        &ordered_phases,
        "safe drain",
        now_ms + 5,
    );
}

fn commit_test_receipt(
    security: &SecurityStore,
    operation: &OperationRecord,
    phase: OperationPhase,
    ordered_phases: &[OperationPhase],
    label: &str,
    now_ms: i64,
) -> EvidenceDigest {
    let intent = digest(&format!("{label} intent"));
    let authorization_digest = executor_authorization_digest(operation)
        .unwrap_or_else(|error| panic!("safe soak authorization digest: {error}"));
    security
        .begin_phase_intent(PhaseIntentRequest {
            attempt_id: operation.attempt_id,
            project_id: &operation.project_id,
            phase,
            branch: ExecutorPhaseBranch::Primary,
            phase_plan: ExecutorPhasePlan::new(ordered_phases, false),
            intent_digest: &intent,
            authorization_digest: &authorization_digest,
            started_at_ms: now_ms,
        })
        .unwrap_or_else(|error| panic!("begin soak receipt: {error}"));
    let source_proof = digest(&format!("{} stateful source gate", operation.attempt_id));
    if phase == OperationPhase::BackingUp {
        security
            .record_source_gate_proof(&SourceGateProofRecord {
                attempt_id: operation.attempt_id,
                phase,
                proof_digest: source_proof.clone(),
                project_id: operation.project_id.clone(),
                source_sequence: operation
                    .evidence
                    .source_sequence
                    .unwrap_or_else(|| panic!("fixture source sequence is missing")),
                attestation_digest: operation
                    .evidence
                    .source_attestation_digest
                    .clone()
                    .unwrap_or_else(|| panic!("fixture source attestation is missing")),
                checked_at_ms: now_ms,
            })
            .unwrap_or_else(|error| panic!("record fixture source proof: {error}"));
    }
    let artifacts = match phase {
        OperationPhase::BackingUp => PhaseArtifacts {
            source_gate_proof_digest: Some(source_proof.clone()),
            backup_set_id: Some(operation.attempt_id),
            base_backup_id: Some(Uuid::from_u128(operation.attempt_id.as_u128() ^ 1)),
            base_backup_manifest_digest: Some(digest(&format!("{label} manifest"))),
            base_backup_evidence_digest: Some(digest(&format!("{label} local evidence"))),
            base_backup_offsite_evidence_digest: Some(digest(&format!("{label} offsite evidence"))),
            base_backup_verification_digest: Some(digest(&format!(
                "{label} verified backup chain"
            ))),
            ..PhaseArtifacts::default()
        },
        OperationPhase::Draining => PhaseArtifacts {
            source_gate_proof_digest: Some(source_proof),
            drain_evidence_digest: Some(digest(&format!("{label} drain evidence"))),
            ..PhaseArtifacts::default()
        },
        _ => PhaseArtifacts::default(),
    };
    assert_eq!(
        security
            .record_phase_observation(
                operation.attempt_id,
                phase,
                &intent,
                &digest(&format!("{label} observation")),
                &artifacts,
                now_ms + 1,
            )
            .unwrap_or_else(|error| panic!("observe soak receipt: {error}")),
        rdashboard::store::ObservationAcceptance::Accepted
    );
    security
        .mark_phase_verified(operation.attempt_id, phase, now_ms + 2)
        .unwrap_or_else(|error| panic!("verify {label} receipt: {error}"));
    security
        .commit_phase_receipt(operation.attempt_id, phase, now_ms + 3)
        .unwrap_or_else(|error| panic!("commit {label} receipt: {error}"))
        .receipt_digest
}

#[test]
fn write_fence_requires_a_committed_drain_after_backup() {
    let fixture = execution_fixture('7');
    let security = reopen_security(&fixture.security_path);
    security
        .acquire_resource(
            &ExecutionResource::ProjectDeploy(fixture.operation.project_id.clone()),
            fixture.operation.attempt_id,
            100,
        )
        .unwrap_or_else(|error| panic!("acquire project lock fixture: {error}"));
    let ordered_phases = [OperationPhase::BackingUp, OperationPhase::Draining];
    commit_test_receipt(
        &security,
        &fixture.operation,
        OperationPhase::BackingUp,
        &ordered_phases,
        "backup without drain",
        101,
    );

    assert!(matches!(
        security.begin_fence_acquire(
            &fixture.operation.project_id,
            fixture.operation.attempt_id,
            105,
        ),
        Err(StoreError::FencePhaseInvalid)
    ));

    commit_test_receipt(
        &security,
        &fixture.operation,
        OperationPhase::Draining,
        &ordered_phases,
        "committed drain",
        106,
    );
    assert_eq!(
        security
            .begin_fence_acquire(
                &fixture.operation.project_id,
                fixture.operation.attempt_id,
                110,
            )
            .unwrap_or_else(|error| panic!("begin fence after drain: {error}"))
            .state,
        FenceJournalState::AcquireIntent
    );
}

#[test]
fn idempotent_fence_acquire_revalidates_committed_backup_and_drain_receipts() {
    let fixture = execution_fixture('8');
    let security = reopen_security(&fixture.security_path);
    prepare_fence_prerequisites(&security, &fixture.operation, 120);
    assert_eq!(
        security
            .begin_fence_acquire(
                &fixture.operation.project_id,
                fixture.operation.attempt_id,
                130,
            )
            .unwrap_or_else(|error| panic!("begin fence fixture: {error}"))
            .state,
        FenceJournalState::AcquireIntent
    );

    let tamper = rusqlite::Connection::open(&fixture.security_path)
        .unwrap_or_else(|error| panic!("open fence prerequisite tamper store: {error}"));
    tamper
        .execute(
            "DELETE FROM executor_phase_receipts WHERE attempt_id = ?1 AND phase = 'draining'",
            [fixture.operation.attempt_id.to_string()],
        )
        .unwrap_or_else(|error| panic!("remove committed drain receipt: {error}"));
    drop(tamper);

    assert!(matches!(
        security.begin_fence_acquire(
            &fixture.operation.project_id,
            fixture.operation.attempt_id,
            131,
        ),
        Err(StoreError::FencePhaseInvalid)
    ));
}

#[test]
fn fence_acquire_and_release_recover_at_every_boundary() {
    let crash_points = [
        FenceCrashPoint::AfterIntentPersisted,
        FenceCrashPoint::AfterEffectApplied,
        FenceCrashPoint::AfterObservationPersisted,
    ];
    for (index, crash_point) in crash_points.into_iter().enumerate() {
        let fixture = execution_fixture(char::from(b'b' + u8::try_from(index).unwrap_or(0)));
        let security = reopen_security(&fixture.security_path);
        prepare_fence_prerequisites(&security, &fixture.operation, 190);
        let executor = recovered_executor(
            security,
            fixture.effects.clone(),
            &fixture.operation.project_id,
        );
        assert!(matches!(
            executor.acquire_write_fence(
                &fixture.operation.project_id,
                fixture.operation.attempt_id,
                Some(crash_point),
                200
            ),
            Err(FenceExecutionError::InjectedCrash(actual)) if actual == crash_point
        ));
        drop(executor);
        let recovered_security = reopen_security(&fixture.security_path);
        let recovered = recovered_executor(
            recovered_security.clone(),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        );
        recovered
            .reconcile_active_fences(201)
            .unwrap_or_else(|error| panic!("recover fence acquire {crash_point:?}: {error}"));
        assert_eq!(
            recovered_security
                .active_fence(&fixture.operation.project_id)
                .unwrap_or_else(|error| panic!("active fence: {error}"))
                .map(|lease| lease.state),
            Some(FenceJournalState::Held)
        );
    }

    for (target, crash_point) in ['e', 'f', '0'].into_iter().zip(crash_points) {
        let fixture = execution_fixture(target);
        let security = reopen_security(&fixture.security_path);
        prepare_fence_prerequisites(&security, &fixture.operation, 290);
        let executor = recovered_executor(
            security.clone(),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        );
        executor
            .acquire_write_fence(
                &fixture.operation.project_id,
                fixture.operation.attempt_id,
                None,
                300,
            )
            .unwrap_or_else(|error| panic!("acquire release fixture: {error}"));
        let safe_receipt = safe_soak_receipt(&security, &fixture.operation, 301);
        assert!(matches!(
            executor.release_write_fence(
                &fixture.operation.project_id,
                fixture.operation.attempt_id,
                &safe_receipt,
                Some(crash_point),
                310
            ),
            Err(FenceExecutionError::InjectedCrash(actual)) if actual == crash_point
        ));
        drop(executor);
        let recovered_security = reopen_security(&fixture.security_path);
        let recovered = recovered_executor(
            recovered_security.clone(),
            fixture.effects.clone(),
            &fixture.operation.project_id,
        );
        recovered
            .reconcile_active_fences(311)
            .unwrap_or_else(|error| panic!("recover fence release {crash_point:?}: {error}"));
        assert!(
            recovered_security
                .active_fence(&fixture.operation.project_id)
                .unwrap_or_else(|error| panic!("released fence state: {error}"))
                .is_none()
        );
        assert_eq!(
            fixture
                .effects
                .observe_fence(&fixture.operation.project_id)
                .unwrap_or_else(|error| panic!("external fence state: {error}")),
            FenceObservation::Released
        );
    }
}

#[test]
fn fence_release_rejects_a_tampered_release_safe_receipt_before_the_effect() {
    let fixture = execution_fixture('a');
    let security = reopen_security(&fixture.security_path);
    prepare_fence_prerequisites(&security, &fixture.operation, 400);
    let executor = recovered_executor(
        security.clone(),
        fixture.effects.clone(),
        &fixture.operation.project_id,
    );
    executor
        .acquire_write_fence(
            &fixture.operation.project_id,
            fixture.operation.attempt_id,
            None,
            410,
        )
        .unwrap_or_else(|error| panic!("acquire tamper-test fence: {error}"));
    let safe_receipt = safe_soak_receipt(&security, &fixture.operation, 411);
    let tamper = rusqlite::Connection::open(&fixture.security_path)
        .unwrap_or_else(|error| panic!("open tamper-test security store: {error}"));
    tamper
        .execute(
            "UPDATE executor_phase_receipts SET receipt_json = '{}'
             WHERE receipt_digest = ?1",
            [safe_receipt.as_str()],
        )
        .unwrap_or_else(|error| panic!("tamper release-safe receipt: {error}"));
    drop(tamper);

    assert!(matches!(
        executor.release_write_fence(
            &fixture.operation.project_id,
            fixture.operation.attempt_id,
            &safe_receipt,
            None,
            420,
        ),
        Err(FenceExecutionError::Store(
            StoreError::CorruptSecurityJournal(_)
        ))
    ));
    assert!(matches!(
        fixture
            .effects
            .observe_fence(&fixture.operation.project_id)
            .unwrap_or_else(|error| panic!("observe fence after receipt tamper: {error}")),
        FenceObservation::Held { .. }
    ));
}

#[test]
fn fence_recovery_revalidates_the_receipt_and_revokes_project_readiness_on_tamper() {
    let fixture = execution_fixture('b');
    let security = reopen_security(&fixture.security_path);
    prepare_fence_prerequisites(&security, &fixture.operation, 500);
    let executor = recovered_executor(
        security.clone(),
        fixture.effects.clone(),
        &fixture.operation.project_id,
    );
    executor
        .acquire_write_fence(
            &fixture.operation.project_id,
            fixture.operation.attempt_id,
            None,
            510,
        )
        .unwrap_or_else(|error| panic!("acquire recovery-tamper fence: {error}"));
    let safe_receipt = safe_soak_receipt(&security, &fixture.operation, 511);
    assert!(matches!(
        executor.release_write_fence(
            &fixture.operation.project_id,
            fixture.operation.attempt_id,
            &safe_receipt,
            Some(FenceCrashPoint::AfterIntentPersisted),
            520,
        ),
        Err(FenceExecutionError::InjectedCrash(
            FenceCrashPoint::AfterIntentPersisted
        ))
    ));
    let tamper = rusqlite::Connection::open(&fixture.security_path)
        .unwrap_or_else(|error| panic!("open recovery-tamper security store: {error}"));
    let mismatched_receipt = PhaseReceipt::new(
        fixture.operation.attempt_id,
        OperationPhase::Soaking,
        ExecutorPhaseBranch::Primary,
        digest("mismatched release intent"),
        digest("mismatched release observation"),
        PhaseArtifacts::default(),
        519,
    )
    .unwrap_or_else(|error| panic!("construct mismatched release receipt: {error}"));
    tamper
        .execute(
            "UPDATE executor_phase_receipts SET receipt_json = ?2
             WHERE receipt_digest = ?1",
            rusqlite::params![
                safe_receipt.as_str(),
                serde_json::to_string(&mismatched_receipt)
                    .unwrap_or_else(|error| panic!("encode mismatched receipt: {error}"))
            ],
        )
        .unwrap_or_else(|error| panic!("mismatch recovery receipt binding: {error}"));
    drop(tamper);

    assert!(matches!(
        executor.reconcile_active_fences(521),
        Err(FenceExecutionError::Store(
            StoreError::CorruptSecurityJournal(_)
        ))
    ));
    assert!(matches!(
        executor.execute_phase(&fixture.operation, None, 522),
        Err(PhaseExecutionError::Store(
            StoreError::SecurityRecoveryRequired
        ))
    ));
    assert_eq!(
        security
            .active_fence(&fixture.operation.project_id)
            .unwrap_or_else(|error| panic!("load fence after recovery tamper: {error}"))
            .map(|fence| fence.state),
        Some(FenceJournalState::ReleaseIntent)
    );
    assert!(matches!(
        fixture
            .effects
            .observe_fence(&fixture.operation.project_id)
            .unwrap_or_else(|error| panic!("observe held recovery-tamper fence: {error}")),
        FenceObservation::Held { .. }
    ));
}

#[test]
fn mismatched_and_orphan_fences_are_persistently_blocked() {
    let fixture = execution_fixture('1');
    let security = reopen_security(&fixture.security_path);
    prepare_fence_prerequisites(&security, &fixture.operation, 190);
    let executor = recovered_executor(
        security.clone(),
        fixture.effects.clone(),
        &fixture.operation.project_id,
    );
    assert!(matches!(
        executor.acquire_write_fence(
            &fixture.operation.project_id,
            fixture.operation.attempt_id,
            Some(FenceCrashPoint::AfterIntentPersisted),
            200
        ),
        Err(FenceExecutionError::InjectedCrash(
            FenceCrashPoint::AfterIntentPersisted
        ))
    ));
    fixture
        .effects
        .force_fence(
            fixture.operation.project_id.clone(),
            Uuid::new_v4(),
            9_999,
            Uuid::new_v4(),
        )
        .unwrap_or_else(|error| panic!("force mismatched fence: {error}"));
    assert!(matches!(
        executor.reconcile_active_fences(201),
        Err(FenceExecutionError::NeedsReconcile)
    ));
    assert_eq!(
        security
            .active_fence(&fixture.operation.project_id)
            .unwrap_or_else(|error| panic!("mismatched fence journal: {error}"))
            .map(|lease| lease.state),
        Some(FenceJournalState::NeedsReconcile)
    );
    assert!(matches!(
        security.begin_fence_acquire(
            &fixture.operation.project_id,
            fixture.operation.attempt_id,
            10_000_000
        ),
        Err(StoreError::FenceConflict)
    ));

    let orphan_directory = tempdir().unwrap_or_else(|error| panic!("orphan temp dir: {error}"));
    let orphan_security = SecurityStore::open(orphan_directory.path().join("security.sqlite"))
        .unwrap_or_else(|error| panic!("orphan security store: {error}"));
    let orphan_project = project();
    let orphan_attempt = Uuid::new_v4();
    orphan_security
        .authorize_attempt(
            &ExecutorAuthorization {
                authorization_id: Uuid::new_v4(),
                digest: digest("orphan authorization"),
                attempt_id: orphan_attempt,
                project_id: orphan_project.clone(),
                expires_at_ms: 10_000,
                disk_reservation: None,
            },
            100,
        )
        .unwrap_or_else(|error| panic!("orphan authorization: {error}"));
    assert_eq!(
        orphan_security
            .reconcile_fence(
                &orphan_project,
                &FenceObservation::Held {
                    attempt_id: Uuid::new_v4(),
                    epoch: 777,
                    token: Uuid::new_v4(),
                },
                101,
            )
            .unwrap_or_else(|error| panic!("record orphan fence: {error}")),
        FenceProjection::NeedsReconcile
    );
    assert_eq!(
        orphan_security
            .active_fence(&orphan_project)
            .unwrap_or_else(|error| panic!("orphan fence projection: {error}"))
            .map(|lease| lease.state),
        Some(FenceJournalState::NeedsReconcile)
    );
    assert!(matches!(
        orphan_security.begin_fence_acquire(&orphan_project, orphan_attempt, 102),
        Err(StoreError::FenceConflict)
    ));
}

#[test]
fn reappearing_released_epoch_records_anomaly_without_rewriting_history() {
    let fixture = execution_fixture('6');
    let security = reopen_security(&fixture.security_path);
    prepare_fence_prerequisites(&security, &fixture.operation, 190);
    let executor = recovered_executor(
        security.clone(),
        fixture.effects.clone(),
        &fixture.operation.project_id,
    );
    let lease = executor
        .acquire_write_fence(
            &fixture.operation.project_id,
            fixture.operation.attempt_id,
            None,
            200,
        )
        .unwrap_or_else(|error| panic!("acquire historical fence: {error}"));
    let safe_receipt = safe_soak_receipt(&security, &fixture.operation, 201);
    executor
        .release_write_fence(
            &fixture.operation.project_id,
            fixture.operation.attempt_id,
            &safe_receipt,
            None,
            210,
        )
        .unwrap_or_else(|error| panic!("release historical fence: {error}"));

    let foreign_attempt = Uuid::new_v4();
    let foreign_token = Uuid::new_v4();
    assert_eq!(
        security
            .reconcile_fence(
                &fixture.operation.project_id,
                &FenceObservation::Held {
                    attempt_id: foreign_attempt,
                    epoch: lease.epoch,
                    token: foreign_token,
                },
                211,
            )
            .unwrap_or_else(|error| panic!("record reappearing epoch: {error}")),
        FenceProjection::NeedsReconcile
    );
    let anomaly = security
        .active_fence(&fixture.operation.project_id)
        .unwrap_or_else(|error| panic!("load reappearing epoch anomaly: {error}"))
        .unwrap_or_else(|| panic!("reappearing epoch anomaly is missing"));
    assert_eq!(anomaly.state, FenceJournalState::NeedsReconcile);
    assert_eq!(anomaly.epoch, lease.epoch);
    assert_eq!(anomaly.attempt_id, foreign_attempt);
    assert_ne!(anomaly.journal_id, lease.journal_id);
}
