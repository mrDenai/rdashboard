use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use serde::Serialize;
use uuid::Uuid;

use crate::{
    controller::DurableController,
    domain::{
        AuthorizedPhaseSpecDigestV1, BlockingReason, DiskAvailabilityObservation, EvidenceDigest,
        FailureCapsule, GitCommitId, InstalledPolicyIdentity, OperationActor, OperationKind,
        OperationPhase, OperationRecord, OperationRecoveryMode, OperationResult, PhaseArtifacts,
        PhaseReceipt, ProjectId, ReleaseClass, Retryability, StructuredError,
    },
    source::{LiveSourceGate, SourceGateError},
    store::{
        BackupBoundaryLease, DrainIdentityLease, ExecutionResource, ExecutorPhaseBranch,
        ExecutorPhasePlan, FenceJournalState, FenceLease, FenceObservation, FenceProjection,
        ObservationAcceptance, PhaseIntentRequest, PhaseJournalStatus, PhaseObservationRequest,
        SecurityStore, SourceGateProofRecord, StoreError,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseIntent {
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub payload: PhaseIntentPayloadV1,
    pub digest: EvidenceDigest,
}

impl PhaseIntent {
    pub fn from_operation(
        operation: &OperationRecord,
        executor_authorization_digest: EvidenceDigest,
    ) -> Result<Self, StoreError> {
        phase_intent(operation, executor_authorization_digest)
    }

    pub fn has_valid_digest(&self) -> Result<bool, serde_json::Error> {
        Ok(self.attempt_id == self.payload.attempt_id
            && self.project_id == self.payload.project_id
            && self.phase == self.payload.phase
            && self.branch == self.payload.branch
            && self.digest == EvidenceDigest::sha256(serde_jcs::to_vec(&self.payload)?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseIntentPayloadV1 {
    pub purpose: &'static str,
    pub attempt_id: Uuid,
    pub request_id: Uuid,
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub release_class: Option<ReleaseClass>,
    pub target_commit: Option<GitCommitId>,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub installed_policy: Option<InstalledPolicyIdentity>,
    pub authorized_phase_spec_digests: Vec<AuthorizedPhaseSpecDigestV1>,
    pub executor_authorization_digest: EvidenceDigest,
    pub source_attestation_digest: Option<EvidenceDigest>,
    pub source_sequence: Option<u64>,
    pub source_gate_proof_digest: Option<EvidenceDigest>,
    pub drain_evidence_digest: Option<EvidenceDigest>,
    pub source_export_digest: Option<EvidenceDigest>,
    pub prefetch_evidence_digest: Option<EvidenceDigest>,
    pub ci_evidence_digest: Option<EvidenceDigest>,
    pub build_plan_digest: Option<EvidenceDigest>,
    pub deployment_plan_digest: Option<EvidenceDigest>,
    pub release_bundle_digest: Option<EvidenceDigest>,
    pub resource_reservation_digest: Option<EvidenceDigest>,
    pub action_grant_digest: Option<EvidenceDigest>,
    pub build_context_digest: Option<EvidenceDigest>,
    pub generated_output_digests: Vec<EvidenceDigest>,
    pub image_digest: Option<EvidenceDigest>,
    pub image_id_digest: Option<EvidenceDigest>,
    pub base_image_digests: Vec<EvidenceDigest>,
    pub schema_version: Option<String>,
    pub backup_id: Option<Uuid>,
    pub backup_set_id: Option<Uuid>,
    pub base_backup_id: Option<Uuid>,
    pub base_backup_manifest_digest: Option<EvidenceDigest>,
    pub base_backup_evidence_digest: Option<EvidenceDigest>,
    pub base_backup_offsite_evidence_digest: Option<EvidenceDigest>,
    pub base_backup_verification_digest: Option<EvidenceDigest>,
    pub cutover_backup_id: Option<Uuid>,
    pub cutover_backup_manifest_digest: Option<EvidenceDigest>,
    pub cutover_backup_evidence_digest: Option<EvidenceDigest>,
    pub cutover_backup_verification_digest: Option<EvidenceDigest>,
    pub previous_release_bundle_digest: Option<EvidenceDigest>,
    pub health_evidence_digest: Option<EvidenceDigest>,
    pub rollback_health_evidence_digest: Option<EvidenceDigest>,
    pub fencing_epoch: Option<u64>,
    pub fence_acquisition_receipt_digest: Option<EvidenceDigest>,
    pub recovery_mode: Option<OperationRecoveryMode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectObservation {
    Absent,
    Applied(Box<PhaseEffectEvidence>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseEffectEvidence {
    pub intent_digest: EvidenceDigest,
    pub observation_digest: EvidenceDigest,
    pub artifacts: PhaseArtifacts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PhaseOperationIdentityLeaseV1 {
    BaseBackup(BackupBoundaryLease),
    Drain(DrainIdentityLease),
}

pub trait ExternalEffects: Clone + Send + Sync + 'static {
    fn observe_phase(&self, intent: &PhaseIntent)
    -> Result<EffectObservation, ExternalEffectError>;

    fn apply_phase(&self, intent: &PhaseIntent) -> Result<(), ExternalEffectError>;

    fn observe_phase_with_operation_identity(
        &self,
        intent: &PhaseIntent,
        _operation_identity: Option<&PhaseOperationIdentityLeaseV1>,
    ) -> Result<EffectObservation, ExternalEffectError> {
        self.observe_phase(intent)
    }

    fn apply_phase_with_operation_identity(
        &self,
        intent: &PhaseIntent,
        _operation_identity: Option<&PhaseOperationIdentityLeaseV1>,
    ) -> Result<(), ExternalEffectError> {
        self.apply_phase(intent)
    }

    fn observe_fence(
        &self,
        project_id: &ProjectId,
    ) -> Result<FenceObservation, ExternalEffectError>;

    fn acquire_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError>;

    fn release_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError>;
}

pub trait DiskSpaceProbe: std::fmt::Debug + Send + Sync + 'static {
    fn observe(
        &self,
        project_id: &ProjectId,
        now_ms: i64,
    ) -> Result<DiskAvailabilityObservation, StoreError>;
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExternalEffectError {
    #[error("model external state lock was poisoned")]
    StatePoisoned,
    #[error("external state conflicts with the persisted intent")]
    ConflictingState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseCrashPoint {
    AfterIntentPersisted,
    AfterEffectApplied,
    AfterObservationPersisted,
    AfterVerificationPersisted,
    AfterReceiptCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FenceCrashPoint {
    AfterIntentPersisted,
    AfterEffectApplied,
    AfterObservationPersisted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorCrashPoint {
    AfterSecurityReceipt,
    AfterControllerProjection,
}

#[derive(Debug, thiserror::Error)]
pub enum PhaseExecutionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    External(#[from] ExternalEffectError),
    #[error(transparent)]
    Source(#[from] SourceGateError),
    #[error("injected executor crash at {0:?}")]
    InjectedCrash(PhaseCrashPoint),
    #[error("executor evidence is ambiguous and requires reconciliation")]
    NeedsReconcile,
    #[error("operation is not in an executable running phase")]
    InvalidOperationState,
}

#[derive(Debug, thiserror::Error)]
pub enum FenceExecutionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    External(#[from] ExternalEffectError),
    #[error("injected fence crash at {0:?}")]
    InjectedCrash(FenceCrashPoint),
    #[error("write fence evidence is ambiguous and requires reconciliation")]
    NeedsReconcile,
}

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Executor(#[from] PhaseExecutionError),
    #[error(transparent)]
    Fence(#[from] FenceExecutionError),
    #[error("injected coordinator crash at {0:?}")]
    InjectedCrash(CoordinatorCrashPoint),
}

#[derive(Clone, Debug)]
pub struct DurableExecutor<A> {
    security: SecurityStore,
    effects: A,
    recovered_projects: Arc<Mutex<BTreeSet<ProjectId>>>,
    project_execution_gates: Arc<Mutex<BTreeMap<ProjectId, Arc<Mutex<()>>>>>,
    source_gate: Option<Arc<dyn LiveSourceGate>>,
    disk_space_probe: Option<Arc<dyn DiskSpaceProbe>>,
}

impl<A: ExternalEffects> DurableExecutor<A> {
    pub fn new(security: SecurityStore, effects: A) -> Self {
        Self {
            security,
            effects,
            recovered_projects: Arc::new(Mutex::new(BTreeSet::new())),
            project_execution_gates: Arc::new(Mutex::new(BTreeMap::new())),
            source_gate: None,
            disk_space_probe: None,
        }
    }

    #[must_use]
    pub fn with_source_gate(mut self, source_gate: Arc<dyn LiveSourceGate>) -> Self {
        self.source_gate = Some(source_gate);
        self
    }

    #[must_use]
    pub fn with_disk_space_probe(mut self, disk_space_probe: Arc<dyn DiskSpaceProbe>) -> Self {
        self.disk_space_probe = Some(disk_space_probe);
        self
    }

    pub const fn security(&self) -> &SecurityStore {
        &self.security
    }

    pub fn recover_security_state(
        &self,
        project_ids: &[ProjectId],
        now_ms: i64,
    ) -> Result<(), FenceExecutionError> {
        let project_ids = project_ids.iter().cloned().collect::<BTreeSet<_>>();
        if project_ids.is_empty() {
            return Err(StoreError::InvalidControllerInput(
                "security recovery requires the installed project set",
            )
            .into());
        }
        for project_id in project_ids {
            let execution_gate = self.project_execution_gate(&project_id)?;
            let _execution_guard = execution_gate
                .lock()
                .map_err(|_| StoreError::LockPoisoned)?;
            self.recovered_projects
                .lock()
                .map_err(|_| StoreError::LockPoisoned)?
                .remove(&project_id);
            self.reconcile_active_fence_for_project_under_gate(&project_id, now_ms)?;
            let observation = self.effects.observe_fence(&project_id)?;
            if self
                .security
                .reconcile_fence(&project_id, &observation, now_ms)?
                == FenceProjection::NeedsReconcile
            {
                return Err(FenceExecutionError::NeedsReconcile);
            }
            self.recovered_projects
                .lock()
                .map_err(|_| StoreError::LockPoisoned)?
                .insert(project_id);
        }
        Ok(())
    }

    fn project_execution_gate(&self, project_id: &ProjectId) -> Result<Arc<Mutex<()>>, StoreError> {
        let mut gates = self
            .project_execution_gates
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        Ok(gates
            .entry(project_id.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone())
    }

    fn require_recovery(&self, project_id: &ProjectId) -> Result<(), StoreError> {
        if self
            .recovered_projects
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?
            .contains(project_id)
        {
            Ok(())
        } else {
            Err(StoreError::SecurityRecoveryRequired)
        }
    }

    pub fn execute_phase(
        &self,
        operation: &OperationRecord,
        crash_at: Option<PhaseCrashPoint>,
        now_ms: i64,
    ) -> Result<PhaseReceipt, PhaseExecutionError> {
        let execution_gate = self.project_execution_gate(&operation.project_id)?;
        let _execution_guard = execution_gate
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        self.execute_phase_under_gate(operation, crash_at, now_ms)
    }

    fn execute_phase_under_gate(
        &self,
        operation: &OperationRecord,
        crash_at: Option<PhaseCrashPoint>,
        now_ms: i64,
    ) -> Result<PhaseReceipt, PhaseExecutionError> {
        self.require_recovery(&operation.project_id)?;
        if operation.state.result != OperationResult::Running
            || operation.state.phase == OperationPhase::Reconciliation
        {
            return Err(PhaseExecutionError::InvalidOperationState);
        }
        let phase = operation.state.phase;
        let authorization_digest = executor_authorization_digest(operation)?;
        let intent = phase_intent(operation, authorization_digest.clone())?;
        let branch = intent.branch;
        let ordered_phases = operation
            .operation_kind
            .required_phases(operation.release_class)
            .map_err(StoreError::from)?;
        let phase_plan = ExecutorPhasePlan::new(
            ordered_phases,
            operation.operation_kind == OperationKind::Deploy
                && matches!(
                    operation.release_class,
                    Some(ReleaseClass::CodeOnlyCompatible | ReleaseClass::StatefulCompatible)
                ),
        );

        if branch == ExecutorPhaseBranch::RollbackRecovery && phase == OperationPhase::Rollback {
            self.security.begin_rollback_takeover(
                operation.attempt_id,
                &operation.project_id,
                &authorization_digest,
                now_ms,
            )?;
        }

        self.security.validate_phase_start(
            operation.attempt_id,
            &operation.project_id,
            phase,
            branch,
            &phase_plan,
            &authorization_digest,
        )?;

        if let Some(receipt) =
            self.security
                .phase_receipt_in_branch(operation.attempt_id, phase, branch)?
        {
            self.complete_live_source_mutation(operation)?;
            self.cleanup_ephemeral_resource(operation, now_ms)?;
            return Ok(receipt);
        }

        let journal = self.security.begin_phase_intent(PhaseIntentRequest {
            attempt_id: operation.attempt_id,
            project_id: &operation.project_id,
            phase,
            branch,
            phase_plan,
            intent_digest: &intent.digest,
            authorization_digest: &authorization_digest,
            started_at_ms: now_ms,
        })?;
        if journal.status == PhaseJournalStatus::NeedsReconcile {
            self.compensate_rejected_source_proof(operation, &intent, now_ms)?;
        }

        self.acquire_persistent_phase_resources(operation, phase, now_ms)?;
        if let Some(resource) = phase_resource(operation) {
            self.security
                .acquire_resource(&resource, operation.attempt_id, now_ms)?;
        }
        self.prepare_drain_identity(operation, now_ms)?;
        phase_crash(crash_at, PhaseCrashPoint::AfterIntentPersisted)?;

        self.apply_or_recover_phase_effect(operation, &intent, now_ms)?;
        phase_crash(crash_at, PhaseCrashPoint::AfterEffectApplied)?;

        let source_gate_proof =
            self.required_source_gate_proof(operation, phase, branch, now_ms)?;

        let receipt =
            self.observe_and_commit_phase(operation, &intent, source_gate_proof, crash_at, now_ms)?;
        self.complete_live_source_mutation(operation)?;
        self.cleanup_ephemeral_resource(operation, now_ms)?;
        Ok(receipt)
    }

    fn observe_and_commit_phase(
        &self,
        operation: &OperationRecord,
        intent: &PhaseIntent,
        source_gate_proof: Option<EvidenceDigest>,
        crash_at: Option<PhaseCrashPoint>,
        now_ms: i64,
    ) -> Result<PhaseReceipt, PhaseExecutionError> {
        let operation_identity = self.operation_identity_for_phase(operation)?;
        let mut evidence = match self
            .effects
            .observe_phase_with_operation_identity(intent, operation_identity.as_ref())
        {
            Ok(EffectObservation::Applied(evidence)) => evidence,
            Ok(EffectObservation::Absent) | Err(_) => {
                self.security.mark_phase_needs_reconcile_in_branch(
                    operation.attempt_id,
                    intent.phase,
                    intent.branch,
                    now_ms,
                )?;
                return Err(PhaseExecutionError::NeedsReconcile);
            }
        };
        if let Some(proof) = source_gate_proof {
            match &evidence.artifacts.source_gate_proof_digest {
                Some(existing) if existing != &proof => {
                    self.security.mark_phase_needs_reconcile_in_branch(
                        operation.attempt_id,
                        intent.phase,
                        intent.branch,
                        now_ms,
                    )?;
                    return Err(PhaseExecutionError::NeedsReconcile);
                }
                Some(_) => {}
                None => evidence.artifacts.source_gate_proof_digest = Some(proof),
            }
        }
        if self
            .security
            .record_phase_observation_in_branch(PhaseObservationRequest {
                attempt_id: operation.attempt_id,
                phase: intent.phase,
                branch: intent.branch,
                observed_intent_digest: &evidence.intent_digest,
                observation_digest: &evidence.observation_digest,
                artifacts: &evidence.artifacts,
                observed_at_ms: now_ms,
            })?
            == ObservationAcceptance::NeedsReconcile
        {
            return Err(PhaseExecutionError::NeedsReconcile);
        }
        phase_crash(crash_at, PhaseCrashPoint::AfterObservationPersisted)?;

        self.security.mark_phase_verified_in_branch(
            operation.attempt_id,
            intent.phase,
            intent.branch,
            now_ms,
        )?;
        phase_crash(crash_at, PhaseCrashPoint::AfterVerificationPersisted)?;

        let receipt = self.security.commit_phase_receipt_in_branch(
            operation.attempt_id,
            intent.phase,
            intent.branch,
            now_ms,
        )?;
        phase_crash(crash_at, PhaseCrashPoint::AfterReceiptCommitted)?;
        Ok(receipt)
    }

    fn apply_or_recover_phase_effect(
        &self,
        operation: &OperationRecord,
        intent: &PhaseIntent,
        now_ms: i64,
    ) -> Result<(), PhaseExecutionError> {
        let operation_identity = self.operation_identity_for_phase(operation)?;
        match self
            .effects
            .observe_phase_with_operation_identity(intent, operation_identity.as_ref())?
        {
            EffectObservation::Absent => {
                self.authorize_live_source_mutation(operation, intent, now_ms)?;
                match self
                    .effects
                    .apply_phase_with_operation_identity(intent, operation_identity.as_ref())
                {
                    Ok(()) => Ok(()),
                    Err(apply_error) => self.reconcile_failed_phase_application(
                        operation,
                        intent,
                        apply_error,
                        now_ms,
                    ),
                }
            }
            EffectObservation::Applied(evidence) if evidence.intent_digest == intent.digest => {
                Ok(())
            }
            EffectObservation::Applied(evidence) => {
                let acceptance =
                    self.security
                        .record_phase_observation_in_branch(PhaseObservationRequest {
                            attempt_id: operation.attempt_id,
                            phase: intent.phase,
                            branch: intent.branch,
                            observed_intent_digest: &evidence.intent_digest,
                            observation_digest: &evidence.observation_digest,
                            artifacts: &evidence.artifacts,
                            observed_at_ms: now_ms,
                        })?;
                debug_assert_eq!(acceptance, ObservationAcceptance::NeedsReconcile);
                Err(PhaseExecutionError::NeedsReconcile)
            }
        }
    }

    fn reconcile_failed_phase_application(
        &self,
        operation: &OperationRecord,
        intent: &PhaseIntent,
        apply_error: ExternalEffectError,
        now_ms: i64,
    ) -> Result<(), PhaseExecutionError> {
        let operation_identity = self.operation_identity_for_phase(operation)?;
        match self
            .effects
            .observe_phase_with_operation_identity(intent, operation_identity.as_ref())
        {
            Ok(EffectObservation::Absent) => {
                self.abort_live_source_mutation(operation)?;
                Err(apply_error.into())
            }
            Ok(EffectObservation::Applied(evidence)) if evidence.intent_digest == intent.digest => {
                Ok(())
            }
            Ok(EffectObservation::Applied(evidence)) => {
                self.security
                    .record_phase_observation_in_branch(PhaseObservationRequest {
                        attempt_id: operation.attempt_id,
                        phase: intent.phase,
                        branch: intent.branch,
                        observed_intent_digest: &evidence.intent_digest,
                        observation_digest: &evidence.observation_digest,
                        artifacts: &evidence.artifacts,
                        observed_at_ms: now_ms,
                    })?;
                Err(PhaseExecutionError::NeedsReconcile)
            }
            Err(_) => {
                self.security.mark_phase_needs_reconcile_in_branch(
                    operation.attempt_id,
                    intent.phase,
                    intent.branch,
                    now_ms,
                )?;
                Err(PhaseExecutionError::NeedsReconcile)
            }
        }
    }

    fn authorize_live_source_mutation(
        &self,
        operation: &OperationRecord,
        intent: &PhaseIntent,
        now_ms: i64,
    ) -> Result<(), PhaseExecutionError> {
        if !requires_live_source_check(operation) {
            return Ok(());
        }
        let source_result = self
            .source_gate
            .as_ref()
            .ok_or(SourceGateError::Unavailable)
            .and_then(|gate| gate.check_live(operation, now_ms));
        let proof = match source_result {
            Ok(proof) => proof,
            Err(error) => {
                self.abort_live_source_mutation(operation)?;
                self.suspend_pre_mutation_resources(operation, now_ms)?;
                return Err(error.into());
            }
        };
        let record_result = self
            .security
            .record_source_gate_proof(&SourceGateProofRecord {
                attempt_id: operation.attempt_id,
                phase: intent.phase,
                proof_digest: proof.digest,
                project_id: proof.project_id,
                source_sequence: proof.sequence,
                attestation_digest: proof.attestation_digest,
                checked_at_ms: proof.checked_at_ms,
            });
        match record_result {
            Ok(()) => Ok(()),
            Err(error) => {
                self.abort_live_source_mutation(operation)?;
                if self.security.source_gate_rejection_pending(
                    operation.attempt_id,
                    &operation.project_id,
                    intent.phase,
                    intent.branch,
                )? {
                    self.security.compensate_source_gate_rejection(
                        operation.attempt_id,
                        &operation.project_id,
                        intent.phase,
                        intent.branch,
                        &intent.digest,
                        now_ms,
                    )?;
                }
                self.suspend_pre_mutation_resources(operation, now_ms)?;
                Err(error.into())
            }
        }
    }

    fn compensate_rejected_source_proof(
        &self,
        operation: &OperationRecord,
        intent: &PhaseIntent,
        now_ms: i64,
    ) -> Result<(), PhaseExecutionError> {
        if !self.security.source_gate_rejection_pending(
            operation.attempt_id,
            &operation.project_id,
            intent.phase,
            intent.branch,
        )? {
            return Err(PhaseExecutionError::NeedsReconcile);
        }
        let operation_identity = self.operation_identity_for_phase(operation)?;
        match self
            .effects
            .observe_phase_with_operation_identity(intent, operation_identity.as_ref())
        {
            Ok(EffectObservation::Absent) => {}
            Ok(EffectObservation::Applied(_)) | Err(_) => {
                return Err(PhaseExecutionError::NeedsReconcile);
            }
        }
        self.abort_live_source_mutation(operation)?;
        self.security.compensate_source_gate_rejection(
            operation.attempt_id,
            &operation.project_id,
            intent.phase,
            intent.branch,
            &intent.digest,
            now_ms,
        )?;
        Ok(())
    }

    fn prepare_drain_identity(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        if operation.state.phase == OperationPhase::BackingUp
            && self
                .security
                .authorized_phase_spec_in_branch(
                    operation.attempt_id,
                    OperationPhase::BackingUp,
                    ExecutorPhaseBranch::Primary,
                )?
                .is_some()
        {
            self.security.begin_backup_boundary(
                &operation.project_id,
                operation.attempt_id,
                now_ms,
            )?;
        } else if is_stateful_deploy(operation) && operation.state.phase == OperationPhase::Draining
        {
            self.security.begin_drain_identity(
                &operation.project_id,
                operation.attempt_id,
                now_ms,
            )?;
        }
        Ok(())
    }

    fn operation_identity_for_phase(
        &self,
        operation: &OperationRecord,
    ) -> Result<Option<PhaseOperationIdentityLeaseV1>, PhaseExecutionError> {
        match operation.state.phase {
            OperationPhase::BackingUp
                if self
                    .security
                    .authorized_phase_spec_in_branch(
                        operation.attempt_id,
                        OperationPhase::BackingUp,
                        ExecutorPhaseBranch::Primary,
                    )?
                    .is_some() =>
            {
                match self
                    .security
                    .active_backup_boundary(&operation.project_id)?
                {
                    Some(identity) if identity.attempt_id == operation.attempt_id => {
                        Ok(Some(PhaseOperationIdentityLeaseV1::BaseBackup(identity)))
                    }
                    Some(_) | None => Err(PhaseExecutionError::NeedsReconcile),
                }
            }
            OperationPhase::Draining if is_stateful_deploy(operation) => {
                match self.security.active_drain_identity(&operation.project_id)? {
                    Some(identity) if identity.attempt_id == operation.attempt_id => {
                        Ok(Some(PhaseOperationIdentityLeaseV1::Drain(identity)))
                    }
                    Some(_) | None => Err(PhaseExecutionError::NeedsReconcile),
                }
            }
            _ => Ok(None),
        }
    }

    fn acquire_persistent_phase_resources(
        &self,
        operation: &OperationRecord,
        phase: OperationPhase,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        if requires_disk_reservation(operation, phase) {
            let observation = self
                .disk_space_probe
                .as_ref()
                .ok_or(StoreError::DiskObservationUnavailable)?
                .observe(&operation.project_id, now_ms)?;
            self.security.acquire_disk_reservation(
                &operation.project_id,
                operation.attempt_id,
                &observation,
                now_ms,
            )?;
        }
        if matches!(phase, OperationPhase::Building | OperationPhase::Deploying) {
            self.security.acquire_resource(
                &ExecutionResource::GlobalLocalRegistry,
                operation.attempt_id,
                now_ms,
            )?;
        }
        if requires_project_lock(phase) {
            self.security.acquire_resource(
                &ExecutionResource::ProjectDeploy(operation.project_id.clone()),
                operation.attempt_id,
                now_ms,
            )?;
        }
        Ok(())
    }

    fn required_source_gate_proof(
        &self,
        operation: &OperationRecord,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
        now_ms: i64,
    ) -> Result<Option<EvidenceDigest>, PhaseExecutionError> {
        let proof_phase = if requires_live_source_check(operation) {
            phase
        } else if is_stateful_deploy(operation) && phase == OperationPhase::Draining {
            OperationPhase::BackingUp
        } else {
            return Ok(None);
        };
        if let Some(proof) = self
            .security
            .source_gate_proof(operation.attempt_id, proof_phase)?
        {
            return Ok(Some(proof));
        }
        self.security.mark_phase_needs_reconcile_in_branch(
            operation.attempt_id,
            phase,
            branch,
            now_ms,
        )?;
        Err(PhaseExecutionError::NeedsReconcile)
    }

    fn complete_live_source_mutation(
        &self,
        operation: &OperationRecord,
    ) -> Result<(), PhaseExecutionError> {
        if live_source_completion_phase(operation) != Some(operation.state.phase) {
            return Ok(());
        }
        self.complete_source_ticket(operation)
    }

    fn refresh_stateful_source_before_fence_under_gate(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<(), PhaseExecutionError> {
        if operation.state.phase != OperationPhase::CutoverSnapshotting
            || !is_stateful_deploy(operation)
        {
            return Err(PhaseExecutionError::InvalidOperationState);
        }
        match self.security.active_fence(&operation.project_id)? {
            Some(fence)
                if fence.attempt_id == operation.attempt_id
                    && fence.state == FenceJournalState::Held =>
            {
                return Ok(());
            }
            Some(_) => return Err(PhaseExecutionError::NeedsReconcile),
            None => {}
        }

        let source_result = self
            .source_gate
            .as_ref()
            .ok_or(SourceGateError::Unavailable)
            .and_then(|gate| gate.check_live(operation, now_ms));
        let proof = match source_result {
            Ok(proof) => proof,
            Err(SourceGateError::Unavailable) => return Err(SourceGateError::Unavailable.into()),
            Err(_) => return Err(PhaseExecutionError::NeedsReconcile),
        };
        let Some(persisted) = self
            .security
            .source_gate_proof(operation.attempt_id, OperationPhase::BackingUp)?
        else {
            return Err(PhaseExecutionError::NeedsReconcile);
        };
        if persisted != proof.digest {
            return Err(PhaseExecutionError::NeedsReconcile);
        }
        Ok(())
    }

    fn complete_source_ticket(
        &self,
        operation: &OperationRecord,
    ) -> Result<(), PhaseExecutionError> {
        let completed = self
            .source_gate
            .as_ref()
            .ok_or(SourceGateError::Unavailable)
            .and_then(|gate| gate.complete_live(operation));
        if completed.is_err() {
            return Err(PhaseExecutionError::NeedsReconcile);
        }
        Ok(())
    }

    fn reconcile_committed_live_source_mutation_under_gate(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<Option<PhaseReceipt>, PhaseExecutionError> {
        if operation.state.phase != OperationPhase::Reconciliation {
            return Err(PhaseExecutionError::InvalidOperationState);
        }
        let Some(admission_phase) = live_source_admission_phase(operation) else {
            return Ok(None);
        };
        let Some(completion_phase) = live_source_completion_phase(operation) else {
            return Ok(None);
        };
        let entered_reconciliation_from_completion = operation
            .evidence
            .transitions
            .last()
            .is_some_and(|transition| {
                transition.from.phase == completion_phase
                    && transition.to.phase == OperationPhase::Reconciliation
                    && transition.to.result == OperationResult::Running
                    && transition.receipt_digest.is_none()
            });
        if !entered_reconciliation_from_completion {
            return Ok(None);
        }
        let Some(completion_receipt) = self.security.phase_receipt_in_branch(
            operation.attempt_id,
            completion_phase,
            ExecutorPhaseBranch::Primary,
        )?
        else {
            return Err(PhaseExecutionError::NeedsReconcile);
        };
        let Some(admission_receipt) = self.security.phase_receipt_in_branch(
            operation.attempt_id,
            admission_phase,
            ExecutorPhaseBranch::Primary,
        )?
        else {
            return Err(PhaseExecutionError::NeedsReconcile);
        };
        let Some(source_proof) = self
            .security
            .source_gate_proof(operation.attempt_id, admission_phase)?
        else {
            return Err(PhaseExecutionError::NeedsReconcile);
        };
        if admission_receipt
            .artifacts
            .source_gate_proof_digest
            .as_ref()
            != Some(&source_proof)
        {
            return Err(PhaseExecutionError::NeedsReconcile);
        }

        self.complete_source_ticket(operation)?;
        let mut completed_phase = operation.clone();
        completed_phase.state.phase = completion_phase;
        self.cleanup_ephemeral_resource(&completed_phase, now_ms)?;
        Ok(Some(completion_receipt))
    }

    fn abort_live_source_mutation(
        &self,
        operation: &OperationRecord,
    ) -> Result<(), PhaseExecutionError> {
        if !requires_live_source_check(operation) {
            return Ok(());
        }
        let aborted = self
            .source_gate
            .as_ref()
            .ok_or(SourceGateError::Unavailable)
            .and_then(|gate| gate.abort_live(operation));
        aborted.map_err(PhaseExecutionError::Source)
    }

    pub fn cleanup_terminal_resources(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        let execution_gate = self.project_execution_gate(&operation.project_id)?;
        let _execution_guard = execution_gate
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        self.cleanup_terminal_resources_under_gate(operation, now_ms)
    }

    fn cleanup_terminal_resources_under_gate(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        if operation.state.result == OperationResult::Running {
            return Ok(());
        }
        self.security.release_resource_if_owned(
            &ExecutionResource::ProjectDeploy(operation.project_id.clone()),
            operation.attempt_id,
            now_ms,
        )?;
        self.security.release_disk_reservation_if_owned(
            &operation.project_id,
            operation.attempt_id,
            now_ms,
        )?;
        self.security.release_resource_if_owned(
            &ExecutionResource::GlobalLocalRegistry,
            operation.attempt_id,
            now_ms,
        )?;
        if let Some(resource) = phase_resource(operation)
            && !matches!(resource, ExecutionResource::ProjectDeploy(_))
        {
            self.security
                .release_resource_if_owned(&resource, operation.attempt_id, now_ms)?;
        }
        Ok(())
    }

    fn suspend_pre_mutation_resources(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        self.cleanup_ephemeral_resource(operation, now_ms)?;
        self.security.release_disk_reservation_if_owned(
            &operation.project_id,
            operation.attempt_id,
            now_ms,
        )?;
        self.security.release_resource_if_owned(
            &ExecutionResource::GlobalLocalRegistry,
            operation.attempt_id,
            now_ms,
        )?;
        self.security.release_resource_if_owned(
            &ExecutionResource::ProjectDeploy(operation.project_id.clone()),
            operation.attempt_id,
            now_ms,
        )
    }

    pub fn acquire_write_fence(
        &self,
        project_id: &ProjectId,
        attempt_id: Uuid,
        crash_at: Option<FenceCrashPoint>,
        now_ms: i64,
    ) -> Result<FenceLease, FenceExecutionError> {
        let execution_gate = self.project_execution_gate(project_id)?;
        let _execution_guard = execution_gate
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        self.require_recovery(project_id)?;
        self.acquire_write_fence_under_gate(project_id, attempt_id, crash_at, now_ms)
    }

    fn acquire_write_fence_under_gate(
        &self,
        project_id: &ProjectId,
        attempt_id: Uuid,
        crash_at: Option<FenceCrashPoint>,
        now_ms: i64,
    ) -> Result<FenceLease, FenceExecutionError> {
        let lease = self
            .security
            .begin_fence_acquire(project_id, attempt_id, now_ms)?;
        if lease.state == FenceJournalState::NeedsReconcile {
            return Err(FenceExecutionError::NeedsReconcile);
        }
        fence_crash(crash_at, FenceCrashPoint::AfterIntentPersisted)?;
        match self.effects.observe_fence(project_id)? {
            FenceObservation::Released => self.effects.acquire_fence(&lease)?,
            FenceObservation::Held {
                attempt_id: observed_attempt,
                epoch,
                token,
            } if observed_attempt == lease.attempt_id
                && epoch == lease.epoch
                && token == lease.token => {}
            observation @ FenceObservation::Held { .. } => {
                self.security
                    .reconcile_fence(project_id, &observation, now_ms)?;
                return Err(FenceExecutionError::NeedsReconcile);
            }
        }
        fence_crash(crash_at, FenceCrashPoint::AfterEffectApplied)?;
        let observation = self.effects.observe_fence(project_id)?;
        if self
            .security
            .reconcile_fence(project_id, &observation, now_ms)?
            != FenceProjection::Held
        {
            return Err(FenceExecutionError::NeedsReconcile);
        }
        fence_crash(crash_at, FenceCrashPoint::AfterObservationPersisted)?;
        self.security
            .active_fence(project_id)?
            .ok_or(FenceExecutionError::NeedsReconcile)
    }

    pub fn release_write_fence(
        &self,
        project_id: &ProjectId,
        attempt_id: Uuid,
        release_safe_receipt_digest: &EvidenceDigest,
        crash_at: Option<FenceCrashPoint>,
        now_ms: i64,
    ) -> Result<(), FenceExecutionError> {
        let execution_gate = self.project_execution_gate(project_id)?;
        let _execution_guard = execution_gate
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        self.require_recovery(project_id)?;
        self.release_write_fence_under_gate(
            project_id,
            attempt_id,
            release_safe_receipt_digest,
            crash_at,
            now_ms,
        )
    }

    fn release_write_fence_under_gate(
        &self,
        project_id: &ProjectId,
        attempt_id: Uuid,
        release_safe_receipt_digest: &EvidenceDigest,
        crash_at: Option<FenceCrashPoint>,
        now_ms: i64,
    ) -> Result<(), FenceExecutionError> {
        let lease = self.security.begin_fence_release(
            project_id,
            attempt_id,
            release_safe_receipt_digest,
            now_ms,
        )?;
        fence_crash(crash_at, FenceCrashPoint::AfterIntentPersisted)?;
        match self.effects.observe_fence(project_id)? {
            FenceObservation::Released => {}
            FenceObservation::Held {
                attempt_id: observed_attempt,
                epoch,
                token,
            } if observed_attempt == lease.attempt_id
                && epoch == lease.epoch
                && token == lease.token =>
            {
                self.effects.release_fence(&lease)?;
            }
            observation @ FenceObservation::Held { .. } => {
                self.security
                    .reconcile_fence(project_id, &observation, now_ms)?;
                return Err(FenceExecutionError::NeedsReconcile);
            }
        }
        fence_crash(crash_at, FenceCrashPoint::AfterEffectApplied)?;
        let observation = self.effects.observe_fence(project_id)?;
        if self
            .security
            .reconcile_fence(project_id, &observation, now_ms)?
            != FenceProjection::Released
        {
            return Err(FenceExecutionError::NeedsReconcile);
        }
        fence_crash(crash_at, FenceCrashPoint::AfterObservationPersisted)?;
        Ok(())
    }

    pub fn reconcile_active_fences(&self, now_ms: i64) -> Result<(), FenceExecutionError> {
        for lease in self.security.active_fences()? {
            let execution_gate = self.project_execution_gate(&lease.project_id)?;
            let _execution_guard = execution_gate
                .lock()
                .map_err(|_| StoreError::LockPoisoned)?;
            let was_recovered = self
                .recovered_projects
                .lock()
                .map_err(|_| StoreError::LockPoisoned)?
                .remove(&lease.project_id);
            self.reconcile_active_fence_for_project_under_gate(&lease.project_id, now_ms)?;
            if was_recovered {
                self.recovered_projects
                    .lock()
                    .map_err(|_| StoreError::LockPoisoned)?
                    .insert(lease.project_id);
            }
        }
        Ok(())
    }

    fn reconcile_active_fence_for_project_under_gate(
        &self,
        project_id: &ProjectId,
        now_ms: i64,
    ) -> Result<(), FenceExecutionError> {
        let Some(lease) = self.security.active_fence(project_id)? else {
            return Ok(());
        };
        match lease.state {
            FenceJournalState::AcquireIntent | FenceJournalState::Held => {
                self.acquire_write_fence_under_gate(project_id, lease.attempt_id, None, now_ms)?;
            }
            FenceJournalState::ReleaseIntent => {
                let digest = lease
                    .release_safe_receipt_digest
                    .as_ref()
                    .ok_or(FenceExecutionError::NeedsReconcile)?;
                self.release_write_fence_under_gate(
                    project_id,
                    lease.attempt_id,
                    digest,
                    None,
                    now_ms,
                )?;
            }
            FenceJournalState::NeedsReconcile => {
                return Err(FenceExecutionError::NeedsReconcile);
            }
            FenceJournalState::Released => {}
        }
        Ok(())
    }

    fn cleanup_ephemeral_resource(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        if let Some(resource) = phase_resource(operation)
            && !matches!(resource, ExecutionResource::ProjectDeploy(_))
        {
            self.security
                .release_resource_if_owned(&resource, operation.attempt_id, now_ms)?;
        }
        if operation.state.phase == OperationPhase::Deploying {
            self.security.release_resource_if_owned(
                &ExecutionResource::GlobalLocalRegistry,
                operation.attempt_id,
                now_ms,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DurableCoordinator<A> {
    controller: DurableController,
    executor: DurableExecutor<A>,
}

enum CutoverPreparation {
    Ready(OperationRecord),
    Settled(OperationRecord),
}

impl<A: ExternalEffects> DurableCoordinator<A> {
    pub const fn new(controller: DurableController, executor: DurableExecutor<A>) -> Self {
        Self {
            controller,
            executor,
        }
    }

    #[must_use]
    pub fn with_source_gate(mut self, source_gate: Arc<dyn LiveSourceGate>) -> Self {
        self.executor = self.executor.with_source_gate(source_gate);
        self
    }

    #[must_use]
    pub fn with_disk_space_probe(mut self, disk_space_probe: Arc<dyn DiskSpaceProbe>) -> Self {
        self.executor = self.executor.with_disk_space_probe(disk_space_probe);
        self
    }

    pub const fn controller(&self) -> &DurableController {
        &self.controller
    }

    pub const fn executor(&self) -> &DurableExecutor<A> {
        &self.executor
    }

    pub fn begin_rollback(
        &self,
        attempt_id: Uuid,
        crash_at: Option<CoordinatorCrashPoint>,
        now_ms: i64,
    ) -> Result<OperationRecord, CoordinatorError> {
        let current = self
            .controller
            .operation(attempt_id)?
            .ok_or(StoreError::OperationNotFound(attempt_id))?;
        let execution_gate = self.executor.project_execution_gate(&current.project_id)?;
        let _execution_guard = execution_gate
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        self.executor.require_recovery(&current.project_id)?;

        if current.state.phase == OperationPhase::Reconciliation
            && let Some(receipt) = self
                .executor
                .reconcile_committed_live_source_mutation_under_gate(&current, now_ms)?
        {
            self.controller
                .commit_reconciled_phase_receipt(&receipt, now_ms)?;
        }

        let validated = self.controller.validate_rollback(attempt_id)?;
        let authorization_digest = executor_authorization_digest(&validated)?;
        self.executor.security.begin_rollback_takeover(
            validated.attempt_id,
            &validated.project_id,
            &authorization_digest,
            now_ms,
        )?;
        coordinator_crash(crash_at, CoordinatorCrashPoint::AfterSecurityReceipt)?;
        let rollback = self.controller.begin_rollback(attempt_id, now_ms)?;
        coordinator_crash(crash_at, CoordinatorCrashPoint::AfterControllerProjection)?;
        Ok(rollback)
    }

    pub fn advance_once(
        &self,
        attempt_id: Uuid,
        phase_crash_at: Option<PhaseCrashPoint>,
        coordinator_crash_at: Option<CoordinatorCrashPoint>,
        now_ms: i64,
    ) -> Result<OperationRecord, CoordinatorError> {
        let initial = self
            .controller
            .operation(attempt_id)?
            .ok_or(StoreError::OperationNotFound(attempt_id))?;
        let execution_gate = self.executor.project_execution_gate(&initial.project_id)?;
        let _execution_guard = execution_gate
            .lock()
            .map_err(|_| StoreError::LockPoisoned)?;
        let mut operation = self
            .controller
            .operation(attempt_id)?
            .ok_or(StoreError::OperationNotFound(attempt_id))?;
        self.executor.require_recovery(&operation.project_id)?;
        if self.settle_non_executable_operation_under_gate(&operation, now_ms)? {
            return self
                .controller
                .operation(attempt_id)?
                .ok_or(StoreError::OperationNotFound(attempt_id).into());
        }
        if operation.state.phase == OperationPhase::CutoverSnapshotting {
            match self.prepare_cutover_under_gate(&operation, now_ms)? {
                CutoverPreparation::Ready(prepared) => operation = prepared,
                CutoverPreparation::Settled(settled) => return Ok(settled),
            }
        }
        let receipt =
            match self
                .executor
                .execute_phase_under_gate(&operation, phase_crash_at, now_ms)
            {
                Ok(receipt) => receipt,
                Err(PhaseExecutionError::NeedsReconcile) => {
                    return Ok(self.controller.mark_needs_reconcile(
                        attempt_id,
                        reconciliation_capsule(operation.state.phase),
                        now_ms,
                    )?);
                }
                Err(PhaseExecutionError::Source(SourceGateError::HeadSuperseded)) => {
                    let superseded = self.controller.supersede_source_attempt(
                        operation.attempt_id,
                        source_failure_capsule(SourceGateError::HeadSuperseded),
                        now_ms,
                    )?;
                    self.executor
                        .cleanup_terminal_resources_under_gate(&superseded, now_ms)?;
                    return Ok(superseded);
                }
                Err(PhaseExecutionError::Source(error)) => {
                    return Ok(self.controller.set_source_block(
                        operation.attempt_id,
                        source_blocking_reason(error),
                        now_ms,
                    )?);
                }
                Err(PhaseExecutionError::Store(StoreError::DiskReservationCapacity { .. })) => {
                    return Ok(self.controller.set_disk_block(attempt_id, now_ms)?);
                }
                Err(error) => return Err(error.into()),
            };
        if operation.state.phase == OperationPhase::Soaking {
            match self
                .executor
                .security()
                .active_fence(&operation.project_id)?
            {
                Some(fence) if fence.attempt_id == operation.attempt_id => {
                    self.executor.release_write_fence_under_gate(
                        &operation.project_id,
                        operation.attempt_id,
                        &receipt.receipt_digest,
                        None,
                        now_ms,
                    )?;
                }
                Some(_) => return Err(FenceExecutionError::NeedsReconcile.into()),
                None => {}
            }
        }
        coordinator_crash(
            coordinator_crash_at,
            CoordinatorCrashPoint::AfterSecurityReceipt,
        )?;
        let projected = self.controller.commit_phase_receipt(&receipt, now_ms)?;
        coordinator_crash(
            coordinator_crash_at,
            CoordinatorCrashPoint::AfterControllerProjection,
        )?;
        if projected.state.result != OperationResult::Running {
            self.executor
                .cleanup_terminal_resources_under_gate(&projected, now_ms)?;
        }
        Ok(projected)
    }

    fn prepare_cutover_under_gate(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<CutoverPreparation, CoordinatorError> {
        match self
            .executor
            .refresh_stateful_source_before_fence_under_gate(operation, now_ms)
        {
            Ok(()) => {}
            Err(PhaseExecutionError::Source(SourceGateError::Unavailable)) => {
                return Ok(CutoverPreparation::Settled(
                    self.controller
                        .set_stateful_cutover_source_block(operation.attempt_id, now_ms)?,
                ));
            }
            Err(PhaseExecutionError::NeedsReconcile | PhaseExecutionError::Source(_)) => {
                return Ok(CutoverPreparation::Settled(
                    self.controller.mark_needs_reconcile(
                        operation.attempt_id,
                        reconciliation_capsule(operation.state.phase),
                        now_ms,
                    )?,
                ));
            }
            Err(error) => return Err(error.into()),
        }
        self.controller
            .clear_stateful_cutover_source_block(operation.attempt_id, now_ms)?;
        let fence = self.executor.acquire_write_fence_under_gate(
            &operation.project_id,
            operation.attempt_id,
            None,
            now_ms,
        )?;
        let fence_receipt = self
            .executor
            .security()
            .fence_acquisition_receipt(&operation.project_id, operation.attempt_id)?
            .ok_or(FenceExecutionError::NeedsReconcile)?;
        debug_assert_eq!(fence.epoch, fence_receipt.epoch);
        let prepared = self.controller.record_fence_acquisition(
            operation.attempt_id,
            &fence_receipt,
            now_ms,
        )?;
        Ok(CutoverPreparation::Ready(prepared))
    }

    fn settle_non_executable_operation_under_gate(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<bool, CoordinatorError> {
        if operation.state.result != OperationResult::Running {
            if operation.state.phase == OperationPhase::Reconciliation {
                match self
                    .executor
                    .reconcile_committed_live_source_mutation_under_gate(operation, now_ms)
                {
                    Ok(_) => {}
                    Err(PhaseExecutionError::NeedsReconcile) => return Ok(true),
                    Err(error) => return Err(error.into()),
                }
            }
            self.executor
                .cleanup_terminal_resources_under_gate(operation, now_ms)?;
            return Ok(true);
        }
        if operation.state.phase == OperationPhase::Reconciliation {
            return match self
                .executor
                .reconcile_committed_live_source_mutation_under_gate(operation, now_ms)
            {
                Ok(Some(receipt)) => {
                    self.controller
                        .commit_reconciled_phase_receipt(&receipt, now_ms)?;
                    Ok(true)
                }
                Ok(None) | Err(PhaseExecutionError::NeedsReconcile) => Ok(true),
                Err(error) => Err(error.into()),
            };
        }
        Ok(operation.state.blocking_reason != BlockingReason::None
            && !is_retryable_source_block(operation.state.blocking_reason))
    }

    pub fn fail_before_mutation(
        &self,
        attempt_id: Uuid,
        failure_capsule: FailureCapsule,
        now_ms: i64,
    ) -> Result<OperationRecord, CoordinatorError> {
        let current = self
            .controller
            .operation(attempt_id)?
            .ok_or(StoreError::OperationNotFound(attempt_id))?;
        self.executor.require_recovery(&current.project_id)?;
        let operation = self
            .controller
            .fail_attempt(attempt_id, failure_capsule, now_ms)?;
        self.executor
            .cleanup_terminal_resources(&operation, now_ms)?;
        Ok(operation)
    }

    pub fn cancel_before_mutation(
        &self,
        attempt_id: Uuid,
        now_ms: i64,
    ) -> Result<OperationRecord, CoordinatorError> {
        let current = self
            .controller
            .operation(attempt_id)?
            .ok_or(StoreError::OperationNotFound(attempt_id))?;
        self.executor.require_recovery(&current.project_id)?;
        let operation = self.controller.cancel_before_mutation(attempt_id, now_ms)?;
        self.executor
            .cleanup_terminal_resources(&operation, now_ms)?;
        Ok(operation)
    }

    pub fn retry_disk_reservation(
        &self,
        attempt_id: Uuid,
        now_ms: i64,
    ) -> Result<OperationRecord, CoordinatorError> {
        let current = self
            .controller
            .operation(attempt_id)?
            .ok_or(StoreError::OperationNotFound(attempt_id))?;
        self.executor.require_recovery(&current.project_id)?;
        Ok(self.controller.clear_disk_block(attempt_id, now_ms)?)
    }
}

fn requires_live_source_check(operation: &OperationRecord) -> bool {
    live_source_admission_phase(operation) == Some(operation.state.phase)
}

fn is_stateful_deploy(operation: &OperationRecord) -> bool {
    operation.operation_kind == OperationKind::Deploy
        && matches!(
            operation.release_class,
            Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking)
        )
}

fn live_source_admission_phase(operation: &OperationRecord) -> Option<OperationPhase> {
    if operation.operation_kind != OperationKind::Deploy {
        return None;
    }
    match operation.release_class {
        Some(ReleaseClass::CodeOnlyCompatible) => Some(OperationPhase::Deploying),
        Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking) => {
            Some(OperationPhase::BackingUp)
        }
        Some(ReleaseClass::Rollback) | None => None,
    }
}

fn live_source_completion_phase(operation: &OperationRecord) -> Option<OperationPhase> {
    if operation.operation_kind != OperationKind::Deploy {
        return None;
    }
    match operation.release_class {
        Some(ReleaseClass::CodeOnlyCompatible) => Some(OperationPhase::Deploying),
        Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking) => {
            Some(OperationPhase::CutoverSnapshotting)
        }
        Some(ReleaseClass::Rollback) | None => None,
    }
}

fn requires_disk_reservation(_operation: &OperationRecord, phase: OperationPhase) -> bool {
    matches!(
        phase,
        OperationPhase::Testing
            | OperationPhase::Building
            | OperationPhase::Preflight
            | OperationPhase::BackingUp
            | OperationPhase::CutoverSnapshotting
            | OperationPhase::Migrating
            | OperationPhase::Deploying
            | OperationPhase::HealthChecking
            | OperationPhase::Soaking
            | OperationPhase::Rollback
    )
}

const fn is_retryable_source_block(reason: BlockingReason) -> bool {
    matches!(reason, BlockingReason::SourceBrokerUnavailable)
}

const fn source_blocking_reason(error: SourceGateError) -> BlockingReason {
    match error {
        SourceGateError::Unavailable => BlockingReason::SourceBrokerUnavailable,
        SourceGateError::AttestationInvalid => BlockingReason::SourceAttestationInvalid,
        SourceGateError::Diverged => BlockingReason::SourceDivergence,
        SourceGateError::BlockedSha | SourceGateError::Paused => BlockingReason::OperatorHold,
        SourceGateError::HeadSuperseded => BlockingReason::SourceHeadSuperseded,
    }
}

fn source_failure_capsule(error: SourceGateError) -> FailureCapsule {
    let (code, summary) = match error {
        SourceGateError::HeadSuperseded => (
            "source_head_superseded",
            "A newer canonical main head superseded this deployment before mutation",
        ),
        SourceGateError::AttestationInvalid => (
            "source_attestation_invalid",
            "The signed accepted-head evidence is invalid",
        ),
        SourceGateError::Unavailable => (
            "source_broker_unavailable",
            "The source broker is unavailable",
        ),
        SourceGateError::Diverged => (
            "source_diverged",
            "Source histories diverged and require an owner decision",
        ),
        SourceGateError::BlockedSha => (
            "source_sha_blocked",
            "The canonical source SHA is blocked by policy",
        ),
        SourceGateError::Paused => (
            "source_reconciliation_paused",
            "Source reconciliation is paused by policy",
        ),
    };
    FailureCapsule {
        schema_version: 1,
        failing_step: "verifying_source".to_owned(),
        error: StructuredError {
            code: code.to_owned(),
            summary: summary.to_owned(),
            retryability: Retryability::Automatic,
            runbook_id: None,
        },
        excerpt: summary.to_owned(),
        truncated: false,
    }
}

#[derive(Clone, Debug, Default)]
pub struct DeterministicModelEffects {
    state: Arc<Mutex<ModelState>>,
}

#[derive(Debug, Default)]
struct ModelState {
    phase_effects: BTreeMap<(Uuid, String), PhaseEffectEvidence>,
    phase_artifact_outputs: BTreeMap<(Uuid, String), PhaseArtifacts>,
    phase_apply_attempts: BTreeMap<(Uuid, String), u32>,
    phase_failures_before_effect: BTreeSet<(Uuid, String)>,
    phase_observations_hidden_once_after_apply: BTreeSet<(Uuid, String)>,
    phase_mutations: BTreeMap<(Uuid, String), u32>,
    fences: BTreeMap<ProjectId, ModelFence>,
}

#[derive(Clone, Debug)]
struct ModelFence {
    attempt_id: Uuid,
    epoch: u64,
    token: Uuid,
}

impl DeterministicModelEffects {
    pub fn phase_application_attempts(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
    ) -> Result<u32, ExternalEffectError> {
        self.phase_application_attempts_in_branch(attempt_id, phase, ExecutorPhaseBranch::Primary)
    }

    pub fn phase_application_attempts_in_branch(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
    ) -> Result<u32, ExternalEffectError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?;
        Ok(*state
            .phase_apply_attempts
            .get(&(attempt_id, model_phase_key(branch, phase)?))
            .unwrap_or(&0))
    }

    pub fn phase_mutations(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
    ) -> Result<u32, ExternalEffectError> {
        self.phase_mutations_in_branch(attempt_id, phase, ExecutorPhaseBranch::Primary)
    }

    pub fn phase_mutations_in_branch(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
    ) -> Result<u32, ExternalEffectError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?;
        Ok(*state
            .phase_mutations
            .get(&(attempt_id, model_phase_key(branch, phase)?))
            .unwrap_or(&0))
    }

    pub fn force_phase_effect(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        digest: EvidenceDigest,
    ) -> Result<(), ExternalEffectError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?;
        state.phase_effects.insert(
            (attempt_id, phase_name(phase).to_owned()),
            PhaseEffectEvidence {
                observation_digest: EvidenceDigest::sha256(format!("forced-observation:{digest}")),
                intent_digest: digest,
                artifacts: PhaseArtifacts::default(),
            },
        );
        Ok(())
    }

    pub fn set_phase_artifacts(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        artifacts: PhaseArtifacts,
    ) -> Result<(), ExternalEffectError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?;
        state
            .phase_artifact_outputs
            .insert((attempt_id, phase_name(phase).to_owned()), artifacts);
        Ok(())
    }

    pub fn fail_next_phase_before_effect(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
    ) -> Result<(), ExternalEffectError> {
        self.state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?
            .phase_failures_before_effect
            .insert((attempt_id, phase_name(phase).to_owned()));
        Ok(())
    }

    pub fn hide_next_applied_phase_observation(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
    ) -> Result<(), ExternalEffectError> {
        self.hide_next_applied_phase_observation_in_branch(
            attempt_id,
            phase,
            ExecutorPhaseBranch::Primary,
        )
    }

    pub fn hide_next_applied_phase_observation_in_branch(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
    ) -> Result<(), ExternalEffectError> {
        self.state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?
            .phase_observations_hidden_once_after_apply
            .insert((attempt_id, model_phase_key(branch, phase)?));
        Ok(())
    }

    pub fn force_fence(
        &self,
        project_id: ProjectId,
        attempt_id: Uuid,
        epoch: u64,
        token: Uuid,
    ) -> Result<(), ExternalEffectError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?;
        state.fences.insert(
            project_id,
            ModelFence {
                attempt_id,
                epoch,
                token,
            },
        );
        Ok(())
    }
}

impl ExternalEffects for DeterministicModelEffects {
    fn observe_phase(
        &self,
        intent: &PhaseIntent,
    ) -> Result<EffectObservation, ExternalEffectError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?;
        let key = (
            intent.attempt_id,
            model_phase_key(intent.branch, intent.phase)?,
        );
        if state.phase_effects.contains_key(&key)
            && state
                .phase_observations_hidden_once_after_apply
                .remove(&key)
        {
            return Ok(EffectObservation::Absent);
        }
        Ok(state
            .phase_effects
            .get(&key)
            .cloned()
            .map_or(EffectObservation::Absent, |evidence| {
                EffectObservation::Applied(Box::new(evidence))
            }))
    }

    fn apply_phase(&self, intent: &PhaseIntent) -> Result<(), ExternalEffectError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?;
        let key = (
            intent.attempt_id,
            model_phase_key(intent.branch, intent.phase)?,
        );
        let attempts = state.phase_apply_attempts.entry(key.clone()).or_default();
        *attempts = attempts.saturating_add(1);
        if state.phase_failures_before_effect.remove(&key) {
            return Err(ExternalEffectError::ConflictingState);
        }
        match state.phase_effects.get(&key) {
            Some(existing) if existing.intent_digest == intent.digest => Ok(()),
            Some(_) => Err(ExternalEffectError::ConflictingState),
            None => {
                let artifacts = state
                    .phase_artifact_outputs
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| deterministic_phase_artifacts(intent));
                state.phase_effects.insert(
                    key.clone(),
                    PhaseEffectEvidence {
                        intent_digest: intent.digest.clone(),
                        observation_digest: EvidenceDigest::sha256(format!(
                            "model-observation:{}",
                            intent.digest
                        )),
                        artifacts,
                    },
                );
                let mutations = state.phase_mutations.entry(key).or_default();
                *mutations = mutations.saturating_add(1);
                Ok(())
            }
        }
    }

    fn observe_fence(
        &self,
        project_id: &ProjectId,
    ) -> Result<FenceObservation, ExternalEffectError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?;
        Ok(state
            .fences
            .get(project_id)
            .map_or(FenceObservation::Released, |fence| FenceObservation::Held {
                attempt_id: fence.attempt_id,
                epoch: fence.epoch,
                token: fence.token,
            }))
    }

    fn acquire_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?;
        match state.fences.get(&lease.project_id) {
            Some(existing)
                if existing.attempt_id == lease.attempt_id
                    && existing.epoch == lease.epoch
                    && existing.token == lease.token =>
            {
                Ok(())
            }
            Some(_) => Err(ExternalEffectError::ConflictingState),
            None => {
                state.fences.insert(
                    lease.project_id.clone(),
                    ModelFence {
                        attempt_id: lease.attempt_id,
                        epoch: lease.epoch,
                        token: lease.token,
                    },
                );
                Ok(())
            }
        }
    }

    fn release_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalEffectError::StatePoisoned)?;
        match state.fences.get(&lease.project_id) {
            Some(existing)
                if existing.attempt_id == lease.attempt_id
                    && existing.epoch == lease.epoch
                    && existing.token == lease.token =>
            {
                state.fences.remove(&lease.project_id);
                Ok(())
            }
            Some(_) => Err(ExternalEffectError::ConflictingState),
            None => Ok(()),
        }
    }
}

fn deterministic_phase_artifacts(intent: &PhaseIntent) -> PhaseArtifacts {
    let phase_evidence = |label: &str| {
        EvidenceDigest::sha256(format!(
            "rdashboard.deterministic-effect.v1:{label}:{}",
            intent.digest
        ))
    };
    let release_evidence = |label: &str| {
        EvidenceDigest::sha256(format!(
            "rdashboard.deterministic-release.v1:{label}:{}:{}",
            intent.project_id, intent.attempt_id
        ))
    };
    match intent.phase {
        OperationPhase::Testing => PhaseArtifacts {
            source_export_digest: Some(release_evidence("source-export")),
            prefetch_evidence_digest: Some(release_evidence("prefetch")),
            ci_evidence_digest: Some(phase_evidence("ci")),
            build_context_digest: Some(release_evidence("context")),
            resource_reservation_digest: Some(release_evidence("resource-reservation")),
            base_image_digests: vec![release_evidence("base-image")],
            ..PhaseArtifacts::default()
        },
        OperationPhase::Building => PhaseArtifacts {
            build_context_digest: Some(release_evidence("context")),
            build_plan_digest: Some(phase_evidence("build-plan")),
            image_digest: Some(phase_evidence("image")),
            image_id_digest: Some(phase_evidence("image-id")),
            base_image_digests: vec![release_evidence("base-image")],
            ..PhaseArtifacts::default()
        },
        OperationPhase::Preflight => PhaseArtifacts {
            resource_reservation_digest: Some(release_evidence("resource-reservation")),
            ..PhaseArtifacts::default()
        },
        OperationPhase::BackingUp => PhaseArtifacts {
            backup_set_id: Some(intent.attempt_id),
            base_backup_id: Some(Uuid::from_u128(intent.attempt_id.as_u128() ^ 1)),
            base_backup_manifest_digest: Some(phase_evidence("base-backup-manifest")),
            base_backup_evidence_digest: Some(phase_evidence("base-backup-evidence")),
            base_backup_offsite_evidence_digest: Some(phase_evidence("base-backup-offsite")),
            base_backup_verification_digest: Some(phase_evidence("base-backup-verification")),
            ..PhaseArtifacts::default()
        },
        OperationPhase::Draining => PhaseArtifacts {
            drain_evidence_digest: Some(phase_evidence("drain")),
            ..PhaseArtifacts::default()
        },
        OperationPhase::CutoverSnapshotting => PhaseArtifacts {
            backup_set_id: intent.payload.backup_set_id,
            cutover_backup_id: Some(Uuid::from_u128(intent.attempt_id.as_u128() ^ 2)),
            cutover_backup_manifest_digest: Some(phase_evidence("cutover-backup-manifest")),
            cutover_backup_evidence_digest: Some(phase_evidence("cutover-backup-evidence")),
            cutover_backup_verification_digest: Some(phase_evidence("cutover-backup-verification")),
            fencing_epoch: intent.payload.fencing_epoch,
            ..PhaseArtifacts::default()
        },
        OperationPhase::Migrating => PhaseArtifacts {
            schema_version: Some("deterministic-schema-v1".to_owned()),
            ..PhaseArtifacts::default()
        },
        OperationPhase::Deploying => PhaseArtifacts {
            deployment_plan_digest: Some(phase_evidence("deployment-plan")),
            release_bundle_digest: Some(release_evidence("release-bundle")),
            ..PhaseArtifacts::default()
        },
        OperationPhase::HealthChecking => PhaseArtifacts {
            health_evidence_digest: Some(phase_evidence("health")),
            ..PhaseArtifacts::default()
        },
        _ => PhaseArtifacts::default(),
    }
}

fn phase_intent(
    operation: &OperationRecord,
    executor_authorization_digest: EvidenceDigest,
) -> Result<PhaseIntent, StoreError> {
    let branch = executor_phase_branch(operation);
    let (operation_kind, release_class) =
        if operation.evidence.recovery_mode == Some(OperationRecoveryMode::Rollback) {
            (OperationKind::CodeRollback, Some(ReleaseClass::Rollback))
        } else {
            (operation.operation_kind, operation.release_class)
        };
    let payload = PhaseIntentPayloadV1 {
        purpose: "rdashboard.phase-intent.v1",
        attempt_id: operation.attempt_id,
        request_id: operation.request_id,
        project_id: operation.project_id.clone(),
        operation_kind,
        release_class,
        target_commit: operation.target_commit.clone(),
        phase: operation.state.phase,
        branch,
        installed_policy: operation.evidence.installed_policy.clone(),
        authorized_phase_spec_digests: operation.evidence.authorized_phase_spec_digests.clone(),
        executor_authorization_digest,
        source_attestation_digest: operation.evidence.source_attestation_digest.clone(),
        source_sequence: operation.evidence.source_sequence,
        source_gate_proof_digest: operation.evidence.source_gate_proof_digest.clone(),
        drain_evidence_digest: operation.evidence.drain_evidence_digest.clone(),
        source_export_digest: operation.evidence.source_export_digest.clone(),
        prefetch_evidence_digest: operation.evidence.prefetch_evidence_digest.clone(),
        ci_evidence_digest: operation.evidence.ci_evidence_digest.clone(),
        build_plan_digest: operation.evidence.build_plan_digest.clone(),
        deployment_plan_digest: operation.evidence.deployment_plan_digest.clone(),
        release_bundle_digest: operation.evidence.release_bundle_digest.clone(),
        resource_reservation_digest: operation.evidence.resource_reservation_digest.clone(),
        action_grant_digest: operation.evidence.action_grant_digest.clone(),
        build_context_digest: operation.evidence.build_context_digest.clone(),
        generated_output_digests: operation.evidence.generated_output_digests.clone(),
        image_digest: operation.evidence.image_digest.clone(),
        image_id_digest: operation.evidence.image_id_digest.clone(),
        base_image_digests: operation.evidence.base_image_digests.clone(),
        schema_version: operation.evidence.schema_version.clone(),
        backup_id: operation.evidence.backup_id,
        backup_set_id: operation.evidence.backup_set_id,
        base_backup_id: operation.evidence.base_backup_id,
        base_backup_manifest_digest: operation.evidence.base_backup_manifest_digest.clone(),
        base_backup_evidence_digest: operation.evidence.base_backup_evidence_digest.clone(),
        base_backup_offsite_evidence_digest: operation
            .evidence
            .base_backup_offsite_evidence_digest
            .clone(),
        base_backup_verification_digest: operation.evidence.base_backup_verification_digest.clone(),
        cutover_backup_id: operation.evidence.cutover_backup_id,
        cutover_backup_manifest_digest: operation.evidence.cutover_backup_manifest_digest.clone(),
        cutover_backup_evidence_digest: operation.evidence.cutover_backup_evidence_digest.clone(),
        cutover_backup_verification_digest: operation
            .evidence
            .cutover_backup_verification_digest
            .clone(),
        previous_release_bundle_digest: operation.evidence.previous_release_bundle_digest.clone(),
        health_evidence_digest: operation.evidence.health_evidence_digest.clone(),
        rollback_health_evidence_digest: operation.evidence.rollback_health_evidence_digest.clone(),
        fencing_epoch: operation.evidence.fencing_epoch,
        fence_acquisition_receipt_digest: operation
            .evidence
            .fence_acquisition_receipt_digest
            .clone(),
        recovery_mode: operation.evidence.recovery_mode,
    };
    let digest = EvidenceDigest::sha256(serde_jcs::to_vec(&payload)?);
    Ok(PhaseIntent {
        attempt_id: operation.attempt_id,
        project_id: operation.project_id.clone(),
        phase: operation.state.phase,
        branch,
        payload,
        digest,
    })
}

fn executor_phase_branch(operation: &OperationRecord) -> ExecutorPhaseBranch {
    if operation.evidence.recovery_mode == Some(OperationRecoveryMode::Rollback) {
        ExecutorPhaseBranch::RollbackRecovery
    } else {
        ExecutorPhaseBranch::Primary
    }
}

fn model_phase_key(
    branch: ExecutorPhaseBranch,
    phase: OperationPhase,
) -> Result<String, ExternalEffectError> {
    branch
        .storage_key(phase)
        .map(str::to_owned)
        .map_err(|_| ExternalEffectError::ConflictingState)
}

#[derive(Serialize)]
struct AuthorizedOperationV1<'a> {
    purpose: &'static str,
    attempt_id: Uuid,
    request_id: Uuid,
    project_id: &'a ProjectId,
    operation_kind: OperationKind,
    target_commit: &'a Option<crate::domain::GitCommitId>,
    release_class: &'a Option<crate::domain::ReleaseClass>,
    installed_policy: &'a Option<crate::domain::InstalledPolicyIdentity>,
    actor: &'a OperationActor,
    action_grant_digest: &'a Option<EvidenceDigest>,
    source_attestation_digest: &'a Option<EvidenceDigest>,
    source_sequence: &'a Option<u64>,
}

pub fn executor_authorization_digest(
    operation: &OperationRecord,
) -> Result<EvidenceDigest, StoreError> {
    let capability_present = match &operation.actor {
        OperationActor::Interactive { .. } => operation.evidence.action_grant_digest.is_some(),
        OperationActor::Automation { .. } => {
            operation.evidence.source_attestation_digest.is_some()
                && operation.evidence.source_sequence.is_some()
        }
    };
    if !capability_present {
        return Err(StoreError::CorruptController(
            "operation is missing its executor authorization evidence",
        ));
    }
    let payload = AuthorizedOperationV1 {
        purpose: "rdashboard.authorized-operation.v1",
        attempt_id: operation.attempt_id,
        request_id: operation.request_id,
        project_id: &operation.project_id,
        operation_kind: operation.operation_kind,
        target_commit: &operation.target_commit,
        release_class: &operation.release_class,
        installed_policy: &operation.evidence.installed_policy,
        actor: &operation.actor,
        action_grant_digest: &operation.evidence.action_grant_digest,
        source_attestation_digest: &operation.evidence.source_attestation_digest,
        source_sequence: &operation.evidence.source_sequence,
    };
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(&payload)?))
}

fn phase_resource(operation: &OperationRecord) -> Option<ExecutionResource> {
    match operation.state.phase {
        OperationPhase::Testing | OperationPhase::Building => Some(ExecutionResource::GlobalBuild),
        OperationPhase::BackingUp
        | OperationPhase::CutoverSnapshotting
        | OperationPhase::Migrating => Some(ExecutionResource::GlobalHeavyIo),
        OperationPhase::Queued
        | OperationPhase::SyncingSource
        | OperationPhase::VerifyingSource
        | OperationPhase::Preflight
        | OperationPhase::Draining
        | OperationPhase::Deploying
        | OperationPhase::HealthChecking
        | OperationPhase::Soaking
        | OperationPhase::Rollback
        | OperationPhase::Reconciliation => None,
    }
}

const fn requires_project_lock(phase: OperationPhase) -> bool {
    matches!(
        phase,
        OperationPhase::Preflight
            | OperationPhase::BackingUp
            | OperationPhase::Draining
            | OperationPhase::CutoverSnapshotting
            | OperationPhase::Migrating
            | OperationPhase::Deploying
            | OperationPhase::HealthChecking
            | OperationPhase::Soaking
            | OperationPhase::Rollback
    )
}

fn reconciliation_capsule(phase: OperationPhase) -> FailureCapsule {
    FailureCapsule {
        schema_version: 1,
        failing_step: phase_name(phase).to_owned(),
        error: StructuredError {
            code: "executor_evidence_ambiguous".to_owned(),
            summary: "External state does not match the persisted executor intent".to_owned(),
            retryability: Retryability::OperatorRunbook,
            runbook_id: None,
        },
        excerpt: "Mutation remains fenced; reconcile the security journal with actual state."
            .to_owned(),
        truncated: false,
    }
}

fn phase_crash(
    configured: Option<PhaseCrashPoint>,
    boundary: PhaseCrashPoint,
) -> Result<(), PhaseExecutionError> {
    if configured == Some(boundary) {
        Err(PhaseExecutionError::InjectedCrash(boundary))
    } else {
        Ok(())
    }
}

fn fence_crash(
    configured: Option<FenceCrashPoint>,
    boundary: FenceCrashPoint,
) -> Result<(), FenceExecutionError> {
    if configured == Some(boundary) {
        Err(FenceExecutionError::InjectedCrash(boundary))
    } else {
        Ok(())
    }
}

fn coordinator_crash(
    configured: Option<CoordinatorCrashPoint>,
    boundary: CoordinatorCrashPoint,
) -> Result<(), CoordinatorError> {
    if configured == Some(boundary) {
        Err(CoordinatorError::InjectedCrash(boundary))
    } else {
        Ok(())
    }
}

const fn phase_name(phase: OperationPhase) -> &'static str {
    match phase {
        OperationPhase::Queued => "queued",
        OperationPhase::SyncingSource => "syncing_source",
        OperationPhase::VerifyingSource => "verifying_source",
        OperationPhase::Testing => "testing",
        OperationPhase::Building => "building",
        OperationPhase::Preflight => "preflight",
        OperationPhase::BackingUp => "backing_up",
        OperationPhase::Draining => "draining",
        OperationPhase::CutoverSnapshotting => "cutover_snapshotting",
        OperationPhase::Migrating => "migrating",
        OperationPhase::Deploying => "deploying",
        OperationPhase::HealthChecking => "health_checking",
        OperationPhase::Soaking => "soaking",
        OperationPhase::Rollback => "rollback",
        OperationPhase::Reconciliation => "reconciliation",
    }
}
