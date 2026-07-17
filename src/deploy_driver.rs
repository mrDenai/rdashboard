use std::{fmt, sync::Arc};

use uuid::Uuid;

use crate::{
    backup::{TrustedClockEvidenceV1, VerifiedBackupChainV1},
    backup_driver::{
        BackupDiskProbeErrorV1, DiskReservationRequirementsV1, InstalledBackupDiskProbeV1,
    },
    build::{ReleaseBundleV1, ResourceReservationEvidenceV1},
    build_attestation::{BuildReleaseAttestationV1, RuntimeCandidateArtifactsV1},
    domain::{
        AuthorizedPhaseSpecDigestV1, BlockingReason, EvidenceDigest, ExecutorPhaseBranch,
        OperationActor, OperationEvidence, OperationKind, OperationPhase, OperationRecord,
        OperationRecoveryMode, OperationResult, OperationState, OperationTransition,
        PhaseArtifacts, PhaseReceipt, ReleaseClass,
    },
    executor::{
        DurableExecutor, EffectObservation, ExternalEffectError, ExternalEffects,
        FenceExecutionError, PhaseEffectEvidence, PhaseExecutionError, PhaseIntent,
        PhaseOperationIdentityLeaseV1, executor_authorization_digest,
    },
    installed_deploy::{
        DeploySourceSnapshotV1, InstalledDeployError, InstalledDeployIntentResolverV1,
        InstalledDeployMutationPolicyV1, InstalledReleaseStateV1,
    },
    phase6::{
        AuthorizedPhasePrerequisitesV1, AuthorizedPhaseSpecInputV1, AuthorizedPhaseSpecV1,
        InstalledRimgPolicyV1, Phase6ContractError, ReleaseClassificationAuthorityV1,
        ReleaseClassificationInputV1, RuntimeReleaseStateEvidenceInputV1,
        RuntimeReleaseStateEvidenceV1, RuntimeReleaseStateV1, SchemaContractEvaluationEvidenceV1,
        SchemaContractEvaluationInputV1, SchemaContractKindV1, SchemaContractVerdictV1,
        SchemaInspectionEvidenceInputV1, SchemaInspectionEvidenceV1,
    },
    source::LiveSourceGate,
    store::{
        AcceptedMutationV1, AuthorizedPhaseSpecBinding, ExecutorAuthorization, ExecutorPhasePlan,
        FenceLease, FenceObservation, PhaseIntentRequest, SecurityStore, StoreError,
    },
};

#[derive(Clone, Debug)]
pub struct PreparedInstalledDeploymentV1 {
    pub operation: OperationRecord,
    pub mutation_policy: InstalledDeployMutationPolicyV1,
    pub rimg_policy: InstalledRimgPolicyV1,
    pub release_state: InstalledReleaseStateV1,
    pub attestation: BuildReleaseAttestationV1,
    pub candidate: ReleaseBundleV1,
    pub current: Option<ReleaseBundleV1>,
    pub base_backup_chain: Option<VerifiedBackupChainV1>,
    accepted: AcceptedMutationV1,
}

#[derive(Clone, Debug)]
pub struct RuntimeBoundInstalledDeploymentV1 {
    pub prepared: PreparedInstalledDeploymentV1,
    pub authorization: ExecutorAuthorization,
    pub artifacts: RuntimeCandidateArtifactsV1,
}

impl PreparedInstalledDeploymentV1 {
    pub fn load<S: DeploySourceSnapshotV1>(
        resolver: &InstalledDeployIntentResolverV1<S>,
        accepted: &AcceptedMutationV1,
    ) -> Result<Self, DeployDriverError> {
        Self::load_with_base_backup(resolver, accepted, None)
    }

    fn load_for_execution<S: DeploySourceSnapshotV1>(
        resolver: &InstalledDeployIntentResolverV1<S>,
        security: &SecurityStore,
        accepted: &AcceptedMutationV1,
    ) -> Result<Self, DeployDriverError> {
        let base_backup_chain = if accepted.previous_release_bundle_digest.is_some() {
            security
                .latest_committed_base_backup_chain(&accepted.project_id)?
                .map(|record| VerifiedBackupChainV1::decode_canonical(&record.canonical_json))
                .transpose()?
        } else {
            None
        };
        Self::load_with_base_backup(resolver, accepted, base_backup_chain)
    }

    fn load_with_base_backup<S: DeploySourceSnapshotV1>(
        resolver: &InstalledDeployIntentResolverV1<S>,
        accepted: &AcceptedMutationV1,
        base_backup_chain: Option<VerifiedBackupChainV1>,
    ) -> Result<Self, DeployDriverError> {
        let mutation_policy = resolver.load_policy()?;
        let rimg_policy = resolver.load_rimg_policy()?;
        let release_state = resolver.load_release_state()?;
        validate_policy_state_binding(&mutation_policy, &rimg_policy, &release_state)?;
        if accepted.previous_release_bundle_digest.is_some()
            && (!rimg_policy.capabilities().stable_routing
                || !rimg_policy.capabilities().automatic_code_rollback)
        {
            return Err(DeployDriverError::InstalledBinding);
        }
        let target = validate_accepted_deploy(accepted, &mutation_policy)?;
        let (attestation, candidate) =
            resolver.load_candidate(&mutation_policy, target, accepted.accepted_at_ms)?;
        validate_candidate_binding(accepted, &attestation, &candidate, &rimg_policy)?;
        let current = accepted
            .previous_release_bundle_digest
            .as_ref()
            .map(|digest| resolver.load_promoted_bundle(&mutation_policy, digest))
            .transpose()?;
        validate_release_shape(
            &release_state,
            current.as_ref(),
            &candidate,
            base_backup_chain.as_ref(),
        )?;
        let operation = reconstruct_deploy_operation(
            accepted,
            &mutation_policy,
            &candidate,
            base_backup_chain.as_ref(),
        );
        Ok(Self {
            operation,
            mutation_policy,
            rimg_policy,
            release_state,
            attestation,
            candidate,
            current,
            base_backup_chain,
            accepted: accepted.clone(),
        })
    }

    pub fn bind_runtime_reservation(
        mut self,
        security: &crate::store::SecurityStore,
        disk: &InstalledBackupDiskProbeV1,
        now_ms: i64,
    ) -> Result<RuntimeBoundInstalledDeploymentV1, DeployDriverError> {
        if now_ms < 0 {
            return Err(DeployDriverError::InvalidTime);
        }
        let authorization_digest = executor_authorization_digest(&self.operation)?;
        let expires_at_ms = self
            .accepted
            .intent_expires_at_ms
            .min(self.accepted.grant_expires_at_ms);
        let authorization = if let Some(existing) =
            security.executor_authorization(self.accepted.attempt_id)?
        {
            existing
        } else {
            let reservation = disk.reservation_with_requirements(
                DiskReservationRequirementsV1 {
                    backup_staging: self.mutation_policy.backup_staging_bytes,
                    build_peak: self.mutation_policy.build_peak_bytes,
                    registry_peak: self.mutation_policy.registry_peak_bytes,
                    last_known_good: self.mutation_policy.last_known_good_bytes,
                    projected_hot_store_growth: self
                        .mutation_policy
                        .projected_hot_store_growth_bytes,
                },
                now_ms,
            )?;
            let reservation =
                ResourceReservationEvidenceV1::reserve(authorization_digest.clone(), reservation)?;
            let authorization = ExecutorAuthorization {
                authorization_id: self.accepted.action_grant_nonce,
                digest: authorization_digest.clone(),
                attempt_id: self.accepted.attempt_id,
                project_id: self.accepted.project_id.clone(),
                expires_at_ms,
                disk_reservation: Some(reservation.authorization()),
            };
            security.authorize_attempt(&authorization, self.accepted.accepted_at_ms)?;
            authorization
        };
        if authorization.authorization_id != self.accepted.action_grant_nonce
            || authorization.digest != authorization_digest
            || authorization.attempt_id != self.accepted.attempt_id
            || authorization.project_id != self.accepted.project_id
            || authorization.expires_at_ms != expires_at_ms
        {
            return Err(DeployDriverError::AuthorizationBinding);
        }
        let reservation_digest = authorization
            .disk_reservation
            .as_ref()
            .ok_or(DeployDriverError::AuthorizationBinding)?
            .reservation_digest
            .clone();
        let artifacts = self
            .attestation
            .bind_runtime_reservation(reservation_digest.clone())?;
        self.operation.evidence.resource_reservation_digest = Some(reservation_digest);
        Ok(RuntimeBoundInstalledDeploymentV1 {
            prepared: self,
            authorization,
            artifacts,
        })
    }
}

fn validate_policy_state_binding(
    mutation: &InstalledDeployMutationPolicyV1,
    rimg: &InstalledRimgPolicyV1,
    state: &InstalledReleaseStateV1,
) -> Result<(), DeployDriverError> {
    if rimg.project_id() != &mutation.project_id
        || rimg.installed_policy() != &mutation.installed_policy
        || rimg.digest() != &mutation.installed_rimg_policy_digest
        || state.project_id != mutation.project_id
        || state.installed_policy != mutation.installed_policy
        || state.installed_rimg_policy_digest != mutation.installed_rimg_policy_digest
        || !rimg.capabilities().bootstrap_with_declared_downtime
    {
        return Err(DeployDriverError::InstalledBinding);
    }
    Ok(())
}

fn validate_release_shape(
    state: &InstalledReleaseStateV1,
    current: Option<&ReleaseBundleV1>,
    candidate: &ReleaseBundleV1,
    base_backup_chain: Option<&VerifiedBackupChainV1>,
) -> Result<(), DeployDriverError> {
    match (state.current_release_bundle_digest.as_ref(), current) {
        (None, None)
            if state.last_known_good_release_bundle_digest.is_none()
                && base_backup_chain.is_none() => {}
        (Some(current_digest), None)
            if current_digest == candidate.digest()
                && state.last_known_good_release_bundle_digest.is_none()
                && base_backup_chain.is_none() => {}
        (Some(current_digest), Some(current))
            if (current.digest() == current_digest || candidate.digest() == current_digest)
                && current.digest() != candidate.digest()
                && base_backup_chain.is_some() => {}
        _ => return Err(DeployDriverError::InstalledBinding),
    }
    Ok(())
}

fn validate_accepted_deploy<'a>(
    accepted: &'a AcceptedMutationV1,
    policy: &InstalledDeployMutationPolicyV1,
) -> Result<&'a crate::domain::GitCommitId, DeployDriverError> {
    if accepted.operation_kind != OperationKind::Deploy
        || accepted.project_id != policy.project_id
        || accepted.installed_policy_digest != policy.document_digest
        || accepted.effective_release_class != Some(ReleaseClass::CodeOnlyCompatible)
        || accepted.source_attestation_digest.is_none()
        || accepted.source_sequence.is_none()
        || accepted.release_bundle_digest.is_none()
        || accepted.build_attestation_digest.is_none()
        || accepted.migration_id.is_some()
    {
        return Err(DeployDriverError::AcceptedMutationBinding);
    }
    accepted
        .target_commit
        .as_ref()
        .ok_or(DeployDriverError::AcceptedMutationBinding)
}

fn validate_candidate_binding(
    accepted: &AcceptedMutationV1,
    attestation: &BuildReleaseAttestationV1,
    candidate: &ReleaseBundleV1,
    rimg: &InstalledRimgPolicyV1,
) -> Result<(), DeployDriverError> {
    if accepted.release_bundle_digest.as_ref() != Some(candidate.digest())
        || accepted.build_attestation_digest.as_ref() != Some(&attestation.payload_digest)
        || accepted.source_attestation_digest.as_ref()
            != Some(&attestation.source_attestation_digest)
        || accepted.source_sequence != Some(attestation.source_sequence)
        || accepted.target_commit.as_ref() != Some(&attestation.source_head)
        || candidate.project_id() != rimg.project_id()
        || candidate.deployment_plan().installed_policy() != rimg.installed_policy()
    {
        return Err(DeployDriverError::CandidateBinding);
    }
    Ok(())
}

fn reconstruct_deploy_operation(
    accepted: &AcceptedMutationV1,
    policy: &InstalledDeployMutationPolicyV1,
    candidate: &ReleaseBundleV1,
    base_backup_chain: Option<&VerifiedBackupChainV1>,
) -> OperationRecord {
    let mut evidence = OperationEvidence {
        installed_policy: Some(policy.installed_policy.clone()),
        source_attestation_digest: accepted.source_attestation_digest.clone(),
        source_sequence: accepted.source_sequence,
        deployment_plan_digest: Some(candidate.deployment_plan_digest().clone()),
        release_bundle_digest: Some(candidate.digest().clone()),
        previous_release_bundle_digest: accepted.previous_release_bundle_digest.clone(),
        action_grant_digest: Some(accepted.action_grant_digest.clone()),
        ..OperationEvidence::default()
    };
    if let Some(chain) = base_backup_chain {
        evidence.backup_set_id = Some(chain.authorized_spec().backup_set_id);
        evidence.base_backup_id = Some(chain.authorized_spec().backup_id);
        evidence.base_backup_manifest_digest = Some(chain.manifest().manifest_digest.clone());
        evidence.base_backup_evidence_digest = Some(chain.local().evidence_digest.clone());
        evidence.base_backup_offsite_evidence_digest =
            chain.offsite().map(|value| value.evidence_digest.clone());
        evidence.base_backup_verification_digest = Some(chain.chain_digest().clone());
    }
    OperationRecord {
        operation_id: accepted.intent_id,
        request_id: accepted.request_id,
        attempt_id: accepted.attempt_id,
        attempt_number: 1,
        project_id: accepted.project_id.clone(),
        operation_kind: OperationKind::Deploy,
        target_commit: accepted.target_commit.clone(),
        release_class: accepted.effective_release_class,
        state: OperationState {
            phase: OperationPhase::Queued,
            result: OperationResult::Running,
            blocking_reason: BlockingReason::None,
        },
        actor: OperationActor::Interactive {
            user_id: accepted.actor_id,
        },
        evidence,
        failure_capsule: None,
        created_at_ms: accepted.accepted_at_ms,
        updated_at_ms: accepted.accepted_at_ms,
    }
}

pub trait DeployClockSourceV1: fmt::Debug + Send + Sync + 'static {
    fn observe(
        &self,
        expected_executable_digest: &EvidenceDigest,
        now_ms: i64,
    ) -> Result<TrustedClockEvidenceV1, DeployDriverError>;
}

pub trait AcceptedDeployJobDriverV1: Send + Sync + 'static {
    fn drive(&self, accepted: &AcceptedMutationV1) -> Result<OperationRecord, DeployDriverError>;

    fn has_committed_terminal(
        &self,
        accepted: &AcceptedMutationV1,
    ) -> Result<bool, DeployDriverError>;
}

#[derive(Debug)]
pub struct DeployJobFailureV1 {
    pub intent_id: Uuid,
    pub attempt_id: Uuid,
    pub error: DeployDriverError,
}

pub fn drive_pending_deploy_jobs_until<F>(
    security: &SecurityStore,
    driver: &dyn AcceptedDeployJobDriverV1,
    mut cancelled: F,
) -> Result<Vec<DeployJobFailureV1>, StoreError>
where
    F: FnMut() -> bool,
{
    let mut failures = Vec::new();
    for accepted in security.accepted_mutations()? {
        if cancelled() {
            break;
        }
        if accepted.operation_kind != OperationKind::Deploy {
            continue;
        }
        let terminal_receipt = security
            .phase_receipt(accepted.attempt_id, OperationPhase::Soaking)?
            .is_some()
            || security
                .phase_receipt_in_branch(
                    accepted.attempt_id,
                    OperationPhase::Soaking,
                    ExecutorPhaseBranch::RollbackRecovery,
                )?
                .is_some();
        if terminal_receipt {
            match driver.has_committed_terminal(&accepted) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    failures.push(DeployJobFailureV1 {
                        intent_id: accepted.intent_id,
                        attempt_id: accepted.attempt_id,
                        error,
                    });
                    continue;
                }
            }
        }
        if let Err(error) = driver.drive(&accepted) {
            failures.push(DeployJobFailureV1 {
                intent_id: accepted.intent_id,
                attempt_id: accepted.attempt_id,
                error,
            });
        }
    }
    Ok(failures)
}

#[derive(Clone, Debug)]
struct InstalledDeployEffectsV1<E> {
    delegate: E,
    candidate: RuntimeCandidateArtifactsV1,
}

impl<E: ExternalEffects> InstalledDeployEffectsV1<E> {
    fn candidate_observation(
        &self,
        intent: &PhaseIntent,
    ) -> Result<EffectObservation, ExternalEffectError> {
        let artifacts = match intent.phase {
            OperationPhase::Queued
            | OperationPhase::SyncingSource
            | OperationPhase::VerifyingSource => PhaseArtifacts::default(),
            OperationPhase::Testing => self.candidate.testing.clone(),
            OperationPhase::Building => self.candidate.building.clone(),
            OperationPhase::Preflight => self.candidate.preflight.clone(),
            _ => return Err(ExternalEffectError::ConflictingState),
        };
        let observation_digest = EvidenceDigest::sha256(
            serde_jcs::to_vec(&(
                "rdashboard.bootstrap-candidate-observation.v1",
                &intent.digest,
                &artifacts,
            ))
            .map_err(|_| ExternalEffectError::ConflictingState)?,
        );
        Ok(EffectObservation::Applied(Box::new(PhaseEffectEvidence {
            intent_digest: intent.digest.clone(),
            observation_digest,
            artifacts,
        })))
    }
}

impl<E: ExternalEffects> ExternalEffects for InstalledDeployEffectsV1<E> {
    fn observe_phase(
        &self,
        intent: &PhaseIntent,
    ) -> Result<EffectObservation, ExternalEffectError> {
        if intent.phase.crosses_mutation_boundary() {
            self.delegate.observe_phase(intent)
        } else {
            self.candidate_observation(intent)
        }
    }

    fn apply_phase(&self, intent: &PhaseIntent) -> Result<(), ExternalEffectError> {
        if intent.phase.crosses_mutation_boundary() {
            self.delegate.apply_phase(intent)
        } else {
            Ok(())
        }
    }

    fn observe_phase_with_operation_identity(
        &self,
        intent: &PhaseIntent,
        operation_identity: Option<&PhaseOperationIdentityLeaseV1>,
    ) -> Result<EffectObservation, ExternalEffectError> {
        if intent.phase.crosses_mutation_boundary() {
            self.delegate
                .observe_phase_with_operation_identity(intent, operation_identity)
        } else if operation_identity.is_none() {
            self.candidate_observation(intent)
        } else {
            Err(ExternalEffectError::ConflictingState)
        }
    }

    fn apply_phase_with_operation_identity(
        &self,
        intent: &PhaseIntent,
        operation_identity: Option<&PhaseOperationIdentityLeaseV1>,
    ) -> Result<(), ExternalEffectError> {
        if intent.phase.crosses_mutation_boundary() {
            self.delegate
                .apply_phase_with_operation_identity(intent, operation_identity)
        } else if operation_identity.is_none() {
            Ok(())
        } else {
            Err(ExternalEffectError::ConflictingState)
        }
    }

    fn observe_fence(
        &self,
        project_id: &crate::domain::ProjectId,
    ) -> Result<FenceObservation, ExternalEffectError> {
        self.delegate.observe_fence(project_id)
    }

    fn acquire_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError> {
        self.delegate.acquire_fence(lease)
    }

    fn release_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError> {
        self.delegate.release_fence(lease)
    }
}

#[derive(Clone, Debug)]
pub struct InstalledDeployOperationDriverV1<S, E, C> {
    security: SecurityStore,
    resolver: InstalledDeployIntentResolverV1<S>,
    disk: InstalledBackupDiskProbeV1,
    effects: E,
    clock: C,
}

impl<S, E, C> InstalledDeployOperationDriverV1<S, E, C>
where
    S: DeploySourceSnapshotV1 + LiveSourceGate + Clone,
    E: ExternalEffects + Clone,
    C: DeployClockSourceV1,
{
    pub const fn new(
        security: SecurityStore,
        resolver: InstalledDeployIntentResolverV1<S>,
        disk: InstalledBackupDiskProbeV1,
        effects: E,
        clock: C,
    ) -> Self {
        Self {
            security,
            resolver,
            disk,
            effects,
            clock,
        }
    }

    pub fn drive_accepted(
        &self,
        accepted: &AcceptedMutationV1,
        now_ms: i64,
    ) -> Result<OperationRecord, DeployDriverError> {
        let prepared = PreparedInstalledDeploymentV1::load_for_execution(
            &self.resolver,
            &self.security,
            accepted,
        )?;
        let mut projected = prepared.operation.clone();
        project_existing_deploy_receipts(&self.security, &mut projected)?;
        if projected.state.result == OperationResult::Succeeded
            && prepared
                .release_state
                .current_release_bundle_digest
                .as_ref()
                == Some(prepared.candidate.digest())
        {
            return Ok(projected);
        }
        if projected.state.result == OperationResult::RolledBack
            && prepared.release_state.current_release_bundle_digest
                == accepted.previous_release_bundle_digest
        {
            return Ok(projected);
        }
        if prepared
            .release_state
            .current_release_bundle_digest
            .as_ref()
            == Some(prepared.candidate.digest())
        {
            return Err(DeployDriverError::ReleaseStateWithoutTerminalReceipt);
        }
        let runtime = prepared.bind_runtime_reservation(&self.security, &self.disk, now_ms)?;
        self.resolver.promote_candidate_bundle(
            &runtime.prepared.mutation_policy,
            &runtime.prepared.candidate,
        )?;
        let mut operation = runtime.prepared.operation.clone();
        project_existing_deploy_receipts(&self.security, &mut operation)?;
        let authorization_digest = executor_authorization_digest(&operation)?;
        let executor = DurableExecutor::new(
            self.security.clone(),
            InstalledDeployEffectsV1 {
                delegate: self.effects.clone(),
                candidate: runtime.artifacts,
            },
        )
        .with_source_gate(Arc::new(self.resolver.source().clone()))
        .with_disk_space_probe(Arc::new(self.disk.clone()));
        executor.recover_security_state(std::slice::from_ref(&operation.project_id), now_ms)?;

        while operation.state.result == OperationResult::Running {
            if matches!(
                operation.state.phase,
                OperationPhase::Deploying
                    | OperationPhase::HealthChecking
                    | OperationPhase::Soaking
                    | OperationPhase::Rollback
            ) {
                self.ensure_deploy_phase_spec(
                    &operation,
                    &runtime.prepared,
                    &authorization_digest,
                    now_ms,
                )?;
            }
            match executor.execute_phase(&operation, None, now_ms) {
                Ok(receipt) => {
                    let rollback =
                        operation.evidence.recovery_mode == Some(OperationRecoveryMode::Rollback);
                    project_deploy_receipt(&mut operation, &receipt, rollback)?;
                }
                Err(_error)
                    if runtime.prepared.current.is_some()
                        && operation.evidence.recovery_mode.is_none()
                        && matches!(
                            operation.state.phase,
                            OperationPhase::HealthChecking | OperationPhase::Soaking
                        ) =>
                {
                    self.security.begin_rollback_takeover(
                        operation.attempt_id,
                        &operation.project_id,
                        &authorization_digest,
                        now_ms,
                    )?;
                    begin_rollback_projection(&mut operation, now_ms)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        executor.cleanup_terminal_resources(&operation, now_ms)?;
        if operation.state.result == OperationResult::RolledBack {
            return Ok(operation);
        }
        self.commit_succeeded_release(&runtime.prepared, now_ms)?;
        Ok(operation)
    }

    fn commit_succeeded_release(
        &self,
        prepared: &PreparedInstalledDeploymentV1,
        now_ms: i64,
    ) -> Result<(), DeployDriverError> {
        if prepared.current.is_some() {
            self.resolver.commit_installed_release(
                &prepared.release_state,
                &prepared.candidate,
                now_ms,
            )?;
        } else {
            self.resolver.commit_bootstrap_release(
                &prepared.release_state,
                &prepared.candidate,
                now_ms,
            )?;
        }
        Ok(())
    }

    fn ensure_deploy_phase_spec(
        &self,
        operation: &OperationRecord,
        prepared: &PreparedInstalledDeploymentV1,
        authorization_digest: &EvidenceDigest,
        now_ms: i64,
    ) -> Result<(), DeployDriverError> {
        let intent = PhaseIntent::from_operation(operation, authorization_digest.clone())?;
        let branch = intent.branch;
        let phase_plan = operation
            .operation_kind
            .required_phases(operation.release_class)
            .map_err(StoreError::from)?;
        self.security.begin_phase_intent(PhaseIntentRequest {
            attempt_id: operation.attempt_id,
            project_id: &operation.project_id,
            phase: operation.state.phase,
            branch,
            phase_plan: ExecutorPhasePlan::new(phase_plan, true),
            intent_digest: &intent.digest,
            authorization_digest,
            started_at_ms: now_ms,
        })?;
        let existing = self.security.authorized_phase_spec_in_branch(
            operation.attempt_id,
            operation.state.phase,
            branch,
        )?;
        if let Some(record) = existing {
            let stored = AuthorizedPhaseSpecV1::decode_canonical(&record.canonical_json)?;
            if stored.attempt_id != operation.attempt_id
                || stored.project_id != operation.project_id
                || stored.phase != operation.state.phase
                || stored.branch != intent.branch
                || stored.intent_digest != intent.digest
                || stored.installed_rimg_policy_digest != *prepared.rimg_policy.digest()
                || stored.release_bundle_digest.as_ref() != Some(prepared.candidate.digest())
                || stored.deployment_plan_digest.as_ref()
                    != Some(prepared.candidate.deployment_plan_digest())
                || stored.effective_release_class
                    != Some(if intent.branch == ExecutorPhaseBranch::RollbackRecovery {
                        ReleaseClass::Rollback
                    } else {
                        ReleaseClass::CodeOnlyCompatible
                    })
            {
                return Err(DeployDriverError::PhaseSpecBinding);
            }
            return Ok(());
        }
        let expected = if intent.branch == ExecutorPhaseBranch::RollbackRecovery {
            rollback_phase_spec(&intent, prepared)?
        } else {
            deploy_phase_spec(&intent, prepared, &self.clock, now_ms)?
        };
        let canonical = expected.canonical_bytes()?;
        self.security
            .bind_authorized_phase_spec(AuthorizedPhaseSpecBinding {
                attempt_id: operation.attempt_id,
                project_id: &operation.project_id,
                phase: operation.state.phase,
                branch,
                intent_digest: &intent.digest,
                spec_digest: &expected.spec_digest,
                canonical_json: &canonical,
                persisted_at_ms: now_ms,
            })?;
        Ok(())
    }
}

impl<S, E, C> AcceptedDeployJobDriverV1 for InstalledDeployOperationDriverV1<S, E, C>
where
    S: DeploySourceSnapshotV1 + LiveSourceGate + Clone,
    E: ExternalEffects + Clone,
    C: DeployClockSourceV1,
{
    fn drive(&self, accepted: &AcceptedMutationV1) -> Result<OperationRecord, DeployDriverError> {
        self.drive_accepted(accepted, crate::unix_time_ms()?)
    }

    fn has_committed_terminal(
        &self,
        accepted: &AcceptedMutationV1,
    ) -> Result<bool, DeployDriverError> {
        let prepared = PreparedInstalledDeploymentV1::load_for_execution(
            &self.resolver,
            &self.security,
            accepted,
        )?;
        let mut operation = prepared.operation.clone();
        project_existing_deploy_receipts(&self.security, &mut operation)?;
        let state_committed = prepared
            .release_state
            .current_release_bundle_digest
            .as_ref()
            == Some(prepared.candidate.digest());
        let rolled_back = operation.state.result == OperationResult::RolledBack
            && prepared.release_state.current_release_bundle_digest
                == accepted.previous_release_bundle_digest;
        if state_committed && operation.state.result != OperationResult::Succeeded {
            return Err(DeployDriverError::ReleaseStateWithoutTerminalReceipt);
        }
        Ok(state_committed || rolled_back)
    }
}

fn deploy_phase_spec<'a>(
    intent: &'a PhaseIntent,
    prepared: &'a PreparedInstalledDeploymentV1,
    clock_source: &dyn DeployClockSourceV1,
    boundary_now_ms: i64,
) -> Result<AuthorizedPhaseSpecV1, DeployDriverError> {
    let policy = &prepared.rimg_policy;
    let compatibility = SchemaContractEvaluationEvidenceV1::new(SchemaContractEvaluationInputV1 {
        intent,
        policy,
        kind: SchemaContractKindV1::DataCompatibility,
        current_schema_version: prepared
            .current
            .as_ref()
            .map(ReleaseBundleV1::application_schema_version),
        candidate_schema_version: prepared.candidate.application_schema_version(),
        migration_id: None,
        contract_digest: policy.schema_contract_digest().clone(),
        verdict: SchemaContractVerdictV1::Satisfied,
        observation_digest: prepared
            .attestation
            .data_compatibility_observation_digest
            .clone(),
        evaluated_at_ms: prepared.accepted.accepted_at_ms,
    })?;
    let inspection = SchemaInspectionEvidenceV1::new(SchemaInspectionEvidenceInputV1 {
        intent,
        policy,
        current_bundle: prepared.current.as_ref(),
        candidate_bundle: &prepared.candidate,
        migration_id: None,
        migration_plan_evidence: None,
        data_compatibility_evidence: &compatibility,
        observation_digest: EvidenceDigest::sha256(serde_jcs::to_vec(&(
            "rdashboard.bootstrap-schema-inspection.v1",
            &intent.digest,
            &prepared.attestation.payload_digest,
        ))?),
        inspected_at_ms: prepared.accepted.accepted_at_ms,
    })?;
    let classification = ReleaseClassificationAuthorityV1::derive(&ReleaseClassificationInputV1 {
        intent,
        policy,
        current_bundle: prepared.current.as_ref(),
        candidate_bundle: &prepared.candidate,
        schema_inspection: &inspection,
    })?;
    let (clock, runtime) =
        if intent.phase == OperationPhase::Deploying {
            let clock =
                clock_source.observe(&prepared.mutation_policy.chronyc_sha256, boundary_now_ms)?;
            let valid_until_ms = boundary_now_ms
                .checked_add(30_000)
                .ok_or(DeployDriverError::InvalidTime)?;
            let runtime_state = prepared.current.as_ref().map_or(
                RuntimeReleaseStateV1::NeverInstalled,
                |current| RuntimeReleaseStateV1::Installed {
                    current_release_bundle_digest: current.digest().clone(),
                },
            );
            let runtime = RuntimeReleaseStateEvidenceV1::observe(
                RuntimeReleaseStateEvidenceInputV1 {
                    attempt_id: intent.attempt_id,
                    project_id: intent.project_id.clone(),
                    installed_policy: policy.installed_policy().clone(),
                    phase_intent_digest: intent.digest.clone(),
                    state: runtime_state,
                    valid_until_ms,
                    observation_digest: EvidenceDigest::sha256(serde_jcs::to_vec(&(
                        "rdashboard.installed-release-state-observation.v1",
                        &prepared.release_state.document_digest,
                        &intent.digest,
                    ))?),
                },
                &clock,
            )?;
            (Some(clock), Some(runtime))
        } else {
            (None, None)
        };
    AuthorizedPhaseSpecV1::resolve(AuthorizedPhaseSpecInputV1 {
        intent,
        policy,
        classification: Some(&classification),
        backup: None,
        prerequisites: AuthorizedPhasePrerequisitesV1 {
            trusted_clock: clock.as_ref(),
            boundary_now_ms: clock.as_ref().map(|_| boundary_now_ms),
            base_backup_chain: (intent.phase == OperationPhase::Deploying)
                .then_some(prepared.base_backup_chain.as_ref())
                .flatten(),
            runtime_release_state: runtime.as_ref(),
            ..AuthorizedPhasePrerequisitesV1::default()
        },
    })
    .map_err(Into::into)
}

fn rollback_phase_spec(
    intent: &PhaseIntent,
    prepared: &PreparedInstalledDeploymentV1,
) -> Result<AuthorizedPhaseSpecV1, DeployDriverError> {
    let policy = &prepared.rimg_policy;
    let rollback_target = prepared
        .current
        .as_ref()
        .ok_or(DeployDriverError::RollbackBinding)?;
    let compatibility_observation = EvidenceDigest::sha256(serde_jcs::to_vec(&(
        "rdashboard.rollback-data-compatibility-observation.v1",
        &intent.digest,
        prepared.candidate.digest(),
        rollback_target.digest(),
        policy.schema_contract_digest(),
    ))?);
    let compatibility = SchemaContractEvaluationEvidenceV1::new(SchemaContractEvaluationInputV1 {
        intent,
        policy,
        kind: SchemaContractKindV1::DataCompatibility,
        current_schema_version: Some(prepared.candidate.application_schema_version()),
        candidate_schema_version: rollback_target.application_schema_version(),
        migration_id: None,
        contract_digest: policy.schema_contract_digest().clone(),
        verdict: SchemaContractVerdictV1::Satisfied,
        observation_digest: compatibility_observation,
        evaluated_at_ms: prepared.accepted.accepted_at_ms,
    })?;
    let inspection = SchemaInspectionEvidenceV1::new(SchemaInspectionEvidenceInputV1 {
        intent,
        policy,
        current_bundle: Some(&prepared.candidate),
        candidate_bundle: rollback_target,
        migration_id: None,
        migration_plan_evidence: None,
        data_compatibility_evidence: &compatibility,
        observation_digest: EvidenceDigest::sha256(serde_jcs::to_vec(&(
            "rdashboard.rollback-schema-inspection.v1",
            &intent.digest,
            prepared.candidate.digest(),
            rollback_target.digest(),
        ))?),
        inspected_at_ms: prepared.accepted.accepted_at_ms,
    })?;
    let classification = ReleaseClassificationAuthorityV1::derive(&ReleaseClassificationInputV1 {
        intent,
        policy,
        current_bundle: Some(&prepared.candidate),
        candidate_bundle: rollback_target,
        schema_inspection: &inspection,
    })?;
    AuthorizedPhaseSpecV1::resolve(AuthorizedPhaseSpecInputV1 {
        intent,
        policy,
        classification: Some(&classification),
        backup: None,
        prerequisites: AuthorizedPhasePrerequisitesV1::default(),
    })
    .map_err(Into::into)
}

fn project_existing_deploy_receipts(
    security: &SecurityStore,
    operation: &mut OperationRecord,
) -> Result<(), DeployDriverError> {
    let mut missing = false;
    for phase in OperationKind::Deploy.required_phases(operation.release_class)? {
        match security.phase_receipt(operation.attempt_id, *phase)? {
            Some(receipt) if !missing => project_deploy_receipt(operation, &receipt, false)?,
            Some(_) => return Err(DeployDriverError::ReceiptOrder),
            None => missing = true,
        }
    }
    if let Some(takeover) = security.rollback_takeover(operation.attempt_id)? {
        if operation.evidence.recovery_mode.is_none() {
            begin_rollback_projection(operation, takeover.created_at_ms)?;
        }
        let mut rollback_missing = false;
        for phase in [
            OperationPhase::Rollback,
            OperationPhase::HealthChecking,
            OperationPhase::Soaking,
        ] {
            match security.phase_receipt_in_branch(
                operation.attempt_id,
                phase,
                ExecutorPhaseBranch::RollbackRecovery,
            )? {
                Some(receipt) if !rollback_missing => {
                    project_deploy_receipt(operation, &receipt, true)?;
                }
                Some(_) => return Err(DeployDriverError::ReceiptOrder),
                None => rollback_missing = true,
            }
        }
    }
    Ok(())
}

fn begin_rollback_projection(
    operation: &mut OperationRecord,
    occurred_at_ms: i64,
) -> Result<(), DeployDriverError> {
    if operation.state.result != OperationResult::Running
        || !matches!(
            operation.state.phase,
            OperationPhase::HealthChecking | OperationPhase::Soaking
        )
        || operation.evidence.previous_release_bundle_digest.is_none()
    {
        return Err(DeployDriverError::RollbackBinding);
    }
    let next = OperationState {
        phase: OperationPhase::Rollback,
        result: OperationResult::Running,
        blocking_reason: BlockingReason::None,
    };
    let sequence = u32::try_from(operation.evidence.transitions.len())
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(DeployDriverError::TransitionOverflow)?;
    operation.evidence.transitions.push(OperationTransition {
        sequence,
        from: operation.state.clone(),
        to: next.clone(),
        receipt_digest: None,
        occurred_at_ms,
    });
    operation.evidence.recovery_mode = Some(OperationRecoveryMode::Rollback);
    operation.state = next;
    operation.updated_at_ms = occurred_at_ms;
    Ok(())
}

fn project_deploy_receipt(
    operation: &mut OperationRecord,
    receipt: &PhaseReceipt,
    rollback_recovery: bool,
) -> Result<(), DeployDriverError> {
    if !receipt.has_valid_digest()?
        || receipt.attempt_id != operation.attempt_id
        || receipt.branch
            != if rollback_recovery {
                ExecutorPhaseBranch::RollbackRecovery
            } else {
                ExecutorPhaseBranch::Primary
            }
        || receipt.phase != operation.state.phase
        || operation.state.result != OperationResult::Running
    {
        return Err(DeployDriverError::ReceiptBinding);
    }
    receipt.artifacts.validate_for_phase(receipt.phase)?;
    merge_deploy_artifacts(
        &mut operation.evidence,
        &receipt.artifacts,
        receipt.phase,
        rollback_recovery,
    )?;
    let rollback_phases = [
        OperationPhase::Rollback,
        OperationPhase::HealthChecking,
        OperationPhase::Soaking,
    ];
    let phases = if rollback_recovery {
        rollback_phases.as_slice()
    } else {
        operation
            .operation_kind
            .required_phases(operation.release_class)?
    };
    let index = phases
        .iter()
        .position(|phase| *phase == receipt.phase)
        .ok_or(DeployDriverError::ReceiptBinding)?;
    let next = phases.get(index + 1).copied();
    let next_state = next.map_or(
        OperationState {
            phase: receipt.phase,
            result: if rollback_recovery {
                OperationResult::RolledBack
            } else {
                OperationResult::Succeeded
            },
            blocking_reason: BlockingReason::None,
        },
        |phase| OperationState {
            phase,
            result: OperationResult::Running,
            blocking_reason: BlockingReason::None,
        },
    );
    let sequence = u32::try_from(operation.evidence.transitions.len())
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(DeployDriverError::TransitionOverflow)?;
    operation.evidence.transitions.push(OperationTransition {
        sequence,
        from: operation.state.clone(),
        to: next_state.clone(),
        receipt_digest: Some(receipt.receipt_digest.clone()),
        occurred_at_ms: receipt.committed_at_ms,
    });
    operation.state = next_state;
    operation.updated_at_ms = receipt.committed_at_ms;
    Ok(())
}

fn merge_deploy_artifacts(
    evidence: &mut OperationEvidence,
    artifacts: &PhaseArtifacts,
    phase: OperationPhase,
    rollback_recovery: bool,
) -> Result<(), DeployDriverError> {
    if let Some(spec_digest) = artifacts.authorized_phase_spec_digest.as_ref() {
        let binding = AuthorizedPhaseSpecDigestV1 {
            branch: if rollback_recovery {
                ExecutorPhaseBranch::RollbackRecovery
            } else {
                ExecutorPhaseBranch::Primary
            },
            phase,
            spec_digest: spec_digest.clone(),
        };
        match evidence
            .authorized_phase_spec_digests
            .iter()
            .find(|value| value.phase == phase && value.branch == binding.branch)
        {
            Some(existing) if existing == &binding => {}
            Some(_) => return Err(DeployDriverError::ArtifactConflict),
            None => evidence.authorized_phase_spec_digests.push(binding),
        }
    }
    merge_optional(
        &mut evidence.source_gate_proof_digest,
        artifacts.source_gate_proof_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.source_export_digest,
        artifacts.source_export_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.prefetch_evidence_digest,
        artifacts.prefetch_evidence_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.ci_evidence_digest,
        artifacts.ci_evidence_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.build_plan_digest,
        artifacts.build_plan_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.deployment_plan_digest,
        artifacts.deployment_plan_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.release_bundle_digest,
        artifacts.release_bundle_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.resource_reservation_digest,
        artifacts.resource_reservation_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.build_context_digest,
        artifacts.build_context_digest.as_ref(),
    )?;
    merge_vector(
        &mut evidence.generated_output_digests,
        &artifacts.generated_output_digests,
    )?;
    merge_optional(&mut evidence.image_digest, artifacts.image_digest.as_ref())?;
    merge_optional(
        &mut evidence.image_id_digest,
        artifacts.image_id_digest.as_ref(),
    )?;
    merge_vector(
        &mut evidence.base_image_digests,
        &artifacts.base_image_digests,
    )?;
    if phase == OperationPhase::Soaking && artifacts.health_evidence_digest.is_some() {
        if rollback_recovery {
            evidence
                .rollback_health_evidence_digest
                .clone_from(&artifacts.health_evidence_digest);
        } else {
            evidence
                .health_evidence_digest
                .clone_from(&artifacts.health_evidence_digest);
        }
        Ok(())
    } else {
        merge_optional(
            if rollback_recovery {
                &mut evidence.rollback_health_evidence_digest
            } else {
                &mut evidence.health_evidence_digest
            },
            artifacts.health_evidence_digest.as_ref(),
        )
    }
}

fn merge_optional<T: Clone + Eq>(
    target: &mut Option<T>,
    incoming: Option<&T>,
) -> Result<(), DeployDriverError> {
    match (&*target, incoming) {
        (_, None) => Ok(()),
        (None, Some(value)) => {
            *target = Some(value.clone());
            Ok(())
        }
        (Some(current), Some(value)) if current == value => Ok(()),
        (Some(_), Some(_)) => Err(DeployDriverError::ArtifactConflict),
    }
}

fn merge_vector<T: Clone + Eq>(
    target: &mut Vec<T>,
    incoming: &[T],
) -> Result<(), DeployDriverError> {
    if incoming.is_empty() || target == incoming {
        Ok(())
    } else if target.is_empty() {
        *target = incoming.to_vec();
        Ok(())
    } else {
        Err(DeployDriverError::ArtifactConflict)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeployDriverError {
    #[error("deploy driver time is invalid")]
    InvalidTime,
    #[error("installed deploy policy, rimg policy and release state do not match")]
    InstalledBinding,
    #[error("accepted mutation is not an authorized installed deployment")]
    AcceptedMutationBinding,
    #[error("accepted build candidate does not match the signed deploy intent")]
    CandidateBinding,
    #[error("persisted executor authorization conflicts with the accepted deployment")]
    AuthorizationBinding,
    #[error("persisted deploy receipts are not an ordered prefix")]
    ReceiptOrder,
    #[error("deploy receipt does not match the reconstructed deployment")]
    ReceiptBinding,
    #[error("deploy receipt evidence conflicts with prior durable evidence")]
    ArtifactConflict,
    #[error("deploy transition sequence overflowed")]
    TransitionOverflow,
    #[error("authorized deploy phase specification is not bound to this operation")]
    PhaseSpecBinding,
    #[error("the installed release state was committed without a terminal soak receipt")]
    ReleaseStateWithoutTerminalReceipt,
    #[error(
        "automatic rollback is not bound to the exact installed candidate and previous release"
    )]
    RollbackBinding,
    #[error("deploy driver cannot read a valid Unix system clock: {0}")]
    SystemClock(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Clock(#[from] crate::installed_clock::InstalledClockErrorV1),
    #[error(transparent)]
    Installed(#[from] InstalledDeployError),
    #[error(transparent)]
    Disk(#[from] BackupDiskProbeErrorV1),
    #[error(transparent)]
    Build(#[from] crate::build::BuildContractError),
    #[error(transparent)]
    BuildAttestation(#[from] crate::build_attestation::BuildReleaseAttestationError),
    #[error(transparent)]
    Backup(#[from] crate::backup::BackupContractError),
    #[error(transparent)]
    Phase6(#[from] Phase6ContractError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Phase(#[from] PhaseExecutionError),
    #[error(transparent)]
    Fence(#[from] FenceExecutionError),
    #[error(transparent)]
    Artifact(#[from] crate::domain::ArtifactContractError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Operation(#[from] crate::domain::OperationContractError),
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        path::{Path, PathBuf},
        str::FromStr as _,
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::SigningKey;
    use tempfile::{TempDir, tempdir};
    use uuid::Uuid;

    use super::*;
    use crate::{
        authorization::ActionGrantRoleV1,
        build::{ReleaseBundleStore, ReleaseBundleV1},
        build_attestation::{BuildReleaseAttestationInputV1, BuildReleaseAttestationV1},
        domain::{EvidenceDigest, GitCommitId, InstalledPolicyIdentity, PhaseArtifacts, ProjectId},
        executor::{DeterministicModelEffects, PhaseOperationIdentityLeaseV1},
        installed_deploy::{InstalledDeployMutationPolicyInputV1, InstalledReleaseStateInputV1},
        oci_handoff::OciArchivePublisherV1,
        phase6::tests::test_installed_rimg_policy,
        source::{SourceGateError, SourceGateProof, SourceSnapshot},
    };

    fn digest(label: &str) -> EvidenceDigest {
        EvidenceDigest::sha256(label)
    }

    fn project() -> ProjectId {
        ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project: {error}"))
    }

    fn installed_policy() -> InstalledPolicyIdentity {
        InstalledPolicyIdentity {
            digest: digest("installed policy"),
            version: 1,
        }
    }

    fn mutation_policy() -> InstalledDeployMutationPolicyV1 {
        let signing_key = SigningKey::from_bytes(&[41; 32]);
        InstalledDeployMutationPolicyV1::new(InstalledDeployMutationPolicyInputV1 {
            project_id: project(),
            installed_policy: installed_policy(),
            installed_rimg_policy_digest: digest("rimg policy"),
            build_uid: 1001,
            build_reader_gid: 1001,
            build_key_id: "build-v1".to_owned(),
            build_key_epoch: 1,
            build_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            chronyc_sha256: digest("chronyc executable"),
            backup_staging_bytes: 1,
            build_peak_bytes: 2,
            registry_peak_bytes: 3,
            last_known_good_bytes: 4,
            projected_hot_store_growth_bytes: 5,
            intent_ttl_ms: 30_000,
        })
        .unwrap_or_else(|error| panic!("mutation policy: {error}"))
    }

    fn accepted(policy: &InstalledDeployMutationPolicyV1) -> AcceptedMutationV1 {
        AcceptedMutationV1 {
            intent_id: Uuid::new_v4(),
            intent_digest: digest("intent"),
            signed_intent: "signed-intent".to_owned(),
            attempt_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            project_id: project(),
            operation_kind: OperationKind::Deploy,
            target_commit: Some(
                GitCommitId::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    .unwrap_or_else(|error| panic!("commit: {error}")),
            ),
            proposed_release_class: Some(ReleaseClass::CodeOnlyCompatible),
            effective_release_class: Some(ReleaseClass::CodeOnlyCompatible),
            installed_policy_digest: policy.document_digest.clone(),
            source_attestation_digest: Some(digest("source attestation")),
            source_sequence: Some(7),
            release_bundle_digest: Some(digest("candidate")),
            build_attestation_digest: Some(digest("build attestation")),
            migration_id: None,
            previous_release_bundle_digest: None,
            intent_expires_at_ms: 40_000,
            actor_id: Uuid::new_v4(),
            action_grant_role: ActionGrantRoleV1::Operator,
            action_grant_nonce: Uuid::new_v4(),
            action_grant_digest: digest("action grant"),
            lease_id: Uuid::new_v4(),
            lease_generation: 1,
            grant_expires_at_ms: 35_000,
            accepted_at_ms: 10_000,
        }
    }

    #[derive(Clone, Debug)]
    struct FixedDeploySourceV1;

    impl DeploySourceSnapshotV1 for FixedDeploySourceV1 {
        fn snapshot(&self, _project_id: &ProjectId) -> Result<SourceSnapshot, SourceGateError> {
            Err(SourceGateError::Unavailable)
        }
    }

    impl LiveSourceGate for FixedDeploySourceV1 {
        fn check_live(
            &self,
            operation: &OperationRecord,
            now_ms: i64,
        ) -> Result<SourceGateProof, SourceGateError> {
            Ok(SourceGateProof {
                digest: digest("live source proof"),
                project_id: operation.project_id.clone(),
                sequence: operation
                    .evidence
                    .source_sequence
                    .ok_or(SourceGateError::AttestationInvalid)?,
                attestation_digest: operation
                    .evidence
                    .source_attestation_digest
                    .clone()
                    .ok_or(SourceGateError::AttestationInvalid)?,
                checked_at_ms: now_ms,
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct FixedDeployClockV1;

    impl DeployClockSourceV1 for FixedDeployClockV1 {
        fn observe(
            &self,
            _expected_executable_digest: &EvidenceDigest,
            now_ms: i64,
        ) -> Result<TrustedClockEvidenceV1, DeployDriverError> {
            Ok(TrustedClockEvidenceV1::new(
                true,
                0,
                now_ms,
                digest("trusted clock observation"),
            )?)
        }
    }

    #[derive(Clone, Debug)]
    struct BoundDeployEffectsV1 {
        security: SecurityStore,
        model: DeterministicModelEffects,
    }

    impl BoundDeployEffectsV1 {
        fn bind_observation(
            &self,
            intent: &PhaseIntent,
            observation: EffectObservation,
        ) -> Result<EffectObservation, ExternalEffectError> {
            let EffectObservation::Applied(mut evidence) = observation else {
                return Ok(EffectObservation::Absent);
            };
            let record = self
                .security
                .authorized_phase_spec_in_branch(
                    intent.attempt_id,
                    intent.phase,
                    ExecutorPhaseBranch::Primary,
                )
                .map_err(|_| ExternalEffectError::ConflictingState)?
                .ok_or(ExternalEffectError::ConflictingState)?;
            let spec = AuthorizedPhaseSpecV1::decode_canonical(&record.canonical_json)
                .map_err(|_| ExternalEffectError::ConflictingState)?;
            evidence.artifacts = spec
                .bind_artifacts(evidence.artifacts)
                .map_err(|_| ExternalEffectError::ConflictingState)?;
            Ok(EffectObservation::Applied(evidence))
        }
    }

    impl ExternalEffects for BoundDeployEffectsV1 {
        fn observe_phase(
            &self,
            intent: &PhaseIntent,
        ) -> Result<EffectObservation, ExternalEffectError> {
            self.bind_observation(intent, self.model.observe_phase(intent)?)
        }

        fn apply_phase(&self, intent: &PhaseIntent) -> Result<(), ExternalEffectError> {
            self.security
                .authorize_bound_phase_spec(
                    intent.attempt_id,
                    intent.phase,
                    ExecutorPhaseBranch::Primary,
                    1_500,
                )
                .map_err(|_| ExternalEffectError::ConflictingState)?;
            self.model.apply_phase(intent)
        }

        fn observe_phase_with_operation_identity(
            &self,
            intent: &PhaseIntent,
            operation_identity: Option<&PhaseOperationIdentityLeaseV1>,
        ) -> Result<EffectObservation, ExternalEffectError> {
            if operation_identity.is_some() {
                return Err(ExternalEffectError::ConflictingState);
            }
            self.observe_phase(intent)
        }

        fn apply_phase_with_operation_identity(
            &self,
            intent: &PhaseIntent,
            operation_identity: Option<&PhaseOperationIdentityLeaseV1>,
        ) -> Result<(), ExternalEffectError> {
            if operation_identity.is_some() {
                return Err(ExternalEffectError::ConflictingState);
            }
            self.apply_phase(intent)
        }

        fn observe_fence(
            &self,
            project_id: &ProjectId,
        ) -> Result<FenceObservation, ExternalEffectError> {
            self.model.observe_fence(project_id)
        }

        fn acquire_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError> {
            self.model.acquire_fence(lease)
        }

        fn release_fence(&self, lease: &FenceLease) -> Result<(), ExternalEffectError> {
            self.model.release_fence(lease)
        }
    }

    struct BootstrapDriverFixtureV1 {
        _directory: TempDir,
        security_path: PathBuf,
        state_path: PathBuf,
        resolver: InstalledDeployIntentResolverV1<FixedDeploySourceV1>,
        disk: InstalledBackupDiskProbeV1,
        effects: BoundDeployEffectsV1,
        accepted: AcceptedMutationV1,
        initial_state: InstalledReleaseStateV1,
        candidate: ReleaseBundleV1,
    }

    impl BootstrapDriverFixtureV1 {
        fn driver(
            &self,
            security: SecurityStore,
        ) -> InstalledDeployOperationDriverV1<
            FixedDeploySourceV1,
            BoundDeployEffectsV1,
            FixedDeployClockV1,
        > {
            InstalledDeployOperationDriverV1::new(
                security,
                self.resolver.clone(),
                self.disk.clone(),
                self.effects.clone(),
                FixedDeployClockV1,
            )
        }
    }

    fn private_directory(path: &Path) {
        fs::create_dir(path).unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("chmod {}: {error}", path.display()));
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("chmod {}: {error}", path.display()));
    }

    fn share_candidate_directory(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o2750))
            .unwrap_or_else(|error| panic!("share directory {}: {error}", path.display()));
    }

    fn share_candidate_file(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o440))
            .unwrap_or_else(|error| panic!("share candidate {}: {error}", path.display()));
    }

    fn persist_shared_candidate_bundle(root: &Path, owner_uid: u32, candidate: &ReleaseBundleV1) {
        let candidate_path = ReleaseBundleStore::open_for_owner(root, owner_uid)
            .unwrap_or_else(|error| panic!("build bundle store: {error}"))
            .persist(candidate.project_id(), candidate)
            .unwrap_or_else(|error| panic!("persist build candidate: {error}"));
        share_candidate_directory(root);
        share_candidate_directory(&root.join(candidate.project_id().as_str()));
        share_candidate_file(&candidate_path);
    }

    fn persist_shared_candidate_attestation(root: &Path, attestation: &BuildReleaseAttestationV1) {
        let project_root = root.join(project().as_str());
        private_directory(&project_root);
        let path = project_root.join(format!("{}.jcs", attestation.source_head.as_str()));
        write_private(
            &path,
            &attestation
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("attestation JCS: {error}")),
        );
        share_candidate_directory(root);
        share_candidate_directory(&project_root);
        share_candidate_file(&path);
    }

    fn persist_shared_candidate_oci(
        root: &Path,
        owner_uid: u32,
        reader_gid: u32,
        candidate: &ReleaseBundleV1,
    ) {
        private_directory(root);
        private_directory(&root.join(candidate.project_id().as_str()));
        fs::set_permissions(root, fs::Permissions::from_mode(0o2750))
            .unwrap_or_else(|error| panic!("share OCI root: {error}"));
        fs::set_permissions(
            root.join(candidate.project_id().as_str()),
            fs::Permissions::from_mode(0o2750),
        )
        .unwrap_or_else(|error| panic!("share OCI project: {error}"));
        let source_path = root
            .parent()
            .unwrap_or_else(|| panic!("OCI root parent"))
            .join("candidate.oci.tar");
        fs::write(&source_path, b"fixture OCI archive")
            .unwrap_or_else(|error| panic!("write OCI fixture: {error}"));
        let source =
            File::open(&source_path).unwrap_or_else(|error| panic!("open OCI fixture: {error}"));
        OciArchivePublisherV1::open(root, owner_uid, reader_gid)
            .and_then(|publisher| publisher.publish(candidate, &source, 1_000))
            .unwrap_or_else(|error| panic!("publish OCI fixture: {error}"));
    }

    fn signed_candidate(
        candidate: &ReleaseBundleV1,
        rimg_policy_digest: &EvidenceDigest,
        signing_key: &SigningKey,
    ) -> BuildReleaseAttestationV1 {
        let (testing_artifacts, building_artifacts, preflight_artifacts) =
            crate::build_attestation::tests::phase_artifacts(candidate);
        BuildReleaseAttestationV1::issue(
            BuildReleaseAttestationInputV1 {
                key_id: "build-v1".to_owned(),
                key_epoch: 1,
                project_id: project(),
                source_head: GitCommitId::from_str("dddddddddddddddddddddddddddddddddddddddd")
                    .unwrap_or_else(|error| panic!("candidate commit: {error}")),
                source_sequence: 7,
                source_attestation_digest: digest("source attestation"),
                installed_policy: crate::build_attestation::tests::installed_policy(),
                installed_rimg_policy_digest: rimg_policy_digest.clone(),
                release_bundle_digest: candidate.digest().clone(),
                testing_artifacts,
                building_artifacts,
                preflight_artifacts,
                migration_plan_observation_digest: None,
                data_compatibility_observation_digest: digest("compatibility observation"),
                issued_at_ms: 1_000,
                expires_at_ms: 10_000,
            },
            signing_key,
        )
        .unwrap_or_else(|error| panic!("signed candidate: {error}"))
    }

    fn build_bootstrap_fixture() -> BootstrapDriverFixtureV1 {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let directory_metadata = fs::metadata(directory.path())
            .unwrap_or_else(|error| panic!("tempdir metadata: {error}"));
        let owner_uid = directory_metadata.uid();
        let reader_group_gid = directory_metadata.gid();
        assert_ne!(
            owner_uid, 0,
            "deploy builder fixture requires a non-root test uid"
        );
        let path = |name: &str| directory.path().join(name);
        let build_bundles = path("build-bundles");
        let build_attestations = path("build-attestations");
        let build_oci = path("build-oci");
        let root_bundles = path("root-bundles");
        let root_oci = path("root-oci");
        let releases = path("releases");
        let disk_path = path("disk");
        for private in [
            &build_bundles,
            &build_attestations,
            &root_bundles,
            &root_oci,
            &releases,
            &disk_path,
        ] {
            private_directory(private);
        }
        let candidate = crate::build_attestation::tests::release_bundle();
        persist_shared_candidate_bundle(&build_bundles, owner_uid, &candidate);
        private_directory(&root_oci.join(candidate.project_id().as_str()));
        persist_shared_candidate_oci(&build_oci, owner_uid, reader_group_gid, &candidate);
        let rimg_policy = test_installed_rimg_policy();
        let signing_key = SigningKey::from_bytes(&[47; 32]);
        let policy = InstalledDeployMutationPolicyV1::new(InstalledDeployMutationPolicyInputV1 {
            project_id: project(),
            installed_policy: crate::build_attestation::tests::installed_policy(),
            installed_rimg_policy_digest: rimg_policy.digest().clone(),
            build_uid: owner_uid,
            build_reader_gid: reader_group_gid,
            build_key_id: "build-v1".to_owned(),
            build_key_epoch: 1,
            build_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            chronyc_sha256: digest("chronyc"),
            backup_staging_bytes: 1,
            build_peak_bytes: 1,
            registry_peak_bytes: 1,
            last_known_good_bytes: 1,
            projected_hot_store_growth_bytes: 1,
            intent_ttl_ms: 30_000,
        })
        .unwrap_or_else(|error| panic!("deploy policy: {error}"));
        let initial_state = InstalledReleaseStateV1::new(InstalledReleaseStateInputV1 {
            project_id: project(),
            installed_policy: policy.installed_policy.clone(),
            installed_rimg_policy_digest: rimg_policy.digest().clone(),
            generation: 1,
            current_release_bundle_digest: None,
            last_known_good_release_bundle_digest: None,
            updated_at_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("initial release state: {error}"));
        let attestation = signed_candidate(&candidate, rimg_policy.digest(), &signing_key);
        let deploy_policy_path = path("deploy-policy.jcs");
        let rimg_policy_path = path("rimg-policy.jcs");
        let state_path = releases.join("rimg.jcs");
        write_private(
            &deploy_policy_path,
            &serde_jcs::to_vec(&policy)
                .unwrap_or_else(|error| panic!("deploy policy JCS: {error}")),
        );
        write_private(
            &rimg_policy_path,
            &serde_jcs::to_vec(&rimg_policy)
                .unwrap_or_else(|error| panic!("rimg policy JCS: {error}")),
        );
        write_private(
            &state_path,
            &initial_state
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("release state JCS: {error}")),
        );
        persist_shared_candidate_attestation(&build_attestations, &attestation);
        finish_bootstrap_fixture(
            directory,
            &policy,
            initial_state,
            candidate,
            &attestation,
            deploy_policy_path,
            rimg_policy_path,
            build_bundles,
            build_attestations,
            build_oci,
            root_bundles,
            root_oci,
            state_path,
            disk_path,
            owner_uid,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_bootstrap_fixture(
        directory: TempDir,
        policy: &InstalledDeployMutationPolicyV1,
        initial_state: InstalledReleaseStateV1,
        candidate: ReleaseBundleV1,
        attestation: &BuildReleaseAttestationV1,
        deploy_policy_path: PathBuf,
        rimg_policy_path: PathBuf,
        build_bundles: PathBuf,
        build_attestations: PathBuf,
        build_oci: PathBuf,
        root_bundles: PathBuf,
        root_oci: PathBuf,
        state_path: PathBuf,
        disk_path: PathBuf,
        uid: u32,
    ) -> BootstrapDriverFixtureV1 {
        let security_path = directory.path().join("security.sqlite");
        let security = SecurityStore::open(&security_path)
            .unwrap_or_else(|error| panic!("security store: {error}"));
        let model = DeterministicModelEffects::default();
        let accepted = AcceptedMutationV1 {
            release_bundle_digest: Some(candidate.digest().clone()),
            build_attestation_digest: Some(attestation.payload_digest.clone()),
            target_commit: Some(attestation.source_head.clone()),
            source_attestation_digest: Some(attestation.source_attestation_digest.clone()),
            source_sequence: Some(attestation.source_sequence),
            installed_policy_digest: policy.document_digest.clone(),
            effective_release_class: Some(ReleaseClass::CodeOnlyCompatible),
            proposed_release_class: Some(ReleaseClass::CodeOnlyCompatible),
            intent_expires_at_ms: 100_000,
            grant_expires_at_ms: 100_000,
            accepted_at_ms: 1_200,
            ..accepted(policy)
        };
        model
            .set_phase_artifacts(
                accepted.attempt_id,
                OperationPhase::Deploying,
                PhaseArtifacts {
                    deployment_plan_digest: Some(candidate.deployment_plan_digest().clone()),
                    release_bundle_digest: Some(candidate.digest().clone()),
                    ..PhaseArtifacts::default()
                },
            )
            .unwrap_or_else(|error| panic!("deploy artifacts: {error}"));
        for (phase, label) in [
            (OperationPhase::HealthChecking, "readiness evidence"),
            (OperationPhase::Soaking, "soak evidence"),
        ] {
            model
                .set_phase_artifacts(
                    accepted.attempt_id,
                    phase,
                    PhaseArtifacts {
                        health_evidence_digest: Some(digest(label)),
                        ..PhaseArtifacts::default()
                    },
                )
                .unwrap_or_else(|error| panic!("{label}: {error}"));
        }
        let effects = BoundDeployEffectsV1 {
            security: security.clone(),
            model,
        };
        BootstrapDriverFixtureV1 {
            resolver: InstalledDeployIntentResolverV1::bound(
                FixedDeploySourceV1,
                deploy_policy_path,
                rimg_policy_path,
                directory.path().join("unused-source-policy.jcs"),
                build_bundles,
                build_attestations,
                build_oci,
                root_bundles,
                root_oci,
                state_path.clone(),
                uid,
            ),
            disk: InstalledBackupDiskProbeV1::bound(disk_path, uid),
            effects,
            accepted,
            security_path,
            state_path,
            initial_state,
            candidate,
            _directory: directory,
        }
    }

    #[test]
    fn bootstrap_handoff_requires_exact_candidate_source_policy_and_release_shape() {
        let policy = mutation_policy();
        let exact = accepted(&policy);
        assert_eq!(
            validate_accepted_deploy(&exact, &policy)
                .unwrap_or_else(|error| panic!("exact accepted binding: {error}")),
            exact
                .target_commit
                .as_ref()
                .unwrap_or_else(|| panic!("target"))
        );

        for substituted in [
            AcceptedMutationV1 {
                build_attestation_digest: None,
                ..exact.clone()
            },
            AcceptedMutationV1 {
                effective_release_class: Some(ReleaseClass::StatefulCompatible),
                ..exact.clone()
            },
            AcceptedMutationV1 {
                installed_policy_digest: digest("other deploy policy"),
                ..exact
            },
        ] {
            assert!(matches!(
                validate_accepted_deploy(&substituted, &policy),
                Err(DeployDriverError::AcceptedMutationBinding)
            ));
        }
    }

    #[test]
    fn bootstrap_worker_recovers_terminal_receipts_before_release_state_commit_without_reapply() {
        let fixture = build_bootstrap_fixture();
        let orphan = fixture
            .state_path
            .parent()
            .unwrap_or_else(|| panic!("release-state parent"))
            .join(format!(".rimg.{}.tmp", Uuid::from_u128(900)));
        write_private(&orphan, b"interrupted release-state publication");
        let first_security = fixture.effects.security.clone();
        let first_driver = fixture.driver(first_security);

        let completed = first_driver
            .drive_accepted(&fixture.accepted, 1_500)
            .unwrap_or_else(|error| panic!("initial bootstrap: {error}"));

        assert_eq!(completed.state.result, OperationResult::Succeeded);
        assert!(!orphan.exists());
        assert_eq!(
            completed.evidence.health_evidence_digest,
            Some(digest("soak evidence"))
        );
        let committed = fixture
            .resolver
            .load_release_state()
            .unwrap_or_else(|error| panic!("committed release state: {error}"));
        assert_eq!(
            committed.current_release_bundle_digest.as_ref(),
            Some(fixture.candidate.digest())
        );
        assert_privileged_application_counts(&fixture, 1);

        write_private(
            &fixture.state_path,
            &fixture
                .initial_state
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("reset state JCS: {error}")),
        );
        let recovery_security = SecurityStore::open(&fixture.security_path)
            .unwrap_or_else(|error| panic!("reopen security store: {error}"));
        let recovery_driver = fixture.driver(recovery_security);
        assert!(
            !recovery_driver
                .has_committed_terminal(&fixture.accepted)
                .unwrap_or_else(|error| panic!("pre-recovery terminal check: {error}"))
        );

        let recovered = recovery_driver
            .drive_accepted(&fixture.accepted, 1_600)
            .unwrap_or_else(|error| panic!("recover release state commit: {error}"));

        assert_eq!(recovered.state.result, OperationResult::Succeeded);
        assert_privileged_application_counts(&fixture, 1);
        assert!(
            recovery_driver
                .has_committed_terminal(&fixture.accepted)
                .unwrap_or_else(|error| panic!("post-recovery terminal check: {error}"))
        );
        recovery_driver
            .drive_accepted(&fixture.accepted, 1_700)
            .unwrap_or_else(|error| panic!("terminal replay: {error}"));
        assert_privileged_application_counts(&fixture, 1);
    }

    #[test]
    fn installed_release_commit_advances_current_and_preserves_previous_as_last_known_good() {
        let fixture = build_bootstrap_fixture();
        let previous = digest("previous installed release");
        let expected = InstalledReleaseStateV1::new(InstalledReleaseStateInputV1 {
            project_id: fixture.initial_state.project_id.clone(),
            installed_policy: fixture.initial_state.installed_policy.clone(),
            installed_rimg_policy_digest: fixture
                .initial_state
                .installed_rimg_policy_digest
                .clone(),
            generation: 7,
            current_release_bundle_digest: Some(previous.clone()),
            last_known_good_release_bundle_digest: Some(digest("older release")),
            updated_at_ms: 2_000,
        })
        .unwrap_or_else(|error| panic!("installed release state: {error}"));
        write_private(
            &fixture.state_path,
            &expected
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("release state JCS: {error}")),
        );

        let committed = fixture
            .resolver
            .commit_installed_release(&expected, &fixture.candidate, 2_500)
            .unwrap_or_else(|error| panic!("commit installed release: {error}"));

        assert_eq!(committed.generation, 8);
        assert_eq!(
            committed.current_release_bundle_digest.as_ref(),
            Some(fixture.candidate.digest())
        );
        assert_eq!(
            committed.last_known_good_release_bundle_digest,
            Some(previous)
        );
        assert!(matches!(
            fixture
                .resolver
                .commit_installed_release(&expected, &fixture.candidate, 2_600),
            Err(crate::installed_deploy::InstalledDeployError::ReleaseStateConflict)
        ));
    }

    #[test]
    fn rollback_recovery_intent_uses_rollback_contract_without_changing_authority() {
        let policy = mutation_policy();
        let candidate = crate::build_attestation::tests::release_bundle();
        let accepted = AcceptedMutationV1 {
            release_bundle_digest: Some(candidate.digest().clone()),
            previous_release_bundle_digest: Some(digest("previous release")),
            ..accepted(&policy)
        };
        let mut operation = reconstruct_deploy_operation(&accepted, &policy, &candidate, None);
        operation.state.phase = OperationPhase::Rollback;
        operation.evidence.recovery_mode = Some(OperationRecoveryMode::Rollback);
        let authorization = digest("original deploy authorization");

        let intent = PhaseIntent::from_operation(&operation, authorization.clone())
            .unwrap_or_else(|error| panic!("rollback phase intent: {error}"));

        assert_eq!(intent.branch, ExecutorPhaseBranch::RollbackRecovery);
        assert_eq!(intent.payload.operation_kind, OperationKind::CodeRollback);
        assert_eq!(intent.payload.release_class, Some(ReleaseClass::Rollback));
        assert_eq!(intent.payload.executor_authorization_digest, authorization);
        assert_eq!(
            intent.payload.release_bundle_digest.as_ref(),
            Some(candidate.digest())
        );
        assert_eq!(
            intent.payload.previous_release_bundle_digest,
            accepted.previous_release_bundle_digest
        );
    }

    fn assert_privileged_application_counts(fixture: &BootstrapDriverFixtureV1, expected: u32) {
        for phase in [
            OperationPhase::Deploying,
            OperationPhase::HealthChecking,
            OperationPhase::Soaking,
        ] {
            assert_eq!(
                fixture
                    .effects
                    .model
                    .phase_application_attempts(fixture.accepted.attempt_id, phase)
                    .unwrap_or_else(|error| panic!("{phase:?} attempts: {error}")),
                expected,
                "unexpected {phase:?} application count"
            );
        }
    }
}
