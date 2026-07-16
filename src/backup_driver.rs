use std::{
    fmt,
    fs::{self, File},
    os::unix::fs::MetadataExt as _,
    path::PathBuf,
    sync::Arc,
};

use uuid::Uuid;

use crate::{
    backup::{
        AuthorizedBackupSpecInputV1, AuthorizedBackupSpecV1, BackupCapturePurposeV1,
        BackupSnapshotKindV1,
    },
    build::ResourceReservationEvidenceV1,
    domain::{
        AuthorizedPhaseSpecDigestV1, BlockingReason, DiskAvailabilityObservation, DiskReservation,
        EvidenceDigest, ExecutorPhaseBranch, OperationActor, OperationEvidence, OperationKind,
        OperationPhase, OperationRecord, OperationResult, OperationState, OperationTransition,
        PhaseArtifacts, PhaseReceipt,
    },
    executor::{
        DiskSpaceProbe, DurableExecutor, EffectObservation, ExternalEffectError, ExternalEffects,
        FenceExecutionError, PhaseEffectEvidence, PhaseExecutionError, PhaseIntent,
        PhaseOperationIdentityLeaseV1, executor_authorization_digest,
    },
    installed_intent_resolver::{
        InstalledBackupMutationPolicyV1, InstalledIntentResolverError,
        load_installed_backup_mutation_policy,
    },
    installed_policy::{InstalledPolicyLoadError, load_installed_rimg_policy},
    mutation_admission::{
        ExecuteMutationGrantV1, MutationAcceptanceV1, MutationControlFailureV1, MutationControlV1,
        ObserveMutationStatusV1, PrepareMutationIntentV1,
    },
    phase6::{
        AuthorizedPhasePrerequisitesV1, AuthorizedPhaseSpecInputV1, AuthorizedPhaseSpecV1,
        InstalledRimgPolicyV1, Phase6ContractError,
    },
    store::{
        AcceptedMutationV1, AuthorizedPhaseSpecBinding, ExecutorAuthorization, ExecutorPhasePlan,
        FenceLease, FenceObservation, PhaseIntentRequest, SecurityStore, StoreError,
    },
};
use tokio::sync::Notify;

pub const INSTALLED_BACKUP_STAGING_PATH: &str = "/var/lib/rdashboard-executor/backups";
pub const ROOT_SECURITY_STORE_PATH: &str = "/var/lib/rdashboard-executor/security.sqlite";

#[derive(Debug)]
pub struct BackupJobQueueControlV1<C> {
    admission: C,
    wake: Arc<Notify>,
}

impl<C> BackupJobQueueControlV1<C> {
    pub const fn new(admission: C, wake: Arc<Notify>) -> Self {
        Self { admission, wake }
    }
}

impl<C: MutationControlV1> MutationControlV1 for BackupJobQueueControlV1<C> {
    fn prepare_intent(
        &self,
        request: &PrepareMutationIntentV1,
        now_ms: i64,
    ) -> Result<String, MutationControlFailureV1> {
        self.admission.prepare_intent(request, now_ms)
    }

    fn accept_grant(
        &self,
        request: &ExecuteMutationGrantV1,
        now_ms: i64,
    ) -> Result<MutationAcceptanceV1, MutationControlFailureV1> {
        let acceptance = self.admission.accept_grant(request, now_ms)?;
        self.wake.notify_one();
        Ok(acceptance)
    }

    fn mutation_status(
        &self,
        request: &ObserveMutationStatusV1,
    ) -> Result<crate::domain::MutationStatusV1, MutationControlFailureV1> {
        self.admission.mutation_status(request)
    }
}

pub trait AcceptedBackupJobDriverV1: Send + Sync + 'static {
    fn drive(&self, accepted: &AcceptedMutationV1) -> Result<OperationRecord, BackupDriverError>;
}

#[derive(Debug)]
pub struct BackupJobFailureV1 {
    pub intent_id: Uuid,
    pub attempt_id: Uuid,
    pub error: BackupDriverError,
}

pub fn drive_pending_backup_jobs(
    security: &SecurityStore,
    driver: &dyn AcceptedBackupJobDriverV1,
) -> Result<Vec<BackupJobFailureV1>, StoreError> {
    drive_pending_backup_jobs_until(security, driver, || false)
}

pub fn drive_pending_backup_jobs_until<F>(
    security: &SecurityStore,
    driver: &dyn AcceptedBackupJobDriverV1,
    mut cancelled: F,
) -> Result<Vec<BackupJobFailureV1>, StoreError>
where
    F: FnMut() -> bool,
{
    let mut failures = Vec::new();
    for accepted in security.accepted_mutations()? {
        if cancelled() {
            break;
        }
        if accepted.operation_kind != OperationKind::BackupOnly
            || security
                .phase_receipt(accepted.attempt_id, OperationPhase::BackingUp)?
                .is_some()
        {
            continue;
        }
        if let Err(error) = driver.drive(&accepted) {
            failures.push(BackupJobFailureV1 {
                intent_id: accepted.intent_id,
                attempt_id: accepted.attempt_id,
                error,
            });
        }
    }
    Ok(failures)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupDriverPoliciesV1 {
    pub mutation: InstalledBackupMutationPolicyV1,
    pub rimg: InstalledRimgPolicyV1,
}

impl BackupDriverPoliciesV1 {
    fn validate(&self) -> Result<(), BackupDriverError> {
        self.mutation.validate_installed_rimg_policy(&self.rimg)?;
        Ok(())
    }
}

pub trait BackupDriverPolicySourceV1: fmt::Debug + Send + Sync + 'static {
    fn load(&self) -> Result<BackupDriverPoliciesV1, BackupDriverPolicySourceErrorV1>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InstalledBackupDriverPolicySourceV1;

impl BackupDriverPolicySourceV1 for InstalledBackupDriverPolicySourceV1 {
    fn load(&self) -> Result<BackupDriverPoliciesV1, BackupDriverPolicySourceErrorV1> {
        Ok(BackupDriverPoliciesV1 {
            mutation: load_installed_backup_mutation_policy()?,
            rimg: load_installed_rimg_policy()?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BackupDriverPolicySourceErrorV1 {
    #[error(transparent)]
    Mutation(#[from] InstalledIntentResolverError),
    #[error(transparent)]
    Rimg(#[from] InstalledPolicyLoadError),
}

pub trait BackupDiskProbeV1: DiskSpaceProbe + Clone {
    fn reservation(
        &self,
        policy: &InstalledBackupMutationPolicyV1,
        now_ms: i64,
    ) -> Result<DiskReservation, BackupDiskProbeErrorV1>;
}

#[derive(Clone, Debug)]
pub struct InstalledBackupDiskProbeV1 {
    path: PathBuf,
    required_uid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DiskReservationRequirementsV1 {
    pub backup_staging: u64,
    pub build_peak: u64,
    pub registry_peak: u64,
    pub last_known_good: u64,
    pub projected_hot_store_growth: u64,
}

impl InstalledBackupDiskProbeV1 {
    pub fn installed() -> Self {
        Self {
            path: PathBuf::from(INSTALLED_BACKUP_STAGING_PATH),
            required_uid: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn bound(path: PathBuf, required_uid: u32) -> Self {
        Self { path, required_uid }
    }

    fn measure(
        &self,
        observed_at_ms: i64,
    ) -> Result<FilesystemMeasurementV1, BackupDiskProbeErrorV1> {
        if observed_at_ms < 0 {
            return Err(BackupDiskProbeErrorV1::InvalidObservationTime);
        }
        let path_metadata = fs::symlink_metadata(&self.path)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_dir()
            || path_metadata.uid() != self.required_uid
            || path_metadata.mode() & 0o077 != 0
        {
            return Err(BackupDiskProbeErrorV1::UnsafeStagingDirectory);
        }
        let directory = File::open(&self.path)?;
        let opened_metadata = directory.metadata()?;
        let total_bytes = fs2::total_space(&self.path)?;
        let available_bytes = fs2::available_space(&self.path)?;
        let final_metadata = fs::symlink_metadata(&self.path)?;
        if opened_metadata.dev() != path_metadata.dev()
            || opened_metadata.ino() != path_metadata.ino()
            || final_metadata.dev() != path_metadata.dev()
            || final_metadata.ino() != path_metadata.ino()
            || available_bytes > total_bytes
        {
            return Err(BackupDiskProbeErrorV1::UnstableMeasurement);
        }
        let identity = EvidenceDigest::sha256(serde_jcs::to_vec(&(
            "rdashboard.filesystem-identity.v1",
            opened_metadata.dev(),
        ))?);
        Ok(FilesystemMeasurementV1 {
            identity,
            total_bytes,
            available_bytes,
            observed_at_ms,
        })
    }

    pub(crate) fn reservation_with_requirements(
        &self,
        requirements: DiskReservationRequirementsV1,
        now_ms: i64,
    ) -> Result<DiskReservation, BackupDiskProbeErrorV1> {
        let measurement = self.measure(now_ms)?;
        Ok(DiskReservation {
            filesystem_identity: measurement.identity,
            filesystem_total_bytes: measurement.total_bytes,
            filesystem_available_bytes: measurement.available_bytes,
            observed_at_ms: measurement.observed_at_ms,
            backup_staging_bytes: requirements.backup_staging,
            build_peak_bytes: requirements.build_peak,
            registry_peak_bytes: requirements.registry_peak,
            last_known_good_bytes: requirements.last_known_good,
            projected_hot_store_growth_bytes: requirements.projected_hot_store_growth,
        })
    }
}

impl DiskSpaceProbe for InstalledBackupDiskProbeV1 {
    fn observe(
        &self,
        _project_id: &crate::domain::ProjectId,
        now_ms: i64,
    ) -> Result<DiskAvailabilityObservation, StoreError> {
        self.measure(now_ms)
            .map(|measurement| DiskAvailabilityObservation {
                filesystem_identity: measurement.identity,
                available_bytes: measurement.available_bytes,
                observed_at_ms: measurement.observed_at_ms,
            })
            .map_err(|_| StoreError::DiskObservationUnavailable)
    }
}

impl BackupDiskProbeV1 for InstalledBackupDiskProbeV1 {
    fn reservation(
        &self,
        policy: &InstalledBackupMutationPolicyV1,
        now_ms: i64,
    ) -> Result<DiskReservation, BackupDiskProbeErrorV1> {
        self.reservation_with_requirements(
            DiskReservationRequirementsV1 {
                backup_staging: policy.backup_staging_bytes,
                build_peak: 0,
                registry_peak: 0,
                last_known_good: 0,
                projected_hot_store_growth: policy.projected_hot_store_growth_bytes,
            },
            now_ms,
        )
    }
}

#[derive(Debug)]
struct FilesystemMeasurementV1 {
    identity: EvidenceDigest,
    total_bytes: u64,
    available_bytes: u64,
    observed_at_ms: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum BackupDiskProbeErrorV1 {
    #[error("backup disk observation time is invalid")]
    InvalidObservationTime,
    #[error("backup staging directory is not a private stable directory")]
    UnsafeStagingDirectory,
    #[error("backup filesystem changed or reported inconsistent capacity during observation")]
    UnstableMeasurement,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug)]
struct BackupOnlyEffectsV1<E> {
    security: SecurityStore,
    delegate: E,
}

impl<E: ExternalEffects> BackupOnlyEffectsV1<E> {
    fn non_privileged_observation(
        &self,
        intent: &PhaseIntent,
    ) -> Result<EffectObservation, ExternalEffectError> {
        let artifacts = match intent.phase {
            OperationPhase::Queued => PhaseArtifacts::default(),
            OperationPhase::Preflight => {
                let authorization = self
                    .security
                    .executor_authorization(intent.attempt_id)
                    .map_err(|_| ExternalEffectError::ConflictingState)?
                    .ok_or(ExternalEffectError::ConflictingState)?;
                let claim = authorization
                    .disk_reservation
                    .ok_or(ExternalEffectError::ConflictingState)?;
                PhaseArtifacts {
                    resource_reservation_digest: Some(claim.reservation_digest),
                    ..PhaseArtifacts::default()
                }
            }
            _ => return Err(ExternalEffectError::ConflictingState),
        };
        let observation_digest = EvidenceDigest::sha256(
            serde_jcs::to_vec(&(
                "rdashboard.backup-driver-non-privileged-observation.v1",
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

    fn bind_backup_observation(
        &self,
        intent: &PhaseIntent,
        observation: EffectObservation,
    ) -> Result<EffectObservation, ExternalEffectError> {
        let EffectObservation::Applied(evidence) = observation else {
            return Ok(EffectObservation::Absent);
        };
        let record = self
            .security
            .authorized_phase_spec_in_branch(
                intent.attempt_id,
                OperationPhase::BackingUp,
                ExecutorPhaseBranch::Primary,
            )
            .map_err(|_| ExternalEffectError::ConflictingState)?
            .ok_or(ExternalEffectError::ConflictingState)?;
        let spec = AuthorizedPhaseSpecV1::decode_canonical(&record.canonical_json)
            .map_err(|_| ExternalEffectError::ConflictingState)?;
        let artifacts = spec
            .bind_artifacts(evidence.artifacts)
            .map_err(|_| ExternalEffectError::ConflictingState)?;
        let observation_digest = EvidenceDigest::sha256(
            serde_jcs::to_vec(&(
                "rdashboard.backup-driver-privileged-observation.v1",
                &intent.digest,
                &evidence.observation_digest,
                &artifacts,
            ))
            .map_err(|_| ExternalEffectError::ConflictingState)?,
        );
        Ok(EffectObservation::Applied(Box::new(PhaseEffectEvidence {
            intent_digest: evidence.intent_digest,
            observation_digest,
            artifacts,
        })))
    }
}

impl<E: ExternalEffects> ExternalEffects for BackupOnlyEffectsV1<E> {
    fn observe_phase(
        &self,
        intent: &PhaseIntent,
    ) -> Result<EffectObservation, ExternalEffectError> {
        match intent.phase {
            OperationPhase::Queued | OperationPhase::Preflight => {
                self.non_privileged_observation(intent)
            }
            OperationPhase::BackingUp => {
                let observation = self.delegate.observe_phase(intent)?;
                self.bind_backup_observation(intent, observation)
            }
            _ => Err(ExternalEffectError::ConflictingState),
        }
    }

    fn apply_phase(&self, intent: &PhaseIntent) -> Result<(), ExternalEffectError> {
        match intent.phase {
            OperationPhase::Queued | OperationPhase::Preflight => Ok(()),
            OperationPhase::BackingUp => self.delegate.apply_phase(intent),
            _ => Err(ExternalEffectError::ConflictingState),
        }
    }

    fn observe_phase_with_operation_identity(
        &self,
        intent: &PhaseIntent,
        operation_identity: Option<&PhaseOperationIdentityLeaseV1>,
    ) -> Result<EffectObservation, ExternalEffectError> {
        match intent.phase {
            OperationPhase::Queued | OperationPhase::Preflight => {
                self.non_privileged_observation(intent)
            }
            OperationPhase::BackingUp => {
                let observation = self
                    .delegate
                    .observe_phase_with_operation_identity(intent, operation_identity)?;
                self.bind_backup_observation(intent, observation)
            }
            _ => Err(ExternalEffectError::ConflictingState),
        }
    }

    fn apply_phase_with_operation_identity(
        &self,
        intent: &PhaseIntent,
        operation_identity: Option<&PhaseOperationIdentityLeaseV1>,
    ) -> Result<(), ExternalEffectError> {
        match intent.phase {
            OperationPhase::Queued | OperationPhase::Preflight => Ok(()),
            OperationPhase::BackingUp => self
                .delegate
                .apply_phase_with_operation_identity(intent, operation_identity),
            _ => Err(ExternalEffectError::ConflictingState),
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
pub struct BackupOperationDriverV1<P, D, E> {
    security: SecurityStore,
    policies: P,
    disk: D,
    effects: E,
}

impl<P, D, E> BackupOperationDriverV1<P, D, E>
where
    P: BackupDriverPolicySourceV1,
    D: BackupDiskProbeV1,
    E: ExternalEffects + Clone,
{
    pub const fn new(security: SecurityStore, policies: P, disk: D, effects: E) -> Self {
        Self {
            security,
            policies,
            disk,
            effects,
        }
    }

    pub fn drive_accepted(
        &self,
        accepted: &AcceptedMutationV1,
        now_ms: i64,
    ) -> Result<OperationRecord, BackupDriverError> {
        if now_ms < 0 {
            return Err(BackupDriverError::InvalidTime);
        }
        let policies = self.policies.load()?;
        policies.validate()?;
        let mut operation = self.reconstruct_operation(accepted, &policies)?;
        let authorization_digest = executor_authorization_digest(&operation)?;
        self.ensure_authorization(
            accepted,
            &policies.mutation,
            &operation,
            &authorization_digest,
            now_ms,
        )?;

        let executor = DurableExecutor::new(
            self.security.clone(),
            BackupOnlyEffectsV1 {
                security: self.security.clone(),
                delegate: self.effects.clone(),
            },
        )
        .with_disk_space_probe(Arc::new(self.disk.clone()));
        executor.recover_security_state(std::slice::from_ref(&operation.project_id), now_ms)?;

        while operation.state.result == OperationResult::Running {
            if operation.state.phase == OperationPhase::BackingUp {
                self.ensure_backup_spec(&operation, &policies, &authorization_digest, now_ms)?;
            }
            let receipt = executor.execute_phase(&operation, None, now_ms)?;
            project_backup_receipt(&mut operation, &receipt)?;
        }
        executor.cleanup_terminal_resources(&operation, now_ms)?;
        Ok(operation)
    }

    fn reconstruct_operation(
        &self,
        accepted: &AcceptedMutationV1,
        policies: &BackupDriverPoliciesV1,
    ) -> Result<OperationRecord, BackupDriverError> {
        if accepted.operation_kind != OperationKind::BackupOnly
            || accepted.target_commit.is_some()
            || accepted.proposed_release_class.is_some()
            || accepted.effective_release_class.is_some()
            || accepted.source_attestation_digest.is_some()
            || accepted.source_sequence.is_some()
            || accepted.release_bundle_digest.is_some()
            || accepted.build_attestation_digest.is_some()
            || accepted.migration_id.is_some()
            || accepted.previous_release_bundle_digest.is_some()
            || accepted.project_id != policies.mutation.project_id
            || accepted.installed_policy_digest != policies.mutation.document_digest
        {
            return Err(BackupDriverError::AcceptedMutationBinding);
        }
        let mut operation = OperationRecord {
            operation_id: accepted.intent_id,
            request_id: accepted.request_id,
            attempt_id: accepted.attempt_id,
            attempt_number: 1,
            project_id: accepted.project_id.clone(),
            operation_kind: OperationKind::BackupOnly,
            target_commit: None,
            release_class: None,
            state: OperationState {
                phase: OperationPhase::Queued,
                result: OperationResult::Running,
                blocking_reason: BlockingReason::None,
            },
            actor: OperationActor::Interactive {
                user_id: accepted.actor_id,
            },
            evidence: OperationEvidence {
                installed_policy: Some(policies.mutation.installed_policy.clone()),
                action_grant_digest: Some(accepted.action_grant_digest.clone()),
                ..OperationEvidence::default()
            },
            failure_capsule: None,
            created_at_ms: accepted.accepted_at_ms,
            updated_at_ms: accepted.accepted_at_ms,
        };
        let phases = [
            OperationPhase::Queued,
            OperationPhase::Preflight,
            OperationPhase::BackingUp,
        ];
        let mut missing = false;
        for phase in phases {
            match self.security.phase_receipt(accepted.attempt_id, phase)? {
                Some(receipt) if !missing => project_backup_receipt(&mut operation, &receipt)?,
                Some(_) => return Err(BackupDriverError::ReceiptOrder),
                None => missing = true,
            }
        }
        Ok(operation)
    }

    fn ensure_authorization(
        &self,
        accepted: &AcceptedMutationV1,
        policy: &InstalledBackupMutationPolicyV1,
        operation: &OperationRecord,
        authorization_digest: &EvidenceDigest,
        now_ms: i64,
    ) -> Result<(), BackupDriverError> {
        let expires_at_ms = accepted
            .intent_expires_at_ms
            .min(accepted.grant_expires_at_ms);
        if let Some(existing) = self.security.executor_authorization(accepted.attempt_id)? {
            if existing.authorization_id != accepted.action_grant_nonce
                || existing.digest != *authorization_digest
                || existing.attempt_id != accepted.attempt_id
                || existing.project_id != operation.project_id
                || existing.expires_at_ms != expires_at_ms
                || existing.disk_reservation.is_none()
            {
                return Err(BackupDriverError::AuthorizationBinding);
            }
            return Ok(());
        }
        let reservation = self.disk.reservation(policy, now_ms)?;
        let evidence =
            ResourceReservationEvidenceV1::reserve(authorization_digest.clone(), reservation)?;
        self.security.authorize_attempt(
            &ExecutorAuthorization {
                authorization_id: accepted.action_grant_nonce,
                digest: authorization_digest.clone(),
                attempt_id: accepted.attempt_id,
                project_id: operation.project_id.clone(),
                expires_at_ms,
                disk_reservation: Some(evidence.authorization()),
            },
            accepted.accepted_at_ms,
        )?;
        Ok(())
    }

    fn ensure_backup_spec(
        &self,
        operation: &OperationRecord,
        policies: &BackupDriverPoliciesV1,
        authorization_digest: &EvidenceDigest,
        now_ms: i64,
    ) -> Result<(), BackupDriverError> {
        let intent = PhaseIntent::from_operation(operation, authorization_digest.clone())?;
        let phase_plan = operation
            .operation_kind
            .required_phases(operation.release_class)
            .map_err(StoreError::from)?;
        self.security.begin_phase_intent(PhaseIntentRequest {
            attempt_id: operation.attempt_id,
            project_id: &operation.project_id,
            phase: OperationPhase::BackingUp,
            branch: ExecutorPhaseBranch::Primary,
            phase_plan: ExecutorPhasePlan::new(phase_plan, false),
            intent_digest: &intent.digest,
            authorization_digest,
            started_at_ms: now_ms,
        })?;
        if let Some(record) = self.security.authorized_phase_spec_in_branch(
            operation.attempt_id,
            OperationPhase::BackingUp,
            ExecutorPhaseBranch::Primary,
        )? {
            let spec = AuthorizedPhaseSpecV1::decode_canonical(&record.canonical_json)?;
            let backup = spec
                .backup
                .clone()
                .ok_or(BackupDriverError::BackupSpecBinding)?;
            let expected = AuthorizedPhaseSpecV1::resolve(AuthorizedPhaseSpecInputV1 {
                intent: &intent,
                policy: &policies.rimg,
                classification: None,
                backup: Some(backup),
                prerequisites: AuthorizedPhasePrerequisitesV1::default(),
            })?;
            if spec != expected
                || spec.phase != OperationPhase::BackingUp
                || spec.branch != ExecutorPhaseBranch::Primary
                || spec.backup.as_ref().is_none_or(|backup| {
                    backup.capture_purpose != BackupCapturePurposeV1::Scheduled
                        || backup.unit.unit_digest != policies.mutation.backup_unit_digest
                        || backup.recipient_fingerprint != policies.mutation.recipient_fingerprint
                })
            {
                return Err(BackupDriverError::BackupSpecBinding);
            }
            return Ok(());
        }

        let unit = policies
            .rimg
            .backup_unit_by_digest(&policies.mutation.backup_unit_digest)
            .cloned()
            .ok_or(BackupDriverError::BackupSpecBinding)?;
        let timeout = i64::try_from(policies.rimg.timeouts().backup_ms)
            .map_err(|_| BackupDriverError::BackupDeadline)?;
        let capture_deadline_ms = now_ms
            .checked_add(timeout)
            .ok_or(BackupDriverError::BackupDeadline)?;
        let backup = AuthorizedBackupSpecV1::new(AuthorizedBackupSpecInputV1 {
            attempt_id: operation.attempt_id,
            project_id: operation.project_id.clone(),
            installed_policy: policies.mutation.installed_policy.clone(),
            installed_rimg_policy_digest: policies.mutation.installed_rimg_policy_digest.clone(),
            phase_intent_digest: intent.digest.clone(),
            backup_set_id: derived_backup_id(operation.attempt_id, BACKUP_SET_MASK),
            backup_id: derived_backup_id(operation.attempt_id, BACKUP_ID_MASK),
            snapshot_kind: BackupSnapshotKindV1::Base,
            capture_purpose: BackupCapturePurposeV1::Scheduled,
            unit,
            recipient_fingerprint: policies.mutation.recipient_fingerprint.clone(),
            provider: policies.rimg.backup_provider(),
            provider_credential_version: policies.rimg.backup_provider_credential_version(),
            capture_deadline_ms,
            fencing_epoch: None,
            fence_receipt_digest: None,
        })?;
        let spec = AuthorizedPhaseSpecV1::resolve(AuthorizedPhaseSpecInputV1 {
            intent: &intent,
            policy: &policies.rimg,
            classification: None,
            backup: Some(backup),
            prerequisites: AuthorizedPhasePrerequisitesV1::default(),
        })?;
        let canonical = spec.canonical_bytes()?;
        self.security
            .bind_authorized_phase_spec(AuthorizedPhaseSpecBinding {
                attempt_id: operation.attempt_id,
                project_id: &operation.project_id,
                phase: OperationPhase::BackingUp,
                branch: ExecutorPhaseBranch::Primary,
                intent_digest: &intent.digest,
                spec_digest: &spec.spec_digest,
                canonical_json: &canonical,
                persisted_at_ms: now_ms,
            })?;
        Ok(())
    }
}

impl<P, D, E> AcceptedBackupJobDriverV1 for BackupOperationDriverV1<P, D, E>
where
    P: BackupDriverPolicySourceV1,
    D: BackupDiskProbeV1,
    E: ExternalEffects + Clone,
{
    fn drive(&self, accepted: &AcceptedMutationV1) -> Result<OperationRecord, BackupDriverError> {
        self.drive_accepted(accepted, crate::unix_time_ms()?)
    }
}

const BACKUP_SET_MASK: u128 = 0x1f4b_0a7e_7584_49c8_91f7_0908_960c_5bf3;
const BACKUP_ID_MASK: u128 = 0xc3aa_71d9_e3de_43ad_82ad_14c2_2f3b_928e;

fn derived_backup_id(attempt_id: Uuid, mask: u128) -> Uuid {
    let candidate = Uuid::from_u128(attempt_id.as_u128() ^ mask);
    if candidate.is_nil() {
        Uuid::from_u128(mask.rotate_left(17))
    } else {
        candidate
    }
}

fn project_backup_receipt(
    operation: &mut OperationRecord,
    receipt: &PhaseReceipt,
) -> Result<(), BackupDriverError> {
    if !receipt.has_valid_digest()?
        || receipt.attempt_id != operation.attempt_id
        || receipt.branch != ExecutorPhaseBranch::Primary
        || operation.state.result != OperationResult::Running
        || operation.state.phase != receipt.phase
    {
        return Err(BackupDriverError::ReceiptBinding);
    }
    receipt.artifacts.validate_for_phase(receipt.phase)?;
    merge_backup_driver_artifacts(&mut operation.evidence, &receipt.artifacts, receipt.phase)?;
    let next_state = match receipt.phase {
        OperationPhase::Queued => OperationState {
            phase: OperationPhase::Preflight,
            result: OperationResult::Running,
            blocking_reason: BlockingReason::None,
        },
        OperationPhase::Preflight => OperationState {
            phase: OperationPhase::BackingUp,
            result: OperationResult::Running,
            blocking_reason: BlockingReason::None,
        },
        OperationPhase::BackingUp => OperationState {
            phase: OperationPhase::BackingUp,
            result: OperationResult::Succeeded,
            blocking_reason: BlockingReason::None,
        },
        _ => return Err(BackupDriverError::ReceiptBinding),
    };
    let sequence = u32::try_from(operation.evidence.transitions.len())
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(BackupDriverError::TransitionOverflow)?;
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

fn merge_backup_driver_artifacts(
    evidence: &mut OperationEvidence,
    artifacts: &PhaseArtifacts,
    phase: OperationPhase,
) -> Result<(), BackupDriverError> {
    if let Some(spec_digest) = artifacts.authorized_phase_spec_digest.as_ref() {
        let binding = AuthorizedPhaseSpecDigestV1 {
            branch: ExecutorPhaseBranch::Primary,
            phase,
            spec_digest: spec_digest.clone(),
        };
        match evidence
            .authorized_phase_spec_digests
            .iter()
            .find(|entry| entry.phase == phase && entry.branch == ExecutorPhaseBranch::Primary)
        {
            Some(existing) if existing == &binding => {}
            Some(_) => return Err(BackupDriverError::ArtifactConflict),
            None => evidence.authorized_phase_spec_digests.push(binding),
        }
    }
    merge_optional(
        &mut evidence.resource_reservation_digest,
        artifacts.resource_reservation_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.backup_set_id,
        artifacts.backup_set_id.as_ref(),
    )?;
    merge_optional(&mut evidence.backup_id, artifacts.backup_id.as_ref())?;
    merge_optional(
        &mut evidence.base_backup_id,
        artifacts.base_backup_id.as_ref(),
    )?;
    merge_optional(
        &mut evidence.base_backup_manifest_digest,
        artifacts.base_backup_manifest_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.base_backup_evidence_digest,
        artifacts.base_backup_evidence_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.base_backup_offsite_evidence_digest,
        artifacts.base_backup_offsite_evidence_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.base_backup_verification_digest,
        artifacts.base_backup_verification_digest.as_ref(),
    )
}

fn merge_optional<T: Clone + Eq>(
    target: &mut Option<T>,
    incoming: Option<&T>,
) -> Result<(), BackupDriverError> {
    match (&*target, incoming) {
        (_, None) => Ok(()),
        (None, Some(value)) => {
            *target = Some(value.clone());
            Ok(())
        }
        (Some(current), Some(value)) if current == value => Ok(()),
        (Some(_), Some(_)) => Err(BackupDriverError::ArtifactConflict),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BackupDriverError {
    #[error("backup driver time is invalid")]
    InvalidTime,
    #[error("backup driver cannot read a valid Unix system clock: {0}")]
    Clock(#[from] std::time::SystemTimeError),
    #[error("accepted mutation is not bound to the installed backup policy")]
    AcceptedMutationBinding,
    #[error("persisted executor authorization conflicts with the accepted backup")]
    AuthorizationBinding,
    #[error("persisted backup receipts are not an ordered prefix")]
    ReceiptOrder,
    #[error("backup receipt does not match the reconstructed operation")]
    ReceiptBinding,
    #[error("backup receipt evidence conflicts with prior durable evidence")]
    ArtifactConflict,
    #[error("backup operation transition sequence overflowed")]
    TransitionOverflow,
    #[error("authorized backup phase specification is not bound to this operation")]
    BackupSpecBinding,
    #[error("authorized backup deadline is outside the supported range")]
    BackupDeadline,
    #[error(transparent)]
    PolicySource(#[from] BackupDriverPolicySourceErrorV1),
    #[error(transparent)]
    Policy(#[from] InstalledIntentResolverError),
    #[error(transparent)]
    Disk(#[from] BackupDiskProbeErrorV1),
    #[error(transparent)]
    Build(#[from] crate::build::BuildContractError),
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
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Artifact(#[from] crate::domain::ArtifactContractError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ControlRejectionCodeV1;

    #[derive(Debug)]
    struct FakeAdmission;

    impl MutationControlV1 for FakeAdmission {
        fn prepare_intent(
            &self,
            _request: &PrepareMutationIntentV1,
            _now_ms: i64,
        ) -> Result<String, MutationControlFailureV1> {
            Err(MutationControlFailureV1 {
                code: ControlRejectionCodeV1::MutationRejected,
                retryable: false,
            })
        }

        fn accept_grant(
            &self,
            request: &ExecuteMutationGrantV1,
            _now_ms: i64,
        ) -> Result<MutationAcceptanceV1, MutationControlFailureV1> {
            Ok(MutationAcceptanceV1 {
                intent_id: request.intent_id,
                attempt_id: request.attempt_id,
                replayed: false,
            })
        }

        fn mutation_status(
            &self,
            _request: &ObserveMutationStatusV1,
        ) -> Result<crate::domain::MutationStatusV1, MutationControlFailureV1> {
            Err(MutationControlFailureV1 {
                code: ControlRejectionCodeV1::MutationRejected,
                retryable: false,
            })
        }
    }

    #[tokio::test]
    async fn durable_acceptance_wakes_the_out_of_band_worker() {
        let wake = Arc::new(Notify::new());
        let control = BackupJobQueueControlV1::new(FakeAdmission, Arc::clone(&wake));
        let request = ExecuteMutationGrantV1 {
            intent_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            action_grant: "test grant".to_owned(),
        };
        let notified = wake.notified();
        let accepted = control
            .accept_grant(&request, 1)
            .unwrap_or_else(|failure| panic!("accept failed: {:?}", failure.code));
        assert_eq!(accepted.intent_id, request.intent_id);
        tokio::time::timeout(std::time::Duration::from_millis(10), notified)
            .await
            .unwrap_or_else(|_| panic!("worker was not notified"));
    }
}
