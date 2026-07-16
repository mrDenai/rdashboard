use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    BlockingReason, EvidenceDigest, FailureCapsule, GitCommitId, OperationPhase, OperationResult,
    ProjectId,
};

pub const FENCE_ACQUISITION_RECEIPT_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Deploy,
    CodeRollback,
    BackupOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationExecutionStateV1 {
    Accepted,
    Running,
    NeedsReconcile,
    Succeeded,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationStatusV1 {
    pub intent_id: Uuid,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub target_commit: Option<GitCommitId>,
    pub effective_release_class: Option<ReleaseClass>,
    pub state: MutationExecutionStateV1,
    pub current_phase: OperationPhase,
    pub completed_phases: Vec<OperationPhase>,
    pub accepted_at_ms: i64,
    pub updated_at_ms: i64,
}

impl OperationKind {
    pub const fn requires_commit(self) -> bool {
        matches!(self, Self::Deploy | Self::CodeRollback)
    }

    pub fn required_phases(
        self,
        release_class: Option<ReleaseClass>,
    ) -> Result<&'static [OperationPhase], OperationContractError> {
        match (self, release_class) {
            (
                Self::Deploy,
                Some(
                    class @ (ReleaseClass::CodeOnlyCompatible
                    | ReleaseClass::StatefulCompatible
                    | ReleaseClass::StatefulBreaking),
                ),
            ) => Ok(class.required_phases()),
            (Self::CodeRollback, Some(ReleaseClass::Rollback)) => Ok(ROLLBACK_PHASES),
            (Self::BackupOnly, None) => Ok(BACKUP_ONLY_PHASES),
            _ => Err(OperationContractError::ReleaseClassMismatch),
        }
    }

    pub fn permits_transition(
        self,
        release_class: Option<ReleaseClass>,
        current: OperationPhase,
        next: OperationPhase,
    ) -> Result<bool, OperationContractError> {
        if next == OperationPhase::Reconciliation {
            return Ok(true);
        }
        if next == OperationPhase::Rollback {
            return Ok(current.crosses_mutation_boundary());
        }
        Ok(self
            .required_phases(release_class)?
            .windows(2)
            .any(|pair| pair == [current, next]))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseClass {
    CodeOnlyCompatible,
    StatefulCompatible,
    StatefulBreaking,
    Rollback,
}

const CODE_ONLY_PHASES: &[OperationPhase] = &[
    OperationPhase::Queued,
    OperationPhase::SyncingSource,
    OperationPhase::VerifyingSource,
    OperationPhase::Testing,
    OperationPhase::Building,
    OperationPhase::Preflight,
    OperationPhase::Deploying,
    OperationPhase::HealthChecking,
    OperationPhase::Soaking,
];

const STATEFUL_PHASES: &[OperationPhase] = &[
    OperationPhase::Queued,
    OperationPhase::SyncingSource,
    OperationPhase::VerifyingSource,
    OperationPhase::Testing,
    OperationPhase::Building,
    OperationPhase::Preflight,
    OperationPhase::BackingUp,
    OperationPhase::Draining,
    OperationPhase::CutoverSnapshotting,
    OperationPhase::Migrating,
    OperationPhase::Deploying,
    OperationPhase::HealthChecking,
    OperationPhase::Soaking,
];

const ROLLBACK_PHASES: &[OperationPhase] = &[
    OperationPhase::Queued,
    OperationPhase::Preflight,
    OperationPhase::Rollback,
    OperationPhase::HealthChecking,
    OperationPhase::Soaking,
];

const BACKUP_ONLY_PHASES: &[OperationPhase] = &[
    OperationPhase::Queued,
    OperationPhase::Preflight,
    OperationPhase::BackingUp,
];

impl ReleaseClass {
    pub const fn required_phases(self) -> &'static [OperationPhase] {
        match self {
            Self::CodeOnlyCompatible => CODE_ONLY_PHASES,
            Self::StatefulCompatible | Self::StatefulBreaking => STATEFUL_PHASES,
            Self::Rollback => ROLLBACK_PHASES,
        }
    }

    pub fn permits_transition(self, current: OperationPhase, next: OperationPhase) -> bool {
        if next == OperationPhase::Reconciliation {
            return true;
        }
        if next == OperationPhase::Rollback {
            return current.crosses_mutation_boundary();
        }

        self.required_phases()
            .windows(2)
            .any(|pair| pair == [current, next])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationState {
    pub phase: OperationPhase,
    pub result: OperationResult,
    pub blocking_reason: BlockingReason,
}

impl OperationState {
    pub fn validate(&self) -> Result<(), OperationStateError> {
        if self.result != OperationResult::Running && self.blocking_reason != BlockingReason::None {
            return Err(OperationStateError::TerminalOperationBlocked);
        }
        if self.result == OperationResult::ManualRecoveryRequired
            && self.phase != OperationPhase::Reconciliation
        {
            return Err(OperationStateError::ManualRecoveryOutsideReconciliation);
        }
        if self.result == OperationResult::RolledBack
            && !matches!(
                self.phase,
                OperationPhase::Rollback | OperationPhase::Soaking
            )
        {
            return Err(OperationStateError::RolledBackOutsideRollback);
        }
        if self.result == OperationResult::RollbackFailed
            && !matches!(
                self.phase,
                OperationPhase::Rollback | OperationPhase::Reconciliation
            )
        {
            return Err(OperationStateError::RollbackFailureOutsideRecovery);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub operation_id: Uuid,
    pub request_id: Uuid,
    pub attempt_id: Uuid,
    pub attempt_number: u32,
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub target_commit: Option<GitCommitId>,
    pub release_class: Option<ReleaseClass>,
    pub state: OperationState,
    pub actor: OperationActor,
    pub evidence: OperationEvidence,
    pub failure_capsule: Option<FailureCapsule>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperationActor {
    Interactive { user_id: Uuid },
    Automation { source: AutomationSource },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationSource {
    GithubWebhook,
    SourceReconciliation,
    DirectPush,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledPolicyIdentity {
    pub digest: EvidenceDigest,
    pub version: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedPhaseSpecDigestV1 {
    pub branch: ExecutorPhaseBranch,
    pub phase: OperationPhase,
    pub spec_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FenceAcquisitionReceiptV1 {
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub attempt_id: Uuid,
    pub epoch: u64,
    pub lease_digest: EvidenceDigest,
    pub acquired_at_ms: i64,
    pub receipt_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct FenceAcquisitionReceiptDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a ProjectId,
    attempt_id: Uuid,
    epoch: u64,
    lease_digest: &'a EvidenceDigest,
    acquired_at_ms: i64,
}

impl FenceAcquisitionReceiptV1 {
    pub fn new(
        project_id: ProjectId,
        attempt_id: Uuid,
        epoch: u64,
        lease_digest: EvidenceDigest,
        acquired_at_ms: i64,
    ) -> Result<Self, FenceAcquisitionReceiptError> {
        if attempt_id.is_nil() || epoch == 0 || acquired_at_ms < 0 {
            return Err(FenceAcquisitionReceiptError::InvalidDocument);
        }
        let mut receipt = Self {
            schema_version: FENCE_ACQUISITION_RECEIPT_SCHEMA_VERSION,
            project_id,
            attempt_id,
            epoch,
            lease_digest,
            acquired_at_ms,
            receipt_digest: EvidenceDigest::sha256([]),
        };
        receipt.receipt_digest = receipt.calculate_digest()?;
        Ok(receipt)
    }

    pub fn has_valid_digest(&self) -> Result<bool, FenceAcquisitionReceiptError> {
        if self.schema_version != FENCE_ACQUISITION_RECEIPT_SCHEMA_VERSION
            || self.attempt_id.is_nil()
            || self.epoch == 0
            || self.acquired_at_ms < 0
        {
            return Ok(false);
        }
        Ok(self.receipt_digest == self.calculate_digest()?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FenceAcquisitionReceiptError> {
        if !self.has_valid_digest()? {
            return Err(FenceAcquisitionReceiptError::DigestMismatch);
        }
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FenceAcquisitionReceiptError> {
        let receipt: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&receipt)? != bytes {
            return Err(FenceAcquisitionReceiptError::InvalidDocument);
        }
        if !receipt.has_valid_digest()? {
            return Err(FenceAcquisitionReceiptError::DigestMismatch);
        }
        Ok(receipt)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, FenceAcquisitionReceiptError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &FenceAcquisitionReceiptDigestPayload {
                purpose: "rdashboard.fence-acquisition-receipt.v1",
                schema_version: self.schema_version,
                project_id: &self.project_id,
                attempt_id: self.attempt_id,
                epoch: self.epoch,
                lease_digest: &self.lease_digest,
                acquired_at_ms: self.acquired_at_ms,
            },
        )?))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FenceAcquisitionReceiptError {
    #[error("fence acquisition receipt is structurally invalid")]
    InvalidDocument,
    #[error("fence acquisition receipt digest does not match its canonical payload")]
    DigestMismatch,
    #[error("fence acquisition receipt canonical encoding failed")]
    CanonicalEncoding(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OperationEvidence {
    pub authorized_phase_spec_digests: Vec<AuthorizedPhaseSpecDigestV1>,
    pub installed_policy: Option<InstalledPolicyIdentity>,
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
    pub action_grant_digest: Option<EvidenceDigest>,
    pub fencing_epoch: Option<u64>,
    pub fence_acquisition_receipt_digest: Option<EvidenceDigest>,
    pub recovery_mode: Option<OperationRecoveryMode>,
    pub transitions: Vec<OperationTransition>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationRecoveryMode {
    Rollback,
    Reconciliation,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationTransition {
    pub sequence: u32,
    pub from: OperationState,
    pub to: OperationState,
    pub receipt_digest: Option<EvidenceDigest>,
    pub occurred_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseReceipt {
    pub attempt_id: Uuid,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub intent_digest: EvidenceDigest,
    pub observation_digest: EvidenceDigest,
    pub artifacts: PhaseArtifacts,
    pub receipt_digest: EvidenceDigest,
    pub committed_at_ms: i64,
}

impl PhaseReceipt {
    pub fn new(
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
        intent_digest: EvidenceDigest,
        observation_digest: EvidenceDigest,
        artifacts: PhaseArtifacts,
        committed_at_ms: i64,
    ) -> Result<Self, serde_json::Error> {
        let receipt_digest = receipt_digest(
            attempt_id,
            phase,
            branch,
            &intent_digest,
            &observation_digest,
            &artifacts,
            committed_at_ms,
        )?;
        Ok(Self {
            attempt_id,
            phase,
            branch,
            intent_digest,
            observation_digest,
            artifacts,
            receipt_digest,
            committed_at_ms,
        })
    }

    pub fn has_valid_digest(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_digest
            == receipt_digest(
                self.attempt_id,
                self.phase,
                self.branch,
                &self.intent_digest,
                &self.observation_digest,
                &self.artifacts,
                self.committed_at_ms,
            )?)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorPhaseBranch {
    Primary,
    RollbackRecovery,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PhaseArtifacts {
    pub authorized_phase_spec_digest: Option<EvidenceDigest>,
    pub source_gate_proof_digest: Option<EvidenceDigest>,
    pub drain_evidence_digest: Option<EvidenceDigest>,
    pub source_export_digest: Option<EvidenceDigest>,
    pub prefetch_evidence_digest: Option<EvidenceDigest>,
    pub ci_evidence_digest: Option<EvidenceDigest>,
    pub build_plan_digest: Option<EvidenceDigest>,
    pub deployment_plan_digest: Option<EvidenceDigest>,
    pub release_bundle_digest: Option<EvidenceDigest>,
    pub resource_reservation_digest: Option<EvidenceDigest>,
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
    pub fencing_epoch: Option<u64>,
}

impl PhaseArtifacts {
    pub fn validate_for_phase(&self, phase: OperationPhase) -> Result<(), ArtifactContractError> {
        let required = match phase {
            OperationPhase::Testing => {
                [
                    self.source_export_digest.as_ref(),
                    self.prefetch_evidence_digest.as_ref(),
                    self.ci_evidence_digest.as_ref(),
                    self.build_context_digest.as_ref(),
                    self.resource_reservation_digest.as_ref(),
                ]
                .into_iter()
                .all(|value| value.is_some())
                    && !self.base_image_digests.is_empty()
            }
            OperationPhase::Building => {
                [
                    self.build_context_digest.as_ref(),
                    self.build_plan_digest.as_ref(),
                    self.image_digest.as_ref(),
                    self.image_id_digest.as_ref(),
                ]
                .into_iter()
                .all(|value| value.is_some())
                    && !self.base_image_digests.is_empty()
            }
            OperationPhase::Preflight => self.resource_reservation_digest.is_some(),
            OperationPhase::Draining => {
                self.source_gate_proof_digest.is_some() && self.drain_evidence_digest.is_some()
            }
            OperationPhase::Deploying => {
                self.deployment_plan_digest.is_some() && self.release_bundle_digest.is_some()
            }
            OperationPhase::BackingUp => [
                self.backup_set_id.as_ref().map(|_| ()),
                self.base_backup_id.as_ref().map(|_| ()),
                self.base_backup_manifest_digest.as_ref().map(|_| ()),
                self.base_backup_evidence_digest.as_ref().map(|_| ()),
                self.base_backup_offsite_evidence_digest
                    .as_ref()
                    .map(|_| ()),
                self.base_backup_verification_digest.as_ref().map(|_| ()),
            ]
            .into_iter()
            .all(|value| value.is_some()),
            OperationPhase::CutoverSnapshotting => [
                self.backup_set_id.as_ref().map(|_| ()),
                self.cutover_backup_id.as_ref().map(|_| ()),
                self.cutover_backup_manifest_digest.as_ref().map(|_| ()),
                self.cutover_backup_evidence_digest.as_ref().map(|_| ()),
                self.cutover_backup_verification_digest.as_ref().map(|_| ()),
                self.fencing_epoch.as_ref().map(|_| ()),
            ]
            .into_iter()
            .all(|value| value.is_some()),
            OperationPhase::Migrating => self.schema_version.is_some(),
            OperationPhase::HealthChecking => self.health_evidence_digest.is_some(),
            OperationPhase::Soaking
            | OperationPhase::Rollback
            | OperationPhase::Queued
            | OperationPhase::SyncingSource
            | OperationPhase::VerifyingSource
            | OperationPhase::Reconciliation => true,
        };
        if required && self.contains_only_phase_artifacts(phase) {
            Ok(())
        } else if required {
            Err(ArtifactContractError::UnexpectedEvidence { phase })
        } else {
            Err(ArtifactContractError::MissingRequiredEvidence { phase })
        }
    }

    fn contains_only_phase_artifacts(&self, phase: OperationPhase) -> bool {
        let mut unexpected = self.clone();
        unexpected.authorized_phase_spec_digest = None;
        match phase {
            OperationPhase::Testing => {
                unexpected.source_export_digest = None;
                unexpected.prefetch_evidence_digest = None;
                unexpected.ci_evidence_digest = None;
                unexpected.resource_reservation_digest = None;
                unexpected.build_context_digest = None;
                unexpected.generated_output_digests.clear();
                unexpected.base_image_digests.clear();
            }
            OperationPhase::Building => {
                unexpected.build_context_digest = None;
                unexpected.build_plan_digest = None;
                unexpected.image_digest = None;
                unexpected.image_id_digest = None;
                unexpected.base_image_digests.clear();
            }
            OperationPhase::Preflight => {
                unexpected.resource_reservation_digest = None;
            }
            OperationPhase::BackingUp => {
                unexpected.source_gate_proof_digest = None;
                unexpected.backup_set_id = None;
                unexpected.base_backup_id = None;
                unexpected.base_backup_manifest_digest = None;
                unexpected.base_backup_evidence_digest = None;
                unexpected.base_backup_offsite_evidence_digest = None;
                unexpected.base_backup_verification_digest = None;
            }
            OperationPhase::Draining => {
                unexpected.source_gate_proof_digest = None;
                unexpected.drain_evidence_digest = None;
            }
            OperationPhase::CutoverSnapshotting => {
                unexpected.backup_set_id = None;
                unexpected.cutover_backup_id = None;
                unexpected.cutover_backup_manifest_digest = None;
                unexpected.cutover_backup_evidence_digest = None;
                unexpected.cutover_backup_verification_digest = None;
                unexpected.fencing_epoch = None;
            }
            OperationPhase::Migrating => {
                unexpected.schema_version = None;
            }
            OperationPhase::Deploying => {
                unexpected.source_gate_proof_digest = None;
                unexpected.deployment_plan_digest = None;
                unexpected.release_bundle_digest = None;
                unexpected.previous_release_bundle_digest = None;
            }
            OperationPhase::HealthChecking | OperationPhase::Soaking => {
                unexpected.health_evidence_digest = None;
            }
            OperationPhase::Rollback => {
                unexpected.previous_release_bundle_digest = None;
            }
            OperationPhase::Queued
            | OperationPhase::SyncingSource
            | OperationPhase::VerifyingSource
            | OperationPhase::Reconciliation => {}
        }
        unexpected == Self::default()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactContractError {
    #[error("phase {phase:?} is missing required typed executor evidence")]
    MissingRequiredEvidence { phase: OperationPhase },
    #[error("phase {phase:?} contains evidence owned by another phase")]
    UnexpectedEvidence { phase: OperationPhase },
}

#[derive(Serialize)]
struct ReceiptDigestPayload<'a> {
    attempt_id: Uuid,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
    intent_digest: &'a EvidenceDigest,
    observation_digest: &'a EvidenceDigest,
    artifacts: &'a PhaseArtifacts,
    committed_at_ms: i64,
}

fn receipt_digest(
    attempt_id: Uuid,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
    intent_digest: &EvidenceDigest,
    observation_digest: &EvidenceDigest,
    artifacts: &PhaseArtifacts,
    committed_at_ms: i64,
) -> Result<EvidenceDigest, serde_json::Error> {
    let canonical = serde_jcs::to_vec(&ReceiptDigestPayload {
        attempt_id,
        phase,
        branch,
        intent_digest,
        observation_digest,
        artifacts,
        committed_at_ms,
    })?;
    Ok(EvidenceDigest::sha256(canonical))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OperationStateError {
    #[error("a terminal operation cannot retain a blocking reason")]
    TerminalOperationBlocked,
    #[error("manual recovery is valid only during reconciliation")]
    ManualRecoveryOutsideReconciliation,
    #[error("rolled-back result is valid only in rollback or its completed soak phase")]
    RolledBackOutsideRollback,
    #[error("rollback failure is valid only in rollback or reconciliation")]
    RollbackFailureOutsideRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OperationContractError {
    #[error("operation kind and release class do not form a valid execution plan")]
    ReleaseClassMismatch,
}
