use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    backup::{
        BackupManifestV1, BackupSnapshotKindV1, LocalBackupEvidenceV1,
        OffsiteVerificationEvidenceV1, ProviderUploadReceiptV1, VerifiedBackupChainV1,
    },
    domain::{
        EvidenceDigest, ExecutorPhaseBranch, InstalledPolicyIdentity, OperationPhase,
        PhaseArtifacts, ProjectId,
    },
    phase6::{
        AdapterResultSchemaV1, AuthorizedPhaseSpecV1, FixedAdapterProfileV1, FixedAdapterRequestV1,
        Phase6ContractError,
    },
};

pub const FIXED_ADAPTER_RESULT_SCHEMA_VERSION: u16 = 1;
pub const PHASE_OBSERVATION_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const MAX_FIXED_ADAPTER_RESULT_BYTES: usize = 256 * 1024;

const FIXED_ADAPTER_RESULT_PURPOSE: &str = "rdashboard.fixed-adapter-result.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RimgSchemaCompatibilityV1 {
    UpgradeRequired,
    Current,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RimgSchemaObservationEvidenceV1 {
    pub schema_version: u16,
    pub phase_intent_digest: EvidenceDigest,
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub migration_id: String,
    pub current_schema_version: String,
    pub candidate_schema_version: String,
    pub pending_migrations: u32,
    pub compatibility: RimgSchemaCompatibilityV1,
    pub integrity_check: String,
    pub inspected_at_ms: i64,
    pub observation_digest: EvidenceDigest,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RimgSchemaObservationInputV1 {
    pub current_schema_version: String,
    pub candidate_schema_version: String,
    pub pending_migrations: u32,
    pub compatibility: RimgSchemaCompatibilityV1,
    pub integrity_check: String,
    pub inspected_at_ms: i64,
    pub observation_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct RimgSchemaObservationDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    phase_intent_digest: &'a EvidenceDigest,
    project_id: &'a ProjectId,
    installed_policy: &'a InstalledPolicyIdentity,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    migration_id: &'a str,
    current_schema_version: &'a str,
    candidate_schema_version: &'a str,
    pending_migrations: u32,
    compatibility: RimgSchemaCompatibilityV1,
    integrity_check: &'a str,
    inspected_at_ms: i64,
    observation_digest: &'a EvidenceDigest,
}

impl RimgSchemaObservationEvidenceV1 {
    pub fn new(
        spec: &AuthorizedPhaseSpecV1,
        input: RimgSchemaObservationInputV1,
    ) -> Result<Self, AdapterResultContractError> {
        let migration_id = spec
            .migration_id
            .clone()
            .ok_or(AdapterResultContractError::EvidenceMismatch)?;
        let mut evidence = Self {
            schema_version: 1,
            phase_intent_digest: spec.intent_digest.clone(),
            project_id: spec.project_id.clone(),
            installed_policy: spec.installed_policy.clone(),
            installed_rimg_policy_digest: spec.installed_rimg_policy_digest.clone(),
            migration_id,
            current_schema_version: input.current_schema_version,
            candidate_schema_version: input.candidate_schema_version,
            pending_migrations: input.pending_migrations,
            compatibility: input.compatibility,
            integrity_check: input.integrity_check,
            inspected_at_ms: input.inspected_at_ms,
            observation_digest: input.observation_digest,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        evidence.evidence_digest = evidence.calculate_digest()?;
        if !evidence.has_valid_digest()? {
            return Err(AdapterResultContractError::EvidenceMismatch);
        }
        Ok(evidence)
    }

    pub fn has_valid_digest(&self) -> Result<bool, AdapterResultContractError> {
        let compatibility_valid = match self.compatibility {
            RimgSchemaCompatibilityV1::Current => {
                self.current_schema_version == self.candidate_schema_version
                    && self.pending_migrations == 0
            }
            RimgSchemaCompatibilityV1::UpgradeRequired => {
                self.current_schema_version != self.candidate_schema_version
                    && self.pending_migrations > 0
            }
        };
        Ok(self.schema_version == 1
            && self.installed_policy.version > 0
            && !self.migration_id.is_empty()
            && !self.current_schema_version.is_empty()
            && !self.candidate_schema_version.is_empty()
            && self.integrity_check == "ok"
            && self.inspected_at_ms >= 0
            && compatibility_valid
            && self.evidence_digest == self.calculate_digest()?)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, AdapterResultContractError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &RimgSchemaObservationDigestPayload {
                purpose: "rdashboard.rimg-schema-observation.v1",
                schema_version: self.schema_version,
                phase_intent_digest: &self.phase_intent_digest,
                project_id: &self.project_id,
                installed_policy: &self.installed_policy,
                installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
                migration_id: &self.migration_id,
                current_schema_version: &self.current_schema_version,
                candidate_schema_version: &self.candidate_schema_version,
                pending_migrations: self.pending_migrations,
                compatibility: self.compatibility,
                integrity_check: &self.integrity_check,
                inspected_at_ms: self.inspected_at_ms,
                observation_digest: &self.observation_digest,
            },
        )?))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseObservationEvidenceV1 {
    pub schema_version: u16,
    pub observed_at_ms: i64,
    pub observation_digest: EvidenceDigest,
    pub artifacts: PhaseArtifacts,
}

impl PhaseObservationEvidenceV1 {
    pub fn new(
        observed_at_ms: i64,
        observation_digest: EvidenceDigest,
        artifacts: PhaseArtifacts,
    ) -> Result<Self, AdapterResultContractError> {
        if observed_at_ms < 0 {
            return Err(AdapterResultContractError::InvalidCompletionTime);
        }
        Ok(Self {
            schema_version: PHASE_OBSERVATION_EVIDENCE_SCHEMA_VERSION,
            observed_at_ms,
            observation_digest,
            artifacts,
        })
    }

    fn has_valid_shape(&self) -> bool {
        self.schema_version == PHASE_OBSERVATION_EVIDENCE_SCHEMA_VERSION && self.observed_at_ms >= 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", content = "document", rename_all = "snake_case")]
pub enum FixedAdapterEvidenceV1 {
    BackupManifest(BackupManifestV1),
    LocalBackupEvidence(LocalBackupEvidenceV1),
    ProviderUploadReceipt(ProviderUploadReceiptV1),
    OffsiteVerificationEvidence(OffsiteVerificationEvidenceV1),
    DrainEvidence(PhaseObservationEvidenceV1),
    SchemaInspectionEvidence(RimgSchemaObservationEvidenceV1),
    MigrationEvidence(PhaseObservationEvidenceV1),
    DeploymentEvidence(PhaseObservationEvidenceV1),
    ReadinessEvidence(PhaseObservationEvidenceV1),
    ConsumerSmokeEvidence(PhaseObservationEvidenceV1),
    SoakEvidence(PhaseObservationEvidenceV1),
    RollbackEvidence(PhaseObservationEvidenceV1),
}

impl FixedAdapterEvidenceV1 {
    pub const fn result_schema(&self) -> AdapterResultSchemaV1 {
        match self {
            Self::BackupManifest(_) => AdapterResultSchemaV1::BackupManifest,
            Self::LocalBackupEvidence(_) => AdapterResultSchemaV1::LocalBackupEvidence,
            Self::ProviderUploadReceipt(_) => AdapterResultSchemaV1::ProviderUploadReceipt,
            Self::OffsiteVerificationEvidence(_) => {
                AdapterResultSchemaV1::OffsiteVerificationEvidence
            }
            Self::DrainEvidence(_) => AdapterResultSchemaV1::DrainEvidence,
            Self::SchemaInspectionEvidence(_) => AdapterResultSchemaV1::SchemaInspectionEvidence,
            Self::MigrationEvidence(_) => AdapterResultSchemaV1::MigrationEvidence,
            Self::DeploymentEvidence(_) => AdapterResultSchemaV1::DeploymentEvidence,
            Self::ReadinessEvidence(_) => AdapterResultSchemaV1::ReadinessEvidence,
            Self::ConsumerSmokeEvidence(_) => AdapterResultSchemaV1::ConsumerSmokeEvidence,
            Self::SoakEvidence(_) => AdapterResultSchemaV1::SoakEvidence,
            Self::RollbackEvidence(_) => AdapterResultSchemaV1::RollbackEvidence,
        }
    }

    fn completed_at_ms(&self) -> i64 {
        match self {
            Self::BackupManifest(document) => document.completed_at_ms,
            Self::LocalBackupEvidence(document) => document.encryption.encrypted_at_ms,
            Self::ProviderUploadReceipt(document) => document.uploaded_at_ms,
            Self::OffsiteVerificationEvidence(document) => document.verified_at_ms,
            Self::SchemaInspectionEvidence(document) => document.inspected_at_ms,
            Self::DrainEvidence(document)
            | Self::MigrationEvidence(document)
            | Self::DeploymentEvidence(document)
            | Self::ReadinessEvidence(document)
            | Self::ConsumerSmokeEvidence(document)
            | Self::SoakEvidence(document)
            | Self::RollbackEvidence(document) => document.observed_at_ms,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixedAdapterResultV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub attempt_id: uuid::Uuid,
    pub request_id: uuid::Uuid,
    pub project_id: ProjectId,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub sequence: u16,
    pub profile: FixedAdapterProfileV1,
    pub result_schema: AdapterResultSchemaV1,
    pub request_document_digest: EvidenceDigest,
    pub authorized_phase_spec_digest: EvidenceDigest,
    pub prior_result_digest: Option<EvidenceDigest>,
    pub completed_at_ms: i64,
    pub evidence: FixedAdapterEvidenceV1,
    pub result_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseExecutionProjectionV1 {
    pub observation_digest: EvidenceDigest,
    pub completed_at_ms: i64,
    pub artifacts: PhaseArtifacts,
    pub verified_backup_chain: Option<VerifiedBackupChainV1>,
}

impl PhaseExecutionProjectionV1 {
    pub fn from_results(
        spec: &AuthorizedPhaseSpecV1,
        results: &[FixedAdapterResultV1],
    ) -> Result<Self, AdapterResultContractError> {
        validate_complete_result_chain(spec, results)?;
        let last = results
            .last()
            .ok_or(AdapterResultContractError::IncompleteResultChain)?;
        let (artifacts, verified_backup_chain) = match spec.phase {
            OperationPhase::BackingUp | OperationPhase::CutoverSnapshotting => {
                project_backup_artifacts(spec, results)?
            }
            OperationPhase::Draining
            | OperationPhase::Migrating
            | OperationPhase::Deploying
            | OperationPhase::HealthChecking
            | OperationPhase::Soaking
            | OperationPhase::Rollback => (
                projected_observation_artifacts(spec.phase, &last.evidence)?,
                None,
            ),
            _ => return Err(AdapterResultContractError::PhaseProjectionMismatch),
        };
        spec.validate_observed_artifacts(&artifacts)?;
        Ok(Self {
            observation_digest: last.result_digest.clone(),
            completed_at_ms: last.completed_at_ms,
            artifacts,
            verified_backup_chain,
        })
    }
}

#[derive(Serialize)]
struct FixedAdapterResultDigestPayload<'a> {
    purpose: &'a str,
    schema_version: u16,
    attempt_id: uuid::Uuid,
    request_id: uuid::Uuid,
    project_id: &'a ProjectId,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
    sequence: u16,
    profile: FixedAdapterProfileV1,
    result_schema: AdapterResultSchemaV1,
    request_document_digest: &'a EvidenceDigest,
    authorized_phase_spec_digest: &'a EvidenceDigest,
    prior_result_digest: &'a Option<EvidenceDigest>,
    completed_at_ms: i64,
    evidence: &'a FixedAdapterEvidenceV1,
}

impl FixedAdapterResultV1 {
    pub fn validate_for_adapter(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
        prior_results: &[Self],
    ) -> Result<(), AdapterResultContractError> {
        self.validate_authorized(spec, sequence, prior_results)
    }

    pub fn validate_prior_chain(
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
        prior_results: &[Self],
    ) -> Result<(), AdapterResultContractError> {
        validate_prior_results(spec, sequence, prior_results)
    }

    pub fn new(
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
        evidence: FixedAdapterEvidenceV1,
        prior_results: &[Self],
    ) -> Result<Self, AdapterResultContractError> {
        let request = spec.fixed_adapter_request(sequence)?;
        let mut result = Self {
            purpose: FIXED_ADAPTER_RESULT_PURPOSE.to_owned(),
            schema_version: FIXED_ADAPTER_RESULT_SCHEMA_VERSION,
            attempt_id: request.attempt_id,
            request_id: request.request_id,
            project_id: request.project_id.clone(),
            phase: request.phase,
            branch: request.branch,
            sequence,
            profile: request.profile,
            result_schema: request.result_schema,
            request_document_digest: request.digest()?,
            authorized_phase_spec_digest: spec.spec_digest.clone(),
            prior_result_digest: prior_results
                .last()
                .map(|result| result.result_digest.clone()),
            completed_at_ms: evidence.completed_at_ms(),
            evidence,
            result_digest: EvidenceDigest::sha256([]),
        };
        result.result_digest = result.calculate_digest()?;
        result.validate_authorized(spec, sequence, prior_results)?;
        Ok(result)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AdapterResultContractError> {
        if !self.has_valid_digest()? {
            return Err(AdapterResultContractError::DigestMismatch);
        }
        let bytes = serde_jcs::to_vec(self)?;
        if bytes.len() > MAX_FIXED_ADAPTER_RESULT_BYTES {
            return Err(AdapterResultContractError::ResultTooLarge);
        }
        Ok(bytes)
    }

    pub fn decode_authorized(
        bytes: &[u8],
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
        prior_results: &[Self],
    ) -> Result<Self, AdapterResultContractError> {
        if bytes.is_empty() || bytes.len() > MAX_FIXED_ADAPTER_RESULT_BYTES {
            return Err(AdapterResultContractError::ResultTooLarge);
        }
        let result: Self = decode_canonical(bytes)?;
        result.validate_authorized(spec, sequence, prior_results)?;
        Ok(result)
    }

    pub fn has_valid_digest(&self) -> Result<bool, AdapterResultContractError> {
        Ok(self.purpose == FIXED_ADAPTER_RESULT_PURPOSE
            && self.schema_version == FIXED_ADAPTER_RESULT_SCHEMA_VERSION
            && self.completed_at_ms >= 0
            && self.result_schema == self.evidence.result_schema()
            && self.completed_at_ms == self.evidence.completed_at_ms()
            && self.result_digest == self.calculate_digest()?)
    }

    fn validate_authorized(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        sequence: u16,
        prior_results: &[Self],
    ) -> Result<(), AdapterResultContractError> {
        let request = spec.fixed_adapter_request(sequence)?;
        validate_prior_results(spec, sequence, prior_results)?;
        if !self.has_valid_digest()?
            || !result_identity_matches(self, spec, &request, sequence)?
            || self.prior_result_digest
                != prior_results
                    .last()
                    .map(|result| result.result_digest.clone())
            || request
                .boundary_now_ms
                .is_some_and(|time| self.completed_at_ms < time)
            || request
                .prerequisites_valid_through_ms
                .is_some_and(|time| self.completed_at_ms > time)
            || prior_results
                .last()
                .is_some_and(|prior| self.completed_at_ms < prior.completed_at_ms)
        {
            return Err(AdapterResultContractError::AuthorizationMismatch);
        }
        validate_evidence(self, spec, prior_results)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, AdapterResultContractError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &FixedAdapterResultDigestPayload {
                purpose: &self.purpose,
                schema_version: self.schema_version,
                attempt_id: self.attempt_id,
                request_id: self.request_id,
                project_id: &self.project_id,
                phase: self.phase,
                branch: self.branch,
                sequence: self.sequence,
                profile: self.profile,
                result_schema: self.result_schema,
                request_document_digest: &self.request_document_digest,
                authorized_phase_spec_digest: &self.authorized_phase_spec_digest,
                prior_result_digest: &self.prior_result_digest,
                completed_at_ms: self.completed_at_ms,
                evidence: &self.evidence,
            },
        )?))
    }
}

fn result_identity_matches(
    result: &FixedAdapterResultV1,
    spec: &AuthorizedPhaseSpecV1,
    request: &FixedAdapterRequestV1,
    sequence: u16,
) -> Result<bool, AdapterResultContractError> {
    Ok(result.attempt_id == request.attempt_id
        && result.request_id == request.request_id
        && result.project_id == request.project_id
        && result.phase == request.phase
        && result.branch == request.branch
        && result.sequence == sequence
        && result.profile == request.profile
        && result.result_schema == request.result_schema
        && result.request_document_digest == request.digest()?
        && result.authorized_phase_spec_digest == spec.spec_digest)
}

fn validate_prior_results(
    spec: &AuthorizedPhaseSpecV1,
    sequence: u16,
    prior_results: &[FixedAdapterResultV1],
) -> Result<(), AdapterResultContractError> {
    let expected_count = usize::from(sequence.saturating_sub(1));
    if sequence == 0 || prior_results.len() != expected_count {
        return Err(AdapterResultContractError::PriorResultChainMismatch);
    }
    for (index, result) in prior_results.iter().enumerate() {
        let result_sequence = u16::try_from(index + 1)
            .map_err(|_| AdapterResultContractError::PriorResultChainMismatch)?;
        let request = spec.fixed_adapter_request(result_sequence)?;
        let expected_prior_digest = index
            .checked_sub(1)
            .and_then(|prior| prior_results.get(prior))
            .map(|prior| prior.result_digest.clone());
        if !result.has_valid_digest()?
            || !result_identity_matches(result, spec, &request, result_sequence)?
            || result.prior_result_digest != expected_prior_digest
            || request
                .boundary_now_ms
                .is_some_and(|time| result.completed_at_ms < time)
            || request
                .prerequisites_valid_through_ms
                .is_some_and(|time| result.completed_at_ms > time)
            || index
                .checked_sub(1)
                .is_some_and(|prior| result.completed_at_ms < prior_results[prior].completed_at_ms)
        {
            return Err(AdapterResultContractError::PriorResultChainMismatch);
        }
        validate_evidence(result, spec, &prior_results[..index])?;
    }
    Ok(())
}

fn validate_complete_result_chain(
    spec: &AuthorizedPhaseSpecV1,
    results: &[FixedAdapterResultV1],
) -> Result<(), AdapterResultContractError> {
    if results.is_empty() || results.len() != spec.steps.len() {
        return Err(AdapterResultContractError::IncompleteResultChain);
    }
    for (index, result) in results.iter().enumerate() {
        let sequence = u16::try_from(index + 1)
            .map_err(|_| AdapterResultContractError::IncompleteResultChain)?;
        result.validate_authorized(spec, sequence, &results[..index])?;
    }
    Ok(())
}

fn project_backup_artifacts(
    spec: &AuthorizedPhaseSpecV1,
    results: &[FixedAdapterResultV1],
) -> Result<(PhaseArtifacts, Option<VerifiedBackupChainV1>), AdapterResultContractError> {
    let backup = required_backup_spec(spec)?;
    let manifest = prior_backup_manifest(results)?;
    let local = prior_local_backup(results)?;
    let (artifacts, chain) = match backup.snapshot_kind {
        BackupSnapshotKindV1::Base if spec.phase == OperationPhase::BackingUp => {
            let receipt = prior_upload_receipt(results)?;
            let offsite = prior_offsite_verification(results)?;
            let chain = VerifiedBackupChainV1::new_base(backup, manifest, local, receipt, offsite)?;
            (
                PhaseArtifacts {
                    backup_set_id: Some(backup.backup_set_id),
                    base_backup_id: Some(backup.backup_id),
                    base_backup_manifest_digest: Some(manifest.manifest_digest.clone()),
                    base_backup_evidence_digest: Some(local.evidence_digest.clone()),
                    base_backup_offsite_evidence_digest: Some(offsite.evidence_digest.clone()),
                    base_backup_verification_digest: Some(chain.chain_digest().clone()),
                    ..PhaseArtifacts::default()
                },
                chain,
            )
        }
        BackupSnapshotKindV1::Cutover if spec.phase == OperationPhase::CutoverSnapshotting => {
            let chain = VerifiedBackupChainV1::new_cutover(backup, manifest, local)?;
            (
                PhaseArtifacts {
                    backup_set_id: Some(backup.backup_set_id),
                    cutover_backup_id: Some(backup.backup_id),
                    cutover_backup_manifest_digest: Some(manifest.manifest_digest.clone()),
                    cutover_backup_evidence_digest: Some(local.evidence_digest.clone()),
                    cutover_backup_verification_digest: Some(chain.chain_digest().clone()),
                    fencing_epoch: backup.fencing_epoch,
                    ..PhaseArtifacts::default()
                },
                chain,
            )
        }
        _ => return Err(AdapterResultContractError::PhaseProjectionMismatch),
    };
    Ok((spec.bind_artifacts(artifacts)?, Some(chain)))
}

fn projected_observation_artifacts(
    phase: OperationPhase,
    evidence: &FixedAdapterEvidenceV1,
) -> Result<PhaseArtifacts, AdapterResultContractError> {
    let ((OperationPhase::Draining, FixedAdapterEvidenceV1::DrainEvidence(document))
    | (OperationPhase::Migrating, FixedAdapterEvidenceV1::MigrationEvidence(document))
    | (OperationPhase::Deploying, FixedAdapterEvidenceV1::DeploymentEvidence(document))
    | (OperationPhase::HealthChecking, FixedAdapterEvidenceV1::ConsumerSmokeEvidence(document))
    | (OperationPhase::Soaking, FixedAdapterEvidenceV1::SoakEvidence(document))
    | (OperationPhase::Rollback, FixedAdapterEvidenceV1::RollbackEvidence(document))) =
        (phase, evidence)
    else {
        return Err(AdapterResultContractError::PhaseProjectionMismatch);
    };
    Ok(document.artifacts.clone())
}

fn validate_evidence(
    result: &FixedAdapterResultV1,
    spec: &AuthorizedPhaseSpecV1,
    prior_results: &[FixedAdapterResultV1],
) -> Result<(), AdapterResultContractError> {
    match &result.evidence {
        FixedAdapterEvidenceV1::BackupManifest(manifest) => {
            manifest.require_verified_against(required_backup_spec(spec)?)?;
        }
        FixedAdapterEvidenceV1::LocalBackupEvidence(local) => {
            let manifest = prior_backup_manifest(prior_results)?;
            local.require_verified_against(required_backup_spec(spec)?, manifest)?;
        }
        FixedAdapterEvidenceV1::ProviderUploadReceipt(receipt) => {
            let local = prior_local_backup(prior_results)?;
            receipt.require_verified_against(required_backup_spec(spec)?, local)?;
        }
        FixedAdapterEvidenceV1::OffsiteVerificationEvidence(offsite) => {
            let local = prior_local_backup(prior_results)?;
            let receipt = prior_upload_receipt(prior_results)?;
            offsite.require_verified_against(required_backup_spec(spec)?, local, receipt)?;
        }
        FixedAdapterEvidenceV1::SchemaInspectionEvidence(evidence) => {
            if !evidence.has_valid_digest()?
                || evidence.phase_intent_digest != spec.intent_digest
                || evidence.project_id != spec.project_id
                || evidence.installed_policy != spec.installed_policy
                || evidence.installed_rimg_policy_digest != spec.installed_rimg_policy_digest
                || Some(evidence.migration_id.as_str()) != spec.migration_id.as_deref()
                || spec
                    .expected_observation_artifacts
                    .schema_version
                    .as_deref()
                    != Some(evidence.candidate_schema_version.as_str())
            {
                return Err(AdapterResultContractError::EvidenceMismatch);
            }
        }
        FixedAdapterEvidenceV1::DrainEvidence(evidence)
        | FixedAdapterEvidenceV1::MigrationEvidence(evidence)
        | FixedAdapterEvidenceV1::DeploymentEvidence(evidence)
        | FixedAdapterEvidenceV1::ReadinessEvidence(evidence)
        | FixedAdapterEvidenceV1::ConsumerSmokeEvidence(evidence)
        | FixedAdapterEvidenceV1::SoakEvidence(evidence)
        | FixedAdapterEvidenceV1::RollbackEvidence(evidence) => {
            if !evidence.has_valid_shape() {
                return Err(AdapterResultContractError::EvidenceMismatch);
            }
            spec.validate_observed_artifacts(&evidence.artifacts)?;
        }
    }
    Ok(())
}

fn required_backup_spec(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<&crate::backup::AuthorizedBackupSpecV1, AdapterResultContractError> {
    spec.backup
        .as_ref()
        .ok_or(AdapterResultContractError::EvidenceMismatch)
}

fn prior_backup_manifest(
    results: &[FixedAdapterResultV1],
) -> Result<&BackupManifestV1, AdapterResultContractError> {
    results
        .iter()
        .find_map(|result| match &result.evidence {
            FixedAdapterEvidenceV1::BackupManifest(document) => Some(document),
            _ => None,
        })
        .ok_or(AdapterResultContractError::PriorResultChainMismatch)
}

fn prior_local_backup(
    results: &[FixedAdapterResultV1],
) -> Result<&LocalBackupEvidenceV1, AdapterResultContractError> {
    results
        .iter()
        .find_map(|result| match &result.evidence {
            FixedAdapterEvidenceV1::LocalBackupEvidence(document) => Some(document),
            _ => None,
        })
        .ok_or(AdapterResultContractError::PriorResultChainMismatch)
}

fn prior_upload_receipt(
    results: &[FixedAdapterResultV1],
) -> Result<&ProviderUploadReceiptV1, AdapterResultContractError> {
    results
        .iter()
        .find_map(|result| match &result.evidence {
            FixedAdapterEvidenceV1::ProviderUploadReceipt(document) => Some(document),
            _ => None,
        })
        .ok_or(AdapterResultContractError::PriorResultChainMismatch)
}

fn prior_offsite_verification(
    results: &[FixedAdapterResultV1],
) -> Result<&OffsiteVerificationEvidenceV1, AdapterResultContractError> {
    results
        .iter()
        .find_map(|result| match &result.evidence {
            FixedAdapterEvidenceV1::OffsiteVerificationEvidence(document) => Some(document),
            _ => None,
        })
        .ok_or(AdapterResultContractError::PriorResultChainMismatch)
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, AdapterResultContractError>
where
    T: DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice::<T>(bytes)?;
    if serde_jcs::to_vec(&value)? != bytes {
        return Err(AdapterResultContractError::NonCanonicalDocument);
    }
    Ok(value)
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterResultContractError {
    #[error("fixed adapter result exceeds its canonical document bound")]
    ResultTooLarge,
    #[error("fixed adapter result is not canonical JCS")]
    NonCanonicalDocument,
    #[error("fixed adapter result digest is invalid")]
    DigestMismatch,
    #[error("fixed adapter result is not bound to the authorized request and phase")]
    AuthorizationMismatch,
    #[error("fixed adapter result completion time is invalid")]
    InvalidCompletionTime,
    #[error("fixed adapter result evidence does not satisfy its typed contract")]
    EvidenceMismatch,
    #[error("fixed adapter prior-result hash chain is incomplete or mismatched")]
    PriorResultChainMismatch,
    #[error("fixed adapter phase does not have one complete authorized result chain")]
    IncompleteResultChain,
    #[error("fixed adapter result chain cannot be projected into the authorized phase artifacts")]
    PhaseProjectionMismatch,
    #[error("canonical fixed adapter result encoding failed: {0}")]
    CanonicalEncoding(#[from] serde_json::Error),
    #[error(transparent)]
    Phase6(#[from] Phase6ContractError),
    #[error(transparent)]
    Backup(#[from] crate::backup::BackupContractError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phase6::tests::{
        test_bootstrap_phase_spec, test_health_phase_spec, test_migration_phase_spec,
    };

    fn health_artifacts(
        spec: &AuthorizedPhaseSpecV1,
        label: &str,
    ) -> Result<PhaseArtifacts, Phase6ContractError> {
        spec.bind_artifacts(PhaseArtifacts {
            health_evidence_digest: Some(EvidenceDigest::sha256(label)),
            ..PhaseArtifacts::default()
        })
    }

    #[test]
    fn canonical_result_is_bound_to_request_evidence_and_prior_chain() {
        let spec = test_bootstrap_phase_spec();
        let artifacts = spec
            .bind_artifacts(spec.expected_observation_artifacts.clone())
            .unwrap_or_else(|error| panic!("bind deployment artifacts: {error}"));
        let evidence = FixedAdapterEvidenceV1::DeploymentEvidence(
            PhaseObservationEvidenceV1::new(
                900,
                EvidenceDigest::sha256("deployment observation"),
                artifacts,
            )
            .unwrap_or_else(|error| panic!("deployment evidence: {error}")),
        );
        let result = FixedAdapterResultV1::new(&spec, 1, evidence, &[])
            .unwrap_or_else(|error| panic!("result: {error}"));
        let bytes = result
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("canonical result: {error}"));
        let decoded = FixedAdapterResultV1::decode_authorized(&bytes, &spec, 1, &[])
            .unwrap_or_else(|error| panic!("decode result: {error}"));
        assert_eq!(decoded, result);

        let mut wrong_sequence = result.clone();
        wrong_sequence.sequence = 2;
        assert!(matches!(
            wrong_sequence.validate_authorized(&spec, 1, &[]),
            Err(AdapterResultContractError::AuthorizationMismatch)
        ));
        assert!(matches!(
            result.validate_authorized(&spec, 1, std::slice::from_ref(&result)),
            Err(AdapterResultContractError::PriorResultChainMismatch)
        ));
    }

    #[test]
    fn result_rejects_noncanonical_or_wrongly_typed_documents() {
        let spec = test_bootstrap_phase_spec();
        let artifacts = spec
            .bind_artifacts(spec.expected_observation_artifacts.clone())
            .unwrap_or_else(|error| panic!("bind deployment artifacts: {error}"));
        let evidence = FixedAdapterEvidenceV1::RollbackEvidence(
            PhaseObservationEvidenceV1::new(
                900,
                EvidenceDigest::sha256("rollback observation"),
                artifacts,
            )
            .unwrap_or_else(|error| panic!("rollback evidence: {error}")),
        );
        assert!(matches!(
            FixedAdapterResultV1::new(&spec, 1, evidence, &[]),
            Err(AdapterResultContractError::AuthorizationMismatch)
        ));

        assert!(matches!(
            FixedAdapterResultV1::decode_authorized(b"{ }", &spec, 1, &[]),
            Err(AdapterResultContractError::CanonicalEncoding(_)
                | AdapterResultContractError::NonCanonicalDocument)
        ));
    }

    #[test]
    fn result_chain_requires_monotonic_completion_time() {
        let spec = test_health_phase_spec();
        let readiness = FixedAdapterResultV1::new(
            &spec,
            1,
            FixedAdapterEvidenceV1::ReadinessEvidence(
                PhaseObservationEvidenceV1::new(
                    200,
                    EvidenceDigest::sha256("readiness observation"),
                    health_artifacts(&spec, "readiness artifacts")
                        .unwrap_or_else(|error| panic!("readiness artifacts: {error}")),
                )
                .unwrap_or_else(|error| panic!("readiness evidence: {error}")),
            ),
            &[],
        )
        .unwrap_or_else(|error| panic!("readiness result: {error}"));
        let smoke = FixedAdapterEvidenceV1::ConsumerSmokeEvidence(
            PhaseObservationEvidenceV1::new(
                199,
                EvidenceDigest::sha256("smoke observation"),
                health_artifacts(&spec, "smoke artifacts")
                    .unwrap_or_else(|error| panic!("smoke artifacts: {error}")),
            )
            .unwrap_or_else(|error| panic!("smoke evidence: {error}")),
        );
        assert!(matches!(
            FixedAdapterResultV1::new(&spec, 2, smoke, &[readiness]),
            Err(AdapterResultContractError::AuthorizationMismatch)
        ));
    }

    #[test]
    fn schema_observation_is_runtime_evidence_not_replayed_classification() {
        let spec = test_migration_phase_spec();
        let evidence = RimgSchemaObservationEvidenceV1::new(
            &spec,
            RimgSchemaObservationInputV1 {
                current_schema_version: "1".to_owned(),
                candidate_schema_version: "2".to_owned(),
                pending_migrations: 1,
                compatibility: RimgSchemaCompatibilityV1::UpgradeRequired,
                integrity_check: "ok".to_owned(),
                inspected_at_ms: 200,
                observation_digest: EvidenceDigest::sha256("rimg schema inspect output"),
            },
        )
        .unwrap_or_else(|error| panic!("schema observation: {error}"));
        let result = FixedAdapterResultV1::new(
            &spec,
            1,
            FixedAdapterEvidenceV1::SchemaInspectionEvidence(evidence.clone()),
            &[],
        )
        .unwrap_or_else(|error| panic!("schema result: {error}"));
        assert!(result.has_valid_digest().unwrap_or(false));

        let mut substituted = evidence;
        substituted.candidate_schema_version = "3".to_owned();
        substituted.evidence_digest = substituted
            .calculate_digest()
            .unwrap_or_else(|error| panic!("substituted evidence: {error}"));
        assert!(matches!(
            FixedAdapterResultV1::new(
                &spec,
                1,
                FixedAdapterEvidenceV1::SchemaInspectionEvidence(substituted),
                &[],
            ),
            Err(AdapterResultContractError::EvidenceMismatch)
        ));
    }

    #[test]
    fn complete_health_chain_projects_the_last_chain_bound_observation() {
        let spec = test_health_phase_spec();
        let readiness = FixedAdapterResultV1::new(
            &spec,
            1,
            FixedAdapterEvidenceV1::ReadinessEvidence(
                PhaseObservationEvidenceV1::new(
                    200,
                    EvidenceDigest::sha256("readiness observation"),
                    health_artifacts(&spec, "readiness artifacts")
                        .unwrap_or_else(|error| panic!("readiness artifacts: {error}")),
                )
                .unwrap_or_else(|error| panic!("readiness evidence: {error}")),
            ),
            &[],
        )
        .unwrap_or_else(|error| panic!("readiness result: {error}"));
        let smoke_artifacts = health_artifacts(&spec, "smoke artifacts")
            .unwrap_or_else(|error| panic!("smoke artifacts: {error}"));
        let smoke = FixedAdapterResultV1::new(
            &spec,
            2,
            FixedAdapterEvidenceV1::ConsumerSmokeEvidence(
                PhaseObservationEvidenceV1::new(
                    201,
                    EvidenceDigest::sha256("smoke observation"),
                    smoke_artifacts.clone(),
                )
                .unwrap_or_else(|error| panic!("smoke evidence: {error}")),
            ),
            std::slice::from_ref(&readiness),
        )
        .unwrap_or_else(|error| panic!("smoke result: {error}"));
        let results = [readiness, smoke.clone()];
        let projection = PhaseExecutionProjectionV1::from_results(&spec, &results)
            .unwrap_or_else(|error| panic!("health projection: {error}"));
        assert_eq!(projection.observation_digest, smoke.result_digest);
        assert_eq!(projection.completed_at_ms, 201);
        assert_eq!(projection.artifacts, smoke_artifacts);
        assert!(projection.verified_backup_chain.is_none());
        assert!(matches!(
            PhaseExecutionProjectionV1::from_results(&spec, &results[..1]),
            Err(AdapterResultContractError::IncompleteResultChain)
        ));
    }
}
