use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::domain::{
    EvidenceDigest, InstalledPolicyIdentity, PhaseArtifacts, ProjectId, RelativePolicyPath,
    valid_application_schema_version,
};

pub const BACKUP_UNIT_SCHEMA_VERSION: u16 = 1;
pub const AUTHORIZED_BACKUP_SPEC_SCHEMA_VERSION: u16 = 1;
pub const BACKUP_MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const LOCAL_BACKUP_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const PROVIDER_UPLOAD_RECEIPT_SCHEMA_VERSION: u16 = 1;
pub const OFFSITE_VERIFICATION_SCHEMA_VERSION: u16 = 1;
pub const TRUSTED_CLOCK_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const BACKUP_FRESHNESS_EVIDENCE_SCHEMA_VERSION: u16 = 1;
pub const VERIFIED_BACKUP_CHAIN_SCHEMA_VERSION: u16 = 1;

const MAX_BACKUP_OBJECTS: usize = 16_384;
const MAX_BACKUP_CHECKS: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 96;
const MAX_PROVIDER_OBJECT_ID_BYTES: usize = 512;
const MAX_ALLOWED_BACKUP_AGE_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_TRUSTED_CLOCK_OFFSET_MS: i64 = 30_000;
pub const MAX_TRUSTED_CLOCK_EVIDENCE_AGE_MS: i64 = 30_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSnapshotKindV1 {
    Base,
    Cutover,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupCapturePurposeV1 {
    DeploymentBase,
    DeploymentCutover,
    Scheduled,
    RestoreSafety,
    ControlPlane,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupConsistencyMechanismV1 {
    SqliteOnlineBackupV1,
    QuiescedFilesystemV1,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BackupObjectKindV1 {
    SqliteDatabase,
    Master,
    Blob,
    Configuration,
    PolicyBundle,
    ReleaseBundle,
    SourceLedger,
    GitBundle,
    OciLayout,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedBackupObjectV1 {
    pub path: RelativePolicyPath,
    pub kind: BackupObjectKindV1,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupObjectV1 {
    pub path: RelativePolicyPath,
    pub kind: BackupObjectKindV1,
    pub size_bytes: u64,
    pub sha256: EvidenceDigest,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub hard_link_count: u64,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BackupCheckKindV1 {
    SqliteIntegrity,
    ForeignKeys,
    DatabaseToFiles,
    DomainInvariant,
    StagedReadSmoke,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCheckSpecV1 {
    pub name: String,
    pub kind: BackupCheckKindV1,
    pub definition_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupUnitSpecInputV1 {
    pub unit_id: String,
    pub consistency: BackupConsistencyMechanismV1,
    pub expected_objects: Vec<ExpectedBackupObjectV1>,
    pub primary_sqlite_path: RelativePolicyPath,
    pub required_checks: Vec<BackupCheckSpecV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupUnitSpecV1 {
    pub schema_version: u16,
    pub unit_id: String,
    pub consistency: BackupConsistencyMechanismV1,
    pub expected_objects: Vec<ExpectedBackupObjectV1>,
    pub primary_sqlite_path: RelativePolicyPath,
    pub required_checks: Vec<BackupCheckSpecV1>,
    pub unit_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct BackupUnitDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    unit_id: &'a str,
    consistency: BackupConsistencyMechanismV1,
    expected_objects: &'a [ExpectedBackupObjectV1],
    primary_sqlite_path: &'a RelativePolicyPath,
    required_checks: &'a [BackupCheckSpecV1],
}

impl BackupUnitSpecV1 {
    pub fn new(mut input: BackupUnitSpecInputV1) -> Result<Self, BackupContractError> {
        validate_bounded_identifier(&input.unit_id)?;
        sort_unique_expected_objects(&mut input.expected_objects)?;
        sort_unique_check_specs(&mut input.required_checks)?;
        if input.expected_objects.is_empty()
            || input.expected_objects.len() > MAX_BACKUP_OBJECTS
            || input.required_checks.is_empty()
            || input.required_checks.len() > MAX_BACKUP_CHECKS
        {
            return Err(BackupContractError::InvalidUnitDefinition);
        }
        let primary_count = input
            .expected_objects
            .iter()
            .filter(|object| {
                object.path == input.primary_sqlite_path
                    && object.kind == BackupObjectKindV1::SqliteDatabase
            })
            .count();
        if primary_count != 1
            || input
                .expected_objects
                .iter()
                .filter(|object| object.kind == BackupObjectKindV1::SqliteDatabase)
                .count()
                != 1
            || !has_exact_required_check_kinds(&input.required_checks)
        {
            return Err(BackupContractError::InvalidUnitDefinition);
        }
        let mut unit = Self {
            schema_version: BACKUP_UNIT_SCHEMA_VERSION,
            unit_id: input.unit_id,
            consistency: input.consistency,
            expected_objects: input.expected_objects,
            primary_sqlite_path: input.primary_sqlite_path,
            required_checks: input.required_checks,
            unit_digest: EvidenceDigest::sha256([]),
        };
        unit.unit_digest = unit.calculate_digest()?;
        Ok(unit)
    }

    pub fn has_valid_digest(&self) -> Result<bool, BackupContractError> {
        self.validate_document()?;
        Ok(self.unit_digest == self.calculate_digest()?)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BackupContractError> {
        digest_jcs(&BackupUnitDigestPayload {
            purpose: "rdashboard.backup-unit.v1",
            schema_version: self.schema_version,
            unit_id: &self.unit_id,
            consistency: self.consistency,
            expected_objects: &self.expected_objects,
            primary_sqlite_path: &self.primary_sqlite_path,
            required_checks: &self.required_checks,
        })
    }

    fn validate_document(&self) -> Result<(), BackupContractError> {
        if self.schema_version != BACKUP_UNIT_SCHEMA_VERSION {
            return Err(BackupContractError::UnsupportedSchemaVersion);
        }
        let reconstructed = Self::new(BackupUnitSpecInputV1 {
            unit_id: self.unit_id.clone(),
            consistency: self.consistency,
            expected_objects: self.expected_objects.clone(),
            primary_sqlite_path: self.primary_sqlite_path.clone(),
            required_checks: self.required_checks.clone(),
        })?;
        if reconstructed.expected_objects != self.expected_objects
            || reconstructed.required_checks != self.required_checks
            || reconstructed.unit_digest != self.unit_digest
        {
            return Err(BackupContractError::NonCanonicalDocument);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupProviderV1 {
    GoogleDrive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedBackupSpecInputV1 {
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub phase_intent_digest: EvidenceDigest,
    pub backup_set_id: Uuid,
    pub backup_id: Uuid,
    pub snapshot_kind: BackupSnapshotKindV1,
    pub capture_purpose: BackupCapturePurposeV1,
    pub unit: BackupUnitSpecV1,
    pub recipient_fingerprint: EvidenceDigest,
    pub provider: BackupProviderV1,
    pub provider_credential_version: u64,
    pub capture_deadline_ms: i64,
    pub fencing_epoch: Option<u64>,
    pub fence_receipt_digest: Option<EvidenceDigest>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedBackupSpecV1 {
    pub schema_version: u16,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub installed_policy: InstalledPolicyIdentity,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub phase_intent_digest: EvidenceDigest,
    pub backup_set_id: Uuid,
    pub backup_id: Uuid,
    pub snapshot_kind: BackupSnapshotKindV1,
    pub capture_purpose: BackupCapturePurposeV1,
    pub unit: BackupUnitSpecV1,
    pub recipient_fingerprint: EvidenceDigest,
    pub provider: BackupProviderV1,
    pub provider_credential_version: u64,
    pub capture_deadline_ms: i64,
    pub fencing_epoch: Option<u64>,
    pub fence_receipt_digest: Option<EvidenceDigest>,
    pub spec_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct AuthorizedBackupSpecDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    attempt_id: Uuid,
    project_id: &'a ProjectId,
    installed_policy: &'a InstalledPolicyIdentity,
    installed_rimg_policy_digest: &'a EvidenceDigest,
    phase_intent_digest: &'a EvidenceDigest,
    backup_set_id: Uuid,
    backup_id: Uuid,
    snapshot_kind: BackupSnapshotKindV1,
    capture_purpose: BackupCapturePurposeV1,
    unit: &'a BackupUnitSpecV1,
    recipient_fingerprint: &'a EvidenceDigest,
    provider: BackupProviderV1,
    provider_credential_version: u64,
    capture_deadline_ms: i64,
    fencing_epoch: Option<u64>,
    fence_receipt_digest: &'a Option<EvidenceDigest>,
}

impl AuthorizedBackupSpecV1 {
    pub fn new(input: AuthorizedBackupSpecInputV1) -> Result<Self, BackupContractError> {
        if input.attempt_id.is_nil()
            || input.backup_set_id.is_nil()
            || input.backup_id.is_nil()
            || input.installed_policy.version == 0
            || input.provider_credential_version == 0
            || input.capture_deadline_ms < 0
            || !input.unit.has_valid_digest()?
        {
            return Err(BackupContractError::InvalidIdentity);
        }
        validate_snapshot_binding(
            input.snapshot_kind,
            input.capture_purpose,
            input.fencing_epoch,
            input.fence_receipt_digest.as_ref(),
        )?;
        let mut spec = Self {
            schema_version: AUTHORIZED_BACKUP_SPEC_SCHEMA_VERSION,
            attempt_id: input.attempt_id,
            project_id: input.project_id,
            installed_policy: input.installed_policy,
            installed_rimg_policy_digest: input.installed_rimg_policy_digest,
            phase_intent_digest: input.phase_intent_digest,
            backup_set_id: input.backup_set_id,
            backup_id: input.backup_id,
            snapshot_kind: input.snapshot_kind,
            capture_purpose: input.capture_purpose,
            unit: input.unit,
            recipient_fingerprint: input.recipient_fingerprint,
            provider: input.provider,
            provider_credential_version: input.provider_credential_version,
            capture_deadline_ms: input.capture_deadline_ms,
            fencing_epoch: input.fencing_epoch,
            fence_receipt_digest: input.fence_receipt_digest,
            spec_digest: EvidenceDigest::sha256([]),
        };
        spec.spec_digest = spec.calculate_digest()?;
        Ok(spec)
    }

    pub fn has_valid_digest(&self) -> Result<bool, BackupContractError> {
        self.validate_document()?;
        Ok(self.spec_digest == self.calculate_digest()?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BackupContractError> {
        if !self.has_valid_digest()? {
            return Err(BackupContractError::DigestMismatch);
        }
        canonical_bytes(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, BackupContractError> {
        let spec: Self = decode_canonical(bytes)?;
        if !spec.has_valid_digest()? {
            return Err(BackupContractError::DigestMismatch);
        }
        Ok(spec)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BackupContractError> {
        digest_jcs(&AuthorizedBackupSpecDigestPayload {
            purpose: "rdashboard.authorized-backup-spec.v1",
            schema_version: self.schema_version,
            attempt_id: self.attempt_id,
            project_id: &self.project_id,
            installed_policy: &self.installed_policy,
            installed_rimg_policy_digest: &self.installed_rimg_policy_digest,
            phase_intent_digest: &self.phase_intent_digest,
            backup_set_id: self.backup_set_id,
            backup_id: self.backup_id,
            snapshot_kind: self.snapshot_kind,
            capture_purpose: self.capture_purpose,
            unit: &self.unit,
            recipient_fingerprint: &self.recipient_fingerprint,
            provider: self.provider,
            provider_credential_version: self.provider_credential_version,
            capture_deadline_ms: self.capture_deadline_ms,
            fencing_epoch: self.fencing_epoch,
            fence_receipt_digest: &self.fence_receipt_digest,
        })
    }

    fn validate_document(&self) -> Result<(), BackupContractError> {
        if self.schema_version != AUTHORIZED_BACKUP_SPEC_SCHEMA_VERSION
            || self.attempt_id.is_nil()
            || self.backup_set_id.is_nil()
            || self.backup_id.is_nil()
            || self.installed_policy.version == 0
            || self.provider_credential_version == 0
            || self.capture_deadline_ms < 0
            || !self.unit.has_valid_digest()?
        {
            return Err(BackupContractError::InvalidIdentity);
        }
        validate_snapshot_binding(
            self.snapshot_kind,
            self.capture_purpose,
            self.fencing_epoch,
            self.fence_receipt_digest.as_ref(),
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupCheckOutcomeV1 {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCheckEvidenceV1 {
    pub name: String,
    pub kind: BackupCheckKindV1,
    pub definition_digest: EvidenceDigest,
    pub checked_object_digest: EvidenceDigest,
    pub outcome: BackupCheckOutcomeV1,
    pub observation_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupManifestInputV1 {
    pub application_schema_version: String,
    pub started_at_ms: i64,
    pub completed_at_ms: i64,
    pub objects: Vec<BackupObjectV1>,
    pub checks: Vec<BackupCheckEvidenceV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifestV1 {
    pub schema_version: u16,
    pub authorized_spec_digest: EvidenceDigest,
    pub backup_set_id: Uuid,
    pub backup_id: Uuid,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub snapshot_kind: BackupSnapshotKindV1,
    pub capture_purpose: BackupCapturePurposeV1,
    pub unit_digest: EvidenceDigest,
    pub consistency: BackupConsistencyMechanismV1,
    pub application_schema_version: String,
    pub fencing_epoch: Option<u64>,
    pub fence_receipt_digest: Option<EvidenceDigest>,
    pub started_at_ms: i64,
    pub completed_at_ms: i64,
    pub expected_paths: Vec<RelativePolicyPath>,
    pub objects: Vec<BackupObjectV1>,
    pub missing_paths: Vec<RelativePolicyPath>,
    pub unexpected_paths: Vec<RelativePolicyPath>,
    pub checks: Vec<BackupCheckEvidenceV1>,
    pub manifest_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct BackupManifestDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    authorized_spec_digest: &'a EvidenceDigest,
    backup_set_id: Uuid,
    backup_id: Uuid,
    attempt_id: Uuid,
    project_id: &'a ProjectId,
    snapshot_kind: BackupSnapshotKindV1,
    capture_purpose: BackupCapturePurposeV1,
    unit_digest: &'a EvidenceDigest,
    consistency: BackupConsistencyMechanismV1,
    application_schema_version: &'a str,
    fencing_epoch: Option<u64>,
    fence_receipt_digest: &'a Option<EvidenceDigest>,
    started_at_ms: i64,
    completed_at_ms: i64,
    expected_paths: &'a [RelativePolicyPath],
    objects: &'a [BackupObjectV1],
    missing_paths: &'a [RelativePolicyPath],
    unexpected_paths: &'a [RelativePolicyPath],
    checks: &'a [BackupCheckEvidenceV1],
}

impl BackupManifestV1 {
    pub fn new(
        spec: &AuthorizedBackupSpecV1,
        mut input: BackupManifestInputV1,
    ) -> Result<Self, BackupContractError> {
        if !spec.has_valid_digest()? {
            return Err(BackupContractError::DigestMismatch);
        }
        validate_manifest_metadata(spec, &input)?;
        sort_unique_objects(&mut input.objects)?;
        sort_unique_check_evidence(&mut input.checks)?;
        validate_objects_against_unit(&spec.unit, &input.objects)?;
        validate_checks_against_unit(&spec.unit, &input.objects, &input.checks)?;
        let expected_paths = spec
            .unit
            .expected_objects
            .iter()
            .map(|object| object.path.clone())
            .collect::<Vec<_>>();
        let (missing_paths, unexpected_paths) =
            inventory_differences(&expected_paths, &input.objects);
        let mut manifest = Self {
            schema_version: BACKUP_MANIFEST_SCHEMA_VERSION,
            authorized_spec_digest: spec.spec_digest.clone(),
            backup_set_id: spec.backup_set_id,
            backup_id: spec.backup_id,
            attempt_id: spec.attempt_id,
            project_id: spec.project_id.clone(),
            snapshot_kind: spec.snapshot_kind,
            capture_purpose: spec.capture_purpose,
            unit_digest: spec.unit.unit_digest.clone(),
            consistency: spec.unit.consistency,
            application_schema_version: input.application_schema_version,
            fencing_epoch: spec.fencing_epoch,
            fence_receipt_digest: spec.fence_receipt_digest.clone(),
            started_at_ms: input.started_at_ms,
            completed_at_ms: input.completed_at_ms,
            expected_paths,
            objects: input.objects,
            missing_paths,
            unexpected_paths,
            checks: input.checks,
            manifest_digest: EvidenceDigest::sha256([]),
        };
        manifest.manifest_digest = manifest.calculate_digest()?;
        manifest.require_verified_against(spec)?;
        Ok(manifest)
    }

    pub fn require_verified_against(
        &self,
        spec: &AuthorizedBackupSpecV1,
    ) -> Result<(), BackupContractError> {
        self.validate_document()?;
        if !spec.has_valid_digest()?
            || self.authorized_spec_digest != spec.spec_digest
            || self.backup_set_id != spec.backup_set_id
            || self.backup_id != spec.backup_id
            || self.attempt_id != spec.attempt_id
            || self.project_id != spec.project_id
            || self.snapshot_kind != spec.snapshot_kind
            || self.capture_purpose != spec.capture_purpose
            || self.unit_digest != spec.unit.unit_digest
            || self.consistency != spec.unit.consistency
            || self.fencing_epoch != spec.fencing_epoch
            || self.fence_receipt_digest != spec.fence_receipt_digest
            || !self.missing_paths.is_empty()
            || !self.unexpected_paths.is_empty()
            || self.manifest_digest != self.calculate_digest()?
        {
            return Err(BackupContractError::BackupUnverified);
        }
        validate_objects_against_unit(&spec.unit, &self.objects)?;
        validate_checks_against_unit(&spec.unit, &self.objects, &self.checks)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BackupContractError> {
        self.validate_document()?;
        if self.manifest_digest != self.calculate_digest()? {
            return Err(BackupContractError::DigestMismatch);
        }
        canonical_bytes(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, BackupContractError> {
        let manifest: Self = decode_canonical(bytes)?;
        manifest.validate_document()?;
        if manifest.manifest_digest != manifest.calculate_digest()? {
            return Err(BackupContractError::DigestMismatch);
        }
        Ok(manifest)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BackupContractError> {
        digest_jcs(&BackupManifestDigestPayload {
            purpose: "rdashboard.backup-manifest.v1",
            schema_version: self.schema_version,
            authorized_spec_digest: &self.authorized_spec_digest,
            backup_set_id: self.backup_set_id,
            backup_id: self.backup_id,
            attempt_id: self.attempt_id,
            project_id: &self.project_id,
            snapshot_kind: self.snapshot_kind,
            capture_purpose: self.capture_purpose,
            unit_digest: &self.unit_digest,
            consistency: self.consistency,
            application_schema_version: &self.application_schema_version,
            fencing_epoch: self.fencing_epoch,
            fence_receipt_digest: &self.fence_receipt_digest,
            started_at_ms: self.started_at_ms,
            completed_at_ms: self.completed_at_ms,
            expected_paths: &self.expected_paths,
            objects: &self.objects,
            missing_paths: &self.missing_paths,
            unexpected_paths: &self.unexpected_paths,
            checks: &self.checks,
        })
    }

    fn validate_document(&self) -> Result<(), BackupContractError> {
        if self.schema_version != BACKUP_MANIFEST_SCHEMA_VERSION
            || self.backup_set_id.is_nil()
            || self.backup_id.is_nil()
            || self.attempt_id.is_nil()
            || self.started_at_ms < 0
            || self.completed_at_ms < self.started_at_ms
            || !valid_application_schema_version(&self.application_schema_version)
        {
            return Err(BackupContractError::InvalidManifestMetadata);
        }
        validate_snapshot_binding(
            self.snapshot_kind,
            self.capture_purpose,
            self.fencing_epoch,
            self.fence_receipt_digest.as_ref(),
        )?;
        let mut expected_paths = self.expected_paths.clone();
        sort_unique_paths(&mut expected_paths)?;
        let mut objects = self.objects.clone();
        sort_unique_objects(&mut objects)?;
        let mut checks = self.checks.clone();
        sort_unique_check_evidence(&mut checks)?;
        if expected_paths != self.expected_paths || objects != self.objects || checks != self.checks
        {
            return Err(BackupContractError::NonCanonicalDocument);
        }
        let (missing, unexpected) = inventory_differences(&self.expected_paths, &self.objects);
        if missing != self.missing_paths || unexpected != self.unexpected_paths {
            return Err(BackupContractError::InventoryMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupEncryptionAlgorithmV1 {
    AgeX25519,
}

#[must_use]
pub fn age_x25519_recipient_fingerprint(recipient: &str) -> EvidenceDigest {
    let mut bytes = b"rdashboard.age-x25519-recipient.v1\0".to_vec();
    bytes.extend_from_slice(recipient.as_bytes());
    EvidenceDigest::sha256(bytes)
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupEncryptionEvidenceV1 {
    pub algorithm: BackupEncryptionAlgorithmV1,
    pub authorized_spec_digest: EvidenceDigest,
    pub backup_id: Uuid,
    pub manifest_digest: EvidenceDigest,
    pub plaintext_archive_digest: EvidenceDigest,
    pub recipient_fingerprint: EvidenceDigest,
    pub ciphertext_digest: EvidenceDigest,
    pub ciphertext_size_bytes: u64,
    pub encrypted_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBackupEvidenceV1 {
    pub schema_version: u16,
    pub authorized_spec_digest: EvidenceDigest,
    pub backup_set_id: Uuid,
    pub backup_id: Uuid,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub snapshot_kind: BackupSnapshotKindV1,
    pub manifest_digest: EvidenceDigest,
    pub completed_at_ms: i64,
    pub fencing_epoch: Option<u64>,
    pub encryption: BackupEncryptionEvidenceV1,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct LocalBackupEvidenceDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    authorized_spec_digest: &'a EvidenceDigest,
    backup_set_id: Uuid,
    backup_id: Uuid,
    attempt_id: Uuid,
    project_id: &'a ProjectId,
    snapshot_kind: BackupSnapshotKindV1,
    manifest_digest: &'a EvidenceDigest,
    completed_at_ms: i64,
    fencing_epoch: Option<u64>,
    encryption: &'a BackupEncryptionEvidenceV1,
}

impl LocalBackupEvidenceV1 {
    pub fn new(
        spec: &AuthorizedBackupSpecV1,
        manifest: &BackupManifestV1,
        encryption: BackupEncryptionEvidenceV1,
    ) -> Result<Self, BackupContractError> {
        manifest.require_verified_against(spec)?;
        validate_encryption(spec, manifest, &encryption)?;
        let mut evidence = Self {
            schema_version: LOCAL_BACKUP_EVIDENCE_SCHEMA_VERSION,
            authorized_spec_digest: spec.spec_digest.clone(),
            backup_set_id: spec.backup_set_id,
            backup_id: spec.backup_id,
            attempt_id: spec.attempt_id,
            project_id: spec.project_id.clone(),
            snapshot_kind: spec.snapshot_kind,
            manifest_digest: manifest.manifest_digest.clone(),
            completed_at_ms: manifest.completed_at_ms,
            fencing_epoch: spec.fencing_epoch,
            encryption,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        evidence.evidence_digest = evidence.calculate_digest()?;
        Ok(evidence)
    }

    pub fn require_verified_against(
        &self,
        spec: &AuthorizedBackupSpecV1,
        manifest: &BackupManifestV1,
    ) -> Result<(), BackupContractError> {
        self.validate_document()?;
        manifest.require_verified_against(spec)?;
        validate_encryption(spec, manifest, &self.encryption)?;
        if self.authorized_spec_digest != spec.spec_digest
            || self.backup_set_id != spec.backup_set_id
            || self.backup_id != spec.backup_id
            || self.attempt_id != spec.attempt_id
            || self.project_id != spec.project_id
            || self.snapshot_kind != spec.snapshot_kind
            || self.manifest_digest != manifest.manifest_digest
            || self.completed_at_ms != manifest.completed_at_ms
            || self.fencing_epoch != spec.fencing_epoch
            || self.evidence_digest != self.calculate_digest()?
        {
            return Err(BackupContractError::BackupUnverified);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BackupContractError> {
        digest_jcs(&LocalBackupEvidenceDigestPayload {
            purpose: "rdashboard.local-backup-evidence.v1",
            schema_version: self.schema_version,
            authorized_spec_digest: &self.authorized_spec_digest,
            backup_set_id: self.backup_set_id,
            backup_id: self.backup_id,
            attempt_id: self.attempt_id,
            project_id: &self.project_id,
            snapshot_kind: self.snapshot_kind,
            manifest_digest: &self.manifest_digest,
            completed_at_ms: self.completed_at_ms,
            fencing_epoch: self.fencing_epoch,
            encryption: &self.encryption,
        })
    }

    fn validate_document(&self) -> Result<(), BackupContractError> {
        if self.schema_version != LOCAL_BACKUP_EVIDENCE_SCHEMA_VERSION
            || self.backup_set_id.is_nil()
            || self.backup_id.is_nil()
            || self.attempt_id.is_nil()
            || self.completed_at_ms < 0
            || self.encryption.authorized_spec_digest != self.authorized_spec_digest
            || self.encryption.backup_id != self.backup_id
            || self.encryption.manifest_digest != self.manifest_digest
            || self.encryption.ciphertext_size_bytes == 0
            || self.encryption.encrypted_at_ms < self.completed_at_ms
        {
            return Err(BackupContractError::InvalidEncryptionEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderUploadReceiptInputV1 {
    pub provider: BackupProviderV1,
    pub provider_credential_version: u64,
    pub object_id: String,
    pub version_id: String,
    pub uploaded_at_ms: i64,
    pub provider_receipt_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderUploadReceiptV1 {
    pub schema_version: u16,
    pub authorized_spec_digest: EvidenceDigest,
    pub backup_id: Uuid,
    pub local_evidence_digest: EvidenceDigest,
    pub provider: BackupProviderV1,
    pub provider_credential_version: u64,
    pub object_id: String,
    pub version_id: String,
    pub size_bytes: u64,
    pub ciphertext_digest: EvidenceDigest,
    pub uploaded_at_ms: i64,
    pub provider_receipt_digest: EvidenceDigest,
    pub receipt_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct ProviderUploadReceiptDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    authorized_spec_digest: &'a EvidenceDigest,
    backup_id: Uuid,
    local_evidence_digest: &'a EvidenceDigest,
    provider: BackupProviderV1,
    provider_credential_version: u64,
    object_id: &'a str,
    version_id: &'a str,
    size_bytes: u64,
    ciphertext_digest: &'a EvidenceDigest,
    uploaded_at_ms: i64,
    provider_receipt_digest: &'a EvidenceDigest,
}

impl ProviderUploadReceiptV1 {
    pub fn new(
        spec: &AuthorizedBackupSpecV1,
        local: &LocalBackupEvidenceV1,
        input: ProviderUploadReceiptInputV1,
    ) -> Result<Self, BackupContractError> {
        if local.authorized_spec_digest != spec.spec_digest
            || local.backup_id != spec.backup_id
            || input.provider != spec.provider
            || input.provider_credential_version != spec.provider_credential_version
            || !valid_provider_identifier(&input.object_id)
            || !valid_provider_identifier(&input.version_id)
            || input.uploaded_at_ms < local.encryption.encrypted_at_ms
            || offsite_deadline_applies(spec) && input.uploaded_at_ms > spec.capture_deadline_ms
        {
            return Err(BackupContractError::InvalidOffsiteEvidence);
        }
        let mut receipt = Self {
            schema_version: PROVIDER_UPLOAD_RECEIPT_SCHEMA_VERSION,
            authorized_spec_digest: spec.spec_digest.clone(),
            backup_id: spec.backup_id,
            local_evidence_digest: local.evidence_digest.clone(),
            provider: input.provider,
            provider_credential_version: input.provider_credential_version,
            object_id: input.object_id,
            version_id: input.version_id,
            size_bytes: local.encryption.ciphertext_size_bytes,
            ciphertext_digest: local.encryption.ciphertext_digest.clone(),
            uploaded_at_ms: input.uploaded_at_ms,
            provider_receipt_digest: input.provider_receipt_digest,
            receipt_digest: EvidenceDigest::sha256([]),
        };
        receipt.receipt_digest = receipt.calculate_digest()?;
        Ok(receipt)
    }

    pub fn require_verified_against(
        &self,
        spec: &AuthorizedBackupSpecV1,
        local: &LocalBackupEvidenceV1,
    ) -> Result<(), BackupContractError> {
        if self.schema_version != PROVIDER_UPLOAD_RECEIPT_SCHEMA_VERSION
            || self.authorized_spec_digest != spec.spec_digest
            || self.backup_id != spec.backup_id
            || self.local_evidence_digest != local.evidence_digest
            || self.provider != spec.provider
            || self.provider_credential_version != spec.provider_credential_version
            || self.size_bytes != local.encryption.ciphertext_size_bytes
            || self.ciphertext_digest != local.encryption.ciphertext_digest
            || !valid_provider_identifier(&self.object_id)
            || !valid_provider_identifier(&self.version_id)
            || self.uploaded_at_ms < local.encryption.encrypted_at_ms
            || offsite_deadline_applies(spec) && self.uploaded_at_ms > spec.capture_deadline_ms
            || self.receipt_digest != self.calculate_digest()?
        {
            return Err(BackupContractError::InvalidOffsiteEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BackupContractError> {
        digest_jcs(&ProviderUploadReceiptDigestPayload {
            purpose: "rdashboard.provider-upload-receipt.v1",
            schema_version: self.schema_version,
            authorized_spec_digest: &self.authorized_spec_digest,
            backup_id: self.backup_id,
            local_evidence_digest: &self.local_evidence_digest,
            provider: self.provider,
            provider_credential_version: self.provider_credential_version,
            object_id: &self.object_id,
            version_id: &self.version_id,
            size_bytes: self.size_bytes,
            ciphertext_digest: &self.ciphertext_digest,
            uploaded_at_ms: self.uploaded_at_ms,
            provider_receipt_digest: &self.provider_receipt_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OffsiteVerificationInputV1 {
    pub readback_size_bytes: u64,
    pub readback_ciphertext_digest: EvidenceDigest,
    pub readback_observation_digest: EvidenceDigest,
    pub verified_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OffsiteVerificationEvidenceV1 {
    pub schema_version: u16,
    pub authorized_spec_digest: EvidenceDigest,
    pub backup_id: Uuid,
    pub local_evidence_digest: EvidenceDigest,
    pub upload_receipt_digest: EvidenceDigest,
    pub provider: BackupProviderV1,
    pub object_id: String,
    pub version_id: String,
    pub readback_size_bytes: u64,
    pub readback_ciphertext_digest: EvidenceDigest,
    pub readback_observation_digest: EvidenceDigest,
    pub verified_at_ms: i64,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct OffsiteVerificationDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    authorized_spec_digest: &'a EvidenceDigest,
    backup_id: Uuid,
    local_evidence_digest: &'a EvidenceDigest,
    upload_receipt_digest: &'a EvidenceDigest,
    provider: BackupProviderV1,
    object_id: &'a str,
    version_id: &'a str,
    readback_size_bytes: u64,
    readback_ciphertext_digest: &'a EvidenceDigest,
    readback_observation_digest: &'a EvidenceDigest,
    verified_at_ms: i64,
}

impl OffsiteVerificationEvidenceV1 {
    pub fn new(
        spec: &AuthorizedBackupSpecV1,
        local: &LocalBackupEvidenceV1,
        receipt: &ProviderUploadReceiptV1,
        input: OffsiteVerificationInputV1,
    ) -> Result<Self, BackupContractError> {
        receipt.require_verified_against(spec, local)?;
        if input.readback_size_bytes != local.encryption.ciphertext_size_bytes
            || input.readback_ciphertext_digest != local.encryption.ciphertext_digest
            || input.readback_observation_digest == receipt.provider_receipt_digest
            || input.verified_at_ms < receipt.uploaded_at_ms
            || offsite_deadline_applies(spec) && input.verified_at_ms > spec.capture_deadline_ms
        {
            return Err(BackupContractError::InvalidOffsiteEvidence);
        }
        let mut evidence = Self {
            schema_version: OFFSITE_VERIFICATION_SCHEMA_VERSION,
            authorized_spec_digest: spec.spec_digest.clone(),
            backup_id: spec.backup_id,
            local_evidence_digest: local.evidence_digest.clone(),
            upload_receipt_digest: receipt.receipt_digest.clone(),
            provider: receipt.provider,
            object_id: receipt.object_id.clone(),
            version_id: receipt.version_id.clone(),
            readback_size_bytes: input.readback_size_bytes,
            readback_ciphertext_digest: input.readback_ciphertext_digest,
            readback_observation_digest: input.readback_observation_digest,
            verified_at_ms: input.verified_at_ms,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        evidence.evidence_digest = evidence.calculate_digest()?;
        Ok(evidence)
    }

    pub fn require_verified_against(
        &self,
        spec: &AuthorizedBackupSpecV1,
        local: &LocalBackupEvidenceV1,
        receipt: &ProviderUploadReceiptV1,
    ) -> Result<(), BackupContractError> {
        receipt.require_verified_against(spec, local)?;
        if self.schema_version != OFFSITE_VERIFICATION_SCHEMA_VERSION
            || self.authorized_spec_digest != spec.spec_digest
            || self.backup_id != spec.backup_id
            || self.local_evidence_digest != local.evidence_digest
            || self.upload_receipt_digest != receipt.receipt_digest
            || self.provider != receipt.provider
            || self.object_id != receipt.object_id
            || self.version_id != receipt.version_id
            || self.readback_size_bytes != local.encryption.ciphertext_size_bytes
            || self.readback_ciphertext_digest != local.encryption.ciphertext_digest
            || self.readback_observation_digest == receipt.provider_receipt_digest
            || self.verified_at_ms < receipt.uploaded_at_ms
            || offsite_deadline_applies(spec) && self.verified_at_ms > spec.capture_deadline_ms
            || self.evidence_digest != self.calculate_digest()?
        {
            return Err(BackupContractError::InvalidOffsiteEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BackupContractError> {
        digest_jcs(&OffsiteVerificationDigestPayload {
            purpose: "rdashboard.offsite-verification-evidence.v1",
            schema_version: self.schema_version,
            authorized_spec_digest: &self.authorized_spec_digest,
            backup_id: self.backup_id,
            local_evidence_digest: &self.local_evidence_digest,
            upload_receipt_digest: &self.upload_receipt_digest,
            provider: self.provider,
            object_id: &self.object_id,
            version_id: &self.version_id,
            readback_size_bytes: self.readback_size_bytes,
            readback_ciphertext_digest: &self.readback_ciphertext_digest,
            readback_observation_digest: &self.readback_observation_digest,
            verified_at_ms: self.verified_at_ms,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedBackupChainV1 {
    schema_version: u16,
    snapshot_kind: BackupSnapshotKindV1,
    authorized_spec: AuthorizedBackupSpecV1,
    manifest: BackupManifestV1,
    local: LocalBackupEvidenceV1,
    upload_receipt: Option<ProviderUploadReceiptV1>,
    offsite: Option<OffsiteVerificationEvidenceV1>,
    chain_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct VerifiedBackupChainDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    snapshot_kind: BackupSnapshotKindV1,
    authorized_spec: &'a AuthorizedBackupSpecV1,
    manifest: &'a BackupManifestV1,
    local: &'a LocalBackupEvidenceV1,
    upload_receipt: &'a Option<ProviderUploadReceiptV1>,
    offsite: &'a Option<OffsiteVerificationEvidenceV1>,
}

impl VerifiedBackupChainV1 {
    pub fn new_base(
        spec: &AuthorizedBackupSpecV1,
        manifest: &BackupManifestV1,
        local: &LocalBackupEvidenceV1,
        receipt: &ProviderUploadReceiptV1,
        offsite: &OffsiteVerificationEvidenceV1,
    ) -> Result<Self, BackupContractError> {
        if spec.snapshot_kind != BackupSnapshotKindV1::Base {
            return Err(BackupContractError::InvalidSnapshotBinding);
        }
        let mut chain = Self {
            schema_version: VERIFIED_BACKUP_CHAIN_SCHEMA_VERSION,
            snapshot_kind: BackupSnapshotKindV1::Base,
            authorized_spec: spec.clone(),
            manifest: manifest.clone(),
            local: local.clone(),
            upload_receipt: Some(receipt.clone()),
            offsite: Some(offsite.clone()),
            chain_digest: EvidenceDigest::sha256([]),
        };
        chain.chain_digest = chain.calculate_digest()?;
        chain.require_verified()?;
        Ok(chain)
    }

    pub fn new_cutover(
        spec: &AuthorizedBackupSpecV1,
        manifest: &BackupManifestV1,
        local: &LocalBackupEvidenceV1,
    ) -> Result<Self, BackupContractError> {
        if spec.snapshot_kind != BackupSnapshotKindV1::Cutover {
            return Err(BackupContractError::InvalidSnapshotBinding);
        }
        let mut chain = Self {
            schema_version: VERIFIED_BACKUP_CHAIN_SCHEMA_VERSION,
            snapshot_kind: BackupSnapshotKindV1::Cutover,
            authorized_spec: spec.clone(),
            manifest: manifest.clone(),
            local: local.clone(),
            upload_receipt: None,
            offsite: None,
            chain_digest: EvidenceDigest::sha256([]),
        };
        chain.chain_digest = chain.calculate_digest()?;
        chain.require_verified()?;
        Ok(chain)
    }

    pub fn require_verified(&self) -> Result<(), BackupContractError> {
        if self.schema_version != VERIFIED_BACKUP_CHAIN_SCHEMA_VERSION
            || self.snapshot_kind != self.authorized_spec.snapshot_kind
            || !self.authorized_spec.has_valid_digest()?
        {
            return Err(BackupContractError::BackupUnverified);
        }
        self.local
            .require_verified_against(&self.authorized_spec, &self.manifest)?;
        match (
            self.snapshot_kind,
            self.upload_receipt.as_ref(),
            self.offsite.as_ref(),
        ) {
            (BackupSnapshotKindV1::Base, Some(receipt), Some(offsite)) => {
                receipt.require_verified_against(&self.authorized_spec, &self.local)?;
                offsite.require_verified_against(&self.authorized_spec, &self.local, receipt)?;
            }
            (BackupSnapshotKindV1::Cutover, None, None) => {}
            _ => return Err(BackupContractError::InvalidSnapshotBinding),
        }
        if self.chain_digest != self.calculate_digest()? {
            return Err(BackupContractError::DigestMismatch);
        }
        Ok(())
    }

    pub fn require_verified_against(
        &self,
        expected_spec: &AuthorizedBackupSpecV1,
    ) -> Result<(), BackupContractError> {
        self.require_verified()?;
        if &self.authorized_spec != expected_spec {
            return Err(BackupContractError::BackupUnverified);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BackupContractError> {
        self.require_verified()?;
        canonical_bytes(self)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, BackupContractError> {
        let chain: Self = decode_canonical(bytes)?;
        chain.require_verified()?;
        Ok(chain)
    }

    pub const fn snapshot_kind(&self) -> BackupSnapshotKindV1 {
        self.snapshot_kind
    }

    pub const fn authorized_spec(&self) -> &AuthorizedBackupSpecV1 {
        &self.authorized_spec
    }

    pub const fn manifest(&self) -> &BackupManifestV1 {
        &self.manifest
    }

    pub const fn local(&self) -> &LocalBackupEvidenceV1 {
        &self.local
    }

    pub const fn upload_receipt(&self) -> Option<&ProviderUploadReceiptV1> {
        self.upload_receipt.as_ref()
    }

    pub const fn offsite(&self) -> Option<&OffsiteVerificationEvidenceV1> {
        self.offsite.as_ref()
    }

    pub const fn chain_digest(&self) -> &EvidenceDigest {
        &self.chain_digest
    }

    pub fn verification_completed_at_ms(&self) -> Result<i64, BackupContractError> {
        self.require_verified()?;
        Ok(self
            .offsite
            .as_ref()
            .map_or(self.local.encryption.encrypted_at_ms, |offsite| {
                offsite.verified_at_ms
            }))
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BackupContractError> {
        digest_jcs(&VerifiedBackupChainDigestPayload {
            purpose: "rdashboard.verified-backup-chain.v1",
            schema_version: self.schema_version,
            snapshot_kind: self.snapshot_kind,
            authorized_spec: &self.authorized_spec,
            manifest: &self.manifest,
            local: &self.local,
            upload_receipt: &self.upload_receipt,
            offsite: &self.offsite,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedClockEvidenceV1 {
    pub schema_version: u16,
    pub synchronized: bool,
    pub estimated_offset_ms: i64,
    pub observed_at_ms: i64,
    pub observation_digest: EvidenceDigest,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct TrustedClockDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    synchronized: bool,
    estimated_offset_ms: i64,
    observed_at_ms: i64,
    observation_digest: &'a EvidenceDigest,
}

impl TrustedClockEvidenceV1 {
    pub fn new(
        synchronized: bool,
        estimated_offset_ms: i64,
        observed_at_ms: i64,
        observation_digest: EvidenceDigest,
    ) -> Result<Self, BackupContractError> {
        if observed_at_ms < 0 || estimated_offset_ms == i64::MIN {
            return Err(BackupContractError::ClockUnsynchronized);
        }
        let mut evidence = Self {
            schema_version: TRUSTED_CLOCK_EVIDENCE_SCHEMA_VERSION,
            synchronized,
            estimated_offset_ms,
            observed_at_ms,
            observation_digest,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        evidence.evidence_digest = evidence.calculate_digest()?;
        evidence.require_synchronized()?;
        Ok(evidence)
    }

    pub fn require_synchronized(&self) -> Result<(), BackupContractError> {
        if self.schema_version != TRUSTED_CLOCK_EVIDENCE_SCHEMA_VERSION
            || !self.synchronized
            || self.estimated_offset_ms == i64::MIN
            || self.estimated_offset_ms.abs() > MAX_TRUSTED_CLOCK_OFFSET_MS
            || self.observed_at_ms < 0
            || self.evidence_digest != self.calculate_digest()?
        {
            return Err(BackupContractError::ClockUnsynchronized);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BackupContractError> {
        digest_jcs(&TrustedClockDigestPayload {
            purpose: "rdashboard.trusted-clock-evidence.v1",
            schema_version: self.schema_version,
            synchronized: self.synchronized,
            estimated_offset_ms: self.estimated_offset_ms,
            observed_at_ms: self.observed_at_ms,
            observation_digest: &self.observation_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupFreshnessEvidenceV1 {
    pub schema_version: u16,
    pub backup_id: Uuid,
    pub verified_chain_digest: EvidenceDigest,
    pub local_evidence_digest: EvidenceDigest,
    pub offsite_evidence_digest: Option<EvidenceDigest>,
    pub trusted_clock_evidence_digest: EvidenceDigest,
    pub trusted_clock_observed_at_ms: i64,
    pub completed_at_ms: i64,
    pub evaluated_at_ms: i64,
    pub age_ms: i64,
    pub max_age_ms: i64,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct BackupFreshnessDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    backup_id: Uuid,
    verified_chain_digest: &'a EvidenceDigest,
    local_evidence_digest: &'a EvidenceDigest,
    offsite_evidence_digest: &'a Option<EvidenceDigest>,
    trusted_clock_evidence_digest: &'a EvidenceDigest,
    trusted_clock_observed_at_ms: i64,
    completed_at_ms: i64,
    evaluated_at_ms: i64,
    age_ms: i64,
    max_age_ms: i64,
}

impl BackupFreshnessEvidenceV1 {
    pub fn new(
        chain: &VerifiedBackupChainV1,
        clock: &TrustedClockEvidenceV1,
        boundary_now_ms: i64,
        max_age_ms: i64,
        require_offsite: bool,
    ) -> Result<Self, BackupContractError> {
        chain.require_verified()?;
        validate_freshness_policy(max_age_ms, require_offsite, chain)?;
        validate_clock_at_boundary(clock, boundary_now_ms)?;
        let local = chain.local();
        if boundary_now_ms < chain.verification_completed_at_ms()? {
            return Err(BackupContractError::BackupStale);
        }
        let age_ms = elapsed_ms(boundary_now_ms, local.completed_at_ms)?;
        if age_ms > max_age_ms {
            return Err(BackupContractError::BackupStale);
        }
        let mut evidence = Self {
            schema_version: BACKUP_FRESHNESS_EVIDENCE_SCHEMA_VERSION,
            backup_id: local.backup_id,
            verified_chain_digest: chain.chain_digest().clone(),
            local_evidence_digest: local.evidence_digest.clone(),
            offsite_evidence_digest: chain.offsite().map(|value| value.evidence_digest.clone()),
            trusted_clock_evidence_digest: clock.evidence_digest.clone(),
            trusted_clock_observed_at_ms: clock.observed_at_ms,
            completed_at_ms: local.completed_at_ms,
            evaluated_at_ms: boundary_now_ms,
            age_ms,
            max_age_ms,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        evidence.evidence_digest = evidence.calculate_digest()?;
        Ok(evidence)
    }

    pub fn require_current(
        &self,
        chain: &VerifiedBackupChainV1,
        fresh_clock: &TrustedClockEvidenceV1,
        boundary_now_ms: i64,
        required_max_age_ms: i64,
        require_offsite: bool,
    ) -> Result<(), BackupContractError> {
        self.require_verified_against_chain(chain, required_max_age_ms, require_offsite)?;
        validate_clock_at_boundary(fresh_clock, boundary_now_ms)?;
        if fresh_clock.evidence_digest == self.trusted_clock_evidence_digest
            || fresh_clock.observed_at_ms <= self.evaluated_at_ms
            || boundary_now_ms <= self.evaluated_at_ms
            || boundary_now_ms < chain.verification_completed_at_ms()?
        {
            return Err(BackupContractError::BackupStale);
        }
        let current_age_ms = elapsed_ms(boundary_now_ms, chain.local().completed_at_ms)?;
        if current_age_ms > required_max_age_ms {
            return Err(BackupContractError::BackupStale);
        }
        Ok(())
    }

    fn require_verified_against_chain(
        &self,
        chain: &VerifiedBackupChainV1,
        required_max_age_ms: i64,
        require_offsite: bool,
    ) -> Result<(), BackupContractError> {
        chain.require_verified()?;
        validate_freshness_policy(required_max_age_ms, require_offsite, chain)?;
        let local = chain.local();
        let expected_offsite_digest = chain.offsite().map(|value| value.evidence_digest.clone());
        let recorded_age_ms = elapsed_ms(self.evaluated_at_ms, self.completed_at_ms)?;
        let clock_evidence_age_ms =
            elapsed_ms(self.evaluated_at_ms, self.trusted_clock_observed_at_ms)?;
        if self.schema_version != BACKUP_FRESHNESS_EVIDENCE_SCHEMA_VERSION
            || self.backup_id != local.backup_id
            || self.verified_chain_digest != *chain.chain_digest()
            || self.local_evidence_digest != local.evidence_digest
            || self.offsite_evidence_digest != expected_offsite_digest
            || self.completed_at_ms != local.completed_at_ms
            || self.evaluated_at_ms < chain.verification_completed_at_ms()?
            || self.age_ms != recorded_age_ms
            || self.max_age_ms != required_max_age_ms
            || recorded_age_ms > required_max_age_ms
            || clock_evidence_age_ms > MAX_TRUSTED_CLOCK_EVIDENCE_AGE_MS
        {
            return Err(BackupContractError::BackupStale);
        }
        if self.evidence_digest != self.calculate_digest()? {
            return Err(BackupContractError::DigestMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, BackupContractError> {
        digest_jcs(&BackupFreshnessDigestPayload {
            purpose: "rdashboard.backup-freshness-evidence.v1",
            schema_version: self.schema_version,
            backup_id: self.backup_id,
            verified_chain_digest: &self.verified_chain_digest,
            local_evidence_digest: &self.local_evidence_digest,
            offsite_evidence_digest: &self.offsite_evidence_digest,
            trusted_clock_evidence_digest: &self.trusted_clock_evidence_digest,
            trusted_clock_observed_at_ms: self.trusted_clock_observed_at_ms,
            completed_at_ms: self.completed_at_ms,
            evaluated_at_ms: self.evaluated_at_ms,
            age_ms: self.age_ms,
            max_age_ms: self.max_age_ms,
        })
    }
}

fn validate_freshness_policy(
    max_age_ms: i64,
    require_offsite: bool,
    chain: &VerifiedBackupChainV1,
) -> Result<(), BackupContractError> {
    if max_age_ms <= 0
        || max_age_ms > MAX_ALLOWED_BACKUP_AGE_MS
        || require_offsite && chain.offsite().is_none()
    {
        return Err(BackupContractError::BackupStale);
    }
    Ok(())
}

fn validate_clock_at_boundary(
    clock: &TrustedClockEvidenceV1,
    boundary_now_ms: i64,
) -> Result<(), BackupContractError> {
    clock.require_synchronized()?;
    let evidence_age_ms = elapsed_ms(boundary_now_ms, clock.observed_at_ms)?;
    if evidence_age_ms > MAX_TRUSTED_CLOCK_EVIDENCE_AGE_MS {
        return Err(BackupContractError::BackupStale);
    }
    Ok(())
}

fn elapsed_ms(later_ms: i64, earlier_ms: i64) -> Result<i64, BackupContractError> {
    if earlier_ms < 0 {
        return Err(BackupContractError::BackupStale);
    }
    later_ms
        .checked_sub(earlier_ms)
        .filter(|elapsed| *elapsed >= 0)
        .ok_or(BackupContractError::BackupStale)
}

pub fn base_phase_artifacts(
    spec: &AuthorizedBackupSpecV1,
    manifest: &BackupManifestV1,
    local: &LocalBackupEvidenceV1,
    receipt: &ProviderUploadReceiptV1,
    offsite: &OffsiteVerificationEvidenceV1,
) -> Result<PhaseArtifacts, BackupContractError> {
    let chain = VerifiedBackupChainV1::new_base(spec, manifest, local, receipt, offsite)?;
    Ok(PhaseArtifacts {
        backup_set_id: Some(spec.backup_set_id),
        base_backup_id: Some(spec.backup_id),
        base_backup_manifest_digest: Some(chain.manifest().manifest_digest.clone()),
        base_backup_evidence_digest: Some(chain.local().evidence_digest.clone()),
        base_backup_offsite_evidence_digest: chain
            .offsite()
            .map(|evidence| evidence.evidence_digest.clone()),
        base_backup_verification_digest: Some(chain.chain_digest().clone()),
        ..PhaseArtifacts::default()
    })
}

pub fn cutover_phase_artifacts(
    spec: &AuthorizedBackupSpecV1,
    manifest: &BackupManifestV1,
    local: &LocalBackupEvidenceV1,
) -> Result<PhaseArtifacts, BackupContractError> {
    let chain = VerifiedBackupChainV1::new_cutover(spec, manifest, local)?;
    Ok(PhaseArtifacts {
        backup_set_id: Some(spec.backup_set_id),
        cutover_backup_id: Some(spec.backup_id),
        cutover_backup_manifest_digest: Some(chain.manifest().manifest_digest.clone()),
        cutover_backup_evidence_digest: Some(chain.local().evidence_digest.clone()),
        cutover_backup_verification_digest: Some(chain.chain_digest().clone()),
        fencing_epoch: spec.fencing_epoch,
        ..PhaseArtifacts::default()
    })
}

fn validate_manifest_metadata(
    spec: &AuthorizedBackupSpecV1,
    input: &BackupManifestInputV1,
) -> Result<(), BackupContractError> {
    if input.started_at_ms < 0
        || input.completed_at_ms < input.started_at_ms
        || input.completed_at_ms > spec.capture_deadline_ms
        || !valid_application_schema_version(&input.application_schema_version)
        || input.objects.is_empty()
        || input.objects.len() > MAX_BACKUP_OBJECTS
        || input.checks.is_empty()
        || input.checks.len() > MAX_BACKUP_CHECKS
    {
        return Err(BackupContractError::InvalidManifestMetadata);
    }
    Ok(())
}

fn validate_encryption(
    spec: &AuthorizedBackupSpecV1,
    manifest: &BackupManifestV1,
    encryption: &BackupEncryptionEvidenceV1,
) -> Result<(), BackupContractError> {
    if encryption.authorized_spec_digest != spec.spec_digest
        || encryption.backup_id != spec.backup_id
        || encryption.manifest_digest != manifest.manifest_digest
        || encryption.recipient_fingerprint != spec.recipient_fingerprint
        || encryption.ciphertext_size_bytes == 0
        || encryption.encrypted_at_ms < manifest.completed_at_ms
        || encryption.encrypted_at_ms > spec.capture_deadline_ms
    {
        return Err(BackupContractError::InvalidEncryptionEvidence);
    }
    Ok(())
}

const fn offsite_deadline_applies(spec: &AuthorizedBackupSpecV1) -> bool {
    matches!(spec.snapshot_kind, BackupSnapshotKindV1::Base)
}

fn validate_objects_against_unit(
    unit: &BackupUnitSpecV1,
    objects: &[BackupObjectV1],
) -> Result<(), BackupContractError> {
    let expected = unit
        .expected_objects
        .iter()
        .map(|object| (object.path.as_str(), object))
        .collect::<BTreeMap<_, _>>();
    for object in objects {
        if object.mode > 0o777 || object.hard_link_count != 1 {
            return Err(BackupContractError::InvalidObjectMetadata);
        }
        if let Some(contract) = expected.get(object.path.as_str())
            && (object.kind != contract.kind
                || object.uid != contract.uid
                || object.gid != contract.gid
                || object.mode != contract.mode)
        {
            return Err(BackupContractError::InvalidObjectMetadata);
        }
    }
    Ok(())
}

fn validate_checks_against_unit(
    unit: &BackupUnitSpecV1,
    objects: &[BackupObjectV1],
    checks: &[BackupCheckEvidenceV1],
) -> Result<(), BackupContractError> {
    let database_digest = objects
        .iter()
        .find(|object| object.path == unit.primary_sqlite_path)
        .map(|object| &object.sha256)
        .ok_or(BackupContractError::BackupUnverified)?;
    if checks.len() != unit.required_checks.len() {
        return Err(BackupContractError::BackupUnverified);
    }
    for (contract, evidence) in unit.required_checks.iter().zip(checks) {
        if evidence.name != contract.name
            || evidence.kind != contract.kind
            || evidence.definition_digest != contract.definition_digest
            || &evidence.checked_object_digest != database_digest
            || evidence.outcome != BackupCheckOutcomeV1::Passed
        {
            return Err(BackupContractError::BackupUnverified);
        }
    }
    Ok(())
}

fn validate_snapshot_binding(
    kind: BackupSnapshotKindV1,
    purpose: BackupCapturePurposeV1,
    fencing_epoch: Option<u64>,
    fence_receipt_digest: Option<&EvidenceDigest>,
) -> Result<(), BackupContractError> {
    match (kind, purpose, fencing_epoch, fence_receipt_digest) {
        (
            BackupSnapshotKindV1::Base,
            BackupCapturePurposeV1::DeploymentBase
            | BackupCapturePurposeV1::Scheduled
            | BackupCapturePurposeV1::RestoreSafety
            | BackupCapturePurposeV1::ControlPlane,
            None,
            None,
        )
        | (
            BackupSnapshotKindV1::Cutover,
            BackupCapturePurposeV1::DeploymentCutover,
            Some(1..),
            Some(_),
        ) => Ok(()),
        _ => Err(BackupContractError::InvalidSnapshotBinding),
    }
}

fn has_exact_required_check_kinds(checks: &[BackupCheckSpecV1]) -> bool {
    for required in [
        BackupCheckKindV1::SqliteIntegrity,
        BackupCheckKindV1::ForeignKeys,
        BackupCheckKindV1::DatabaseToFiles,
        BackupCheckKindV1::StagedReadSmoke,
    ] {
        if checks.iter().filter(|check| check.kind == required).count() != 1 {
            return false;
        }
    }
    checks
        .iter()
        .any(|check| check.kind == BackupCheckKindV1::DomainInvariant)
}

fn sort_unique_expected_objects(
    objects: &mut [ExpectedBackupObjectV1],
) -> Result<(), BackupContractError> {
    objects.sort_by(|left, right| left.path.as_str().cmp(right.path.as_str()));
    if objects.windows(2).any(|pair| pair[0].path == pair[1].path)
        || objects.iter().any(|object| object.mode > 0o777)
    {
        return Err(BackupContractError::InvalidUnitDefinition);
    }
    Ok(())
}

fn sort_unique_check_specs(checks: &mut [BackupCheckSpecV1]) -> Result<(), BackupContractError> {
    checks.sort_by(|left, right| left.name.cmp(&right.name));
    if checks.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(BackupContractError::DuplicateCheck);
    }
    for check in checks {
        validate_bounded_identifier(&check.name)?;
    }
    Ok(())
}

fn sort_unique_check_evidence(
    checks: &mut [BackupCheckEvidenceV1],
) -> Result<(), BackupContractError> {
    checks.sort_by(|left, right| left.name.cmp(&right.name));
    if checks.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(BackupContractError::DuplicateCheck);
    }
    for check in checks {
        validate_bounded_identifier(&check.name)?;
    }
    Ok(())
}

fn sort_unique_paths(paths: &mut [RelativePolicyPath]) -> Result<(), BackupContractError> {
    paths.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    if paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(BackupContractError::DuplicatePath);
    }
    Ok(())
}

fn sort_unique_objects(objects: &mut [BackupObjectV1]) -> Result<(), BackupContractError> {
    objects.sort_by(|left, right| left.path.as_str().cmp(right.path.as_str()));
    if objects.windows(2).any(|pair| pair[0].path == pair[1].path) {
        return Err(BackupContractError::DuplicatePath);
    }
    Ok(())
}

fn inventory_differences(
    expected_paths: &[RelativePolicyPath],
    objects: &[BackupObjectV1],
) -> (Vec<RelativePolicyPath>, Vec<RelativePolicyPath>) {
    let expected = expected_paths
        .iter()
        .map(|path| (path.as_str(), path))
        .collect::<BTreeMap<_, _>>();
    let actual = objects
        .iter()
        .map(|object| (object.path.as_str(), &object.path))
        .collect::<BTreeMap<_, _>>();
    let missing = expected
        .iter()
        .filter(|(path, _)| !actual.contains_key(*path))
        .map(|(_, path)| (*path).clone())
        .collect();
    let unexpected = actual
        .iter()
        .filter(|(path, _)| !expected.contains_key(*path))
        .map(|(_, path)| (*path).clone())
        .collect();
    (missing, unexpected)
}

fn validate_bounded_identifier(value: &str) -> Result<(), BackupContractError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(BackupContractError::InvalidIdentifier);
    }
    Ok(())
}

fn valid_provider_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_OBJECT_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\'' | b'\\'))
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, BackupContractError> {
    Ok(serde_jcs::to_vec(value)?)
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, BackupContractError>
where
    T: DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice::<T>(bytes)?;
    if serde_jcs::to_vec(&value)? != bytes {
        return Err(BackupContractError::NonCanonicalDocument);
    }
    Ok(value)
}

fn digest_jcs<T: Serialize>(value: &T) -> Result<EvidenceDigest, BackupContractError> {
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(value)?))
}

#[derive(Debug, thiserror::Error)]
pub enum BackupContractError {
    #[error("unsupported backup contract schema version")]
    UnsupportedSchemaVersion,
    #[error("backup identity, installed policy, deadline or credential version is invalid")]
    InvalidIdentity,
    #[error("backup unit definition is incomplete or inconsistent")]
    InvalidUnitDefinition,
    #[error("backup identifiers must be canonical and bounded")]
    InvalidIdentifier,
    #[error("backup paths must be unique")]
    DuplicatePath,
    #[error("backup checks must be unique")]
    DuplicateCheck,
    #[error("backup snapshot kind, purpose and fence evidence are inconsistent")]
    InvalidSnapshotBinding,
    #[error("backup manifest metadata or deadline is invalid")]
    InvalidManifestMetadata,
    #[error("backup object metadata violates the installed backup unit")]
    InvalidObjectMetadata,
    #[error("backup missing/unexpected inventory is inconsistent")]
    InventoryMismatch,
    #[error("backup manifest or check evidence is not verified against its authorization")]
    BackupUnverified,
    #[error("backup encryption does not match its manifest, recipient or authorization")]
    InvalidEncryptionEvidence,
    #[error("provider upload or read-back evidence is invalid")]
    InvalidOffsiteEvidence,
    #[error("trusted clock is unsynchronized or outside the allowed offset")]
    ClockUnsynchronized,
    #[error("backup is stale, from the future or missing required offsite evidence")]
    BackupStale,
    #[error("canonical backup document has a digest mismatch")]
    DigestMismatch,
    #[error("backup document is not in canonical JCS form")]
    NonCanonicalDocument,
    #[error("canonical backup encoding failed: {0}")]
    CanonicalEncoding(#[from] serde_json::Error),
}
