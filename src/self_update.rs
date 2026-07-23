use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read as _, Seek as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    str::FromStr as _,
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::domain::{EvidenceDigest, GitCommitId, ProjectId};

pub const SELF_RELEASE_SCHEMA_VERSION: u16 = 1;
pub const SELF_UPDATE_POLICY_SCHEMA_VERSION: u16 = 1;
pub const SELF_UPDATE_BOOTSTRAP_PROTOCOL_V1: u16 = 1;
pub const SELF_RELEASE_DESCRIPTOR_FILE: &str = "release.jcs";
pub const SELF_RELEASE_ARCHIVE_FILE: &str = "release.tar";

#[cfg(test)]
pub(crate) static SELF_UPDATE_FILESYSTEM_TEST_LOCK: Mutex<()> = Mutex::new(());

const SELF_RELEASE_PURPOSE: &str = "rdashboard.self-release.v1";
const SELF_RELEASE_SIGNATURE_DOMAIN: &str = "rdashboard.self-release-signature.v1";
const SELF_UPDATE_POLICY_PURPOSE: &str = "rdashboard.self-update-policy.v1";

pub const SELF_UPDATE_CURRENT_BIN_ROOT: &str = "/var/lib/rdashboard-bootstrap/current/bin";
pub const CURRENT_ADAPTER_RECEIPT_EXECUTABLE: &str =
    "/var/lib/rdashboard-bootstrap/current/bin/rdashboard-adapter-receipt";
pub const CURRENT_WORKFLOW_JOB_EXECUTABLE: &str =
    "/var/lib/rdashboard-bootstrap/current/bin/rdashboard-workflow-job";
pub const CURRENT_ROOTLESS_OCI_BUILD_EXECUTABLE: &str =
    "/var/lib/rdashboard-bootstrap/current/bin/rdashboard-workflow-oci-build";
pub const CURRENT_SELF_RELEASE_BUILD_EXECUTABLE: &str =
    "/var/lib/rdashboard-bootstrap/current/bin/rdashboard-workflow-self-release-build";

/// The complete application payload advanced by the A/B `current` pointer.
///
/// The bootstrap supervisor and policy-pinned external adapters deliberately stay outside this
/// set so recovery remains available when an application release is invalid.
pub const VERSIONED_SELF_RELEASE_BINARIES: &[&str] = &[
    "rdashboard-adapter-receipt",
    "rdashboard-dependency-fetcher",
    "rdashboard-executor",
    "rdashboard-native-release",
    "rdashboard-observer",
    "rdashboard-rimg-health-proxy",
    "rdashboard-source",
    "rdashboard-source-dispatcher",
    "rdashboard-source-ingress",
    "rdashboard-titanium",
    "rdashboard-worker",
    "rdashboard-workflow-gateway",
    "rdashboard-workflow-job",
    "rdashboard-workflow-launcher",
    "rdashboard-workflow-oci-build",
    "rdashboard-workflow-self-release-build",
    "rdashboardd",
];
const MAX_RELEASE_FILES: usize = 64;
const MAX_RELEASE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RELEASE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DESCRIPTOR_BYTES: u64 = 256 * 1024;
const MAX_RELEASE_PATH_BYTES: usize = 160;
const MAX_KEY_ID_BYTES: usize = 96;
const MAX_SIGNATURE_VALIDITY_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfReleaseFileV1 {
    pub path: String,
    pub mode: u32,
    pub bytes: u64,
    pub sha256: EvidenceDigest,
}

impl SelfReleaseFileV1 {
    fn validate(&self) -> Result<(), SelfUpdateError> {
        if !valid_release_path(&self.path)
            || !matches!(self.mode, 0o444 | 0o555)
            || self.bytes == 0
            || self.bytes > MAX_RELEASE_FILE_BYTES
        {
            return Err(SelfUpdateError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfReleaseManifestInputV1 {
    pub source_head: GitCommitId,
    pub source_sequence: u64,
    pub source_attestation_digest: EvidenceDigest,
    pub workflow_policy_digest: EvidenceDigest,
    pub verification_receipt_digest: EvidenceDigest,
    pub runtime_contract_digest: EvidenceDigest,
    pub state_schema_version: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfReleaseManifestV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub source_head: GitCommitId,
    pub source_sequence: u64,
    pub source_attestation_digest: EvidenceDigest,
    pub workflow_policy_digest: EvidenceDigest,
    pub verification_receipt_digest: EvidenceDigest,
    pub runtime_contract_digest: EvidenceDigest,
    pub bootstrap_protocol: u16,
    pub state_schema_version: u32,
    pub files: Vec<SelfReleaseFileV1>,
    pub total_bytes: u64,
    pub manifest_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct SelfReleaseManifestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a ProjectId,
    source_head: &'a GitCommitId,
    source_sequence: u64,
    source_attestation_digest: &'a EvidenceDigest,
    workflow_policy_digest: &'a EvidenceDigest,
    verification_receipt_digest: &'a EvidenceDigest,
    runtime_contract_digest: &'a EvidenceDigest,
    bootstrap_protocol: u16,
    state_schema_version: u32,
    files: &'a [SelfReleaseFileV1],
    total_bytes: u64,
}

impl SelfReleaseManifestV1 {
    pub fn new(
        input: SelfReleaseManifestInputV1,
        mut files: Vec<SelfReleaseFileV1>,
    ) -> Result<Self, SelfUpdateError> {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let total_bytes = files.iter().try_fold(0_u64, |total, file| {
            total
                .checked_add(file.bytes)
                .ok_or(SelfUpdateError::InvalidManifest)
        })?;
        let mut manifest = Self {
            purpose: SELF_RELEASE_PURPOSE.to_owned(),
            schema_version: SELF_RELEASE_SCHEMA_VERSION,
            project_id: ProjectId::from_str("rdashboard")
                .map_err(|_| SelfUpdateError::InvalidManifest)?,
            source_head: input.source_head,
            source_sequence: input.source_sequence,
            source_attestation_digest: input.source_attestation_digest,
            workflow_policy_digest: input.workflow_policy_digest,
            verification_receipt_digest: input.verification_receipt_digest,
            runtime_contract_digest: input.runtime_contract_digest,
            bootstrap_protocol: SELF_UPDATE_BOOTSTRAP_PROTOCOL_V1,
            state_schema_version: input.state_schema_version,
            files,
            total_bytes,
            manifest_digest: EvidenceDigest::sha256([]),
        };
        manifest.manifest_digest = manifest.calculate_digest()?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), SelfUpdateError> {
        let rdashboard =
            ProjectId::from_str("rdashboard").map_err(|_| SelfUpdateError::InvalidManifest)?;
        if self.purpose != SELF_RELEASE_PURPOSE
            || self.schema_version != SELF_RELEASE_SCHEMA_VERSION
            || self.project_id != rdashboard
            || self.source_sequence == 0
            || self.bootstrap_protocol != SELF_UPDATE_BOOTSTRAP_PROTOCOL_V1
            || self.state_schema_version == 0
            || self.files.is_empty()
            || self.files.len() > MAX_RELEASE_FILES
            || self.total_bytes == 0
            || self.total_bytes > MAX_RELEASE_BYTES
            || !strictly_sorted_unique_paths(&self.files)
            || self.files.iter().any(|file| file.validate().is_err())
            || self.files.iter().map(|file| file.bytes).sum::<u64>() != self.total_bytes
            || self.manifest_digest != self.calculate_digest()?
        {
            return Err(SelfUpdateError::InvalidManifest);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SelfUpdateError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SelfUpdateError> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_DESCRIPTOR_BYTES)
        {
            return Err(SelfUpdateError::InvalidManifest);
        }
        let manifest: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&manifest)? != bytes {
            return Err(SelfUpdateError::NoncanonicalDocument);
        }
        manifest.validate()?;
        Ok(manifest)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, SelfUpdateError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &SelfReleaseManifestPayload {
                purpose: SELF_RELEASE_PURPOSE,
                schema_version: SELF_RELEASE_SCHEMA_VERSION,
                project_id: &self.project_id,
                source_head: &self.source_head,
                source_sequence: self.source_sequence,
                source_attestation_digest: &self.source_attestation_digest,
                workflow_policy_digest: &self.workflow_policy_digest,
                verification_receipt_digest: &self.verification_receipt_digest,
                runtime_contract_digest: &self.runtime_contract_digest,
                bootstrap_protocol: self.bootstrap_protocol,
                state_schema_version: self.state_schema_version,
                files: &self.files,
                total_bytes: self.total_bytes,
            },
        )?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfReleaseSignatureInputV1 {
    pub key_id: String,
    pub key_epoch: u64,
    pub archive_digest: EvidenceDigest,
    pub archive_bytes: u64,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSelfReleaseV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub manifest: SelfReleaseManifestV1,
    pub key_id: String,
    pub key_epoch: u64,
    pub archive_digest: EvidenceDigest,
    pub archive_bytes: u64,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub payload_digest: EvidenceDigest,
    pub signature: String,
}

#[derive(Serialize)]
struct SignedSelfReleasePayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    manifest: &'a SelfReleaseManifestV1,
    key_id: &'a str,
    key_epoch: u64,
    archive_digest: &'a EvidenceDigest,
    archive_bytes: u64,
    issued_at_ms: i64,
    expires_at_ms: i64,
}

impl SignedSelfReleaseV1 {
    pub fn issue(
        manifest: SelfReleaseManifestV1,
        input: SelfReleaseSignatureInputV1,
        signing_key: &SigningKey,
    ) -> Result<Self, SelfUpdateError> {
        manifest.validate()?;
        let mut release = Self {
            purpose: SELF_RELEASE_SIGNATURE_DOMAIN.to_owned(),
            schema_version: SELF_RELEASE_SCHEMA_VERSION,
            manifest,
            key_id: input.key_id,
            key_epoch: input.key_epoch,
            archive_digest: input.archive_digest,
            archive_bytes: input.archive_bytes,
            issued_at_ms: input.issued_at_ms,
            expires_at_ms: input.expires_at_ms,
            payload_digest: EvidenceDigest::sha256([]),
            signature: String::new(),
        };
        let payload = release.payload_bytes()?;
        release.payload_digest = EvidenceDigest::sha256(&payload);
        release.signature = URL_SAFE_NO_PAD.encode(signing_key.sign(&payload).to_bytes());
        release.validate_shape()?;
        Ok(release)
    }

    pub fn verify(
        &self,
        policy: &InstalledSelfUpdatePolicyV1,
        now_ms: i64,
    ) -> Result<(), SelfUpdateError> {
        self.validate_shape()?;
        policy.validate()?;
        if now_ms < self.issued_at_ms
            || now_ms > self.expires_at_ms
            || self.key_id != policy.key_id
            || self.key_epoch != policy.key_epoch
            || self.manifest.bootstrap_protocol != policy.bootstrap_protocol
            || self.manifest.runtime_contract_digest != policy.runtime_contract_digest
            || self.manifest.state_schema_version < policy.minimum_state_schema_version
            || self.manifest.state_schema_version > policy.maximum_state_schema_version
            || self.archive_bytes > policy.maximum_release_bytes
            || self.manifest.files.len() != policy.files.len()
            || self
                .manifest
                .files
                .iter()
                .zip(&policy.files)
                .any(|(actual, expected)| {
                    actual.path != expected.path || actual.mode != expected.mode
                })
        {
            return Err(SelfUpdateError::PolicyMismatch);
        }
        let verifying_key = policy.verifying_key()?;
        let payload = self.payload_bytes()?;
        if EvidenceDigest::sha256(&payload) != self.payload_digest {
            return Err(SelfUpdateError::InvalidSignature);
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| SelfUpdateError::InvalidSignature)?;
        if URL_SAFE_NO_PAD.encode(&signature_bytes) != self.signature {
            return Err(SelfUpdateError::InvalidSignature);
        }
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| SelfUpdateError::InvalidSignature)?;
        verifying_key
            .verify(&payload, &signature)
            .map_err(|_| SelfUpdateError::InvalidSignature)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SelfUpdateError> {
        self.validate_shape()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SelfUpdateError> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_DESCRIPTOR_BYTES)
        {
            return Err(SelfUpdateError::InvalidDescriptor);
        }
        let release: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&release)? != bytes {
            return Err(SelfUpdateError::NoncanonicalDocument);
        }
        release.validate_shape()?;
        Ok(release)
    }

    fn validate_shape(&self) -> Result<(), SelfUpdateError> {
        if self.purpose != SELF_RELEASE_SIGNATURE_DOMAIN
            || self.schema_version != SELF_RELEASE_SCHEMA_VERSION
            || self.manifest.validate().is_err()
            || !valid_key_id(&self.key_id)
            || self.key_epoch == 0
            || self.archive_bytes == 0
            || self.archive_bytes > MAX_RELEASE_BYTES
            || self.issued_at_ms < 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_SIGNATURE_VALIDITY_MS
            || self.payload_digest != EvidenceDigest::sha256(self.payload_bytes()?)
            || self.signature.is_empty()
        {
            return Err(SelfUpdateError::InvalidDescriptor);
        }
        Ok(())
    }

    fn payload_bytes(&self) -> Result<Vec<u8>, SelfUpdateError> {
        Ok(serde_jcs::to_vec(&SignedSelfReleasePayload {
            purpose: SELF_RELEASE_SIGNATURE_DOMAIN,
            schema_version: SELF_RELEASE_SCHEMA_VERSION,
            manifest: &self.manifest,
            key_id: &self.key_id,
            key_epoch: self.key_epoch,
            archive_digest: &self.archive_digest,
            archive_bytes: self.archive_bytes,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
        })?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfUpdateFilePolicyV1 {
    pub path: String,
    pub mode: u32,
}

impl SelfUpdateFilePolicyV1 {
    fn validate(&self) -> Result<(), SelfUpdateError> {
        if !valid_release_path(&self.path) || !matches!(self.mode, 0o444 | 0o555) {
            return Err(SelfUpdateError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledSelfUpdatePolicyInputV1 {
    pub key_id: String,
    pub key_epoch: u64,
    pub public_key: String,
    pub runtime_contract_digest: EvidenceDigest,
    pub minimum_state_schema_version: u32,
    pub maximum_state_schema_version: u32,
    pub maximum_release_bytes: u64,
    pub files: Vec<SelfUpdateFilePolicyV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledSelfUpdatePolicyV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub bootstrap_protocol: u16,
    pub key_id: String,
    pub key_epoch: u64,
    pub public_key: String,
    pub runtime_contract_digest: EvidenceDigest,
    pub minimum_state_schema_version: u32,
    pub maximum_state_schema_version: u32,
    pub maximum_release_bytes: u64,
    pub files: Vec<SelfUpdateFilePolicyV1>,
    pub document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct InstalledSelfUpdatePolicyPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a ProjectId,
    bootstrap_protocol: u16,
    key_id: &'a str,
    key_epoch: u64,
    public_key: &'a str,
    runtime_contract_digest: &'a EvidenceDigest,
    minimum_state_schema_version: u32,
    maximum_state_schema_version: u32,
    maximum_release_bytes: u64,
    files: &'a [SelfUpdateFilePolicyV1],
}

impl InstalledSelfUpdatePolicyV1 {
    pub fn new(mut input: InstalledSelfUpdatePolicyInputV1) -> Result<Self, SelfUpdateError> {
        input
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
        let mut policy = Self {
            purpose: SELF_UPDATE_POLICY_PURPOSE.to_owned(),
            schema_version: SELF_UPDATE_POLICY_SCHEMA_VERSION,
            project_id: ProjectId::from_str("rdashboard")
                .map_err(|_| SelfUpdateError::InvalidPolicy)?,
            bootstrap_protocol: SELF_UPDATE_BOOTSTRAP_PROTOCOL_V1,
            key_id: input.key_id,
            key_epoch: input.key_epoch,
            public_key: input.public_key,
            runtime_contract_digest: input.runtime_contract_digest,
            minimum_state_schema_version: input.minimum_state_schema_version,
            maximum_state_schema_version: input.maximum_state_schema_version,
            maximum_release_bytes: input.maximum_release_bytes,
            files: input.files,
            document_digest: EvidenceDigest::sha256([]),
        };
        policy.document_digest = policy.calculate_digest()?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), SelfUpdateError> {
        let rdashboard =
            ProjectId::from_str("rdashboard").map_err(|_| SelfUpdateError::InvalidPolicy)?;
        if self.purpose != SELF_UPDATE_POLICY_PURPOSE
            || self.schema_version != SELF_UPDATE_POLICY_SCHEMA_VERSION
            || self.project_id != rdashboard
            || self.bootstrap_protocol != SELF_UPDATE_BOOTSTRAP_PROTOCOL_V1
            || !valid_key_id(&self.key_id)
            || self.key_epoch == 0
            || self.verifying_key().is_err()
            || self.minimum_state_schema_version == 0
            || self.maximum_state_schema_version < self.minimum_state_schema_version
            || self.maximum_release_bytes == 0
            || self.maximum_release_bytes > MAX_RELEASE_BYTES
            || self.files.is_empty()
            || self.files.len() > MAX_RELEASE_FILES
            || !strictly_sorted_unique_policy_paths(&self.files)
            || self.files.iter().any(|file| file.validate().is_err())
            || self.document_digest != self.calculate_digest()?
        {
            return Err(SelfUpdateError::InvalidPolicy);
        }
        Ok(())
    }

    pub fn validate_versioned_application_payload(&self) -> Result<(), SelfUpdateError> {
        self.validate()?;
        let expected = VERSIONED_SELF_RELEASE_BINARIES
            .iter()
            .map(|binary| SelfUpdateFilePolicyV1 {
                path: format!("bin/{binary}"),
                mode: 0o555,
            })
            .collect::<Vec<_>>();
        if self.files != expected {
            return Err(SelfUpdateError::InvalidPolicy);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SelfUpdateError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SelfUpdateError> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_DESCRIPTOR_BYTES)
        {
            return Err(SelfUpdateError::InvalidPolicy);
        }
        let policy: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&policy)? != bytes {
            return Err(SelfUpdateError::NoncanonicalDocument);
        }
        policy.validate()?;
        Ok(policy)
    }

    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey, SelfUpdateError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .map_err(|_| SelfUpdateError::InvalidPolicy)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != self.public_key {
            return Err(SelfUpdateError::InvalidPolicy);
        }
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SelfUpdateError::InvalidPolicy)?;
        VerifyingKey::from_bytes(&key).map_err(|_| SelfUpdateError::InvalidPolicy)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, SelfUpdateError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &InstalledSelfUpdatePolicyPayload {
                purpose: SELF_UPDATE_POLICY_PURPOSE,
                schema_version: SELF_UPDATE_POLICY_SCHEMA_VERSION,
                project_id: &self.project_id,
                bootstrap_protocol: self.bootstrap_protocol,
                key_id: &self.key_id,
                key_epoch: self.key_epoch,
                public_key: &self.public_key,
                runtime_contract_digest: &self.runtime_contract_digest,
                minimum_state_schema_version: self.minimum_state_schema_version,
                maximum_state_schema_version: self.maximum_state_schema_version,
                maximum_release_bytes: self.maximum_release_bytes,
                files: &self.files,
            },
        )?))
    }
}

#[derive(Clone, Debug)]
pub struct SelfReleaseSourceV1 {
    pub path: String,
    pub source: PathBuf,
    pub executable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltSelfReleaseV1 {
    pub descriptor: SignedSelfReleaseV1,
    pub descriptor_path: PathBuf,
    pub archive_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltSelfReleaseArchiveV1 {
    pub manifest: SelfReleaseManifestV1,
    pub archive_digest: EvidenceDigest,
    pub archive_bytes: u64,
    pub archive_path: PathBuf,
}

pub fn build_self_release_archive(
    output_root: &Path,
    output_stem: &str,
    manifest_input: SelfReleaseManifestInputV1,
    mut sources: Vec<SelfReleaseSourceV1>,
    producer_uid: u32,
    reader_gid: u32,
) -> Result<BuiltSelfReleaseArchiveV1, SelfUpdateError> {
    validate_directory(output_root, producer_uid, Some(reader_gid), 0o2750)?;
    if !valid_output_stem(output_stem) || sources.is_empty() || sources.len() > MAX_RELEASE_FILES {
        return Err(SelfUpdateError::InvalidBuildInput);
    }
    sources.sort_by(|left, right| left.path.cmp(&right.path));
    if sources.windows(2).any(|pair| pair[0].path >= pair[1].path) {
        return Err(SelfUpdateError::InvalidBuildInput);
    }

    let archive_path = output_root.join(format!("{output_stem}.tar"));
    if fs::symlink_metadata(&archive_path).is_ok() {
        return Err(SelfUpdateError::OutputExists);
    }
    let result = (|| {
        let mut files = Vec::with_capacity(sources.len());
        let archive = create_private_output(&archive_path)?;
        let mut builder = tar::Builder::new(archive);
        builder.mode(tar::HeaderMode::Deterministic);
        for source in &sources {
            let mode = if source.executable { 0o555 } else { 0o444 };
            let (mut opened, bytes, digest) = open_release_source(&source.source, producer_uid)?;
            let file = SelfReleaseFileV1 {
                path: source.path.clone(),
                mode,
                bytes,
                sha256: digest,
            };
            file.validate()?;
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes);
            header.set_mode(mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, &file.path, &mut opened)?;
            files.push(file);
        }
        builder.finish()?;
        let archive = builder.into_inner()?;
        archive.sync_all()?;
        fs::set_permissions(&archive_path, fs::Permissions::from_mode(0o440))?;
        set_group(&archive_path, reader_gid)?;
        let (archive_digest, archive_bytes) = hash_stable_file(
            &archive_path,
            producer_uid,
            Some(reader_gid),
            0o440,
            MAX_RELEASE_BYTES,
        )?;
        let manifest = SelfReleaseManifestV1::new(manifest_input, files)?;
        Ok(BuiltSelfReleaseArchiveV1 {
            manifest,
            archive_digest,
            archive_bytes,
            archive_path: archive_path.clone(),
        })
    })();
    if result.is_err() {
        remove_created_file(&archive_path);
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub fn build_signed_self_release(
    output_root: &Path,
    output_stem: &str,
    manifest_input: SelfReleaseManifestInputV1,
    sources: Vec<SelfReleaseSourceV1>,
    signature_input: SelfReleaseSignatureInputV1,
    signing_key: &SigningKey,
    producer_uid: u32,
    reader_gid: u32,
) -> Result<BuiltSelfReleaseV1, SelfUpdateError> {
    let archive_path = output_root.join(format!("{output_stem}.tar"));
    let descriptor_path = output_root.join(format!("{output_stem}.jcs"));
    if fs::symlink_metadata(&archive_path).is_ok() || fs::symlink_metadata(&descriptor_path).is_ok()
    {
        return Err(SelfUpdateError::OutputExists);
    }

    let result = (|| {
        let built = build_self_release_archive(
            output_root,
            output_stem,
            manifest_input,
            sources,
            producer_uid,
            reader_gid,
        )?;
        let descriptor = SignedSelfReleaseV1::issue(
            built.manifest,
            SelfReleaseSignatureInputV1 {
                archive_digest: built.archive_digest,
                archive_bytes: built.archive_bytes,
                ..signature_input
            },
            signing_key,
        )?;
        write_shared_document(
            &descriptor_path,
            &descriptor.canonical_bytes()?,
            producer_uid,
            reader_gid,
        )?;
        Ok(BuiltSelfReleaseV1 {
            descriptor,
            descriptor_path: descriptor_path.clone(),
            archive_path: archive_path.clone(),
        })
    })();
    if result.is_err() {
        remove_created_file(&descriptor_path);
        remove_created_file(&archive_path);
    }
    result
}

pub fn verify_signed_self_release_archive(
    descriptor: &SignedSelfReleaseV1,
    archive_path: &Path,
    policy: &InstalledSelfUpdatePolicyV1,
    now_ms: i64,
    source_owner_uid: u32,
    source_reader_gid: u32,
) -> Result<(), SelfUpdateError> {
    descriptor.verify(policy, now_ms)?;
    let (archive_digest, archive_bytes) = hash_stable_file(
        archive_path,
        source_owner_uid,
        Some(source_reader_gid),
        0o440,
        policy.maximum_release_bytes,
    )?;
    if archive_digest != descriptor.archive_digest || archive_bytes != descriptor.archive_bytes {
        return Err(SelfUpdateError::ArchiveBinding);
    }
    validate_release_archive_contents(
        archive_path,
        descriptor,
        source_owner_uid,
        source_reader_gid,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedSelfReleaseV1 {
    pub manifest_digest: EvidenceDigest,
    pub release_path: PathBuf,
}

#[derive(Debug)]
pub struct SelfReleaseStoreV1 {
    root: PathBuf,
    root_mode: u32,
    owner_uid: u32,
    source_owner_uid: u32,
    source_reader_gid: u32,
    root_lock: File,
    operation_lock: Mutex<()>,
}

impl SelfReleaseStoreV1 {
    pub fn open(
        root: impl AsRef<Path>,
        owner_uid: u32,
        source_owner_uid: u32,
        source_reader_gid: u32,
    ) -> Result<Self, SelfUpdateError> {
        use fs2::FileExt as _;

        let root = root.as_ref();
        let root_mode = directory_mode(root, owner_uid, None)?;
        if !matches!(root_mode, 0o700 | 0o711) {
            return Err(SelfUpdateError::UnsafeStore);
        }
        let root_lock = File::open(root)?;
        root_lock
            .try_lock_exclusive()
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::WouldBlock => SelfUpdateError::StoreAlreadyOpen,
                _ => SelfUpdateError::Io(error),
            })?;
        let store = Self {
            root: root.to_owned(),
            root_mode,
            owner_uid,
            source_owner_uid,
            source_reader_gid,
            root_lock,
            operation_lock: Mutex::new(()),
        };
        store.reconcile_staging()?;
        Ok(store)
    }

    pub fn stage(
        &self,
        descriptor_path: &Path,
        archive_path: &Path,
        policy: &InstalledSelfUpdatePolicyV1,
        now_ms: i64,
    ) -> Result<StagedSelfReleaseV1, SelfUpdateError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| SelfUpdateError::StoreLockPoisoned)?;
        self.revalidate_root()?;
        let descriptor_bytes = read_stable_shared_file(
            descriptor_path,
            self.source_owner_uid,
            self.source_reader_gid,
            0o440,
            MAX_DESCRIPTOR_BYTES,
        )?;
        let descriptor = SignedSelfReleaseV1::decode_canonical(&descriptor_bytes)?;
        descriptor.verify(policy, now_ms)?;
        let (archive_digest, archive_bytes) = hash_stable_file(
            archive_path,
            self.source_owner_uid,
            Some(self.source_reader_gid),
            0o440,
            policy.maximum_release_bytes,
        )?;
        if archive_digest != descriptor.archive_digest || archive_bytes != descriptor.archive_bytes
        {
            return Err(SelfUpdateError::ArchiveBinding);
        }

        let final_path = self.root.join(descriptor.manifest.manifest_digest.as_str());
        if fs::symlink_metadata(&final_path).is_ok() {
            verify_staged_release(&final_path, &descriptor, self.owner_uid)?;
            return Ok(StagedSelfReleaseV1 {
                manifest_digest: descriptor.manifest.manifest_digest,
                release_path: final_path,
            });
        }

        let staging_path = self.root.join(format!(".stage-{}", Uuid::new_v4()));
        fs::create_dir(&staging_path)?;
        fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o700))?;
        let result = extract_release_archive(
            archive_path,
            &staging_path,
            &descriptor,
            self.source_owner_uid,
            self.source_reader_gid,
            self.owner_uid,
        )
        .and_then(|()| {
            write_owner_document(
                &staging_path.join(SELF_RELEASE_DESCRIPTOR_FILE),
                &descriptor.canonical_bytes()?,
                self.owner_uid,
            )?;
            make_release_tree_read_only(&staging_path, self.owner_uid)?;
            fs::rename(&staging_path, &final_path)?;
            sync_directory(&self.root)?;
            verify_staged_release(&final_path, &descriptor, self.owner_uid)
        });
        if result.is_err() {
            remove_created_tree(&staging_path);
            return result.map(|()| unreachable!());
        }
        Ok(StagedSelfReleaseV1 {
            manifest_digest: descriptor.manifest.manifest_digest,
            release_path: final_path,
        })
    }

    pub fn verify_staged(
        &self,
        manifest_digest: &EvidenceDigest,
    ) -> Result<SignedSelfReleaseV1, SelfUpdateError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| SelfUpdateError::StoreLockPoisoned)?;
        self.revalidate_root()?;
        let release_path = self.root.join(manifest_digest.as_str());
        let descriptor_bytes = read_stable_owner_file(
            &release_path.join(SELF_RELEASE_DESCRIPTOR_FILE),
            self.owner_uid,
            0o444,
            MAX_DESCRIPTOR_BYTES,
        )?;
        let descriptor = SignedSelfReleaseV1::decode_canonical(&descriptor_bytes)?;
        if descriptor.manifest.manifest_digest != *manifest_digest {
            return Err(SelfUpdateError::StagedReleaseMismatch);
        }
        verify_staged_release(&release_path, &descriptor, self.owner_uid)?;
        Ok(descriptor)
    }

    fn reconcile_staging(&self) -> Result<(), SelfUpdateError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| SelfUpdateError::StoreLockPoisoned)?;
        self.revalidate_root()?;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| SelfUpdateError::UnsafeStore)?;
            if !name.starts_with(".stage-") {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != self.owner_uid
            {
                return Err(SelfUpdateError::UnsafeStore);
            }
            remove_created_tree(&entry.path());
        }
        sync_directory(&self.root)?;
        Ok(())
    }

    fn revalidate_root(&self) -> Result<(), SelfUpdateError> {
        validate_directory(&self.root, self.owner_uid, None, self.root_mode)?;
        let opened = self.root_lock.metadata()?;
        let named = fs::symlink_metadata(&self.root)?;
        if opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(SelfUpdateError::UnsafeStore);
        }
        Ok(())
    }
}

impl Drop for SelfReleaseStoreV1 {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.root_lock);
    }
}

pub fn load_installed_self_update_policy_from(
    path: &Path,
    owner_uid: u32,
) -> Result<InstalledSelfUpdatePolicyV1, SelfUpdateError> {
    let bytes = read_stable_owner_file(path, owner_uid, 0o400, MAX_DESCRIPTOR_BYTES)?;
    let policy = InstalledSelfUpdatePolicyV1::decode_canonical(&bytes)?;
    policy.validate_versioned_application_payload()?;
    Ok(policy)
}

const SELF_UPDATE_RECORD_PURPOSE: &str = "rdashboard.self-update-record.v1";
const SELF_UPDATE_RECORD_SCHEMA_VERSION: u16 = 1;
const SELF_UPDATE_RECORD_FILE_SUFFIX: &str = ".jcs";
const MAX_SELF_UPDATE_RECORDS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfUpdatePhaseV1 {
    BackupPending,
    SwitchPending,
    StartPending,
    HealthPending,
    CommitPending,
    RollbackPending,
    RollbackHealthPending,
    Succeeded,
    RolledBack,
    NeedsReconcile,
}

impl SelfUpdatePhaseV1 {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::RolledBack | Self::NeedsReconcile
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfUpdateRecordV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub operation_id: Uuid,
    pub candidate_release_digest: EvidenceDigest,
    pub previous_release_digest: EvidenceDigest,
    pub phase: SelfUpdatePhaseV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_receipt_digest: Option<EvidenceDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub begun_at_ms: i64,
    pub updated_at_ms: i64,
    pub document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct SelfUpdateRecordPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    operation_id: Uuid,
    candidate_release_digest: &'a EvidenceDigest,
    previous_release_digest: &'a EvidenceDigest,
    phase: SelfUpdatePhaseV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_receipt_digest: &'a Option<EvidenceDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reason: &'a Option<String>,
    begun_at_ms: i64,
    updated_at_ms: i64,
}

impl SelfUpdateRecordV1 {
    fn begin(
        operation_id: Uuid,
        candidate_release_digest: EvidenceDigest,
        previous_release_digest: EvidenceDigest,
        now_ms: i64,
    ) -> Result<Self, SelfUpdateError> {
        let mut record = Self {
            purpose: SELF_UPDATE_RECORD_PURPOSE.to_owned(),
            schema_version: SELF_UPDATE_RECORD_SCHEMA_VERSION,
            operation_id,
            candidate_release_digest,
            previous_release_digest,
            phase: SelfUpdatePhaseV1::BackupPending,
            backup_receipt_digest: None,
            failure_reason: None,
            begun_at_ms: now_ms,
            updated_at_ms: now_ms,
            document_digest: EvidenceDigest::sha256([]),
        };
        record.document_digest = record.calculate_digest()?;
        record.validate()?;
        Ok(record)
    }

    fn transitioned(
        &self,
        phase: SelfUpdatePhaseV1,
        backup_receipt_digest: Option<EvidenceDigest>,
        failure_reason: Option<&str>,
        now_ms: i64,
    ) -> Result<Self, SelfUpdateError> {
        self.validate()?;
        if !valid_phase_transition(self.phase, phase) || now_ms < self.updated_at_ms {
            return Err(SelfUpdateError::InvalidJournalTransition);
        }
        let mut next = self.clone();
        next.phase = phase;
        next.backup_receipt_digest = backup_receipt_digest;
        next.failure_reason = failure_reason.map(str::to_owned);
        next.updated_at_ms = now_ms;
        next.document_digest = next.calculate_digest()?;
        next.validate()?;
        Ok(next)
    }

    pub fn validate(&self) -> Result<(), SelfUpdateError> {
        if self.purpose != SELF_UPDATE_RECORD_PURPOSE
            || self.schema_version != SELF_UPDATE_RECORD_SCHEMA_VERSION
            || self.operation_id.is_nil()
            || self.candidate_release_digest == self.previous_release_digest
            || self.begun_at_ms < 0
            || self.updated_at_ms < self.begun_at_ms
            || matches!(self.phase, SelfUpdatePhaseV1::BackupPending)
                && self.backup_receipt_digest.is_some()
            || !matches!(
                self.phase,
                SelfUpdatePhaseV1::BackupPending | SelfUpdatePhaseV1::NeedsReconcile
            ) && self.backup_receipt_digest.is_none()
            || self
                .failure_reason
                .as_deref()
                .is_some_and(|reason| !valid_reason_code(reason))
            || matches!(
                self.phase,
                SelfUpdatePhaseV1::RollbackPending
                    | SelfUpdatePhaseV1::RollbackHealthPending
                    | SelfUpdatePhaseV1::RolledBack
                    | SelfUpdatePhaseV1::NeedsReconcile
            ) != self.failure_reason.is_some()
            || self.document_digest != self.calculate_digest()?
        {
            return Err(SelfUpdateError::InvalidJournalRecord);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SelfUpdateError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SelfUpdateError> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_DESCRIPTOR_BYTES)
        {
            return Err(SelfUpdateError::InvalidJournalRecord);
        }
        let record: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&record)? != bytes {
            return Err(SelfUpdateError::NoncanonicalDocument);
        }
        record.validate()?;
        Ok(record)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, SelfUpdateError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &SelfUpdateRecordPayload {
                purpose: SELF_UPDATE_RECORD_PURPOSE,
                schema_version: SELF_UPDATE_RECORD_SCHEMA_VERSION,
                operation_id: self.operation_id,
                candidate_release_digest: &self.candidate_release_digest,
                previous_release_digest: &self.previous_release_digest,
                phase: self.phase,
                backup_receipt_digest: &self.backup_receipt_digest,
                failure_reason: &self.failure_reason,
                begun_at_ms: self.begun_at_ms,
                updated_at_ms: self.updated_at_ms,
            },
        )?))
    }
}

#[derive(Clone, Debug)]
pub struct SelfUpdateJournalV1 {
    root: PathBuf,
    owner_uid: u32,
    root_lock: Arc<File>,
    operation_lock: Arc<Mutex<()>>,
}

impl SelfUpdateJournalV1 {
    pub fn open(root: impl AsRef<Path>, owner_uid: u32) -> Result<Self, SelfUpdateError> {
        use fs2::FileExt as _;

        let root = root.as_ref();
        validate_directory(root, owner_uid, None, 0o700)?;
        let root_lock = File::open(root)?;
        root_lock
            .try_lock_exclusive()
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::WouldBlock => SelfUpdateError::JournalAlreadyOpen,
                _ => SelfUpdateError::Io(error),
            })?;
        let journal = Self {
            root: root.to_owned(),
            owner_uid,
            root_lock: Arc::new(root_lock),
            operation_lock: Arc::new(Mutex::new(())),
        };
        let _ = journal.load_records()?;
        Ok(journal)
    }

    pub fn active(&self) -> Result<Option<SelfUpdateRecordV1>, SelfUpdateError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| SelfUpdateError::JournalLockPoisoned)?;
        let records = self.load_records()?;
        active_record(&records)
    }

    pub fn records(&self) -> Result<Vec<SelfUpdateRecordV1>, SelfUpdateError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| SelfUpdateError::JournalLockPoisoned)?;
        Ok(self.load_records()?.into_values().collect())
    }

    pub fn begin(
        &self,
        candidate_release_digest: EvidenceDigest,
        previous_release_digest: EvidenceDigest,
        now_ms: i64,
    ) -> Result<SelfUpdateRecordV1, SelfUpdateError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| SelfUpdateError::JournalLockPoisoned)?;
        let mut records = self.load_records()?;
        if active_record(&records)?.is_some() {
            return Err(SelfUpdateError::UpdateAlreadyActive);
        }
        if records
            .values()
            .any(|record| record.phase == SelfUpdatePhaseV1::NeedsReconcile)
        {
            return Err(SelfUpdateError::RecoveryRequired);
        }
        if records.len() >= MAX_SELF_UPDATE_RECORDS {
            let mut terminal = records
                .values()
                .filter(|record| {
                    matches!(
                        record.phase,
                        SelfUpdatePhaseV1::Succeeded | SelfUpdatePhaseV1::RolledBack
                    )
                })
                .cloned()
                .collect::<Vec<_>>();
            terminal.sort_by(|left, right| {
                left.updated_at_ms
                    .cmp(&right.updated_at_ms)
                    .then_with(|| left.operation_id.cmp(&right.operation_id))
            });
            let remove_count = records
                .len()
                .saturating_sub(MAX_SELF_UPDATE_RECORDS.saturating_sub(1));
            for record in terminal.into_iter().take(remove_count) {
                self.remove_terminal_record(&record)?;
                records.remove(&record.operation_id);
            }
        }
        let record = SelfUpdateRecordV1::begin(
            Uuid::new_v4(),
            candidate_release_digest,
            previous_release_digest,
            now_ms,
        )?;
        self.publish_record(&record, true)?;
        Ok(record)
    }

    pub fn transition(
        &self,
        record: &SelfUpdateRecordV1,
        phase: SelfUpdatePhaseV1,
        backup_receipt_digest: Option<EvidenceDigest>,
        failure_reason: Option<&str>,
        now_ms: i64,
    ) -> Result<SelfUpdateRecordV1, SelfUpdateError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| SelfUpdateError::JournalLockPoisoned)?;
        let records = self.load_records()?;
        let current = records
            .get(&record.operation_id)
            .ok_or(SelfUpdateError::JournalRecordMissing)?;
        if current != record || current.phase.is_terminal() {
            return Err(SelfUpdateError::JournalRecordConflict);
        }
        let next = current.transitioned(phase, backup_receipt_digest, failure_reason, now_ms)?;
        self.publish_record(&next, false)?;
        Ok(next)
    }

    pub fn mark_recovered_rollback(
        &self,
        record: &SelfUpdateRecordV1,
        now_ms: i64,
    ) -> Result<SelfUpdateRecordV1, SelfUpdateError> {
        let _operation = self
            .operation_lock
            .lock()
            .map_err(|_| SelfUpdateError::JournalLockPoisoned)?;
        let records = self.load_records()?;
        let current = records
            .get(&record.operation_id)
            .ok_or(SelfUpdateError::JournalRecordMissing)?;
        if current != record
            || current.phase != SelfUpdatePhaseV1::NeedsReconcile
            || current.backup_receipt_digest.is_none()
        {
            return Err(SelfUpdateError::JournalRecordConflict);
        }
        let next = current.transitioned(
            SelfUpdatePhaseV1::RolledBack,
            current.backup_receipt_digest.clone(),
            current.failure_reason.as_deref(),
            now_ms,
        )?;
        self.publish_record(&next, false)?;
        Ok(next)
    }

    fn load_records(&self) -> Result<BTreeMap<Uuid, SelfUpdateRecordV1>, SelfUpdateError> {
        self.revalidate_root()?;
        let mut records = BTreeMap::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| SelfUpdateError::UnsafeJournal)?;
            if name.starts_with(".record-")
                && Path::new(&name)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("tmp"))
            {
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.uid() != self.owner_uid
                {
                    return Err(SelfUpdateError::UnsafeJournal);
                }
                fs::remove_file(entry.path())?;
                continue;
            }
            let Some(stem) = name.strip_suffix(SELF_UPDATE_RECORD_FILE_SUFFIX) else {
                return Err(SelfUpdateError::UnsafeJournal);
            };
            let operation_id = Uuid::parse_str(stem).map_err(|_| SelfUpdateError::UnsafeJournal)?;
            let bytes =
                read_stable_owner_file(&entry.path(), self.owner_uid, 0o400, MAX_DESCRIPTOR_BYTES)?;
            let record = SelfUpdateRecordV1::decode_canonical(&bytes)?;
            if record.operation_id != operation_id || records.insert(operation_id, record).is_some()
            {
                return Err(SelfUpdateError::UnsafeJournal);
            }
        }
        if records.len() > MAX_SELF_UPDATE_RECORDS {
            return Err(SelfUpdateError::JournalCapacityExceeded);
        }
        let _ = active_record(&records)?;
        Ok(records)
    }

    fn publish_record(
        &self,
        record: &SelfUpdateRecordV1,
        create_new: bool,
    ) -> Result<(), SelfUpdateError> {
        record.validate()?;
        self.revalidate_root()?;
        let final_path = self.root.join(format!(
            "{}{}",
            record.operation_id, SELF_UPDATE_RECORD_FILE_SUFFIX
        ));
        if create_new == fs::symlink_metadata(&final_path).is_ok() {
            return Err(SelfUpdateError::JournalRecordConflict);
        }
        let temporary = self.root.join(format!(".record-{}.tmp", Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&record.canonical_bytes()?)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o400))?;
        if !create_new {
            validate_owner_file(
                &final_path,
                self.owner_uid,
                0o400,
                fs::symlink_metadata(&final_path)?.len(),
            )?;
        }
        fs::rename(&temporary, &final_path)?;
        sync_directory(&self.root)?;
        Ok(())
    }

    fn remove_terminal_record(&self, record: &SelfUpdateRecordV1) -> Result<(), SelfUpdateError> {
        record.validate()?;
        if !record.phase.is_terminal() {
            return Err(SelfUpdateError::InvalidJournalTransition);
        }
        let path = self.root.join(format!(
            "{}{}",
            record.operation_id, SELF_UPDATE_RECORD_FILE_SUFFIX
        ));
        let bytes = read_stable_owner_file(&path, self.owner_uid, 0o400, MAX_DESCRIPTOR_BYTES)?;
        if SelfUpdateRecordV1::decode_canonical(&bytes)? != *record {
            return Err(SelfUpdateError::JournalRecordConflict);
        }
        fs::remove_file(path)?;
        sync_directory(&self.root)?;
        Ok(())
    }

    fn revalidate_root(&self) -> Result<(), SelfUpdateError> {
        validate_directory(&self.root, self.owner_uid, None, 0o700)?;
        let opened = self.root_lock.metadata()?;
        let named = fs::symlink_metadata(&self.root)?;
        if opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(SelfUpdateError::UnsafeJournal);
        }
        Ok(())
    }
}

fn active_record(
    records: &BTreeMap<Uuid, SelfUpdateRecordV1>,
) -> Result<Option<SelfUpdateRecordV1>, SelfUpdateError> {
    let mut active = records
        .values()
        .filter(|record| !record.phase.is_terminal());
    let first = active.next().cloned();
    if active.next().is_some() {
        return Err(SelfUpdateError::MultipleActiveUpdates);
    }
    Ok(first)
}

fn valid_phase_transition(from: SelfUpdatePhaseV1, to: SelfUpdatePhaseV1) -> bool {
    use SelfUpdatePhaseV1 as Phase;
    matches!(
        (from, to),
        (Phase::BackupPending, Phase::SwitchPending)
            | (Phase::SwitchPending, Phase::StartPending)
            | (Phase::StartPending, Phase::HealthPending)
            | (
                Phase::HealthPending,
                Phase::CommitPending | Phase::RollbackPending
            )
            | (Phase::CommitPending, Phase::Succeeded)
            | (Phase::RollbackPending, Phase::RollbackHealthPending)
            | (
                Phase::RollbackHealthPending | Phase::NeedsReconcile,
                Phase::RolledBack
            )
    ) || (!from.is_terminal() && to == Phase::NeedsReconcile)
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("self-update platform failed: {reason_code}")]
pub struct SelfUpdatePlatformFailureV1 {
    pub reason_code: String,
}

impl SelfUpdatePlatformFailureV1 {
    pub fn new(reason_code: impl Into<String>) -> Result<Self, SelfUpdateError> {
        let failure = Self {
            reason_code: reason_code.into(),
        };
        if !valid_reason_code(&failure.reason_code) {
            return Err(SelfUpdateError::InvalidPlatformFailure);
        }
        Ok(failure)
    }
}

pub trait SelfUpdatePlatformV1 {
    fn active_release(&mut self) -> Result<EvidenceDigest, SelfUpdatePlatformFailureV1>;

    fn backup_state(
        &mut self,
        operation_id: Uuid,
        candidate_release_digest: &EvidenceDigest,
    ) -> Result<EvidenceDigest, SelfUpdatePlatformFailureV1>;

    fn activate_release(
        &mut self,
        candidate_release_digest: &EvidenceDigest,
    ) -> Result<(), SelfUpdatePlatformFailureV1>;

    fn start_release(
        &mut self,
        release_digest: &EvidenceDigest,
    ) -> Result<(), SelfUpdatePlatformFailureV1>;

    fn release_is_healthy(
        &mut self,
        release_digest: &EvidenceDigest,
    ) -> Result<bool, SelfUpdatePlatformFailureV1>;

    fn commit_release(
        &mut self,
        candidate_release_digest: &EvidenceDigest,
        previous_release_digest: &EvidenceDigest,
    ) -> Result<(), SelfUpdatePlatformFailureV1>;

    fn restore_release(
        &mut self,
        previous_release_digest: &EvidenceDigest,
        backup_receipt_digest: &EvidenceDigest,
    ) -> Result<(), SelfUpdatePlatformFailureV1>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelfUpdateOutcomeV1 {
    Succeeded,
    RolledBack,
    NeedsReconcile,
}

pub struct SelfUpdateCoordinatorV1 {
    journal: SelfUpdateJournalV1,
}

impl SelfUpdateCoordinatorV1 {
    pub const fn new(journal: SelfUpdateJournalV1) -> Self {
        Self { journal }
    }

    pub fn apply<P: SelfUpdatePlatformV1>(
        &self,
        candidate_release_digest: EvidenceDigest,
        platform: &mut P,
        now_ms: i64,
    ) -> Result<SelfUpdateOutcomeV1, SelfUpdateError> {
        let mut record = if let Some(active) = self.journal.active()? {
            if active.candidate_release_digest != candidate_release_digest {
                return Err(SelfUpdateError::UpdateAlreadyActive);
            }
            active
        } else {
            let previous = platform
                .active_release()
                .map_err(SelfUpdateError::Platform)?;
            self.journal
                .begin(candidate_release_digest, previous, now_ms)?
        };
        for _ in 0..16 {
            if let Some(outcome) = terminal_outcome(record.phase) {
                return Ok(outcome);
            }
            record = self.advance(record, platform, now_ms)?;
        }
        Err(SelfUpdateError::InvalidJournalTransition)
    }

    #[allow(clippy::too_many_lines)]
    fn advance<P: SelfUpdatePlatformV1>(
        &self,
        record: SelfUpdateRecordV1,
        platform: &mut P,
        now_ms: i64,
    ) -> Result<SelfUpdateRecordV1, SelfUpdateError> {
        use SelfUpdatePhaseV1 as Phase;

        let active = platform
            .active_release()
            .map_err(SelfUpdateError::Platform)?;
        let backup = record.backup_receipt_digest.clone();
        match record.phase {
            Phase::BackupPending => {
                if active != record.previous_release_digest {
                    return self.needs_reconcile(&record, "active_release_changed", now_ms);
                }
                let receipt = platform
                    .backup_state(record.operation_id, &record.candidate_release_digest)
                    .map_err(SelfUpdateError::Platform)?;
                self.journal
                    .transition(&record, Phase::SwitchPending, Some(receipt), None, now_ms)
            }
            Phase::SwitchPending => {
                if active == record.previous_release_digest {
                    platform
                        .activate_release(&record.candidate_release_digest)
                        .map_err(SelfUpdateError::Platform)?;
                } else if active != record.candidate_release_digest {
                    return self.needs_reconcile(&record, "active_release_unknown", now_ms);
                }
                self.journal
                    .transition(&record, Phase::StartPending, backup, None, now_ms)
            }
            Phase::StartPending => {
                if active != record.candidate_release_digest {
                    return self.needs_reconcile(&record, "candidate_not_active", now_ms);
                }
                platform
                    .start_release(&record.candidate_release_digest)
                    .map_err(SelfUpdateError::Platform)?;
                self.journal
                    .transition(&record, Phase::HealthPending, backup, None, now_ms)
            }
            Phase::HealthPending => {
                if active != record.candidate_release_digest {
                    return self.needs_reconcile(&record, "candidate_not_active", now_ms);
                }
                if platform
                    .release_is_healthy(&record.candidate_release_digest)
                    .map_err(SelfUpdateError::Platform)?
                {
                    self.journal
                        .transition(&record, Phase::CommitPending, backup, None, now_ms)
                } else {
                    self.journal.transition(
                        &record,
                        Phase::RollbackPending,
                        backup,
                        Some("candidate_unhealthy"),
                        now_ms,
                    )
                }
            }
            Phase::CommitPending => {
                if active != record.candidate_release_digest {
                    return self.needs_reconcile(&record, "candidate_not_active", now_ms);
                }
                platform
                    .commit_release(
                        &record.candidate_release_digest,
                        &record.previous_release_digest,
                    )
                    .map_err(SelfUpdateError::Platform)?;
                self.journal
                    .transition(&record, Phase::Succeeded, backup, None, now_ms)
            }
            Phase::RollbackPending => {
                if active == record.candidate_release_digest {
                    let receipt = backup
                        .as_ref()
                        .ok_or(SelfUpdateError::InvalidJournalRecord)?;
                    platform
                        .restore_release(&record.previous_release_digest, receipt)
                        .map_err(SelfUpdateError::Platform)?;
                } else if active != record.previous_release_digest {
                    return self.needs_reconcile(&record, "rollback_release_unknown", now_ms);
                }
                self.journal.transition(
                    &record,
                    Phase::RollbackHealthPending,
                    backup,
                    record.failure_reason.as_deref(),
                    now_ms,
                )
            }
            Phase::RollbackHealthPending => {
                if active != record.previous_release_digest {
                    return self.needs_reconcile(&record, "rollback_not_active", now_ms);
                }
                platform
                    .start_release(&record.previous_release_digest)
                    .map_err(SelfUpdateError::Platform)?;
                if platform
                    .release_is_healthy(&record.previous_release_digest)
                    .map_err(SelfUpdateError::Platform)?
                {
                    self.journal.transition(
                        &record,
                        Phase::RolledBack,
                        backup,
                        record.failure_reason.as_deref(),
                        now_ms,
                    )
                } else {
                    self.needs_reconcile(&record, "rollback_unhealthy", now_ms)
                }
            }
            Phase::Succeeded | Phase::RolledBack | Phase::NeedsReconcile => Ok(record),
        }
    }

    fn needs_reconcile(
        &self,
        record: &SelfUpdateRecordV1,
        reason: &'static str,
        now_ms: i64,
    ) -> Result<SelfUpdateRecordV1, SelfUpdateError> {
        self.journal.transition(
            record,
            SelfUpdatePhaseV1::NeedsReconcile,
            record.backup_receipt_digest.clone(),
            Some(reason),
            now_ms,
        )
    }
}

fn terminal_outcome(phase: SelfUpdatePhaseV1) -> Option<SelfUpdateOutcomeV1> {
    match phase {
        SelfUpdatePhaseV1::Succeeded => Some(SelfUpdateOutcomeV1::Succeeded),
        SelfUpdatePhaseV1::RolledBack => Some(SelfUpdateOutcomeV1::RolledBack),
        SelfUpdatePhaseV1::NeedsReconcile => Some(SelfUpdateOutcomeV1::NeedsReconcile),
        _ => None,
    }
}

fn extract_release_archive(
    archive_path: &Path,
    staging_path: &Path,
    descriptor: &SignedSelfReleaseV1,
    source_owner_uid: u32,
    source_reader_gid: u32,
    owner_uid: u32,
) -> Result<(), SelfUpdateError> {
    let archive = open_stable_shared_file(
        archive_path,
        source_owner_uid,
        source_reader_gid,
        0o440,
        descriptor.archive_bytes,
    )?;
    let mut archive = tar::Archive::new(archive);
    let expected = descriptor
        .manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut observed = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(SelfUpdateError::UnsafeArchive);
        }
        let path = entry
            .path()?
            .into_owned()
            .into_os_string()
            .into_string()
            .map_err(|_| SelfUpdateError::UnsafeArchive)?;
        if !valid_release_path(&path) || !observed.insert(path.clone()) {
            return Err(SelfUpdateError::UnsafeArchive);
        }
        let expected_file = expected
            .get(path.as_str())
            .ok_or(SelfUpdateError::ArchiveBinding)?;
        let size = entry.header().size()?;
        let mode = entry.header().mode()? & 0o7777;
        if size != expected_file.bytes || mode != expected_file.mode {
            return Err(SelfUpdateError::ArchiveBinding);
        }
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or(SelfUpdateError::UnsafeArchive)?;
        if total_bytes > descriptor.manifest.total_bytes {
            return Err(SelfUpdateError::UnsafeArchive);
        }
        let destination = staging_path.join(&path);
        create_private_parents(staging_path, &destination, owner_uid)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut output = options.open(&destination)?;
        let mut hasher = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let read = entry.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(u64::try_from(read).map_err(|_| SelfUpdateError::UnsafeArchive)?)
                .ok_or(SelfUpdateError::UnsafeArchive)?;
            if copied > size {
                return Err(SelfUpdateError::UnsafeArchive);
            }
            hasher.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
        }
        if copied != size || hex_sha256(hasher.finalize()) != expected_file.sha256.as_str() {
            return Err(SelfUpdateError::ArchiveBinding);
        }
        output.sync_all()?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(expected_file.mode))?;
        validate_owner_file(
            &destination,
            owner_uid,
            expected_file.mode,
            expected_file.bytes,
        )?;
    }
    if observed.len() != expected.len()
        || total_bytes != descriptor.manifest.total_bytes
        || expected.keys().any(|path| !observed.contains(*path))
    {
        return Err(SelfUpdateError::ArchiveBinding);
    }
    Ok(())
}

fn validate_release_archive_contents(
    archive_path: &Path,
    descriptor: &SignedSelfReleaseV1,
    source_owner_uid: u32,
    source_reader_gid: u32,
) -> Result<(), SelfUpdateError> {
    let archive = open_stable_shared_file(
        archive_path,
        source_owner_uid,
        source_reader_gid,
        0o440,
        descriptor.archive_bytes,
    )?;
    let mut archive = tar::Archive::new(archive);
    let expected = descriptor
        .manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let mut observed = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(SelfUpdateError::UnsafeArchive);
        }
        let path = entry
            .path()?
            .into_owned()
            .into_os_string()
            .into_string()
            .map_err(|_| SelfUpdateError::UnsafeArchive)?;
        if !valid_release_path(&path) || !observed.insert(path.clone()) {
            return Err(SelfUpdateError::UnsafeArchive);
        }
        let expected_file = expected
            .get(path.as_str())
            .ok_or(SelfUpdateError::ArchiveBinding)?;
        let size = entry.header().size()?;
        let mode = entry.header().mode()? & 0o7777;
        if size != expected_file.bytes || mode != expected_file.mode {
            return Err(SelfUpdateError::ArchiveBinding);
        }
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or(SelfUpdateError::UnsafeArchive)?;
        if total_bytes > descriptor.manifest.total_bytes {
            return Err(SelfUpdateError::UnsafeArchive);
        }
        let mut hasher = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let read = entry.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(u64::try_from(read).map_err(|_| SelfUpdateError::UnsafeArchive)?)
                .ok_or(SelfUpdateError::UnsafeArchive)?;
            if copied > size {
                return Err(SelfUpdateError::UnsafeArchive);
            }
            hasher.update(&buffer[..read]);
        }
        if copied != size || hex_sha256(hasher.finalize()) != expected_file.sha256.as_str() {
            return Err(SelfUpdateError::ArchiveBinding);
        }
    }
    if observed.len() != expected.len()
        || total_bytes != descriptor.manifest.total_bytes
        || expected.keys().any(|path| !observed.contains(*path))
    {
        return Err(SelfUpdateError::ArchiveBinding);
    }
    Ok(())
}

fn verify_staged_release(
    release_path: &Path,
    descriptor: &SignedSelfReleaseV1,
    owner_uid: u32,
) -> Result<(), SelfUpdateError> {
    validate_directory(release_path, owner_uid, None, 0o555)?;
    let descriptor_path = release_path.join(SELF_RELEASE_DESCRIPTOR_FILE);
    let descriptor_bytes =
        read_stable_owner_file(&descriptor_path, owner_uid, 0o444, MAX_DESCRIPTOR_BYTES)?;
    if SignedSelfReleaseV1::decode_canonical(&descriptor_bytes)? != *descriptor {
        return Err(SelfUpdateError::StagedReleaseMismatch);
    }
    let mut expected_directories = BTreeSet::from([release_path.to_owned()]);
    for file in &descriptor.manifest.files {
        let path = release_path.join(&file.path);
        let (digest, bytes) = hash_owner_file(&path, owner_uid, file.mode, file.bytes)?;
        if digest != file.sha256 || bytes != file.bytes {
            return Err(SelfUpdateError::StagedReleaseMismatch);
        }
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if !directory.starts_with(release_path) {
                return Err(SelfUpdateError::UnsafeStore);
            }
            expected_directories.insert(directory.to_owned());
            if directory == release_path {
                break;
            }
            parent = directory.parent();
        }
    }
    verify_release_tree_shape(release_path, descriptor, owner_uid, &expected_directories)
}

fn verify_release_tree_shape(
    root: &Path,
    descriptor: &SignedSelfReleaseV1,
    owner_uid: u32,
    expected_directories: &BTreeSet<PathBuf>,
) -> Result<(), SelfUpdateError> {
    let expected_files = descriptor
        .manifest
        .files
        .iter()
        .map(|file| root.join(&file.path))
        .chain(std::iter::once(root.join(SELF_RELEASE_DESCRIPTOR_FILE)))
        .collect::<BTreeSet<_>>();
    let mut pending = vec![root.to_owned()];
    let mut observed_files = BTreeSet::new();
    let mut observed_directories = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        validate_directory(&directory, owner_uid, None, 0o555)?;
        observed_directories.insert(directory.clone());
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || metadata.uid() != owner_uid {
                return Err(SelfUpdateError::UnsafeStore);
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() && metadata.nlink() == 1 {
                observed_files.insert(path);
            } else {
                return Err(SelfUpdateError::UnsafeStore);
            }
        }
    }
    if observed_files != expected_files || observed_directories != *expected_directories {
        return Err(SelfUpdateError::StagedReleaseMismatch);
    }
    Ok(())
}

fn make_release_tree_read_only(root: &Path, owner_uid: u32) -> Result<(), SelfUpdateError> {
    let mut directories = vec![root.to_owned()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        let metadata = fs::symlink_metadata(&directory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != owner_uid {
            return Err(SelfUpdateError::UnsafeStore);
        }
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || metadata.uid() != owner_uid {
                return Err(SelfUpdateError::UnsafeStore);
            }
            if metadata.is_dir() {
                directories.push(entry.path());
            } else if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(SelfUpdateError::UnsafeStore);
            }
        }
        index += 1;
    }
    for directory in directories.into_iter().rev() {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o555))?;
    }
    Ok(())
}

fn create_private_parents(
    root: &Path,
    destination: &Path,
    owner_uid: u32,
) -> Result<(), SelfUpdateError> {
    let relative = destination
        .strip_prefix(root)
        .map_err(|_| SelfUpdateError::UnsafeArchive)?;
    let parent = relative.parent().ok_or(SelfUpdateError::UnsafeArchive)?;
    let mut current = root.to_owned();
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(SelfUpdateError::UnsafeArchive);
        };
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        validate_directory(&current, owner_uid, None, 0o700)?;
    }
    Ok(())
}

fn open_release_source(
    path: &Path,
    required_uid: u32,
) -> Result<(File, u64, EvidenceDigest), SelfUpdateError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != required_uid
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_RELEASE_FILE_BYTES
    {
        return Err(SelfUpdateError::UnsafeBuildInput);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
    {
        return Err(SelfUpdateError::ConcurrentChange);
    }
    let digest = hash_reader(&mut file, metadata.len())?;
    let after = fs::symlink_metadata(path)?;
    if after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
    {
        return Err(SelfUpdateError::ConcurrentChange);
    }
    file.rewind()?;
    Ok((file, metadata.len(), digest))
}

fn hash_reader(reader: &mut File, expected_bytes: u64) -> Result<EvidenceDigest, SelfUpdateError> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| SelfUpdateError::ConcurrentChange)?)
            .ok_or(SelfUpdateError::ConcurrentChange)?;
        if total > expected_bytes {
            return Err(SelfUpdateError::ConcurrentChange);
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_bytes {
        return Err(SelfUpdateError::ConcurrentChange);
    }
    EvidenceDigest::from_str(&hex_sha256(hasher.finalize()))
        .map_err(|_| SelfUpdateError::ConcurrentChange)
}

fn hash_stable_file(
    path: &Path,
    owner_uid: u32,
    group_gid: Option<u32>,
    mode: u32,
    maximum_bytes: u64,
) -> Result<(EvidenceDigest, u64), SelfUpdateError> {
    let mut file = open_stable_file(path, owner_uid, group_gid, mode, maximum_bytes)?;
    let metadata = file.metadata()?;
    let digest = hash_reader(&mut file, metadata.len())?;
    let named = fs::symlink_metadata(path)?;
    if named.dev() != metadata.dev()
        || named.ino() != metadata.ino()
        || named.len() != metadata.len()
    {
        return Err(SelfUpdateError::ConcurrentChange);
    }
    Ok((digest, metadata.len()))
}

fn hash_owner_file(
    path: &Path,
    owner_uid: u32,
    mode: u32,
    expected_bytes: u64,
) -> Result<(EvidenceDigest, u64), SelfUpdateError> {
    let result = hash_stable_file(path, owner_uid, None, mode, expected_bytes)?;
    if result.1 != expected_bytes {
        return Err(SelfUpdateError::StagedReleaseMismatch);
    }
    Ok(result)
}

fn read_stable_shared_file(
    path: &Path,
    owner_uid: u32,
    group_gid: u32,
    mode: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, SelfUpdateError> {
    read_stable_file(path, owner_uid, Some(group_gid), mode, maximum_bytes)
}

fn read_stable_owner_file(
    path: &Path,
    owner_uid: u32,
    mode: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, SelfUpdateError> {
    read_stable_file(path, owner_uid, None, mode, maximum_bytes)
}

fn read_stable_file(
    path: &Path,
    owner_uid: u32,
    group_gid: Option<u32>,
    mode: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, SelfUpdateError> {
    let mut file = open_stable_file(path, owner_uid, group_gid, mode, maximum_bytes)?;
    let metadata = file.metadata()?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    let named = fs::symlink_metadata(path)?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len())
        || named.dev() != metadata.dev()
        || named.ino() != metadata.ino()
        || named.len() != metadata.len()
    {
        return Err(SelfUpdateError::ConcurrentChange);
    }
    Ok(bytes)
}

fn open_stable_shared_file(
    path: &Path,
    owner_uid: u32,
    group_gid: u32,
    mode: u32,
    maximum_bytes: u64,
) -> Result<File, SelfUpdateError> {
    open_stable_file(path, owner_uid, Some(group_gid), mode, maximum_bytes)
}

fn open_stable_file(
    path: &Path,
    owner_uid: u32,
    group_gid: Option<u32>,
    mode: u32,
    maximum_bytes: u64,
) -> Result<File, SelfUpdateError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != owner_uid
        || group_gid.is_some_and(|gid| metadata.gid() != gid)
        || metadata.permissions().mode() & 0o7777 != mode
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(SelfUpdateError::UnsafeHandoff);
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
    {
        return Err(SelfUpdateError::ConcurrentChange);
    }
    Ok(file)
}

fn validate_owner_file(
    path: &Path,
    owner_uid: u32,
    mode: u32,
    expected_bytes: u64,
) -> Result<(), SelfUpdateError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != mode
        || metadata.len() != expected_bytes
    {
        return Err(SelfUpdateError::UnsafeStore);
    }
    Ok(())
}

fn validate_directory(
    path: &Path,
    owner_uid: u32,
    group_gid: Option<u32>,
    mode: u32,
) -> Result<(), SelfUpdateError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || group_gid.is_some_and(|gid| metadata.gid() != gid)
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(SelfUpdateError::UnsafeStore);
    }
    Ok(())
}

fn directory_mode(
    path: &Path,
    owner_uid: u32,
    group_gid: Option<u32>,
) -> Result<u32, SelfUpdateError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || group_gid.is_some_and(|gid| metadata.gid() != gid)
    {
        return Err(SelfUpdateError::UnsafeStore);
    }
    Ok(metadata.permissions().mode() & 0o7777)
}

fn create_private_output(path: &Path) -> Result<File, SelfUpdateError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    Ok(options.open(path)?)
}

fn write_shared_document(
    path: &Path,
    bytes: &[u8],
    producer_uid: u32,
    reader_gid: u32,
) -> Result<(), SelfUpdateError> {
    let mut file = create_private_output(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o440))?;
    set_group(path, reader_gid)?;
    validate_owner_file(path, producer_uid, 0o440, bytes.len() as u64)
}

fn write_owner_document(path: &Path, bytes: &[u8], owner_uid: u32) -> Result<(), SelfUpdateError> {
    let mut file = create_private_output(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    validate_owner_file(path, owner_uid, 0o444, bytes.len() as u64)
}

fn set_group(path: &Path, gid: u32) -> Result<(), SelfUpdateError> {
    rustix::fs::chown(path, None, Some(rustix::fs::Gid::from_raw(gid)))?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), SelfUpdateError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn remove_created_file(path: &Path) {
    if fs::symlink_metadata(path).is_ok() {
        let _ = fs::remove_file(path);
    }
}

fn remove_created_tree(path: &Path) {
    if fs::symlink_metadata(path).is_ok() {
        let _ = fs::remove_dir_all(path);
    }
}

fn valid_release_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_RELEASE_PATH_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
    {
        return false;
    }
    let path = Path::new(value);
    path.components().all(|component| match component {
        Component::Normal(segment) => {
            let bytes = segment.as_encoded_bytes();
            !bytes.is_empty()
                && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.'))
        }
        _ => false,
    })
}

fn valid_key_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=MAX_KEY_ID_BYTES).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.'))
}

fn valid_output_stem(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_reason_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=96).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn strictly_sorted_unique_paths(files: &[SelfReleaseFileV1]) -> bool {
    files.windows(2).all(|pair| pair[0].path < pair[1].path)
}

fn strictly_sorted_unique_policy_paths(files: &[SelfUpdateFilePolicyV1]) -> bool {
    files.windows(2).all(|pair| pair[0].path < pair[1].path)
}

fn hex_sha256(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[derive(Debug, thiserror::Error)]
pub enum SelfUpdateError {
    #[error("the self-release manifest is invalid")]
    InvalidManifest,
    #[error("the signed self-release descriptor is invalid")]
    InvalidDescriptor,
    #[error("the installed self-update policy is invalid")]
    InvalidPolicy,
    #[error("the self-update document is not canonical JCS")]
    NoncanonicalDocument,
    #[error("the self-release signature is invalid")]
    InvalidSignature,
    #[error("the self-release does not match the installed policy")]
    PolicyMismatch,
    #[error("the self-release build input is invalid")]
    InvalidBuildInput,
    #[error("the self-release build input is unsafe")]
    UnsafeBuildInput,
    #[error("the self-release output already exists")]
    OutputExists,
    #[error("the self-release handoff file is unsafe")]
    UnsafeHandoff,
    #[error("the self-release archive is unsafe")]
    UnsafeArchive,
    #[error("the self-release archive does not match its signed descriptor")]
    ArchiveBinding,
    #[error("the immutable self-release store is unsafe")]
    UnsafeStore,
    #[error("the immutable self-release store is already open")]
    StoreAlreadyOpen,
    #[error("the immutable self-release store lock is poisoned")]
    StoreLockPoisoned,
    #[error("the staged self-release does not match its signed descriptor")]
    StagedReleaseMismatch,
    #[error("a self-release input changed while it was being verified")]
    ConcurrentChange,
    #[error("the self-update journal is unsafe")]
    UnsafeJournal,
    #[error("the self-update journal is already open")]
    JournalAlreadyOpen,
    #[error("the self-update journal lock is poisoned")]
    JournalLockPoisoned,
    #[error("the self-update journal reached its fixed capacity")]
    JournalCapacityExceeded,
    #[error("more than one self-update operation is active")]
    MultipleActiveUpdates,
    #[error("a different self-update operation is already active")]
    UpdateAlreadyActive,
    #[error("a self-update operation requires root recovery")]
    RecoveryRequired,
    #[error("the self-update journal record is invalid")]
    InvalidJournalRecord,
    #[error("the self-update journal transition is invalid")]
    InvalidJournalTransition,
    #[error("the self-update journal record is missing")]
    JournalRecordMissing,
    #[error("the self-update journal record changed concurrently")]
    JournalRecordConflict,
    #[error("the self-update platform failure is invalid")]
    InvalidPlatformFailure,
    #[error(transparent)]
    Platform(#[from] SelfUpdatePlatformFailureV1),
    #[error("self-update JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("self-update I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("self-update ownership handling failed: {0}")]
    Errno(#[from] rustix::io::Errno),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::MutexGuard;
    use tempfile::TempDir;

    struct Fixture {
        _test_lock: MutexGuard<'static, ()>,
        directory: TempDir,
        output: PathBuf,
        store: PathBuf,
        sources: Vec<SelfReleaseSourceV1>,
        signing_key: SigningKey,
        uid: u32,
        gid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let test_lock = SELF_UPDATE_FILESYSTEM_TEST_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let directory = tempfile::tempdir().expect("temporary directory");
            let temporary_metadata =
                fs::symlink_metadata(directory.path()).expect("temporary directory metadata");
            let uid = temporary_metadata.uid();
            let gid = temporary_metadata.gid();
            let output = directory.path().join("output");
            let store = directory.path().join("store");
            fs::create_dir(&output).expect("create output");
            fs::set_permissions(&output, fs::Permissions::from_mode(0o2750))
                .expect("protect output");
            fs::create_dir(&store).expect("create store");
            fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).expect("protect store");
            let source_root = directory.path().join("sources");
            fs::create_dir(&source_root).expect("create sources");
            fs::write(source_root.join("rdashboardd"), b"dashboard binary")
                .expect("write dashboard");
            fs::write(source_root.join("worker"), b"worker binary").expect("write worker");
            fs::set_permissions(
                source_root.join("rdashboardd"),
                fs::Permissions::from_mode(0o755),
            )
            .expect("dashboard mode");
            fs::set_permissions(
                source_root.join("worker"),
                fs::Permissions::from_mode(0o755),
            )
            .expect("worker mode");
            Self {
                _test_lock: test_lock,
                directory,
                output,
                store,
                sources: vec![
                    SelfReleaseSourceV1 {
                        path: "bin/rdashboard-worker".to_owned(),
                        source: source_root.join("worker"),
                        executable: true,
                    },
                    SelfReleaseSourceV1 {
                        path: "bin/rdashboardd".to_owned(),
                        source: source_root.join("rdashboardd"),
                        executable: true,
                    },
                ],
                signing_key: SigningKey::from_bytes(&[41; 32]),
                uid,
                gid,
            }
        }

        fn manifest_input() -> SelfReleaseManifestInputV1 {
            SelfReleaseManifestInputV1 {
                source_head: "a".repeat(40).parse().expect("source SHA"),
                source_sequence: 7,
                source_attestation_digest: digest("source attestation"),
                workflow_policy_digest: digest("workflow policy"),
                verification_receipt_digest: digest("verification receipt"),
                runtime_contract_digest: digest("runtime contract"),
                state_schema_version: 3,
            }
        }

        fn signature_input() -> SelfReleaseSignatureInputV1 {
            SelfReleaseSignatureInputV1 {
                key_id: "self-release-2026".to_owned(),
                key_epoch: 1,
                archive_digest: digest("replaced by builder"),
                archive_bytes: 1,
                issued_at_ms: 1_000,
                expires_at_ms: 2_000,
            }
        }

        fn policy(&self) -> InstalledSelfUpdatePolicyV1 {
            InstalledSelfUpdatePolicyV1::new(InstalledSelfUpdatePolicyInputV1 {
                key_id: "self-release-2026".to_owned(),
                key_epoch: 1,
                public_key: URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().as_bytes()),
                runtime_contract_digest: digest("runtime contract"),
                minimum_state_schema_version: 2,
                maximum_state_schema_version: 3,
                maximum_release_bytes: 8 * 1024 * 1024,
                files: vec![
                    SelfUpdateFilePolicyV1 {
                        path: "bin/rdashboardd".to_owned(),
                        mode: 0o555,
                    },
                    SelfUpdateFilePolicyV1 {
                        path: "bin/rdashboard-worker".to_owned(),
                        mode: 0o555,
                    },
                ],
            })
            .expect("self-update policy")
        }

        fn build(&self, stem: &str) -> BuiltSelfReleaseV1 {
            build_signed_self_release(
                &self.output,
                stem,
                Self::manifest_input(),
                self.sources.clone(),
                Self::signature_input(),
                &self.signing_key,
                self.uid,
                self.gid,
            )
            .expect("build signed release")
        }
    }

    fn digest(value: &str) -> EvidenceDigest {
        EvidenceDigest::sha256(value)
    }

    #[test]
    fn signed_release_is_staged_as_an_exact_immutable_tree() {
        let fixture = Fixture::new();
        let built = fixture.build("candidate");
        built
            .descriptor
            .verify(&fixture.policy(), 1_500)
            .expect("verify signed descriptor");
        let store = SelfReleaseStoreV1::open(&fixture.store, fixture.uid, fixture.uid, fixture.gid)
            .expect("open store");
        assert!(matches!(
            SelfReleaseStoreV1::open(&fixture.store, fixture.uid, fixture.uid, fixture.gid),
            Err(SelfUpdateError::StoreAlreadyOpen)
        ));
        let staged = store
            .stage(
                &built.descriptor_path,
                &built.archive_path,
                &fixture.policy(),
                1_500,
            )
            .expect("stage release");
        assert_eq!(
            fs::read(staged.release_path.join("bin/rdashboardd")).expect("read staged binary"),
            b"dashboard binary"
        );
        assert_eq!(
            fs::symlink_metadata(staged.release_path.join("bin/rdashboardd"))
                .expect("staged metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o555
        );
        assert_eq!(
            store
                .stage(
                    &built.descriptor_path,
                    &built.archive_path,
                    &fixture.policy(),
                    1_500,
                )
                .expect("idempotent stage"),
            staged
        );
    }

    #[test]
    fn policy_and_signature_substitution_are_rejected() {
        let fixture = Fixture::new();
        let built = fixture.build("candidate");
        let mut policy = fixture.policy();
        policy.runtime_contract_digest = digest("substituted runtime");
        policy.document_digest = policy.calculate_digest().expect("policy digest");
        assert!(matches!(
            built.descriptor.verify(&policy, 1_500),
            Err(SelfUpdateError::PolicyMismatch)
        ));

        let mut descriptor = built.descriptor;
        descriptor.signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
        assert!(matches!(
            descriptor.verify(&fixture.policy(), 1_500),
            Err(SelfUpdateError::InvalidSignature | SelfUpdateError::InvalidDescriptor)
        ));
    }

    #[test]
    fn archive_tamper_and_unsafe_handoff_are_rejected() {
        let fixture = Fixture::new();
        let built = fixture.build("candidate");
        fs::set_permissions(&built.archive_path, fs::Permissions::from_mode(0o640))
            .expect("weaken archive mode");
        let store = SelfReleaseStoreV1::open(&fixture.store, fixture.uid, fixture.uid, fixture.gid)
            .expect("open store");
        assert!(matches!(
            store.stage(
                &built.descriptor_path,
                &built.archive_path,
                &fixture.policy(),
                1_500
            ),
            Err(SelfUpdateError::UnsafeHandoff)
        ));

        fs::set_permissions(&built.archive_path, fs::Permissions::from_mode(0o440))
            .expect("restore archive mode");
        let mut bytes = fs::read(&built.archive_path).expect("read archive");
        let index = bytes.len() / 2;
        bytes[index] ^= 0x01;
        fs::set_permissions(&built.archive_path, fs::Permissions::from_mode(0o600))
            .expect("open archive for tamper");
        fs::write(&built.archive_path, bytes).expect("tamper archive");
        fs::set_permissions(&built.archive_path, fs::Permissions::from_mode(0o440))
            .expect("restore archive handoff");
        assert!(matches!(
            store.stage(
                &built.descriptor_path,
                &built.archive_path,
                &fixture.policy(),
                1_500
            ),
            Err(SelfUpdateError::ArchiveBinding)
        ));
    }

    #[test]
    fn symlink_and_hardlinked_build_inputs_are_rejected() {
        let fixture = Fixture::new();
        let target = &fixture.sources[0].source;
        let symlink_path = fixture.directory.path().join("linked-source");
        symlink(target, &symlink_path).expect("create symlink");
        let mut symlink_sources = fixture.sources.clone();
        symlink_sources[0].source = symlink_path;
        assert!(matches!(
            build_signed_self_release(
                &fixture.output,
                "symlinked",
                Fixture::manifest_input(),
                symlink_sources,
                Fixture::signature_input(),
                &fixture.signing_key,
                fixture.uid,
                fixture.gid,
            ),
            Err(SelfUpdateError::UnsafeBuildInput)
        ));

        let hardlink_path = fixture.directory.path().join("hardlinked-source");
        fs::hard_link(target, &hardlink_path).expect("create hardlink");
        assert!(matches!(
            build_signed_self_release(
                &fixture.output,
                "hardlinked",
                Fixture::manifest_input(),
                fixture.sources.clone(),
                Fixture::signature_input(),
                &fixture.signing_key,
                fixture.uid,
                fixture.gid,
            ),
            Err(SelfUpdateError::UnsafeBuildInput)
        ));
    }

    #[test]
    fn policy_requires_the_exact_complete_release_shape() {
        let fixture = Fixture::new();
        let built = fixture.build("candidate");
        let mut policy = fixture.policy();
        policy.files.pop();
        policy.document_digest = policy.calculate_digest().expect("policy digest");
        assert!(matches!(
            built.descriptor.verify(&policy, 1_500),
            Err(SelfUpdateError::PolicyMismatch)
        ));

        let mut schema_policy = fixture.policy();
        schema_policy.maximum_state_schema_version = 2;
        schema_policy.document_digest = schema_policy.calculate_digest().expect("policy digest");
        assert!(matches!(
            built.descriptor.verify(&schema_policy, 1_500),
            Err(SelfUpdateError::PolicyMismatch)
        ));
    }

    #[test]
    fn installed_policy_loader_requires_the_complete_versioned_application() {
        let fixture = Fixture::new();
        let policy_path = fixture.directory.path().join("installed-policy.jcs");
        fs::write(
            &policy_path,
            fixture
                .policy()
                .canonical_bytes()
                .expect("incomplete policy bytes"),
        )
        .expect("write incomplete installed policy");
        fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o400))
            .expect("protect installed policy");
        assert!(matches!(
            load_installed_self_update_policy_from(&policy_path, fixture.uid),
            Err(SelfUpdateError::InvalidPolicy)
        ));

        let complete = InstalledSelfUpdatePolicyV1::new(InstalledSelfUpdatePolicyInputV1 {
            key_id: "self-release-2026".to_owned(),
            key_epoch: 1,
            public_key: URL_SAFE_NO_PAD.encode(fixture.signing_key.verifying_key().as_bytes()),
            runtime_contract_digest: digest("runtime contract"),
            minimum_state_schema_version: 2,
            maximum_state_schema_version: 3,
            maximum_release_bytes: 128 * 1024 * 1024,
            files: VERSIONED_SELF_RELEASE_BINARIES
                .iter()
                .map(|binary| SelfUpdateFilePolicyV1 {
                    path: format!("bin/{binary}"),
                    mode: 0o555,
                })
                .collect(),
        })
        .expect("complete installed policy");
        fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600))
            .expect("make installed policy writable");
        fs::write(
            &policy_path,
            complete.canonical_bytes().expect("complete policy bytes"),
        )
        .expect("write complete installed policy");
        fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o400))
            .expect("protect complete installed policy");
        assert_eq!(
            load_installed_self_update_policy_from(&policy_path, fixture.uid)
                .expect("load complete policy"),
            complete
        );
    }

    #[derive(Debug)]
    struct FakePlatform {
        active: EvidenceDigest,
        candidate: EvidenceDigest,
        previous: EvidenceDigest,
        candidate_healthy: bool,
        previous_healthy: bool,
        actions: Vec<String>,
    }

    impl FakePlatform {
        fn new(candidate_healthy: bool) -> Self {
            Self {
                active: digest("previous release"),
                candidate: digest("candidate release"),
                previous: digest("previous release"),
                candidate_healthy,
                previous_healthy: true,
                actions: Vec::new(),
            }
        }
    }

    impl SelfUpdatePlatformV1 for FakePlatform {
        fn active_release(&mut self) -> Result<EvidenceDigest, SelfUpdatePlatformFailureV1> {
            Ok(self.active.clone())
        }

        fn backup_state(
            &mut self,
            _operation_id: Uuid,
            candidate_release_digest: &EvidenceDigest,
        ) -> Result<EvidenceDigest, SelfUpdatePlatformFailureV1> {
            assert_eq!(candidate_release_digest, &self.candidate);
            self.actions.push("backup".to_owned());
            Ok(digest("backup receipt"))
        }

        fn activate_release(
            &mut self,
            candidate_release_digest: &EvidenceDigest,
        ) -> Result<(), SelfUpdatePlatformFailureV1> {
            assert_eq!(candidate_release_digest, &self.candidate);
            self.actions.push("activate-candidate".to_owned());
            self.active = candidate_release_digest.clone();
            Ok(())
        }

        fn start_release(
            &mut self,
            release_digest: &EvidenceDigest,
        ) -> Result<(), SelfUpdatePlatformFailureV1> {
            self.actions.push(if release_digest == &self.candidate {
                "start-candidate".to_owned()
            } else {
                assert_eq!(release_digest, &self.previous);
                "start-previous".to_owned()
            });
            Ok(())
        }

        fn release_is_healthy(
            &mut self,
            release_digest: &EvidenceDigest,
        ) -> Result<bool, SelfUpdatePlatformFailureV1> {
            if release_digest == &self.candidate {
                self.actions.push("health-candidate".to_owned());
                Ok(self.candidate_healthy)
            } else {
                assert_eq!(release_digest, &self.previous);
                self.actions.push("health-previous".to_owned());
                Ok(self.previous_healthy)
            }
        }

        fn commit_release(
            &mut self,
            candidate_release_digest: &EvidenceDigest,
            previous_release_digest: &EvidenceDigest,
        ) -> Result<(), SelfUpdatePlatformFailureV1> {
            assert_eq!(candidate_release_digest, &self.candidate);
            assert_eq!(previous_release_digest, &self.previous);
            self.actions.push("commit".to_owned());
            Ok(())
        }

        fn restore_release(
            &mut self,
            previous_release_digest: &EvidenceDigest,
            backup_receipt_digest: &EvidenceDigest,
        ) -> Result<(), SelfUpdatePlatformFailureV1> {
            assert_eq!(previous_release_digest, &self.previous);
            assert_eq!(backup_receipt_digest, &digest("backup receipt"));
            self.actions.push("restore-previous".to_owned());
            self.active = previous_release_digest.clone();
            Ok(())
        }
    }

    fn journal_fixture(directory: &TempDir) -> SelfUpdateJournalV1 {
        let root = directory.path().join("journal");
        fs::create_dir(&root).expect("create journal");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protect journal");
        let uid = fs::symlink_metadata(&root).expect("journal metadata").uid();
        SelfUpdateJournalV1::open(root, uid).expect("open journal")
    }

    #[test]
    fn bootstrap_journal_commits_a_healthy_candidate_in_order() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let journal = journal_fixture(&directory);
        let coordinator = SelfUpdateCoordinatorV1::new(journal.clone());
        let mut platform = FakePlatform::new(true);
        assert_eq!(
            coordinator
                .apply(platform.candidate.clone(), &mut platform, 1_000)
                .expect("apply update"),
            SelfUpdateOutcomeV1::Succeeded
        );
        assert_eq!(
            platform.actions,
            [
                "backup",
                "activate-candidate",
                "start-candidate",
                "health-candidate",
                "commit"
            ]
        );
        assert!(journal.active().expect("active record").is_none());
    }

    #[test]
    fn unhealthy_candidate_restores_and_proves_the_previous_release() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let journal = journal_fixture(&directory);
        let coordinator = SelfUpdateCoordinatorV1::new(journal.clone());
        let mut platform = FakePlatform::new(false);
        assert_eq!(
            coordinator
                .apply(platform.candidate.clone(), &mut platform, 1_000)
                .expect("apply update"),
            SelfUpdateOutcomeV1::RolledBack
        );
        assert_eq!(
            platform.actions,
            [
                "backup",
                "activate-candidate",
                "start-candidate",
                "health-candidate",
                "restore-previous",
                "start-previous",
                "health-previous"
            ]
        );
        assert_eq!(platform.active, platform.previous);
        assert!(journal.active().expect("active record").is_none());
    }

    #[test]
    fn replay_observes_an_already_switched_pointer_without_repeating_the_effect() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let journal = journal_fixture(&directory);
        let mut platform = FakePlatform::new(true);
        let begun = journal
            .begin(platform.candidate.clone(), platform.previous.clone(), 1_000)
            .expect("begin update");
        let switched = journal
            .transition(
                &begun,
                SelfUpdatePhaseV1::SwitchPending,
                Some(digest("backup receipt")),
                None,
                1_001,
            )
            .expect("record backup");
        assert_eq!(switched.phase, SelfUpdatePhaseV1::SwitchPending);
        platform.active = platform.candidate.clone();

        let coordinator = SelfUpdateCoordinatorV1::new(journal);
        assert_eq!(
            coordinator
                .apply(platform.candidate.clone(), &mut platform, 1_002)
                .expect("replay update"),
            SelfUpdateOutcomeV1::Succeeded
        );
        assert!(!platform.actions.contains(&"activate-candidate".to_owned()));
        assert_eq!(
            platform.actions,
            ["start-candidate", "health-candidate", "commit"]
        );
    }

    #[test]
    fn an_unknown_active_pointer_fails_closed_for_recovery() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let journal = journal_fixture(&directory);
        let begun = journal
            .begin(
                digest("candidate release"),
                digest("previous release"),
                1_000,
            )
            .expect("begin update");
        assert_eq!(begun.phase, SelfUpdatePhaseV1::BackupPending);
        let coordinator = SelfUpdateCoordinatorV1::new(journal.clone());
        let mut platform = FakePlatform::new(true);
        platform.active = digest("unknown release");
        assert_eq!(
            coordinator
                .apply(platform.candidate.clone(), &mut platform, 1_001)
                .expect("classify ambiguous update"),
            SelfUpdateOutcomeV1::NeedsReconcile
        );
        assert!(journal.active().expect("active record").is_none());
        assert!(platform.actions.is_empty());
    }

    #[test]
    fn resolved_terminal_history_is_bounded_without_removing_active_work() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let journal = journal_fixture(&directory);
        for index in 0..MAX_SELF_UPDATE_RECORDS {
            let record = journal
                .begin(
                    digest(&format!("candidate-{index}")),
                    digest("previous release"),
                    i64::try_from(index).expect("bounded index"),
                )
                .expect("begin update");
            let unresolved = journal
                .transition(
                    &record,
                    SelfUpdatePhaseV1::NeedsReconcile,
                    Some(digest(&format!("backup-{index}"))),
                    Some("test_reconcile"),
                    record.updated_at_ms,
                )
                .expect("require recovery");
            journal
                .mark_recovered_rollback(&unresolved, unresolved.updated_at_ms)
                .expect("finish recovered update");
        }
        assert_eq!(
            journal.records().expect("full bounded history").len(),
            MAX_SELF_UPDATE_RECORDS
        );
        let newest = journal
            .begin(digest("new candidate"), digest("previous release"), 100)
            .expect("begin after pruning");
        assert_eq!(newest.phase, SelfUpdatePhaseV1::BackupPending);
        assert_eq!(
            journal.records().expect("pruned history").len(),
            MAX_SELF_UPDATE_RECORDS
        );
        assert_eq!(
            journal
                .active()
                .expect("active update")
                .expect("active record")
                .operation_id,
            newest.operation_id
        );
    }

    #[test]
    fn unresolved_recovery_debt_blocks_new_updates_and_cannot_be_pruned() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let journal = journal_fixture(&directory);
        let record = journal
            .begin(digest("candidate"), digest("previous"), 1_000)
            .expect("begin update");
        let unresolved = journal
            .transition(
                &record,
                SelfUpdatePhaseV1::NeedsReconcile,
                Some(digest("backup")),
                Some("active_release_changed"),
                1_001,
            )
            .expect("require recovery");
        assert!(matches!(
            journal.begin(digest("new candidate"), digest("previous"), 1_002),
            Err(SelfUpdateError::RecoveryRequired)
        ));
        assert_eq!(journal.records().expect("records"), [unresolved]);
    }

    #[test]
    fn every_versioned_service_executes_from_the_atomic_current_slot() {
        let services = [
            (
                "rdashboard-native-release",
                include_str!("../deploy/systemd/rdashboard-native-release-recovery.service"),
            ),
            (
                "rdashboard-dependency-fetcher",
                include_str!("../deploy/systemd/rdashboard-dependency-fetcher.service"),
            ),
            (
                "rdashboard-executor",
                include_str!("../deploy/systemd/rdashboard-executor.service"),
            ),
            (
                "rdashboard-observer",
                include_str!("../deploy/systemd/rdashboard-observer.service"),
            ),
            (
                "rdashboard-rimg-health-proxy",
                include_str!("../deploy/systemd/rdashboard-rimg-health.service"),
            ),
            (
                "rdashboard-source",
                include_str!("../deploy/systemd/rdashboard-source.service"),
            ),
            (
                "rdashboard-source-dispatcher",
                include_str!("../deploy/systemd/rdashboard-source-dispatcher.service"),
            ),
            (
                "rdashboard-source-ingress",
                include_str!("../deploy/systemd/rdashboard-source-ingress.service"),
            ),
            (
                "rdashboard-worker",
                include_str!("../deploy/systemd/rdashboard-worker.service"),
            ),
            (
                "rdashboard-workflow-gateway",
                include_str!("../deploy/systemd/rdashboard-workflow-gateway.service"),
            ),
            (
                "rdashboard-workflow-launcher",
                include_str!("../deploy/systemd/rdashboard-workflow-launcher.service"),
            ),
            (
                "rdashboardd",
                include_str!("../deploy/systemd/rdashboard.service"),
            ),
        ];
        for (binary, service) in services {
            let expected = format!("ExecStart={SELF_UPDATE_CURRENT_BIN_ROOT}/{binary}");
            let exec_starts = service
                .lines()
                .filter(|line| line.starts_with("ExecStart="))
                .collect::<Vec<_>>();
            assert_eq!(exec_starts.len(), 1);
            assert_eq!(
                exec_starts[0].split_ascii_whitespace().next(),
                Some(expected.as_str())
            );
            assert!(VERSIONED_SELF_RELEASE_BINARIES.contains(&binary));
        }

        assert_eq!(
            CURRENT_ADAPTER_RECEIPT_EXECUTABLE,
            format!("{SELF_UPDATE_CURRENT_BIN_ROOT}/rdashboard-adapter-receipt")
        );
        assert_eq!(
            CURRENT_WORKFLOW_JOB_EXECUTABLE,
            format!("{SELF_UPDATE_CURRENT_BIN_ROOT}/rdashboard-workflow-job")
        );
        assert_eq!(
            CURRENT_ROOTLESS_OCI_BUILD_EXECUTABLE,
            format!("{SELF_UPDATE_CURRENT_BIN_ROOT}/rdashboard-workflow-oci-build")
        );
        assert_eq!(
            CURRENT_SELF_RELEASE_BUILD_EXECUTABLE,
            format!("{SELF_UPDATE_CURRENT_BIN_ROOT}/rdashboard-workflow-self-release-build")
        );
        assert!(!VERSIONED_SELF_RELEASE_BINARIES.contains(&"rdashboard-bootstrap"));
        assert!(!VERSIONED_SELF_RELEASE_BINARIES.contains(&"rdashboard-recovery"));
        assert!(!VERSIONED_SELF_RELEASE_BINARIES.contains(&"rdashboard-self-update-config"));
        let native_recovery =
            include_str!("../deploy/systemd/rdashboard-native-release-recovery.service");
        assert!(native_recovery.contains("Requires=rdashboard-bootstrap.service"));
        assert!(native_recovery.contains("After=local-fs.target rdashboard-bootstrap.service"));
        assert!(
            include_str!("../deploy/systemd/rdashboard-bootstrap.service")
                .contains("Before=rdashboard-native-release-recovery.service ")
        );
    }
}
