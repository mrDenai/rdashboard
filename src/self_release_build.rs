use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::{Mutex, MutexGuard},
};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize as _;

use crate::{
    domain::{
        EvidenceDigest, GitCommitId, ProjectId, WorkflowAdapterIdV1, WorkflowArtifactKindV1,
        WorkflowLeaseV1, WorkflowNodeKindV1,
    },
    self_update::{
        BuiltSelfReleaseArchiveV1, CURRENT_SELF_RELEASE_BUILD_EXECUTABLE,
        InstalledSelfUpdatePolicyV1, SelfReleaseManifestInputV1, SelfReleaseManifestV1,
        SelfReleaseSignatureInputV1, SelfReleaseSourceV1, SelfUpdateError, SignedSelfReleaseV1,
        VERSIONED_SELF_RELEASE_BINARIES, build_self_release_archive,
        verify_signed_self_release_archive,
    },
};

pub const SELF_RELEASE_BUILD_POLICY_SCHEMA_VERSION: u16 = 1;
pub const SELF_RELEASE_BUILD_REQUEST_SCHEMA_VERSION: u16 = 1;
pub const SELF_RELEASE_BUILD_RESULT_SCHEMA_VERSION: u16 = 1;
pub const SELF_RELEASE_BUILD_EXECUTABLE: &str = CURRENT_SELF_RELEASE_BUILD_EXECUTABLE;
pub const SELF_RELEASE_BUILD_REQUEST_PATH: &str = "/request/self-release-build-request.jcs";
pub const SELF_RELEASE_BUILD_OPERATION_ROOT: &str = "/operation";
pub const SELF_RELEASE_BUILD_OUTPUT_ROOT: &str = "/output";
pub const SELF_RELEASE_HANDOFF_ROOT: &str = "/var/lib/rdashboard-build/self-releases";
pub const SELF_RELEASE_REQUEST_ROOT: &str =
    "/var/lib/rdashboard-workflow-launcher/self-release-requests";
pub const SELF_RELEASE_SIGNING_CREDENTIAL_PATH: &str =
    "/run/credentials/rdashboard-workflow-launcher.service/self-release-seed";
pub const SELF_RELEASE_BOOTSTRAP_SIGNING_CREDENTIAL_PATH: &str =
    "/etc/rdashboard/credentials/self-release-seed";

const POLICY_PURPOSE: &str = "rdashboard.self-release-build-policy.v1";
const REQUEST_PURPOSE: &str = "rdashboard.self-release-build-request.v1";
const RESULT_PURPOSE: &str = "rdashboard.self-release-build-result.v1";
const PUBLISHED_RELEASE_PREFIX: &str = "release-";
const ARCHIVE_FILE: &str = "release.tar";
const DESCRIPTOR_FILE: &str = "release.jcs";
const RESULT_FILE: &str = "result.jcs";
const RESULT_REQUEST_FILE: &str = "request.jcs";
const MAX_POLICY_FILES: usize = 64;
const MAX_POLICY_BYTES: u64 = 256 * 1024;
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_RESULT_BYTES: u64 = 256 * 1024;
const MAX_HANDOFF_ENTRIES: usize = 128;
const MAX_VALIDITY_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_SELF_RELEASE_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const ED25519_KEY_BYTES: usize = 32;

pub fn load_installed_self_release_signing_key(
    policy: &SelfReleaseBuildPolicyV1,
) -> Result<SigningKey, SelfReleaseBuildError> {
    load_self_release_signing_key(Path::new(SELF_RELEASE_SIGNING_CREDENTIAL_PATH), 0, policy)
}

pub fn load_bootstrap_self_release_signing_key(
    policy: &SelfReleaseBuildPolicyV1,
) -> Result<SigningKey, SelfReleaseBuildError> {
    load_self_release_signing_key(
        Path::new(SELF_RELEASE_BOOTSTRAP_SIGNING_CREDENTIAL_PATH),
        0,
        policy,
    )
}

fn load_self_release_signing_key(
    path: &Path,
    required_uid: u32,
    policy: &SelfReleaseBuildPolicyV1,
) -> Result<SigningKey, SelfReleaseBuildError> {
    policy.validate()?;
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.permissions().mode() & 0o022 != 0
        || path_metadata.len() != ED25519_KEY_BYTES as u64
    {
        return Err(SelfReleaseBuildError::UnsafeCredential);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != path_metadata.dev()
        || opened.ino() != path_metadata.ino()
        || opened.uid() != required_uid
        || opened.permissions().mode() & 0o022 != 0
        || opened.len() != ED25519_KEY_BYTES as u64
    {
        return Err(SelfReleaseBuildError::ConcurrentChange);
    }
    let mut seed = [0_u8; ED25519_KEY_BYTES];
    file.read_exact(&mut seed)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        seed.zeroize();
        return Err(SelfReleaseBuildError::ConcurrentChange);
    }
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    if signing_key.verifying_key().to_bytes()
        != policy.self_update_policy.verifying_key()?.to_bytes()
    {
        return Err(SelfReleaseBuildError::SigningKeyMismatch);
    }
    Ok(signing_key)
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfReleaseBinaryV1 {
    pub binary_name: String,
    pub release_path: String,
}

impl SelfReleaseBinaryV1 {
    fn validate(&self) -> Result<(), SelfReleaseBuildError> {
        if !valid_binary_name(&self.binary_name)
            || self.release_path != format!("bin/{}", self.binary_name)
        {
            return Err(SelfReleaseBuildError::InvalidPolicy);
        }
        Ok(())
    }

    fn operation_path(&self, operation_root: &Path) -> PathBuf {
        operation_root
            .join("target")
            .join("release")
            .join(&self.binary_name)
    }
}

pub fn versioned_self_release_binaries() -> Vec<SelfReleaseBinaryV1> {
    VERSIONED_SELF_RELEASE_BINARIES
        .iter()
        .map(|binary_name| SelfReleaseBinaryV1 {
            binary_name: (*binary_name).to_owned(),
            release_path: format!("bin/{binary_name}"),
        })
        .collect()
}

/// Turns Cargo's top-level hard links into stable, single-link release inputs.
///
/// Cargo commonly hard-links `target/release/<binary>` to an entry below `deps/`. The signed
/// release builder deliberately refuses linked inputs because a second pathname could mutate the
/// inode after verification. Sealing only the canonical inventory after the full gate preserves
/// Cargo's efficient build layout while giving the packager immutable, independently owned inputs.
pub fn seal_versioned_self_release_inputs(
    release_root: &Path,
) -> Result<(), SelfReleaseBuildError> {
    if !release_root.is_absolute() {
        return Err(SelfReleaseBuildError::UnsafeFile);
    }
    let owner_uid = rustix::process::geteuid().as_raw();
    let root_metadata = fs::symlink_metadata(release_root)?;
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || root_metadata.uid() != owner_uid
        || root_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(SelfReleaseBuildError::UnsafeFile);
    }

    for binary in versioned_self_release_binaries() {
        seal_self_release_input(&release_root.join(binary.binary_name), owner_uid)?;
    }
    File::open(release_root)?.sync_all()?;
    Ok(())
}

fn seal_self_release_input(path: &Path, owner_uid: u32) -> Result<(), SelfReleaseBuildError> {
    let before = fs::symlink_metadata(path)?;
    validate_sealable_input(&before, owner_uid)?;
    if before.nlink() == 1 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o555))?;
        validate_sealed_input(&fs::symlink_metadata(path)?, owner_uid, before.len())?;
        return Ok(());
    }

    let parent = path.parent().ok_or(SelfReleaseBuildError::UnsafeFile)?;
    let temporary = parent.join(format!(
        ".self-release-seal-{}.tmp",
        Uuid::new_v4().simple()
    ));
    let result = (|| {
        let mut source = File::open(path)?;
        let opened = source.metadata()?;
        if !same_file_metadata(&before, &opened) {
            return Err(SelfReleaseBuildError::ConcurrentChange);
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o500);
        let mut output = options.open(&temporary)?;
        if io::copy(&mut source, &mut output)? != before.len() {
            return Err(SelfReleaseBuildError::ConcurrentChange);
        }
        output.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o555))?;

        let after_opened = source.metadata()?;
        let after_path = fs::symlink_metadata(path)?;
        if !same_file_metadata(&before, &after_opened) || !same_file_metadata(&before, &after_path)
        {
            return Err(SelfReleaseBuildError::ConcurrentChange);
        }
        validate_sealed_input(&fs::symlink_metadata(&temporary)?, owner_uid, before.len())?;
        fs::rename(&temporary, path)?;
        validate_sealed_input(&fs::symlink_metadata(path)?, owner_uid, before.len())
    })();
    if result.is_err() && temporary.try_exists().unwrap_or(false) {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_sealable_input(
    metadata: &fs::Metadata,
    owner_uid: u32,
) -> Result<(), SelfReleaseBuildError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.nlink() == 0
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_SELF_RELEASE_BINARY_BYTES
    {
        return Err(SelfReleaseBuildError::UnsafeFile);
    }
    Ok(())
}

fn validate_sealed_input(
    metadata: &fs::Metadata,
    owner_uid: u32,
    expected_bytes: u64,
) -> Result<(), SelfReleaseBuildError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o555
        || metadata.len() != expected_bytes
    {
        return Err(SelfReleaseBuildError::UnsafeFile);
    }
    Ok(())
}

fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.permissions().mode() == right.permissions().mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfReleaseBuildPolicyV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub self_update_policy: InstalledSelfUpdatePolicyV1,
    pub state_schema_version: u32,
    pub signature_validity_ms: i64,
    pub binaries: Vec<SelfReleaseBinaryV1>,
    pub document_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct SelfReleaseBuildPolicyPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    project_id: &'a ProjectId,
    self_update_policy: &'a InstalledSelfUpdatePolicyV1,
    state_schema_version: u32,
    signature_validity_ms: i64,
    binaries: &'a [SelfReleaseBinaryV1],
}

impl SelfReleaseBuildPolicyV1 {
    pub fn new(
        self_update_policy: InstalledSelfUpdatePolicyV1,
        state_schema_version: u32,
        signature_validity_ms: i64,
        mut binaries: Vec<SelfReleaseBinaryV1>,
    ) -> Result<Self, SelfReleaseBuildError> {
        binaries.sort();
        let mut policy = Self {
            purpose: POLICY_PURPOSE.to_owned(),
            schema_version: SELF_RELEASE_BUILD_POLICY_SCHEMA_VERSION,
            project_id: ProjectId::from_str("rdashboard")
                .map_err(|_| SelfReleaseBuildError::InvalidPolicy)?,
            self_update_policy,
            state_schema_version,
            signature_validity_ms,
            binaries,
            document_digest: EvidenceDigest::sha256([]),
        };
        policy.document_digest = policy.calculate_digest()?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), SelfReleaseBuildError> {
        self.self_update_policy
            .validate_versioned_application_payload()?;
        let expected_project =
            ProjectId::from_str("rdashboard").map_err(|_| SelfReleaseBuildError::InvalidPolicy)?;
        let expected_files = self
            .binaries
            .iter()
            .map(|binary| (binary.release_path.as_str(), 0o555))
            .collect::<Vec<_>>();
        let installed_files = self
            .self_update_policy
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.mode))
            .collect::<Vec<_>>();
        if self.purpose != POLICY_PURPOSE
            || self.schema_version != SELF_RELEASE_BUILD_POLICY_SCHEMA_VERSION
            || self.project_id != expected_project
            || self.self_update_policy.project_id != self.project_id
            || !(self.self_update_policy.minimum_state_schema_version
                ..=self.self_update_policy.maximum_state_schema_version)
                .contains(&self.state_schema_version)
            || !(1_000..=MAX_VALIDITY_MS).contains(&self.signature_validity_ms)
            || self.binaries != versioned_self_release_binaries()
            || self.binaries.len() > MAX_POLICY_FILES
            || !self.binaries.windows(2).all(|pair| pair[0] < pair[1])
            || self
                .binaries
                .iter()
                .any(|binary| binary.validate().is_err())
            || expected_files != installed_files
            || self.document_digest != self.calculate_digest()?
        {
            return Err(SelfReleaseBuildError::InvalidPolicy);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SelfReleaseBuildError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SelfReleaseBuildError> {
        if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_POLICY_BYTES)
        {
            return Err(SelfReleaseBuildError::InvalidPolicy);
        }
        let policy: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&policy)? != bytes {
            return Err(SelfReleaseBuildError::NoncanonicalDocument);
        }
        policy.validate()?;
        Ok(policy)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, SelfReleaseBuildError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &SelfReleaseBuildPolicyPayload {
                purpose: POLICY_PURPOSE,
                schema_version: SELF_RELEASE_BUILD_POLICY_SCHEMA_VERSION,
                project_id: &self.project_id,
                self_update_policy: &self.self_update_policy,
                state_schema_version: self.state_schema_version,
                signature_validity_ms: self.signature_validity_ms,
                binaries: &self.binaries,
            },
        )?))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfReleaseBuildRequestV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub lease_digest: EvidenceDigest,
    pub lease_id: Uuid,
    pub lease_generation: u32,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub source_sha: GitCommitId,
    pub source_sequence: u64,
    pub source_attestation_digest: EvidenceDigest,
    pub workflow_policy_digest: EvidenceDigest,
    pub preparation_key: EvidenceDigest,
    pub expected_input_digest: EvidenceDigest,
    pub verification_receipt_digest: EvidenceDigest,
    pub build_policy_digest: EvidenceDigest,
    pub self_update_policy_digest: EvidenceDigest,
    pub runtime_contract_digest: EvidenceDigest,
    pub state_schema_version: u32,
    pub key_id: String,
    pub key_epoch: u64,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub binaries: Vec<SelfReleaseBinaryV1>,
    pub request_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct SelfReleaseBuildRequestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    lease_digest: &'a EvidenceDigest,
    lease_id: Uuid,
    lease_generation: u32,
    attempt_id: Uuid,
    project_id: &'a ProjectId,
    source_sha: &'a GitCommitId,
    source_sequence: u64,
    source_attestation_digest: &'a EvidenceDigest,
    workflow_policy_digest: &'a EvidenceDigest,
    preparation_key: &'a EvidenceDigest,
    expected_input_digest: &'a EvidenceDigest,
    verification_receipt_digest: &'a EvidenceDigest,
    build_policy_digest: &'a EvidenceDigest,
    self_update_policy_digest: &'a EvidenceDigest,
    runtime_contract_digest: &'a EvidenceDigest,
    state_schema_version: u32,
    key_id: &'a str,
    key_epoch: u64,
    issued_at_ms: i64,
    expires_at_ms: i64,
    binaries: &'a [SelfReleaseBinaryV1],
}

impl SelfReleaseBuildRequestV1 {
    pub fn from_policy(
        lease: &WorkflowLeaseV1,
        policy: &SelfReleaseBuildPolicyV1,
    ) -> Result<Self, SelfReleaseBuildError> {
        lease.validate()?;
        policy.validate()?;
        if lease.node_kind != WorkflowNodeKindV1::ReleaseBuild
            || lease.adapter_id != WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1
            || lease.output_contract != WorkflowArtifactKindV1::ReleaseBuildResult
            || lease.project_id != policy.project_id
            || lease.operation_state.is_none()
        {
            return Err(SelfReleaseBuildError::LeaseMismatch);
        }
        let source = lease.required_source_identity()?;
        let verification_receipt_digest =
            required_input_digest(lease, WorkflowArtifactKindV1::VerificationReceipt)?.clone();
        let _ = required_input_digest(lease, WorkflowArtifactKindV1::PreparedRun)?;
        let expires_at_ms = lease
            .leased_at_ms
            .checked_add(policy.signature_validity_ms)
            .ok_or(SelfReleaseBuildError::InvalidRequest)?;
        let mut request = Self {
            purpose: REQUEST_PURPOSE.to_owned(),
            schema_version: SELF_RELEASE_BUILD_REQUEST_SCHEMA_VERSION,
            lease_digest: lease.lease_digest.clone(),
            lease_id: lease.lease_id,
            lease_generation: lease.lease_generation,
            attempt_id: lease.attempt_id,
            project_id: lease.project_id.clone(),
            source_sha: lease.source_sha.clone(),
            source_sequence: source.sequence,
            source_attestation_digest: source.attestation_digest.clone(),
            workflow_policy_digest: lease.workflow_policy_digest.clone(),
            preparation_key: lease.preparation_key.clone(),
            expected_input_digest: lease.expected_input_digest.clone(),
            verification_receipt_digest,
            build_policy_digest: policy.document_digest.clone(),
            self_update_policy_digest: policy.self_update_policy.document_digest.clone(),
            runtime_contract_digest: policy.self_update_policy.runtime_contract_digest.clone(),
            state_schema_version: policy.state_schema_version,
            key_id: policy.self_update_policy.key_id.clone(),
            key_epoch: policy.self_update_policy.key_epoch,
            issued_at_ms: lease.leased_at_ms,
            expires_at_ms,
            binaries: policy.binaries.clone(),
            request_digest: EvidenceDigest::sha256([]),
        };
        request.request_digest = request.calculate_digest()?;
        request.validate_for_lease(lease, policy)?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), SelfReleaseBuildError> {
        if self.purpose != REQUEST_PURPOSE
            || self.schema_version != SELF_RELEASE_BUILD_REQUEST_SCHEMA_VERSION
            || self.lease_id.is_nil()
            || self.lease_generation == 0
            || self.attempt_id.is_nil()
            || self.source_sequence == 0
            || self.state_schema_version == 0
            || self.key_epoch == 0
            || self.key_id.is_empty()
            || self.issued_at_ms < 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_VALIDITY_MS
            || self.binaries.is_empty()
            || self.binaries.len() > MAX_POLICY_FILES
            || !self.binaries.windows(2).all(|pair| pair[0] < pair[1])
            || self
                .binaries
                .iter()
                .any(|binary| binary.validate().is_err())
            || self.request_digest != self.calculate_digest()?
        {
            return Err(SelfReleaseBuildError::InvalidRequest);
        }
        Ok(())
    }

    pub fn validate_for_lease(
        &self,
        lease: &WorkflowLeaseV1,
        policy: &SelfReleaseBuildPolicyV1,
    ) -> Result<(), SelfReleaseBuildError> {
        self.validate()?;
        lease.validate()?;
        policy.validate()?;
        let source = lease.required_source_identity()?;
        let verification =
            required_input_digest(lease, WorkflowArtifactKindV1::VerificationReceipt)?;
        let _ = required_input_digest(lease, WorkflowArtifactKindV1::PreparedRun)?;
        if lease.node_kind != WorkflowNodeKindV1::ReleaseBuild
            || lease.adapter_id != WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1
            || lease.output_contract != WorkflowArtifactKindV1::ReleaseBuildResult
            || lease.operation_state.is_none()
            || self.lease_digest != lease.lease_digest
            || self.lease_id != lease.lease_id
            || self.lease_generation != lease.lease_generation
            || self.attempt_id != lease.attempt_id
            || self.project_id != lease.project_id
            || self.source_sha != lease.source_sha
            || self.source_sequence != source.sequence
            || self.source_attestation_digest != source.attestation_digest
            || self.workflow_policy_digest != lease.workflow_policy_digest
            || self.preparation_key != lease.preparation_key
            || self.expected_input_digest != lease.expected_input_digest
            || &self.verification_receipt_digest != verification
            || self.build_policy_digest != policy.document_digest
            || self.self_update_policy_digest != policy.self_update_policy.document_digest
            || self.runtime_contract_digest != policy.self_update_policy.runtime_contract_digest
            || self.state_schema_version != policy.state_schema_version
            || self.key_id != policy.self_update_policy.key_id
            || self.key_epoch != policy.self_update_policy.key_epoch
            || self.issued_at_ms != lease.leased_at_ms
            || self.expires_at_ms - self.issued_at_ms != policy.signature_validity_ms
            || self.binaries != policy.binaries
        {
            return Err(SelfReleaseBuildError::LeaseMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SelfReleaseBuildError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SelfReleaseBuildError> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_REQUEST_BYTES)
        {
            return Err(SelfReleaseBuildError::InvalidRequest);
        }
        let request: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&request)? != bytes {
            return Err(SelfReleaseBuildError::NoncanonicalDocument);
        }
        request.validate()?;
        Ok(request)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, SelfReleaseBuildError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &SelfReleaseBuildRequestPayload {
                purpose: REQUEST_PURPOSE,
                schema_version: SELF_RELEASE_BUILD_REQUEST_SCHEMA_VERSION,
                lease_digest: &self.lease_digest,
                lease_id: self.lease_id,
                lease_generation: self.lease_generation,
                attempt_id: self.attempt_id,
                project_id: &self.project_id,
                source_sha: &self.source_sha,
                source_sequence: self.source_sequence,
                source_attestation_digest: &self.source_attestation_digest,
                workflow_policy_digest: &self.workflow_policy_digest,
                preparation_key: &self.preparation_key,
                expected_input_digest: &self.expected_input_digest,
                verification_receipt_digest: &self.verification_receipt_digest,
                build_policy_digest: &self.build_policy_digest,
                self_update_policy_digest: &self.self_update_policy_digest,
                runtime_contract_digest: &self.runtime_contract_digest,
                state_schema_version: self.state_schema_version,
                key_id: &self.key_id,
                key_epoch: self.key_epoch,
                issued_at_ms: self.issued_at_ms,
                expires_at_ms: self.expires_at_ms,
                binaries: &self.binaries,
            },
        )?))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfReleaseBuildResultV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub request_digest: EvidenceDigest,
    pub project_id: ProjectId,
    pub source_sha: GitCommitId,
    pub manifest: SelfReleaseManifestV1,
    pub archive_digest: EvidenceDigest,
    pub archive_bytes: u64,
    pub result_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct SelfReleaseBuildResultPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    request_digest: &'a EvidenceDigest,
    project_id: &'a ProjectId,
    source_sha: &'a GitCommitId,
    manifest: &'a SelfReleaseManifestV1,
    archive_digest: &'a EvidenceDigest,
    archive_bytes: u64,
}

impl SelfReleaseBuildResultV1 {
    fn new(
        request: &SelfReleaseBuildRequestV1,
        built: BuiltSelfReleaseArchiveV1,
    ) -> Result<Self, SelfReleaseBuildError> {
        let mut result = Self {
            purpose: RESULT_PURPOSE.to_owned(),
            schema_version: SELF_RELEASE_BUILD_RESULT_SCHEMA_VERSION,
            request_digest: request.request_digest.clone(),
            project_id: request.project_id.clone(),
            source_sha: request.source_sha.clone(),
            manifest: built.manifest,
            archive_digest: built.archive_digest,
            archive_bytes: built.archive_bytes,
            result_digest: EvidenceDigest::sha256([]),
        };
        result.result_digest = result.calculate_digest()?;
        result.validate(request)?;
        Ok(result)
    }

    pub fn validate(
        &self,
        request: &SelfReleaseBuildRequestV1,
    ) -> Result<(), SelfReleaseBuildError> {
        request.validate()?;
        self.manifest.validate()?;
        let paths = self
            .manifest
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.mode))
            .collect::<Vec<_>>();
        let expected_paths = request
            .binaries
            .iter()
            .map(|binary| (binary.release_path.as_str(), 0o555))
            .collect::<Vec<_>>();
        if self.purpose != RESULT_PURPOSE
            || self.schema_version != SELF_RELEASE_BUILD_RESULT_SCHEMA_VERSION
            || self.request_digest != request.request_digest
            || self.project_id != request.project_id
            || self.source_sha != request.source_sha
            || self.manifest.project_id != request.project_id
            || self.manifest.source_head != request.source_sha
            || self.manifest.source_sequence != request.source_sequence
            || self.manifest.source_attestation_digest != request.source_attestation_digest
            || self.manifest.workflow_policy_digest != request.workflow_policy_digest
            || self.manifest.verification_receipt_digest != request.verification_receipt_digest
            || self.manifest.runtime_contract_digest != request.runtime_contract_digest
            || self.manifest.state_schema_version != request.state_schema_version
            || paths != expected_paths
            || self.archive_bytes == 0
            || self.archive_digest.as_str().is_empty()
            || self.result_digest != self.calculate_digest()?
        {
            return Err(SelfReleaseBuildError::InvalidResult);
        }
        Ok(())
    }

    pub fn canonical_bytes(
        &self,
        request: &SelfReleaseBuildRequestV1,
    ) -> Result<Vec<u8>, SelfReleaseBuildError> {
        self.validate(request)?;
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(
        bytes: &[u8],
        request: &SelfReleaseBuildRequestV1,
    ) -> Result<Self, SelfReleaseBuildError> {
        if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_RESULT_BYTES)
        {
            return Err(SelfReleaseBuildError::InvalidResult);
        }
        let result: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&result)? != bytes {
            return Err(SelfReleaseBuildError::NoncanonicalDocument);
        }
        result.validate(request)?;
        Ok(result)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, SelfReleaseBuildError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &SelfReleaseBuildResultPayload {
                purpose: RESULT_PURPOSE,
                schema_version: SELF_RELEASE_BUILD_RESULT_SCHEMA_VERSION,
                request_digest: &self.request_digest,
                project_id: &self.project_id,
                source_sha: &self.source_sha,
                manifest: &self.manifest,
                archive_digest: &self.archive_digest,
                archive_bytes: self.archive_bytes,
            },
        )?))
    }
}

pub fn execute_installed_self_release_build()
-> Result<SelfReleaseBuildResultV1, SelfReleaseBuildError> {
    execute_self_release_build(
        Path::new(SELF_RELEASE_BUILD_REQUEST_PATH),
        Path::new(SELF_RELEASE_BUILD_OPERATION_ROOT),
        Path::new(SELF_RELEASE_BUILD_OUTPUT_ROOT),
        0,
    )
}

#[allow(clippy::similar_names)]
fn execute_self_release_build(
    request_path: &Path,
    operation_root: &Path,
    output_root: &Path,
    request_owner_uid: u32,
) -> Result<SelfReleaseBuildResultV1, SelfReleaseBuildError> {
    validate_directory_any_owner(operation_root, 0o700)?;
    let (output_uid, output_gid) = validate_build_output_directory(output_root)?;
    let request_bytes = read_stable_file(
        request_path,
        request_owner_uid,
        None,
        0o444,
        MAX_REQUEST_BYTES,
    )?;
    let request = SelfReleaseBuildRequestV1::decode_canonical(&request_bytes)?;
    let sources = request
        .binaries
        .iter()
        .map(|binary| SelfReleaseSourceV1 {
            path: binary.release_path.clone(),
            source: binary.operation_path(operation_root),
            executable: true,
        })
        .collect();
    let built = build_self_release_archive(
        output_root,
        "release",
        SelfReleaseManifestInputV1 {
            source_head: request.source_sha.clone(),
            source_sequence: request.source_sequence,
            source_attestation_digest: request.source_attestation_digest.clone(),
            workflow_policy_digest: request.workflow_policy_digest.clone(),
            verification_receipt_digest: request.verification_receipt_digest.clone(),
            runtime_contract_digest: request.runtime_contract_digest.clone(),
            state_schema_version: request.state_schema_version,
        },
        sources,
        output_uid,
        output_gid,
    )?;
    let result = SelfReleaseBuildResultV1::new(&request, built)?;
    write_build_file(
        &output_root.join(RESULT_REQUEST_FILE),
        &request.canonical_bytes()?,
        output_gid,
    )?;
    write_build_file(
        &output_root.join(RESULT_FILE),
        &result.canonical_bytes(&request)?,
        output_gid,
    )?;
    File::open(output_root)?.sync_all()?;
    let _ = validate_build_output(output_root, &request, (output_uid, output_gid))?;
    Ok(result)
}

#[derive(Debug)]
struct ValidatedBuildOutput {
    result: SelfReleaseBuildResultV1,
}

#[allow(clippy::similar_names)]
fn validate_build_output(
    output_root: &Path,
    expected_request: &SelfReleaseBuildRequestV1,
    expected_owner: (u32, u32),
) -> Result<ValidatedBuildOutput, SelfReleaseBuildError> {
    expected_request.validate()?;
    validate_output_directory(output_root, expected_owner)?;
    let request_bytes = read_output_file(
        &output_root.join(RESULT_REQUEST_FILE),
        expected_owner,
        MAX_REQUEST_BYTES,
    )?;
    let request = SelfReleaseBuildRequestV1::decode_canonical(&request_bytes)?;
    if request != *expected_request {
        return Err(SelfReleaseBuildError::RequestMismatch);
    }
    let result_bytes = read_output_file(
        &output_root.join(RESULT_FILE),
        expected_owner,
        MAX_RESULT_BYTES,
    )?;
    let result = SelfReleaseBuildResultV1::decode_canonical(&result_bytes, &request)?;
    let archive = output_root.join(ARCHIVE_FILE);
    let (owner_uid, owner_gid) = expected_owner;
    let archive_metadata = fs::symlink_metadata(&archive)?;
    if archive_metadata.file_type().is_symlink()
        || !archive_metadata.is_file()
        || archive_metadata.nlink() != 1
        || archive_metadata.uid() != owner_uid
        || archive_metadata.gid() != owner_gid
        || archive_metadata.permissions().mode() & 0o7777 != 0o440
        || archive_metadata.len() != result.archive_bytes
    {
        return Err(SelfReleaseBuildError::UnsafeOutput);
    }
    let names = fs::read_dir(output_root)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = [ARCHIVE_FILE, RESULT_FILE, RESULT_REQUEST_FILE]
        .into_iter()
        .map(OsStr::new)
        .map(OsStr::to_owned)
        .collect();
    if names != expected {
        return Err(SelfReleaseBuildError::UnsafeOutput);
    }
    Ok(ValidatedBuildOutput { result })
}

#[derive(Debug)]
pub struct PublishedSelfReleaseV1 {
    pub descriptor: SignedSelfReleaseV1,
    pub output_digest: EvidenceDigest,
}

pub struct SelfReleaseHandoffStoreV1 {
    handoff_root: PathBuf,
    request_root: PathBuf,
    trusted_uid: u32,
    trusted_gid: u32,
    build_uid: u32,
    build_gid: u32,
    reader_gid: u32,
    policy: SelfReleaseBuildPolicyV1,
    signing_key: SigningKey,
    root_handle: File,
    request_handle: File,
    operation_lock: Mutex<()>,
}

impl SelfReleaseHandoffStoreV1 {
    pub fn staging_path_for(request: &SelfReleaseBuildRequestV1) -> PathBuf {
        Path::new(SELF_RELEASE_HANDOFF_ROOT).join(format!(
            ".stage-{}-g{}",
            request.lease_id.simple(),
            request.lease_generation
        ))
    }

    pub fn request_path_for(request: &SelfReleaseBuildRequestV1) -> PathBuf {
        Path::new(SELF_RELEASE_REQUEST_ROOT).join(format!(
            "{}-g{}.jcs",
            request.lease_id.simple(),
            request.lease_generation
        ))
    }

    #[allow(clippy::similar_names)]
    pub fn open_installed(
        build_uid: u32,
        build_gid: u32,
        reader_gid: u32,
        policy: SelfReleaseBuildPolicyV1,
        signing_key: SigningKey,
    ) -> Result<Self, SelfReleaseBuildError> {
        if build_uid == 0
            || build_uid == u32::MAX
            || build_gid == 0
            || build_gid == u32::MAX
            || reader_gid == 0
            || reader_gid == u32::MAX
            || reader_gid == build_gid
        {
            return Err(SelfReleaseBuildError::InvalidStore);
        }
        Self::open(
            PathBuf::from(SELF_RELEASE_HANDOFF_ROOT),
            PathBuf::from(SELF_RELEASE_REQUEST_ROOT),
            0,
            0,
            build_uid,
            build_gid,
            reader_gid,
            policy,
            signing_key,
        )
    }

    #[allow(clippy::similar_names, clippy::too_many_arguments)]
    fn open(
        handoff_root: PathBuf,
        request_root: PathBuf,
        trusted_uid: u32,
        trusted_gid: u32,
        build_uid: u32,
        build_gid: u32,
        reader_gid: u32,
        policy: SelfReleaseBuildPolicyV1,
        signing_key: SigningKey,
    ) -> Result<Self, SelfReleaseBuildError> {
        use fs2::FileExt as _;

        policy.validate()?;
        if signing_key.verifying_key().to_bytes()
            != policy.self_update_policy.verifying_key()?.to_bytes()
        {
            return Err(SelfReleaseBuildError::SigningKeyMismatch);
        }
        validate_owned_directory(&handoff_root, trusted_uid, trusted_gid, 0o711)?;
        validate_owned_directory(&request_root, trusted_uid, trusted_gid, 0o700)?;
        let root_handle = File::open(&handoff_root)?;
        root_handle.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                SelfReleaseBuildError::StoreAlreadyOpen
            } else {
                SelfReleaseBuildError::Io(error)
            }
        })?;
        let request_handle = File::open(&request_root)?;
        let store = Self {
            handoff_root,
            request_root,
            trusted_uid,
            trusted_gid,
            build_uid,
            build_gid,
            reader_gid,
            policy,
            signing_key,
            root_handle,
            request_handle,
            operation_lock: Mutex::new(()),
        };
        store.reconcile()?;
        Ok(store)
    }

    pub fn prepare(
        &self,
        request: &SelfReleaseBuildRequestV1,
    ) -> Result<PathBuf, SelfReleaseBuildError> {
        request.validate()?;
        let _guard = self.lock()?;
        self.revalidate()?;
        let staging = self.staging_path(request);
        if staging.try_exists()? {
            self.remove_staging(&staging)?;
        }
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&staging)?;
        std::os::unix::fs::chown(&staging, Some(self.build_uid), Some(self.build_gid))?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o2750))?;
        validate_owned_directory(&staging, self.build_uid, self.build_gid, 0o2750)?;
        let request_path = self.request_path(request);
        if request_path.try_exists()? {
            validate_owned_file(
                &request_path,
                self.trusted_uid,
                self.trusted_gid,
                0o444,
                MAX_REQUEST_BYTES,
            )?;
            fs::remove_file(&request_path)?;
        }
        write_trusted_file(
            &request_path,
            &request.canonical_bytes()?,
            self.trusted_uid,
            self.trusted_gid,
            0o444,
        )?;
        self.root_handle.sync_all()?;
        self.request_handle.sync_all()?;
        Ok(staging)
    }

    pub fn promote(
        &self,
        request: &SelfReleaseBuildRequestV1,
        now_ms: i64,
    ) -> Result<PublishedSelfReleaseV1, SelfReleaseBuildError> {
        request.validate_for_lease_shape(&self.policy)?;
        let _guard = self.lock()?;
        self.revalidate()?;
        let staging = self.staging_path(request);
        let validated = validate_build_output(&staging, request, (self.build_uid, self.build_gid))?;
        let descriptor = SignedSelfReleaseV1::issue(
            validated.result.manifest.clone(),
            SelfReleaseSignatureInputV1 {
                key_id: request.key_id.clone(),
                key_epoch: request.key_epoch,
                archive_digest: validated.result.archive_digest.clone(),
                archive_bytes: validated.result.archive_bytes,
                issued_at_ms: request.issued_at_ms,
                expires_at_ms: request.expires_at_ms,
            },
            &self.signing_key,
        )?;
        verify_signed_self_release_archive(
            &descriptor,
            &staging.join(ARCHIVE_FILE),
            &self.policy.self_update_policy,
            now_ms,
            self.build_uid,
            self.build_gid,
        )?;
        fs::remove_file(staging.join(RESULT_FILE))?;
        fs::remove_file(staging.join(RESULT_REQUEST_FILE))?;
        write_trusted_file(
            &staging.join(DESCRIPTOR_FILE),
            &descriptor.canonical_bytes()?,
            self.trusted_uid,
            self.reader_gid,
            0o440,
        )?;
        make_archive_trusted(
            &staging.join(ARCHIVE_FILE),
            self.build_uid,
            self.build_gid,
            self.trusted_uid,
            self.reader_gid,
        )?;
        std::os::unix::fs::chown(&staging, Some(self.trusted_uid), Some(self.reader_gid))?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o550))?;
        validate_published_directory(
            &staging,
            self.trusted_uid,
            self.reader_gid,
            &descriptor,
            &self.policy.self_update_policy,
            now_ms,
        )?;
        let final_path = self.handoff_root.join(format!(
            "{PUBLISHED_RELEASE_PREFIX}{}",
            descriptor.manifest.manifest_digest.as_str()
        ));
        if final_path.try_exists()? {
            let existing = validate_published_directory(
                &final_path,
                self.trusted_uid,
                self.reader_gid,
                &descriptor,
                &self.policy.self_update_policy,
                now_ms,
            )?;
            if existing != descriptor {
                return Err(SelfReleaseBuildError::PublicationConflict);
            }
            remove_published_staging(&staging, self.trusted_uid, self.reader_gid, 0o550)?;
        } else {
            fs::rename(&staging, &final_path)?;
            self.root_handle.sync_all()?;
        }
        self.remove_request(request)?;
        Ok(PublishedSelfReleaseV1 {
            output_digest: descriptor.payload_digest.clone(),
            descriptor,
        })
    }

    pub fn discard(
        &self,
        request: &SelfReleaseBuildRequestV1,
    ) -> Result<(), SelfReleaseBuildError> {
        let _guard = self.lock()?;
        self.revalidate()?;
        let staging = self.staging_path(request);
        if staging.try_exists()? {
            self.remove_staging(&staging)?;
            self.root_handle.sync_all()?;
        }
        self.remove_request(request)
    }

    fn staging_path(&self, request: &SelfReleaseBuildRequestV1) -> PathBuf {
        self.handoff_root.join(format!(
            ".stage-{}-g{}",
            request.lease_id.simple(),
            request.lease_generation
        ))
    }

    fn request_path(&self, request: &SelfReleaseBuildRequestV1) -> PathBuf {
        self.request_root.join(format!(
            "{}-g{}.jcs",
            request.lease_id.simple(),
            request.lease_generation
        ))
    }

    fn remove_request(
        &self,
        request: &SelfReleaseBuildRequestV1,
    ) -> Result<(), SelfReleaseBuildError> {
        let request_path = self.request_path(request);
        if request_path.try_exists()? {
            validate_owned_file(
                &request_path,
                self.trusted_uid,
                self.trusted_gid,
                0o444,
                MAX_REQUEST_BYTES,
            )?;
            fs::remove_file(request_path)?;
            self.request_handle.sync_all()?;
        }
        Ok(())
    }

    fn reconcile(&self) -> Result<(), SelfReleaseBuildError> {
        let _guard = self.lock()?;
        self.revalidate()?;
        let entries = fs::read_dir(&self.handoff_root)?.collect::<Result<Vec<_>, _>>()?;
        if entries.len() > MAX_HANDOFF_ENTRIES {
            return Err(SelfReleaseBuildError::StoreCapacityExceeded);
        }
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| SelfReleaseBuildError::InvalidStore)?;
            if name.starts_with(".stage-") {
                self.remove_staging(&entry.path())?;
                continue;
            }
            let descriptor =
                read_published_descriptor(&entry.path(), self.trusted_uid, self.reader_gid)?;
            if !published_directory_name_matches(&name, &descriptor) {
                return Err(SelfReleaseBuildError::InvalidStore);
            }
            let verify_at = descriptor.expires_at_ms;
            validate_published_directory(
                &entry.path(),
                self.trusted_uid,
                self.reader_gid,
                &descriptor,
                &self.policy.self_update_policy,
                verify_at,
            )?;
        }
        for entry in fs::read_dir(&self.request_root)? {
            let entry = entry?;
            validate_owned_file(
                &entry.path(),
                self.trusted_uid,
                self.trusted_gid,
                0o444,
                MAX_REQUEST_BYTES,
            )?;
            fs::remove_file(entry.path())?;
        }
        self.root_handle.sync_all()?;
        self.request_handle.sync_all()?;
        Ok(())
    }

    fn remove_staging(&self, path: &Path) -> Result<(), SelfReleaseBuildError> {
        let metadata = fs::symlink_metadata(path)?;
        let mode = metadata.permissions().mode() & 0o7777;
        if !metadata.file_type().is_symlink()
            && metadata.is_dir()
            && metadata.uid() == self.build_uid
            && metadata.gid() == self.build_gid
            && mode == 0o2750
        {
            return remove_tree(path);
        }
        if !metadata.file_type().is_symlink()
            && metadata.is_dir()
            && metadata.uid() == self.trusted_uid
            && metadata.gid() == self.reader_gid
            && matches!(mode, 0o2750 | 0o550)
        {
            return remove_published_staging(path, self.trusted_uid, self.reader_gid, mode);
        }
        Err(SelfReleaseBuildError::InvalidStore)
    }

    fn revalidate(&self) -> Result<(), SelfReleaseBuildError> {
        validate_opened_directory(
            &self.handoff_root,
            &self.root_handle,
            self.trusted_uid,
            self.trusted_gid,
            0o711,
        )?;
        validate_opened_directory(
            &self.request_root,
            &self.request_handle,
            self.trusted_uid,
            self.trusted_gid,
            0o700,
        )
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, SelfReleaseBuildError> {
        self.operation_lock
            .lock()
            .map_err(|_| SelfReleaseBuildError::StoreLockPoisoned)
    }
}

fn published_directory_name_matches(name: &str, descriptor: &SignedSelfReleaseV1) -> bool {
    if let Some(digest) = name.strip_prefix(PUBLISHED_RELEASE_PREFIX) {
        return EvidenceDigest::from_str(digest)
            .is_ok_and(|digest| digest == descriptor.manifest.manifest_digest);
    }
    GitCommitId::from_str(name).is_ok_and(|source| source == descriptor.manifest.source_head)
}

impl Drop for SelfReleaseHandoffStoreV1 {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.root_handle);
    }
}

impl SelfReleaseBuildRequestV1 {
    fn validate_for_lease_shape(
        &self,
        policy: &SelfReleaseBuildPolicyV1,
    ) -> Result<(), SelfReleaseBuildError> {
        self.validate()?;
        policy.validate()?;
        if self.project_id != policy.project_id
            || self.build_policy_digest != policy.document_digest
            || self.self_update_policy_digest != policy.self_update_policy.document_digest
            || self.runtime_contract_digest != policy.self_update_policy.runtime_contract_digest
            || self.state_schema_version != policy.state_schema_version
            || self.key_id != policy.self_update_policy.key_id
            || self.key_epoch != policy.self_update_policy.key_epoch
            || self.expires_at_ms - self.issued_at_ms != policy.signature_validity_ms
            || self.binaries != policy.binaries
        {
            return Err(SelfReleaseBuildError::RequestMismatch);
        }
        Ok(())
    }
}

fn required_input_digest(
    lease: &WorkflowLeaseV1,
    kind: WorkflowArtifactKindV1,
) -> Result<&EvidenceDigest, SelfReleaseBuildError> {
    let mut matches = lease
        .required_input_artifacts()?
        .iter()
        .filter(|input| input.artifact_kind == kind);
    let first = matches.next().ok_or(SelfReleaseBuildError::LeaseMismatch)?;
    if matches.next().is_some() {
        return Err(SelfReleaseBuildError::LeaseMismatch);
    }
    Ok(&first.output_digest)
}

fn validate_published_directory(
    path: &Path,
    owner_uid: u32,
    reader_gid: u32,
    expected: &SignedSelfReleaseV1,
    policy: &InstalledSelfUpdatePolicyV1,
    now_ms: i64,
) -> Result<SignedSelfReleaseV1, SelfReleaseBuildError> {
    validate_owned_directory(path, owner_uid, reader_gid, 0o550)?;
    let names = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_names = [ARCHIVE_FILE, DESCRIPTOR_FILE]
        .into_iter()
        .map(OsStr::new)
        .map(OsStr::to_owned)
        .collect();
    if names != expected_names {
        return Err(SelfReleaseBuildError::InvalidStore);
    }
    let descriptor = read_published_descriptor(path, owner_uid, reader_gid)?;
    if descriptor != *expected {
        return Err(SelfReleaseBuildError::PublicationConflict);
    }
    verify_signed_self_release_archive(
        &descriptor,
        &path.join(ARCHIVE_FILE),
        policy,
        now_ms,
        owner_uid,
        reader_gid,
    )?;
    Ok(descriptor)
}

fn read_published_descriptor(
    path: &Path,
    owner_uid: u32,
    reader_gid: u32,
) -> Result<SignedSelfReleaseV1, SelfReleaseBuildError> {
    let bytes = read_stable_file(
        &path.join(DESCRIPTOR_FILE),
        owner_uid,
        Some(reader_gid),
        0o440,
        MAX_RESULT_BYTES,
    )?;
    Ok(SignedSelfReleaseV1::decode_canonical(&bytes)?)
}

fn remove_published_staging(
    path: &Path,
    owner_uid: u32,
    reader_gid: u32,
    mode: u32,
) -> Result<(), SelfReleaseBuildError> {
    if !matches!(mode, 0o2750 | 0o550) {
        return Err(SelfReleaseBuildError::InvalidStore);
    }
    validate_owned_directory(path, owner_uid, reader_gid, mode)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        validate_owned_file(
            &entry.path(),
            owner_uid,
            reader_gid,
            0o440,
            512 * 1024 * 1024,
        )?;
        fs::remove_file(entry.path())?;
    }
    fs::remove_dir(path)?;
    Ok(())
}

#[allow(clippy::similar_names)]
fn make_archive_trusted(
    path: &Path,
    build_uid: u32,
    build_gid: u32,
    trusted_uid: u32,
    reader_gid: u32,
) -> Result<(), SelfReleaseBuildError> {
    validate_owned_file(path, build_uid, build_gid, 0o440, 512 * 1024 * 1024)?;
    std::os::unix::fs::chown(path, Some(trusted_uid), Some(reader_gid))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o440))?;
    validate_owned_file(path, trusted_uid, reader_gid, 0o440, 512 * 1024 * 1024)
}

fn validate_build_output_directory(path: &Path) -> Result<(u32, u32), SelfReleaseBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o2750
        || fs::read_dir(path)?.next().is_some()
    {
        return Err(SelfReleaseBuildError::UnsafeOutput);
    }
    Ok((metadata.uid(), metadata.gid()))
}

fn validate_output_directory(path: &Path, owner: (u32, u32)) -> Result<(), SelfReleaseBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o2750
        || metadata.uid() != owner.0
        || metadata.gid() != owner.1
    {
        return Err(SelfReleaseBuildError::UnsafeOutput);
    }
    Ok(())
}

fn validate_directory_any_owner(path: &Path, mode: u32) -> Result<(), SelfReleaseBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(SelfReleaseBuildError::UnsafeOperationState);
    }
    Ok(())
}

fn read_output_file(
    path: &Path,
    owner: (u32, u32),
    maximum_bytes: u64,
) -> Result<Vec<u8>, SelfReleaseBuildError> {
    read_stable_file(path, owner.0, Some(owner.1), 0o440, maximum_bytes)
}

fn read_stable_file(
    path: &Path,
    owner_uid: u32,
    group_gid: Option<u32>,
    mode: u32,
    maximum_bytes: u64,
) -> Result<Vec<u8>, SelfReleaseBuildError> {
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
        return Err(SelfReleaseBuildError::UnsafeFile);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
        || after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
        || u64::try_from(bytes.len()).ok() != Some(metadata.len())
    {
        return Err(SelfReleaseBuildError::ConcurrentChange);
    }
    Ok(bytes)
}

fn write_build_file(path: &Path, bytes: &[u8], gid: u32) -> Result<(), SelfReleaseBuildError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o440))?;
    std::os::unix::fs::chown(path, None, Some(gid))?;
    Ok(())
}

fn write_trusted_file(
    path: &Path,
    bytes: &[u8],
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), SelfReleaseBuildError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    validate_owned_file(
        path,
        uid,
        gid,
        mode,
        MAX_RESULT_BYTES.max(bytes.len() as u64),
    )
}

fn validate_owned_file(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    maximum_bytes: u64,
) -> Result<(), SelfReleaseBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != mode
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(SelfReleaseBuildError::UnsafeFile);
    }
    Ok(())
}

fn validate_owned_directory(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), SelfReleaseBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(SelfReleaseBuildError::InvalidStore);
    }
    Ok(())
}

fn validate_opened_directory(
    path: &Path,
    opened: &File,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), SelfReleaseBuildError> {
    validate_owned_directory(path, uid, gid, mode)?;
    let opened = opened.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(SelfReleaseBuildError::ConcurrentChange);
    }
    Ok(())
}

fn remove_tree(path: &Path) -> Result<(), SelfReleaseBuildError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
            return Err(SelfReleaseBuildError::InvalidStore);
        }
        fs::remove_file(entry.path())?;
    }
    fs::remove_dir(path)?;
    Ok(())
}

fn valid_binary_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=96).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
}

#[derive(Debug, thiserror::Error)]
pub enum SelfReleaseBuildError {
    #[error("the self-release build policy is invalid")]
    InvalidPolicy,
    #[error("the self-release build request is invalid")]
    InvalidRequest,
    #[error("the self-release build result is invalid")]
    InvalidResult,
    #[error("the self-release build lease does not match the installed policy")]
    LeaseMismatch,
    #[error("the self-release build request does not match its root-authored request")]
    RequestMismatch,
    #[error("the self-release build document is not canonical JCS")]
    NoncanonicalDocument,
    #[error("the self-release signing key does not match the installed public policy")]
    SigningKeyMismatch,
    #[error("the self-release signing credential is not a stable private 32-byte seed")]
    UnsafeCredential,
    #[error("the self-release operation state is unsafe")]
    UnsafeOperationState,
    #[error("the self-release build output is unsafe")]
    UnsafeOutput,
    #[error("the self-release handoff store is invalid")]
    InvalidStore,
    #[error("the self-release handoff store is already open")]
    StoreAlreadyOpen,
    #[error("the self-release handoff store lock is poisoned")]
    StoreLockPoisoned,
    #[error("the self-release handoff store reached its fixed capacity")]
    StoreCapacityExceeded,
    #[error("a different self-release publication already exists for this source")]
    PublicationConflict,
    #[error("a self-release file is unsafe")]
    UnsafeFile,
    #[error("a self-release file changed while it was read")]
    ConcurrentChange,
    #[error(transparent)]
    Workflow(#[from] crate::domain::WorkflowContractError),
    #[error(transparent)]
    SelfUpdate(#[from] SelfUpdateError),
    #[error("self-release JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("self-release I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl SelfReleaseBuildError {
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidPolicy => "self_release_policy_invalid",
            Self::InvalidRequest | Self::RequestMismatch => "self_release_request_invalid",
            Self::InvalidResult | Self::UnsafeOutput => "self_release_result_invalid",
            Self::LeaseMismatch => "self_release_lease_mismatch",
            Self::NoncanonicalDocument => "self_release_document_noncanonical",
            Self::SigningKeyMismatch | Self::UnsafeCredential => {
                "self_release_signing_credential_invalid"
            }
            Self::UnsafeOperationState => "self_release_operation_state_invalid",
            Self::InvalidStore
            | Self::StoreAlreadyOpen
            | Self::StoreLockPoisoned
            | Self::StoreCapacityExceeded => "self_release_store_invalid",
            Self::PublicationConflict => "self_release_publication_conflict",
            Self::UnsafeFile | Self::ConcurrentChange => "self_release_file_invalid",
            Self::Workflow(_) => "self_release_workflow_contract_invalid",
            Self::SelfUpdate(_) => "self_release_signature_or_archive_invalid",
            Self::Json(_) => "self_release_json_invalid",
            Self::Io(_) => "self_release_io_failed",
        }
    }

    pub fn evidence_digest(&self) -> EvidenceDigest {
        let detail = match self {
            Self::Io(error) => format!("{:?}:{:?}", error.kind(), error.raw_os_error()),
            Self::Workflow(error) => error.to_string(),
            Self::SelfUpdate(error) => error.to_string(),
            Self::Json(error) => format!("{:?}", error.classify()),
            _ => String::new(),
        };
        EvidenceDigest::sha256(format!("{}:{detail}", self.reason_code()))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use tempfile::TempDir;

    use super::*;
    use crate::{
        domain::{
            WorkflowCacheClassV1, WorkflowExecutionProfileV1, WorkflowLeaseInputV1,
            WorkflowNetworkClassV1, WorkflowNodeActivationV1, WorkflowNodeV1,
            WorkflowOperationStateV1, WorkflowProfileId, WorkflowResourceEnvelopeV1,
            WorkflowWorkerPoolV1,
        },
        self_update::{InstalledSelfUpdatePolicyInputV1, SelfUpdateFilePolicyV1},
    };

    fn digest(label: &str) -> EvidenceDigest {
        EvidenceDigest::sha256(label)
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[23_u8; 32])
    }

    fn policy() -> SelfReleaseBuildPolicyV1 {
        let key = signing_key();
        let binaries = versioned_self_release_binaries();
        let self_update = InstalledSelfUpdatePolicyV1::new(InstalledSelfUpdatePolicyInputV1 {
            key_id: "self-release-2026".to_owned(),
            key_epoch: 1,
            public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            runtime_contract_digest: digest("runtime"),
            minimum_state_schema_version: 1,
            maximum_state_schema_version: 3,
            maximum_release_bytes: 64 * 1024 * 1024,
            files: binaries
                .iter()
                .map(|binary| SelfUpdateFilePolicyV1 {
                    path: binary.release_path.clone(),
                    mode: 0o555,
                })
                .collect(),
        })
        .expect("self-update policy");
        SelfReleaseBuildPolicyV1::new(self_update, 3, 60_000, binaries).expect("build policy")
    }

    fn lease() -> WorkflowLeaseV1 {
        lease_for_source(7, "source attestation", "verification output")
    }

    fn lease_for_source(
        source_sequence: u64,
        source_attestation: &str,
        verification_output: &str,
    ) -> WorkflowLeaseV1 {
        let node = WorkflowNodeV1 {
            node_id: "release-build".parse().expect("node ID"),
            display_name: "Build signed self release".to_owned(),
            kind: WorkflowNodeKindV1::ReleaseBuild,
            activation: WorkflowNodeActivationV1::Always,
            profile_id: WorkflowProfileId::from_str("native-self-release").expect("profile ID"),
            depends_on: vec![
                "prepare".parse().expect("prepare node"),
                "verify".parse().expect("verify node"),
            ],
            input_contracts: vec![
                WorkflowArtifactKindV1::PreparedRun,
                WorkflowArtifactKindV1::VerificationReceipt,
            ],
            output_contract: WorkflowArtifactKindV1::ReleaseBuildResult,
        };
        let profile = WorkflowExecutionProfileV1 {
            profile_id: node.profile_id.clone(),
            adapter_id: WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1,
            worker_pool: WorkflowWorkerPoolV1::VpsRequired,
            network_class: WorkflowNetworkClassV1::Offline,
            cache_class: WorkflowCacheClassV1::PreparedRun,
            timeout_ms: 30_000,
            resources: Some(WorkflowResourceEnvelopeV1 {
                cpu_millicores: 1_000,
                memory_max_bytes: 256 * 1024 * 1024,
                tasks_max: 64,
                scratch_max_bytes: 512 * 1024 * 1024,
                scratch_max_inodes: 10_000,
                output_max_bytes: 128 * 1024 * 1024,
            }),
        };
        let attempt_id = Uuid::new_v4();
        let project_id = ProjectId::from_str("rdashboard").expect("project ID");
        let source_sha = GitCommitId::from_str(&"a".repeat(40)).expect("source SHA");
        let workflow_policy_digest = digest("workflow");
        let preparation_key = digest("prepared");
        let worker_id = "vps-build-1";
        let host_id = "vps-1";
        let operation_state = WorkflowOperationStateV1::new(
            attempt_id,
            &project_id,
            &source_sha,
            &workflow_policy_digest,
            &preparation_key,
            worker_id,
            host_id,
            vec![node.node_id.clone(), "verify".parse().expect("verify node")],
            512 * 1024 * 1024,
            10_000,
        )
        .expect("operation state");
        WorkflowLeaseV1::new(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            attempt_id,
            project_id,
            source_sha,
            source_sequence,
            digest(source_attestation),
            workflow_policy_digest,
            preparation_key,
            &node,
            &profile,
            None,
            vec![
                WorkflowLeaseInputV1 {
                    node_id: "prepare".parse().expect("prepare node"),
                    artifact_kind: WorkflowArtifactKindV1::PreparedRun,
                    output_digest: digest("prepared output"),
                },
                WorkflowLeaseInputV1 {
                    node_id: "verify".parse().expect("verify node"),
                    artifact_kind: WorkflowArtifactKindV1::VerificationReceipt,
                    output_digest: digest(verification_output),
                },
            ],
            digest("combined inputs"),
            worker_id.to_owned(),
            host_id.to_owned(),
            1_000,
            31_000,
        )
        .expect("lease")
        .with_operation_state(operation_state)
        .expect("stateful lease")
    }

    struct Fixture {
        _directory: TempDir,
        operation: PathBuf,
        output: PathBuf,
        request: PathBuf,
        handoff: PathBuf,
        request_root: PathBuf,
        uid: u32,
        gid: u32,
    }

    impl Fixture {
        fn new(request: &SelfReleaseBuildRequestV1) -> Self {
            let directory = tempfile::tempdir().expect("temporary directory");
            let metadata = fs::symlink_metadata(directory.path()).expect("temporary metadata");
            let uid = metadata.uid();
            let gid = metadata.gid();
            let operation = directory.path().join("operation");
            let output = directory.path().join("output");
            let handoff = directory.path().join("handoff");
            let request_root = directory.path().join("requests");
            for (path, mode) in [
                (&operation, 0o700),
                (&output, 0o2750),
                (&handoff, 0o711),
                (&request_root, 0o700),
            ] {
                fs::create_dir(path).expect("create fixture directory");
                fs::set_permissions(path, fs::Permissions::from_mode(mode))
                    .expect("protect fixture directory");
            }
            let release = operation.join("target/release");
            fs::create_dir_all(&release).expect("create release output");
            for binary in &request.binaries {
                let path = release.join(&binary.binary_name);
                fs::write(&path, format!("{} binary", binary.binary_name))
                    .expect("write release binary");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                    .expect("protect release binary");
            }
            let request_path = directory.path().join("request.jcs");
            fs::write(
                &request_path,
                request.canonical_bytes().expect("request bytes"),
            )
            .expect("write request");
            fs::set_permissions(&request_path, fs::Permissions::from_mode(0o444))
                .expect("protect request");
            Self {
                _directory: directory,
                operation,
                output,
                request: request_path,
                handoff,
                request_root,
                uid,
                gid,
            }
        }
    }

    #[test]
    fn request_requires_the_verified_serial_native_lease() {
        let policy = policy();
        let lease = lease();
        let request =
            SelfReleaseBuildRequestV1::from_policy(&lease, &policy).expect("native request");
        assert_eq!(
            request.verification_receipt_digest,
            digest("verification output")
        );
        assert_eq!(
            SelfReleaseBuildRequestV1::decode_canonical(
                &request.canonical_bytes().expect("request bytes")
            )
            .expect("decode request"),
            request
        );

        let mut wrong = lease;
        wrong
            .input_artifacts
            .retain(|input| input.artifact_kind == WorkflowArtifactKindV1::PreparedRun);
        wrong.input_contracts = vec![WorkflowArtifactKindV1::PreparedRun];
        assert!(SelfReleaseBuildRequestV1::from_policy(&wrong, &policy).is_err());
    }

    #[test]
    fn policy_requires_the_complete_versioned_runtime_payload() {
        let policy = policy();
        let mut incomplete = policy.binaries.clone();
        incomplete.pop();
        assert!(
            SelfReleaseBuildPolicyV1::new(
                policy.self_update_policy,
                policy.state_schema_version,
                policy.signature_validity_ms,
                incomplete,
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_client_reuses_release_outputs_without_compiling_again() {
        let policy = policy();
        let request = SelfReleaseBuildRequestV1::from_policy(&lease(), &policy).expect("request");
        let fixture = Fixture::new(&request);
        let result = execute_self_release_build(
            &fixture.request,
            &fixture.operation,
            &fixture.output,
            fixture.uid,
        )
        .expect("build release archive");
        assert_eq!(result.manifest.source_head, request.source_sha);
        assert_eq!(
            result.manifest.files.len(),
            VERSIONED_SELF_RELEASE_BINARIES.len()
        );
        assert_eq!(
            fs::read_dir(&fixture.output)
                .expect("output entries")
                .count(),
            3
        );
    }

    #[test]
    fn cargo_hard_links_are_sealed_before_the_strict_release_build() {
        let policy = policy();
        let request = SelfReleaseBuildRequestV1::from_policy(&lease(), &policy).expect("request");
        let fixture = Fixture::new(&request);
        let release_root = fixture.operation.join("target/release");
        for binary in &request.binaries {
            let source = release_root.join(&binary.binary_name);
            fs::hard_link(
                &source,
                release_root.join(format!(".deps-{}", binary.binary_name)),
            )
            .expect("simulate Cargo hard link");
            assert_eq!(
                fs::symlink_metadata(&source)
                    .expect("linked binary metadata")
                    .nlink(),
                2
            );
        }

        assert!(matches!(
            execute_self_release_build(
                &fixture.request,
                &fixture.operation,
                &fixture.output,
                fixture.uid,
            ),
            Err(SelfReleaseBuildError::SelfUpdate(
                SelfUpdateError::UnsafeBuildInput
            ))
        ));
        seal_versioned_self_release_inputs(&release_root).expect("seal canonical inputs");
        for binary in &request.binaries {
            let metadata = fs::symlink_metadata(release_root.join(&binary.binary_name))
                .expect("sealed binary metadata");
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o555);
        }
        execute_self_release_build(
            &fixture.request,
            &fixture.operation,
            &fixture.output,
            fixture.uid,
        )
        .expect("package sealed Cargo outputs");
    }

    #[test]
    fn root_store_signs_and_atomically_publishes_one_complete_directory() {
        let policy = policy();
        let request = SelfReleaseBuildRequestV1::from_policy(&lease(), &policy).expect("request");
        let fixture = Fixture::new(&request);
        execute_self_release_build(
            &fixture.request,
            &fixture.operation,
            &fixture.output,
            fixture.uid,
        )
        .expect("build worker output");
        let store = SelfReleaseHandoffStoreV1::open(
            fixture.handoff.clone(),
            fixture.request_root.clone(),
            fixture.uid,
            fixture.gid,
            fixture.uid,
            fixture.gid,
            fixture.gid,
            policy.clone(),
            signing_key(),
        )
        .expect("open handoff store");
        let staging = store.prepare(&request).expect("prepare handoff");
        for entry in fs::read_dir(&fixture.output).expect("built output") {
            let entry = entry.expect("built entry");
            fs::rename(entry.path(), staging.join(entry.file_name())).expect("move built entry");
        }
        let published = store.promote(&request, 1_500).expect("publish release");
        assert_eq!(
            published.descriptor.manifest.verification_receipt_digest,
            request.verification_receipt_digest
        );
        let final_path = fixture.handoff.join(format!(
            "{PUBLISHED_RELEASE_PREFIX}{}",
            published.descriptor.manifest.manifest_digest.as_str()
        ));
        assert!(final_path.join(DESCRIPTOR_FILE).is_file());
        assert!(final_path.join(ARCHIVE_FILE).is_file());
        assert!(!staging.exists());
        assert!(!store.request_path(&request).exists());
        assert_eq!(
            fs::symlink_metadata(&final_path)
                .expect("published metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o550
        );
    }

    #[test]
    fn root_store_keeps_distinct_attestations_of_the_same_source_commit() {
        let policy = policy();
        let first =
            SelfReleaseBuildRequestV1::from_policy(&lease(), &policy).expect("first request");
        let second = SelfReleaseBuildRequestV1::from_policy(
            &lease_for_source(8, "refreshed source", "refreshed verification"),
            &policy,
        )
        .expect("refreshed request");
        let fixture = Fixture::new(&first);
        let store = SelfReleaseHandoffStoreV1::open(
            fixture.handoff.clone(),
            fixture.request_root.clone(),
            fixture.uid,
            fixture.gid,
            fixture.uid,
            fixture.gid,
            fixture.gid,
            policy.clone(),
            signing_key(),
        )
        .expect("open handoff store");

        let mut published = Vec::new();
        for request in [&first, &second] {
            fs::remove_file(&fixture.request).expect("replace build request");
            fs::write(
                &fixture.request,
                request.canonical_bytes().expect("request bytes"),
            )
            .expect("write build request");
            fs::set_permissions(&fixture.request, fs::Permissions::from_mode(0o444))
                .expect("protect build request");
            execute_self_release_build(
                &fixture.request,
                &fixture.operation,
                &fixture.output,
                fixture.uid,
            )
            .expect("build release archive");
            let staging = store.prepare(request).expect("prepare handoff");
            for entry in fs::read_dir(&fixture.output).expect("built output") {
                let entry = entry.expect("built entry");
                fs::rename(entry.path(), staging.join(entry.file_name()))
                    .expect("move built entry");
            }
            published.push(store.promote(request, 1_500).expect("publish release"));
        }

        assert_ne!(
            published[0].descriptor.manifest.manifest_digest,
            published[1].descriptor.manifest.manifest_digest
        );
        assert_eq!(
            fs::read_dir(&fixture.handoff)
                .expect("handoff entries")
                .count(),
            2
        );
        for release in published {
            let path = fixture.handoff.join(format!(
                "{PUBLISHED_RELEASE_PREFIX}{}",
                release.descriptor.manifest.manifest_digest.as_str()
            ));
            assert!(path.join(DESCRIPTOR_FILE).is_file());
            assert!(path.join(ARCHIVE_FILE).is_file());
        }
        let loaded = crate::self_update_handoff::load_exact_self_release_handoff(
            &fixture.handoff,
            &second.source_sha,
            &policy.self_update_policy,
            fixture.uid,
            fixture.gid,
            fixture.gid,
            1_500,
        )
        .expect("load newest attestation for the exact source");
        assert_eq!(loaded.descriptor.manifest.source_sequence, 8);
    }

    #[test]
    fn startup_removes_only_bounded_hidden_staging_and_request_debt() {
        let policy = policy();
        let request = SelfReleaseBuildRequestV1::from_policy(&lease(), &policy).expect("request");
        let fixture = Fixture::new(&request);
        let staging = fixture.handoff.join(format!(
            ".stage-{}-g{}",
            request.lease_id.simple(),
            request.lease_generation
        ));
        fs::create_dir(&staging).expect("create interrupted staging");
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o2750))
            .expect("protect interrupted staging");
        fs::write(staging.join("partial"), b"partial").expect("write partial");
        fs::set_permissions(staging.join("partial"), fs::Permissions::from_mode(0o440))
            .expect("protect partial");
        let sealed_staging = fixture
            .handoff
            .join(format!(".stage-{}-g1", Uuid::from_u128(99).simple()));
        fs::create_dir(&sealed_staging).expect("create interrupted sealed staging");
        for name in [ARCHIVE_FILE, DESCRIPTOR_FILE] {
            fs::write(sealed_staging.join(name), b"interrupted sealed output")
                .expect("write interrupted sealed output");
            fs::set_permissions(sealed_staging.join(name), fs::Permissions::from_mode(0o440))
                .expect("protect interrupted sealed output");
        }
        fs::set_permissions(&sealed_staging, fs::Permissions::from_mode(0o550))
            .expect("seal interrupted staging");
        let request_path = fixture.request_root.join(format!(
            "{}-g{}.jcs",
            request.lease_id.simple(),
            request.lease_generation
        ));
        fs::write(
            &request_path,
            request.canonical_bytes().expect("request bytes"),
        )
        .expect("write interrupted request");
        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o444))
            .expect("protect interrupted request");
        let _store = SelfReleaseHandoffStoreV1::open(
            fixture.handoff.clone(),
            fixture.request_root.clone(),
            fixture.uid,
            fixture.gid,
            fixture.uid,
            fixture.gid,
            fixture.gid,
            policy,
            signing_key(),
        )
        .expect("reconcile handoff store");
        assert!(!staging.exists());
        assert!(!sealed_staging.exists());
        assert!(!request_path.exists());
    }
}
