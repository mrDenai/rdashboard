use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr as _,
    time::{SystemTime, UNIX_EPOCH},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    BackupAdapterError, BackupPipelineRuntimeV1, EncryptedBackupMaterialV1,
    ReadbackBackupMaterialV1, UploadedBackupMaterialV1,
};
use crate::{
    adapter::{DRIVE_SERVICE_ACCOUNT_CREDENTIAL_NAME, fixed_adapter_unit_name},
    backup::{
        BackupManifestV1, BackupObjectKindV1, BackupProviderV1, LocalBackupEvidenceV1,
        ProviderUploadReceiptV1, age_x25519_recipient_fingerprint,
    },
    domain::{EvidenceDigest, ProjectId},
    phase6::{AuthorizedPhaseSpecV1, FixedAdapterProfileV1},
    rimg_adapter::runtime::{
        read_stable_private_file, validate_executable, validate_private_directory,
    },
};

pub const BACKUP_ADAPTER_CONFIG_PATH: &str = "/etc/rdashboard/projects/rimg/backup-runtime.jcs";
pub const AGE_EXECUTABLE_PATH: &str = "/usr/libexec/rdashboard/age";
pub const RCLONE_EXECUTABLE_PATH: &str = "/usr/libexec/rdashboard/rclone";
pub const RCLONE_CONFIG_PATH: &str = "/etc/rdashboard/projects/rimg/rclone.conf";

const BACKUP_ROOT: &str = "/var/lib/rdashboard-executor/backups";
const SYSTEMD_CREDENTIAL_ROOT: &str = "/run/credentials";
const MAX_RUNTIME_CONFIG_BYTES: u64 = 32 * 1024;
const MAX_RCLONE_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_CREDENTIAL_BYTES: u64 = 128 * 1024;
const MAX_STATE_BYTES: u64 = 64 * 1024;
const MAX_PROVIDER_STDOUT_BYTES: usize = 256 * 1024;
const ARCHIVE_MAGIC: &[u8; 8] = b"RDBARCH1";
const ENCRYPTION_STATE_SUFFIX: &str = ".age.jcs";
const ENCRYPTION_PENDING_SUFFIX: &str = ".age.pending";
const ENCRYPTION_STATE_PENDING_SUFFIX: &str = ".age.jcs.pending";
const UPLOAD_STATE_FILE: &str = "provider-upload.jcs";

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledBackupAdapterRuntimeV1 {
    pub purpose: String,
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub installed_rimg_policy_digest: EvidenceDigest,
    pub age_sha256: EvidenceDigest,
    pub age_recipient: String,
    pub age_recipient_fingerprint: EvidenceDigest,
    pub rclone_sha256: EvidenceDigest,
    pub rclone_config_sha256: EvidenceDigest,
    pub provider: BackupProviderV1,
    pub provider_credential_version: u64,
    pub drive_remote: String,
    pub drive_root_folder_id: String,
    pub drive_service_account_sha256: EvidenceDigest,
}

impl InstalledBackupAdapterRuntimeV1 {
    fn load(
        config_path: &Path,
        age_path: &Path,
        rclone_path: &Path,
        rclone_config_path: &Path,
        required_uid: u32,
        spec: &AuthorizedPhaseSpecV1,
    ) -> Result<Self, BackupAdapterError> {
        let bytes = read_stable_private_file(config_path, required_uid, MAX_RUNTIME_CONFIG_BYTES)?;
        let config: Self = serde_json::from_slice(&bytes)?;
        let backup = spec
            .backup
            .as_ref()
            .ok_or(BackupAdapterError::MissingBackupAuthorization)?;
        if serde_jcs::to_vec(&config)? != bytes
            || config.purpose != "rdashboard.installed-backup-adapter-runtime.v1"
            || config.schema_version != 1
            || config.project_id != spec.project_id
            || config.installed_rimg_policy_digest != spec.installed_rimg_policy_digest
            || config.provider != BackupProviderV1::GoogleDrive
            || config.provider != backup.provider
            || config.provider_credential_version != backup.provider_credential_version
            || !valid_remote_name(&config.drive_remote)
            || !valid_drive_identifier(&config.drive_root_folder_id)
            || !valid_age_recipient(&config.age_recipient)
            || config.age_recipient_fingerprint
                != age_x25519_recipient_fingerprint(&config.age_recipient)
            || config.age_recipient_fingerprint != backup.recipient_fingerprint
        {
            return Err(BackupAdapterError::RuntimeConfigMismatch);
        }
        validate_executable(age_path, required_uid, &config.age_sha256)?;
        validate_executable(rclone_path, required_uid, &config.rclone_sha256)?;
        let rclone_config =
            read_stable_private_file(rclone_config_path, required_uid, MAX_RCLONE_CONFIG_BYTES)?;
        if rclone_config != canonical_rclone_config(&config)
            || EvidenceDigest::sha256(&rclone_config) != config.rclone_config_sha256
        {
            return Err(BackupAdapterError::RuntimeConfigMismatch);
        }
        Ok(config)
    }
}

#[derive(Debug)]
pub struct InstalledBackupPipelineRuntimeV1 {
    config: InstalledBackupAdapterRuntimeV1,
    age_path: PathBuf,
    rclone_path: PathBuf,
    rclone_config_path: PathBuf,
    credential_path: PathBuf,
    backup_root: PathBuf,
    job_directory: PathBuf,
    required_uid: u32,
}

impl InstalledBackupPipelineRuntimeV1 {
    pub fn new(
        job_directory: &Path,
        spec: &AuthorizedPhaseSpecV1,
        profile: FixedAdapterProfileV1,
        sequence: u16,
    ) -> Result<Self, BackupAdapterError> {
        let unit_name = fixed_adapter_unit_name(spec, sequence)?;
        let credential_path = credential_path_for_unit(&unit_name);
        Self::new_bound(
            Path::new(BACKUP_ADAPTER_CONFIG_PATH),
            Path::new(AGE_EXECUTABLE_PATH),
            Path::new(RCLONE_EXECUTABLE_PATH),
            Path::new(RCLONE_CONFIG_PATH),
            &credential_path,
            Path::new(BACKUP_ROOT),
            job_directory,
            0,
            spec,
            profile,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_bound(
        config_path: &Path,
        age_path: &Path,
        rclone_path: &Path,
        rclone_config_path: &Path,
        credential_path: &Path,
        backup_root: &Path,
        job_directory: &Path,
        required_uid: u32,
        spec: &AuthorizedPhaseSpecV1,
        profile: FixedAdapterProfileV1,
    ) -> Result<Self, BackupAdapterError> {
        validate_private_directory(backup_root, required_uid)?;
        validate_private_directory(job_directory, required_uid)?;
        let config = InstalledBackupAdapterRuntimeV1::load(
            config_path,
            age_path,
            rclone_path,
            rclone_config_path,
            required_uid,
            spec,
        )?;
        if matches!(
            profile,
            FixedAdapterProfileV1::BackupUploadGoogleDrive
                | FixedAdapterProfileV1::BackupReadbackVerify
        ) {
            let credential =
                read_stable_private_file(credential_path, required_uid, MAX_CREDENTIAL_BYTES)?;
            if EvidenceDigest::sha256(credential) != config.drive_service_account_sha256 {
                return Err(BackupAdapterError::RuntimeConfigMismatch);
            }
        }
        Ok(Self {
            config,
            age_path: age_path.to_path_buf(),
            rclone_path: rclone_path.to_path_buf(),
            rclone_config_path: rclone_config_path.to_path_buf(),
            credential_path: credential_path.to_path_buf(),
            backup_root: backup_root.to_path_buf(),
            job_directory: job_directory.to_path_buf(),
            required_uid,
        })
    }
}

fn credential_path_for_unit(unit_name: &str) -> PathBuf {
    Path::new(SYSTEMD_CREDENTIAL_ROOT)
        .join(format!("{unit_name}.service"))
        .join(DRIVE_SERVICE_ACCOUNT_CREDENTIAL_NAME)
}

impl BackupPipelineRuntimeV1 for InstalledBackupPipelineRuntimeV1 {
    fn encrypt(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
        manifest: &BackupManifestV1,
    ) -> Result<EncryptedBackupMaterialV1, BackupAdapterError> {
        manifest.require_verified_against(required_backup(spec)?)?;
        let paths = EncryptionPathsV1::new(&self.backup_root, manifest.backup_id);
        if let Some(state) =
            reconcile_encrypted_artifact(&paths, spec, manifest, &self.config, self.required_uid)?
        {
            return Ok(state.into_material());
        }
        remove_safe_pending(&paths.ciphertext_pending, self.required_uid)?;
        remove_safe_pending(&paths.state_pending, self.required_uid)?;
        let plaintext_archive_digest = encrypt_archive(
            &self.age_path,
            &self.config.age_recipient,
            &paths.ciphertext_pending,
            &self.backup_root.join(manifest.backup_id.to_string()),
            manifest,
            self.required_uid,
        )?;
        fs::set_permissions(&paths.ciphertext_pending, fs::Permissions::from_mode(0o600))?;
        let ciphertext =
            hash_private_file(&paths.ciphertext_pending, self.required_uid, None, true)?;
        let state = EncryptionStateV1 {
            purpose: "rdashboard.encrypted-backup-state.v1".to_owned(),
            schema_version: 1,
            authorized_spec_digest: required_backup(spec)?.spec_digest.clone(),
            backup_id: manifest.backup_id,
            manifest_digest: manifest.manifest_digest.clone(),
            plaintext_archive_digest,
            recipient_fingerprint: self.config.age_recipient_fingerprint.clone(),
            age_executable_digest: self.config.age_sha256.clone(),
            ciphertext_digest: ciphertext.digest,
            ciphertext_size_bytes: ciphertext.size,
            encrypted_at_ms: now_ms()?,
        };
        state.validate(spec, manifest, &self.config)?;
        materialize_private_state(&paths.state_pending, self.required_uid, &state)?;
        publish_link(&paths.ciphertext_pending, &paths.ciphertext)?;
        publish_link(&paths.state_pending, &paths.state)?;
        remove_safe_pending(&paths.ciphertext_pending, self.required_uid)?;
        remove_safe_pending(&paths.state_pending, self.required_uid)?;
        sync_directory(&self.backup_root)?;
        let state =
            validate_published_encryption(&paths, spec, manifest, &self.config, self.required_uid)?;
        Ok(state.into_material())
    }

    fn upload(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
        local: &LocalBackupEvidenceV1,
    ) -> Result<UploadedBackupMaterialV1, BackupAdapterError> {
        let backup = required_backup(spec)?;
        let ciphertext_path = self.backup_root.join(format!("{}.age", backup.backup_id));
        let ciphertext = hash_private_file(
            &ciphertext_path,
            self.required_uid,
            Some(local.encryption.ciphertext_size_bytes),
            false,
        )?;
        if ciphertext.digest != local.encryption.ciphertext_digest {
            return Err(BackupAdapterError::InvalidEncryptedArtifact);
        }
        let remote_key = remote_key(backup, &local.encryption.ciphertext_digest);
        let remote_path = format!("{}:{remote_key}", self.config.drive_remote);
        let state_path = self.job_directory.join(UPLOAD_STATE_FILE);
        if state_path.exists() {
            let state: ProviderUploadStateV1 =
                read_canonical_state(&state_path, self.required_uid, MAX_STATE_BYTES)?;
            let observed = self.stat_remote(&remote_key)?;
            state.validate(spec, local, &remote_key, &observed, &self.config)?;
            return Ok(state.into_material());
        }
        let observed = if self.stat_remote_optional(&remote_key)?.is_some() {
            self.verify_remote_ciphertext(&remote_key, &remote_path, local)?
        } else {
            let source = path_text(&ciphertext_path)?;
            self.run_rclone(&["copyto", source, &remote_path, "--immutable", "--checksum"])?;
            self.verify_remote_ciphertext(&remote_key, &remote_path, local)?
        };
        let uploaded_at_ms = now_ms()?;
        let version_id = remote_version_id(&observed)?;
        let provider_receipt_digest = upload_observation_digest(
            &remote_key,
            &observed,
            &local.encryption.ciphertext_digest,
            self.config.provider_credential_version,
        )?;
        let state = ProviderUploadStateV1 {
            purpose: "rdashboard.provider-upload-state.v1".to_owned(),
            schema_version: 1,
            authorized_spec_digest: backup.spec_digest.clone(),
            local_evidence_digest: local.evidence_digest.clone(),
            remote_key,
            object_id: observed.id.clone(),
            version_id,
            size_bytes: observed.size,
            ciphertext_digest: local.encryption.ciphertext_digest.clone(),
            provider_credential_version: self.config.provider_credential_version,
            uploaded_at_ms,
            provider_receipt_digest,
        };
        state.validate(spec, local, &state.remote_key, &observed, &self.config)?;
        materialize_private_state(&state_path, self.required_uid, &state)?;
        Ok(state.into_material())
    }

    fn readback(
        &mut self,
        spec: &AuthorizedPhaseSpecV1,
        local: &LocalBackupEvidenceV1,
        receipt: &ProviderUploadReceiptV1,
    ) -> Result<ReadbackBackupMaterialV1, BackupAdapterError> {
        let backup = required_backup(spec)?;
        receipt.require_verified_against(backup, local)?;
        let remote_key = remote_key(backup, &local.encryption.ciphertext_digest);
        let remote_path = format!("{}:{remote_key}", self.config.drive_remote);
        let observed = self.verify_remote_ciphertext(&remote_key, &remote_path, local)?;
        if observed.id != receipt.object_id || remote_version_id(&observed)? != receipt.version_id {
            return Err(BackupAdapterError::InvalidProviderEvidence);
        }
        let verified_at_ms = now_ms()?;
        let observation_digest = readback_observation_digest(
            &remote_key,
            &observed,
            &receipt.ciphertext_digest,
            verified_at_ms,
        )?;
        Ok(ReadbackBackupMaterialV1 {
            size_bytes: receipt.size_bytes,
            ciphertext_digest: receipt.ciphertext_digest.clone(),
            observation_digest,
            verified_at_ms,
        })
    }
}

impl InstalledBackupPipelineRuntimeV1 {
    fn verify_remote_ciphertext(
        &self,
        remote_key: &str,
        remote_path: &str,
        local: &LocalBackupEvidenceV1,
    ) -> Result<RcloneObjectV1, BackupAdapterError> {
        let before = self.stat_remote(remote_key)?;
        validate_remote_object(&before, remote_key, local)?;
        let readback = self.hash_remote(remote_path, local.encryption.ciphertext_size_bytes)?;
        if readback.digest != local.encryption.ciphertext_digest {
            return Err(BackupAdapterError::InvalidProviderReadback);
        }
        let after = self.stat_remote(remote_key)?;
        validate_remote_object(&after, remote_key, local)?;
        if before != after {
            return Err(BackupAdapterError::InvalidProviderEvidence);
        }
        Ok(after)
    }

    fn stat_remote(&self, remote_key: &str) -> Result<RcloneObjectV1, BackupAdapterError> {
        self.stat_remote_optional(remote_key)?
            .ok_or(BackupAdapterError::InvalidProviderEvidence)
    }

    fn stat_remote_optional(
        &self,
        remote_key: &str,
    ) -> Result<Option<RcloneObjectV1>, BackupAdapterError> {
        let (parent, name) = remote_key
            .rsplit_once('/')
            .ok_or(BackupAdapterError::InvalidProviderEvidence)?;
        let remote_parent = format!("{}:{parent}", self.config.drive_remote);
        let bytes = self.run_rclone(&[
            "lsjson",
            &remote_parent,
            "--files-only",
            "--hash",
            "--hash-type",
            "MD5",
            "--max-depth",
            "1",
        ])?;
        let matches = serde_json::from_slice::<Vec<RcloneObjectV1>>(&bytes)?
            .into_iter()
            .filter(|object| object.name == name && object.path == name)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Ok(None),
            [object] => Ok(Some(object.clone())),
            _ => Err(BackupAdapterError::InvalidProviderEvidence),
        }
    }

    fn run_rclone(&self, arguments: &[&str]) -> Result<Vec<u8>, BackupAdapterError> {
        let config = path_text(&self.rclone_config_path)?;
        let credential = path_text(&self.credential_path)?;
        let mut command = Command::new(&self.rclone_path);
        command.args([
            "--config",
            config,
            "--drive-service-account-file",
            credential,
            "--drive-auth-owner-only",
            "--retries",
            "1",
            "--low-level-retries",
            "1",
            "--stats",
            "0",
        ]);
        command.args(arguments);
        run_bounded_stdout(command, MAX_PROVIDER_STDOUT_BYTES)
    }

    fn hash_remote(
        &self,
        remote_path: &str,
        expected_size: u64,
    ) -> Result<FileHashV1, BackupAdapterError> {
        let config = path_text(&self.rclone_config_path)?;
        let credential = path_text(&self.credential_path)?;
        let mut child = Command::new(&self.rclone_path)
            .args([
                "--config",
                config,
                "--drive-service-account-file",
                credential,
                "--drive-auth-owner-only",
                "--retries",
                "1",
                "--low-level-retries",
                "1",
                "--stats",
                "0",
                "cat",
                remote_path,
            ])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("rclone stdout pipe is unavailable"))?;
        let result = hash_reader_exact(&mut stdout, expected_size);
        if result.is_err() {
            let _ = child.kill();
        }
        let status = child.wait()?;
        let hash = result?;
        if !status.success() {
            return Err(BackupAdapterError::CommandFailed(format!(
                "rclone exited with {status}"
            )));
        }
        Ok(hash)
    }
}

#[derive(Clone, Debug)]
struct EncryptionPathsV1 {
    ciphertext: PathBuf,
    ciphertext_pending: PathBuf,
    state: PathBuf,
    state_pending: PathBuf,
}

impl EncryptionPathsV1 {
    fn new(root: &Path, backup_id: uuid::Uuid) -> Self {
        let name = backup_id.to_string();
        Self {
            ciphertext: root.join(format!("{name}.age")),
            ciphertext_pending: root.join(format!("{name}{ENCRYPTION_PENDING_SUFFIX}")),
            state: root.join(format!("{name}{ENCRYPTION_STATE_SUFFIX}")),
            state_pending: root.join(format!("{name}{ENCRYPTION_STATE_PENDING_SUFFIX}")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EncryptionStateV1 {
    purpose: String,
    schema_version: u16,
    authorized_spec_digest: EvidenceDigest,
    backup_id: uuid::Uuid,
    manifest_digest: EvidenceDigest,
    plaintext_archive_digest: EvidenceDigest,
    recipient_fingerprint: EvidenceDigest,
    age_executable_digest: EvidenceDigest,
    ciphertext_digest: EvidenceDigest,
    ciphertext_size_bytes: u64,
    encrypted_at_ms: i64,
}

impl EncryptionStateV1 {
    fn validate(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        manifest: &BackupManifestV1,
        config: &InstalledBackupAdapterRuntimeV1,
    ) -> Result<(), BackupAdapterError> {
        let backup = required_backup(spec)?;
        if self.purpose != "rdashboard.encrypted-backup-state.v1"
            || self.schema_version != 1
            || self.authorized_spec_digest != backup.spec_digest
            || self.backup_id != backup.backup_id
            || self.manifest_digest != manifest.manifest_digest
            || self.recipient_fingerprint != backup.recipient_fingerprint
            || self.recipient_fingerprint != config.age_recipient_fingerprint
            || self.age_executable_digest != config.age_sha256
            || self.ciphertext_size_bytes == 0
            || self.encrypted_at_ms < manifest.completed_at_ms
            || self.encrypted_at_ms > backup.capture_deadline_ms
        {
            return Err(BackupAdapterError::InvalidEncryptedArtifact);
        }
        Ok(())
    }

    fn into_material(self) -> EncryptedBackupMaterialV1 {
        EncryptedBackupMaterialV1 {
            plaintext_archive_digest: self.plaintext_archive_digest,
            ciphertext_digest: self.ciphertext_digest,
            ciphertext_size_bytes: self.ciphertext_size_bytes,
            encrypted_at_ms: self.encrypted_at_ms,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderUploadStateV1 {
    purpose: String,
    schema_version: u16,
    authorized_spec_digest: EvidenceDigest,
    local_evidence_digest: EvidenceDigest,
    remote_key: String,
    object_id: String,
    version_id: String,
    size_bytes: u64,
    ciphertext_digest: EvidenceDigest,
    provider_credential_version: u64,
    uploaded_at_ms: i64,
    provider_receipt_digest: EvidenceDigest,
}

impl ProviderUploadStateV1 {
    fn validate(
        &self,
        spec: &AuthorizedPhaseSpecV1,
        local: &LocalBackupEvidenceV1,
        remote_key: &str,
        observed: &RcloneObjectV1,
        config: &InstalledBackupAdapterRuntimeV1,
    ) -> Result<(), BackupAdapterError> {
        let backup = required_backup(spec)?;
        validate_remote_object(observed, remote_key, local)?;
        if self.purpose != "rdashboard.provider-upload-state.v1"
            || self.schema_version != 1
            || self.authorized_spec_digest != backup.spec_digest
            || self.local_evidence_digest != local.evidence_digest
            || self.remote_key != remote_key
            || self.object_id != observed.id
            || self.version_id != remote_version_id(observed)?
            || self.size_bytes != local.encryption.ciphertext_size_bytes
            || self.ciphertext_digest != local.encryption.ciphertext_digest
            || self.provider_credential_version != backup.provider_credential_version
            || self.provider_credential_version != config.provider_credential_version
            || self.uploaded_at_ms < local.encryption.encrypted_at_ms
            || self.uploaded_at_ms > backup.capture_deadline_ms
            || self.provider_receipt_digest
                != upload_observation_digest(
                    remote_key,
                    observed,
                    &local.encryption.ciphertext_digest,
                    self.provider_credential_version,
                )?
        {
            return Err(BackupAdapterError::InvalidProviderEvidence);
        }
        Ok(())
    }

    fn into_material(self) -> UploadedBackupMaterialV1 {
        UploadedBackupMaterialV1 {
            object_id: self.object_id,
            version_id: self.version_id,
            uploaded_at_ms: self.uploaded_at_ms,
            provider_receipt_digest: self.provider_receipt_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RcloneObjectV1 {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Size")]
    size: u64,
    #[serde(rename = "IsDir")]
    is_dir: bool,
    #[serde(rename = "Hashes")]
    hashes: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct UploadObservationV1<'a> {
    purpose: &'static str,
    remote_key: &'a str,
    object: &'a RcloneObjectV1,
    ciphertext_digest: &'a EvidenceDigest,
    provider_credential_version: u64,
}

#[derive(Serialize)]
struct ReadbackObservationV1<'a> {
    purpose: &'static str,
    remote_key: &'a str,
    object: &'a RcloneObjectV1,
    readback_ciphertext_digest: &'a EvidenceDigest,
    verified_at_ms: i64,
}

fn required_backup(
    spec: &AuthorizedPhaseSpecV1,
) -> Result<&crate::backup::AuthorizedBackupSpecV1, BackupAdapterError> {
    spec.backup
        .as_ref()
        .ok_or(BackupAdapterError::MissingBackupAuthorization)
}

fn valid_age_recipient(value: &str) -> bool {
    value.len() == 62
        && value.starts_with("age1")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_remote_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_drive_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn canonical_rclone_config(config: &InstalledBackupAdapterRuntimeV1) -> Vec<u8> {
    format!(
        "[{}]\ntype = drive\nscope = drive.file\nroot_folder_id = {}\n",
        config.drive_remote, config.drive_root_folder_id
    )
    .into_bytes()
}

fn now_ms() -> Result<i64, BackupAdapterError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackupAdapterError::RuntimeConfigMismatch)?;
    i64::try_from(duration.as_millis()).map_err(|_| BackupAdapterError::RuntimeConfigMismatch)
}

fn path_text(path: &Path) -> Result<&str, BackupAdapterError> {
    path.to_str()
        .ok_or(BackupAdapterError::RuntimeConfigMismatch)
}

fn remote_key(
    backup: &crate::backup::AuthorizedBackupSpecV1,
    ciphertext_digest: &EvidenceDigest,
) -> String {
    format!(
        "{}/{}/{}.age",
        backup.backup_set_id, backup.backup_id, ciphertext_digest
    )
}

fn remote_version_id(object: &RcloneObjectV1) -> Result<String, BackupAdapterError> {
    let md5 = object
        .hashes
        .get("MD5")
        .filter(|value| value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(BackupAdapterError::InvalidProviderEvidence)?;
    Ok(format!(
        "gdrive:{}:md5:{}",
        object.id,
        md5.to_ascii_lowercase()
    ))
}

fn validate_remote_object(
    object: &RcloneObjectV1,
    remote_key: &str,
    local: &LocalBackupEvidenceV1,
) -> Result<(), BackupAdapterError> {
    let expected_name = remote_key
        .rsplit_once('/')
        .map_or(remote_key, |(_, name)| name);
    if object.id.is_empty()
        || object.id.len() > 512
        || !valid_drive_identifier(&object.id)
        || object.is_dir
        || object.name != expected_name
        || object.path != expected_name
        || object.size != local.encryption.ciphertext_size_bytes
        || remote_version_id(object).is_err()
    {
        return Err(BackupAdapterError::InvalidProviderEvidence);
    }
    Ok(())
}

fn upload_observation_digest(
    remote_key: &str,
    object: &RcloneObjectV1,
    ciphertext_digest: &EvidenceDigest,
    credential_version: u64,
) -> Result<EvidenceDigest, BackupAdapterError> {
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
        &UploadObservationV1 {
            purpose: "rdashboard.google-drive-upload-observation.v1",
            remote_key,
            object,
            ciphertext_digest,
            provider_credential_version: credential_version,
        },
    )?))
}

fn readback_observation_digest(
    remote_key: &str,
    object: &RcloneObjectV1,
    ciphertext_digest: &EvidenceDigest,
    verified_at_ms: i64,
) -> Result<EvidenceDigest, BackupAdapterError> {
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
        &ReadbackObservationV1 {
            purpose: "rdashboard.google-drive-readback-observation.v1",
            remote_key,
            object,
            readback_ciphertext_digest: ciphertext_digest,
            verified_at_ms,
        },
    )?))
}

fn reconcile_encrypted_artifact(
    paths: &EncryptionPathsV1,
    spec: &AuthorizedPhaseSpecV1,
    manifest: &BackupManifestV1,
    config: &InstalledBackupAdapterRuntimeV1,
    required_uid: u32,
) -> Result<Option<EncryptionStateV1>, BackupAdapterError> {
    if paths.state.exists() && paths.ciphertext.exists() {
        remove_safe_pending(&paths.ciphertext_pending, required_uid)?;
        remove_safe_pending(&paths.state_pending, required_uid)?;
        return validate_published_encryption(paths, spec, manifest, config, required_uid)
            .map(Some);
    }
    if paths.state.exists() || paths.ciphertext.exists() && !paths.state_pending.exists() {
        return Err(BackupAdapterError::InvalidEncryptedArtifact);
    }
    if paths.state_pending.exists() {
        let candidate = if paths.ciphertext.exists() {
            &paths.ciphertext
        } else if paths.ciphertext_pending.exists() {
            &paths.ciphertext_pending
        } else {
            return Err(BackupAdapterError::InvalidEncryptedArtifact);
        };
        validate_encryption_pair(
            candidate,
            &paths.state_pending,
            spec,
            manifest,
            config,
            required_uid,
            true,
        )?;
        if !paths.ciphertext.exists() {
            publish_link(&paths.ciphertext_pending, &paths.ciphertext)?;
        }
        publish_link(&paths.state_pending, &paths.state)?;
        remove_safe_pending(&paths.ciphertext_pending, required_uid)?;
        remove_safe_pending(&paths.state_pending, required_uid)?;
        sync_directory(
            paths
                .ciphertext
                .parent()
                .ok_or(BackupAdapterError::InvalidEncryptedArtifact)?,
        )?;
        return validate_published_encryption(paths, spec, manifest, config, required_uid)
            .map(Some);
    }
    remove_safe_pending(&paths.ciphertext_pending, required_uid)?;
    Ok(None)
}

fn validate_published_encryption(
    paths: &EncryptionPathsV1,
    spec: &AuthorizedPhaseSpecV1,
    manifest: &BackupManifestV1,
    config: &InstalledBackupAdapterRuntimeV1,
    required_uid: u32,
) -> Result<EncryptionStateV1, BackupAdapterError> {
    validate_encryption_pair(
        &paths.ciphertext,
        &paths.state,
        spec,
        manifest,
        config,
        required_uid,
        false,
    )
}

fn validate_encryption_pair(
    ciphertext_path: &Path,
    state_path: &Path,
    spec: &AuthorizedPhaseSpecV1,
    manifest: &BackupManifestV1,
    config: &InstalledBackupAdapterRuntimeV1,
    required_uid: u32,
    allow_multiple_links: bool,
) -> Result<EncryptionStateV1, BackupAdapterError> {
    let state: EncryptionStateV1 = read_canonical_state(state_path, required_uid, MAX_STATE_BYTES)?;
    state.validate(spec, manifest, config)?;
    let ciphertext = hash_private_file(
        ciphertext_path,
        required_uid,
        Some(state.ciphertext_size_bytes),
        allow_multiple_links,
    )?;
    if ciphertext.digest != state.ciphertext_digest {
        return Err(BackupAdapterError::InvalidEncryptedArtifact);
    }
    let archive_digest = plaintext_archive_digest(
        &ciphertext_path
            .parent()
            .ok_or(BackupAdapterError::InvalidEncryptedArtifact)?
            .join(manifest.backup_id.to_string()),
        manifest,
        required_uid,
    )?;
    if archive_digest != state.plaintext_archive_digest {
        return Err(BackupAdapterError::InvalidEncryptedArtifact);
    }
    Ok(state)
}

fn plaintext_archive_digest(
    snapshot: &Path,
    manifest: &BackupManifestV1,
    required_uid: u32,
) -> Result<EvidenceDigest, BackupAdapterError> {
    let mut writer = DigestWriterV1::new(io::sink());
    write_plaintext_archive(&mut writer, snapshot, manifest, required_uid)?;
    Ok(writer.finish())
}

fn encrypt_archive(
    age_path: &Path,
    recipient: &str,
    output: &Path,
    snapshot: &Path,
    manifest: &BackupManifestV1,
    required_uid: u32,
) -> Result<EvidenceDigest, BackupAdapterError> {
    let output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)?;
    let mut child = Command::new(age_path)
        .args(["--encrypt", "--recipient", recipient, "-"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::from(output_file))
        .stderr(Stdio::null())
        .spawn()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("age stdin pipe is unavailable"))?;
    let mut writer = DigestWriterV1::new(stdin);
    let write_result = write_plaintext_archive(&mut writer, snapshot, manifest, required_uid);
    let digest = writer.finish();
    if write_result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    write_result?;
    if !status.success() {
        return Err(BackupAdapterError::CommandFailed(format!(
            "age exited with {status}"
        )));
    }
    File::open(output)?.sync_all()?;
    Ok(digest)
}

fn write_plaintext_archive(
    writer: &mut impl Write,
    snapshot: &Path,
    manifest: &BackupManifestV1,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    let manifest_bytes = manifest.canonical_bytes()?;
    let database = manifest
        .objects
        .iter()
        .find(|object| object.kind == BackupObjectKindV1::SqliteDatabase)
        .ok_or(BackupAdapterError::InvalidSnapshot)?;
    let masters = manifest
        .objects
        .iter()
        .find(|object| object.kind == BackupObjectKindV1::Master)
        .ok_or(BackupAdapterError::InvalidSnapshot)?;
    writer.write_all(ARCHIVE_MAGIC)?;
    writer.write_all(&3_u32.to_be_bytes())?;
    write_memory_entry(
        writer,
        "rdashboard-manifest.jcs",
        &manifest_bytes,
        &EvidenceDigest::sha256(&manifest_bytes),
    )?;
    write_file_entry(
        writer,
        "database.sqlite",
        &snapshot.join("database.sqlite"),
        database,
        required_uid,
    )?;
    write_file_entry(
        writer,
        "masters.bundle",
        &snapshot.join("masters.bundle"),
        masters,
        required_uid,
    )
}

fn write_memory_entry(
    writer: &mut impl Write,
    name: &str,
    bytes: &[u8],
    digest: &EvidenceDigest,
) -> Result<(), BackupAdapterError> {
    write_entry_header(
        writer,
        name,
        u64::try_from(bytes.len()).map_err(|_| BackupAdapterError::InvalidSnapshot)?,
        digest,
    )?;
    writer.write_all(bytes)?;
    Ok(())
}

fn write_file_entry(
    writer: &mut impl Write,
    name: &str,
    path: &Path,
    expected: &crate::backup::BackupObjectV1,
    required_uid: u32,
) -> Result<(), BackupAdapterError> {
    write_entry_header(writer, name, expected.size_bytes, &expected.sha256)?;
    let path_metadata =
        safe_private_file_metadata(path, required_uid, Some(expected.size_bytes), false)?;
    if path_metadata.uid() != expected.uid
        || path_metadata.gid() != expected.gid
        || path_metadata.mode() & 0o777 != expected.mode
        || path_metadata.nlink() != expected.hard_link_count
    {
        return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != path_metadata.dev() || opened.ino() != path_metadata.ino() {
        return Err(BackupAdapterError::UnsafeSnapshotFilesystem);
    }
    let mut remaining = expected.size_bytes;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| BackupAdapterError::InvalidSnapshot)?;
        let read = file.read(&mut buffer[..limit])?;
        if read == 0 {
            return Err(BackupAdapterError::InvalidSnapshot);
        }
        writer.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        remaining -= u64::try_from(read).unwrap_or(0);
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0
        || digest_from_hasher(hasher)? != expected.sha256
        || !same_file_after_read(path, &opened)?
    {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    Ok(())
}

fn write_entry_header(
    writer: &mut impl Write,
    name: &str,
    size: u64,
    digest: &EvidenceDigest,
) -> Result<(), BackupAdapterError> {
    let name = name.as_bytes();
    writer.write_all(
        &u32::try_from(name.len())
            .map_err(|_| BackupAdapterError::InvalidSnapshot)?
            .to_be_bytes(),
    )?;
    writer.write_all(name)?;
    writer.write_all(&size.to_be_bytes())?;
    writer.write_all(&digest_bytes(digest)?)?;
    Ok(())
}

struct DigestWriterV1<W> {
    inner: W,
    hasher: Sha256,
}

impl<W> DigestWriterV1<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finish(self) -> EvidenceDigest {
        EvidenceDigest::from_str(&format!("{:x}", self.hasher.finalize()))
            .unwrap_or_else(|_| EvidenceDigest::sha256([]))
    }
}

impl<W: Write> Write for DigestWriterV1<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileHashV1 {
    size: u64,
    digest: EvidenceDigest,
}

fn hash_private_file(
    path: &Path,
    required_uid: u32,
    expected_size: Option<u64>,
    allow_multiple_links: bool,
) -> Result<FileHashV1, BackupAdapterError> {
    let path_metadata =
        safe_private_file_metadata(path, required_uid, expected_size, allow_multiple_links)?;
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != path_metadata.dev() || opened.ino() != path_metadata.ino() {
        return Err(BackupAdapterError::InvalidEncryptedArtifact);
    }
    let mut hasher = Sha256::new();
    let size = io::copy(&mut file, &mut hasher)?;
    if size != opened.len() || !same_file_after_read(path, &opened)? {
        return Err(BackupAdapterError::InvalidEncryptedArtifact);
    }
    Ok(FileHashV1 {
        size,
        digest: digest_from_hasher(hasher)?,
    })
}

fn hash_reader_exact(
    reader: &mut impl Read,
    expected_size: u64,
) -> Result<FileHashV1, BackupAdapterError> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or(BackupAdapterError::InvalidProviderReadback)?;
        if size > expected_size {
            return Err(BackupAdapterError::InvalidProviderReadback);
        }
        hasher.update(&buffer[..read]);
    }
    if size != expected_size {
        return Err(BackupAdapterError::InvalidProviderReadback);
    }
    Ok(FileHashV1 {
        size,
        digest: digest_from_hasher(hasher)?,
    })
}

fn safe_private_file_metadata(
    path: &Path,
    required_uid: u32,
    expected_size: Option<u64>,
    allow_multiple_links: bool,
) -> Result<fs::Metadata, BackupAdapterError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != required_uid
        || metadata.mode() & 0o077 != 0
        || metadata.len() == 0
        || expected_size.is_some_and(|size| size != metadata.len())
        || if allow_multiple_links {
            metadata.nlink() > 2
        } else {
            metadata.nlink() != 1
        }
    {
        return Err(BackupAdapterError::InvalidEncryptedArtifact);
    }
    Ok(metadata)
}

fn same_file_after_read(path: &Path, opened: &fs::Metadata) -> Result<bool, BackupAdapterError> {
    let final_metadata = fs::symlink_metadata(path)?;
    Ok(!final_metadata.file_type().is_symlink()
        && final_metadata.dev() == opened.dev()
        && final_metadata.ino() == opened.ino()
        && final_metadata.len() == opened.len())
}

fn digest_from_hasher(hasher: Sha256) -> Result<EvidenceDigest, BackupAdapterError> {
    EvidenceDigest::from_str(&format!("{:x}", hasher.finalize()))
        .map_err(|_| BackupAdapterError::InvalidEncryptedArtifact)
}

fn digest_bytes(digest: &EvidenceDigest) -> Result<[u8; 32], BackupAdapterError> {
    let text = digest.to_string();
    let mut bytes = [0_u8; 32];
    if text.len() != 64 {
        return Err(BackupAdapterError::InvalidSnapshot);
    }
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| BackupAdapterError::InvalidSnapshot)?;
    }
    Ok(bytes)
}

fn materialize_private_state<T: Serialize>(
    path: &Path,
    required_uid: u32,
    state: &T,
) -> Result<(), BackupAdapterError> {
    let bytes = serde_jcs::to_vec(state)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let existing = read_stable_private_file(
                path,
                required_uid,
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            )?;
            if existing != bytes {
                return Err(BackupAdapterError::InvalidEncryptedArtifact);
            }
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    sync_directory(
        path.parent()
            .ok_or(BackupAdapterError::InvalidEncryptedArtifact)?,
    )
}

fn read_canonical_state<T>(
    path: &Path,
    required_uid: u32,
    maximum_bytes: u64,
) -> Result<T, BackupAdapterError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let bytes = read_stable_private_file(path, required_uid, maximum_bytes)?;
    let state = serde_json::from_slice(&bytes)?;
    if serde_jcs::to_vec(&state)? != bytes {
        return Err(BackupAdapterError::InvalidEncryptedArtifact);
    }
    Ok(state)
}

fn publish_link(source: &Path, destination: &Path) -> Result<(), BackupAdapterError> {
    match fs::hard_link(source, destination) {
        Ok(()) => sync_directory(
            destination
                .parent()
                .ok_or(BackupAdapterError::InvalidEncryptedArtifact)?,
        ),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_safe_pending(path: &Path, required_uid: u32) -> Result<(), BackupAdapterError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && metadata.is_file()
                && metadata.uid() == required_uid
                && metadata.mode().trailing_zeros() >= 6 =>
        {
            fs::remove_file(path)?;
            sync_directory(
                path.parent()
                    .ok_or(BackupAdapterError::InvalidEncryptedArtifact)?,
            )
        }
        Ok(_) => Err(BackupAdapterError::InvalidEncryptedArtifact),
    }
}

fn sync_directory(path: &Path) -> Result<(), BackupAdapterError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn run_bounded_stdout(
    mut command: Command,
    maximum_bytes: usize,
) -> Result<Vec<u8>, BackupAdapterError> {
    let mut child = command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("command stdout pipe is unavailable"))?;
    let read = read_bounded(&mut stdout, maximum_bytes);
    if read.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    let bytes = read?;
    if !status.success() {
        return Err(BackupAdapterError::CommandFailed(format!(
            "provider command exited with {status}"
        )));
    }
    Ok(bytes)
}

fn read_bounded(
    reader: &mut impl Read,
    maximum_bytes: usize,
) -> Result<Vec<u8>, BackupAdapterError> {
    let mut bytes = Vec::with_capacity(maximum_bytes.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(bytes);
        }
        if bytes.len().saturating_add(read) > maximum_bytes {
            return Err(BackupAdapterError::InvalidProviderEvidence);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::tempdir;

    use super::*;
    use crate::phase6::tests::test_base_backup_phase_spec;

    #[test]
    fn age_fingerprint_is_domain_separated_and_only_x25519_recipients_are_accepted() {
        let recipient = format!("age1{}", "q".repeat(58));
        assert!(valid_age_recipient(&recipient));
        assert_eq!(
            age_x25519_recipient_fingerprint(&recipient),
            age_x25519_recipient_fingerprint(&recipient)
        );
        assert_ne!(
            age_x25519_recipient_fingerprint(&recipient),
            EvidenceDigest::sha256(recipient.as_bytes())
        );
        assert!(!valid_age_recipient("AGE1invalid"));
        assert!(!valid_age_recipient("age1plugin1invalid"));
    }

    #[test]
    fn readback_hash_rejects_short_long_and_changed_content() {
        let expected = b"ciphertext";
        let hash = hash_reader_exact(&mut expected.as_slice(), expected.len() as u64)
            .unwrap_or_else(|error| panic!("hash: {error}"));
        assert_eq!(hash.digest, EvidenceDigest::sha256(expected));
        assert!(hash_reader_exact(&mut expected.as_slice(), expected.len() as u64 + 1).is_err());
        assert!(hash_reader_exact(&mut expected.as_slice(), expected.len() as u64 - 1).is_err());
    }

    #[test]
    fn provider_version_binds_google_drive_id_and_md5() {
        let object = RcloneObjectV1 {
            id: "drive-object-id".to_owned(),
            name: "cipher.age".to_owned(),
            path: "cipher.age".to_owned(),
            size: 12,
            is_dir: false,
            hashes: BTreeMap::from([(
                "MD5".to_owned(),
                "0123456789abcdef0123456789ABCDEF".to_owned(),
            )]),
        };
        assert_eq!(
            remote_version_id(&object).unwrap_or_else(|error| panic!("version: {error}")),
            "gdrive:drive-object-id:md5:0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn installed_runtime_pins_tools_and_accepts_only_secret_free_drive_config() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let uid = fs::metadata(directory.path())
            .unwrap_or_else(|error| panic!("metadata: {error}"))
            .uid();
        let age_path = directory.path().join("age");
        let rclone_path = directory.path().join("rclone");
        for (path, bytes) in [
            (&age_path, b"pinned age".as_slice()),
            (&rclone_path, b"pinned rclone".as_slice()),
        ] {
            fs::write(path, bytes).unwrap_or_else(|error| panic!("write executable: {error}"));
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("executable permissions: {error}"));
        }
        let spec = test_base_backup_phase_spec();
        let recipient = format!("age1{}", "q".repeat(58));
        let mut config = InstalledBackupAdapterRuntimeV1 {
            purpose: "rdashboard.installed-backup-adapter-runtime.v1".to_owned(),
            schema_version: 1,
            project_id: spec.project_id.clone(),
            installed_rimg_policy_digest: spec.installed_rimg_policy_digest.clone(),
            age_sha256: EvidenceDigest::sha256(b"pinned age"),
            age_recipient_fingerprint: age_x25519_recipient_fingerprint(&recipient),
            age_recipient: recipient,
            rclone_sha256: EvidenceDigest::sha256(b"pinned rclone"),
            rclone_config_sha256: EvidenceDigest::sha256([]),
            provider: BackupProviderV1::GoogleDrive,
            provider_credential_version: 1,
            drive_remote: "rdashboard-drive".to_owned(),
            drive_root_folder_id: "DriveRoot_123".to_owned(),
            drive_service_account_sha256: EvidenceDigest::sha256(b"service account"),
        };
        let rclone_config_path = directory.path().join("rclone.conf");
        let rclone_config = canonical_rclone_config(&config);
        config.rclone_config_sha256 = EvidenceDigest::sha256(&rclone_config);
        fs::write(&rclone_config_path, &rclone_config)
            .unwrap_or_else(|error| panic!("write rclone config: {error}"));
        fs::set_permissions(&rclone_config_path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("rclone config permissions: {error}"));
        let config_path = directory.path().join("backup-runtime.jcs");
        write_test_config(&config_path, &config);

        assert_eq!(
            InstalledBackupAdapterRuntimeV1::load(
                &config_path,
                &age_path,
                &rclone_path,
                &rclone_config_path,
                uid,
                &spec,
            )
            .unwrap_or_else(|error| panic!("load runtime: {error}")),
            config
        );

        let secret_config = b"[rdashboard-drive]\ntype = drive\ntoken = secret\n";
        fs::write(&rclone_config_path, secret_config)
            .unwrap_or_else(|error| panic!("write secret config: {error}"));
        config.rclone_config_sha256 = EvidenceDigest::sha256(secret_config);
        write_test_config(&config_path, &config);
        assert!(matches!(
            InstalledBackupAdapterRuntimeV1::load(
                &config_path,
                &age_path,
                &rclone_path,
                &rclone_config_path,
                uid,
                &spec,
            ),
            Err(BackupAdapterError::RuntimeConfigMismatch)
        ));
    }

    #[test]
    fn transient_service_credential_path_includes_the_systemd_unit_suffix() {
        let spec = test_base_backup_phase_spec();
        let unit_name =
            fixed_adapter_unit_name(&spec, 3).unwrap_or_else(|error| panic!("unit name: {error}"));
        let credential_path = credential_path_for_unit(&unit_name);

        assert_eq!(
            credential_path,
            Path::new(SYSTEMD_CREDENTIAL_ROOT)
                .join(format!("{unit_name}.service"))
                .join("rimg-drive-service-account.json")
        );
    }

    fn write_test_config(path: &Path, config: &InstalledBackupAdapterRuntimeV1) {
        fs::write(
            path,
            serde_jcs::to_vec(config).unwrap_or_else(|error| panic!("config bytes: {error}")),
        )
        .unwrap_or_else(|error| panic!("write config: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("config permissions: {error}"));
    }
}
