use std::{
    fs::{self, File},
    io::{self, Read as _},
    os::unix::fs::MetadataExt as _,
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroize as _;

use crate::workflow_execution_grant::{
    WorkflowExecutionGrantError, WorkflowExecutionGrantSignerV1,
};

pub const WORKFLOW_EXECUTION_SIGNING_SCHEMA_VERSION: u16 = 1;
pub const WORKFLOW_EXECUTION_SEED_CREDENTIAL_PATH: &str =
    "/run/credentials/rdashboard-workflow-gateway.service/workflow-grant-seed";

const ED25519_KEY_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowExecutionSigningConfigV1 {
    pub schema_version: u16,
    pub issuer: String,
    pub launcher_audience: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub public_key_base64url: String,
}

impl WorkflowExecutionSigningConfigV1 {
    pub fn load_system_credential(
        &self,
    ) -> Result<WorkflowExecutionGrantSignerV1, WorkflowExecutionAuthorityError> {
        let process_uid = fs::metadata("/proc/self")?.uid();
        if process_uid == 0 || process_uid == u32::MAX {
            return Err(WorkflowExecutionAuthorityError::InvalidProcessIdentity);
        }
        self.load_from_path(
            Path::new(WORKFLOW_EXECUTION_SEED_CREDENTIAL_PATH),
            process_uid,
            true,
        )
    }

    pub(crate) fn load_from_path(
        &self,
        path: &Path,
        process_uid: u32,
        allow_root_owner: bool,
    ) -> Result<WorkflowExecutionGrantSignerV1, WorkflowExecutionAuthorityError> {
        if self.schema_version != WORKFLOW_EXECUTION_SIGNING_SCHEMA_VERSION {
            return Err(WorkflowExecutionAuthorityError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        let expected_public_key = decode_public_key(&self.public_key_base64url)?;
        let signing_key = read_signing_key(path, process_uid, allow_root_owner)?;
        if signing_key.verifying_key() != expected_public_key {
            return Err(WorkflowExecutionAuthorityError::CredentialKeyMismatch);
        }
        Ok(WorkflowExecutionGrantSignerV1::new(
            self.issuer.clone(),
            self.launcher_audience.clone(),
            self.key_id.clone(),
            self.key_epoch,
            signing_key,
        )?)
    }
}

fn decode_public_key(value: &str) -> Result<VerifyingKey, WorkflowExecutionAuthorityError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| WorkflowExecutionAuthorityError::InvalidPublicKey)?;
    let bytes: [u8; ED25519_KEY_BYTES] = decoded
        .try_into()
        .map_err(|_| WorkflowExecutionAuthorityError::InvalidPublicKey)?;
    if URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(WorkflowExecutionAuthorityError::InvalidPublicKey);
    }
    VerifyingKey::from_bytes(&bytes).map_err(|_| WorkflowExecutionAuthorityError::InvalidPublicKey)
}

fn read_signing_key(
    path: &Path,
    process_uid: u32,
    allow_root_owner: bool,
) -> Result<SigningKey, WorkflowExecutionAuthorityError> {
    if process_uid == 0 || process_uid == u32::MAX {
        return Err(WorkflowExecutionAuthorityError::InvalidProcessIdentity);
    }
    let path_metadata = fs::symlink_metadata(path)?;
    let mode = path_metadata.mode() & 0o777;
    let permissions_allowed = if path_metadata.uid() == process_uid {
        mode.trailing_zeros() >= 6
    } else {
        allow_root_owner
            && systemd_credential_permissions_are_safe(
                path_metadata.uid(),
                path_metadata.gid(),
                mode,
            )
    };
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || !permissions_allowed
        || path_metadata.nlink() != 1
        || path_metadata.len() != ED25519_KEY_BYTES as u64
    {
        return Err(WorkflowExecutionAuthorityError::UnsafeCredential);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != path_metadata.dev()
        || opened.ino() != path_metadata.ino()
        || opened.uid() != path_metadata.uid()
        || opened.mode() != path_metadata.mode()
        || opened.nlink() != 1
        || opened.len() != ED25519_KEY_BYTES as u64
    {
        return Err(WorkflowExecutionAuthorityError::CredentialChanged);
    }
    let mut seed = [0_u8; ED25519_KEY_BYTES];
    file.read_exact(&mut seed)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        seed.zeroize();
        return Err(WorkflowExecutionAuthorityError::CredentialChanged);
    }
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.dev() != opened.dev()
        || final_metadata.ino() != opened.ino()
        || final_metadata.uid() != opened.uid()
        || final_metadata.mode() != opened.mode()
        || final_metadata.len() != opened.len()
    {
        seed.zeroize();
        return Err(WorkflowExecutionAuthorityError::CredentialChanged);
    }
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(signing_key)
}

const fn systemd_credential_permissions_are_safe(uid: u32, gid: u32, mode: u32) -> bool {
    uid == 0 && gid == 0 && matches!(mode, 0o400 | 0o440)
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowExecutionAuthorityError {
    #[error("unsupported workflow execution signing schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("workflow execution signing process must use a dedicated non-root identity")]
    InvalidProcessIdentity,
    #[error("workflow execution signing public key is not canonical unpadded base64url")]
    InvalidPublicKey,
    #[error("workflow execution signing credential is not a stable private 32-byte file")]
    UnsafeCredential,
    #[error("workflow execution signing credential changed while being read")]
    CredentialChanged,
    #[error("workflow execution signing credential does not match its installed public key")]
    CredentialKeyMismatch,
    #[error("workflow execution signing credential I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("workflow execution signing policy is invalid: {0}")]
    Grant(#[from] WorkflowExecutionGrantError),
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use super::*;

    fn config(key: &SigningKey) -> WorkflowExecutionSigningConfigV1 {
        WorkflowExecutionSigningConfigV1 {
            schema_version: WORKFLOW_EXECUTION_SIGNING_SCHEMA_VERSION,
            issuer: "workflow-gateway".to_owned(),
            launcher_audience: "workflow-launcher".to_owned(),
            key_id: "workflow-key-1".to_owned(),
            key_epoch: 1,
            public_key_base64url: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
        }
    }

    #[test]
    fn signing_seed_is_private_exact_and_public_key_bound() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("seed");
        let key = SigningKey::from_bytes(&[29_u8; ED25519_KEY_BYTES]);
        fs::write(&path, key.to_bytes()).expect("write seed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("seed mode");
        let uid = fs::metadata(&path).expect("seed metadata").uid();
        assert!(config(&key).load_from_path(&path, uid, false).is_ok());

        let wrong = SigningKey::from_bytes(&[30_u8; ED25519_KEY_BYTES]);
        assert!(matches!(
            config(&wrong).load_from_path(&path, uid, false),
            Err(WorkflowExecutionAuthorityError::CredentialKeyMismatch)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("unsafe seed mode");
        assert!(matches!(
            config(&key).load_from_path(&path, uid, false),
            Err(WorkflowExecutionAuthorityError::UnsafeCredential)
        ));
    }

    #[test]
    fn systemd_root_owned_credential_permissions_are_accepted() {
        assert!(systemd_credential_permissions_are_safe(0, 0, 0o400));
        assert!(systemd_credential_permissions_are_safe(0, 0, 0o440));
        assert!(!systemd_credential_permissions_are_safe(0, 1, 0o440));
        assert!(!systemd_credential_permissions_are_safe(0, 0, 0o640));
    }
}
