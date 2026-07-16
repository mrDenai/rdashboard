use std::{
    fs::{self, File},
    io::{self, Read as _},
    os::unix::fs::MetadataExt as _,
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use crate::{
    authorization::{ActionGrantError, ActionGrantVerificationKeyV1, ActionGrantVerifierV1},
    executor_intent::{ExecutorIntentError, ExecutorIntentSignerV1},
};

pub const ROOT_EXECUTOR_AUTHORITY_SCHEMA_VERSION: u16 = 1;
pub const EXECUTOR_INTENT_SEED_CREDENTIAL_PATH: &str =
    "/run/credentials/rdashboard-executor.service/executor-intent-seed";

const ED25519_KEY_BYTES: usize = 32;
const MAX_ACTION_GRANT_VERIFICATION_KEYS: usize = 8;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionGrantVerificationKeyConfigV1 {
    pub key_id: String,
    pub key_epoch: u64,
    pub public_key_base64url: String,
    pub active_from_ms: i64,
    pub signing_retired_at_ms: Option<i64>,
    pub verify_until_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootExecutorAuthorityConfigV1 {
    pub schema_version: u16,
    pub action_grant_issuer: String,
    pub executor_audience: String,
    pub minimum_action_grant_key_epoch: u64,
    pub action_grant_verification_keys: Vec<ActionGrantVerificationKeyConfigV1>,
    pub executor_intent_issuer: String,
    pub authorizer_audience: String,
    pub executor_intent_key_id: String,
    pub executor_intent_key_epoch: u64,
    pub executor_intent_public_key_base64url: String,
}

impl RootExecutorAuthorityConfigV1 {
    pub fn validate(&self) -> Result<(), ExecutorAuthorityError> {
        if self.schema_version != ROOT_EXECUTOR_AUTHORITY_SCHEMA_VERSION {
            return Err(ExecutorAuthorityError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        self.build_action_grant_verifier()?;
        let _ = self.build_intent_signer(SigningKey::from_bytes(&[0_u8; ED25519_KEY_BYTES]))?;
        decode_public_key(&self.executor_intent_public_key_base64url)?;
        Ok(())
    }

    fn build_action_grant_verifier(&self) -> Result<ActionGrantVerifierV1, ExecutorAuthorityError> {
        if !(1..=MAX_ACTION_GRANT_VERIFICATION_KEYS)
            .contains(&self.action_grant_verification_keys.len())
        {
            return Err(ExecutorAuthorityError::InvalidActionGrantKeyCount);
        }
        let keys = self
            .action_grant_verification_keys
            .iter()
            .map(|key| {
                Ok(ActionGrantVerificationKeyV1::new(
                    key.key_id.clone(),
                    key.key_epoch,
                    decode_public_key(&key.public_key_base64url)?,
                    key.active_from_ms,
                    key.signing_retired_at_ms,
                    key.verify_until_ms,
                    key.revoked_at_ms,
                )?)
            })
            .collect::<Result<Vec<_>, ExecutorAuthorityError>>()?;
        Ok(ActionGrantVerifierV1::new(
            self.action_grant_issuer.clone(),
            self.executor_audience.clone(),
            self.minimum_action_grant_key_epoch,
            keys,
        )?)
    }

    fn build_intent_signer(
        &self,
        signing_key: SigningKey,
    ) -> Result<ExecutorIntentSignerV1, ExecutorAuthorityError> {
        Ok(ExecutorIntentSignerV1::new(
            self.executor_intent_issuer.clone(),
            self.authorizer_audience.clone(),
            self.executor_intent_key_id.clone(),
            self.executor_intent_key_epoch,
            signing_key,
        )?)
    }
}

#[derive(Clone, Debug)]
pub struct RootExecutorAuthorityV1 {
    action_grant_verifier: ActionGrantVerifierV1,
    executor_intent_signer: ExecutorIntentSignerV1,
}

impl RootExecutorAuthorityV1 {
    pub fn load_system_credential(
        config: &RootExecutorAuthorityConfigV1,
    ) -> Result<Self, ExecutorAuthorityError> {
        Self::load_from_credential_path(config, Path::new(EXECUTOR_INTENT_SEED_CREDENTIAL_PATH), 0)
    }

    pub(crate) fn load_from_credential_path(
        config: &RootExecutorAuthorityConfigV1,
        credential_path: &Path,
        required_uid: u32,
    ) -> Result<Self, ExecutorAuthorityError> {
        config.validate()?;
        let signing_key = read_signing_key(credential_path, required_uid)?;
        let expected_public_key = decode_public_key(&config.executor_intent_public_key_base64url)?;
        if signing_key.verifying_key() != expected_public_key {
            return Err(ExecutorAuthorityError::CredentialKeyMismatch);
        }
        Ok(Self {
            action_grant_verifier: config.build_action_grant_verifier()?,
            executor_intent_signer: config.build_intent_signer(signing_key)?,
        })
    }

    pub const fn action_grant_verifier(&self) -> &ActionGrantVerifierV1 {
        &self.action_grant_verifier
    }

    pub const fn executor_intent_signer(&self) -> &ExecutorIntentSignerV1 {
        &self.executor_intent_signer
    }
}

fn decode_public_key(value: &str) -> Result<VerifyingKey, ExecutorAuthorityError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ExecutorAuthorityError::InvalidPublicKey)?;
    let bytes: [u8; ED25519_KEY_BYTES] = decoded
        .try_into()
        .map_err(|_| ExecutorAuthorityError::InvalidPublicKey)?;
    if URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(ExecutorAuthorityError::InvalidPublicKey);
    }
    VerifyingKey::from_bytes(&bytes).map_err(|_| ExecutorAuthorityError::InvalidPublicKey)
}

fn read_signing_key(path: &Path, required_uid: u32) -> Result<SigningKey, ExecutorAuthorityError> {
    let path_metadata = fs::symlink_metadata(path).map_err(ExecutorAuthorityError::CredentialIo)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.mode() & 0o022 != 0
        || path_metadata.len() != ED25519_KEY_BYTES as u64
    {
        return Err(ExecutorAuthorityError::UnsafeCredential);
    }

    let mut file = File::open(path).map_err(ExecutorAuthorityError::CredentialIo)?;
    let opened_metadata = file
        .metadata()
        .map_err(ExecutorAuthorityError::CredentialIo)?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.uid() != required_uid
        || opened_metadata.mode() & 0o022 != 0
        || opened_metadata.len() != ED25519_KEY_BYTES as u64
    {
        return Err(ExecutorAuthorityError::CredentialChanged);
    }

    let mut seed = [0_u8; ED25519_KEY_BYTES];
    file.read_exact(&mut seed)
        .map_err(ExecutorAuthorityError::CredentialIo)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(ExecutorAuthorityError::CredentialIo)?
        != 0
    {
        return Err(ExecutorAuthorityError::CredentialChanged);
    }
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(signing_key)
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutorAuthorityError {
    #[error("unsupported root executor authority schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error(
        "action-grant verification keyring must contain 1-{MAX_ACTION_GRANT_VERIFICATION_KEYS} keys"
    )]
    InvalidActionGrantKeyCount,
    #[error("an Ed25519 public key is not canonical unpadded base64url")]
    InvalidPublicKey,
    #[error("action-grant verification policy is invalid: {0}")]
    ActionGrant(#[from] ActionGrantError),
    #[error("executor-intent signing policy is invalid: {0}")]
    ExecutorIntent(#[from] ExecutorIntentError),
    #[error("executor-intent signing credential could not be read: {0}")]
    CredentialIo(io::Error),
    #[error("executor-intent signing credential must be a root-owned, non-writable 32-byte file")]
    UnsafeCredential,
    #[error("executor-intent signing credential changed while it was being opened or read")]
    CredentialChanged,
    #[error("executor-intent signing credential does not match its installed public key")]
    CredentialKeyMismatch,
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    use super::*;

    fn config(intent_signing_key: &SigningKey) -> RootExecutorAuthorityConfigV1 {
        let action_signing_key = SigningKey::from_bytes(&[41_u8; ED25519_KEY_BYTES]);
        RootExecutorAuthorityConfigV1 {
            schema_version: ROOT_EXECUTOR_AUTHORITY_SCHEMA_VERSION,
            action_grant_issuer: "https://actions.dev.4u.ge".to_owned(),
            executor_audience: "rdashboard-executor".to_owned(),
            minimum_action_grant_key_epoch: 1,
            action_grant_verification_keys: vec![ActionGrantVerificationKeyConfigV1 {
                key_id: "authorizer-2026-01".to_owned(),
                key_epoch: 1,
                public_key_base64url: URL_SAFE_NO_PAD
                    .encode(action_signing_key.verifying_key().to_bytes()),
                active_from_ms: 1_700_000_000_000,
                signing_retired_at_ms: None,
                verify_until_ms: None,
                revoked_at_ms: None,
            }],
            executor_intent_issuer: "rdashboard-executor".to_owned(),
            authorizer_audience: "https://actions.dev.4u.ge".to_owned(),
            executor_intent_key_id: "executor-2026-01".to_owned(),
            executor_intent_key_epoch: 1,
            executor_intent_public_key_base64url: URL_SAFE_NO_PAD
                .encode(intent_signing_key.verifying_key().to_bytes()),
        }
    }

    fn write_credential(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap_or_else(|error| panic!("write credential: {error}"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("credential permissions: {error}"));
    }

    fn credential_uid(path: &Path) -> u32 {
        fs::metadata(path)
            .unwrap_or_else(|error| panic!("credential metadata: {error}"))
            .uid()
    }

    #[test]
    fn loads_exact_root_owned_seed_and_both_authorities() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let credential = temp.path().join("executor-intent-seed");
        let signing_key = SigningKey::from_bytes(&[73_u8; ED25519_KEY_BYTES]);
        write_credential(&credential, &signing_key.to_bytes());

        let authority = RootExecutorAuthorityV1::load_from_credential_path(
            &config(&signing_key),
            &credential,
            credential_uid(&credential),
        )
        .unwrap_or_else(|error| panic!("load authority: {error}"));

        let _ = authority.action_grant_verifier();
        let _ = authority.executor_intent_signer();
    }

    #[test]
    fn rejects_seed_that_does_not_match_installed_public_key() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let credential = temp.path().join("executor-intent-seed");
        let expected = SigningKey::from_bytes(&[73_u8; ED25519_KEY_BYTES]);
        let wrong = SigningKey::from_bytes(&[74_u8; ED25519_KEY_BYTES]);
        write_credential(&credential, &wrong.to_bytes());

        assert!(matches!(
            RootExecutorAuthorityV1::load_from_credential_path(
                &config(&expected),
                &credential,
                credential_uid(&credential),
            ),
            Err(ExecutorAuthorityError::CredentialKeyMismatch)
        ));
    }

    #[test]
    fn rejects_noncanonical_or_oversized_keyrings() {
        let signing_key = SigningKey::from_bytes(&[73_u8; ED25519_KEY_BYTES]);
        let mut invalid_public_key = config(&signing_key);
        invalid_public_key.action_grant_verification_keys[0]
            .public_key_base64url
            .push('=');
        assert!(matches!(
            invalid_public_key.validate(),
            Err(ExecutorAuthorityError::InvalidPublicKey)
        ));

        let mut empty = config(&signing_key);
        empty.action_grant_verification_keys.clear();
        assert!(matches!(
            empty.validate(),
            Err(ExecutorAuthorityError::InvalidActionGrantKeyCount)
        ));
    }
}
