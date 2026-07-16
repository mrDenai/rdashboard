use std::collections::{BTreeMap, HashSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::{ManifestError, ProjectManifestV1};

pub const POLICY_BUNDLE_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleV1 {
    pub schema_version: u16,
    pub policy_version: u64,
    pub issued_at_ms: i64,
    pub projects: Vec<ProjectManifestV1>,
}

impl PolicyBundleV1 {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema_version != POLICY_BUNDLE_SCHEMA_VERSION {
            return Err(PolicyError::UnsupportedSchemaVersion(self.schema_version));
        }
        if self.policy_version == 0 {
            return Err(PolicyError::ZeroPolicyVersion);
        }
        if self.projects.is_empty() {
            return Err(PolicyError::EmptyPolicy);
        }
        let mut project_ids = HashSet::new();
        for project in &self.projects {
            project.validate()?;
            if !project_ids.insert(project.project_id.clone()) {
                return Err(PolicyError::DuplicateProject(
                    project.project_id.to_string(),
                ));
            }
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        serde_jcs::to_vec(self).map_err(PolicyError::CanonicalEncoding)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyBundleV1 {
    pub key_id: String,
    pub payload: PolicyBundleV1,
    pub signature: String,
}

impl SignedPolicyBundleV1 {
    /// Intended for the offline policy-authoring tool, never for an online dashboard service.
    pub fn sign(
        key_id: impl Into<String>,
        payload: PolicyBundleV1,
        signing_key: &SigningKey,
    ) -> Result<Self, PolicyError> {
        payload.validate()?;
        let signature = signing_key.sign(&payload.canonical_bytes()?);
        Ok(Self {
            key_id: key_id.into(),
            payload,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct PolicyVerifier {
    keys: BTreeMap<String, VerifyingKey>,
    minimum_policy_version: u64,
}

impl PolicyVerifier {
    pub fn new(
        keys: BTreeMap<String, VerifyingKey>,
        minimum_policy_version: u64,
    ) -> Result<Self, PolicyError> {
        if keys.is_empty() {
            return Err(PolicyError::EmptyKeyring);
        }
        Ok(Self {
            keys,
            minimum_policy_version,
        })
    }

    pub fn verify<'a>(
        &self,
        signed: &'a SignedPolicyBundleV1,
    ) -> Result<&'a PolicyBundleV1, PolicyError> {
        signed.payload.validate()?;
        if signed.payload.policy_version < self.minimum_policy_version {
            return Err(PolicyError::PolicyRollback {
                received: signed.payload.policy_version,
                minimum: self.minimum_policy_version,
            });
        }
        let key = self
            .keys
            .get(&signed.key_id)
            .ok_or_else(|| PolicyError::UnknownKey(signed.key_id.clone()))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&signed.signature)
            .map_err(PolicyError::InvalidSignatureEncoding)?;
        let signature = Signature::from_slice(&bytes).map_err(PolicyError::InvalidSignature)?;
        key.verify_strict(&signed.payload.canonical_bytes()?, &signature)
            .map_err(PolicyError::SignatureVerification)?;
        Ok(&signed.payload)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("unsupported policy bundle schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("policy version must be non-zero")]
    ZeroPolicyVersion,
    #[error("policy bundle must contain at least one project")]
    EmptyPolicy,
    #[error("policy keyring must not be empty")]
    EmptyKeyring,
    #[error("duplicate project {0}")]
    DuplicateProject(String),
    #[error("unknown policy signing key {0}")]
    UnknownKey(String),
    #[error("policy rollback rejected: received {received}, minimum {minimum}")]
    PolicyRollback { received: u64, minimum: u64 },
    #[error("manifest validation failed: {0}")]
    Manifest(#[from] ManifestError),
    #[error("canonical policy encoding failed: {0}")]
    CanonicalEncoding(serde_json::Error),
    #[error("signature is not valid base64url: {0}")]
    InvalidSignatureEncoding(base64::DecodeError),
    #[error("signature has the wrong length: {0}")]
    InvalidSignature(ed25519_dalek::SignatureError),
    #[error("policy signature verification failed: {0}")]
    SignatureVerification(ed25519_dalek::SignatureError),
}
