use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{
    EvidenceDigest, ProjectId, WorkflowAdapterIdV1, WorkflowLeaseV1, WorkflowWorkerPoolV1,
    valid_workflow_identity,
};

pub const WORKFLOW_EXECUTION_GRANT_SCHEMA_VERSION: u16 = 1;
pub const WORKFLOW_EXECUTION_GRANT_MAX_TTL_MS: i64 = 60_000;

const SIGNATURE_DOMAIN: &[u8] = b"rdashboard.workflow-execution-grant.v1\0";
const PURPOSE: &str = "rdashboard.workflow-execution-grant.v1";
const MAX_PAYLOAD_BYTES: usize = 4 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_KEYS: usize = 8;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkflowExecutionGrantPayloadV1 {
    purpose: String,
    schema_version: u16,
    issuer: String,
    launcher_audience: String,
    key_id: String,
    key_epoch: u64,
    issued_at_ms: i64,
    not_before_ms: i64,
    expires_at_ms: i64,
    nonce: Uuid,
    lease_digest: EvidenceDigest,
    lease_id: Uuid,
    lease_generation: u32,
    request_id: Uuid,
    attempt_id: Uuid,
    project_id: ProjectId,
    worker_id: String,
    host_id: String,
    adapter_id: WorkflowAdapterIdV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowExecutionGrantClaimsV1 {
    pub issuer: String,
    pub launcher_audience: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub issued_at_ms: i64,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: Uuid,
    pub lease_digest: EvidenceDigest,
    pub lease_id: Uuid,
    pub lease_generation: u32,
    pub request_id: Uuid,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub worker_id: String,
    pub host_id: String,
    pub adapter_id: WorkflowAdapterIdV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWorkflowExecutionGrantV1 {
    pub claims: WorkflowExecutionGrantClaimsV1,
    pub token_digest: EvidenceDigest,
}

#[derive(Clone, Debug)]
pub struct WorkflowExecutionGrantSignerV1 {
    issuer: String,
    launcher_audience: String,
    key_id: String,
    key_epoch: u64,
    signing_key: SigningKey,
}

impl WorkflowExecutionGrantSignerV1 {
    pub fn new(
        issuer: impl Into<String>,
        launcher_audience: impl Into<String>,
        key_id: impl Into<String>,
        key_epoch: u64,
        signing_key: SigningKey,
    ) -> Result<Self, WorkflowExecutionGrantError> {
        let signer = Self {
            issuer: issuer.into(),
            launcher_audience: launcher_audience.into(),
            key_id: key_id.into(),
            key_epoch,
            signing_key,
        };
        validate_authority(
            &signer.issuer,
            &signer.launcher_audience,
            &signer.key_id,
            signer.key_epoch,
        )?;
        Ok(signer)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn issue(
        &self,
        lease: &WorkflowLeaseV1,
        issued_at_ms: i64,
        nonce: Uuid,
    ) -> Result<String, WorkflowExecutionGrantError> {
        validate_execution_lease(lease)?;
        if nonce.is_nil()
            || issued_at_ms < lease.leased_at_ms
            || lease.expires_at_ms <= issued_at_ms
            || lease.expires_at_ms - issued_at_ms > WORKFLOW_EXECUTION_GRANT_MAX_TTL_MS
        {
            return Err(WorkflowExecutionGrantError::InvalidLifetime);
        }
        let payload = WorkflowExecutionGrantPayloadV1 {
            purpose: PURPOSE.to_owned(),
            schema_version: WORKFLOW_EXECUTION_GRANT_SCHEMA_VERSION,
            issuer: self.issuer.clone(),
            launcher_audience: self.launcher_audience.clone(),
            key_id: self.key_id.clone(),
            key_epoch: self.key_epoch,
            issued_at_ms,
            not_before_ms: issued_at_ms,
            expires_at_ms: lease.expires_at_ms,
            nonce,
            lease_digest: lease.lease_digest.clone(),
            lease_id: lease.lease_id,
            lease_generation: lease.lease_generation,
            request_id: lease.request_id,
            attempt_id: lease.attempt_id,
            project_id: lease.project_id.clone(),
            worker_id: lease.worker_id.clone(),
            host_id: lease.host_id.clone(),
            adapter_id: lease.adapter_id,
        };
        validate_payload(&payload)?;
        let bytes = serde_jcs::to_vec(&payload)?;
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(WorkflowExecutionGrantError::PayloadTooLarge);
        }
        let signature = self.signing_key.sign(&signature_input(&bytes));
        let token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(bytes),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        if token.len() > MAX_TOKEN_BYTES {
            return Err(WorkflowExecutionGrantError::TokenTooLarge);
        }
        Ok(token)
    }
}

#[derive(Clone, Debug)]
pub struct WorkflowExecutionGrantVerificationKeyV1 {
    key_id: String,
    key_epoch: u64,
    verifying_key: VerifyingKey,
    active_from_ms: i64,
    signing_retired_at_ms: Option<i64>,
    verify_until_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
}

impl WorkflowExecutionGrantVerificationKeyV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key_id: impl Into<String>,
        key_epoch: u64,
        verifying_key: VerifyingKey,
        active_from_ms: i64,
        signing_retired_at_ms: Option<i64>,
        verify_until_ms: Option<i64>,
        revoked_at_ms: Option<i64>,
    ) -> Result<Self, WorkflowExecutionGrantError> {
        let key = Self {
            key_id: key_id.into(),
            key_epoch,
            verifying_key,
            active_from_ms,
            signing_retired_at_ms,
            verify_until_ms,
            revoked_at_ms,
        };
        validate_key(&key)?;
        Ok(key)
    }
}

#[derive(Clone, Debug)]
pub struct WorkflowExecutionGrantVerifierV1 {
    issuer: String,
    launcher_audience: String,
    minimum_key_epoch: u64,
    keys: BTreeMap<String, WorkflowExecutionGrantVerificationKeyV1>,
}

impl WorkflowExecutionGrantVerifierV1 {
    pub fn new(
        issuer: impl Into<String>,
        launcher_audience: impl Into<String>,
        minimum_key_epoch: u64,
        keys: impl IntoIterator<Item = WorkflowExecutionGrantVerificationKeyV1>,
    ) -> Result<Self, WorkflowExecutionGrantError> {
        let issuer = issuer.into();
        let launcher_audience = launcher_audience.into();
        validate_authority(
            &issuer,
            &launcher_audience,
            "verification-key",
            minimum_key_epoch,
        )?;
        let mut indexed = BTreeMap::new();
        for key in keys {
            validate_key(&key)?;
            if indexed.insert(key.key_id.clone(), key).is_some() {
                return Err(WorkflowExecutionGrantError::DuplicateKey);
            }
        }
        if indexed.is_empty() || indexed.len() > MAX_KEYS {
            return Err(WorkflowExecutionGrantError::InvalidKeyCount);
        }
        Ok(Self {
            issuer,
            launcher_audience,
            minimum_key_epoch,
            keys: indexed,
        })
    }

    pub fn verify(
        &self,
        token: &str,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
    ) -> Result<VerifiedWorkflowExecutionGrantV1, WorkflowExecutionGrantError> {
        validate_execution_lease(lease)?;
        if now_ms < 0 {
            return Err(WorkflowExecutionGrantError::InvalidVerificationTime);
        }
        let (payload_bytes, signature) = decode_token(token)?;
        let payload: WorkflowExecutionGrantPayloadV1 = serde_json::from_slice(&payload_bytes)?;
        if serde_jcs::to_vec(&payload)? != payload_bytes {
            return Err(WorkflowExecutionGrantError::NoncanonicalPayload);
        }
        validate_payload(&payload)?;
        let key = self
            .keys
            .get(&payload.key_id)
            .ok_or_else(|| WorkflowExecutionGrantError::UnknownKey(payload.key_id.clone()))?;
        if payload.key_epoch != key.key_epoch || payload.key_epoch < self.minimum_key_epoch {
            return Err(WorkflowExecutionGrantError::KeyEpochRejected);
        }
        key.verifying_key
            .verify_strict(&signature_input(&payload_bytes), &signature)
            .map_err(WorkflowExecutionGrantError::SignatureVerification)?;
        validate_key_lifecycle(key, &payload, now_ms)?;
        if payload.issuer != self.issuer {
            return Err(WorkflowExecutionGrantError::IssuerMismatch);
        }
        if payload.launcher_audience != self.launcher_audience {
            return Err(WorkflowExecutionGrantError::AudienceMismatch);
        }
        if now_ms < payload.not_before_ms || now_ms >= payload.expires_at_ms {
            return Err(WorkflowExecutionGrantError::GrantNotActive);
        }
        if !payload_matches_lease(&payload, lease) {
            return Err(WorkflowExecutionGrantError::LeaseBindingMismatch);
        }
        Ok(VerifiedWorkflowExecutionGrantV1 {
            claims: claims(payload),
            token_digest: EvidenceDigest::sha256(token.as_bytes()),
        })
    }
}

fn validate_execution_lease(lease: &WorkflowLeaseV1) -> Result<(), WorkflowExecutionGrantError> {
    lease.validate()?;
    let _ = lease.required_source_identity()?;
    let _ = lease.required_input_artifacts()?;
    if lease.node_kind.is_controller_managed()
        || lease.node_kind.is_mutation()
        || !matches!(
            lease.worker_pool,
            WorkflowWorkerPoolV1::VpsRequired | WorkflowWorkerPoolV1::BuildCompute
        )
        || !matches!(
            lease.adapter_id,
            WorkflowAdapterIdV1::WorkerHostPrepareV1
                | WorkflowAdapterIdV1::WorkerBareBinCiV1
                | WorkflowAdapterIdV1::WorkerNativeReleaseBuildV1
                | WorkflowAdapterIdV1::WorkerOciReleaseBuildV1
        )
    {
        return Err(WorkflowExecutionGrantError::InvalidLeaseBoundary);
    }
    Ok(())
}

fn validate_payload(
    payload: &WorkflowExecutionGrantPayloadV1,
) -> Result<(), WorkflowExecutionGrantError> {
    validate_authority(
        &payload.issuer,
        &payload.launcher_audience,
        &payload.key_id,
        payload.key_epoch,
    )?;
    if payload.purpose != PURPOSE
        || payload.schema_version != WORKFLOW_EXECUTION_GRANT_SCHEMA_VERSION
        || payload.nonce.is_nil()
        || payload.lease_id.is_nil()
        || payload.request_id.is_nil()
        || payload.attempt_id.is_nil()
        || payload.lease_generation == 0
        || payload.issued_at_ms < 0
        || payload.not_before_ms < payload.issued_at_ms
        || payload.expires_at_ms <= payload.not_before_ms
        || payload.expires_at_ms - payload.issued_at_ms > WORKFLOW_EXECUTION_GRANT_MAX_TTL_MS
        || !valid_workflow_identity(&payload.worker_id)
        || !valid_workflow_identity(&payload.host_id)
    {
        return Err(WorkflowExecutionGrantError::InvalidPayload);
    }
    Ok(())
}

fn validate_authority(
    issuer: &str,
    audience: &str,
    key_id: &str,
    key_epoch: u64,
) -> Result<(), WorkflowExecutionGrantError> {
    if !valid_workflow_identity(issuer)
        || !valid_workflow_identity(audience)
        || !valid_workflow_identity(key_id)
        || key_epoch == 0
        || key_epoch > i64::MAX.unsigned_abs()
    {
        return Err(WorkflowExecutionGrantError::InvalidAuthority);
    }
    Ok(())
}

fn validate_key(
    key: &WorkflowExecutionGrantVerificationKeyV1,
) -> Result<(), WorkflowExecutionGrantError> {
    if !valid_workflow_identity(&key.key_id)
        || key.key_epoch == 0
        || key.key_epoch > i64::MAX.unsigned_abs()
        || key.active_from_ms < 0
        || key
            .signing_retired_at_ms
            .is_some_and(|retired| retired <= key.active_from_ms)
        || key
            .verify_until_ms
            .is_some_and(|until| until <= key.signing_retired_at_ms.unwrap_or(key.active_from_ms))
        || key.signing_retired_at_ms.is_none() != key.verify_until_ms.is_none()
        || key
            .revoked_at_ms
            .is_some_and(|revoked| revoked < key.active_from_ms)
    {
        return Err(WorkflowExecutionGrantError::InvalidKeyLifecycle);
    }
    Ok(())
}

fn validate_key_lifecycle(
    key: &WorkflowExecutionGrantVerificationKeyV1,
    payload: &WorkflowExecutionGrantPayloadV1,
    now_ms: i64,
) -> Result<(), WorkflowExecutionGrantError> {
    if payload.issued_at_ms < key.active_from_ms
        || key
            .signing_retired_at_ms
            .is_some_and(|retired| payload.issued_at_ms >= retired)
        || key.verify_until_ms.is_some_and(|until| now_ms >= until)
        || key
            .revoked_at_ms
            .is_some_and(|revoked| payload.issued_at_ms >= revoked || now_ms >= revoked)
    {
        return Err(WorkflowExecutionGrantError::KeyLifecycleRejected);
    }
    Ok(())
}

fn payload_matches_lease(
    payload: &WorkflowExecutionGrantPayloadV1,
    lease: &WorkflowLeaseV1,
) -> bool {
    payload.expires_at_ms == lease.expires_at_ms
        && payload.lease_digest == lease.lease_digest
        && payload.lease_id == lease.lease_id
        && payload.lease_generation == lease.lease_generation
        && payload.request_id == lease.request_id
        && payload.attempt_id == lease.attempt_id
        && payload.project_id == lease.project_id
        && payload.worker_id == lease.worker_id
        && payload.host_id == lease.host_id
        && payload.adapter_id == lease.adapter_id
}

fn claims(payload: WorkflowExecutionGrantPayloadV1) -> WorkflowExecutionGrantClaimsV1 {
    WorkflowExecutionGrantClaimsV1 {
        issuer: payload.issuer,
        launcher_audience: payload.launcher_audience,
        key_id: payload.key_id,
        key_epoch: payload.key_epoch,
        issued_at_ms: payload.issued_at_ms,
        not_before_ms: payload.not_before_ms,
        expires_at_ms: payload.expires_at_ms,
        nonce: payload.nonce,
        lease_digest: payload.lease_digest,
        lease_id: payload.lease_id,
        lease_generation: payload.lease_generation,
        request_id: payload.request_id,
        attempt_id: payload.attempt_id,
        project_id: payload.project_id,
        worker_id: payload.worker_id,
        host_id: payload.host_id,
        adapter_id: payload.adapter_id,
    }
}

fn signature_input(payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGNATURE_DOMAIN.len() + payload.len());
    input.extend_from_slice(SIGNATURE_DOMAIN);
    input.extend_from_slice(payload);
    input
}

fn decode_token(token: &str) -> Result<(Vec<u8>, Signature), WorkflowExecutionGrantError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(WorkflowExecutionGrantError::TokenTooLarge);
    }
    let mut parts = token.split('.');
    let payload_part = parts
        .next()
        .ok_or(WorkflowExecutionGrantError::MalformedToken)?;
    let signature_part = parts
        .next()
        .ok_or(WorkflowExecutionGrantError::MalformedToken)?;
    if parts.next().is_some() || payload_part.is_empty() || signature_part.is_empty() {
        return Err(WorkflowExecutionGrantError::MalformedToken);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_part)
        .map_err(|_| WorkflowExecutionGrantError::MalformedToken)?;
    if payload.len() > MAX_PAYLOAD_BYTES || URL_SAFE_NO_PAD.encode(&payload) != payload_part {
        return Err(WorkflowExecutionGrantError::NoncanonicalToken);
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| WorkflowExecutionGrantError::MalformedToken)?;
    if URL_SAFE_NO_PAD.encode(&signature_bytes) != signature_part {
        return Err(WorkflowExecutionGrantError::NoncanonicalToken);
    }
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| WorkflowExecutionGrantError::MalformedToken)?;
    Ok((payload, signature))
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowExecutionGrantError {
    #[error("workflow execution-grant authority identity is invalid")]
    InvalidAuthority,
    #[error("workflow execution-grant lease is invalid: {0}")]
    Workflow(#[from] crate::domain::WorkflowContractError),
    #[error("workflow execution-grant lease crosses the unprivileged execution boundary")]
    InvalidLeaseBoundary,
    #[error("workflow execution-grant lifetime is invalid")]
    InvalidLifetime,
    #[error("workflow execution-grant verification time is invalid")]
    InvalidVerificationTime,
    #[error("workflow execution-grant payload is invalid")]
    InvalidPayload,
    #[error("workflow execution-grant payload exceeds its byte limit")]
    PayloadTooLarge,
    #[error("workflow execution-grant token exceeds its byte limit")]
    TokenTooLarge,
    #[error("workflow execution-grant token is malformed")]
    MalformedToken,
    #[error("workflow execution-grant token encoding is not canonical")]
    NoncanonicalToken,
    #[error("workflow execution-grant payload is not canonical JCS")]
    NoncanonicalPayload,
    #[error("workflow execution-grant keyring contains a duplicate key")]
    DuplicateKey,
    #[error("workflow execution-grant keyring must contain 1-{MAX_KEYS} keys")]
    InvalidKeyCount,
    #[error("workflow execution-grant key lifecycle is invalid")]
    InvalidKeyLifecycle,
    #[error("workflow execution-grant key lifecycle rejects this token")]
    KeyLifecycleRejected,
    #[error("workflow execution-grant key epoch is rejected")]
    KeyEpochRejected,
    #[error("workflow execution-grant key {0} is unknown")]
    UnknownKey(String),
    #[error("workflow execution-grant signature is invalid: {0}")]
    SignatureVerification(ed25519_dalek::SignatureError),
    #[error("workflow execution-grant issuer does not match installed policy")]
    IssuerMismatch,
    #[error("workflow execution-grant audience does not match installed policy")]
    AudienceMismatch,
    #[error("workflow execution grant is not active")]
    GrantNotActive,
    #[error("workflow execution grant does not bind the exact lease")]
    LeaseBindingMismatch,
    #[error("workflow execution-grant JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::domain::{
        GitCommitId, ProjectManifestV2, WorkflowArtifactKindV1, WorkflowLeaseInputV1,
        WorkflowNodeKindV1,
    };

    fn lease_fixture(input_artifacts: bool) -> WorkflowLeaseV1 {
        let manifest: ProjectManifestV2 =
            serde_json::from_str(include_str!("../config/project-manifests/ralert.json"))
                .expect("manifest");
        let node = manifest
            .workflow
            .nodes
            .iter()
            .find(|node| node.kind == WorkflowNodeKindV1::HostPrepare)
            .expect("prepare node");
        let profile = manifest
            .workflow
            .profile(&node.profile_id)
            .expect("prepare profile");
        WorkflowLeaseV1::new(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            Uuid::new_v4(),
            manifest.project_id.clone(),
            GitCommitId::from_str(&"a".repeat(40)).expect("source SHA"),
            7,
            EvidenceDigest::sha256("source attestation"),
            manifest.workflow_policy_digest().expect("policy digest"),
            EvidenceDigest::sha256("preparation key"),
            node,
            profile,
            input_artifacts
                .then(|| WorkflowLeaseInputV1 {
                    node_id: "source".parse().expect("source node ID"),
                    artifact_kind: WorkflowArtifactKindV1::SourceSnapshot,
                    output_digest: EvidenceDigest::sha256("source attestation"),
                })
                .into_iter()
                .collect(),
            EvidenceDigest::sha256("expected input"),
            "shared-vps-worker".to_owned(),
            "production-vps".to_owned(),
            100,
            15_100,
        )
        .expect("lease")
    }

    fn signer(key: &SigningKey) -> WorkflowExecutionGrantSignerV1 {
        WorkflowExecutionGrantSignerV1::new(
            "workflow-gateway",
            "workflow-launcher",
            "workflow-key-1",
            1,
            key.clone(),
        )
        .expect("signer")
    }

    fn verifier(key: &SigningKey, revoked_at_ms: Option<i64>) -> WorkflowExecutionGrantVerifierV1 {
        WorkflowExecutionGrantVerifierV1::new(
            "workflow-gateway",
            "workflow-launcher",
            1,
            [WorkflowExecutionGrantVerificationKeyV1::new(
                "workflow-key-1",
                1,
                key.verifying_key(),
                0,
                None,
                None,
                revoked_at_ms,
            )
            .expect("verification key")],
        )
        .expect("verifier")
    }

    #[test]
    fn grant_is_canonical_short_lived_and_bound_to_the_exact_lease() {
        let key = SigningKey::from_bytes(&[17_u8; 32]);
        let lease = lease_fixture(true);
        let token = signer(&key)
            .issue(&lease, 100, Uuid::from_u128(7))
            .expect("issue token");
        let verified = verifier(&key, None)
            .verify(&token, &lease, 101)
            .expect("verify token");
        assert_eq!(verified.claims.lease_digest, lease.lease_digest);
        assert_eq!(verified.claims.adapter_id, lease.adapter_id);
        assert_eq!(verified.claims.expires_at_ms, lease.expires_at_ms);
        assert_eq!(
            verified.token_digest,
            EvidenceDigest::sha256(token.as_bytes())
        );

        let other = lease_fixture(true);
        assert!(matches!(
            verifier(&key, None).verify(&token, &other, 101),
            Err(WorkflowExecutionGrantError::LeaseBindingMismatch)
        ));
        assert!(matches!(
            verifier(&key, None).verify(&format!("{token}="), &lease, 101),
            Err(WorkflowExecutionGrantError::MalformedToken
                | WorkflowExecutionGrantError::NoncanonicalToken)
        ));
        assert!(matches!(
            verifier(&key, None).verify(&token, &lease, lease.expires_at_ms),
            Err(WorkflowExecutionGrantError::GrantNotActive)
        ));
    }

    #[test]
    fn signature_key_lifecycle_and_execution_inputs_fail_closed() {
        let key = SigningKey::from_bytes(&[19_u8; 32]);
        let lease = lease_fixture(true);
        let token = signer(&key)
            .issue(&lease, 100, Uuid::from_u128(9))
            .expect("issue token");
        let wrong = SigningKey::from_bytes(&[20_u8; 32]);
        assert!(matches!(
            verifier(&wrong, None).verify(&token, &lease, 101),
            Err(WorkflowExecutionGrantError::SignatureVerification(_))
        ));
        assert!(matches!(
            verifier(&key, Some(101)).verify(&token, &lease, 101),
            Err(WorkflowExecutionGrantError::KeyLifecycleRejected)
        ));
        assert!(matches!(
            signer(&key).issue(&lease_fixture(false), 100, Uuid::from_u128(10)),
            Err(WorkflowExecutionGrantError::Workflow(
                crate::domain::WorkflowContractError::MissingLeaseInputArtifacts
            ))
        ));
    }
}
