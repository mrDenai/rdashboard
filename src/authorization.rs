use std::{collections::BTreeMap, str::FromStr as _};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::EvidenceDigest;

pub const ACTION_GRANT_SCHEMA_VERSION: u16 = 1;
pub const ACTION_GRANT_MAX_TTL_MS: i64 = 2 * 60 * 1_000;

const ACTION_GRANT_SIGNATURE_DOMAIN: &[u8] = b"rdashboard.action-grant.v1\0";
const MAX_ACTION_GRANT_PAYLOAD_BYTES: usize = 4 * 1024;
const MAX_ACTION_GRANT_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Decode, Deserialize, Encode, Eq, PartialEq, Serialize)]
#[cbor(index_only)]
#[serde(rename_all = "snake_case")]
pub enum ActionGrantRoleV1 {
    #[n(0)]
    Operator,
    #[n(1)]
    Admin,
}

impl ActionGrantRoleV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionGrantIssueInputV1 {
    pub issued_at_ms: i64,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: Uuid,
    pub actor_id: Uuid,
    pub role: ActionGrantRoleV1,
    pub lease_id: Uuid,
    pub lease_generation: u64,
    pub intent_id: Uuid,
    pub intent_digest: EvidenceDigest,
    pub installed_policy_digest: EvidenceDigest,
    pub request_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionGrantExpectedBindingV1 {
    pub actor_id: Uuid,
    pub role: ActionGrantRoleV1,
    pub lease_id: Uuid,
    pub lease_generation: u64,
    pub intent_id: Uuid,
    pub intent_digest: EvidenceDigest,
    pub installed_policy_digest: EvidenceDigest,
    pub request_id: Uuid,
}

#[derive(Clone, Debug)]
pub struct ActionGrantSignerV1 {
    issuer: String,
    executor_audience: String,
    key_id: String,
    key_epoch: u64,
    signing_key: SigningKey,
}

impl ActionGrantSignerV1 {
    pub fn new(
        issuer: impl Into<String>,
        executor_audience: impl Into<String>,
        key_id: impl Into<String>,
        key_epoch: u64,
        signing_key: SigningKey,
    ) -> Result<Self, ActionGrantError> {
        let issuer = issuer.into();
        let executor_audience = executor_audience.into();
        let key_id = key_id.into();
        validate_identity(&issuer)?;
        validate_identity(&executor_audience)?;
        validate_key_id(&key_id)?;
        if key_epoch == 0 || key_epoch > i64::MAX.unsigned_abs() {
            return Err(ActionGrantError::InvalidKeyEpoch);
        }
        Ok(Self {
            issuer,
            executor_audience,
            key_id,
            key_epoch,
            signing_key,
        })
    }

    pub fn issue(&self, input: &ActionGrantIssueInputV1) -> Result<String, ActionGrantError> {
        validate_issue_input(input)?;
        let payload = ActionGrantPayloadCbor {
            schema_version: ACTION_GRANT_SCHEMA_VERSION,
            issuer: self.issuer.clone(),
            executor_audience: self.executor_audience.clone(),
            key_id: self.key_id.clone(),
            key_epoch: self.key_epoch,
            issued_at_ms: input.issued_at_ms,
            not_before_ms: input.not_before_ms,
            expires_at_ms: input.expires_at_ms,
            nonce: *input.nonce.as_bytes(),
            actor_id: *input.actor_id.as_bytes(),
            role: input.role,
            lease_id: *input.lease_id.as_bytes(),
            lease_generation: input.lease_generation,
            intent_id: *input.intent_id.as_bytes(),
            intent_digest: input.intent_digest.to_string(),
            installed_policy_digest: input.installed_policy_digest.to_string(),
            request_id: *input.request_id.as_bytes(),
        };
        let payload_bytes = encode_payload(&payload)?;
        let signature = self.signing_key.sign(&signature_input(&payload_bytes));
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload_bytes),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

#[derive(Clone, Debug)]
pub struct ActionGrantVerificationKeyV1 {
    key_id: String,
    key_epoch: u64,
    verifying_key: VerifyingKey,
    active_from_ms: i64,
    signing_retired_at_ms: Option<i64>,
    verify_until_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
}

impl ActionGrantVerificationKeyV1 {
    pub fn new(
        key_id: impl Into<String>,
        key_epoch: u64,
        verifying_key: VerifyingKey,
        active_from_ms: i64,
        signing_retired_at_ms: Option<i64>,
        verify_until_ms: Option<i64>,
        revoked_at_ms: Option<i64>,
    ) -> Result<Self, ActionGrantError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        if key_epoch == 0
            || key_epoch > i64::MAX.unsigned_abs()
            || active_from_ms < 0
            || signing_retired_at_ms.is_some_and(|value| value <= active_from_ms)
            || verify_until_ms
                .is_some_and(|value| value <= signing_retired_at_ms.unwrap_or(active_from_ms))
            || signing_retired_at_ms.is_none() != verify_until_ms.is_none()
            || revoked_at_ms.is_some_and(|value| value < active_from_ms)
        {
            return Err(ActionGrantError::InvalidKeyLifecycle);
        }
        Ok(Self {
            key_id,
            key_epoch,
            verifying_key,
            active_from_ms,
            signing_retired_at_ms,
            verify_until_ms,
            revoked_at_ms,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ActionGrantVerifierV1 {
    issuer: String,
    executor_audience: String,
    minimum_key_epoch: u64,
    keys: BTreeMap<String, ActionGrantVerificationKeyV1>,
}

impl ActionGrantVerifierV1 {
    pub fn new(
        issuer: impl Into<String>,
        executor_audience: impl Into<String>,
        minimum_key_epoch: u64,
        keys: impl IntoIterator<Item = ActionGrantVerificationKeyV1>,
    ) -> Result<Self, ActionGrantError> {
        let issuer = issuer.into();
        let executor_audience = executor_audience.into();
        validate_identity(&issuer)?;
        validate_identity(&executor_audience)?;
        if minimum_key_epoch == 0 || minimum_key_epoch > i64::MAX.unsigned_abs() {
            return Err(ActionGrantError::InvalidKeyEpoch);
        }
        let mut indexed = BTreeMap::new();
        for key in keys {
            let key_id = key.key_id.clone();
            if indexed.insert(key_id, key).is_some() {
                return Err(ActionGrantError::DuplicateKey);
            }
        }
        if indexed.is_empty() {
            return Err(ActionGrantError::EmptyKeyring);
        }
        Ok(Self {
            issuer,
            executor_audience,
            minimum_key_epoch,
            keys: indexed,
        })
    }

    pub fn verify(
        &self,
        token: &str,
        expected: &ActionGrantExpectedBindingV1,
        now_ms: i64,
    ) -> Result<VerifiedActionGrantV1, ActionGrantError> {
        validate_expected_binding(expected)?;
        let authenticated = self.authenticate_for_persisted_intent(token, now_ms)?;
        if !authenticated.claims.matches(expected) {
            return Err(ActionGrantError::BindingMismatch);
        }
        Ok(VerifiedActionGrantV1 {
            claims: authenticated.claims,
            digest: authenticated.digest,
        })
    }

    pub fn authenticate_for_persisted_intent(
        &self,
        token: &str,
        now_ms: i64,
    ) -> Result<AuthenticatedActionGrantV1, ActionGrantError> {
        if now_ms < 0 {
            return Err(ActionGrantError::InvalidVerificationTime);
        }
        let (payload_bytes, signature) = decode_token(token)?;
        let payload = decode_canonical_payload(&payload_bytes)?;
        validate_payload_shape(&payload)?;
        let key = self
            .keys
            .get(&payload.key_id)
            .ok_or_else(|| ActionGrantError::UnknownKey(payload.key_id.clone()))?;
        if payload.key_epoch != key.key_epoch || payload.key_epoch < self.minimum_key_epoch {
            return Err(ActionGrantError::KeyEpochRejected);
        }
        key.verifying_key
            .verify_strict(&signature_input(&payload_bytes), &signature)
            .map_err(ActionGrantError::SignatureVerification)?;
        validate_key_lifecycle(key, &payload, now_ms)?;
        if payload.issuer != self.issuer {
            return Err(ActionGrantError::IssuerMismatch);
        }
        if payload.executor_audience != self.executor_audience {
            return Err(ActionGrantError::AudienceMismatch);
        }
        if now_ms < payload.not_before_ms {
            return Err(ActionGrantError::NotYetValid);
        }
        if now_ms >= payload.expires_at_ms {
            return Err(ActionGrantError::Expired);
        }
        let claims = ActionGrantClaimsV1::try_from(payload)?;
        let digest = EvidenceDigest::sha256(
            [
                ACTION_GRANT_SIGNATURE_DOMAIN,
                payload_bytes.as_slice(),
                signature.to_bytes().as_slice(),
            ]
            .concat(),
        );
        Ok(AuthenticatedActionGrantV1 { claims, digest })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionGrantClaimsV1 {
    pub schema_version: u16,
    pub issuer: String,
    pub executor_audience: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub issued_at_ms: i64,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: Uuid,
    pub actor_id: Uuid,
    pub role: ActionGrantRoleV1,
    pub lease_id: Uuid,
    pub lease_generation: u64,
    pub intent_id: Uuid,
    pub intent_digest: EvidenceDigest,
    pub installed_policy_digest: EvidenceDigest,
    pub request_id: Uuid,
}

impl ActionGrantClaimsV1 {
    fn matches(&self, expected: &ActionGrantExpectedBindingV1) -> bool {
        self.actor_id == expected.actor_id
            && self.role == expected.role
            && self.lease_id == expected.lease_id
            && self.lease_generation == expected.lease_generation
            && self.intent_id == expected.intent_id
            && self.intent_digest == expected.intent_digest
            && self.installed_policy_digest == expected.installed_policy_digest
            && self.request_id == expected.request_id
    }
}

/// Decodes canonical action-grant claims without authenticating their signature.
///
/// This is only suitable for preflight checks whose result is followed by authoritative
/// verification at the root executor. A caller must never treat these claims as authorization.
pub fn inspect_unverified_action_grant(
    token: &str,
) -> Result<ActionGrantClaimsV1, ActionGrantError> {
    let (payload_bytes, _) = decode_token(token)?;
    let payload = decode_canonical_payload(&payload_bytes)?;
    validate_payload_shape(&payload)?;
    ActionGrantClaimsV1::try_from(payload)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedActionGrantV1 {
    claims: ActionGrantClaimsV1,
    digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedActionGrantV1 {
    claims: ActionGrantClaimsV1,
    digest: EvidenceDigest,
}

impl AuthenticatedActionGrantV1 {
    pub const fn claims(&self) -> &ActionGrantClaimsV1 {
        &self.claims
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.digest
    }
}

impl VerifiedActionGrantV1 {
    pub const fn claims(&self) -> &ActionGrantClaimsV1 {
        &self.claims
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.digest
    }
}

#[derive(Clone, Debug, Decode, Encode)]
#[cbor(map)]
struct ActionGrantPayloadCbor {
    #[n(0)]
    schema_version: u16,
    #[n(1)]
    issuer: String,
    #[n(2)]
    executor_audience: String,
    #[n(3)]
    key_id: String,
    #[n(4)]
    key_epoch: u64,
    #[n(5)]
    issued_at_ms: i64,
    #[n(6)]
    not_before_ms: i64,
    #[n(7)]
    expires_at_ms: i64,
    #[n(8)]
    #[cbor(with = "minicbor::bytes")]
    nonce: [u8; 16],
    #[n(9)]
    #[cbor(with = "minicbor::bytes")]
    actor_id: [u8; 16],
    #[n(10)]
    role: ActionGrantRoleV1,
    #[n(11)]
    #[cbor(with = "minicbor::bytes")]
    lease_id: [u8; 16],
    #[n(12)]
    lease_generation: u64,
    #[n(13)]
    #[cbor(with = "minicbor::bytes")]
    intent_id: [u8; 16],
    #[n(14)]
    intent_digest: String,
    #[n(15)]
    installed_policy_digest: String,
    #[n(16)]
    #[cbor(with = "minicbor::bytes")]
    request_id: [u8; 16],
}

impl TryFrom<ActionGrantPayloadCbor> for ActionGrantClaimsV1 {
    type Error = ActionGrantError;

    fn try_from(payload: ActionGrantPayloadCbor) -> Result<Self, Self::Error> {
        Ok(Self {
            schema_version: payload.schema_version,
            issuer: payload.issuer,
            executor_audience: payload.executor_audience,
            key_id: payload.key_id,
            key_epoch: payload.key_epoch,
            issued_at_ms: payload.issued_at_ms,
            not_before_ms: payload.not_before_ms,
            expires_at_ms: payload.expires_at_ms,
            nonce: Uuid::from_bytes(payload.nonce),
            actor_id: Uuid::from_bytes(payload.actor_id),
            role: payload.role,
            lease_id: Uuid::from_bytes(payload.lease_id),
            lease_generation: payload.lease_generation,
            intent_id: Uuid::from_bytes(payload.intent_id),
            intent_digest: EvidenceDigest::from_str(&payload.intent_digest)
                .map_err(|_| ActionGrantError::InvalidDigest)?,
            installed_policy_digest: EvidenceDigest::from_str(&payload.installed_policy_digest)
                .map_err(|_| ActionGrantError::InvalidDigest)?,
            request_id: Uuid::from_bytes(payload.request_id),
        })
    }
}

fn validate_issue_input(input: &ActionGrantIssueInputV1) -> Result<(), ActionGrantError> {
    if input.issued_at_ms < 0
        || input.not_before_ms < input.issued_at_ms
        || input.expires_at_ms <= input.not_before_ms
        || input.expires_at_ms - input.issued_at_ms > ACTION_GRANT_MAX_TTL_MS
    {
        return Err(ActionGrantError::InvalidLifetime);
    }
    if input.nonce.is_nil()
        || input.actor_id.is_nil()
        || input.lease_id.is_nil()
        || input.intent_id.is_nil()
        || input.request_id.is_nil()
        || input.lease_generation == 0
        || input.lease_generation > i64::MAX.unsigned_abs()
    {
        return Err(ActionGrantError::InvalidIdentity);
    }
    Ok(())
}

fn validate_expected_binding(
    expected: &ActionGrantExpectedBindingV1,
) -> Result<(), ActionGrantError> {
    if expected.actor_id.is_nil()
        || expected.lease_id.is_nil()
        || expected.intent_id.is_nil()
        || expected.request_id.is_nil()
        || expected.lease_generation == 0
    {
        return Err(ActionGrantError::InvalidExpectedBinding);
    }
    Ok(())
}

fn validate_payload_shape(payload: &ActionGrantPayloadCbor) -> Result<(), ActionGrantError> {
    if payload.schema_version != ACTION_GRANT_SCHEMA_VERSION {
        return Err(ActionGrantError::UnsupportedSchemaVersion(
            payload.schema_version,
        ));
    }
    validate_identity(&payload.issuer)?;
    validate_identity(&payload.executor_audience)?;
    validate_key_id(&payload.key_id)?;
    if payload.key_epoch == 0 || payload.key_epoch > i64::MAX.unsigned_abs() {
        return Err(ActionGrantError::InvalidKeyEpoch);
    }
    let input = ActionGrantIssueInputV1 {
        issued_at_ms: payload.issued_at_ms,
        not_before_ms: payload.not_before_ms,
        expires_at_ms: payload.expires_at_ms,
        nonce: Uuid::from_bytes(payload.nonce),
        actor_id: Uuid::from_bytes(payload.actor_id),
        role: payload.role,
        lease_id: Uuid::from_bytes(payload.lease_id),
        lease_generation: payload.lease_generation,
        intent_id: Uuid::from_bytes(payload.intent_id),
        intent_digest: EvidenceDigest::from_str(&payload.intent_digest)
            .map_err(|_| ActionGrantError::InvalidDigest)?,
        installed_policy_digest: EvidenceDigest::from_str(&payload.installed_policy_digest)
            .map_err(|_| ActionGrantError::InvalidDigest)?,
        request_id: Uuid::from_bytes(payload.request_id),
    };
    validate_issue_input(&input)
}

fn validate_key_lifecycle(
    key: &ActionGrantVerificationKeyV1,
    payload: &ActionGrantPayloadCbor,
    now_ms: i64,
) -> Result<(), ActionGrantError> {
    if key.revoked_at_ms.is_some_and(|value| value <= now_ms) {
        return Err(ActionGrantError::KeyRevoked);
    }
    if payload.issued_at_ms < key.active_from_ms
        || key
            .signing_retired_at_ms
            .is_some_and(|value| payload.issued_at_ms >= value)
    {
        return Err(ActionGrantError::KeyInactiveAtIssue);
    }
    if key.verify_until_ms.is_some_and(|value| now_ms >= value) {
        return Err(ActionGrantError::KeyRetired);
    }
    Ok(())
}

fn encode_payload(payload: &ActionGrantPayloadCbor) -> Result<Vec<u8>, ActionGrantError> {
    let bytes = minicbor::to_vec(payload)
        .map_err(|error| ActionGrantError::CborEncode(error.to_string()))?;
    if bytes.len() > MAX_ACTION_GRANT_PAYLOAD_BYTES {
        return Err(ActionGrantError::PayloadOversized);
    }
    Ok(bytes)
}

fn decode_canonical_payload(bytes: &[u8]) -> Result<ActionGrantPayloadCbor, ActionGrantError> {
    if bytes.is_empty() || bytes.len() > MAX_ACTION_GRANT_PAYLOAD_BYTES {
        return Err(ActionGrantError::PayloadOversized);
    }
    let payload: ActionGrantPayloadCbor =
        minicbor::decode(bytes).map_err(|error| ActionGrantError::CborDecode(error.to_string()))?;
    if encode_payload(&payload)? != bytes {
        return Err(ActionGrantError::NonCanonicalPayload);
    }
    Ok(payload)
}

fn decode_token(token: &str) -> Result<(Vec<u8>, Signature), ActionGrantError> {
    if token.len() > MAX_ACTION_GRANT_TOKEN_BYTES || !token.is_ascii() {
        return Err(ActionGrantError::InvalidTokenEncoding);
    }
    let mut parts = token.split('.');
    let payload_part = parts.next().ok_or(ActionGrantError::InvalidTokenEncoding)?;
    let signature_part = parts.next().ok_or(ActionGrantError::InvalidTokenEncoding)?;
    if payload_part.is_empty() || signature_part.is_empty() || parts.next().is_some() {
        return Err(ActionGrantError::InvalidTokenEncoding);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_part)
        .map_err(ActionGrantError::Base64)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(ActionGrantError::Base64)?;
    if URL_SAFE_NO_PAD.encode(&payload) != payload_part
        || URL_SAFE_NO_PAD.encode(&signature_bytes) != signature_part
    {
        return Err(ActionGrantError::NonCanonicalTokenEncoding);
    }
    let signature =
        Signature::from_slice(&signature_bytes).map_err(ActionGrantError::InvalidSignature)?;
    Ok((payload, signature))
}

fn signature_input(payload: &[u8]) -> Vec<u8> {
    [ACTION_GRANT_SIGNATURE_DOMAIN, payload].concat()
}

fn validate_identity(value: &str) -> Result<(), ActionGrantError> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        Err(ActionGrantError::InvalidServiceIdentity)
    } else {
        Ok(())
    }
}

fn validate_key_id(value: &str) -> Result<(), ActionGrantError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(ActionGrantError::InvalidKeyId)
    } else {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ActionGrantError {
    #[error("action-grant service identity is invalid")]
    InvalidServiceIdentity,
    #[error("action-grant key ID is invalid")]
    InvalidKeyId,
    #[error("action-grant key epoch must be non-zero")]
    InvalidKeyEpoch,
    #[error("action-grant key lifecycle is invalid")]
    InvalidKeyLifecycle,
    #[error("action-grant keyring must not be empty")]
    EmptyKeyring,
    #[error("action-grant keyring contains a duplicate key ID")]
    DuplicateKey,
    #[error("action-grant lifetime is invalid or exceeds two minutes")]
    InvalidLifetime,
    #[error("action-grant identity is nil or its lease generation is zero")]
    InvalidIdentity,
    #[error("expected action-grant binding is invalid")]
    InvalidExpectedBinding,
    #[error("action-grant CBOR encoding failed: {0}")]
    CborEncode(String),
    #[error("action-grant CBOR decoding failed: {0}")]
    CborDecode(String),
    #[error("action-grant payload is empty or oversized")]
    PayloadOversized,
    #[error("action-grant payload is not deterministic canonical CBOR")]
    NonCanonicalPayload,
    #[error("action-grant compact token encoding is invalid")]
    InvalidTokenEncoding,
    #[error("action-grant compact token encoding is not canonical")]
    NonCanonicalTokenEncoding,
    #[error("action-grant base64url decoding failed: {0}")]
    Base64(base64::DecodeError),
    #[error("action-grant signature has an invalid length: {0}")]
    InvalidSignature(ed25519_dalek::SignatureError),
    #[error("action-grant signature verification failed: {0}")]
    SignatureVerification(ed25519_dalek::SignatureError),
    #[error("unsupported action-grant schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("action-grant contains an invalid evidence digest")]
    InvalidDigest,
    #[error("action-grant verification time is invalid")]
    InvalidVerificationTime,
    #[error("unknown action-grant key {0}")]
    UnknownKey(String),
    #[error("action-grant key epoch was rolled back or does not match its key")]
    KeyEpochRejected,
    #[error("action-grant key was revoked")]
    KeyRevoked,
    #[error("action-grant key was not active when this grant was issued")]
    KeyInactiveAtIssue,
    #[error("action-grant verification overlap has ended")]
    KeyRetired,
    #[error("action-grant issuer does not match the executor policy")]
    IssuerMismatch,
    #[error("action-grant audience does not match the executor")]
    AudienceMismatch,
    #[error("action grant is not valid yet")]
    NotYetValid,
    #[error("action grant has expired")]
    Expired,
    #[error("action grant does not match the actor, lease, intent, policy or request")]
    BindingMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_rejects_an_epoch_outside_the_durable_journal_range_before_key_lookup() {
        let signing_key = SigningKey::from_bytes(&[73_u8; 32]);
        let actor_id = Uuid::new_v4();
        let lease_id = Uuid::new_v4();
        let intent_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let intent_digest = EvidenceDigest::sha256("oversized epoch intent");
        let installed_policy_digest = EvidenceDigest::sha256("oversized epoch policy");
        let payload = ActionGrantPayloadCbor {
            schema_version: ACTION_GRANT_SCHEMA_VERSION,
            issuer: "https://actions.dev.4u.ge".to_owned(),
            executor_audience: "rdashboard-executor".to_owned(),
            key_id: "authorizer-2026-01".to_owned(),
            key_epoch: i64::MAX.unsigned_abs() + 1,
            issued_at_ms: 2_000,
            not_before_ms: 2_000,
            expires_at_ms: 3_000,
            nonce: *Uuid::new_v4().as_bytes(),
            actor_id: *actor_id.as_bytes(),
            role: ActionGrantRoleV1::Admin,
            lease_id: *lease_id.as_bytes(),
            lease_generation: 7,
            intent_id: *intent_id.as_bytes(),
            intent_digest: intent_digest.to_string(),
            installed_policy_digest: installed_policy_digest.to_string(),
            request_id: *request_id.as_bytes(),
        };
        let payload_bytes =
            encode_payload(&payload).unwrap_or_else(|error| panic!("encode payload: {error}"));
        let signature = signing_key.sign(&signature_input(&payload_bytes));
        let token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload_bytes),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        let key = ActionGrantVerificationKeyV1::new(
            "authorizer-2026-01",
            3,
            signing_key.verifying_key(),
            1_000,
            None,
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("verification key: {error}"));
        let verifier = ActionGrantVerifierV1::new(
            "https://actions.dev.4u.ge",
            "rdashboard-executor",
            3,
            [key],
        )
        .unwrap_or_else(|error| panic!("verifier: {error}"));
        let expected = ActionGrantExpectedBindingV1 {
            actor_id,
            role: ActionGrantRoleV1::Admin,
            lease_id,
            lease_generation: 7,
            intent_id,
            intent_digest,
            installed_policy_digest,
            request_id,
        };

        assert!(matches!(
            verifier.verify(&token, &expected, 2_500),
            Err(ActionGrantError::InvalidKeyEpoch)
        ));
    }
}
