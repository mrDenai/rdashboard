use std::{collections::BTreeMap, str::FromStr as _};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{EvidenceDigest, GitCommitId, OperationKind, ProjectId, ReleaseClass};

pub const EXECUTOR_INTENT_SCHEMA_VERSION: u16 = 2;
pub const EXECUTOR_INTENT_MAX_TTL_MS: i64 = 5 * 60 * 1_000;

const EXECUTOR_INTENT_SIGNATURE_DOMAIN: &[u8] = b"rdashboard.executor-intent.v1\0";
const MAX_EXECUTOR_INTENT_PAYLOAD_BYTES: usize = 8 * 1024;
const MAX_EXECUTOR_INTENT_TOKEN_BYTES: usize = 24 * 1024;
const MAX_MIGRATION_ID_BYTES: usize = 128;

#[derive(
    Clone, Copy, Debug, Decode, Deserialize, Encode, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[cbor(index_only)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorIntentConsequenceV1 {
    #[n(0)]
    CodeDeployment,
    #[n(1)]
    VerifiedBackupRequired,
    #[n(2)]
    ApplicationWriteDrain,
    #[n(3)]
    SchemaMigration,
    #[n(4)]
    AutomaticCodeRollbackAvailable,
    #[n(5)]
    AutomaticRollbackProhibited,
    #[n(6)]
    DataRestoreIsManual,
    #[n(7)]
    FirstInstallRollbackUnavailable,
    #[n(8)]
    CodeRollback,
    #[n(9)]
    BackupOnly,
}

#[derive(Clone, Copy, Debug, Decode, Deserialize, Encode, Eq, PartialEq, Serialize)]
#[cbor(index_only)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorIntentRequiredRoleV1 {
    #[n(0)]
    Operator,
    #[n(1)]
    Admin,
}

impl ExecutorIntentRequiredRoleV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorIntentIssueInputV1 {
    pub issued_at_ms: i64,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub intent_id: Uuid,
    pub request_id: Uuid,
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub target_commit: Option<GitCommitId>,
    pub proposed_release_class: Option<ReleaseClass>,
    pub effective_release_class: Option<ReleaseClass>,
    pub installed_policy_digest: EvidenceDigest,
    pub source_attestation_digest: Option<EvidenceDigest>,
    pub source_sequence: Option<u64>,
    pub release_bundle_digest: Option<EvidenceDigest>,
    pub build_attestation_digest: Option<EvidenceDigest>,
    pub migration_id: Option<String>,
    pub previous_release_bundle_digest: Option<EvidenceDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorIntentExpectedBindingV1 {
    pub request_id: Uuid,
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub target_commit: Option<GitCommitId>,
    pub installed_policy_digest: EvidenceDigest,
}

#[derive(Clone, Debug)]
pub struct ExecutorIntentSignerV1 {
    issuer: String,
    authorizer_audience: String,
    key_id: String,
    key_epoch: u64,
    signing_key: SigningKey,
}

impl ExecutorIntentSignerV1 {
    pub fn new(
        issuer: impl Into<String>,
        authorizer_audience: impl Into<String>,
        key_id: impl Into<String>,
        key_epoch: u64,
        signing_key: SigningKey,
    ) -> Result<Self, ExecutorIntentError> {
        let issuer = issuer.into();
        let authorizer_audience = authorizer_audience.into();
        let key_id = key_id.into();
        validate_service_identity(&issuer)?;
        validate_service_identity(&authorizer_audience)?;
        validate_key_id(&key_id)?;
        validate_epoch(key_epoch)?;
        Ok(Self {
            issuer,
            authorizer_audience,
            key_id,
            key_epoch,
            signing_key,
        })
    }

    pub fn issue(
        &self,
        input: &ExecutorIntentIssueInputV1,
    ) -> Result<SignedExecutorIntentV1, ExecutorIntentError> {
        validate_issue_input(input)?;
        let consequences = expected_consequences(input);
        let payload = ExecutorIntentPayloadCbor {
            schema_version: EXECUTOR_INTENT_SCHEMA_VERSION,
            issuer: self.issuer.clone(),
            authorizer_audience: self.authorizer_audience.clone(),
            key_id: self.key_id.clone(),
            key_epoch: self.key_epoch,
            issued_at_ms: input.issued_at_ms,
            not_before_ms: input.not_before_ms,
            expires_at_ms: input.expires_at_ms,
            intent_id: *input.intent_id.as_bytes(),
            request_id: *input.request_id.as_bytes(),
            project_id: input.project_id.to_string(),
            operation_kind: IntentOperationKindCbor::from(input.operation_kind),
            target_commit: input.target_commit.as_ref().map(ToString::to_string),
            proposed_release_class: input
                .proposed_release_class
                .map(IntentReleaseClassCbor::from),
            effective_release_class: input
                .effective_release_class
                .map(IntentReleaseClassCbor::from),
            installed_policy_digest: input.installed_policy_digest.to_string(),
            source_attestation_digest: input
                .source_attestation_digest
                .as_ref()
                .map(ToString::to_string),
            source_sequence: input.source_sequence,
            release_bundle_digest: input
                .release_bundle_digest
                .as_ref()
                .map(ToString::to_string),
            build_attestation_digest: input
                .build_attestation_digest
                .as_ref()
                .map(ToString::to_string),
            migration_id: input.migration_id.clone(),
            previous_release_bundle_digest: input
                .previous_release_bundle_digest
                .as_ref()
                .map(ToString::to_string),
            consequences,
            minimum_role: expected_minimum_role(input),
        };
        let payload_bytes = encode_payload(&payload)?;
        let signature = self.signing_key.sign(&signature_input(&payload_bytes));
        let compact = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload_bytes),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        let claims = ExecutorIntentClaimsV1::try_from(payload)?;
        let digest = intent_digest(&payload_bytes, &signature);
        Ok(SignedExecutorIntentV1 {
            compact,
            claims,
            digest,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ExecutorIntentVerificationKeyV1 {
    key_id: String,
    key_epoch: u64,
    verifying_key: VerifyingKey,
    active_from_ms: i64,
    signing_retired_at_ms: Option<i64>,
    verify_until_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
}

impl ExecutorIntentVerificationKeyV1 {
    pub fn new(
        key_id: impl Into<String>,
        key_epoch: u64,
        verifying_key: VerifyingKey,
        active_from_ms: i64,
        signing_retired_at_ms: Option<i64>,
        verify_until_ms: Option<i64>,
        revoked_at_ms: Option<i64>,
    ) -> Result<Self, ExecutorIntentError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        validate_epoch(key_epoch)?;
        if active_from_ms < 0
            || signing_retired_at_ms.is_some_and(|value| value <= active_from_ms)
            || verify_until_ms
                .is_some_and(|value| value <= signing_retired_at_ms.unwrap_or(active_from_ms))
            || signing_retired_at_ms.is_none() != verify_until_ms.is_none()
            || revoked_at_ms.is_some_and(|value| value < active_from_ms)
        {
            return Err(ExecutorIntentError::InvalidKeyLifecycle);
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
pub struct ExecutorIntentVerifierV1 {
    issuer: String,
    authorizer_audience: String,
    minimum_key_epoch: u64,
    keys: BTreeMap<String, ExecutorIntentVerificationKeyV1>,
}

impl ExecutorIntentVerifierV1 {
    pub fn new(
        issuer: impl Into<String>,
        authorizer_audience: impl Into<String>,
        minimum_key_epoch: u64,
        keys: impl IntoIterator<Item = ExecutorIntentVerificationKeyV1>,
    ) -> Result<Self, ExecutorIntentError> {
        let issuer = issuer.into();
        let authorizer_audience = authorizer_audience.into();
        validate_service_identity(&issuer)?;
        validate_service_identity(&authorizer_audience)?;
        validate_epoch(minimum_key_epoch)?;
        let mut indexed = BTreeMap::new();
        for key in keys {
            if indexed.insert(key.key_id.clone(), key).is_some() {
                return Err(ExecutorIntentError::DuplicateKey);
            }
        }
        if indexed.is_empty() {
            return Err(ExecutorIntentError::EmptyKeyring);
        }
        Ok(Self {
            issuer,
            authorizer_audience,
            minimum_key_epoch,
            keys: indexed,
        })
    }

    pub fn verify(
        &self,
        token: &str,
        now_ms: i64,
    ) -> Result<VerifiedExecutorIntentV1, ExecutorIntentError> {
        self.verify_inner(token, None, now_ms)
    }

    pub fn verify_bound(
        &self,
        token: &str,
        expected: &ExecutorIntentExpectedBindingV1,
        now_ms: i64,
    ) -> Result<VerifiedExecutorIntentV1, ExecutorIntentError> {
        validate_expected_binding(expected)?;
        self.verify_inner(token, Some(expected), now_ms)
    }

    fn verify_inner(
        &self,
        token: &str,
        expected: Option<&ExecutorIntentExpectedBindingV1>,
        now_ms: i64,
    ) -> Result<VerifiedExecutorIntentV1, ExecutorIntentError> {
        if now_ms < 0 {
            return Err(ExecutorIntentError::InvalidVerificationTime);
        }
        let (payload_bytes, signature) = decode_token(token)?;
        let payload = decode_canonical_payload(&payload_bytes)?;
        validate_payload_shape(&payload)?;
        let key = self
            .keys
            .get(&payload.key_id)
            .ok_or_else(|| ExecutorIntentError::UnknownKey(payload.key_id.clone()))?;
        if payload.key_epoch != key.key_epoch || payload.key_epoch < self.minimum_key_epoch {
            return Err(ExecutorIntentError::KeyEpochRejected);
        }
        key.verifying_key
            .verify_strict(&signature_input(&payload_bytes), &signature)
            .map_err(ExecutorIntentError::SignatureVerification)?;
        validate_key_lifecycle(key, &payload, now_ms)?;
        if payload.issuer != self.issuer {
            return Err(ExecutorIntentError::IssuerMismatch);
        }
        if payload.authorizer_audience != self.authorizer_audience {
            return Err(ExecutorIntentError::AudienceMismatch);
        }
        if now_ms < payload.not_before_ms {
            return Err(ExecutorIntentError::NotYetValid);
        }
        if now_ms >= payload.expires_at_ms {
            return Err(ExecutorIntentError::Expired);
        }
        let claims = ExecutorIntentClaimsV1::try_from(payload)?;
        if expected.is_some_and(|binding| !claims.matches(binding)) {
            return Err(ExecutorIntentError::BindingMismatch);
        }
        Ok(VerifiedExecutorIntentV1 {
            claims,
            digest: intent_digest(&payload_bytes, &signature),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorIntentClaimsV1 {
    pub schema_version: u16,
    pub issuer: String,
    pub authorizer_audience: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub issued_at_ms: i64,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub intent_id: Uuid,
    pub request_id: Uuid,
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub target_commit: Option<GitCommitId>,
    pub proposed_release_class: Option<ReleaseClass>,
    pub effective_release_class: Option<ReleaseClass>,
    pub installed_policy_digest: EvidenceDigest,
    pub source_attestation_digest: Option<EvidenceDigest>,
    pub source_sequence: Option<u64>,
    pub release_bundle_digest: Option<EvidenceDigest>,
    pub build_attestation_digest: Option<EvidenceDigest>,
    pub migration_id: Option<String>,
    pub previous_release_bundle_digest: Option<EvidenceDigest>,
    pub consequences: Vec<ExecutorIntentConsequenceV1>,
    pub minimum_role: ExecutorIntentRequiredRoleV1,
}

impl ExecutorIntentClaimsV1 {
    fn matches(&self, expected: &ExecutorIntentExpectedBindingV1) -> bool {
        self.request_id == expected.request_id
            && self.project_id == expected.project_id
            && self.operation_kind == expected.operation_kind
            && self.target_commit == expected.target_commit
            && self.installed_policy_digest == expected.installed_policy_digest
    }
}

/// Decodes canonical executor-intent claims without authenticating their signature.
///
/// This is suitable only for controller presentation and request correlation. The separate
/// authorizer and root executor must still perform authoritative signature verification.
pub fn inspect_unverified_executor_intent(
    token: &str,
) -> Result<ExecutorIntentClaimsV1, ExecutorIntentError> {
    let (payload_bytes, _) = decode_token(token)?;
    let payload = decode_canonical_payload(&payload_bytes)?;
    validate_payload_shape(&payload)?;
    ExecutorIntentClaimsV1::try_from(payload)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedExecutorIntentV1 {
    compact: String,
    claims: ExecutorIntentClaimsV1,
    digest: EvidenceDigest,
}

impl SignedExecutorIntentV1 {
    pub fn compact(&self) -> &str {
        &self.compact
    }

    pub const fn claims(&self) -> &ExecutorIntentClaimsV1 {
        &self.claims
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedExecutorIntentV1 {
    claims: ExecutorIntentClaimsV1,
    digest: EvidenceDigest,
}

impl VerifiedExecutorIntentV1 {
    pub const fn claims(&self) -> &ExecutorIntentClaimsV1 {
        &self.claims
    }

    pub const fn digest(&self) -> &EvidenceDigest {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Decode, Encode)]
#[cbor(index_only)]
enum IntentOperationKindCbor {
    #[n(0)]
    Deploy,
    #[n(1)]
    CodeRollback,
    #[n(2)]
    BackupOnly,
}

impl From<OperationKind> for IntentOperationKindCbor {
    fn from(value: OperationKind) -> Self {
        match value {
            OperationKind::Deploy => Self::Deploy,
            OperationKind::CodeRollback => Self::CodeRollback,
            OperationKind::BackupOnly => Self::BackupOnly,
        }
    }
}

impl From<IntentOperationKindCbor> for OperationKind {
    fn from(value: IntentOperationKindCbor) -> Self {
        match value {
            IntentOperationKindCbor::Deploy => Self::Deploy,
            IntentOperationKindCbor::CodeRollback => Self::CodeRollback,
            IntentOperationKindCbor::BackupOnly => Self::BackupOnly,
        }
    }
}

#[derive(Clone, Copy, Debug, Decode, Encode)]
#[cbor(index_only)]
enum IntentReleaseClassCbor {
    #[n(0)]
    CodeOnlyCompatible,
    #[n(1)]
    StatefulCompatible,
    #[n(2)]
    StatefulBreaking,
    #[n(3)]
    Rollback,
}

impl From<ReleaseClass> for IntentReleaseClassCbor {
    fn from(value: ReleaseClass) -> Self {
        match value {
            ReleaseClass::CodeOnlyCompatible => Self::CodeOnlyCompatible,
            ReleaseClass::StatefulCompatible => Self::StatefulCompatible,
            ReleaseClass::StatefulBreaking => Self::StatefulBreaking,
            ReleaseClass::Rollback => Self::Rollback,
        }
    }
}

impl From<IntentReleaseClassCbor> for ReleaseClass {
    fn from(value: IntentReleaseClassCbor) -> Self {
        match value {
            IntentReleaseClassCbor::CodeOnlyCompatible => Self::CodeOnlyCompatible,
            IntentReleaseClassCbor::StatefulCompatible => Self::StatefulCompatible,
            IntentReleaseClassCbor::StatefulBreaking => Self::StatefulBreaking,
            IntentReleaseClassCbor::Rollback => Self::Rollback,
        }
    }
}

#[derive(Clone, Debug, Decode, Encode)]
#[cbor(map)]
struct ExecutorIntentPayloadCbor {
    #[n(0)]
    schema_version: u16,
    #[n(1)]
    issuer: String,
    #[n(2)]
    authorizer_audience: String,
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
    intent_id: [u8; 16],
    #[n(9)]
    #[cbor(with = "minicbor::bytes")]
    request_id: [u8; 16],
    #[n(10)]
    project_id: String,
    #[n(11)]
    operation_kind: IntentOperationKindCbor,
    #[n(12)]
    target_commit: Option<String>,
    #[n(13)]
    proposed_release_class: Option<IntentReleaseClassCbor>,
    #[n(14)]
    effective_release_class: Option<IntentReleaseClassCbor>,
    #[n(15)]
    installed_policy_digest: String,
    #[n(16)]
    source_attestation_digest: Option<String>,
    #[n(17)]
    source_sequence: Option<u64>,
    #[n(18)]
    migration_id: Option<String>,
    #[n(19)]
    previous_release_bundle_digest: Option<String>,
    #[n(20)]
    consequences: Vec<ExecutorIntentConsequenceV1>,
    #[n(21)]
    minimum_role: ExecutorIntentRequiredRoleV1,
    #[n(22)]
    release_bundle_digest: Option<String>,
    #[n(23)]
    build_attestation_digest: Option<String>,
}

impl TryFrom<ExecutorIntentPayloadCbor> for ExecutorIntentClaimsV1 {
    type Error = ExecutorIntentError;

    fn try_from(payload: ExecutorIntentPayloadCbor) -> Result<Self, Self::Error> {
        Ok(Self {
            schema_version: payload.schema_version,
            issuer: payload.issuer,
            authorizer_audience: payload.authorizer_audience,
            key_id: payload.key_id,
            key_epoch: payload.key_epoch,
            issued_at_ms: payload.issued_at_ms,
            not_before_ms: payload.not_before_ms,
            expires_at_ms: payload.expires_at_ms,
            intent_id: Uuid::from_bytes(payload.intent_id),
            request_id: Uuid::from_bytes(payload.request_id),
            project_id: ProjectId::from_str(&payload.project_id)
                .map_err(|_| ExecutorIntentError::InvalidProject)?,
            operation_kind: payload.operation_kind.into(),
            target_commit: payload
                .target_commit
                .map(|value| {
                    GitCommitId::from_str(&value).map_err(|_| ExecutorIntentError::InvalidCommit)
                })
                .transpose()?,
            proposed_release_class: payload.proposed_release_class.map(Into::into),
            effective_release_class: payload.effective_release_class.map(Into::into),
            installed_policy_digest: parse_digest(&payload.installed_policy_digest)?,
            source_attestation_digest: payload
                .source_attestation_digest
                .map(|value| parse_digest(&value))
                .transpose()?,
            source_sequence: payload.source_sequence,
            release_bundle_digest: payload
                .release_bundle_digest
                .map(|value| parse_digest(&value))
                .transpose()?,
            build_attestation_digest: payload
                .build_attestation_digest
                .map(|value| parse_digest(&value))
                .transpose()?,
            migration_id: payload.migration_id,
            previous_release_bundle_digest: payload
                .previous_release_bundle_digest
                .map(|value| parse_digest(&value))
                .transpose()?,
            consequences: payload.consequences,
            minimum_role: payload.minimum_role,
        })
    }
}

fn validate_issue_input(input: &ExecutorIntentIssueInputV1) -> Result<(), ExecutorIntentError> {
    if input.issued_at_ms < 0
        || input.not_before_ms < input.issued_at_ms
        || input.expires_at_ms <= input.not_before_ms
        || input.expires_at_ms - input.issued_at_ms > EXECUTOR_INTENT_MAX_TTL_MS
    {
        return Err(ExecutorIntentError::InvalidLifetime);
    }
    if input.intent_id.is_nil() || input.request_id.is_nil() {
        return Err(ExecutorIntentError::InvalidIdentity);
    }
    if input.operation_kind.requires_commit() != input.target_commit.is_some()
        || input
            .operation_kind
            .required_phases(input.effective_release_class)
            .is_err()
    {
        return Err(ExecutorIntentError::OperationMismatch);
    }
    let proposed_valid = match input.operation_kind {
        OperationKind::Deploy => matches!(
            input.proposed_release_class,
            Some(
                ReleaseClass::CodeOnlyCompatible
                    | ReleaseClass::StatefulCompatible
                    | ReleaseClass::StatefulBreaking
            )
        ),
        OperationKind::CodeRollback => input.proposed_release_class == Some(ReleaseClass::Rollback),
        OperationKind::BackupOnly => input.proposed_release_class.is_none(),
    };
    if !proposed_valid {
        return Err(ExecutorIntentError::OperationMismatch);
    }
    let source_present = input.source_attestation_digest.is_some();
    if source_present != input.source_sequence.is_some()
        || source_present != input.operation_kind.requires_commit()
        || input
            .source_sequence
            .is_some_and(|value| value == 0 || value > i64::MAX.unsigned_abs())
    {
        return Err(ExecutorIntentError::InvalidSourceAuthority);
    }
    let needs_migration = matches!(
        input.effective_release_class,
        Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking)
    );
    if needs_migration != input.migration_id.is_some()
        || input
            .migration_id
            .as_deref()
            .is_some_and(|value| !valid_migration_id(value))
    {
        return Err(ExecutorIntentError::InvalidMigrationId);
    }
    let candidate_binding_valid = match input.operation_kind {
        OperationKind::Deploy => {
            input.release_bundle_digest.is_some() && input.build_attestation_digest.is_some()
        }
        OperationKind::CodeRollback => {
            input.release_bundle_digest.is_some() && input.build_attestation_digest.is_none()
        }
        OperationKind::BackupOnly => {
            input.release_bundle_digest.is_none() && input.build_attestation_digest.is_none()
        }
    };
    if !candidate_binding_valid {
        return Err(ExecutorIntentError::OperationMismatch);
    }
    if (input.operation_kind == OperationKind::CodeRollback)
        != input.previous_release_bundle_digest.is_some()
        && input.operation_kind != OperationKind::Deploy
    {
        return Err(ExecutorIntentError::InvalidRollbackTarget);
    }
    Ok(())
}

fn validate_payload_shape(payload: &ExecutorIntentPayloadCbor) -> Result<(), ExecutorIntentError> {
    if payload.schema_version != EXECUTOR_INTENT_SCHEMA_VERSION {
        return Err(ExecutorIntentError::UnsupportedSchemaVersion(
            payload.schema_version,
        ));
    }
    validate_service_identity(&payload.issuer)?;
    validate_service_identity(&payload.authorizer_audience)?;
    validate_key_id(&payload.key_id)?;
    validate_epoch(payload.key_epoch)?;
    let input = ExecutorIntentIssueInputV1 {
        issued_at_ms: payload.issued_at_ms,
        not_before_ms: payload.not_before_ms,
        expires_at_ms: payload.expires_at_ms,
        intent_id: Uuid::from_bytes(payload.intent_id),
        request_id: Uuid::from_bytes(payload.request_id),
        project_id: ProjectId::from_str(&payload.project_id)
            .map_err(|_| ExecutorIntentError::InvalidProject)?,
        operation_kind: payload.operation_kind.into(),
        target_commit: payload
            .target_commit
            .as_deref()
            .map(GitCommitId::from_str)
            .transpose()
            .map_err(|_| ExecutorIntentError::InvalidCommit)?,
        proposed_release_class: payload.proposed_release_class.map(Into::into),
        effective_release_class: payload.effective_release_class.map(Into::into),
        installed_policy_digest: parse_digest(&payload.installed_policy_digest)?,
        source_attestation_digest: payload
            .source_attestation_digest
            .as_deref()
            .map(parse_digest)
            .transpose()?,
        source_sequence: payload.source_sequence,
        release_bundle_digest: payload
            .release_bundle_digest
            .as_deref()
            .map(parse_digest)
            .transpose()?,
        build_attestation_digest: payload
            .build_attestation_digest
            .as_deref()
            .map(parse_digest)
            .transpose()?,
        migration_id: payload.migration_id.clone(),
        previous_release_bundle_digest: payload
            .previous_release_bundle_digest
            .as_deref()
            .map(parse_digest)
            .transpose()?,
    };
    validate_issue_input(&input)?;
    if payload.consequences != expected_consequences(&input) {
        return Err(ExecutorIntentError::InvalidConsequences);
    }
    if payload.minimum_role != expected_minimum_role(&input) {
        return Err(ExecutorIntentError::InvalidRequiredRole);
    }
    Ok(())
}

fn validate_expected_binding(
    expected: &ExecutorIntentExpectedBindingV1,
) -> Result<(), ExecutorIntentError> {
    if expected.request_id.is_nil()
        || expected.operation_kind.requires_commit() != expected.target_commit.is_some()
    {
        return Err(ExecutorIntentError::InvalidExpectedBinding);
    }
    Ok(())
}

fn expected_consequences(input: &ExecutorIntentIssueInputV1) -> Vec<ExecutorIntentConsequenceV1> {
    use ExecutorIntentConsequenceV1 as Consequence;

    match (input.operation_kind, input.effective_release_class) {
        (OperationKind::Deploy, Some(ReleaseClass::CodeOnlyCompatible)) => vec![
            Consequence::CodeDeployment,
            if input.previous_release_bundle_digest.is_some() {
                Consequence::AutomaticCodeRollbackAvailable
            } else {
                Consequence::FirstInstallRollbackUnavailable
            },
            Consequence::DataRestoreIsManual,
        ],
        (OperationKind::Deploy, Some(ReleaseClass::StatefulCompatible)) => vec![
            Consequence::CodeDeployment,
            Consequence::VerifiedBackupRequired,
            Consequence::ApplicationWriteDrain,
            Consequence::SchemaMigration,
            Consequence::AutomaticCodeRollbackAvailable,
            Consequence::DataRestoreIsManual,
        ],
        (OperationKind::Deploy, Some(ReleaseClass::StatefulBreaking)) => vec![
            Consequence::CodeDeployment,
            Consequence::VerifiedBackupRequired,
            Consequence::ApplicationWriteDrain,
            Consequence::SchemaMigration,
            Consequence::AutomaticRollbackProhibited,
            Consequence::DataRestoreIsManual,
        ],
        (OperationKind::CodeRollback, Some(ReleaseClass::Rollback)) => {
            vec![Consequence::CodeRollback, Consequence::DataRestoreIsManual]
        }
        (OperationKind::BackupOnly, None) => vec![Consequence::BackupOnly],
        _ => Vec::new(),
    }
}

fn expected_minimum_role(input: &ExecutorIntentIssueInputV1) -> ExecutorIntentRequiredRoleV1 {
    if input.operation_kind == OperationKind::CodeRollback
        || matches!(
            input.effective_release_class,
            Some(ReleaseClass::StatefulBreaking)
        )
    {
        ExecutorIntentRequiredRoleV1::Admin
    } else {
        ExecutorIntentRequiredRoleV1::Operator
    }
}

fn encode_payload(payload: &ExecutorIntentPayloadCbor) -> Result<Vec<u8>, ExecutorIntentError> {
    let bytes = minicbor::to_vec(payload)
        .map_err(|error| ExecutorIntentError::CborEncode(error.to_string()))?;
    if bytes.len() > MAX_EXECUTOR_INTENT_PAYLOAD_BYTES {
        return Err(ExecutorIntentError::PayloadOversized);
    }
    Ok(bytes)
}

fn decode_canonical_payload(
    bytes: &[u8],
) -> Result<ExecutorIntentPayloadCbor, ExecutorIntentError> {
    if bytes.is_empty() || bytes.len() > MAX_EXECUTOR_INTENT_PAYLOAD_BYTES {
        return Err(ExecutorIntentError::PayloadOversized);
    }
    let payload: ExecutorIntentPayloadCbor = minicbor::decode(bytes)
        .map_err(|error| ExecutorIntentError::CborDecode(error.to_string()))?;
    if encode_payload(&payload)? != bytes {
        return Err(ExecutorIntentError::NonCanonicalPayload);
    }
    Ok(payload)
}

fn decode_token(token: &str) -> Result<(Vec<u8>, Signature), ExecutorIntentError> {
    if token.len() > MAX_EXECUTOR_INTENT_TOKEN_BYTES || !token.is_ascii() {
        return Err(ExecutorIntentError::InvalidTokenEncoding);
    }
    let mut parts = token.split('.');
    let payload_part = parts
        .next()
        .ok_or(ExecutorIntentError::InvalidTokenEncoding)?;
    let signature_part = parts
        .next()
        .ok_or(ExecutorIntentError::InvalidTokenEncoding)?;
    if payload_part.is_empty() || signature_part.is_empty() || parts.next().is_some() {
        return Err(ExecutorIntentError::InvalidTokenEncoding);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_part)
        .map_err(ExecutorIntentError::Base64)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(ExecutorIntentError::Base64)?;
    if URL_SAFE_NO_PAD.encode(&payload) != payload_part
        || URL_SAFE_NO_PAD.encode(&signature_bytes) != signature_part
    {
        return Err(ExecutorIntentError::NonCanonicalTokenEncoding);
    }
    let signature =
        Signature::from_slice(&signature_bytes).map_err(ExecutorIntentError::InvalidSignature)?;
    Ok((payload, signature))
}

fn validate_key_lifecycle(
    key: &ExecutorIntentVerificationKeyV1,
    payload: &ExecutorIntentPayloadCbor,
    now_ms: i64,
) -> Result<(), ExecutorIntentError> {
    if key.revoked_at_ms.is_some_and(|value| value <= now_ms) {
        return Err(ExecutorIntentError::KeyRevoked);
    }
    if payload.issued_at_ms < key.active_from_ms
        || key
            .signing_retired_at_ms
            .is_some_and(|value| payload.issued_at_ms >= value)
    {
        return Err(ExecutorIntentError::KeyInactiveAtIssue);
    }
    if key.verify_until_ms.is_some_and(|value| now_ms >= value) {
        return Err(ExecutorIntentError::KeyRetired);
    }
    Ok(())
}

fn intent_digest(payload: &[u8], signature: &Signature) -> EvidenceDigest {
    EvidenceDigest::sha256(
        [
            EXECUTOR_INTENT_SIGNATURE_DOMAIN,
            payload,
            signature.to_bytes().as_slice(),
        ]
        .concat(),
    )
}

fn signature_input(payload: &[u8]) -> Vec<u8> {
    [EXECUTOR_INTENT_SIGNATURE_DOMAIN, payload].concat()
}

fn validate_service_identity(value: &str) -> Result<(), ExecutorIntentError> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        Err(ExecutorIntentError::InvalidServiceIdentity)
    } else {
        Ok(())
    }
}

fn validate_key_id(value: &str) -> Result<(), ExecutorIntentError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(ExecutorIntentError::InvalidKeyId)
    } else {
        Ok(())
    }
}

fn validate_epoch(value: u64) -> Result<(), ExecutorIntentError> {
    if value == 0 || value > i64::MAX.unsigned_abs() {
        Err(ExecutorIntentError::InvalidKeyEpoch)
    } else {
        Ok(())
    }
}

fn valid_migration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MIGRATION_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn parse_digest(value: &str) -> Result<EvidenceDigest, ExecutorIntentError> {
    EvidenceDigest::from_str(value).map_err(|_| ExecutorIntentError::InvalidDigest)
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutorIntentError {
    #[error("executor-intent service identity is invalid")]
    InvalidServiceIdentity,
    #[error("executor-intent key ID is invalid")]
    InvalidKeyId,
    #[error("executor-intent key epoch is outside the durable range")]
    InvalidKeyEpoch,
    #[error("executor-intent key lifecycle is invalid")]
    InvalidKeyLifecycle,
    #[error("executor-intent keyring must not be empty")]
    EmptyKeyring,
    #[error("executor-intent keyring contains a duplicate key ID")]
    DuplicateKey,
    #[error("executor-intent lifetime is invalid or exceeds five minutes")]
    InvalidLifetime,
    #[error("executor-intent identity must not be nil")]
    InvalidIdentity,
    #[error("executor-intent operation, release class or target is inconsistent")]
    OperationMismatch,
    #[error("executor-intent source authority is missing or inconsistent")]
    InvalidSourceAuthority,
    #[error("executor-intent migration identifier is invalid")]
    InvalidMigrationId,
    #[error("executor-intent rollback target is invalid")]
    InvalidRollbackTarget,
    #[error("executor-intent project is invalid")]
    InvalidProject,
    #[error("executor-intent commit is invalid")]
    InvalidCommit,
    #[error("executor-intent contains an invalid evidence digest")]
    InvalidDigest,
    #[error("executor-intent consequences do not match the resolved operation")]
    InvalidConsequences,
    #[error("executor-intent minimum role does not match the resolved operation")]
    InvalidRequiredRole,
    #[error("expected executor-intent binding is invalid")]
    InvalidExpectedBinding,
    #[error("executor-intent CBOR encoding failed: {0}")]
    CborEncode(String),
    #[error("executor-intent CBOR decoding failed: {0}")]
    CborDecode(String),
    #[error("executor-intent payload is empty or oversized")]
    PayloadOversized,
    #[error("executor-intent payload is not deterministic canonical CBOR")]
    NonCanonicalPayload,
    #[error("executor-intent compact token encoding is invalid")]
    InvalidTokenEncoding,
    #[error("executor-intent compact token encoding is not canonical")]
    NonCanonicalTokenEncoding,
    #[error("executor-intent base64url decoding failed: {0}")]
    Base64(base64::DecodeError),
    #[error("executor-intent signature has an invalid length: {0}")]
    InvalidSignature(ed25519_dalek::SignatureError),
    #[error("executor-intent signature verification failed: {0}")]
    SignatureVerification(ed25519_dalek::SignatureError),
    #[error("unsupported executor-intent schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("executor-intent verification time is invalid")]
    InvalidVerificationTime,
    #[error("unknown executor-intent key {0}")]
    UnknownKey(String),
    #[error("executor-intent key epoch was rolled back or does not match its key")]
    KeyEpochRejected,
    #[error("executor-intent key was revoked")]
    KeyRevoked,
    #[error("executor-intent key was not active when this intent was issued")]
    KeyInactiveAtIssue,
    #[error("executor-intent verification overlap has ended")]
    KeyRetired,
    #[error("executor-intent issuer does not match policy")]
    IssuerMismatch,
    #[error("executor-intent audience does not match the authorizer")]
    AudienceMismatch,
    #[error("executor intent is not valid yet")]
    NotYetValid,
    #[error("executor intent has expired")]
    Expired,
    #[error("executor intent does not match the expected request, project, operation or policy")]
    BindingMismatch,
}
