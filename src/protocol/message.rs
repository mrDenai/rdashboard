use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{
    GitCommitId, HostTelemetry, MutationStatusV1, OperationKind, ProjectId, ReleaseClass,
};

pub const CONTROL_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequestEnvelope {
    pub version: u16,
    pub request_id: Uuid,
    pub request: ControlRequestV1,
}

impl ControlRequestEnvelope {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.version != CONTROL_PROTOCOL_VERSION {
            return Err(ProtocolValidationError::UnsupportedVersion(self.version));
        }
        if self.request_id.is_nil() {
            return Err(ProtocolValidationError::NilRequestId);
        }
        self.request.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "operation", content = "parameters", rename_all = "snake_case")]
pub enum ControlRequestV1 {
    Negotiate {
        supported_versions: Vec<u16>,
    },
    ObserveHostSnapshot,
    ObserveDockerSnapshot {
        project_id: ProjectId,
    },
    ObserveSystemdUnits {
        project_id: ProjectId,
    },
    PrepareOperationIntent {
        project_id: ProjectId,
        operation_kind: OperationKind,
        target_commit: Option<GitCommitId>,
        release_class: Option<ReleaseClass>,
        idempotency_key: Uuid,
    },
    ExecuteGrantedOperation {
        intent_id: Uuid,
        attempt_id: Uuid,
        action_grant: String,
    },
    ObserveMutationStatus {
        intent_id: Uuid,
        attempt_id: Uuid,
    },
}

impl ControlRequestV1 {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        match self {
            Self::Negotiate { supported_versions } => {
                if supported_versions.is_empty() || supported_versions.len() > 8 {
                    return Err(ProtocolValidationError::InvalidVersionSet);
                }
            }
            Self::PrepareOperationIntent {
                operation_kind,
                target_commit,
                release_class,
                idempotency_key,
                ..
            } => {
                if idempotency_key.is_nil() {
                    return Err(ProtocolValidationError::NilIdempotencyKey);
                }
                if operation_kind.requires_commit() != target_commit.is_some() {
                    return Err(ProtocolValidationError::TargetCommitMismatch);
                }
                operation_kind
                    .required_phases(*release_class)
                    .map_err(|_| ProtocolValidationError::ReleaseClassMismatch)?;
            }
            Self::ExecuteGrantedOperation {
                intent_id,
                attempt_id,
                action_grant,
            } => {
                if intent_id.is_nil() || attempt_id.is_nil() {
                    return Err(ProtocolValidationError::NilOperationIdentity);
                }
                if !(32..=16_384).contains(&action_grant.len()) {
                    return Err(ProtocolValidationError::InvalidActionGrantSize);
                }
            }
            Self::ObserveMutationStatus {
                intent_id,
                attempt_id,
            } => {
                if intent_id.is_nil() || attempt_id.is_nil() {
                    return Err(ProtocolValidationError::NilOperationIdentity);
                }
            }
            Self::ObserveHostSnapshot
            | Self::ObserveDockerSnapshot { .. }
            | Self::ObserveSystemdUnits { .. } => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRequestEnvelope {
    pub version: u16,
    pub request_id: Uuid,
    pub request: RecoveryRequestV1,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "operation", content = "parameters", rename_all = "snake_case")]
pub enum RecoveryRequestV1 {
    ListVerifiedBackups {
        project_id: ProjectId,
    },
    StageRestore {
        project_id: ProjectId,
        backup_id: Uuid,
    },
    VerifyStagedRestore {
        project_id: ProjectId,
        stage_id: Uuid,
    },
    CommitStagedRestore {
        project_id: ProjectId,
        stage_id: Uuid,
        fence_epoch: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResponseEnvelope<T> {
    pub version: u16,
    pub request_id: Uuid,
    pub response: T,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "result", content = "payload", rename_all = "snake_case")]
pub enum ControlResponseV1 {
    Negotiated {
        selected_version: u16,
    },
    HostSnapshot {
        snapshot: Box<HostTelemetry>,
    },
    OperationIntentPrepared {
        signed_intent: String,
    },
    OperationAccepted {
        intent_id: Uuid,
        attempt_id: Uuid,
        replayed: bool,
    },
    MutationStatus {
        status: Box<MutationStatusV1>,
    },
    Rejected {
        code: ControlRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlRejectionCodeV1 {
    UnsupportedProtocolVersion,
    InvalidRequest,
    ProjectObservationNotConfigured,
    MutationAuthorityUnavailable,
    MutationRejected,
    MutationConflict,
    InternalFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolValidationError {
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("request ID must not be nil")]
    NilRequestId,
    #[error("version negotiation must contain 1-8 versions")]
    InvalidVersionSet,
    #[error("idempotency key must not be nil")]
    NilIdempotencyKey,
    #[error("target commit presence does not match the operation kind")]
    TargetCommitMismatch,
    #[error("release class presence does not match the operation kind")]
    ReleaseClassMismatch,
    #[error("intent and attempt IDs must not be nil")]
    NilOperationIdentity,
    #[error("action grant must contain 32-16384 bytes")]
    InvalidActionGrantSize,
}
