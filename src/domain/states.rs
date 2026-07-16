use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationPhase {
    Queued,
    SyncingSource,
    VerifyingSource,
    Testing,
    Building,
    Preflight,
    BackingUp,
    Draining,
    CutoverSnapshotting,
    Migrating,
    Deploying,
    HealthChecking,
    Soaking,
    Rollback,
    Reconciliation,
}

impl OperationPhase {
    pub const fn crosses_mutation_boundary(self) -> bool {
        matches!(
            self,
            Self::BackingUp
                | Self::Draining
                | Self::CutoverSnapshotting
                | Self::Migrating
                | Self::Deploying
                | Self::HealthChecking
                | Self::Soaking
                | Self::Rollback
                | Self::Reconciliation
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationResult {
    Running,
    Succeeded,
    Failed,
    RolledBack,
    RollbackFailed,
    Cancelled,
    Superseded,
    ManualRecoveryRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockingReason {
    None,
    DiskReserve,
    SourceDivergence,
    SourceBrokerUnavailable,
    SourceHeadSuperseded,
    SourceAttestationInvalid,
    PolicyUnavailable,
    PolicyInvalid,
    PolicyStale,
    SecurityStateInvalid,
    BackupPolicy,
    StaleTelemetry,
    ClockUnsynchronized,
    MaintenanceConflict,
    OperatorHold,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Retryability {
    Automatic,
    AfterExternalRecovery,
    OperatorRunbook,
}

impl BlockingReason {
    pub const fn retryability(self) -> Option<Retryability> {
        match self {
            Self::None => None,
            Self::SourceBrokerUnavailable | Self::SourceHeadSuperseded | Self::StaleTelemetry => {
                Some(Retryability::Automatic)
            }
            Self::PolicyUnavailable
            | Self::ClockUnsynchronized
            | Self::BackupPolicy
            | Self::DiskReserve => Some(Retryability::AfterExternalRecovery),
            Self::SourceDivergence
            | Self::SourceAttestationInvalid
            | Self::PolicyInvalid
            | Self::PolicyStale
            | Self::SecurityStateInvalid
            | Self::MaintenanceConflict
            | Self::OperatorHold => Some(Retryability::OperatorRunbook),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectCondition {
    Healthy,
    Degraded,
    Down,
    Maintenance,
    Migrating,
    Unknown,
    SignalLost,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupStatus {
    Absent,
    Pending,
    VerifiedLocal,
    VerifiedOffsite,
    Unverified,
    Corrupt,
    ProviderDegraded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackCapability {
    Unavailable,
    Eligible,
    Ineligible,
    Consumed,
    UnsafeAfterMigration,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationDelivery {
    Pending,
    Sending,
    Delivered,
    DeliveryUnknown,
    RetryScheduled,
    DeliveredPossibleDuplicate,
    PermanentlyFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationPath {
    Healthy,
    GatewayDegradedDirectAvailable,
    Unavailable,
}
