mod control;
mod integrations;
mod metrics;
mod notifications;
mod security;

pub use control::*;
pub use integrations::*;
pub use metrics::*;
pub use notifications::*;
pub use security::*;

use std::sync::{Mutex, MutexGuard};

use rusqlite::Connection;

pub const MINIMUM_SAFE_SQLITE_VERSION_NUMBER: i32 = 3_051_003;

fn verify_sqlite_version() -> Result<(), StoreError> {
    let actual = rusqlite::version_number();
    if actual < MINIMUM_SAFE_SQLITE_VERSION_NUMBER {
        return Err(StoreError::UnsafeSqliteVersion {
            actual: rusqlite::version().to_owned(),
            minimum_number: MINIMUM_SAFE_SQLITE_VERSION_NUMBER,
        });
    }
    Ok(())
}

fn lock_connection(
    connection: &Mutex<Connection>,
) -> Result<MutexGuard<'_, Connection>, StoreError> {
    connection.lock().map_err(|_| StoreError::LockPoisoned)
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database mutex was poisoned")]
    LockPoisoned,
    #[error("persisted sequence is outside the supported range")]
    SequenceRange,
    #[error("metric {field} is outside SQLite INTEGER range")]
    MetricRange { field: &'static str },
    #[error("metric observation timestamp must be non-negative")]
    InvalidMetricTimestamp,
    #[error("persisted metric field {field} is corrupt")]
    CorruptMetric { field: &'static str },
    #[error("persisted {kind} rollup {key} does not match its database key")]
    CorruptRollup { kind: &'static str, key: String },
    #[error("metrics schema version {actual} is unsupported; this build supports {supported}")]
    UnsupportedMetricsSchemaVersion { actual: i64, supported: i64 },
    #[error("legacy metrics migration expected {expected} projects but migrated {migrated}")]
    LegacyMetricsMigrationMismatch { expected: i64, migrated: usize },
    #[error("legacy metrics contain invalid project identifier {value:?}")]
    InvalidLegacyProjectId { value: String },
    #[error("rollup cutoff {rollup} must not be newer than raw cutoff {raw}")]
    InvalidRetentionCutoffs { raw: i64, rollup: i64 },
    #[error("event sequence exhausted")]
    SequenceExhausted,
    #[error("observation operation {0} was not running")]
    ObservationNotRunning(uuid::Uuid),
    #[error("invalid controller input: {0}")]
    InvalidControllerInput(&'static str),
    #[error("tab lease was revoked or does not match the current generation")]
    LeaseRevoked,
    #[error("tab lease has expired")]
    LeaseExpired,
    #[error("action grant has expired")]
    GrantExpired,
    #[error("action grant is not bound to this actor, operation, or target")]
    GrantBindingMismatch,
    #[error("action grant nonce was already consumed by another admission")]
    GrantReplay,
    #[error("request {0} failed previously and requires an explicit retry grant")]
    RetryGrantRequired(uuid::Uuid),
    #[error("request {0} requires the audited recovery path and cannot be retried")]
    RecoveryRequired(uuid::Uuid),
    #[error("automation admission was not authorized by exact policy and source evidence")]
    AutomationAdmissionRejected,
    #[error("deploy admission requires a current source-broker attestation")]
    SourceAdmissionRequired,
    #[error("source admission sequence is older than the latest request generation")]
    StaleSourceSequence,
    #[error("transport delivery identity was reused with different content")]
    DeliveryConflict,
    #[error("operation attempt {0} does not exist")]
    OperationNotFound(uuid::Uuid),
    #[error("operation transition is not permitted by the installed execution plan")]
    TransitionRejected,
    #[error("a committed executor receipt does not match the current attempt and phase")]
    ReceiptMismatch,
    #[error("executor receipt digest does not match its canonical payload")]
    ReceiptDigestMismatch,
    #[error("executor artifact evidence conflicts with persisted field {0}")]
    ArtifactEvidenceConflict(&'static str),
    #[error("operation cannot be cancelled after its mutation boundary")]
    CancellationAfterMutation,
    #[error("operation failure after the mutation boundary must enter reconciliation")]
    FailureAfterMutationRequiresReconcile,
    #[error("persisted controller record is corrupt: {0}")]
    CorruptController(&'static str),
    #[error("control schema version {actual} is unsupported; this build supports {supported}")]
    UnsupportedControlSchemaVersion { actual: i64, supported: i64 },
    #[error("control schema is missing required table or column {0}")]
    CorruptControlSchema(&'static str),
    #[error("persisted security journal is corrupt: {0}")]
    CorruptSecurityJournal(&'static str),
    #[error("security schema version {actual} is unsupported; this build supports {supported}")]
    UnsupportedSecuritySchemaVersion { actual: i64, supported: i64 },
    #[error("security schema is missing required table or column {0}")]
    CorruptSecuritySchema(&'static str),
    #[error("security schema migration requires explicit disk-reservation reconciliation")]
    SecurityDiskMigrationRequiresReconciliation,
    #[error("security schema migration requires explicit phase-receipt reconciliation")]
    SecurityReceiptMigrationRequiresReconciliation,
    #[error("security schema migration requires explicit unresolved-phase reconciliation")]
    SecurityPhaseMigrationRequiresReconciliation,
    #[error("executor security recovery must complete before accepting work")]
    SecurityRecoveryRequired,
    #[error("executor authorization was already consumed by another attempt")]
    ExecutorAuthorizationReplay,
    #[error("executor action grant was already consumed by another attempt or intent")]
    ExecutorActionGrantReplay,
    #[error("executor action grant expired before its first consumption")]
    ExecutorActionGrantExpired,
    #[error("executor action grant contains a value outside the security journal range")]
    ExecutorActionGrantRange,
    #[error("executor intent identity conflicts with an existing prepared intent")]
    ExecutorIntentConflict,
    #[error("executor intent expired before it could be durably prepared")]
    ExecutorIntentExpired,
    #[error("executor intent cannot be consumed before its durable preparation window")]
    ExecutorIntentNotCurrent,
    #[error("executor intent contains a value outside the security journal range")]
    ExecutorIntentRange,
    #[error("prepared executor intent does not exist in the root security journal")]
    ExecutorIntentMissing,
    #[error("action grant does not match the persisted executor intent")]
    ExecutorIntentGrantBinding,
    #[error("action grant role is below the executor intent minimum role")]
    ExecutorIntentRole,
    #[error("prepared executor intent was already consumed by another attempt or grant")]
    ExecutorIntentConsumed,
    #[error("executor authorization is not bound to this project or operation digest")]
    ExecutorAuthorizationBinding,
    #[error("operation attempt is not authorized by the executor security journal")]
    ExecutorAttemptUnauthorized,
    #[error("another uncommitted phase exists for this attempt")]
    ExecutorPhaseConflict,
    #[error("executor phase is not the next permitted security-journal step")]
    ExecutorPhaseOrder,
    #[error("executor phase journal is not in the required state")]
    ExecutorPhaseState,
    #[error("authorized phase specification is missing from the durable security journal")]
    AuthorizedPhaseSpecMissing,
    #[error("authorized phase specification is noncanonical or structurally invalid")]
    AuthorizedPhaseSpecInvalid,
    #[error("authorized phase specification does not match its intent, phase or evidence")]
    AuthorizedPhaseSpecBinding,
    #[error("observed phase artifacts do not match the authorized phase specification")]
    AuthorizedPhaseArtifactMismatch,
    #[error("a different authorized phase specification is already bound to this phase")]
    AuthorizedPhaseSpecConflict,
    #[error("authorized phase prerequisites expired before the privileged effect")]
    PhaseAuthorityExpired,
    #[error("stateful-breaking mutation grant was already consumed by another phase")]
    MutationGrantReplay,
    #[error("project bootstrap was already reserved or completed by another attempt")]
    BootstrapAlreadyClaimed,
    #[error("project bootstrap effect has no matching durable permit reservation")]
    BootstrapPermitMissing,
    #[error("verified backup chain is missing from the durable security journal")]
    VerifiedBackupChainMissing,
    #[error("verified backup chain is noncanonical or structurally invalid")]
    VerifiedBackupChainInvalid,
    #[error("verified backup chain does not match its phase specification or artifacts")]
    VerifiedBackupChainBinding,
    #[error("a different verified backup chain is already bound to this phase")]
    VerifiedBackupChainConflict,
    #[error("executor observation does not match the persisted phase intent")]
    ExecutorObservationMismatch,
    #[error("source live-gate proof conflicts with the persisted attempt and phase")]
    SourceGateProofMismatch,
    #[error("source sequence or attestation regressed below the executor trust high-water mark")]
    SourceTrustRollback,
    #[error("execution resource is held by another attempt")]
    ExecutionResourceBusy,
    #[error("execution resource release does not match its recorded owner")]
    ExecutionResourceOwnership,
    #[error("executor authorization does not contain a disk reservation claim")]
    DiskReservationAuthorizationMissing,
    #[error("executor disk reservation claim is invalid or conflicts with persisted evidence")]
    DiskReservationAuthorizationInvalid,
    #[error("a fresh trusted disk-space observation is required")]
    DiskObservationUnavailable,
    #[error("disk-space observation is stale, future-dated, or for another filesystem")]
    DiskObservationInvalid,
    #[error("disk reservation bytes are outside the durable journal range")]
    DiskReservationRange,
    #[error(
        "active disk reservations require {required} bytes but only {available} bytes are available"
    )]
    DiskReservationCapacity { required: u64, available: u64 },
    #[error("write fence is held or unresolved for this project")]
    FenceConflict,
    #[error(
        "write fence acquisition requires the project deploy lock and committed backup and drain phases"
    )]
    FencePhaseInvalid,
    #[error("write fence observation does not match its journal owner, epoch, or token")]
    FenceOwnershipMismatch,
    #[error("write fence cannot be released without a committed release-safe receipt")]
    FenceReleaseUnsafe,
    #[error(transparent)]
    OperationContract(#[from] crate::domain::OperationContractError),
    #[error(transparent)]
    OperationState(#[from] crate::domain::OperationStateError),
    #[error(transparent)]
    ArtifactContract(#[from] crate::domain::ArtifactContractError),
    #[error("bundled SQLite {actual} is below safe version number {minimum_number}")]
    UnsafeSqliteVersion { actual: String, minimum_number: i32 },
}
