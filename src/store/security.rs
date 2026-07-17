use std::{
    collections::BTreeSet,
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex},
};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use uuid::Uuid;

use crate::authorization::{ActionGrantRoleV1, AuthenticatedActionGrantV1, VerifiedActionGrantV1};
use crate::backup::{BackupSnapshotKindV1, VerifiedBackupChainV1};
pub use crate::domain::ExecutorPhaseBranch;
use crate::domain::{
    AuthorizedDiskReservation, DISK_OBSERVATION_MAX_AGE_MS, DiskAvailabilityObservation,
    EvidenceDigest, FenceAcquisitionReceiptV1, GitCommitId, MutationExecutionStateV1,
    MutationStatusV1, OperationKind, OperationPhase, PhaseArtifacts, PhaseReceipt, ProjectId,
    ReleaseClass,
};
use crate::executor_intent::{ExecutorIntentClaimsV1, SignedExecutorIntentV1};
use crate::phase6::{AuthorizedPhaseSpecV1, RuntimeReleaseStateV1};

use super::{StoreError, lock_connection, verify_sqlite_version};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorAuthorization {
    pub authorization_id: Uuid,
    pub digest: EvidenceDigest,
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub expires_at_ms: i64,
    pub disk_reservation: Option<AuthorizedDiskReservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionGrantConsumptionV1 {
    Consumed,
    AlreadyConsumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorIntentPersistenceV1 {
    Prepared,
    AlreadyPrepared,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedMutationV1 {
    pub intent_id: Uuid,
    pub intent_digest: EvidenceDigest,
    pub signed_intent: String,
    pub attempt_id: Uuid,
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
    pub intent_expires_at_ms: i64,
    pub actor_id: Uuid,
    pub action_grant_role: ActionGrantRoleV1,
    pub action_grant_nonce: Uuid,
    pub action_grant_digest: EvidenceDigest,
    pub lease_id: Uuid,
    pub lease_generation: u64,
    pub grant_expires_at_ms: i64,
    pub accepted_at_ms: i64,
}

struct PreparedIntentGrantBinding {
    intent_digest: String,
    request_id: String,
    installed_policy_digest: String,
    minimum_role: String,
    not_before_ms: i64,
    expires_at_ms: i64,
    prepared_at_ms: i64,
    state: String,
    attempt_id: Option<String>,
    action_grant_nonce: Option<String>,
    action_grant_digest: Option<String>,
}

struct PreparedIntentGrantConsumption<'a> {
    grant: &'a AuthenticatedActionGrantV1,
    intent_id: String,
    attempt_id: String,
    request_id: String,
    nonce: String,
    consumed_at_ms: i64,
    lease_generation: i64,
    key_epoch: i64,
}

struct AcceptedMutationStorageRow {
    intent_id: String,
    intent_digest: String,
    compact_token: String,
    attempt_id: Option<String>,
    request_id: String,
    project_id: String,
    operation_kind: String,
    target_commit: Option<String>,
    proposed_release_class: Option<String>,
    effective_release_class: Option<String>,
    installed_policy_digest: String,
    source_attestation_digest: Option<String>,
    source_sequence: Option<i64>,
    release_bundle_digest: Option<String>,
    build_attestation_digest: Option<String>,
    migration_id: Option<String>,
    previous_release_bundle_digest: Option<String>,
    intent_expires_at_ms: i64,
    consumed_at_ms: Option<i64>,
    action_grant_nonce: Option<String>,
    intent_action_grant_digest: Option<String>,
    grant_nonce: Option<String>,
    grant_digest: Option<String>,
    grant_attempt_id: Option<String>,
    grant_intent_id: Option<String>,
    grant_intent_digest: Option<String>,
    grant_request_id: Option<String>,
    grant_installed_policy_digest: Option<String>,
    actor_id: Option<String>,
    role: Option<String>,
    lease_id: Option<String>,
    lease_generation: Option<i64>,
    grant_expires_at_ms: Option<i64>,
}

struct AcceptedMutationGrantBinding {
    attempt_id: Uuid,
    actor_id: Uuid,
    role: ActionGrantRoleV1,
    nonce: Uuid,
    digest: EvidenceDigest,
    lease_id: Uuid,
    lease_generation: u64,
    expires_at_ms: i64,
    accepted_at_ms: i64,
}

struct AcceptedMutationShape<'a> {
    operation_kind: OperationKind,
    target_commit: &'a Option<GitCommitId>,
    proposed_release_class: Option<ReleaseClass>,
    effective_release_class: Option<ReleaseClass>,
    source_attestation_digest: &'a Option<EvidenceDigest>,
    source_sequence: Option<u64>,
    release_bundle_digest: &'a Option<EvidenceDigest>,
    build_attestation_digest: &'a Option<EvidenceDigest>,
    migration_id: &'a Option<String>,
    previous_release_bundle_digest: &'a Option<EvidenceDigest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseJournalStatus {
    IntentPersisted,
    Observed,
    Verified,
    Committed,
    NeedsReconcile,
}

impl PhaseJournalStatus {
    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "intent_persisted" => Ok(Self::IntentPersisted),
            "observed" => Ok(Self::Observed),
            "verified" => Ok(Self::Verified),
            "committed" => Ok(Self::Committed),
            "needs_reconcile" => Ok(Self::NeedsReconcile),
            _ => Err(StoreError::CorruptSecurityJournal("phase status")),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::IntentPersisted => "intent_persisted",
            Self::Observed => "observed",
            Self::Verified => "verified",
            Self::Committed => "committed",
            Self::NeedsReconcile => "needs_reconcile",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseJournalEntry {
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub phase: OperationPhase,
    pub intent_digest: EvidenceDigest,
    pub observation_digest: Option<EvidenceDigest>,
    pub artifacts: PhaseArtifacts,
    pub status: PhaseJournalStatus,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedPhaseSpecRecord {
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub intent_digest: EvidenceDigest,
    pub spec_digest: EvidenceDigest,
    pub document_digest: EvidenceDigest,
    pub canonical_json: Vec<u8>,
    pub persisted_at_ms: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct AuthorizedPhaseSpecBinding<'a> {
    pub attempt_id: Uuid,
    pub project_id: &'a ProjectId,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub intent_digest: &'a EvidenceDigest,
    pub spec_digest: &'a EvidenceDigest,
    pub canonical_json: &'a [u8],
    pub persisted_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedPhasePermitV1 {
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub intent_digest: EvidenceDigest,
    pub spec_digest: EvidenceDigest,
    pub document_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBackupChainRecord {
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub authorized_phase_spec_digest: EvidenceDigest,
    pub chain_digest: EvidenceDigest,
    pub document_digest: EvidenceDigest,
    pub canonical_json: Vec<u8>,
    pub persisted_at_ms: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedBackupChainBinding<'a> {
    pub attempt_id: Uuid,
    pub project_id: &'a ProjectId,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub authorized_phase_spec_digest: &'a EvidenceDigest,
    pub chain: &'a VerifiedBackupChainV1,
    pub persisted_at_ms: i64,
}

struct PreparedVerifiedBackupChain {
    storage_phase: &'static str,
    canonical_json: Vec<u8>,
    document_digest: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackTakeover {
    pub attempt_id: Uuid,
    pub project_id: ProjectId,
    pub forward_phase: OperationPhase,
    pub forward_status: PhaseJournalStatus,
    pub forward_intent_digest: EvidenceDigest,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceGateProofRecord {
    pub attempt_id: Uuid,
    pub phase: OperationPhase,
    pub proof_digest: EvidenceDigest,
    pub project_id: ProjectId,
    pub source_sequence: u64,
    pub attestation_digest: EvidenceDigest,
    pub checked_at_ms: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutorPhasePlan<'a> {
    ordered_phases: &'a [OperationPhase],
    recovery_rollback_allowed: bool,
}

impl ExecutorPhaseBranch {
    pub fn storage_key(self, phase: OperationPhase) -> Result<&'static str, StoreError> {
        match (self, phase) {
            (Self::Primary, phase) => Ok(phase_name(phase)),
            (Self::RollbackRecovery, OperationPhase::Rollback) => Ok("rollback_recovery"),
            (Self::RollbackRecovery, OperationPhase::HealthChecking) => {
                Ok("rollback_recovery_health_checking")
            }
            (Self::RollbackRecovery, OperationPhase::Soaking) => Ok("rollback_recovery_soaking"),
            (Self::RollbackRecovery, _) => Err(StoreError::ExecutorPhaseOrder),
        }
    }
}

impl<'a> ExecutorPhasePlan<'a> {
    pub const fn new(
        ordered_phases: &'a [OperationPhase],
        recovery_rollback_allowed: bool,
    ) -> Self {
        Self {
            ordered_phases,
            recovery_rollback_allowed,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PhaseIntentRequest<'a> {
    pub attempt_id: Uuid,
    pub project_id: &'a ProjectId,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub phase_plan: ExecutorPhasePlan<'a>,
    pub intent_digest: &'a EvidenceDigest,
    pub authorization_digest: &'a EvidenceDigest,
    pub started_at_ms: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct PhaseObservationRequest<'a> {
    pub attempt_id: Uuid,
    pub phase: OperationPhase,
    pub branch: ExecutorPhaseBranch,
    pub observed_intent_digest: &'a EvidenceDigest,
    pub observation_digest: &'a EvidenceDigest,
    pub artifacts: &'a PhaseArtifacts,
    pub observed_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationAcceptance {
    Accepted,
    NeedsReconcile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionResource {
    GlobalBuild,
    GlobalHeavyIo,
    GlobalLocalRegistry,
    ProjectDeploy(ProjectId),
}

impl ExecutionResource {
    fn key(&self) -> String {
        match self {
            Self::GlobalBuild => "global:build".to_owned(),
            Self::GlobalHeavyIo => "global:heavy_io".to_owned(),
            Self::GlobalLocalRegistry => "global:local_registry:5555".to_owned(),
            Self::ProjectDeploy(project_id) => format!("project:deploy:{project_id}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FenceJournalState {
    AcquireIntent,
    Held,
    ReleaseIntent,
    Released,
    NeedsReconcile,
}

impl FenceJournalState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AcquireIntent => "acquire_intent",
            Self::Held => "held",
            Self::ReleaseIntent => "release_intent",
            Self::Released => "released",
            Self::NeedsReconcile => "needs_reconcile",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "acquire_intent" => Ok(Self::AcquireIntent),
            "held" => Ok(Self::Held),
            "release_intent" => Ok(Self::ReleaseIntent),
            "released" => Ok(Self::Released),
            "needs_reconcile" => Ok(Self::NeedsReconcile),
            _ => Err(StoreError::CorruptSecurityJournal("fence state")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FenceLease {
    pub journal_id: i64,
    pub project_id: ProjectId,
    pub attempt_id: Uuid,
    pub epoch: u64,
    pub token: Uuid,
    pub created_at_ms: i64,
    pub state: FenceJournalState,
    pub release_safe_receipt_digest: Option<EvidenceDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainIdentityLease {
    pub journal_id: i64,
    pub project_id: ProjectId,
    pub attempt_id: Uuid,
    pub epoch: u64,
    pub token: Uuid,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupBoundaryLease {
    pub journal_id: i64,
    pub project_id: ProjectId,
    pub attempt_id: Uuid,
    pub epoch: u64,
    pub token: Uuid,
    pub created_at_ms: i64,
}

#[derive(Serialize)]
struct FenceLeaseDigestPayload<'a> {
    purpose: &'static str,
    journal_id: i64,
    project_id: &'a ProjectId,
    attempt_id: Uuid,
    epoch: u64,
    token: Uuid,
    created_at_ms: i64,
}

impl FenceLease {
    fn lease_digest(&self) -> Result<EvidenceDigest, StoreError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &FenceLeaseDigestPayload {
                purpose: "rdashboard.fence-lease.v1",
                journal_id: self.journal_id,
                project_id: &self.project_id,
                attempt_id: self.attempt_id,
                epoch: self.epoch,
                token: self.token,
                created_at_ms: self.created_at_ms,
            },
        )?))
    }
}

fn fence_receipt_from_lease(lease: &FenceLease) -> Result<FenceAcquisitionReceiptV1, StoreError> {
    FenceAcquisitionReceiptV1::new(
        lease.project_id.clone(),
        lease.attempt_id,
        lease.epoch,
        lease.lease_digest()?,
        lease.created_at_ms,
    )
    .map_err(|_| StoreError::CorruptSecurityJournal("fence acquisition receipt"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FenceObservation {
    Released,
    Held {
        attempt_id: Uuid,
        epoch: u64,
        token: Uuid,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FenceProjection {
    Held,
    Released,
    NeedsReconcile,
}

#[derive(Clone, Debug)]
pub struct SecurityStore {
    connection: Arc<Mutex<Connection>>,
}

const SECURITY_SCHEMA_VERSION: i64 = 14;
const PRE_CANDIDATE_BINDING_SECURITY_SCHEMA_VERSION: i64 = 13;
const PRE_BACKUP_BOUNDARY_SECURITY_SCHEMA_VERSION: i64 = 12;
const PRE_EXECUTOR_INTENT_SECURITY_SCHEMA_VERSION: i64 = 11;
const PRE_ACTION_GRANT_SECURITY_SCHEMA_VERSION: i64 = 10;
const DRAIN_IDENTITY_SECURITY_SCHEMA_VERSION: i64 = 9;
const PHASE_AUTHORITY_SECURITY_SCHEMA_VERSION: i64 = 8;
const VERIFIED_BACKUP_SECURITY_SCHEMA_VERSION: i64 = 7;
const PREVIOUS_SECURITY_SCHEMA_VERSION: i64 = 6;
const PHASE_SPEC_SECURITY_SCHEMA_VERSION: i64 = 5;
const RECEIPT_BOUND_SECURITY_SCHEMA_VERSION: i64 = 4;
const ROLLBACK_TAKEOVER_SECURITY_SCHEMA_VERSION: i64 = 3;
const LEGACY_SECURITY_SCHEMA_VERSION: i64 = 2;
const MAX_VERIFIED_BACKUP_CHAIN_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

const EXECUTOR_INTENT_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS executor_operation_intents (
        intent_id TEXT PRIMARY KEY,
        intent_digest TEXT NOT NULL UNIQUE,
        request_id TEXT NOT NULL UNIQUE,
        compact_token TEXT NOT NULL UNIQUE,
        schema_version INTEGER NOT NULL CHECK(schema_version IN (1, 2)),
        issuer TEXT NOT NULL,
        authorizer_audience TEXT NOT NULL,
        project_id TEXT NOT NULL,
        operation_kind TEXT NOT NULL CHECK(operation_kind IN (
            'deploy', 'code_rollback', 'backup_only'
        )),
        target_commit TEXT,
        proposed_release_class TEXT CHECK(proposed_release_class IN (
            'code_only_compatible', 'stateful_compatible', 'stateful_breaking', 'rollback'
        )),
        effective_release_class TEXT CHECK(effective_release_class IN (
            'code_only_compatible', 'stateful_compatible', 'stateful_breaking', 'rollback'
        )),
        installed_policy_digest TEXT NOT NULL,
        source_attestation_digest TEXT,
        source_sequence INTEGER CHECK(source_sequence > 0),
        release_bundle_digest TEXT,
        build_attestation_digest TEXT,
        migration_id TEXT,
        previous_release_bundle_digest TEXT,
        consequences_json TEXT NOT NULL,
        minimum_role TEXT NOT NULL CHECK(minimum_role IN ('operator', 'admin')),
        key_id TEXT NOT NULL,
        key_epoch INTEGER NOT NULL CHECK(key_epoch > 0),
        issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms >= 0),
        not_before_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        prepared_at_ms INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('prepared', 'consumed')),
        attempt_id TEXT UNIQUE,
        action_grant_nonce TEXT UNIQUE,
        action_grant_digest TEXT,
        consumed_at_ms INTEGER,
        CHECK((source_attestation_digest IS NULL) = (source_sequence IS NULL)),
        CHECK(not_before_ms >= issued_at_ms),
        CHECK(expires_at_ms > not_before_ms),
        CHECK(prepared_at_ms >= not_before_ms AND prepared_at_ms < expires_at_ms),
        CHECK(
            (state = 'prepared' AND attempt_id IS NULL
                AND action_grant_nonce IS NULL AND action_grant_digest IS NULL
                AND consumed_at_ms IS NULL)
            OR
            (state = 'consumed' AND attempt_id IS NOT NULL
                AND action_grant_nonce IS NOT NULL AND action_grant_digest IS NOT NULL
                AND consumed_at_ms IS NOT NULL)
        ),
        FOREIGN KEY(action_grant_nonce) REFERENCES executor_action_grants(nonce)
    ) STRICT;
    ";

const ACTION_GRANT_REPLAY_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS executor_action_grants (
        nonce TEXT PRIMARY KEY,
        grant_digest TEXT NOT NULL UNIQUE,
        attempt_id TEXT NOT NULL,
        schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        issuer TEXT NOT NULL,
        executor_audience TEXT NOT NULL,
        intent_id TEXT NOT NULL,
        intent_digest TEXT NOT NULL,
        request_id TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('operator', 'admin')),
        lease_id TEXT NOT NULL,
        lease_generation INTEGER NOT NULL CHECK(lease_generation > 0),
        key_id TEXT NOT NULL,
        key_epoch INTEGER NOT NULL CHECK(key_epoch > 0),
        installed_policy_digest TEXT NOT NULL,
        issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms >= 0),
        not_before_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        consumed_at_ms INTEGER NOT NULL,
        CHECK(not_before_ms >= issued_at_ms),
        CHECK(expires_at_ms > not_before_ms),
        CHECK(consumed_at_ms >= not_before_ms AND consumed_at_ms < expires_at_ms)
    ) STRICT;
    ";

const SOURCE_GATE_REJECTIONS_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS source_gate_rejections (
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        project_id TEXT NOT NULL,
        rejected_proof_digest TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('abort_pending', 'compensated')),
        rejected_at_ms INTEGER NOT NULL CHECK(rejected_at_ms >= 0),
        compensated_at_ms INTEGER,
        CHECK(
            (state = 'abort_pending' AND compensated_at_ms IS NULL)
            OR (state = 'compensated' AND compensated_at_ms IS NOT NULL)
        ),
        PRIMARY KEY(attempt_id, phase),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES executor_phase_journal(attempt_id, phase)
    ) STRICT;
    ";

const ROLLBACK_TAKEOVER_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS executor_rollback_takeovers (
        attempt_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        forward_phase TEXT NOT NULL CHECK(forward_phase IN (
            'deploying', 'health_checking', 'soaking'
        )),
        forward_status TEXT NOT NULL CHECK(forward_status IN (
            'intent_persisted', 'observed', 'verified', 'committed', 'needs_reconcile'
        )),
        forward_intent_digest TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        CHECK(forward_status = 'committed' OR forward_phase IN ('health_checking', 'soaking')),
        FOREIGN KEY(attempt_id, forward_phase)
            REFERENCES executor_phase_journal(attempt_id, phase)
    ) STRICT;
    ";

const ACTIVE_DISK_RESERVATIONS_SCHEMA_SQL: &str = "
    CREATE TABLE active_disk_reservations (
        attempt_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL UNIQUE,
        required_bytes INTEGER NOT NULL CHECK(required_bytes > 0),
        emergency_reserve_bytes INTEGER NOT NULL
            CHECK(emergency_reserve_bytes > 0 AND emergency_reserve_bytes < required_bytes),
        available_bytes INTEGER NOT NULL CHECK(available_bytes >= required_bytes),
        filesystem_identity TEXT NOT NULL,
        reservation_digest TEXT NOT NULL,
        observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
        acquired_at_ms INTEGER NOT NULL,
        FOREIGN KEY(attempt_id) REFERENCES executor_authorizations(attempt_id)
    ) STRICT;
    ";

const AUTHORIZED_PHASE_SPECS_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS authorized_phase_specs (
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        project_id TEXT NOT NULL,
        intent_digest TEXT NOT NULL,
        spec_digest TEXT NOT NULL,
        document_digest TEXT NOT NULL,
        canonical_json BLOB NOT NULL,
        persisted_at_ms INTEGER NOT NULL CHECK(persisted_at_ms >= 0),
        PRIMARY KEY(attempt_id, phase),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES executor_phase_journal(attempt_id, phase)
    ) STRICT;
    ";

const VERIFIED_BACKUP_CHAINS_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS verified_backup_chains (
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        project_id TEXT NOT NULL,
        authorized_phase_spec_digest TEXT NOT NULL,
        chain_digest TEXT NOT NULL,
        document_digest TEXT NOT NULL,
        canonical_json BLOB NOT NULL,
        persisted_at_ms INTEGER NOT NULL CHECK(persisted_at_ms >= 0),
        PRIMARY KEY(attempt_id, phase),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES authorized_phase_specs(attempt_id, phase)
    ) STRICT;
    ";

const PHASE_AUTHORITY_LEDGER_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS consumed_mutation_grants (
        grant_id TEXT PRIMARY KEY,
        grant_digest TEXT NOT NULL UNIQUE,
        attempt_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        spec_digest TEXT NOT NULL,
        consumed_at_ms INTEGER NOT NULL CHECK(consumed_at_ms >= 0),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES authorized_phase_specs(attempt_id, phase)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS project_bootstrap_ledger (
        project_id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL CHECK(phase = 'deploying'),
        spec_digest TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('reserved', 'committed')),
        receipt_digest TEXT,
        updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
        CHECK(
            (state = 'reserved' AND receipt_digest IS NULL)
            OR (state = 'committed' AND receipt_digest IS NOT NULL)
        ),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES authorized_phase_specs(attempt_id, phase)
    ) STRICT;
    ";

const DRAIN_IDENTITY_JOURNAL_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS drain_identity_journal (
        journal_id INTEGER PRIMARY KEY AUTOINCREMENT,
        epoch INTEGER NOT NULL UNIQUE CHECK(epoch > 0),
        project_id TEXT NOT NULL,
        attempt_id TEXT NOT NULL UNIQUE,
        token TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('reserved', 'promoted')),
        created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
        updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
        FOREIGN KEY(attempt_id) REFERENCES executor_authorizations(attempt_id)
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS drain_identity_active_project
        ON drain_identity_journal(project_id)
        WHERE state = 'reserved';
    CREATE INDEX IF NOT EXISTS drain_identity_epoch_history
        ON drain_identity_journal(epoch, journal_id);
    ";

const BACKUP_BOUNDARY_JOURNAL_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS backup_boundary_journal (
        journal_id INTEGER PRIMARY KEY AUTOINCREMENT,
        epoch INTEGER NOT NULL UNIQUE CHECK(epoch > 0),
        project_id TEXT NOT NULL,
        attempt_id TEXT NOT NULL UNIQUE,
        token TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('reserved', 'released')),
        created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
        updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
        FOREIGN KEY(attempt_id) REFERENCES executor_authorizations(attempt_id)
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS backup_boundary_active_project
        ON backup_boundary_journal(project_id)
        WHERE state = 'reserved';
    CREATE INDEX IF NOT EXISTS backup_boundary_epoch_history
        ON backup_boundary_journal(epoch, journal_id);
    ";

const SECURITY_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS security_meta (
        key TEXT PRIMARY KEY,
        integer_value INTEGER NOT NULL
    ) STRICT;
    INSERT OR IGNORE INTO security_meta(key, integer_value)
        VALUES ('fence_epoch', 0);

    CREATE TABLE IF NOT EXISTS executor_authorizations (
        authorization_id TEXT PRIMARY KEY,
        digest TEXT NOT NULL,
        attempt_id TEXT NOT NULL UNIQUE,
        project_id TEXT NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        consumed_at_ms INTEGER NOT NULL,
        disk_reservation_json TEXT
    ) STRICT;

    CREATE TABLE IF NOT EXISTS executor_action_grants (
        nonce TEXT PRIMARY KEY,
        grant_digest TEXT NOT NULL UNIQUE,
        attempt_id TEXT NOT NULL,
        schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        issuer TEXT NOT NULL,
        executor_audience TEXT NOT NULL,
        intent_id TEXT NOT NULL,
        intent_digest TEXT NOT NULL,
        request_id TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('operator', 'admin')),
        lease_id TEXT NOT NULL,
        lease_generation INTEGER NOT NULL CHECK(lease_generation > 0),
        key_id TEXT NOT NULL,
        key_epoch INTEGER NOT NULL CHECK(key_epoch > 0),
        installed_policy_digest TEXT NOT NULL,
        issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms >= 0),
        not_before_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        consumed_at_ms INTEGER NOT NULL,
        CHECK(not_before_ms >= issued_at_ms),
        CHECK(expires_at_ms > not_before_ms),
        CHECK(consumed_at_ms >= not_before_ms AND consumed_at_ms < expires_at_ms)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS executor_operation_intents (
        intent_id TEXT PRIMARY KEY,
        intent_digest TEXT NOT NULL UNIQUE,
        request_id TEXT NOT NULL UNIQUE,
        compact_token TEXT NOT NULL UNIQUE,
        schema_version INTEGER NOT NULL CHECK(schema_version IN (1, 2)),
        issuer TEXT NOT NULL,
        authorizer_audience TEXT NOT NULL,
        project_id TEXT NOT NULL,
        operation_kind TEXT NOT NULL CHECK(operation_kind IN (
            'deploy', 'code_rollback', 'backup_only'
        )),
        target_commit TEXT,
        proposed_release_class TEXT CHECK(proposed_release_class IN (
            'code_only_compatible', 'stateful_compatible', 'stateful_breaking', 'rollback'
        )),
        effective_release_class TEXT CHECK(effective_release_class IN (
            'code_only_compatible', 'stateful_compatible', 'stateful_breaking', 'rollback'
        )),
        installed_policy_digest TEXT NOT NULL,
        source_attestation_digest TEXT,
        source_sequence INTEGER CHECK(source_sequence > 0),
        release_bundle_digest TEXT,
        build_attestation_digest TEXT,
        migration_id TEXT,
        previous_release_bundle_digest TEXT,
        consequences_json TEXT NOT NULL,
        minimum_role TEXT NOT NULL CHECK(minimum_role IN ('operator', 'admin')),
        key_id TEXT NOT NULL,
        key_epoch INTEGER NOT NULL CHECK(key_epoch > 0),
        issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms >= 0),
        not_before_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        prepared_at_ms INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('prepared', 'consumed')),
        attempt_id TEXT UNIQUE,
        action_grant_nonce TEXT UNIQUE,
        action_grant_digest TEXT,
        consumed_at_ms INTEGER,
        CHECK((source_attestation_digest IS NULL) = (source_sequence IS NULL)),
        CHECK(not_before_ms >= issued_at_ms),
        CHECK(expires_at_ms > not_before_ms),
        CHECK(prepared_at_ms >= not_before_ms AND prepared_at_ms < expires_at_ms),
        CHECK(
            (state = 'prepared' AND attempt_id IS NULL
                AND action_grant_nonce IS NULL AND action_grant_digest IS NULL
                AND consumed_at_ms IS NULL)
            OR
            (state = 'consumed' AND attempt_id IS NOT NULL
                AND action_grant_nonce IS NOT NULL AND action_grant_digest IS NOT NULL
                AND consumed_at_ms IS NOT NULL)
        ),
        FOREIGN KEY(action_grant_nonce) REFERENCES executor_action_grants(nonce)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS executor_phase_journal (
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        project_id TEXT NOT NULL,
        intent_digest TEXT NOT NULL,
        observation_digest TEXT,
        artifacts_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN (
            'intent_persisted', 'observed', 'verified', 'committed', 'needs_reconcile'
        )),
        started_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        PRIMARY KEY(attempt_id, phase)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS executor_rollback_takeovers (
        attempt_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        forward_phase TEXT NOT NULL CHECK(forward_phase IN (
            'deploying', 'health_checking', 'soaking'
        )),
        forward_status TEXT NOT NULL CHECK(forward_status IN (
            'intent_persisted', 'observed', 'verified', 'committed', 'needs_reconcile'
        )),
        forward_intent_digest TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        CHECK(forward_status = 'committed' OR forward_phase IN ('health_checking', 'soaking')),
        FOREIGN KEY(attempt_id, forward_phase)
            REFERENCES executor_phase_journal(attempt_id, phase)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS executor_phase_receipts (
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        receipt_digest TEXT NOT NULL UNIQUE,
        receipt_json TEXT NOT NULL,
        committed_at_ms INTEGER NOT NULL,
        PRIMARY KEY(attempt_id, phase),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES executor_phase_journal(attempt_id, phase)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS authorized_phase_specs (
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        project_id TEXT NOT NULL,
        intent_digest TEXT NOT NULL,
        spec_digest TEXT NOT NULL,
        document_digest TEXT NOT NULL,
        canonical_json BLOB NOT NULL,
        persisted_at_ms INTEGER NOT NULL CHECK(persisted_at_ms >= 0),
        PRIMARY KEY(attempt_id, phase),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES executor_phase_journal(attempt_id, phase)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS verified_backup_chains (
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        project_id TEXT NOT NULL,
        authorized_phase_spec_digest TEXT NOT NULL,
        chain_digest TEXT NOT NULL,
        document_digest TEXT NOT NULL,
        canonical_json BLOB NOT NULL,
        persisted_at_ms INTEGER NOT NULL CHECK(persisted_at_ms >= 0),
        PRIMARY KEY(attempt_id, phase),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES authorized_phase_specs(attempt_id, phase)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS consumed_mutation_grants (
        grant_id TEXT PRIMARY KEY,
        grant_digest TEXT NOT NULL UNIQUE,
        attempt_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        spec_digest TEXT NOT NULL,
        consumed_at_ms INTEGER NOT NULL CHECK(consumed_at_ms >= 0),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES authorized_phase_specs(attempt_id, phase)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS project_bootstrap_ledger (
        project_id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL CHECK(phase = 'deploying'),
        spec_digest TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('reserved', 'committed')),
        receipt_digest TEXT,
        updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
        CHECK(
            (state = 'reserved' AND receipt_digest IS NULL)
            OR (state = 'committed' AND receipt_digest IS NOT NULL)
        ),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES authorized_phase_specs(attempt_id, phase)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS source_gate_proofs (
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        proof_digest TEXT NOT NULL,
        project_id TEXT NOT NULL,
        source_sequence INTEGER NOT NULL CHECK(source_sequence > 0),
        attestation_digest TEXT NOT NULL,
        checked_at_ms INTEGER NOT NULL,
        PRIMARY KEY(attempt_id, phase),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES executor_phase_journal(attempt_id, phase)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS source_gate_rejections (
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        project_id TEXT NOT NULL,
        rejected_proof_digest TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('abort_pending', 'compensated')),
        rejected_at_ms INTEGER NOT NULL CHECK(rejected_at_ms >= 0),
        compensated_at_ms INTEGER,
        CHECK(
            (state = 'abort_pending' AND compensated_at_ms IS NULL)
            OR (state = 'compensated' AND compensated_at_ms IS NOT NULL)
        ),
        PRIMARY KEY(attempt_id, phase),
        FOREIGN KEY(attempt_id, phase)
            REFERENCES executor_phase_journal(attempt_id, phase)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS source_trust_highwater (
        project_id TEXT PRIMARY KEY,
        source_sequence INTEGER NOT NULL CHECK(source_sequence > 0),
        attestation_digest TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS execution_resources (
        resource_key TEXT PRIMARY KEY,
        owner_attempt_id TEXT NOT NULL,
        acquired_at_ms INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS execution_resource_receipts (
        resource_key TEXT NOT NULL,
        owner_attempt_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('acquired', 'released')),
        updated_at_ms INTEGER NOT NULL,
        PRIMARY KEY(resource_key, owner_attempt_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS active_disk_reservations (
        attempt_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL UNIQUE,
        required_bytes INTEGER NOT NULL CHECK(required_bytes > 0),
        emergency_reserve_bytes INTEGER NOT NULL
            CHECK(emergency_reserve_bytes > 0 AND emergency_reserve_bytes < required_bytes),
        available_bytes INTEGER NOT NULL CHECK(available_bytes >= required_bytes),
        filesystem_identity TEXT NOT NULL,
        reservation_digest TEXT NOT NULL,
        observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
        acquired_at_ms INTEGER NOT NULL,
        FOREIGN KEY(attempt_id) REFERENCES executor_authorizations(attempt_id)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS drain_identity_journal (
        journal_id INTEGER PRIMARY KEY AUTOINCREMENT,
        epoch INTEGER NOT NULL UNIQUE CHECK(epoch > 0),
        project_id TEXT NOT NULL,
        attempt_id TEXT NOT NULL UNIQUE,
        token TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('reserved', 'promoted')),
        created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
        updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
        FOREIGN KEY(attempt_id) REFERENCES executor_authorizations(attempt_id)
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS drain_identity_active_project
        ON drain_identity_journal(project_id)
        WHERE state = 'reserved';
    CREATE INDEX IF NOT EXISTS drain_identity_epoch_history
        ON drain_identity_journal(epoch, journal_id);

    CREATE TABLE IF NOT EXISTS backup_boundary_journal (
        journal_id INTEGER PRIMARY KEY AUTOINCREMENT,
        epoch INTEGER NOT NULL UNIQUE CHECK(epoch > 0),
        project_id TEXT NOT NULL,
        attempt_id TEXT NOT NULL UNIQUE,
        token TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('reserved', 'released')),
        created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
        updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
        FOREIGN KEY(attempt_id) REFERENCES executor_authorizations(attempt_id)
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS backup_boundary_active_project
        ON backup_boundary_journal(project_id)
        WHERE state = 'reserved';
    CREATE INDEX IF NOT EXISTS backup_boundary_epoch_history
        ON backup_boundary_journal(epoch, journal_id);

    CREATE TABLE IF NOT EXISTS fence_journal (
        journal_id INTEGER PRIMARY KEY AUTOINCREMENT,
        epoch INTEGER NOT NULL CHECK(epoch > 0),
        project_id TEXT NOT NULL,
        attempt_id TEXT NOT NULL,
        token TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN (
            'acquire_intent', 'held', 'release_intent', 'released', 'needs_reconcile'
        )),
        release_safe_receipt_digest TEXT,
        created_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS fence_active_project
        ON fence_journal(project_id)
        WHERE state != 'released';
    CREATE INDEX IF NOT EXISTS fence_epoch_history
        ON fence_journal(epoch, journal_id);
    ";

impl SecurityStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        verify_sqlite_version()?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_security_schema(&mut connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn authorize_attempt(
        &self,
        authorization: &ExecutorAuthorization,
        consumed_at_ms: i64,
    ) -> Result<(), StoreError> {
        if authorization.authorization_id.is_nil() || authorization.attempt_id.is_nil() {
            return Err(StoreError::InvalidControllerInput(
                "executor authorization identities must not be nil",
            ));
        }
        if consumed_at_ms >= authorization.expires_at_ms {
            return Err(StoreError::GrantExpired);
        }
        validate_disk_reservation_authorization(authorization)?;
        let disk_reservation_json = authorization
            .disk_reservation
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        self.immediate_transaction(|transaction| {
            if let Some((digest, attempt_id, project_id, expires_at_ms, stored_reservation)) =
                transaction
                .query_row(
                    "SELECT digest, attempt_id, project_id, expires_at_ms, disk_reservation_json
                     FROM executor_authorizations
                     WHERE authorization_id = ?1",
                    [authorization.authorization_id.to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )
                .optional()?
            {
                if digest == authorization.digest.as_str()
                    && attempt_id == authorization.attempt_id.to_string()
                    && project_id == authorization.project_id.as_str()
                    && expires_at_ms == authorization.expires_at_ms
                    && stored_reservation == disk_reservation_json
                {
                    return Ok(());
                }
                return Err(StoreError::ExecutorAuthorizationReplay);
            }
            if transaction
                .query_row(
                    "SELECT 1 FROM executor_authorizations WHERE attempt_id = ?1",
                    [authorization.attempt_id.to_string()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
            {
                return Err(StoreError::ExecutorAuthorizationReplay);
            }
            transaction.execute(
                "INSERT INTO executor_authorizations(
                    authorization_id, digest, attempt_id, project_id,
                    expires_at_ms, consumed_at_ms, disk_reservation_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    authorization.authorization_id.to_string(),
                    authorization.digest.as_str(),
                    authorization.attempt_id.to_string(),
                    authorization.project_id.as_str(),
                    authorization.expires_at_ms,
                    consumed_at_ms,
                    disk_reservation_json
                ],
            )?;
            Ok(())
        })
    }

    pub fn executor_authorization(
        &self,
        attempt_id: Uuid,
    ) -> Result<Option<ExecutorAuthorization>, StoreError> {
        if attempt_id.is_nil() {
            return Err(StoreError::InvalidControllerInput(
                "executor attempt identity must not be nil",
            ));
        }
        let connection = lock_connection(&self.connection)?;
        let stored = connection
            .query_row(
                "SELECT authorization_id, digest, project_id, expires_at_ms,
                        disk_reservation_json
                 FROM executor_authorizations
                 WHERE attempt_id = ?1",
                [attempt_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?;
        stored
            .map(
                |(authorization_id, digest, project_id, expires_at_ms, disk_reservation)| {
                    let authorization = ExecutorAuthorization {
                        authorization_id: parse_uuid(
                            &authorization_id,
                            "executor authorization ID",
                        )?,
                        digest: parse_digest(&digest)?,
                        attempt_id,
                        project_id: ProjectId::from_str(&project_id).map_err(|_| {
                            StoreError::CorruptSecurityJournal("executor authorization project ID")
                        })?,
                        expires_at_ms,
                        disk_reservation: disk_reservation
                            .as_deref()
                            .map(|json| {
                                serde_json::from_str(json).map_err(|_| {
                                    StoreError::CorruptSecurityJournal(
                                        "executor authorization disk reservation",
                                    )
                                })
                            })
                            .transpose()?,
                    };
                    validate_disk_reservation_authorization(&authorization)?;
                    Ok(authorization)
                },
            )
            .transpose()
    }

    pub fn consume_verified_action_grant(
        &self,
        grant: &VerifiedActionGrantV1,
        attempt_id: Uuid,
        consumed_at_ms: i64,
    ) -> Result<ActionGrantConsumptionV1, StoreError> {
        if attempt_id.is_nil() || consumed_at_ms < 0 {
            return Err(StoreError::InvalidControllerInput(
                "action-grant consumption identity or time is invalid",
            ));
        }
        let claims = grant.claims();
        let lease_generation = i64::try_from(claims.lease_generation)
            .map_err(|_| StoreError::ExecutorActionGrantRange)?;
        let key_epoch =
            i64::try_from(claims.key_epoch).map_err(|_| StoreError::ExecutorActionGrantRange)?;
        self.immediate_transaction(|transaction| {
            let existing = transaction
                .query_row(
                    "SELECT grant_digest, attempt_id FROM executor_action_grants
                     WHERE nonce = ?1",
                    [claims.nonce.to_string()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            if let Some((stored_digest, stored_attempt)) = existing {
                if stored_digest == grant.digest().as_str()
                    && stored_attempt == attempt_id.to_string()
                {
                    return Ok(ActionGrantConsumptionV1::AlreadyConsumed);
                }
                return Err(StoreError::ExecutorActionGrantReplay);
            }
            if consumed_at_ms < claims.not_before_ms || consumed_at_ms >= claims.expires_at_ms {
                return Err(StoreError::ExecutorActionGrantExpired);
            }
            transaction.execute(
                "INSERT INTO executor_action_grants(
                    nonce, grant_digest, attempt_id, schema_version, issuer,
                    executor_audience, intent_id, intent_digest, request_id,
                    actor_id, role, lease_id, lease_generation, key_id, key_epoch,
                    installed_policy_digest, issued_at_ms, not_before_ms,
                    expires_at_ms, consumed_at_ms
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
                 )",
                params![
                    claims.nonce.to_string(),
                    grant.digest().as_str(),
                    attempt_id.to_string(),
                    i64::from(claims.schema_version),
                    &claims.issuer,
                    &claims.executor_audience,
                    claims.intent_id.to_string(),
                    claims.intent_digest.as_str(),
                    claims.request_id.to_string(),
                    claims.actor_id.to_string(),
                    claims.role.as_str(),
                    claims.lease_id.to_string(),
                    lease_generation,
                    &claims.key_id,
                    key_epoch,
                    claims.installed_policy_digest.as_str(),
                    claims.issued_at_ms,
                    claims.not_before_ms,
                    claims.expires_at_ms,
                    consumed_at_ms,
                ],
            )?;
            Ok(ActionGrantConsumptionV1::Consumed)
        })
    }

    pub fn persist_signed_executor_intent(
        &self,
        intent: &SignedExecutorIntentV1,
        prepared_at_ms: i64,
    ) -> Result<ExecutorIntentPersistenceV1, StoreError> {
        if prepared_at_ms < 0 {
            return Err(StoreError::InvalidControllerInput(
                "executor-intent preparation time is invalid",
            ));
        }
        let claims = intent.claims();
        if prepared_at_ms < claims.not_before_ms || prepared_at_ms >= claims.expires_at_ms {
            return Err(StoreError::ExecutorIntentExpired);
        }
        self.immediate_transaction(|transaction| {
            persist_signed_executor_intent(transaction, intent, claims, prepared_at_ms)
        })
    }

    pub fn replay_signed_executor_intent(
        &self,
        request_id: Uuid,
        project_id: &ProjectId,
        operation_kind: crate::domain::OperationKind,
        target_commit: Option<&crate::domain::GitCommitId>,
        proposed_release_class: Option<crate::domain::ReleaseClass>,
    ) -> Result<Option<String>, StoreError> {
        if request_id.is_nil() {
            return Err(StoreError::InvalidControllerInput(
                "executor-intent request identity is invalid",
            ));
        }
        let connection = lock_connection(&self.connection)?;
        let binding = connection
            .query_row(
                "SELECT project_id, operation_kind, target_commit,
                        proposed_release_class, compact_token
                 FROM executor_operation_intents WHERE request_id = ?1",
                [request_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((stored_project, stored_operation, stored_commit, stored_class, compact)) =
            binding
        else {
            return Ok(None);
        };
        let exact = stored_project == project_id.as_str()
            && stored_operation == operation_kind_name(operation_kind)
            && stored_commit.as_deref() == target_commit.map(crate::domain::GitCommitId::as_str)
            && stored_class.as_deref() == proposed_release_class.map(release_class_name);
        if exact {
            Ok(Some(compact))
        } else {
            Err(StoreError::ExecutorIntentConflict)
        }
    }

    pub fn accepted_mutations(&self) -> Result<Vec<AcceptedMutationV1>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        let mut statement = connection.prepare(
            "SELECT i.intent_id, i.intent_digest, i.compact_token, i.attempt_id,
                    i.request_id, i.project_id, i.operation_kind, i.target_commit,
                    i.proposed_release_class, i.effective_release_class,
                    i.installed_policy_digest, i.source_attestation_digest,
                    i.source_sequence, i.release_bundle_digest, i.build_attestation_digest,
                    i.migration_id, i.previous_release_bundle_digest,
                    i.expires_at_ms, i.consumed_at_ms, i.action_grant_nonce,
                    i.action_grant_digest, g.nonce, g.grant_digest, g.attempt_id,
                    g.intent_id, g.intent_digest, g.request_id,
                    g.installed_policy_digest, g.actor_id, g.role, g.lease_id,
                    g.lease_generation, g.expires_at_ms
             FROM executor_operation_intents AS i
             LEFT JOIN executor_action_grants AS g ON g.nonce = i.action_grant_nonce
             WHERE i.state = 'consumed'
             ORDER BY i.consumed_at_ms ASC, i.intent_id ASC",
        )?;
        let stored = statement
            .query_map([], accepted_mutation_storage_row)?
            .collect::<Result<Vec<_>, _>>()?;
        stored.into_iter().map(decode_accepted_mutation).collect()
    }

    pub fn mutation_status(
        &self,
        intent_id: Uuid,
        attempt_id: Uuid,
    ) -> Result<Option<MutationStatusV1>, StoreError> {
        if intent_id.is_nil() || attempt_id.is_nil() {
            return Err(StoreError::InvalidControllerInput(
                "mutation status identities must not be nil",
            ));
        }
        let accepted = self
            .accepted_mutations()?
            .into_iter()
            .find(|accepted| accepted.intent_id == intent_id && accepted.attempt_id == attempt_id);
        let Some(accepted) = accepted else {
            return Ok(None);
        };
        let phases = accepted
            .operation_kind
            .required_phases(accepted.effective_release_class)?;
        let connection = lock_connection(&self.connection)?;
        let mut projection = MutationStatusProjectionV1::new(phases[0], accepted.accepted_at_ms);
        let primary_complete = project_mutation_status_branch(
            &connection,
            attempt_id,
            phases,
            ExecutorPhaseBranch::Primary,
            MutationExecutionStateV1::Accepted,
            &mut projection,
        )?;
        if load_rollback_takeover(&connection, attempt_id)?.is_some() {
            let rollback_complete = project_mutation_status_branch(
                &connection,
                attempt_id,
                &[
                    OperationPhase::Rollback,
                    OperationPhase::HealthChecking,
                    OperationPhase::Soaking,
                ],
                ExecutorPhaseBranch::RollbackRecovery,
                MutationExecutionStateV1::Running,
                &mut projection,
            )?;
            if rollback_complete {
                projection.state = MutationExecutionStateV1::RolledBack;
            }
        } else if primary_complete {
            projection.state = MutationExecutionStateV1::Succeeded;
        }
        Ok(Some(MutationStatusV1 {
            intent_id,
            attempt_id,
            project_id: accepted.project_id,
            operation_kind: accepted.operation_kind,
            target_commit: accepted.target_commit,
            effective_release_class: accepted.effective_release_class,
            state: projection.state,
            current_phase: projection.current_phase,
            completed_phases: projection.completed_phases,
            accepted_at_ms: accepted.accepted_at_ms,
            updated_at_ms: projection.updated_at_ms,
        }))
    }

    pub fn consume_prepared_intent_action_grant(
        &self,
        intent_id: Uuid,
        grant: &AuthenticatedActionGrantV1,
        attempt_id: Uuid,
        consumed_at_ms: i64,
    ) -> Result<ActionGrantConsumptionV1, StoreError> {
        if intent_id.is_nil() || attempt_id.is_nil() || consumed_at_ms < 0 {
            return Err(StoreError::InvalidControllerInput(
                "prepared-intent grant consumption identity or time is invalid",
            ));
        }
        let claims = grant.claims();
        if claims.intent_id != intent_id {
            return Err(StoreError::ExecutorIntentGrantBinding);
        }
        let lease_generation = i64::try_from(claims.lease_generation)
            .map_err(|_| StoreError::ExecutorActionGrantRange)?;
        let key_epoch =
            i64::try_from(claims.key_epoch).map_err(|_| StoreError::ExecutorActionGrantRange)?;
        let context = PreparedIntentGrantConsumption {
            grant,
            intent_id: intent_id.to_string(),
            attempt_id: attempt_id.to_string(),
            request_id: claims.request_id.to_string(),
            nonce: claims.nonce.to_string(),
            consumed_at_ms,
            lease_generation,
            key_epoch,
        };
        self.immediate_transaction(|transaction| {
            consume_prepared_intent_grant(transaction, &context)
        })
    }

    pub fn begin_rollback_takeover(
        &self,
        attempt_id: Uuid,
        project_id: &ProjectId,
        authorization_digest: &EvidenceDigest,
        created_at_ms: i64,
    ) -> Result<Option<RollbackTakeover>, StoreError> {
        self.immediate_transaction(|transaction| {
            require_authorized_for_project(
                transaction,
                attempt_id,
                project_id,
                Some(authorization_digest),
            )?;
            require_rollback_fence_available(transaction, attempt_id, project_id)?;
            if let Some(existing) = load_rollback_takeover(transaction, attempt_id)? {
                if existing.project_id != *project_id {
                    return Err(StoreError::CorruptSecurityJournal(
                        "rollback takeover project binding",
                    ));
                }
                return Ok(Some(existing));
            }

            let (forward_phase, forward_status, forward_intent_digest) =
                select_rollback_forward_snapshot(transaction, attempt_id, project_id)?;
            transaction.execute(
                "INSERT INTO executor_rollback_takeovers(
                    attempt_id, project_id, forward_phase, forward_status,
                    forward_intent_digest, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    attempt_id.to_string(),
                    project_id.as_str(),
                    &forward_phase,
                    forward_status.as_str(),
                    forward_intent_digest.as_str(),
                    created_at_ms
                ],
            )?;
            load_rollback_takeover(transaction, attempt_id)?.map_or_else(
                || {
                    Err(StoreError::CorruptSecurityJournal(
                        "rollback takeover disappeared",
                    ))
                },
                |takeover| Ok(Some(takeover)),
            )
        })
    }

    pub fn rollback_takeover(
        &self,
        attempt_id: Uuid,
    ) -> Result<Option<RollbackTakeover>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        load_rollback_takeover(&connection, attempt_id)
    }

    pub fn begin_phase_intent(
        &self,
        request: PhaseIntentRequest<'_>,
    ) -> Result<PhaseJournalEntry, StoreError> {
        let PhaseIntentRequest {
            attempt_id,
            project_id,
            phase,
            branch,
            phase_plan,
            intent_digest,
            authorization_digest,
            started_at_ms,
        } = request;
        let storage_phase = branch.storage_key(phase)?;
        self.immediate_transaction(|transaction| {
            require_authorized_for_project(
                transaction,
                attempt_id,
                project_id,
                Some(authorization_digest),
            )?;
            require_phase_prerequisites(transaction, attempt_id, phase, branch, &phase_plan)?;
            if let Some(existing) = load_phase_entry(transaction, attempt_id, storage_phase, phase)?
            {
                if existing.project_id == *project_id && existing.intent_digest == *intent_digest {
                    return Ok(existing);
                }
                mark_phase_needs_reconcile(transaction, attempt_id, storage_phase, started_at_ms)?;
                return Ok(PhaseJournalEntry {
                    status: PhaseJournalStatus::NeedsReconcile,
                    updated_at_ms: started_at_ms,
                    ..existing
                });
            }
            if has_uncommitted_phase_conflict(transaction, attempt_id, branch)? {
                return Err(StoreError::ExecutorPhaseConflict);
            }
            transaction.execute(
                "INSERT INTO executor_phase_journal(
                    attempt_id, phase, project_id, intent_digest, artifacts_json,
                    status, started_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'intent_persisted', ?6, ?6)",
                params![
                    attempt_id.to_string(),
                    storage_phase,
                    project_id.as_str(),
                    intent_digest.as_str(),
                    serde_json::to_string(&PhaseArtifacts::default())?,
                    started_at_ms
                ],
            )?;
            Ok(PhaseJournalEntry {
                attempt_id,
                project_id: project_id.clone(),
                phase,
                intent_digest: intent_digest.clone(),
                observation_digest: None,
                artifacts: PhaseArtifacts::default(),
                status: PhaseJournalStatus::IntentPersisted,
                updated_at_ms: started_at_ms,
            })
        })
    }

    pub fn validate_phase_start(
        &self,
        attempt_id: Uuid,
        project_id: &ProjectId,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
        phase_plan: &ExecutorPhasePlan<'_>,
        authorization_digest: &EvidenceDigest,
    ) -> Result<(), StoreError> {
        self.immediate_transaction(|transaction| {
            require_authorized_for_project(
                transaction,
                attempt_id,
                project_id,
                Some(authorization_digest),
            )?;
            require_phase_prerequisites(transaction, attempt_id, phase, branch, phase_plan)
        })
    }

    pub fn phase_entry(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
    ) -> Result<Option<PhaseJournalEntry>, StoreError> {
        self.phase_entry_in_branch(attempt_id, phase, ExecutorPhaseBranch::Primary)
    }

    pub fn phase_entry_in_branch(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
    ) -> Result<Option<PhaseJournalEntry>, StoreError> {
        let storage_phase = branch.storage_key(phase)?;
        let connection = lock_connection(&self.connection)?;
        load_phase_entry(&connection, attempt_id, storage_phase, phase)
    }

    pub fn bind_authorized_phase_spec(
        &self,
        binding: AuthorizedPhaseSpecBinding<'_>,
    ) -> Result<AuthorizedPhaseSpecRecord, StoreError> {
        if binding.attempt_id.is_nil()
            || binding.persisted_at_ms < 0
            || binding.canonical_json.is_empty()
            || binding.canonical_json.len() > 256 * 1024
        {
            return Err(StoreError::AuthorizedPhaseSpecInvalid);
        }
        validate_authorized_phase_spec_document(binding)?;
        let storage_phase = binding.branch.storage_key(binding.phase)?;
        let document_digest = EvidenceDigest::sha256(binding.canonical_json);
        self.immediate_transaction(|transaction| {
            require_branch_not_taken_over(transaction, binding.attempt_id, binding.branch)?;
            let entry = load_phase_entry(
                transaction,
                binding.attempt_id,
                storage_phase,
                binding.phase,
            )?
            .ok_or(StoreError::ExecutorPhaseState)?;
            if entry.project_id != *binding.project_id
                || entry.intent_digest != *binding.intent_digest
                || entry.status != PhaseJournalStatus::IntentPersisted
            {
                return Err(StoreError::AuthorizedPhaseSpecBinding);
            }
            if let Some(existing) = load_authorized_phase_spec(
                transaction,
                binding.attempt_id,
                storage_phase,
                binding.phase,
                binding.branch,
            )? {
                if existing.project_id == *binding.project_id
                    && existing.intent_digest == *binding.intent_digest
                    && existing.spec_digest == *binding.spec_digest
                    && existing.document_digest == document_digest
                    && existing.canonical_json == binding.canonical_json
                {
                    return Ok(existing);
                }
                return Err(StoreError::AuthorizedPhaseSpecConflict);
            }
            transaction.execute(
                "INSERT INTO authorized_phase_specs(
                    attempt_id, phase, project_id, intent_digest, spec_digest,
                    document_digest, canonical_json, persisted_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    binding.attempt_id.to_string(),
                    storage_phase,
                    binding.project_id.as_str(),
                    binding.intent_digest.as_str(),
                    binding.spec_digest.as_str(),
                    document_digest.as_str(),
                    binding.canonical_json,
                    binding.persisted_at_ms,
                ],
            )?;
            Ok(AuthorizedPhaseSpecRecord {
                attempt_id: binding.attempt_id,
                project_id: binding.project_id.clone(),
                phase: binding.phase,
                branch: binding.branch,
                intent_digest: binding.intent_digest.clone(),
                spec_digest: binding.spec_digest.clone(),
                document_digest,
                canonical_json: binding.canonical_json.to_vec(),
                persisted_at_ms: binding.persisted_at_ms,
            })
        })
    }

    pub fn authorized_phase_spec_in_branch(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
    ) -> Result<Option<AuthorizedPhaseSpecRecord>, StoreError> {
        let storage_phase = branch.storage_key(phase)?;
        let connection = lock_connection(&self.connection)?;
        load_authorized_phase_spec(&connection, attempt_id, storage_phase, phase, branch)
    }

    pub fn bind_verified_backup_chain(
        &self,
        binding: VerifiedBackupChainBinding<'_>,
    ) -> Result<VerifiedBackupChainRecord, StoreError> {
        let prepared = prepare_verified_backup_chain(binding)?;
        let storage_phase = prepared.storage_phase;
        let canonical_json = prepared.canonical_json;
        let document_digest = prepared.document_digest;
        self.immediate_transaction(|transaction| {
            require_branch_not_taken_over(transaction, binding.attempt_id, binding.branch)?;
            let entry = load_phase_entry(
                transaction,
                binding.attempt_id,
                storage_phase,
                binding.phase,
            )?
            .ok_or(StoreError::ExecutorPhaseState)?;
            let phase_spec = load_authorized_phase_spec(
                transaction,
                binding.attempt_id,
                storage_phase,
                binding.phase,
                binding.branch,
            )?
            .ok_or(StoreError::AuthorizedPhaseSpecMissing)?;
            let decoded_spec = AuthorizedPhaseSpecV1::decode_canonical(&phase_spec.canonical_json)
                .map_err(|_| StoreError::AuthorizedPhaseSpecInvalid)?;
            if entry.status != PhaseJournalStatus::IntentPersisted
                || entry.project_id != *binding.project_id
                || phase_spec.spec_digest != *binding.authorized_phase_spec_digest
                || binding.chain.authorized_spec().phase_intent_digest != entry.intent_digest
                || decoded_spec.backup.as_ref() != Some(binding.chain.authorized_spec())
            {
                return Err(StoreError::VerifiedBackupChainBinding);
            }
            if let Some(existing) = load_verified_backup_chain(
                transaction,
                binding.attempt_id,
                storage_phase,
                binding.phase,
                binding.branch,
            )? {
                if existing.project_id == *binding.project_id
                    && existing.authorized_phase_spec_digest
                        == *binding.authorized_phase_spec_digest
                    && existing.chain_digest == *binding.chain.chain_digest()
                    && existing.document_digest == document_digest
                    && existing.canonical_json == canonical_json
                {
                    return Ok(existing);
                }
                return Err(StoreError::VerifiedBackupChainConflict);
            }
            transaction.execute(
                "INSERT INTO verified_backup_chains(
                    attempt_id, phase, project_id, authorized_phase_spec_digest,
                    chain_digest, document_digest, canonical_json, persisted_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    binding.attempt_id.to_string(),
                    storage_phase,
                    binding.project_id.as_str(),
                    binding.authorized_phase_spec_digest.as_str(),
                    binding.chain.chain_digest().as_str(),
                    document_digest.as_str(),
                    canonical_json,
                    binding.persisted_at_ms,
                ],
            )?;
            Ok(VerifiedBackupChainRecord {
                attempt_id: binding.attempt_id,
                project_id: binding.project_id.clone(),
                phase: binding.phase,
                branch: binding.branch,
                authorized_phase_spec_digest: binding.authorized_phase_spec_digest.clone(),
                chain_digest: binding.chain.chain_digest().clone(),
                document_digest,
                canonical_json,
                persisted_at_ms: binding.persisted_at_ms,
            })
        })
    }

    pub fn verified_backup_chain_in_branch(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
    ) -> Result<Option<VerifiedBackupChainRecord>, StoreError> {
        let storage_phase = branch.storage_key(phase)?;
        let connection = lock_connection(&self.connection)?;
        load_verified_backup_chain(&connection, attempt_id, storage_phase, phase, branch)
    }

    pub fn latest_committed_base_backup_chain(
        &self,
        project_id: &ProjectId,
    ) -> Result<Option<VerifiedBackupChainRecord>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        load_latest_committed_base_backup_chain(&connection, project_id)
    }

    pub fn authorize_bound_phase_spec(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
        authorized_at_ms: i64,
    ) -> Result<AuthorizedPhasePermitV1, StoreError> {
        if authorized_at_ms < 0 {
            return Err(StoreError::AuthorizedPhaseSpecInvalid);
        }
        let storage_phase = branch.storage_key(phase)?;
        self.immediate_transaction(|transaction| {
            require_branch_not_taken_over(transaction, attempt_id, branch)?;
            let entry = load_phase_entry(transaction, attempt_id, storage_phase, phase)?
                .ok_or(StoreError::ExecutorPhaseState)?;
            if entry.status != PhaseJournalStatus::IntentPersisted {
                return Err(StoreError::ExecutorPhaseState);
            }
            let record =
                load_authorized_phase_spec(transaction, attempt_id, storage_phase, phase, branch)?
                    .ok_or(StoreError::AuthorizedPhaseSpecMissing)?;
            if record.intent_digest != entry.intent_digest
                || record.project_id != entry.project_id
                || EvidenceDigest::sha256(&record.canonical_json) != record.document_digest
            {
                return Err(StoreError::AuthorizedPhaseSpecBinding);
            }
            let spec = decode_authorized_phase_spec_document(AuthorizedPhaseSpecBinding {
                attempt_id,
                project_id: &record.project_id,
                phase,
                branch,
                intent_digest: &record.intent_digest,
                spec_digest: &record.spec_digest,
                canonical_json: &record.canonical_json,
                persisted_at_ms: record.persisted_at_ms,
            })?;
            if spec
                .prerequisites_valid_through_ms
                .is_some_and(|valid_through| authorized_at_ms > valid_through)
            {
                return Err(StoreError::PhaseAuthorityExpired);
            }
            validate_verified_prerequisite_chains(transaction, &spec)?;
            validate_active_fence_for_spec(transaction, &spec)?;
            consume_mutation_grant(transaction, &spec, storage_phase, authorized_at_ms)?;
            reserve_bootstrap(transaction, &spec, storage_phase, authorized_at_ms)?;
            Ok(AuthorizedPhasePermitV1 {
                attempt_id,
                project_id: record.project_id,
                phase,
                branch,
                intent_digest: record.intent_digest,
                spec_digest: record.spec_digest,
                document_digest: record.document_digest,
            })
        })
    }

    pub fn record_source_gate_proof(
        &self,
        proof: &SourceGateProofRecord,
    ) -> Result<(), StoreError> {
        let storage_phase = ExecutorPhaseBranch::Primary.storage_key(proof.phase)?;
        self.immediate_transaction(|transaction| {
            let sequence =
                match validate_source_gate_proof_admission(transaction, proof, storage_phase)? {
                    Ok(sequence) => sequence,
                    Err(rejection) => return Ok(Err(rejection)),
                };
            persist_source_gate_proof(transaction, proof, storage_phase, sequence)
        })?
    }

    pub fn source_gate_proof(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
    ) -> Result<Option<EvidenceDigest>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        connection
            .query_row(
                "SELECT proof_digest FROM source_gate_proofs
                 WHERE attempt_id = ?1 AND phase = ?2",
                params![attempt_id.to_string(), phase_name(phase)],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| {
                EvidenceDigest::from_str(&value)
                    .map_err(|_| StoreError::CorruptSecurityJournal("source gate proof digest"))
            })
            .transpose()
    }

    pub fn source_gate_rejection_pending(
        &self,
        attempt_id: Uuid,
        project_id: &ProjectId,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
    ) -> Result<bool, StoreError> {
        let storage_phase = branch.storage_key(phase)?;
        let connection = lock_connection(&self.connection)?;
        Ok(connection
            .query_row(
                "SELECT project_id, state FROM source_gate_rejections
                 WHERE attempt_id = ?1 AND phase = ?2",
                params![attempt_id.to_string(), storage_phase],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .is_some_and(|(stored_project, state)| {
                stored_project == project_id.as_str() && state == "abort_pending"
            }))
    }

    pub fn compensate_source_gate_rejection(
        &self,
        attempt_id: Uuid,
        project_id: &ProjectId,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
        intent_digest: &EvidenceDigest,
        compensated_at_ms: i64,
    ) -> Result<(), StoreError> {
        if compensated_at_ms < 0 {
            return Err(StoreError::ExecutorPhaseState);
        }
        let storage_phase = branch.storage_key(phase)?;
        let default_artifacts = PhaseArtifacts::default();
        self.immediate_transaction(|transaction| {
            require_branch_not_taken_over(transaction, attempt_id, branch)?;
            let entry = load_phase_entry(transaction, attempt_id, storage_phase, phase)?
                .ok_or(StoreError::ExecutorPhaseState)?;
            if entry.project_id != *project_id
                || entry.intent_digest != *intent_digest
                || entry.status != PhaseJournalStatus::NeedsReconcile
                || entry.observation_digest.is_some()
                || entry.artifacts != default_artifacts
            {
                return Err(StoreError::ExecutorPhaseState);
            }
            let rejection = transaction
                .query_row(
                    "SELECT project_id, state FROM source_gate_rejections
                     WHERE attempt_id = ?1 AND phase = ?2",
                    params![attempt_id.to_string(), storage_phase],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
                .ok_or(StoreError::ExecutorPhaseState)?;
            if rejection.0 != project_id.as_str() || rejection.1 != "abort_pending" {
                return Err(StoreError::ExecutorPhaseState);
            }
            let receipt_exists = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM executor_phase_receipts
                    WHERE attempt_id = ?1 AND phase = ?2
                 )",
                params![attempt_id.to_string(), storage_phase],
                |row| row.get::<_, bool>(0),
            )?;
            if receipt_exists {
                return Err(StoreError::ExecutorPhaseState);
            }
            transaction.execute(
                "DELETE FROM source_gate_proofs
                 WHERE attempt_id = ?1 AND phase = ?2",
                params![attempt_id.to_string(), phase_name(phase)],
            )?;
            let changed = transaction.execute(
                "UPDATE executor_phase_journal
                 SET status = 'intent_persisted', updated_at_ms = ?3
                 WHERE attempt_id = ?1 AND phase = ?2
                   AND status = 'needs_reconcile'",
                params![attempt_id.to_string(), storage_phase, compensated_at_ms],
            )?;
            if changed != 1 {
                return Err(StoreError::ExecutorPhaseState);
            }
            let changed = transaction.execute(
                "UPDATE source_gate_rejections
                 SET state = 'compensated', compensated_at_ms = ?3
                 WHERE attempt_id = ?1 AND phase = ?2 AND state = 'abort_pending'",
                params![attempt_id.to_string(), storage_phase, compensated_at_ms],
            )?;
            if changed == 1 {
                Ok(())
            } else {
                Err(StoreError::ExecutorPhaseState)
            }
        })
    }

    pub fn record_phase_observation(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        observed_intent_digest: &EvidenceDigest,
        observation_digest: &EvidenceDigest,
        artifacts: &PhaseArtifacts,
        observed_at_ms: i64,
    ) -> Result<ObservationAcceptance, StoreError> {
        self.record_phase_observation_in_branch(PhaseObservationRequest {
            attempt_id,
            phase,
            branch: ExecutorPhaseBranch::Primary,
            observed_intent_digest,
            observation_digest,
            artifacts,
            observed_at_ms,
        })
    }

    pub fn record_phase_observation_in_branch(
        &self,
        request: PhaseObservationRequest<'_>,
    ) -> Result<ObservationAcceptance, StoreError> {
        let storage_phase = request.branch.storage_key(request.phase)?;
        self.immediate_transaction(|transaction| {
            require_branch_not_taken_over(transaction, request.attempt_id, request.branch)?;
            let entry = load_phase_entry(
                transaction,
                request.attempt_id,
                storage_phase,
                request.phase,
            )?
            .ok_or(StoreError::ExecutorPhaseState)?;
            if entry.status == PhaseJournalStatus::NeedsReconcile {
                return Ok(ObservationAcceptance::NeedsReconcile);
            }
            let artifacts_json = serde_json::to_string(request.artifacts)?;
            if entry.intent_digest != *request.observed_intent_digest {
                if entry.status == PhaseJournalStatus::Committed {
                    return Err(StoreError::ExecutorObservationMismatch);
                }
                let changed = transaction.execute(
                    "UPDATE executor_phase_journal
                     SET observation_digest = ?3, artifacts_json = ?4,
                         status = 'needs_reconcile', updated_at_ms = ?5
                     WHERE attempt_id = ?1 AND phase = ?2 AND status != 'committed'",
                    params![
                        request.attempt_id.to_string(),
                        storage_phase,
                        request.observation_digest.as_str(),
                        artifacts_json,
                        request.observed_at_ms
                    ],
                )?;
                if changed != 1 {
                    return Err(StoreError::ExecutorObservationMismatch);
                }
                return Ok(ObservationAcceptance::NeedsReconcile);
            }
            request.artifacts.validate_for_phase(request.phase)?;
            validate_artifact_disk_reservation(
                transaction,
                request.attempt_id,
                &entry.project_id,
                request.artifacts,
            )?;
            let bound_spec = validate_bound_phase_spec_artifact(
                transaction,
                request.attempt_id,
                storage_phase,
                request.phase,
                request.branch,
                request.artifacts,
            )?;
            validate_artifact_source_gate_proof(
                transaction,
                request.attempt_id,
                request.phase,
                request.artifacts,
                bound_spec
                    .as_ref()
                    .is_some_and(|spec| bound_spec_requires_source_gate_proof(spec, request.phase)),
            )?;
            if !matches!(
                entry.status,
                PhaseJournalStatus::IntentPersisted
                    | PhaseJournalStatus::Observed
                    | PhaseJournalStatus::Verified
                    | PhaseJournalStatus::Committed
            ) {
                return Err(StoreError::ExecutorPhaseState);
            }
            if entry.status == PhaseJournalStatus::IntentPersisted {
                transaction.execute(
                    "UPDATE executor_phase_journal
                     SET observation_digest = ?3, artifacts_json = ?4,
                         status = 'observed', updated_at_ms = ?5
                     WHERE attempt_id = ?1 AND phase = ?2",
                    params![
                        request.attempt_id.to_string(),
                        storage_phase,
                        request.observation_digest.as_str(),
                        artifacts_json,
                        request.observed_at_ms
                    ],
                )?;
            } else if entry.observation_digest.as_ref() != Some(request.observation_digest)
                || entry.artifacts != *request.artifacts
            {
                if entry.status == PhaseJournalStatus::Committed {
                    return Err(StoreError::ExecutorObservationMismatch);
                }
                mark_phase_needs_reconcile(
                    transaction,
                    request.attempt_id,
                    storage_phase,
                    request.observed_at_ms,
                )?;
                return Ok(ObservationAcceptance::NeedsReconcile);
            }
            Ok(ObservationAcceptance::Accepted)
        })
    }

    pub fn mark_phase_verified(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        verified_at_ms: i64,
    ) -> Result<(), StoreError> {
        self.mark_phase_verified_in_branch(
            attempt_id,
            phase,
            ExecutorPhaseBranch::Primary,
            verified_at_ms,
        )
    }

    pub fn mark_phase_verified_in_branch(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
        verified_at_ms: i64,
    ) -> Result<(), StoreError> {
        let storage_phase = branch.storage_key(phase)?;
        self.immediate_transaction(|transaction| {
            require_branch_not_taken_over(transaction, attempt_id, branch)?;
            let entry = load_phase_entry(transaction, attempt_id, storage_phase, phase)?
                .ok_or(StoreError::ExecutorPhaseState)?;
            match entry.status {
                PhaseJournalStatus::Observed => {
                    transaction.execute(
                        "UPDATE executor_phase_journal
                         SET status = 'verified', updated_at_ms = ?3
                         WHERE attempt_id = ?1 AND phase = ?2",
                        params![attempt_id.to_string(), storage_phase, verified_at_ms],
                    )?;
                    Ok(())
                }
                PhaseJournalStatus::Verified | PhaseJournalStatus::Committed => Ok(()),
                PhaseJournalStatus::IntentPersisted | PhaseJournalStatus::NeedsReconcile => {
                    Err(StoreError::ExecutorPhaseState)
                }
            }
        })
    }

    pub fn mark_phase_needs_reconcile(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        updated_at_ms: i64,
    ) -> Result<(), StoreError> {
        self.mark_phase_needs_reconcile_in_branch(
            attempt_id,
            phase,
            ExecutorPhaseBranch::Primary,
            updated_at_ms,
        )
    }

    pub fn mark_phase_needs_reconcile_in_branch(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
        updated_at_ms: i64,
    ) -> Result<(), StoreError> {
        let storage_phase = branch.storage_key(phase)?;
        self.immediate_transaction(|transaction| {
            require_branch_not_taken_over(transaction, attempt_id, branch)?;
            let changed = transaction.execute(
                "UPDATE executor_phase_journal
                 SET status = 'needs_reconcile', updated_at_ms = ?3
                 WHERE attempt_id = ?1 AND phase = ?2 AND status != 'committed'",
                params![attempt_id.to_string(), storage_phase, updated_at_ms],
            )?;
            if changed == 1 {
                Ok(())
            } else {
                Err(StoreError::ExecutorPhaseState)
            }
        })
    }

    pub fn commit_phase_receipt(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        committed_at_ms: i64,
    ) -> Result<PhaseReceipt, StoreError> {
        self.commit_phase_receipt_in_branch(
            attempt_id,
            phase,
            ExecutorPhaseBranch::Primary,
            committed_at_ms,
        )
    }

    pub fn commit_phase_receipt_in_branch(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
        committed_at_ms: i64,
    ) -> Result<PhaseReceipt, StoreError> {
        let storage_phase = branch.storage_key(phase)?;
        self.immediate_transaction(|transaction| {
            require_branch_not_taken_over(transaction, attempt_id, branch)?;
            if let Some(receipt) =
                load_phase_receipt(transaction, attempt_id, storage_phase, phase, branch)?
            {
                return Ok(receipt);
            }
            let entry = load_phase_entry(transaction, attempt_id, storage_phase, phase)?
                .ok_or(StoreError::ExecutorPhaseState)?;
            if entry.status != PhaseJournalStatus::Verified {
                return Err(StoreError::ExecutorPhaseState);
            }
            let observation_digest =
                entry
                    .observation_digest
                    .ok_or(StoreError::CorruptSecurityJournal(
                        "verified phase without observation",
                    ))?;
            let receipt = PhaseReceipt::new(
                attempt_id,
                phase,
                branch,
                entry.intent_digest,
                observation_digest,
                entry.artifacts,
                committed_at_ms,
            )?;
            commit_bootstrap_ledger_if_needed(
                transaction,
                attempt_id,
                storage_phase,
                phase,
                branch,
                &receipt,
                committed_at_ms,
            )?;
            close_backup_boundary_if_needed(
                transaction,
                attempt_id,
                storage_phase,
                phase,
                branch,
                committed_at_ms,
            )?;
            transaction.execute(
                "INSERT INTO executor_phase_receipts(
                    attempt_id, phase, receipt_digest, receipt_json, committed_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    attempt_id.to_string(),
                    storage_phase,
                    receipt.receipt_digest.as_str(),
                    serde_json::to_string(&receipt)?,
                    committed_at_ms
                ],
            )?;
            transaction.execute(
                "UPDATE executor_phase_journal
                 SET status = 'committed', updated_at_ms = ?3
                 WHERE attempt_id = ?1 AND phase = ?2",
                params![attempt_id.to_string(), storage_phase, committed_at_ms],
            )?;
            Ok(receipt)
        })
    }

    pub fn phase_receipt(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
    ) -> Result<Option<PhaseReceipt>, StoreError> {
        self.phase_receipt_in_branch(attempt_id, phase, ExecutorPhaseBranch::Primary)
    }

    pub fn phase_receipt_in_branch(
        &self,
        attempt_id: Uuid,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
    ) -> Result<Option<PhaseReceipt>, StoreError> {
        let storage_phase = branch.storage_key(phase)?;
        let connection = lock_connection(&self.connection)?;
        load_phase_receipt(&connection, attempt_id, storage_phase, phase, branch)
    }

    pub fn acquire_resource(
        &self,
        resource: &ExecutionResource,
        attempt_id: Uuid,
        acquired_at_ms: i64,
    ) -> Result<(), StoreError> {
        self.immediate_transaction(|transaction| {
            acquire_resource_in_transaction(transaction, resource, attempt_id, acquired_at_ms)
        })
    }

    pub fn acquire_disk_reservation(
        &self,
        project_id: &ProjectId,
        attempt_id: Uuid,
        observation: &DiskAvailabilityObservation,
        acquired_at_ms: i64,
    ) -> Result<(), StoreError> {
        self.immediate_transaction(|transaction| {
            let claim = load_authorized_disk_reservation(transaction, project_id, attempt_id)?;
            validate_disk_observation(&claim, observation, acquired_at_ms)?;
            let already_active =
                if let Some(existing) = load_active_disk_reservation(transaction, attempt_id)? {
                    if !existing.matches(project_id, &claim) {
                        return Err(StoreError::DiskReservationAuthorizationInvalid);
                    }
                    require_resource_key_owned(
                        transaction,
                        &disk_reservation_resource_key(project_id),
                        attempt_id,
                    )?;
                    true
                } else {
                    false
                };
            let (reserved_operation_bytes, active_emergency_reserve_bytes) =
                active_disk_reservation_totals(
                    transaction,
                    &claim.filesystem_identity,
                    attempt_id,
                )?;
            let requested_operation_bytes = reserved_operation_bytes
                .checked_add(
                    claim
                        .operation_bytes()
                        .ok_or(StoreError::DiskReservationAuthorizationInvalid)?,
                )
                .ok_or(StoreError::DiskReservationRange)?;
            let requested_total = requested_operation_bytes
                .checked_add(active_emergency_reserve_bytes.max(claim.emergency_reserve_bytes))
                .ok_or(StoreError::DiskReservationRange)?;
            if requested_total > observation.available_bytes {
                return Err(StoreError::DiskReservationCapacity {
                    required: requested_total,
                    available: observation.available_bytes,
                });
            }
            if already_active {
                transaction.execute(
                    "UPDATE active_disk_reservations
                     SET available_bytes = ?2, observed_at_ms = ?3
                     WHERE attempt_id = ?1",
                    params![
                        attempt_id.to_string(),
                        disk_bytes_to_i64(observation.available_bytes)?,
                        observation.observed_at_ms
                    ],
                )?;
                return Ok(());
            }
            require_project_resource_allowed(transaction, project_id, attempt_id)?;
            acquire_resource_key_in_transaction(
                transaction,
                &disk_reservation_resource_key(project_id),
                attempt_id,
                acquired_at_ms,
            )?;
            transaction.execute(
                "INSERT INTO active_disk_reservations(
                    attempt_id, project_id, required_bytes, emergency_reserve_bytes,
                    available_bytes, filesystem_identity, reservation_digest,
                    observed_at_ms, acquired_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    attempt_id.to_string(),
                    project_id.as_str(),
                    disk_bytes_to_i64(claim.required_bytes)?,
                    disk_bytes_to_i64(claim.emergency_reserve_bytes)?,
                    disk_bytes_to_i64(observation.available_bytes)?,
                    claim.filesystem_identity.as_str(),
                    claim.reservation_digest.as_str(),
                    observation.observed_at_ms,
                    acquired_at_ms
                ],
            )?;
            Ok(())
        })
    }

    pub fn release_disk_reservation_if_owned(
        &self,
        project_id: &ProjectId,
        attempt_id: Uuid,
        released_at_ms: i64,
    ) -> Result<(), StoreError> {
        self.immediate_transaction(|transaction| {
            if let Some(existing) = load_active_disk_reservation(transaction, attempt_id)? {
                if existing.project_id != *project_id {
                    return Err(StoreError::ExecutionResourceOwnership);
                }
                require_resource_key_owned(
                    transaction,
                    &disk_reservation_resource_key(project_id),
                    attempt_id,
                )?;
                transaction.execute(
                    "DELETE FROM active_disk_reservations WHERE attempt_id = ?1",
                    [attempt_id.to_string()],
                )?;
            }
            release_resource_key_if_owned_in_transaction(
                transaction,
                &disk_reservation_resource_key(project_id),
                attempt_id,
                released_at_ms,
            )
        })
    }

    pub fn release_resource(
        &self,
        resource: &ExecutionResource,
        attempt_id: Uuid,
        released_at_ms: i64,
    ) -> Result<(), StoreError> {
        let resource_key = resource.key();
        self.immediate_transaction(|transaction| {
            let owner = transaction
                .query_row(
                    "SELECT owner_attempt_id FROM execution_resources WHERE resource_key = ?1",
                    [&resource_key],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            match owner {
                Some(owner) if owner == attempt_id.to_string() => {
                    transaction.execute(
                        "DELETE FROM execution_resources WHERE resource_key = ?1",
                        [&resource_key],
                    )?;
                    transaction.execute(
                        "UPDATE execution_resource_receipts
                         SET state = 'released', updated_at_ms = ?3
                         WHERE resource_key = ?1 AND owner_attempt_id = ?2",
                        params![resource_key, attempt_id.to_string(), released_at_ms],
                    )?;
                    Ok(())
                }
                Some(_) => Err(StoreError::ExecutionResourceOwnership),
                None => {
                    let released = transaction
                        .query_row(
                            "SELECT state FROM execution_resource_receipts
                             WHERE resource_key = ?1 AND owner_attempt_id = ?2",
                            params![resource_key, attempt_id.to_string()],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()?;
                    if released.as_deref() == Some("released") {
                        Ok(())
                    } else {
                        Err(StoreError::ExecutionResourceOwnership)
                    }
                }
            }
        })
    }

    pub fn release_resource_if_owned(
        &self,
        resource: &ExecutionResource,
        attempt_id: Uuid,
        released_at_ms: i64,
    ) -> Result<(), StoreError> {
        self.immediate_transaction(|transaction| {
            release_resource_if_owned_in_transaction(
                transaction,
                resource,
                attempt_id,
                released_at_ms,
            )
        })
    }

    pub fn begin_backup_boundary(
        &self,
        project_id: &ProjectId,
        attempt_id: Uuid,
        created_at_ms: i64,
    ) -> Result<BackupBoundaryLease, StoreError> {
        self.immediate_transaction(|transaction| {
            require_authorized_for_project(transaction, attempt_id, project_id, None)?;
            require_resource_owned(
                transaction,
                &ExecutionResource::ProjectDeploy(project_id.clone()),
                attempt_id,
            )?;
            let phase = OperationPhase::BackingUp;
            let branch = ExecutorPhaseBranch::Primary;
            let storage_phase = branch.storage_key(phase)?;
            let entry = load_phase_entry(transaction, attempt_id, storage_phase, phase)?
                .ok_or(StoreError::ExecutorPhaseState)?;
            if entry.status != PhaseJournalStatus::IntentPersisted
                || entry.project_id != *project_id
            {
                return Err(StoreError::ExecutorPhaseState);
            }
            let record =
                load_authorized_phase_spec(transaction, attempt_id, storage_phase, phase, branch)?
                    .ok_or(StoreError::AuthorizedPhaseSpecMissing)?;
            let spec = decode_authorized_phase_spec_document(AuthorizedPhaseSpecBinding {
                attempt_id,
                project_id,
                phase,
                branch,
                intent_digest: &record.intent_digest,
                spec_digest: &record.spec_digest,
                canonical_json: &record.canonical_json,
                persisted_at_ms: record.persisted_at_ms,
            })?;
            if spec
                .backup
                .as_ref()
                .is_none_or(|backup| backup.snapshot_kind != BackupSnapshotKindV1::Base)
            {
                return Err(StoreError::AuthorizedPhaseSpecBinding);
            }
            if load_active_fence(transaction, project_id)?.is_some()
                || load_active_drain_identity(transaction, project_id)?.is_some()
            {
                return Err(StoreError::FenceConflict);
            }
            if let Some(active) = load_active_backup_boundary(transaction, project_id)? {
                return if active.attempt_id == attempt_id {
                    Ok(active)
                } else {
                    Err(StoreError::FenceConflict)
                };
            }

            let (epoch, epoch_i64) = allocate_next_fence_epoch(transaction)?;
            let token = Uuid::new_v4();
            transaction.execute(
                "INSERT INTO backup_boundary_journal(
                    epoch, project_id, attempt_id, token, state, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, 'reserved', ?5, ?5)",
                params![
                    epoch_i64,
                    project_id.as_str(),
                    attempt_id.to_string(),
                    token.to_string(),
                    created_at_ms
                ],
            )?;
            Ok(BackupBoundaryLease {
                journal_id: transaction.last_insert_rowid(),
                project_id: project_id.clone(),
                attempt_id,
                epoch,
                token,
                created_at_ms,
            })
        })
    }

    pub fn active_backup_boundary(
        &self,
        project_id: &ProjectId,
    ) -> Result<Option<BackupBoundaryLease>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        load_active_backup_boundary(&connection, project_id)
    }

    pub fn begin_drain_identity(
        &self,
        project_id: &ProjectId,
        attempt_id: Uuid,
        created_at_ms: i64,
    ) -> Result<DrainIdentityLease, StoreError> {
        self.immediate_transaction(|transaction| {
            require_authorized_for_project(transaction, attempt_id, project_id, None)?;
            require_resource_owned(
                transaction,
                &ExecutionResource::ProjectDeploy(project_id.clone()),
                attempt_id,
            )?;
            require_phase_receipt(transaction, attempt_id, OperationPhase::BackingUp)?;
            if load_active_fence(transaction, project_id)?.is_some()
                || load_active_backup_boundary(transaction, project_id)?.is_some()
            {
                return Err(StoreError::FenceConflict);
            }
            if let Some(active) = load_active_drain_identity(transaction, project_id)? {
                return if active.attempt_id == attempt_id {
                    Ok(active)
                } else {
                    Err(StoreError::FenceConflict)
                };
            }

            let (epoch, epoch_i64) = allocate_next_fence_epoch(transaction)?;
            let token = Uuid::new_v4();
            transaction.execute(
                "INSERT INTO drain_identity_journal(
                    epoch, project_id, attempt_id, token, state, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, 'reserved', ?5, ?5)",
                params![
                    epoch_i64,
                    project_id.as_str(),
                    attempt_id.to_string(),
                    token.to_string(),
                    created_at_ms
                ],
            )?;
            Ok(DrainIdentityLease {
                journal_id: transaction.last_insert_rowid(),
                project_id: project_id.clone(),
                attempt_id,
                epoch,
                token,
                created_at_ms,
            })
        })
    }

    pub fn active_drain_identity(
        &self,
        project_id: &ProjectId,
    ) -> Result<Option<DrainIdentityLease>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        load_active_drain_identity(&connection, project_id)
    }

    pub fn begin_fence_acquire(
        &self,
        project_id: &ProjectId,
        attempt_id: Uuid,
        created_at_ms: i64,
    ) -> Result<FenceLease, StoreError> {
        self.immediate_transaction(|transaction| {
            require_authorized_for_project(transaction, attempt_id, project_id, None)?;
            if let Some(active) = load_active_fence(transaction, project_id)? {
                if active.attempt_id == attempt_id
                    && matches!(
                        active.state,
                        FenceJournalState::AcquireIntent | FenceJournalState::Held
                    )
                {
                    require_resource_owned(
                        transaction,
                        &ExecutionResource::ProjectDeploy(project_id.clone()),
                        attempt_id,
                    )?;
                    require_fence_phase_receipts(transaction, attempt_id)?;
                    return Ok(active);
                }
                return Err(StoreError::FenceConflict);
            }
            require_resource_owned(
                transaction,
                &ExecutionResource::ProjectDeploy(project_id.clone()),
                attempt_id,
            )?;
            require_fence_phase_receipts(transaction, attempt_id)?;
            if let Some(drain) = load_active_drain_identity(transaction, project_id)? {
                return promote_drain_identity(
                    transaction,
                    project_id,
                    attempt_id,
                    &drain,
                    created_at_ms,
                );
            }
            allocate_fence_identity(transaction, project_id, attempt_id, created_at_ms)
        })
    }

    pub fn reconcile_fence(
        &self,
        project_id: &ProjectId,
        observation: &FenceObservation,
        observed_at_ms: i64,
    ) -> Result<FenceProjection, StoreError> {
        self.immediate_transaction(|transaction| {
            let Some(active) = load_active_fence(transaction, project_id)? else {
                return match observation {
                    FenceObservation::Released => Ok(FenceProjection::Released),
                    FenceObservation::Held {
                        attempt_id,
                        epoch,
                        token,
                    } => {
                        let epoch_i64 = i64::try_from(*epoch).map_err(|_| {
                            StoreError::CorruptSecurityJournal("observed fence epoch range")
                        })?;
                        if *epoch == 0 || attempt_id.is_nil() || token.is_nil() {
                            return Err(StoreError::FenceOwnershipMismatch);
                        }
                        transaction.execute(
                            "INSERT INTO fence_journal(
                                epoch, project_id, attempt_id, token, state,
                                created_at_ms, updated_at_ms
                             ) VALUES (?1, ?2, ?3, ?4, 'needs_reconcile', ?5, ?5)",
                            params![
                                epoch_i64,
                                project_id.as_str(),
                                attempt_id.to_string(),
                                token.to_string(),
                                observed_at_ms
                            ],
                        )?;
                        Ok(FenceProjection::NeedsReconcile)
                    }
                };
            };
            let release_is_safe = match active.release_safe_receipt_digest.as_ref() {
                Some(digest) => {
                    release_safe_receipt_exists(transaction, active.attempt_id, digest)?
                }
                None => false,
            };
            match (&active.state, observation) {
                (
                    FenceJournalState::AcquireIntent | FenceJournalState::Held,
                    FenceObservation::Held {
                        attempt_id,
                        epoch,
                        token,
                    },
                ) if *attempt_id == active.attempt_id
                    && *epoch == active.epoch
                    && *token == active.token =>
                {
                    set_fence_state(
                        transaction,
                        active.journal_id,
                        FenceJournalState::Held,
                        observed_at_ms,
                    )?;
                    Ok(FenceProjection::Held)
                }
                (
                    FenceJournalState::ReleaseIntent,
                    FenceObservation::Held {
                        attempt_id,
                        epoch,
                        token,
                    },
                ) if release_is_safe
                    && *attempt_id == active.attempt_id
                    && *epoch == active.epoch
                    && *token == active.token =>
                {
                    Ok(FenceProjection::Held)
                }
                (FenceJournalState::ReleaseIntent, FenceObservation::Released)
                    if release_is_safe =>
                {
                    set_fence_state(
                        transaction,
                        active.journal_id,
                        FenceJournalState::Released,
                        observed_at_ms,
                    )?;
                    Ok(FenceProjection::Released)
                }
                (FenceJournalState::Released, FenceObservation::Released) => {
                    Ok(FenceProjection::Released)
                }
                _ => {
                    set_fence_state(
                        transaction,
                        active.journal_id,
                        FenceJournalState::NeedsReconcile,
                        observed_at_ms,
                    )?;
                    Ok(FenceProjection::NeedsReconcile)
                }
            }
        })
    }

    pub fn begin_fence_release(
        &self,
        project_id: &ProjectId,
        attempt_id: Uuid,
        release_safe_receipt_digest: &EvidenceDigest,
        requested_at_ms: i64,
    ) -> Result<FenceLease, StoreError> {
        self.immediate_transaction(|transaction| {
            require_authorized_for_project(transaction, attempt_id, project_id, None)?;
            let Some(release_safe_receipt) =
                load_release_safe_receipt(transaction, attempt_id, release_safe_receipt_digest)?
            else {
                return Err(StoreError::FenceReleaseUnsafe);
            };
            let expected_branch = if load_rollback_takeover(transaction, attempt_id)?.is_some() {
                ExecutorPhaseBranch::RollbackRecovery
            } else {
                ExecutorPhaseBranch::Primary
            };
            if release_safe_receipt.branch != expected_branch {
                return Err(StoreError::FenceReleaseUnsafe);
            }
            let Some(active) = load_active_fence(transaction, project_id)? else {
                let latest = load_latest_fence(transaction, project_id)?
                    .ok_or(StoreError::FenceOwnershipMismatch)?;
                if latest.attempt_id == attempt_id
                    && latest.state == FenceJournalState::Released
                    && latest.release_safe_receipt_digest.as_ref()
                        == Some(release_safe_receipt_digest)
                {
                    return Ok(latest);
                }
                return Err(StoreError::FenceOwnershipMismatch);
            };
            if active.attempt_id != attempt_id {
                return Err(StoreError::FenceOwnershipMismatch);
            }
            match active.state {
                FenceJournalState::Held => {
                    transaction.execute(
                        "UPDATE fence_journal
                         SET state = 'release_intent', release_safe_receipt_digest = ?2,
                             updated_at_ms = ?3
                         WHERE journal_id = ?1",
                        params![
                            active.journal_id,
                            release_safe_receipt_digest.as_str(),
                            requested_at_ms
                        ],
                    )?;
                    Ok(FenceLease {
                        state: FenceJournalState::ReleaseIntent,
                        release_safe_receipt_digest: Some(release_safe_receipt_digest.clone()),
                        ..active
                    })
                }
                FenceJournalState::ReleaseIntent
                    if active.release_safe_receipt_digest.as_ref()
                        == Some(release_safe_receipt_digest) =>
                {
                    Ok(active)
                }
                FenceJournalState::AcquireIntent
                | FenceJournalState::Released
                | FenceJournalState::NeedsReconcile
                | FenceJournalState::ReleaseIntent => Err(StoreError::FenceReleaseUnsafe),
            }
        })
    }

    pub fn active_fence(&self, project_id: &ProjectId) -> Result<Option<FenceLease>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        load_active_fence(&connection, project_id)
    }

    pub fn latest_fence(&self, project_id: &ProjectId) -> Result<Option<FenceLease>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        load_latest_fence(&connection, project_id)
    }

    pub fn fence_acquisition_receipt(
        &self,
        project_id: &ProjectId,
        attempt_id: Uuid,
    ) -> Result<Option<FenceAcquisitionReceiptV1>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        let Some(lease) = load_active_fence(&connection, project_id)? else {
            return Ok(None);
        };
        if lease.attempt_id != attempt_id {
            return Err(StoreError::FenceOwnershipMismatch);
        }
        if !matches!(
            lease.state,
            FenceJournalState::Held | FenceJournalState::ReleaseIntent
        ) {
            return Ok(None);
        }
        fence_receipt_from_lease(&lease).map(Some)
    }

    pub fn active_fences(&self) -> Result<Vec<FenceLease>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        let mut statement = connection.prepare(
            "SELECT project_id FROM fence_journal
             WHERE state != 'released' ORDER BY project_id ASC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut fences = Vec::new();
        for row in rows {
            let project_id = ProjectId::from_str(&row?)
                .map_err(|_| StoreError::CorruptSecurityJournal("project ID"))?;
            fences.push(load_active_fence(&connection, &project_id)?.ok_or(
                StoreError::CorruptSecurityJournal("active fence disappeared"),
            )?);
        }
        Ok(fences)
    }

    fn immediate_transaction<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut connection = lock_connection(&self.connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let output = operation(&transaction)?;
        transaction.commit()?;
        Ok(output)
    }
}

fn persist_signed_executor_intent(
    transaction: &Transaction<'_>,
    intent: &SignedExecutorIntentV1,
    claims: &ExecutorIntentClaimsV1,
    prepared_at_ms: i64,
) -> Result<ExecutorIntentPersistenceV1, StoreError> {
    let key_epoch = i64::try_from(claims.key_epoch).map_err(|_| StoreError::ExecutorIntentRange)?;
    let source_sequence = claims
        .source_sequence
        .map(i64::try_from)
        .transpose()
        .map_err(|_| StoreError::ExecutorIntentRange)?;
    let consequences_json = serde_json::to_string(&claims.consequences)?;
    let operation_kind = operation_kind_name(claims.operation_kind);
    let proposed_release_class = claims.proposed_release_class.map(release_class_name);
    let effective_release_class = claims.effective_release_class.map(release_class_name);
    let (matching_rows, exact_rows): (i64, i64) = transaction.query_row(
        "SELECT COUNT(*), COALESCE(SUM(CASE
            WHEN intent_id = ?1 AND intent_digest = ?2
             AND request_id = ?3 AND compact_token = ?4 THEN 1 ELSE 0 END), 0)
         FROM executor_operation_intents
         WHERE intent_id = ?1 OR intent_digest = ?2
            OR request_id = ?3 OR compact_token = ?4",
        params![
            claims.intent_id.to_string(),
            intent.digest().as_str(),
            claims.request_id.to_string(),
            intent.compact(),
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if matching_rows == 1 && exact_rows == 1 {
        return Ok(ExecutorIntentPersistenceV1::AlreadyPrepared);
    }
    if matching_rows != 0 {
        return Err(StoreError::ExecutorIntentConflict);
    }
    transaction.execute(
        "INSERT INTO executor_operation_intents(
            intent_id, intent_digest, request_id, compact_token,
            schema_version, issuer, authorizer_audience, project_id,
            operation_kind, target_commit, proposed_release_class,
            effective_release_class, installed_policy_digest,
            source_attestation_digest, source_sequence, release_bundle_digest,
            build_attestation_digest, migration_id, previous_release_bundle_digest,
            consequences_json, minimum_role,
            key_id, key_epoch, issued_at_ms, not_before_ms, expires_at_ms,
            prepared_at_ms, state
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
            ?21, ?22, ?23, ?24, ?25, ?26, ?27, 'prepared'
         )",
        params![
            claims.intent_id.to_string(),
            intent.digest().as_str(),
            claims.request_id.to_string(),
            intent.compact(),
            i64::from(claims.schema_version),
            &claims.issuer,
            &claims.authorizer_audience,
            claims.project_id.as_str(),
            operation_kind,
            claims.target_commit.as_ref().map(GitCommitId::as_str),
            proposed_release_class,
            effective_release_class,
            claims.installed_policy_digest.as_str(),
            claims
                .source_attestation_digest
                .as_ref()
                .map(EvidenceDigest::as_str),
            source_sequence,
            claims
                .release_bundle_digest
                .as_ref()
                .map(EvidenceDigest::as_str),
            claims
                .build_attestation_digest
                .as_ref()
                .map(EvidenceDigest::as_str),
            claims.migration_id.as_deref(),
            claims
                .previous_release_bundle_digest
                .as_ref()
                .map(EvidenceDigest::as_str),
            consequences_json,
            claims.minimum_role.as_str(),
            &claims.key_id,
            key_epoch,
            claims.issued_at_ms,
            claims.not_before_ms,
            claims.expires_at_ms,
            prepared_at_ms,
        ],
    )?;
    Ok(ExecutorIntentPersistenceV1::Prepared)
}

fn consume_prepared_intent_grant(
    transaction: &Transaction<'_>,
    context: &PreparedIntentGrantConsumption<'_>,
) -> Result<ActionGrantConsumptionV1, StoreError> {
    let binding = load_prepared_intent_grant_binding(transaction, &context.intent_id)?;
    if let Some(replay) = validate_prepared_intent_grant_binding(&binding, context)? {
        return Ok(replay);
    }
    require_unused_authenticated_action_grant(transaction, context)?;
    insert_authenticated_action_grant(transaction, context)?;
    mark_prepared_intent_consumed(transaction, context)?;
    Ok(ActionGrantConsumptionV1::Consumed)
}

fn load_prepared_intent_grant_binding(
    transaction: &Transaction<'_>,
    intent_id: &str,
) -> Result<PreparedIntentGrantBinding, StoreError> {
    transaction
        .query_row(
            "SELECT intent_digest, request_id, installed_policy_digest,
                    minimum_role, not_before_ms, expires_at_ms, prepared_at_ms, state, attempt_id,
                    action_grant_nonce, action_grant_digest
             FROM executor_operation_intents WHERE intent_id = ?1",
            [intent_id],
            |row| {
                Ok(PreparedIntentGrantBinding {
                    intent_digest: row.get(0)?,
                    request_id: row.get(1)?,
                    installed_policy_digest: row.get(2)?,
                    minimum_role: row.get(3)?,
                    not_before_ms: row.get(4)?,
                    expires_at_ms: row.get(5)?,
                    prepared_at_ms: row.get(6)?,
                    state: row.get(7)?,
                    attempt_id: row.get(8)?,
                    action_grant_nonce: row.get(9)?,
                    action_grant_digest: row.get(10)?,
                })
            },
        )
        .optional()?
        .ok_or(StoreError::ExecutorIntentMissing)
}

fn validate_prepared_intent_grant_binding(
    binding: &PreparedIntentGrantBinding,
    context: &PreparedIntentGrantConsumption<'_>,
) -> Result<Option<ActionGrantConsumptionV1>, StoreError> {
    let claims = context.grant.claims();
    if binding.intent_digest != claims.intent_digest.as_str()
        || binding.request_id != context.request_id
        || binding.installed_policy_digest != claims.installed_policy_digest.as_str()
    {
        return Err(StoreError::ExecutorIntentGrantBinding);
    }
    if binding.state == "consumed" {
        let exact_replay = binding.attempt_id.as_deref() == Some(context.attempt_id.as_str())
            && binding.action_grant_nonce.as_deref() == Some(context.nonce.as_str())
            && binding.action_grant_digest.as_deref() == Some(context.grant.digest().as_str());
        return if exact_replay {
            Ok(Some(ActionGrantConsumptionV1::AlreadyConsumed))
        } else {
            Err(StoreError::ExecutorIntentConsumed)
        };
    }
    if binding.state != "prepared" {
        return Err(StoreError::CorruptSecurityJournal("executor intent state"));
    }
    if context.consumed_at_ms < binding.not_before_ms
        || context.consumed_at_ms < binding.prepared_at_ms
    {
        return Err(StoreError::ExecutorIntentNotCurrent);
    }
    if context.consumed_at_ms >= binding.expires_at_ms
        || context.consumed_at_ms < claims.not_before_ms
        || context.consumed_at_ms >= claims.expires_at_ms
    {
        return Err(StoreError::ExecutorIntentExpired);
    }
    if binding.minimum_role == "admin" && claims.role != ActionGrantRoleV1::Admin {
        return Err(StoreError::ExecutorIntentRole);
    }
    if binding.minimum_role != "admin" && binding.minimum_role != "operator" {
        return Err(StoreError::CorruptSecurityJournal(
            "executor intent minimum role",
        ));
    }
    Ok(None)
}

fn require_unused_authenticated_action_grant(
    transaction: &Transaction<'_>,
    context: &PreparedIntentGrantConsumption<'_>,
) -> Result<(), StoreError> {
    if transaction
        .query_row(
            "SELECT 1 FROM executor_action_grants
             WHERE nonce = ?1 OR grant_digest = ?2",
            params![context.nonce, context.grant.digest().as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        Err(StoreError::ExecutorActionGrantReplay)
    } else {
        Ok(())
    }
}

fn insert_authenticated_action_grant(
    transaction: &Transaction<'_>,
    context: &PreparedIntentGrantConsumption<'_>,
) -> Result<(), StoreError> {
    let claims = context.grant.claims();
    transaction.execute(
        "INSERT INTO executor_action_grants(
            nonce, grant_digest, attempt_id, schema_version, issuer,
            executor_audience, intent_id, intent_digest, request_id,
            actor_id, role, lease_id, lease_generation, key_id, key_epoch,
            installed_policy_digest, issued_at_ms, not_before_ms,
            expires_at_ms, consumed_at_ms
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
         )",
        params![
            context.nonce,
            context.grant.digest().as_str(),
            context.attempt_id,
            i64::from(claims.schema_version),
            &claims.issuer,
            &claims.executor_audience,
            context.intent_id,
            claims.intent_digest.as_str(),
            context.request_id,
            claims.actor_id.to_string(),
            claims.role.as_str(),
            claims.lease_id.to_string(),
            context.lease_generation,
            &claims.key_id,
            context.key_epoch,
            claims.installed_policy_digest.as_str(),
            claims.issued_at_ms,
            claims.not_before_ms,
            claims.expires_at_ms,
            context.consumed_at_ms,
        ],
    )?;
    Ok(())
}

fn mark_prepared_intent_consumed(
    transaction: &Transaction<'_>,
    context: &PreparedIntentGrantConsumption<'_>,
) -> Result<(), StoreError> {
    let updated = transaction.execute(
        "UPDATE executor_operation_intents
         SET state = 'consumed', attempt_id = ?2,
             action_grant_nonce = ?3, action_grant_digest = ?4,
             consumed_at_ms = ?5
         WHERE intent_id = ?1 AND state = 'prepared'",
        params![
            context.intent_id,
            context.attempt_id,
            context.nonce,
            context.grant.digest().as_str(),
            context.consumed_at_ms,
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(StoreError::ExecutorIntentConsumed)
    }
}

fn close_backup_boundary_if_needed(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    storage_phase: &str,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
    committed_at_ms: i64,
) -> Result<(), StoreError> {
    if phase != OperationPhase::BackingUp || branch != ExecutorPhaseBranch::Primary {
        return Ok(());
    }
    let has_bound_spec =
        load_authorized_phase_spec(transaction, attempt_id, storage_phase, phase, branch)?
            .is_some();
    if !has_bound_spec {
        return Ok(());
    }
    let changed = transaction.execute(
        "UPDATE backup_boundary_journal
         SET state = 'released', updated_at_ms = ?2
         WHERE attempt_id = ?1 AND state = 'reserved'",
        params![attempt_id.to_string(), committed_at_ms],
    )?;
    if changed != 1 {
        return Err(StoreError::CorruptSecurityJournal(
            "backup boundary receipt closure",
        ));
    }
    Ok(())
}

fn promote_drain_identity(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    attempt_id: Uuid,
    drain: &DrainIdentityLease,
    created_at_ms: i64,
) -> Result<FenceLease, StoreError> {
    if drain.attempt_id != attempt_id {
        return Err(StoreError::FenceConflict);
    }
    let epoch_i64 = i64::try_from(drain.epoch)
        .map_err(|_| StoreError::CorruptSecurityJournal("fence epoch range"))?;
    let updated = transaction.execute(
        "UPDATE drain_identity_journal
         SET state = 'promoted', updated_at_ms = ?2
         WHERE journal_id = ?1 AND state = 'reserved'",
        params![drain.journal_id, created_at_ms],
    )?;
    if updated != 1 {
        return Err(StoreError::CorruptSecurityJournal(
            "drain identity promotion",
        ));
    }
    transaction.execute(
        "INSERT INTO fence_journal(
            epoch, project_id, attempt_id, token, state, created_at_ms, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, 'acquire_intent', ?5, ?5)",
        params![
            epoch_i64,
            project_id.as_str(),
            attempt_id.to_string(),
            drain.token.to_string(),
            created_at_ms
        ],
    )?;
    Ok(FenceLease {
        journal_id: transaction.last_insert_rowid(),
        project_id: project_id.clone(),
        attempt_id,
        epoch: drain.epoch,
        token: drain.token,
        created_at_ms,
        state: FenceJournalState::AcquireIntent,
        release_safe_receipt_digest: None,
    })
}

fn allocate_fence_identity(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    attempt_id: Uuid,
    created_at_ms: i64,
) -> Result<FenceLease, StoreError> {
    let (epoch, epoch_i64) = allocate_next_fence_epoch(transaction)?;
    let token = Uuid::new_v4();
    transaction.execute(
        "INSERT INTO fence_journal(
            epoch, project_id, attempt_id, token, state, created_at_ms, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, 'acquire_intent', ?5, ?5)",
        params![
            epoch_i64,
            project_id.as_str(),
            attempt_id.to_string(),
            token.to_string(),
            created_at_ms
        ],
    )?;
    Ok(FenceLease {
        journal_id: transaction.last_insert_rowid(),
        project_id: project_id.clone(),
        attempt_id,
        epoch,
        token,
        created_at_ms,
        state: FenceJournalState::AcquireIntent,
        release_safe_receipt_digest: None,
    })
}

fn allocate_next_fence_epoch(transaction: &Transaction<'_>) -> Result<(u64, i64), StoreError> {
    let current: i64 = transaction.query_row(
        "SELECT integer_value FROM security_meta WHERE key = 'fence_epoch'",
        [],
        |row| row.get(0),
    )?;
    let epoch = u64::try_from(current)
        .ok()
        .and_then(|epoch| epoch.checked_add(1))
        .ok_or(StoreError::CorruptSecurityJournal("fence epoch"))?;
    let epoch_i64 = i64::try_from(epoch)
        .map_err(|_| StoreError::CorruptSecurityJournal("fence epoch range"))?;
    transaction.execute(
        "UPDATE security_meta SET integer_value = ?1 WHERE key = 'fence_epoch'",
        [epoch_i64],
    )?;
    Ok((epoch, epoch_i64))
}

fn require_rollback_fence_available(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    project_id: &ProjectId,
) -> Result<(), StoreError> {
    if let Some(active_fence) = load_active_fence(transaction, project_id)? {
        if active_fence.attempt_id != attempt_id || active_fence.state != FenceJournalState::Held {
            return Err(StoreError::FenceReleaseUnsafe);
        }
    } else if load_latest_fence(transaction, project_id)?.is_some_and(|latest| {
        latest.attempt_id == attempt_id && latest.state == FenceJournalState::Released
    }) {
        return Err(StoreError::FenceReleaseUnsafe);
    }
    Ok(())
}

fn select_rollback_forward_snapshot(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    project_id: &ProjectId,
) -> Result<(String, PhaseJournalStatus, EvidenceDigest), StoreError> {
    let mut statement = transaction.prepare(
        "SELECT phase, project_id, status, intent_digest
         FROM executor_phase_journal
         WHERE attempt_id = ?1
           AND status != 'committed'
           AND phase NOT IN (
               'rollback_recovery',
               'rollback_recovery_health_checking',
               'rollback_recovery_soaking'
           )
         ORDER BY phase ASC",
    )?;
    let rows = statement
        .query_map([attempt_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let (phase, stored_project, status, intent_digest) = if let Some(row) = rows.first() {
        if rows.len() != 1
            || row.1 != project_id.as_str()
            || !matches!(row.0.as_str(), "health_checking" | "soaking")
        {
            return Err(StoreError::ExecutorPhaseConflict);
        }
        row.clone()
    } else {
        transaction
            .query_row(
                "SELECT phase, project_id, status, intent_digest
                 FROM executor_phase_journal
                 WHERE attempt_id = ?1
                   AND status = 'committed'
                   AND phase IN ('deploying', 'health_checking', 'soaking')
                 ORDER BY CASE phase
                    WHEN 'deploying' THEN 1
                    WHEN 'health_checking' THEN 2
                    WHEN 'soaking' THEN 3
                    ELSE 0
                 END DESC
                 LIMIT 1",
                [attempt_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::ExecutorPhaseOrder)?
    };
    if stored_project != project_id.as_str() {
        return Err(StoreError::ExecutorAuthorizationBinding);
    }
    let status = PhaseJournalStatus::parse(&status)?;
    let allowed = if status == PhaseJournalStatus::Committed {
        matches!(phase.as_str(), "deploying" | "health_checking" | "soaking")
    } else {
        matches!(phase.as_str(), "health_checking" | "soaking")
            && matches!(
                status,
                PhaseJournalStatus::IntentPersisted
                    | PhaseJournalStatus::Observed
                    | PhaseJournalStatus::Verified
                    | PhaseJournalStatus::NeedsReconcile
            )
    };
    if !allowed {
        return Err(StoreError::ExecutorPhaseConflict);
    }
    Ok((phase, status, parse_digest(&intent_digest)?))
}

fn initialize_security_schema(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS security_meta (
            key TEXT PRIMARY KEY,
            integer_value INTEGER NOT NULL
         ) STRICT;
         INSERT OR IGNORE INTO security_meta(key, integer_value)
            VALUES ('fence_epoch', 0);",
    )?;
    let version = transaction
        .query_row(
            "SELECT integer_value FROM security_meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    migrate_security_schema(&transaction, version)?;
    validate_security_schema(&transaction)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_security_schema(
    transaction: &Transaction<'_>,
    version: Option<i64>,
) -> Result<(), StoreError> {
    require_legacy_security_reconciliation(transaction, version)?;
    match version {
        Some(SECURITY_SCHEMA_VERSION) => {}
        Some(PRE_CANDIDATE_BINDING_SECURITY_SCHEMA_VERSION) => {
            migrate_candidate_binding_schema(transaction)?;
        }
        Some(PRE_BACKUP_BOUNDARY_SECURITY_SCHEMA_VERSION) => {
            validate_security_schema_v12(transaction)?;
            finish_security_schema_upgrade(transaction, &[BACKUP_BOUNDARY_JOURNAL_SCHEMA_SQL])?;
        }
        Some(PRE_EXECUTOR_INTENT_SECURITY_SCHEMA_VERSION) => {
            validate_security_schema_v11(transaction)?;
            finish_security_schema_upgrade(
                transaction,
                &[
                    EXECUTOR_INTENT_SCHEMA_SQL,
                    BACKUP_BOUNDARY_JOURNAL_SCHEMA_SQL,
                ],
            )?;
        }
        Some(PRE_ACTION_GRANT_SECURITY_SCHEMA_VERSION) => {
            validate_security_schema_v10(transaction)?;
            finish_security_schema_upgrade(
                transaction,
                &[
                    ACTION_GRANT_REPLAY_SCHEMA_SQL,
                    EXECUTOR_INTENT_SCHEMA_SQL,
                    BACKUP_BOUNDARY_JOURNAL_SCHEMA_SQL,
                ],
            )?;
        }
        Some(DRAIN_IDENTITY_SECURITY_SCHEMA_VERSION) => {
            validate_security_schema_v9(transaction)?;
            finish_security_schema_upgrade(
                transaction,
                &[
                    DRAIN_IDENTITY_JOURNAL_SCHEMA_SQL,
                    ACTION_GRANT_REPLAY_SCHEMA_SQL,
                    EXECUTOR_INTENT_SCHEMA_SQL,
                    BACKUP_BOUNDARY_JOURNAL_SCHEMA_SQL,
                ],
            )?;
        }
        Some(PHASE_AUTHORITY_SECURITY_SCHEMA_VERSION) => {
            validate_security_schema_v8(transaction)?;
            finish_security_schema_upgrade(
                transaction,
                &[
                    SOURCE_GATE_REJECTIONS_SCHEMA_SQL,
                    DRAIN_IDENTITY_JOURNAL_SCHEMA_SQL,
                    ACTION_GRANT_REPLAY_SCHEMA_SQL,
                    EXECUTOR_INTENT_SCHEMA_SQL,
                    BACKUP_BOUNDARY_JOURNAL_SCHEMA_SQL,
                ],
            )?;
        }
        Some(VERIFIED_BACKUP_SECURITY_SCHEMA_VERSION) => {
            validate_security_schema_v7(transaction)?;
            finish_security_schema_upgrade(
                transaction,
                &[
                    PHASE_AUTHORITY_LEDGER_SCHEMA_SQL,
                    SOURCE_GATE_REJECTIONS_SCHEMA_SQL,
                    DRAIN_IDENTITY_JOURNAL_SCHEMA_SQL,
                    ACTION_GRANT_REPLAY_SCHEMA_SQL,
                    EXECUTOR_INTENT_SCHEMA_SQL,
                    BACKUP_BOUNDARY_JOURNAL_SCHEMA_SQL,
                ],
            )?;
        }
        Some(PREVIOUS_SECURITY_SCHEMA_VERSION) => {
            validate_security_schema_v6(transaction)?;
            finish_security_schema_upgrade(
                transaction,
                &[
                    VERIFIED_BACKUP_CHAINS_SCHEMA_SQL,
                    PHASE_AUTHORITY_LEDGER_SCHEMA_SQL,
                    SOURCE_GATE_REJECTIONS_SCHEMA_SQL,
                    DRAIN_IDENTITY_JOURNAL_SCHEMA_SQL,
                    ACTION_GRANT_REPLAY_SCHEMA_SQL,
                    EXECUTOR_INTENT_SCHEMA_SQL,
                    BACKUP_BOUNDARY_JOURNAL_SCHEMA_SQL,
                ],
            )?;
        }
        Some(version)
            if (LEGACY_SECURITY_SCHEMA_VERSION..=PHASE_SPEC_SECURITY_SCHEMA_VERSION)
                .contains(&version) =>
        {
            migrate_legacy_security_schema(transaction, version)?;
        }
        Some(actual) => {
            return Err(StoreError::UnsupportedSecuritySchemaVersion {
                actual,
                supported: SECURITY_SCHEMA_VERSION,
            });
        }
        None => initialize_unversioned_security_schema(transaction)?,
    }
    Ok(())
}

fn migrate_candidate_binding_schema(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_security_schema_v13(transaction)?;
    rebuild_executor_operation_intents_v14(transaction)?;
    finish_security_schema_upgrade(transaction, &[])
}

fn require_legacy_security_reconciliation(
    transaction: &Transaction<'_>,
    version: Option<i64>,
) -> Result<(), StoreError> {
    if version.is_some_and(|value| {
        (LEGACY_SECURITY_SCHEMA_VERSION..=DRAIN_IDENTITY_SECURITY_SCHEMA_VERSION).contains(&value)
    }) {
        require_empty_legacy_phase_reconciliation(transaction)?;
    }
    Ok(())
}

fn migrate_legacy_security_schema(
    transaction: &Transaction<'_>,
    version: i64,
) -> Result<(), StoreError> {
    let mut schema_batches = vec![
        AUTHORIZED_PHASE_SPECS_SCHEMA_SQL,
        VERIFIED_BACKUP_CHAINS_SCHEMA_SQL,
        PHASE_AUTHORITY_LEDGER_SCHEMA_SQL,
        SOURCE_GATE_REJECTIONS_SCHEMA_SQL,
        DRAIN_IDENTITY_JOURNAL_SCHEMA_SQL,
        ACTION_GRANT_REPLAY_SCHEMA_SQL,
        EXECUTOR_INTENT_SCHEMA_SQL,
        BACKUP_BOUNDARY_JOURNAL_SCHEMA_SQL,
    ];
    match version {
        PHASE_SPEC_SECURITY_SCHEMA_VERSION => validate_security_schema_v5(transaction)?,
        RECEIPT_BOUND_SECURITY_SCHEMA_VERSION => {
            validate_security_schema_v4(transaction)?;
            require_empty_legacy_disk_state(transaction)?;
            require_empty_legacy_receipt_state(transaction)?;
            rebuild_rollback_takeovers_v5(transaction)?;
        }
        ROLLBACK_TAKEOVER_SECURITY_SCHEMA_VERSION => {
            validate_security_schema_v3(transaction)?;
            require_empty_legacy_disk_state(transaction)?;
            require_empty_legacy_receipt_state(transaction)?;
            schema_batches.insert(0, ROLLBACK_TAKEOVER_SCHEMA_SQL);
        }
        LEGACY_SECURITY_SCHEMA_VERSION => {
            validate_security_schema_v2(transaction)?;
            require_empty_legacy_disk_state(transaction)?;
            require_empty_legacy_receipt_state(transaction)?;
            rebuild_active_disk_reservations(transaction)?;
            schema_batches.insert(0, ROLLBACK_TAKEOVER_SCHEMA_SQL);
        }
        _ => {
            return Err(StoreError::UnsupportedSecuritySchemaVersion {
                actual: version,
                supported: SECURITY_SCHEMA_VERSION,
            });
        }
    }
    finish_security_schema_upgrade(transaction, &schema_batches)
}

fn initialize_unversioned_security_schema(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let legacy_authorizations = security_table_exists(transaction, "executor_authorizations")?;
    let legacy_active_reservations =
        security_table_exists(transaction, "active_disk_reservations")?;
    require_empty_legacy_disk_state(transaction)?;
    require_empty_legacy_receipt_state(transaction)?;
    require_empty_legacy_phase_reconciliation(transaction)?;
    transaction.execute_batch(SECURITY_SCHEMA_SQL)?;
    if legacy_authorizations
        && !security_column_exists(
            transaction,
            "executor_authorizations",
            "disk_reservation_json",
        )?
    {
        transaction.execute(
            "ALTER TABLE executor_authorizations ADD COLUMN disk_reservation_json TEXT",
            [],
        )?;
    }
    if legacy_active_reservations
        && !security_column_exists(
            transaction,
            "active_disk_reservations",
            "filesystem_identity",
        )?
    {
        rebuild_active_disk_reservations(transaction)?;
    }
    transaction.execute(
        "INSERT INTO security_meta(key, integer_value) VALUES ('schema_version', ?1)",
        [SECURITY_SCHEMA_VERSION],
    )?;
    Ok(())
}

fn finish_security_schema_upgrade(
    transaction: &Transaction<'_>,
    schema_batches: &[&str],
) -> Result<(), StoreError> {
    for schema in schema_batches {
        transaction.execute_batch(schema)?;
    }
    transaction.execute(
        "UPDATE security_meta SET integer_value = ?1 WHERE key = 'schema_version'",
        [SECURITY_SCHEMA_VERSION],
    )?;
    Ok(())
}

fn require_empty_legacy_disk_state(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    if security_table_exists(transaction, "active_disk_reservations")?
        && transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM active_disk_reservations)",
            [],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Err(StoreError::SecurityDiskMigrationRequiresReconciliation);
    }
    if security_table_exists(transaction, "executor_authorizations")?
        && security_column_exists(
            transaction,
            "executor_authorizations",
            "disk_reservation_json",
        )?
        && transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM executor_authorizations
                WHERE disk_reservation_json IS NOT NULL
             )",
            [],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Err(StoreError::SecurityDiskMigrationRequiresReconciliation);
    }
    Ok(())
}

fn require_empty_legacy_receipt_state(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    if security_table_exists(transaction, "executor_phase_receipts")?
        && transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM executor_phase_receipts)",
            [],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Err(StoreError::SecurityReceiptMigrationRequiresReconciliation);
    }
    Ok(())
}

fn require_empty_legacy_phase_reconciliation(
    transaction: &Transaction<'_>,
) -> Result<(), StoreError> {
    if security_table_exists(transaction, "executor_phase_journal")?
        && security_column_exists(transaction, "executor_phase_journal", "status")?
        && transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM executor_phase_journal WHERE status = 'needs_reconcile'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Err(StoreError::SecurityPhaseMigrationRequiresReconciliation);
    }
    Ok(())
}

fn rebuild_active_disk_reservations(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    transaction.execute("DROP TABLE active_disk_reservations", [])?;
    transaction.execute_batch(ACTIVE_DISK_RESERVATIONS_SCHEMA_SQL)?;
    Ok(())
}

fn rebuild_executor_operation_intents_v14(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    transaction.execute_batch(
        "CREATE TABLE executor_operation_intents_v14 (
            intent_id TEXT PRIMARY KEY,
            intent_digest TEXT NOT NULL UNIQUE,
            request_id TEXT NOT NULL UNIQUE,
            compact_token TEXT NOT NULL UNIQUE,
            schema_version INTEGER NOT NULL CHECK(schema_version IN (1, 2)),
            issuer TEXT NOT NULL,
            authorizer_audience TEXT NOT NULL,
            project_id TEXT NOT NULL,
            operation_kind TEXT NOT NULL CHECK(operation_kind IN (
                'deploy', 'code_rollback', 'backup_only'
            )),
            target_commit TEXT,
            proposed_release_class TEXT CHECK(proposed_release_class IN (
                'code_only_compatible', 'stateful_compatible', 'stateful_breaking', 'rollback'
            )),
            effective_release_class TEXT CHECK(effective_release_class IN (
                'code_only_compatible', 'stateful_compatible', 'stateful_breaking', 'rollback'
            )),
            installed_policy_digest TEXT NOT NULL,
            source_attestation_digest TEXT,
            source_sequence INTEGER CHECK(source_sequence > 0),
            release_bundle_digest TEXT,
            build_attestation_digest TEXT,
            migration_id TEXT,
            previous_release_bundle_digest TEXT,
            consequences_json TEXT NOT NULL,
            minimum_role TEXT NOT NULL CHECK(minimum_role IN ('operator', 'admin')),
            key_id TEXT NOT NULL,
            key_epoch INTEGER NOT NULL CHECK(key_epoch > 0),
            issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms >= 0),
            not_before_ms INTEGER NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            prepared_at_ms INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('prepared', 'consumed')),
            attempt_id TEXT UNIQUE,
            action_grant_nonce TEXT UNIQUE,
            action_grant_digest TEXT,
            consumed_at_ms INTEGER,
            CHECK((source_attestation_digest IS NULL) = (source_sequence IS NULL)),
            CHECK(not_before_ms >= issued_at_ms),
            CHECK(expires_at_ms > not_before_ms),
            CHECK(prepared_at_ms >= not_before_ms AND prepared_at_ms < expires_at_ms),
            CHECK(
                (state = 'prepared' AND attempt_id IS NULL
                    AND action_grant_nonce IS NULL AND action_grant_digest IS NULL
                    AND consumed_at_ms IS NULL)
                OR
                (state = 'consumed' AND attempt_id IS NOT NULL
                    AND action_grant_nonce IS NOT NULL AND action_grant_digest IS NOT NULL
                    AND consumed_at_ms IS NOT NULL)
            ),
            FOREIGN KEY(action_grant_nonce) REFERENCES executor_action_grants(nonce)
        ) STRICT;
        INSERT INTO executor_operation_intents_v14(
            intent_id, intent_digest, request_id, compact_token, schema_version,
            issuer, authorizer_audience, project_id, operation_kind, target_commit,
            proposed_release_class, effective_release_class, installed_policy_digest,
            source_attestation_digest, source_sequence, release_bundle_digest,
            build_attestation_digest, migration_id, previous_release_bundle_digest,
            consequences_json, minimum_role, key_id, key_epoch, issued_at_ms,
            not_before_ms, expires_at_ms, prepared_at_ms, state, attempt_id,
            action_grant_nonce, action_grant_digest, consumed_at_ms
        )
        SELECT intent_id, intent_digest, request_id, compact_token, schema_version,
               issuer, authorizer_audience, project_id, operation_kind, target_commit,
               proposed_release_class, effective_release_class, installed_policy_digest,
               source_attestation_digest, source_sequence, NULL, NULL, migration_id,
               previous_release_bundle_digest, consequences_json, minimum_role, key_id,
               key_epoch, issued_at_ms, not_before_ms, expires_at_ms, prepared_at_ms,
               state, attempt_id, action_grant_nonce, action_grant_digest, consumed_at_ms
        FROM executor_operation_intents;
        DROP TABLE executor_operation_intents;
        ALTER TABLE executor_operation_intents_v14 RENAME TO executor_operation_intents;",
    )?;
    Ok(())
}

fn rebuild_rollback_takeovers_v5(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    transaction.execute_batch(
        "CREATE TABLE executor_rollback_takeovers_v5 (
            attempt_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            forward_phase TEXT NOT NULL CHECK(forward_phase IN (
                'deploying', 'health_checking', 'soaking'
            )),
            forward_status TEXT NOT NULL CHECK(forward_status IN (
                'intent_persisted', 'observed', 'verified', 'committed', 'needs_reconcile'
            )),
            forward_intent_digest TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            CHECK(forward_status = 'committed' OR forward_phase IN (
                'health_checking', 'soaking'
            )),
            FOREIGN KEY(attempt_id, forward_phase)
                REFERENCES executor_phase_journal(attempt_id, phase)
         ) STRICT;
         INSERT INTO executor_rollback_takeovers_v5(
            attempt_id, project_id, forward_phase, forward_status,
            forward_intent_digest, created_at_ms
         )
         SELECT attempt_id, project_id, forward_phase, forward_status,
                forward_intent_digest, created_at_ms
         FROM executor_rollback_takeovers;
         DROP TABLE executor_rollback_takeovers;
         ALTER TABLE executor_rollback_takeovers_v5
            RENAME TO executor_rollback_takeovers;",
    )?;
    Ok(())
}

fn security_table_exists(
    transaction: &Transaction<'_>,
    table: &'static str,
) -> Result<bool, StoreError> {
    Ok(transaction
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn security_column_exists(
    transaction: &Transaction<'_>,
    table: &'static str,
    column: &'static str,
) -> Result<bool, StoreError> {
    let mut statement = transaction.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for existing in columns {
        if existing? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_security_schema(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_security_schema_v13(transaction)?;
    for column in ["release_bundle_digest", "build_attestation_digest"] {
        if !security_column_exists(transaction, "executor_operation_intents", column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

fn validate_security_schema_v13(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_security_schema_v12(transaction)?;
    if !security_table_exists(transaction, "backup_boundary_journal")? {
        return Err(StoreError::CorruptSecuritySchema("backup_boundary_journal"));
    }
    for column in [
        "journal_id",
        "epoch",
        "project_id",
        "attempt_id",
        "token",
        "state",
        "created_at_ms",
        "updated_at_ms",
    ] {
        if !security_column_exists(transaction, "backup_boundary_journal", column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

fn validate_security_schema_v12(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_security_schema_v11(transaction)?;
    if !security_table_exists(transaction, "executor_operation_intents")? {
        return Err(StoreError::CorruptSecuritySchema(
            "executor_operation_intents",
        ));
    }
    for column in [
        "intent_id",
        "intent_digest",
        "request_id",
        "compact_token",
        "schema_version",
        "issuer",
        "authorizer_audience",
        "project_id",
        "operation_kind",
        "target_commit",
        "proposed_release_class",
        "effective_release_class",
        "installed_policy_digest",
        "source_attestation_digest",
        "source_sequence",
        "migration_id",
        "previous_release_bundle_digest",
        "consequences_json",
        "minimum_role",
        "key_id",
        "key_epoch",
        "issued_at_ms",
        "not_before_ms",
        "expires_at_ms",
        "prepared_at_ms",
        "state",
        "attempt_id",
        "action_grant_nonce",
        "action_grant_digest",
        "consumed_at_ms",
    ] {
        if !security_column_exists(transaction, "executor_operation_intents", column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

fn validate_security_schema_v11(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_security_schema_v10(transaction)?;
    if !security_table_exists(transaction, "executor_action_grants")? {
        return Err(StoreError::CorruptSecuritySchema("executor_action_grants"));
    }
    for column in [
        "nonce",
        "grant_digest",
        "attempt_id",
        "schema_version",
        "issuer",
        "executor_audience",
        "intent_id",
        "intent_digest",
        "request_id",
        "actor_id",
        "role",
        "lease_id",
        "lease_generation",
        "key_id",
        "key_epoch",
        "installed_policy_digest",
        "issued_at_ms",
        "not_before_ms",
        "expires_at_ms",
        "consumed_at_ms",
    ] {
        if !security_column_exists(transaction, "executor_action_grants", column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

const fn operation_kind_name(kind: crate::domain::OperationKind) -> &'static str {
    match kind {
        crate::domain::OperationKind::Deploy => "deploy",
        crate::domain::OperationKind::CodeRollback => "code_rollback",
        crate::domain::OperationKind::BackupOnly => "backup_only",
    }
}

const fn release_class_name(class: crate::domain::ReleaseClass) -> &'static str {
    match class {
        crate::domain::ReleaseClass::CodeOnlyCompatible => "code_only_compatible",
        crate::domain::ReleaseClass::StatefulCompatible => "stateful_compatible",
        crate::domain::ReleaseClass::StatefulBreaking => "stateful_breaking",
        crate::domain::ReleaseClass::Rollback => "rollback",
    }
}

fn validate_security_schema_v10(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_security_schema_v9(transaction)?;
    if !security_table_exists(transaction, "drain_identity_journal")? {
        return Err(StoreError::CorruptSecuritySchema("drain_identity_journal"));
    }
    for column in [
        "journal_id",
        "epoch",
        "project_id",
        "attempt_id",
        "token",
        "state",
        "created_at_ms",
        "updated_at_ms",
    ] {
        if !security_column_exists(transaction, "drain_identity_journal", column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

fn validate_security_schema_v9(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_security_schema_v8(transaction)?;
    if !security_table_exists(transaction, "source_gate_rejections")? {
        return Err(StoreError::CorruptSecuritySchema("source_gate_rejections"));
    }
    for column in [
        "attempt_id",
        "phase",
        "project_id",
        "rejected_proof_digest",
        "state",
        "rejected_at_ms",
        "compensated_at_ms",
    ] {
        if !security_column_exists(transaction, "source_gate_rejections", column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

fn validate_security_schema_v8(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_security_schema_v7(transaction)?;
    for table in ["consumed_mutation_grants", "project_bootstrap_ledger"] {
        if !security_table_exists(transaction, table)? {
            return Err(StoreError::CorruptSecuritySchema(table));
        }
    }
    for (table, column) in [
        ("consumed_mutation_grants", "grant_id"),
        ("consumed_mutation_grants", "grant_digest"),
        ("consumed_mutation_grants", "attempt_id"),
        ("consumed_mutation_grants", "project_id"),
        ("consumed_mutation_grants", "phase"),
        ("consumed_mutation_grants", "spec_digest"),
        ("consumed_mutation_grants", "consumed_at_ms"),
        ("project_bootstrap_ledger", "project_id"),
        ("project_bootstrap_ledger", "attempt_id"),
        ("project_bootstrap_ledger", "phase"),
        ("project_bootstrap_ledger", "spec_digest"),
        ("project_bootstrap_ledger", "state"),
        ("project_bootstrap_ledger", "receipt_digest"),
        ("project_bootstrap_ledger", "updated_at_ms"),
    ] {
        if !security_column_exists(transaction, table, column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

fn validate_security_schema_v7(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_security_schema_v6(transaction)?;
    if !security_table_exists(transaction, "verified_backup_chains")? {
        return Err(StoreError::CorruptSecuritySchema("verified_backup_chains"));
    }
    for column in [
        "attempt_id",
        "phase",
        "project_id",
        "authorized_phase_spec_digest",
        "chain_digest",
        "document_digest",
        "canonical_json",
        "persisted_at_ms",
    ] {
        if !security_column_exists(transaction, "verified_backup_chains", column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

fn validate_security_schema_v6(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_security_schema_v5(transaction)?;
    if !security_table_exists(transaction, "authorized_phase_specs")? {
        return Err(StoreError::CorruptSecuritySchema("authorized_phase_specs"));
    }
    for column in [
        "attempt_id",
        "phase",
        "project_id",
        "intent_digest",
        "spec_digest",
        "document_digest",
        "canonical_json",
        "persisted_at_ms",
    ] {
        if !security_column_exists(transaction, "authorized_phase_specs", column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

fn validate_security_schema_v5(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let required_tables = [
        "security_meta",
        "executor_authorizations",
        "executor_phase_journal",
        "executor_rollback_takeovers",
        "executor_phase_receipts",
        "source_gate_proofs",
        "source_trust_highwater",
        "execution_resources",
        "execution_resource_receipts",
        "active_disk_reservations",
        "fence_journal",
    ];
    for table in required_tables {
        if !security_table_exists(transaction, table)? {
            return Err(StoreError::CorruptSecuritySchema(table));
        }
    }
    let required_columns = BTreeSet::from([
        ("executor_authorizations", "disk_reservation_json"),
        ("executor_phase_journal", "artifacts_json"),
        ("executor_rollback_takeovers", "attempt_id"),
        ("executor_rollback_takeovers", "project_id"),
        ("executor_rollback_takeovers", "forward_phase"),
        ("executor_rollback_takeovers", "forward_status"),
        ("executor_rollback_takeovers", "forward_intent_digest"),
        ("executor_rollback_takeovers", "created_at_ms"),
        ("source_gate_proofs", "attestation_digest"),
        ("active_disk_reservations", "reservation_digest"),
        ("active_disk_reservations", "emergency_reserve_bytes"),
        ("active_disk_reservations", "filesystem_identity"),
        ("active_disk_reservations", "observed_at_ms"),
        ("fence_journal", "release_safe_receipt_digest"),
    ]);
    for (table, column) in required_columns {
        if !security_column_exists(transaction, table, column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

fn validate_security_schema_v4(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    validate_security_schema_v5(transaction)
}

fn validate_security_schema_v3(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let required_tables = [
        "security_meta",
        "executor_authorizations",
        "executor_phase_journal",
        "executor_phase_receipts",
        "source_gate_proofs",
        "source_trust_highwater",
        "execution_resources",
        "execution_resource_receipts",
        "active_disk_reservations",
        "fence_journal",
    ];
    for table in required_tables {
        if !security_table_exists(transaction, table)? {
            return Err(StoreError::CorruptSecuritySchema(table));
        }
    }
    let required_columns = BTreeSet::from([
        ("executor_authorizations", "disk_reservation_json"),
        ("executor_phase_journal", "artifacts_json"),
        ("source_gate_proofs", "attestation_digest"),
        ("active_disk_reservations", "reservation_digest"),
        ("active_disk_reservations", "emergency_reserve_bytes"),
        ("active_disk_reservations", "filesystem_identity"),
        ("active_disk_reservations", "observed_at_ms"),
        ("fence_journal", "release_safe_receipt_digest"),
    ]);
    for (table, column) in required_columns {
        if !security_column_exists(transaction, table, column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

fn validate_security_schema_v2(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let required_tables = [
        "security_meta",
        "executor_authorizations",
        "executor_phase_journal",
        "executor_phase_receipts",
        "source_gate_proofs",
        "source_trust_highwater",
        "execution_resources",
        "execution_resource_receipts",
        "active_disk_reservations",
        "fence_journal",
    ];
    for table in required_tables {
        if !security_table_exists(transaction, table)? {
            return Err(StoreError::CorruptSecuritySchema(table));
        }
    }
    let required_columns = BTreeSet::from([
        ("executor_authorizations", "disk_reservation_json"),
        ("executor_phase_journal", "artifacts_json"),
        ("source_gate_proofs", "attestation_digest"),
        ("active_disk_reservations", "reservation_digest"),
        ("fence_journal", "release_safe_receipt_digest"),
    ]);
    for (table, column) in required_columns {
        if !security_column_exists(transaction, table, column)? {
            return Err(StoreError::CorruptSecuritySchema(column));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveDiskReservation {
    project_id: ProjectId,
    required_bytes: u64,
    emergency_reserve_bytes: u64,
    filesystem_identity: EvidenceDigest,
    reservation_digest: EvidenceDigest,
}

impl ActiveDiskReservation {
    fn matches(&self, project_id: &ProjectId, claim: &AuthorizedDiskReservation) -> bool {
        self.project_id == *project_id
            && self.required_bytes == claim.required_bytes
            && self.emergency_reserve_bytes == claim.emergency_reserve_bytes
            && self.filesystem_identity == claim.filesystem_identity
            && self.reservation_digest == claim.reservation_digest
    }
}

fn validate_disk_reservation_authorization(
    authorization: &ExecutorAuthorization,
) -> Result<(), StoreError> {
    if let Some(claim) = &authorization.disk_reservation {
        let digest_is_valid = claim.has_valid_reservation_digest()?;
        if claim.operation_digest != authorization.digest
            || !digest_is_valid
            || claim.required_bytes == 0
            || claim.emergency_reserve_bytes == 0
            || claim.emergency_reserve_bytes >= claim.required_bytes
            || claim.available_bytes < claim.required_bytes
            || claim.observed_at_ms < 0
            || i64::try_from(claim.required_bytes).is_err()
            || i64::try_from(claim.available_bytes).is_err()
            || i64::try_from(claim.emergency_reserve_bytes).is_err()
        {
            return Err(StoreError::DiskReservationAuthorizationInvalid);
        }
    }
    Ok(())
}

fn validate_disk_observation(
    claim: &AuthorizedDiskReservation,
    observation: &DiskAvailabilityObservation,
    now_ms: i64,
) -> Result<(), StoreError> {
    let age_ms = now_ms.checked_sub(observation.observed_at_ms);
    if observation.filesystem_identity != claim.filesystem_identity
        || observation.observed_at_ms < 0
        || !matches!(age_ms, Some(age) if (0..=DISK_OBSERVATION_MAX_AGE_MS).contains(&age))
        || i64::try_from(observation.available_bytes).is_err()
    {
        return Err(StoreError::DiskObservationInvalid);
    }
    Ok(())
}

fn load_authorized_disk_reservation(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    attempt_id: Uuid,
) -> Result<AuthorizedDiskReservation, StoreError> {
    let row = transaction
        .query_row(
            "SELECT project_id, digest, disk_reservation_json
             FROM executor_authorizations WHERE attempt_id = ?1",
            [attempt_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::ExecutorAttemptUnauthorized)?;
    if row.0 != project_id.as_str() {
        return Err(StoreError::ExecutorAuthorizationBinding);
    }
    let claim: AuthorizedDiskReservation = row
        .2
        .as_deref()
        .ok_or(StoreError::DiskReservationAuthorizationMissing)
        .and_then(|json| serde_json::from_str(json).map_err(StoreError::from))?;
    if claim.operation_digest.as_str() != row.1 {
        return Err(StoreError::DiskReservationAuthorizationInvalid);
    }
    if !claim.has_valid_reservation_digest()? {
        return Err(StoreError::DiskReservationAuthorizationInvalid);
    }
    Ok(claim)
}

fn validate_artifact_disk_reservation(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    project_id: &ProjectId,
    artifacts: &PhaseArtifacts,
) -> Result<(), StoreError> {
    let Some(reservation_digest) = &artifacts.resource_reservation_digest else {
        return Ok(());
    };
    let claim = load_authorized_disk_reservation(transaction, project_id, attempt_id)?;
    if claim.reservation_digest == *reservation_digest {
        Ok(())
    } else {
        Err(StoreError::DiskReservationAuthorizationInvalid)
    }
}

fn validate_artifact_source_gate_proof(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    phase: OperationPhase,
    artifacts: &PhaseArtifacts,
    required_by_bound_phase_spec: bool,
) -> Result<(), StoreError> {
    let proof_phase = match phase {
        OperationPhase::BackingUp | OperationPhase::Draining => OperationPhase::BackingUp,
        OperationPhase::Deploying => OperationPhase::Deploying,
        _ => {
            return if artifacts.source_gate_proof_digest.is_none() {
                Ok(())
            } else {
                Err(StoreError::SourceGateProofMismatch)
            };
        }
    };
    let persisted = transaction
        .query_row(
            "SELECT proof_digest FROM source_gate_proofs
             WHERE attempt_id = ?1 AND phase = ?2",
            params![attempt_id.to_string(), phase_name(proof_phase)],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|value| parse_digest(&value))
        .transpose()?;
    if required_by_bound_phase_spec && persisted.is_none() {
        return Err(StoreError::SourceGateProofMismatch);
    }
    if persisted.as_ref() == artifacts.source_gate_proof_digest.as_ref() {
        Ok(())
    } else {
        Err(StoreError::SourceGateProofMismatch)
    }
}

fn bound_spec_requires_source_gate_proof(
    spec: &AuthorizedPhaseSpecV1,
    phase: OperationPhase,
) -> bool {
    if spec.operation_kind != crate::domain::OperationKind::Deploy {
        return false;
    }
    match spec.effective_release_class {
        Some(crate::domain::ReleaseClass::CodeOnlyCompatible) => phase == OperationPhase::Deploying,
        Some(
            crate::domain::ReleaseClass::StatefulCompatible
            | crate::domain::ReleaseClass::StatefulBreaking,
        ) => matches!(phase, OperationPhase::BackingUp | OperationPhase::Draining),
        Some(crate::domain::ReleaseClass::Rollback) | None => false,
    }
}

fn load_active_disk_reservation(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
) -> Result<Option<ActiveDiskReservation>, StoreError> {
    transaction
        .query_row(
            "SELECT project_id, required_bytes, emergency_reserve_bytes,
                    filesystem_identity, reservation_digest
             FROM active_disk_reservations d
             WHERE d.attempt_id = ?1",
            [attempt_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .map(
            |(project_id, required, emergency_reserve, filesystem_identity, reservation_digest)| {
                Ok(ActiveDiskReservation {
                    project_id: ProjectId::from_str(&project_id)
                        .map_err(|_| StoreError::DiskReservationAuthorizationInvalid)?,
                    required_bytes: disk_bytes_from_i64(required)?,
                    emergency_reserve_bytes: disk_bytes_from_i64(emergency_reserve)?,
                    filesystem_identity: parse_digest(&filesystem_identity)?,
                    reservation_digest: parse_digest(&reservation_digest)?,
                })
            },
        )
        .transpose()
}

fn active_disk_reservation_totals(
    transaction: &Transaction<'_>,
    filesystem_identity: &EvidenceDigest,
    excluded_attempt_id: Uuid,
) -> Result<(u64, u64), StoreError> {
    let mut statement = transaction.prepare(
        "SELECT required_bytes, emergency_reserve_bytes
         FROM active_disk_reservations
         WHERE filesystem_identity = ?1 AND attempt_id != ?2",
    )?;
    let rows = statement.query_map(
        params![
            filesystem_identity.as_str(),
            excluded_attempt_id.to_string()
        ],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let mut reserved_operation_bytes = 0_u64;
    let mut emergency_reserve_bytes = 0_u64;
    for row in rows {
        let (required, emergency) = row?;
        let required = disk_bytes_from_i64(required)?;
        let emergency = disk_bytes_from_i64(emergency)?;
        let operation = required
            .checked_sub(emergency)
            .ok_or(StoreError::DiskReservationAuthorizationInvalid)?;
        reserved_operation_bytes = reserved_operation_bytes
            .checked_add(operation)
            .ok_or(StoreError::DiskReservationRange)?;
        emergency_reserve_bytes = emergency_reserve_bytes.max(emergency);
    }
    Ok((reserved_operation_bytes, emergency_reserve_bytes))
}

fn disk_bytes_to_i64(bytes: u64) -> Result<i64, StoreError> {
    i64::try_from(bytes).map_err(|_| StoreError::DiskReservationRange)
}

fn disk_bytes_from_i64(bytes: i64) -> Result<u64, StoreError> {
    u64::try_from(bytes).map_err(|_| StoreError::DiskReservationRange)
}

fn acquire_resource_in_transaction(
    transaction: &Transaction<'_>,
    resource: &ExecutionResource,
    attempt_id: Uuid,
    acquired_at_ms: i64,
) -> Result<(), StoreError> {
    let resource_key = resource.key();
    match resource {
        ExecutionResource::ProjectDeploy(project_id) => {
            require_project_resource_allowed(transaction, project_id, attempt_id)?;
        }
        ExecutionResource::GlobalBuild
        | ExecutionResource::GlobalHeavyIo
        | ExecutionResource::GlobalLocalRegistry => require_authorized(transaction, attempt_id)?,
    }
    acquire_resource_key_in_transaction(transaction, &resource_key, attempt_id, acquired_at_ms)
}

fn require_project_resource_allowed(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    attempt_id: Uuid,
) -> Result<(), StoreError> {
    require_authorized_for_project(transaction, attempt_id, project_id, None)?;
    if load_active_fence(transaction, project_id)?
        .is_some_and(|fence| fence.attempt_id != attempt_id)
        || load_active_drain_identity(transaction, project_id)?
            .is_some_and(|drain| drain.attempt_id != attempt_id)
        || load_active_backup_boundary(transaction, project_id)?
            .is_some_and(|boundary| boundary.attempt_id != attempt_id)
    {
        return Err(StoreError::FenceConflict);
    }
    Ok(())
}

fn acquire_resource_key_in_transaction(
    transaction: &Transaction<'_>,
    resource_key: &str,
    attempt_id: Uuid,
    acquired_at_ms: i64,
) -> Result<(), StoreError> {
    if let Some(owner) = transaction
        .query_row(
            "SELECT owner_attempt_id FROM execution_resources WHERE resource_key = ?1",
            [resource_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        return if owner == attempt_id.to_string() {
            Ok(())
        } else {
            Err(StoreError::ExecutionResourceBusy)
        };
    }
    transaction.execute(
        "INSERT INTO execution_resources(resource_key, owner_attempt_id, acquired_at_ms)
         VALUES (?1, ?2, ?3)",
        params![resource_key, attempt_id.to_string(), acquired_at_ms],
    )?;
    transaction.execute(
        "INSERT INTO execution_resource_receipts(
            resource_key, owner_attempt_id, state, updated_at_ms
         ) VALUES (?1, ?2, 'acquired', ?3)
         ON CONFLICT(resource_key, owner_attempt_id) DO UPDATE SET
            state = 'acquired', updated_at_ms = excluded.updated_at_ms",
        params![resource_key, attempt_id.to_string(), acquired_at_ms],
    )?;
    Ok(())
}

fn release_resource_if_owned_in_transaction(
    transaction: &Transaction<'_>,
    resource: &ExecutionResource,
    attempt_id: Uuid,
    released_at_ms: i64,
) -> Result<(), StoreError> {
    let resource_key = resource.key();
    release_resource_key_if_owned_in_transaction(
        transaction,
        &resource_key,
        attempt_id,
        released_at_ms,
    )
}

fn release_resource_key_if_owned_in_transaction(
    transaction: &Transaction<'_>,
    resource_key: &str,
    attempt_id: Uuid,
    released_at_ms: i64,
) -> Result<(), StoreError> {
    let attempt_id = attempt_id.to_string();
    let owner = transaction
        .query_row(
            "SELECT owner_attempt_id FROM execution_resources WHERE resource_key = ?1",
            [resource_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if owner.as_deref() != Some(attempt_id.as_str()) {
        return Ok(());
    }
    transaction.execute(
        "DELETE FROM execution_resources WHERE resource_key = ?1",
        [resource_key],
    )?;
    transaction.execute(
        "UPDATE execution_resource_receipts
         SET state = 'released', updated_at_ms = ?3
         WHERE resource_key = ?1 AND owner_attempt_id = ?2",
        params![resource_key, attempt_id, released_at_ms],
    )?;
    Ok(())
}

fn disk_reservation_resource_key(project_id: &ProjectId) -> String {
    format!("project:disk_reservation:{project_id}")
}

fn require_authorized(transaction: &Transaction<'_>, attempt_id: Uuid) -> Result<(), StoreError> {
    if transaction
        .query_row(
            "SELECT 1 FROM executor_authorizations WHERE attempt_id = ?1",
            [attempt_id.to_string()],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        Ok(())
    } else {
        Err(StoreError::ExecutorAttemptUnauthorized)
    }
}

fn require_authorized_for_project(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    project_id: &ProjectId,
    digest: Option<&EvidenceDigest>,
) -> Result<(), StoreError> {
    let authorization = transaction
        .query_row(
            "SELECT project_id, digest FROM executor_authorizations WHERE attempt_id = ?1",
            [attempt_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    match authorization {
        Some((authorized_project, authorized_digest))
            if authorized_project == project_id.as_str()
                && digest.is_none_or(|expected| expected.as_str() == authorized_digest) =>
        {
            Ok(())
        }
        Some(_) => Err(StoreError::ExecutorAuthorizationBinding),
        None => Err(StoreError::ExecutorAttemptUnauthorized),
    }
}

fn require_resource_owned(
    transaction: &Transaction<'_>,
    resource: &ExecutionResource,
    attempt_id: Uuid,
) -> Result<(), StoreError> {
    require_resource_key_owned(transaction, &resource.key(), attempt_id)
}

fn require_fence_phase_receipts(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
) -> Result<(), StoreError> {
    for phase in [OperationPhase::BackingUp, OperationPhase::Draining] {
        require_phase_receipt(transaction, attempt_id, phase)?;
    }
    Ok(())
}

fn require_phase_receipt(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    phase: OperationPhase,
) -> Result<(), StoreError> {
    let storage_phase = ExecutorPhaseBranch::Primary.storage_key(phase)?;
    if load_phase_receipt(
        transaction,
        attempt_id,
        storage_phase,
        phase,
        ExecutorPhaseBranch::Primary,
    )?
    .is_some()
    {
        Ok(())
    } else {
        Err(StoreError::FencePhaseInvalid)
    }
}

fn require_resource_key_owned(
    transaction: &Transaction<'_>,
    resource_key: &str,
    attempt_id: Uuid,
) -> Result<(), StoreError> {
    let expected_owner = attempt_id.to_string();
    let owner = transaction
        .query_row(
            "SELECT owner_attempt_id FROM execution_resources WHERE resource_key = ?1",
            [resource_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if owner.as_deref() == Some(expected_owner.as_str()) {
        Ok(())
    } else {
        Err(StoreError::ExecutionResourceOwnership)
    }
}

fn validate_authorized_phase_spec_document(
    binding: AuthorizedPhaseSpecBinding<'_>,
) -> Result<(), StoreError> {
    decode_authorized_phase_spec_document(binding).map(|_| ())
}

fn decode_authorized_phase_spec_document(
    binding: AuthorizedPhaseSpecBinding<'_>,
) -> Result<AuthorizedPhaseSpecV1, StoreError> {
    let spec = AuthorizedPhaseSpecV1::decode_canonical(binding.canonical_json)
        .map_err(|_| StoreError::AuthorizedPhaseSpecInvalid)?;
    if spec.attempt_id != binding.attempt_id
        || spec.project_id != *binding.project_id
        || spec.phase != binding.phase
        || spec.branch != binding.branch
        || spec.intent_digest != *binding.intent_digest
        || spec.spec_digest != *binding.spec_digest
    {
        return Err(StoreError::AuthorizedPhaseSpecBinding);
    }
    Ok(spec)
}

fn validate_verified_prerequisite_chains(
    transaction: &Transaction<'_>,
    spec: &AuthorizedPhaseSpecV1,
) -> Result<(), StoreError> {
    if let Some(expected) = spec.verified_base_backup_chain_digest.as_ref() {
        require_verified_prerequisite_chain(
            transaction,
            spec,
            OperationPhase::BackingUp,
            BackupSnapshotKindV1::Base,
            expected,
        )?;
    }
    if let Some(expected) = spec.verified_cutover_backup_chain_digest.as_ref() {
        require_verified_prerequisite_chain(
            transaction,
            spec,
            OperationPhase::CutoverSnapshotting,
            BackupSnapshotKindV1::Cutover,
            expected,
        )?;
    }
    Ok(())
}

fn require_verified_prerequisite_chain(
    transaction: &Transaction<'_>,
    spec: &AuthorizedPhaseSpecV1,
    phase: OperationPhase,
    expected_kind: BackupSnapshotKindV1,
    expected_digest: &EvidenceDigest,
) -> Result<(), StoreError> {
    let record = if expected_kind == BackupSnapshotKindV1::Base {
        load_committed_base_backup_chain_by_digest(transaction, &spec.project_id, expected_digest)?
    } else {
        let storage_phase = ExecutorPhaseBranch::Primary.storage_key(phase)?;
        load_verified_backup_chain(
            transaction,
            spec.attempt_id,
            storage_phase,
            phase,
            ExecutorPhaseBranch::Primary,
        )?
    }
    .ok_or(StoreError::VerifiedBackupChainMissing)?;
    let chain = VerifiedBackupChainV1::decode_canonical(&record.canonical_json)
        .map_err(|_| StoreError::VerifiedBackupChainInvalid)?;
    if record.project_id != spec.project_id
        || record.chain_digest != *expected_digest
        || chain.snapshot_kind() != expected_kind
        || expected_kind == BackupSnapshotKindV1::Cutover
            && chain.authorized_spec().attempt_id != spec.attempt_id
        || chain.authorized_spec().project_id != spec.project_id
        || chain.authorized_spec().installed_policy != spec.installed_policy
        || chain.authorized_spec().installed_rimg_policy_digest != spec.installed_rimg_policy_digest
    {
        return Err(StoreError::VerifiedBackupChainBinding);
    }
    Ok(())
}

fn load_committed_base_backup_chain_by_digest(
    connection: &Connection,
    project_id: &ProjectId,
    chain_digest: &EvidenceDigest,
) -> Result<Option<VerifiedBackupChainRecord>, StoreError> {
    let storage_phase = ExecutorPhaseBranch::Primary.storage_key(OperationPhase::BackingUp)?;
    let attempt_id = connection
        .query_row(
            "SELECT chains.attempt_id
             FROM verified_backup_chains AS chains
             INNER JOIN executor_phase_journal AS journal
                ON journal.attempt_id = chains.attempt_id
               AND journal.phase = chains.phase
             WHERE chains.project_id = ?1 AND chains.phase = ?2
               AND chains.chain_digest = ?3 AND journal.status = 'committed'",
            params![project_id.as_str(), storage_phase, chain_digest.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    attempt_id
        .map(|attempt_id| {
            let attempt_id = Uuid::parse_str(&attempt_id)
                .map_err(|_| StoreError::CorruptSecurityJournal("backup chain attempt"))?;
            load_verified_backup_chain(
                connection,
                attempt_id,
                storage_phase,
                OperationPhase::BackingUp,
                ExecutorPhaseBranch::Primary,
            )?
            .ok_or(StoreError::CorruptSecurityJournal(
                "verified backup chain lookup",
            ))
        })
        .transpose()
}

fn validate_active_fence_for_spec(
    transaction: &Transaction<'_>,
    spec: &AuthorizedPhaseSpecV1,
) -> Result<(), StoreError> {
    match (spec.fencing_epoch, spec.fence_receipt_digest.as_ref()) {
        (None, None) => {
            if load_active_fence(transaction, &spec.project_id)?.is_some() {
                Err(StoreError::FenceConflict)
            } else {
                Ok(())
            }
        }
        (Some(epoch), Some(expected_digest)) => {
            let lease = load_active_fence(transaction, &spec.project_id)?
                .ok_or(StoreError::FenceOwnershipMismatch)?;
            if lease.attempt_id != spec.attempt_id
                || lease.epoch != epoch
                || !matches!(
                    lease.state,
                    FenceJournalState::Held | FenceJournalState::ReleaseIntent
                )
            {
                return Err(StoreError::FenceOwnershipMismatch);
            }
            let receipt = fence_receipt_from_lease(&lease)?;
            if receipt.receipt_digest != *expected_digest {
                return Err(StoreError::FenceOwnershipMismatch);
            }
            Ok(())
        }
        _ => Err(StoreError::AuthorizedPhaseSpecBinding),
    }
}

fn consume_mutation_grant(
    transaction: &Transaction<'_>,
    spec: &AuthorizedPhaseSpecV1,
    storage_phase: &str,
    consumed_at_ms: i64,
) -> Result<(), StoreError> {
    let (Some(grant_id), Some(grant_digest)) =
        (spec.mutation_grant_id, spec.mutation_grant_digest.as_ref())
    else {
        return Ok(());
    };
    let existing = transaction
        .query_row(
            "SELECT grant_digest, attempt_id, project_id, phase, spec_digest
             FROM consumed_mutation_grants WHERE grant_id = ?1",
            [grant_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    if let Some(existing) = existing {
        return if existing.0 == grant_digest.as_str()
            && existing.1 == spec.attempt_id.to_string()
            && existing.2 == spec.project_id.as_str()
            && existing.3 == storage_phase
            && existing.4 == spec.spec_digest.as_str()
        {
            Ok(())
        } else {
            Err(StoreError::MutationGrantReplay)
        };
    }
    if transaction
        .query_row(
            "SELECT 1 FROM consumed_mutation_grants WHERE grant_digest = ?1",
            [grant_digest.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Err(StoreError::MutationGrantReplay);
    }
    transaction.execute(
        "INSERT INTO consumed_mutation_grants(
            grant_id, grant_digest, attempt_id, project_id, phase, spec_digest, consumed_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            grant_id.to_string(),
            grant_digest.as_str(),
            spec.attempt_id.to_string(),
            spec.project_id.as_str(),
            storage_phase,
            spec.spec_digest.as_str(),
            consumed_at_ms,
        ],
    )?;
    Ok(())
}

fn validate_consumed_mutation_grant(
    transaction: &Transaction<'_>,
    spec: &AuthorizedPhaseSpecV1,
    storage_phase: &str,
) -> Result<(), StoreError> {
    let (Some(grant_id), Some(grant_digest)) =
        (spec.mutation_grant_id, spec.mutation_grant_digest.as_ref())
    else {
        return Ok(());
    };
    let exact = transaction
        .query_row(
            "SELECT 1 FROM consumed_mutation_grants
             WHERE grant_id = ?1 AND grant_digest = ?2 AND attempt_id = ?3
               AND project_id = ?4 AND phase = ?5 AND spec_digest = ?6",
            params![
                grant_id.to_string(),
                grant_digest.as_str(),
                spec.attempt_id.to_string(),
                spec.project_id.as_str(),
                storage_phase,
                spec.spec_digest.as_str(),
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exact {
        Ok(())
    } else {
        Err(StoreError::MutationGrantReplay)
    }
}

fn reserve_bootstrap(
    transaction: &Transaction<'_>,
    spec: &AuthorizedPhaseSpecV1,
    storage_phase: &str,
    reserved_at_ms: i64,
) -> Result<(), StoreError> {
    if spec.runtime_release_state != Some(RuntimeReleaseStateV1::NeverInstalled) {
        return Ok(());
    }
    if spec.phase != OperationPhase::Deploying || storage_phase != "deploying" {
        return Err(StoreError::AuthorizedPhaseSpecBinding);
    }
    let existing = transaction
        .query_row(
            "SELECT attempt_id, phase, spec_digest
             FROM project_bootstrap_ledger WHERE project_id = ?1",
            [spec.project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    if let Some(existing) = existing {
        return if existing.0 == spec.attempt_id.to_string()
            && existing.1 == storage_phase
            && existing.2 == spec.spec_digest.as_str()
        {
            Ok(())
        } else {
            Err(StoreError::BootstrapAlreadyClaimed)
        };
    }
    transaction.execute(
        "INSERT INTO project_bootstrap_ledger(
            project_id, attempt_id, phase, spec_digest, state, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, 'reserved', ?5)",
        params![
            spec.project_id.as_str(),
            spec.attempt_id.to_string(),
            storage_phase,
            spec.spec_digest.as_str(),
            reserved_at_ms,
        ],
    )?;
    Ok(())
}

fn validate_bootstrap_reservation(
    transaction: &Transaction<'_>,
    spec: &AuthorizedPhaseSpecV1,
    storage_phase: &str,
) -> Result<(), StoreError> {
    if spec.runtime_release_state != Some(RuntimeReleaseStateV1::NeverInstalled) {
        return Ok(());
    }
    let exact = transaction
        .query_row(
            "SELECT 1 FROM project_bootstrap_ledger
             WHERE project_id = ?1 AND attempt_id = ?2 AND phase = ?3
               AND spec_digest = ?4
               AND (
                   (state = 'reserved' AND receipt_digest IS NULL)
                   OR (state = 'committed' AND receipt_digest IS NOT NULL)
               )",
            params![
                spec.project_id.as_str(),
                spec.attempt_id.to_string(),
                storage_phase,
                spec.spec_digest.as_str(),
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exact {
        Ok(())
    } else {
        Err(StoreError::BootstrapPermitMissing)
    }
}

fn commit_bootstrap_ledger_if_needed(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    storage_phase: &str,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
    receipt: &PhaseReceipt,
    committed_at_ms: i64,
) -> Result<(), StoreError> {
    let Some(record) =
        load_authorized_phase_spec(transaction, attempt_id, storage_phase, phase, branch)?
    else {
        return Ok(());
    };
    let spec = decode_authorized_phase_spec_document(AuthorizedPhaseSpecBinding {
        attempt_id,
        project_id: &record.project_id,
        phase,
        branch,
        intent_digest: &record.intent_digest,
        spec_digest: &record.spec_digest,
        canonical_json: &record.canonical_json,
        persisted_at_ms: record.persisted_at_ms,
    })?;
    if spec.runtime_release_state != Some(RuntimeReleaseStateV1::NeverInstalled) {
        return Ok(());
    }
    let existing = transaction
        .query_row(
            "SELECT attempt_id, phase, spec_digest, state, receipt_digest
             FROM project_bootstrap_ledger WHERE project_id = ?1",
            [spec.project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::BootstrapPermitMissing)?;
    let exact_binding = existing.0 == attempt_id.to_string()
        && existing.1 == storage_phase
        && existing.2 == spec.spec_digest.as_str();
    if !exact_binding {
        return Err(StoreError::BootstrapAlreadyClaimed);
    }
    match (existing.3.as_str(), existing.4.as_deref()) {
        ("reserved", None) => {
            transaction.execute(
                "UPDATE project_bootstrap_ledger
                 SET state = 'committed', receipt_digest = ?2, updated_at_ms = ?3
                 WHERE project_id = ?1",
                params![
                    spec.project_id.as_str(),
                    receipt.receipt_digest.as_str(),
                    committed_at_ms,
                ],
            )?;
            Ok(())
        }
        ("committed", Some(digest)) if digest == receipt.receipt_digest.as_str() => Ok(()),
        _ => Err(StoreError::CorruptSecurityJournal("bootstrap ledger state")),
    }
}

fn prepare_verified_backup_chain(
    binding: VerifiedBackupChainBinding<'_>,
) -> Result<PreparedVerifiedBackupChain, StoreError> {
    if binding.attempt_id.is_nil() || binding.persisted_at_ms < 0 {
        return Err(StoreError::VerifiedBackupChainInvalid);
    }
    binding
        .chain
        .require_verified()
        .map_err(|_| StoreError::VerifiedBackupChainInvalid)?;
    let expected_kind = match binding.phase {
        OperationPhase::BackingUp => BackupSnapshotKindV1::Base,
        OperationPhase::CutoverSnapshotting => BackupSnapshotKindV1::Cutover,
        _ => return Err(StoreError::VerifiedBackupChainBinding),
    };
    if binding.chain.snapshot_kind() != expected_kind
        || binding.chain.authorized_spec().attempt_id != binding.attempt_id
        || binding.chain.authorized_spec().project_id != *binding.project_id
    {
        return Err(StoreError::VerifiedBackupChainBinding);
    }
    let canonical_json = binding
        .chain
        .canonical_bytes()
        .map_err(|_| StoreError::VerifiedBackupChainInvalid)?;
    if canonical_json.is_empty() || canonical_json.len() > MAX_VERIFIED_BACKUP_CHAIN_DOCUMENT_BYTES
    {
        return Err(StoreError::VerifiedBackupChainInvalid);
    }
    Ok(PreparedVerifiedBackupChain {
        storage_phase: binding.branch.storage_key(binding.phase)?,
        document_digest: EvidenceDigest::sha256(&canonical_json),
        canonical_json,
    })
}

fn load_authorized_phase_spec(
    connection: &Connection,
    attempt_id: Uuid,
    storage_phase: &str,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
) -> Result<Option<AuthorizedPhaseSpecRecord>, StoreError> {
    connection
        .query_row(
            "SELECT project_id, intent_digest, spec_digest, document_digest,
                    canonical_json, persisted_at_ms
             FROM authorized_phase_specs WHERE attempt_id = ?1 AND phase = ?2",
            params![attempt_id.to_string(), storage_phase],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?
        .map(
            |(
                project_id,
                intent_digest,
                spec_digest,
                document_digest,
                canonical_json,
                persisted_at_ms,
            )| {
                Ok(AuthorizedPhaseSpecRecord {
                    attempt_id,
                    project_id: ProjectId::from_str(&project_id).map_err(|_| {
                        StoreError::CorruptSecurityJournal("authorized phase project")
                    })?,
                    phase,
                    branch,
                    intent_digest: parse_digest(&intent_digest)?,
                    spec_digest: parse_digest(&spec_digest)?,
                    document_digest: parse_digest(&document_digest)?,
                    canonical_json,
                    persisted_at_ms,
                })
            },
        )
        .transpose()
}

fn load_verified_backup_chain(
    connection: &Connection,
    attempt_id: Uuid,
    storage_phase: &str,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
) -> Result<Option<VerifiedBackupChainRecord>, StoreError> {
    connection
        .query_row(
            "SELECT project_id, authorized_phase_spec_digest, chain_digest,
                    document_digest, canonical_json, persisted_at_ms
             FROM verified_backup_chains WHERE attempt_id = ?1 AND phase = ?2",
            params![attempt_id.to_string(), storage_phase],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?
        .map(
            |(
                project_id,
                authorized_phase_spec_digest,
                chain_digest,
                document_digest,
                canonical_json,
                persisted_at_ms,
            )| {
                let project_id = ProjectId::from_str(&project_id)
                    .map_err(|_| StoreError::CorruptSecurityJournal("backup chain project"))?;
                let record = VerifiedBackupChainRecord {
                    attempt_id,
                    project_id,
                    phase,
                    branch,
                    authorized_phase_spec_digest: parse_digest(&authorized_phase_spec_digest)?,
                    chain_digest: parse_digest(&chain_digest)?,
                    document_digest: parse_digest(&document_digest)?,
                    canonical_json,
                    persisted_at_ms,
                };
                let chain = VerifiedBackupChainV1::decode_canonical(&record.canonical_json)
                    .map_err(|_| {
                        StoreError::CorruptSecurityJournal("verified backup chain document")
                    })?;
                if chain.chain_digest() != &record.chain_digest
                    || EvidenceDigest::sha256(&record.canonical_json) != record.document_digest
                {
                    return Err(StoreError::CorruptSecurityJournal(
                        "verified backup chain row binding",
                    ));
                }
                Ok(record)
            },
        )
        .transpose()
}

fn load_latest_committed_base_backup_chain(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Option<VerifiedBackupChainRecord>, StoreError> {
    let storage_phase = ExecutorPhaseBranch::Primary.storage_key(OperationPhase::BackingUp)?;
    connection
        .query_row(
            "SELECT chains.attempt_id, chains.authorized_phase_spec_digest,
                    chains.chain_digest, chains.document_digest, chains.canonical_json,
                    chains.persisted_at_ms
             FROM verified_backup_chains AS chains
             INNER JOIN executor_phase_journal AS journal
                ON journal.attempt_id = chains.attempt_id
               AND journal.phase = chains.phase
             WHERE chains.project_id = ?1 AND chains.phase = ?2
               AND journal.status = 'committed'
             ORDER BY journal.updated_at_ms DESC, chains.persisted_at_ms DESC,
                      chains.attempt_id DESC
             LIMIT 1",
            params![project_id.as_str(), storage_phase],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?
        .map(
            |(
                attempt_id,
                authorized_phase_spec_digest,
                chain_digest,
                document_digest,
                canonical_json,
                persisted_at_ms,
            )| {
                let attempt_id = Uuid::parse_str(&attempt_id)
                    .map_err(|_| StoreError::CorruptSecurityJournal("backup chain attempt"))?;
                let record = VerifiedBackupChainRecord {
                    attempt_id,
                    project_id: project_id.clone(),
                    phase: OperationPhase::BackingUp,
                    branch: ExecutorPhaseBranch::Primary,
                    authorized_phase_spec_digest: parse_digest(&authorized_phase_spec_digest)?,
                    chain_digest: parse_digest(&chain_digest)?,
                    document_digest: parse_digest(&document_digest)?,
                    canonical_json,
                    persisted_at_ms,
                };
                let chain = VerifiedBackupChainV1::decode_canonical(&record.canonical_json)
                    .map_err(|_| {
                        StoreError::CorruptSecurityJournal("verified backup chain document")
                    })?;
                if chain.snapshot_kind() != BackupSnapshotKindV1::Base
                    || chain.authorized_spec().attempt_id != record.attempt_id
                    || chain.authorized_spec().project_id != record.project_id
                    || chain.chain_digest() != &record.chain_digest
                    || EvidenceDigest::sha256(&record.canonical_json) != record.document_digest
                {
                    return Err(StoreError::CorruptSecurityJournal(
                        "verified backup chain row binding",
                    ));
                }
                Ok(record)
            },
        )
        .transpose()
}

fn validate_bound_phase_spec_artifact(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    storage_phase: &str,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
    artifacts: &PhaseArtifacts,
) -> Result<Option<AuthorizedPhaseSpecV1>, StoreError> {
    let bound_record =
        load_authorized_phase_spec(transaction, attempt_id, storage_phase, phase, branch)?;
    let bound_digest = bound_record.as_ref().map(|record| &record.spec_digest);
    match (
        bound_digest,
        artifacts.authorized_phase_spec_digest.as_ref(),
    ) {
        (None, None) => return Ok(None),
        (Some(bound), Some(observed)) if bound == observed => Ok(()),
        (Some(_), None) => Err(StoreError::AuthorizedPhaseSpecMissing),
        (None | Some(_), Some(_)) => Err(StoreError::AuthorizedPhaseSpecBinding),
    }?;
    let record = bound_record
        .as_ref()
        .ok_or(StoreError::AuthorizedPhaseSpecMissing)?;
    let decoded_spec = decode_authorized_phase_spec_document(AuthorizedPhaseSpecBinding {
        attempt_id,
        project_id: &record.project_id,
        phase,
        branch,
        intent_digest: &record.intent_digest,
        spec_digest: &record.spec_digest,
        canonical_json: &record.canonical_json,
        persisted_at_ms: record.persisted_at_ms,
    })?;
    decoded_spec
        .validate_observed_artifacts(artifacts)
        .map_err(|_| StoreError::AuthorizedPhaseArtifactMismatch)?;
    validate_verified_prerequisite_chains(transaction, &decoded_spec)?;
    validate_active_fence_for_spec(transaction, &decoded_spec)?;
    validate_consumed_mutation_grant(transaction, &decoded_spec, storage_phase)?;
    validate_bootstrap_reservation(transaction, &decoded_spec, storage_phase)?;
    let expected_kind = match phase {
        OperationPhase::BackingUp => Some(BackupSnapshotKindV1::Base),
        OperationPhase::CutoverSnapshotting => Some(BackupSnapshotKindV1::Cutover),
        _ => None,
    };
    let Some(expected_kind) = expected_kind else {
        return Ok(Some(decoded_spec));
    };
    let record = load_verified_backup_chain(transaction, attempt_id, storage_phase, phase, branch)?
        .ok_or(StoreError::VerifiedBackupChainMissing)?;
    if record.authorized_phase_spec_digest
        != *bound_digest.ok_or(StoreError::AuthorizedPhaseSpecMissing)?
    {
        return Err(StoreError::VerifiedBackupChainBinding);
    }
    let chain = VerifiedBackupChainV1::decode_canonical(&record.canonical_json)
        .map_err(|_| StoreError::VerifiedBackupChainInvalid)?;
    if chain.snapshot_kind() != expected_kind {
        return Err(StoreError::VerifiedBackupChainBinding);
    }
    let spec = chain.authorized_spec();
    let manifest = chain.manifest();
    let local = chain.local();
    let matches = match expected_kind {
        BackupSnapshotKindV1::Base => {
            artifacts.backup_set_id == Some(spec.backup_set_id)
                && artifacts.base_backup_id == Some(spec.backup_id)
                && artifacts.base_backup_manifest_digest.as_ref() == Some(&manifest.manifest_digest)
                && artifacts.base_backup_evidence_digest.as_ref() == Some(&local.evidence_digest)
                && artifacts.base_backup_offsite_evidence_digest.as_ref()
                    == chain.offsite().map(|evidence| &evidence.evidence_digest)
                && artifacts.base_backup_verification_digest.as_ref() == Some(chain.chain_digest())
        }
        BackupSnapshotKindV1::Cutover => {
            artifacts.backup_set_id == Some(spec.backup_set_id)
                && artifacts.cutover_backup_id == Some(spec.backup_id)
                && artifacts.cutover_backup_manifest_digest.as_ref()
                    == Some(&manifest.manifest_digest)
                && artifacts.cutover_backup_evidence_digest.as_ref() == Some(&local.evidence_digest)
                && artifacts.cutover_backup_verification_digest.as_ref()
                    == Some(chain.chain_digest())
                && artifacts.fencing_epoch == spec.fencing_epoch
        }
    };
    if matches {
        Ok(Some(decoded_spec))
    } else {
        Err(StoreError::VerifiedBackupChainBinding)
    }
}

struct MutationStatusProjectionV1 {
    completed_phases: Vec<OperationPhase>,
    current_phase: OperationPhase,
    state: MutationExecutionStateV1,
    updated_at_ms: i64,
}

impl MutationStatusProjectionV1 {
    fn new(current_phase: OperationPhase, updated_at_ms: i64) -> Self {
        Self {
            completed_phases: Vec::new(),
            current_phase,
            state: MutationExecutionStateV1::Accepted,
            updated_at_ms,
        }
    }
}

fn project_mutation_status_branch(
    connection: &Connection,
    attempt_id: Uuid,
    phases: &[OperationPhase],
    branch: ExecutorPhaseBranch,
    empty_state: MutationExecutionStateV1,
    projection: &mut MutationStatusProjectionV1,
) -> Result<bool, StoreError> {
    let mut found_gap = false;
    for phase in phases {
        let storage_phase = branch.storage_key(*phase)?;
        let entry = load_phase_entry(connection, attempt_id, storage_phase, *phase)?;
        let receipt = load_phase_receipt(connection, attempt_id, storage_phase, *phase, branch)?;
        if let Some(entry) = entry.as_ref() {
            projection.updated_at_ms = projection.updated_at_ms.max(entry.updated_at_ms);
        }
        if let Some(receipt) = receipt.as_ref() {
            projection.updated_at_ms = projection.updated_at_ms.max(receipt.committed_at_ms);
        }
        match (entry, receipt) {
            (Some(entry), Some(_))
                if !found_gap && entry.status == PhaseJournalStatus::Committed =>
            {
                projection.completed_phases.push(*phase);
                projection.current_phase = *phase;
                projection.state = MutationExecutionStateV1::Running;
            }
            (Some(entry), None) if !found_gap && entry.status != PhaseJournalStatus::Committed => {
                found_gap = true;
                projection.current_phase = *phase;
                projection.state = if entry.status == PhaseJournalStatus::NeedsReconcile {
                    MutationExecutionStateV1::NeedsReconcile
                } else {
                    MutationExecutionStateV1::Running
                };
            }
            (None, None) if !found_gap => {
                found_gap = true;
                projection.current_phase = *phase;
                projection.state = if projection.completed_phases.is_empty() {
                    empty_state
                } else {
                    MutationExecutionStateV1::Running
                };
            }
            (None, None) => {}
            _ => return Err(StoreError::ExecutorPhaseOrder),
        }
    }
    Ok(!found_gap)
}

fn load_phase_entry(
    connection: &Connection,
    attempt_id: Uuid,
    storage_phase: &str,
    expected_phase: OperationPhase,
) -> Result<Option<PhaseJournalEntry>, StoreError> {
    let row = connection
        .query_row(
            "SELECT project_id, intent_digest, observation_digest, artifacts_json,
                    status, updated_at_ms
             FROM executor_phase_journal WHERE attempt_id = ?1 AND phase = ?2",
            params![attempt_id.to_string(), storage_phase],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(project_id, intent_digest, observation_digest, artifacts_json, status, updated_at_ms)| {
            Ok(PhaseJournalEntry {
                attempt_id,
                project_id: ProjectId::from_str(&project_id)
                    .map_err(|_| StoreError::CorruptSecurityJournal("project ID"))?,
                phase: expected_phase,
                intent_digest: parse_digest(&intent_digest)?,
                observation_digest: observation_digest
                    .as_deref()
                    .map(parse_digest)
                    .transpose()?,
                artifacts: serde_json::from_str(&artifacts_json)?,
                status: PhaseJournalStatus::parse(&status)?,
                updated_at_ms,
            })
        },
    )
    .transpose()
}

fn load_rollback_takeover(
    connection: &Connection,
    attempt_id: Uuid,
) -> Result<Option<RollbackTakeover>, StoreError> {
    let row = connection
        .query_row(
            "SELECT
                takeover.project_id,
                takeover.forward_phase,
                takeover.forward_status,
                takeover.forward_intent_digest,
                takeover.created_at_ms,
                journal.project_id,
                journal.status,
                journal.intent_digest
             FROM executor_rollback_takeovers AS takeover
             LEFT JOIN executor_phase_journal AS journal
               ON journal.attempt_id = takeover.attempt_id
              AND journal.phase = takeover.forward_phase
             WHERE takeover.attempt_id = ?1",
            [attempt_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            project_id,
            forward_phase,
            forward_status,
            forward_intent_digest,
            created_at_ms,
            journal_project_id,
            journal_status,
            journal_intent_digest,
        )| {
            if journal_project_id.as_deref() != Some(project_id.as_str())
                || journal_status.as_deref() != Some(forward_status.as_str())
                || journal_intent_digest.as_deref() != Some(forward_intent_digest.as_str())
            {
                return Err(StoreError::CorruptSecurityJournal(
                    "rollback takeover journal binding",
                ));
            }
            let forward_status = PhaseJournalStatus::parse(&forward_status)?;
            let forward_phase = rollback_takeover_phase(&forward_phase)?;
            let valid_forward_snapshot = if forward_status == PhaseJournalStatus::Committed {
                matches!(
                    forward_phase,
                    OperationPhase::Deploying
                        | OperationPhase::HealthChecking
                        | OperationPhase::Soaking
                )
            } else {
                matches!(
                    forward_phase,
                    OperationPhase::HealthChecking | OperationPhase::Soaking
                ) && matches!(
                    forward_status,
                    PhaseJournalStatus::IntentPersisted
                        | PhaseJournalStatus::Observed
                        | PhaseJournalStatus::Verified
                        | PhaseJournalStatus::NeedsReconcile
                )
            };
            if !valid_forward_snapshot {
                return Err(StoreError::CorruptSecurityJournal(
                    "rollback takeover forward status",
                ));
            }
            Ok(RollbackTakeover {
                attempt_id,
                project_id: ProjectId::from_str(&project_id)
                    .map_err(|_| StoreError::CorruptSecurityJournal("project ID"))?,
                forward_phase,
                forward_status,
                forward_intent_digest: parse_digest(&forward_intent_digest)?,
                created_at_ms,
            })
        },
    )
    .transpose()
}

fn rollback_takeover_phase(value: &str) -> Result<OperationPhase, StoreError> {
    match value {
        "deploying" => Ok(OperationPhase::Deploying),
        "health_checking" => Ok(OperationPhase::HealthChecking),
        "soaking" => Ok(OperationPhase::Soaking),
        _ => Err(StoreError::CorruptSecurityJournal(
            "rollback takeover forward phase",
        )),
    }
}

fn has_uncommitted_phase_conflict(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    branch: ExecutorPhaseBranch,
) -> Result<bool, StoreError> {
    let takeover = if branch == ExecutorPhaseBranch::RollbackRecovery {
        load_rollback_takeover(transaction, attempt_id)?
    } else {
        None
    };
    let ignored_forward_phase = takeover
        .as_ref()
        .map(|takeover| phase_name(takeover.forward_phase));
    let mut statement = transaction.prepare(
        "SELECT phase FROM executor_phase_journal
         WHERE attempt_id = ?1 AND status != 'committed'",
    )?;
    let phases = statement
        .query_map([attempt_id.to_string()], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(phases
        .iter()
        .any(|phase| Some(phase.as_str()) != ignored_forward_phase))
}

fn require_branch_not_taken_over(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    branch: ExecutorPhaseBranch,
) -> Result<(), StoreError> {
    if branch == ExecutorPhaseBranch::Primary
        && load_rollback_takeover(transaction, attempt_id)?.is_some()
    {
        Err(StoreError::ExecutorPhaseOrder)
    } else {
        Ok(())
    }
}

fn mark_phase_needs_reconcile(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    storage_phase: &str,
    updated_at_ms: i64,
) -> Result<(), StoreError> {
    let changed = transaction.execute(
        "UPDATE executor_phase_journal
         SET status = 'needs_reconcile', updated_at_ms = ?3
         WHERE attempt_id = ?1 AND phase = ?2 AND status != 'committed'",
        params![attempt_id.to_string(), storage_phase, updated_at_ms],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::ExecutorPhaseState)
    }
}

fn require_phase_prerequisites(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
    phase_plan: &ExecutorPhasePlan<'_>,
) -> Result<(), StoreError> {
    let ordered = phase_plan.ordered_phases;
    if ordered.is_empty()
        || ordered
            .iter()
            .enumerate()
            .any(|(index, candidate)| ordered[..index].contains(candidate))
        || ordered.contains(&OperationPhase::Reconciliation)
    {
        return Err(StoreError::ExecutorPhaseOrder);
    }
    let mut statement = transaction.prepare(
        "SELECT phase FROM executor_phase_journal
         WHERE attempt_id = ?1 AND status = 'committed'",
    )?;
    let committed = statement
        .query_map([attempt_id.to_string()], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    let rollback_takeover = load_rollback_takeover(transaction, attempt_id)?;
    match branch {
        ExecutorPhaseBranch::Primary => {
            if rollback_takeover.is_some() {
                return Err(StoreError::ExecutorPhaseOrder);
            }
            let (required, allowed) = normal_phase_sets(ordered, phase)?;
            if required.iter().any(|required_phase| {
                !committed
                    .iter()
                    .any(|value| value == phase_name(*required_phase))
            }) || committed.iter().any(|value| {
                !allowed
                    .iter()
                    .any(|allowed_phase| value == phase_name(*allowed_phase))
            }) {
                return Err(StoreError::ExecutorPhaseOrder);
            }
            Ok(())
        }
        ExecutorPhaseBranch::RollbackRecovery => require_rollback_recovery_prerequisites(
            ordered,
            phase,
            phase_plan.recovery_rollback_allowed,
            &committed,
        ),
    }
}

fn normal_phase_sets(
    ordered: &[OperationPhase],
    phase: OperationPhase,
) -> Result<(Vec<OperationPhase>, Vec<OperationPhase>), StoreError> {
    let position = ordered
        .iter()
        .position(|candidate| *candidate == phase)
        .ok_or(StoreError::ExecutorPhaseOrder)?;
    Ok((ordered[..position].to_vec(), ordered[..=position].to_vec()))
}

fn require_rollback_recovery_prerequisites(
    ordered: &[OperationPhase],
    phase: OperationPhase,
    recovery_rollback_allowed: bool,
    committed: &[String],
) -> Result<(), StoreError> {
    if !recovery_rollback_allowed {
        return Err(StoreError::ExecutorPhaseOrder);
    }
    let deploy_position = ordered
        .iter()
        .position(|candidate| *candidate == OperationPhase::Deploying)
        .ok_or(StoreError::ExecutorPhaseOrder)?;
    let primary_keys = ordered
        .iter()
        .map(|candidate| phase_name(*candidate))
        .collect::<Vec<_>>();
    let committed_set = committed
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    let mut prefix_ended = false;
    for key in &primary_keys {
        if committed_set.contains(*key) {
            if prefix_ended {
                return Err(StoreError::ExecutorPhaseOrder);
            }
        } else {
            prefix_ended = true;
        }
    }
    if primary_keys[..=deploy_position]
        .iter()
        .any(|required| !committed_set.contains(*required))
    {
        return Err(StoreError::ExecutorPhaseOrder);
    }

    let rollback = ExecutorPhaseBranch::RollbackRecovery.storage_key(OperationPhase::Rollback)?;
    let health =
        ExecutorPhaseBranch::RollbackRecovery.storage_key(OperationPhase::HealthChecking)?;
    let soaking = ExecutorPhaseBranch::RollbackRecovery.storage_key(OperationPhase::Soaking)?;
    let (required_branch, allowed_branch): (&[&str], &[&str]) = match phase {
        OperationPhase::Rollback => (&[], &[rollback]),
        OperationPhase::HealthChecking => (&[rollback], &[rollback, health]),
        OperationPhase::Soaking => (&[rollback, health], &[rollback, health, soaking]),
        _ => return Err(StoreError::ExecutorPhaseOrder),
    };
    if required_branch
        .iter()
        .any(|required| !committed_set.contains(*required))
        || committed.iter().any(|value| {
            !primary_keys.contains(&value.as_str()) && !allowed_branch.contains(&value.as_str())
        })
    {
        return Err(StoreError::ExecutorPhaseOrder);
    }
    Ok(())
}

fn source_trust_regressed(
    transaction: &Transaction<'_>,
    proof: &SourceGateProofRecord,
    sequence: i64,
) -> Result<bool, StoreError> {
    Ok(transaction
        .query_row(
            "SELECT source_sequence, attestation_digest FROM source_trust_highwater
             WHERE project_id = ?1",
            [proof.project_id.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .is_some_and(|(trusted_sequence, trusted_digest)| {
            trusted_sequence > sequence
                || (trusted_sequence == sequence
                    && trusted_digest != proof.attestation_digest.as_str())
        }))
}

fn validate_source_gate_proof_admission(
    transaction: &Transaction<'_>,
    proof: &SourceGateProofRecord,
    storage_phase: &str,
) -> Result<Result<i64, StoreError>, StoreError> {
    let entry = load_phase_entry(transaction, proof.attempt_id, storage_phase, proof.phase)?
        .ok_or(StoreError::ExecutorPhaseState)?;
    if entry.status != PhaseJournalStatus::IntentPersisted {
        return Err(StoreError::ExecutorPhaseState);
    }
    if entry.project_id != proof.project_id {
        return reject_source_gate_proof(
            transaction,
            proof,
            storage_phase,
            StoreError::SourceGateProofMismatch,
        );
    }
    if proof.source_sequence == 0 {
        return reject_source_gate_proof(
            transaction,
            proof,
            storage_phase,
            StoreError::SourceTrustRollback,
        );
    }
    let Ok(sequence) = i64::try_from(proof.source_sequence) else {
        return reject_source_gate_proof(
            transaction,
            proof,
            storage_phase,
            StoreError::SequenceRange,
        );
    };
    if source_trust_regressed(transaction, proof, sequence)? {
        return reject_source_gate_proof(
            transaction,
            proof,
            storage_phase,
            StoreError::SourceTrustRollback,
        );
    }
    Ok(Ok(sequence))
}

fn persist_source_gate_proof(
    transaction: &Transaction<'_>,
    proof: &SourceGateProofRecord,
    storage_phase: &str,
    sequence: i64,
) -> Result<Result<(), StoreError>, StoreError> {
    if let Some((existing, existing_project, existing_sequence, existing_attestation)) = transaction
        .query_row(
            "SELECT proof_digest, project_id, source_sequence, attestation_digest
                 FROM source_gate_proofs
                 WHERE attempt_id = ?1 AND phase = ?2",
            params![proof.attempt_id.to_string(), phase_name(proof.phase)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
    {
        if existing == proof.proof_digest.as_str()
            && existing_project == proof.project_id.as_str()
            && existing_sequence == sequence
            && existing_attestation == proof.attestation_digest.as_str()
        {
            return Ok(Ok(()));
        }
        return reject_source_gate_proof(
            transaction,
            proof,
            storage_phase,
            StoreError::SourceGateProofMismatch,
        );
    }
    transaction.execute(
        "INSERT INTO source_gate_proofs(
            attempt_id, phase, proof_digest, project_id, source_sequence,
            attestation_digest, checked_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            proof.attempt_id.to_string(),
            phase_name(proof.phase),
            proof.proof_digest.as_str(),
            proof.project_id.as_str(),
            sequence,
            proof.attestation_digest.as_str(),
            proof.checked_at_ms
        ],
    )?;
    transaction.execute(
        "INSERT INTO source_trust_highwater(
            project_id, source_sequence, attestation_digest, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(project_id) DO UPDATE SET
            source_sequence = excluded.source_sequence,
            attestation_digest = excluded.attestation_digest,
            updated_at_ms = excluded.updated_at_ms
         WHERE source_trust_highwater.source_sequence < excluded.source_sequence",
        params![
            proof.project_id.as_str(),
            sequence,
            proof.attestation_digest.as_str(),
            proof.checked_at_ms
        ],
    )?;
    Ok(Ok(()))
}

fn reject_source_gate_proof<T>(
    transaction: &Transaction<'_>,
    proof: &SourceGateProofRecord,
    storage_phase: &str,
    error: StoreError,
) -> Result<Result<T, StoreError>, StoreError> {
    let changed = transaction.execute(
        "INSERT INTO source_gate_rejections(
            attempt_id, phase, project_id, rejected_proof_digest,
            state, rejected_at_ms, compensated_at_ms
         )
         SELECT attempt_id, phase, project_id, ?3, 'abort_pending', ?4, NULL
         FROM executor_phase_journal
         WHERE attempt_id = ?1 AND phase = ?2 AND status = 'intent_persisted'
         ON CONFLICT(attempt_id, phase) DO UPDATE SET
            project_id = excluded.project_id,
            rejected_proof_digest = excluded.rejected_proof_digest,
            state = 'abort_pending',
            rejected_at_ms = excluded.rejected_at_ms,
            compensated_at_ms = NULL",
        params![
            proof.attempt_id.to_string(),
            storage_phase,
            proof.proof_digest.as_str(),
            proof.checked_at_ms
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::ExecutorPhaseState);
    }
    mark_phase_needs_reconcile(
        transaction,
        proof.attempt_id,
        storage_phase,
        proof.checked_at_ms,
    )?;
    Ok(Err(error))
}

fn load_phase_receipt(
    connection: &Connection,
    attempt_id: Uuid,
    storage_phase: &str,
    expected_phase: OperationPhase,
    expected_branch: ExecutorPhaseBranch,
) -> Result<Option<PhaseReceipt>, StoreError> {
    connection
        .query_row(
            "SELECT receipt_digest, receipt_json FROM executor_phase_receipts
             WHERE attempt_id = ?1 AND phase = ?2",
            params![attempt_id.to_string(), storage_phase],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .map(|(stored_digest, json)| {
            decode_bound_phase_receipt(
                attempt_id,
                expected_phase,
                expected_branch,
                &stored_digest,
                &json,
            )
        })
        .transpose()
}

fn decode_bound_phase_receipt(
    attempt_id: Uuid,
    expected_phase: OperationPhase,
    expected_branch: ExecutorPhaseBranch,
    stored_digest: &str,
    json: &str,
) -> Result<PhaseReceipt, StoreError> {
    let receipt: PhaseReceipt = serde_json::from_str(json)
        .map_err(|_| StoreError::CorruptSecurityJournal("phase receipt JSON"))?;
    if receipt.attempt_id == attempt_id
        && receipt.phase == expected_phase
        && receipt.branch == expected_branch
        && receipt.receipt_digest.as_str() == stored_digest
        && receipt
            .has_valid_digest()
            .map_err(|_| StoreError::CorruptSecurityJournal("phase receipt digest payload"))?
    {
        Ok(receipt)
    } else {
        Err(StoreError::CorruptSecurityJournal(
            "phase receipt row binding or digest",
        ))
    }
}

fn load_active_fence(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Option<FenceLease>, StoreError> {
    load_fence_with_predicate(
        connection,
        project_id,
        "state != 'released' ORDER BY epoch DESC LIMIT 1",
    )
}

fn load_active_drain_identity(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Option<DrainIdentityLease>, StoreError> {
    let row = connection
        .query_row(
            "SELECT journal_id, attempt_id, epoch, token, created_at_ms
             FROM drain_identity_journal
             WHERE project_id = ?1 AND state = 'reserved'
             ORDER BY epoch DESC LIMIT 1",
            [project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    row.map(|(journal_id, attempt_id, epoch, token, created_at_ms)| {
        Ok(DrainIdentityLease {
            journal_id,
            project_id: project_id.clone(),
            attempt_id: parse_uuid(&attempt_id, "drain attempt UUID")?,
            epoch: u64::try_from(epoch)
                .map_err(|_| StoreError::CorruptSecurityJournal("drain epoch"))?,
            token: parse_uuid(&token, "drain token UUID")?,
            created_at_ms,
        })
    })
    .transpose()
}

fn load_active_backup_boundary(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Option<BackupBoundaryLease>, StoreError> {
    let row = connection
        .query_row(
            "SELECT journal_id, attempt_id, epoch, token, created_at_ms
             FROM backup_boundary_journal
             WHERE project_id = ?1 AND state = 'reserved'
             ORDER BY epoch DESC LIMIT 1",
            [project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    row.map(|(journal_id, attempt_id, epoch, token, created_at_ms)| {
        Ok(BackupBoundaryLease {
            journal_id,
            project_id: project_id.clone(),
            attempt_id: parse_uuid(&attempt_id, "backup boundary attempt UUID")?,
            epoch: u64::try_from(epoch)
                .map_err(|_| StoreError::CorruptSecurityJournal("backup boundary epoch"))?,
            token: parse_uuid(&token, "backup boundary token UUID")?,
            created_at_ms,
        })
    })
    .transpose()
}

fn load_latest_fence(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Option<FenceLease>, StoreError> {
    load_fence_with_predicate(connection, project_id, "1 = 1 ORDER BY epoch DESC LIMIT 1")
}

fn load_fence_with_predicate(
    connection: &Connection,
    project_id: &ProjectId,
    predicate: &str,
) -> Result<Option<FenceLease>, StoreError> {
    let sql = format!(
        "SELECT journal_id, attempt_id, epoch, token, state, release_safe_receipt_digest,
                created_at_ms
         FROM fence_journal WHERE project_id = ?1 AND {predicate}"
    );
    let row = connection
        .query_row(&sql, [project_id.as_str()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .optional()?;
    row.map(
        |(
            journal_id,
            attempt_id,
            epoch,
            token,
            state,
            release_safe_receipt_digest,
            created_at_ms,
        )| {
            Ok(FenceLease {
                journal_id,
                project_id: project_id.clone(),
                attempt_id: parse_uuid(&attempt_id, "fence attempt UUID")?,
                epoch: u64::try_from(epoch)
                    .map_err(|_| StoreError::CorruptSecurityJournal("fence epoch"))?,
                token: parse_uuid(&token, "fence token UUID")?,
                created_at_ms,
                state: FenceJournalState::parse(&state)?,
                release_safe_receipt_digest: release_safe_receipt_digest
                    .as_deref()
                    .map(parse_digest)
                    .transpose()?,
            })
        },
    )
    .transpose()
}

fn release_safe_receipt_exists(
    connection: &Connection,
    attempt_id: Uuid,
    digest: &EvidenceDigest,
) -> Result<bool, StoreError> {
    Ok(load_release_safe_receipt(connection, attempt_id, digest)?.is_some())
}

fn load_release_safe_receipt(
    connection: &Connection,
    attempt_id: Uuid,
    digest: &EvidenceDigest,
) -> Result<Option<PhaseReceipt>, StoreError> {
    let row = connection
        .query_row(
            "SELECT phase, receipt_digest, receipt_json FROM executor_phase_receipts
             WHERE attempt_id = ?1 AND receipt_digest = ?2",
            params![attempt_id.to_string(), digest.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(storage_phase, stored_digest, json)| {
        let (expected_phase, expected_branch) = match storage_phase.as_str() {
            "soaking" => (OperationPhase::Soaking, ExecutorPhaseBranch::Primary),
            "rollback_recovery_soaking" => (
                OperationPhase::Soaking,
                ExecutorPhaseBranch::RollbackRecovery,
            ),
            "rollback" => (OperationPhase::Rollback, ExecutorPhaseBranch::Primary),
            _ => return Ok(None),
        };
        decode_bound_phase_receipt(
            attempt_id,
            expected_phase,
            expected_branch,
            &stored_digest,
            &json,
        )
        .map(Some)
    })
    .transpose()
    .map(Option::flatten)
}

fn set_fence_state(
    transaction: &Transaction<'_>,
    journal_id: i64,
    state: FenceJournalState,
    updated_at_ms: i64,
) -> Result<(), StoreError> {
    let changed = transaction.execute(
        "UPDATE fence_journal SET state = ?2, updated_at_ms = ?3 WHERE journal_id = ?1",
        params![journal_id, state.as_str(), updated_at_ms],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::CorruptSecurityJournal(
            "missing fence journal row",
        ))
    }
}

fn accepted_mutation_storage_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<AcceptedMutationStorageRow> {
    Ok(AcceptedMutationStorageRow {
        intent_id: row.get(0)?,
        intent_digest: row.get(1)?,
        compact_token: row.get(2)?,
        attempt_id: row.get(3)?,
        request_id: row.get(4)?,
        project_id: row.get(5)?,
        operation_kind: row.get(6)?,
        target_commit: row.get(7)?,
        proposed_release_class: row.get(8)?,
        effective_release_class: row.get(9)?,
        installed_policy_digest: row.get(10)?,
        source_attestation_digest: row.get(11)?,
        source_sequence: row.get(12)?,
        release_bundle_digest: row.get(13)?,
        build_attestation_digest: row.get(14)?,
        migration_id: row.get(15)?,
        previous_release_bundle_digest: row.get(16)?,
        intent_expires_at_ms: row.get(17)?,
        consumed_at_ms: row.get(18)?,
        action_grant_nonce: row.get(19)?,
        intent_action_grant_digest: row.get(20)?,
        grant_nonce: row.get(21)?,
        grant_digest: row.get(22)?,
        grant_attempt_id: row.get(23)?,
        grant_intent_id: row.get(24)?,
        grant_intent_digest: row.get(25)?,
        grant_request_id: row.get(26)?,
        grant_installed_policy_digest: row.get(27)?,
        actor_id: row.get(28)?,
        role: row.get(29)?,
        lease_id: row.get(30)?,
        lease_generation: row.get(31)?,
        grant_expires_at_ms: row.get(32)?,
    })
}

fn decode_accepted_mutation(
    stored: AcceptedMutationStorageRow,
) -> Result<AcceptedMutationV1, StoreError> {
    let corrupt = || StoreError::CorruptSecurityJournal("accepted mutation binding");
    let grant = decode_accepted_grant_binding(&stored)?;
    let intent_id = parse_uuid(&stored.intent_id, "accepted mutation intent ID")?;
    let request_id = parse_uuid(&stored.request_id, "accepted mutation request ID")?;
    if intent_id.is_nil() || request_id.is_nil() {
        return Err(corrupt());
    }
    let project_id = ProjectId::from_str(&stored.project_id).map_err(|_| corrupt())?;
    let operation_kind = parse_operation_kind(&stored.operation_kind)?;
    let target_commit = stored
        .target_commit
        .as_deref()
        .map(GitCommitId::from_str)
        .transpose()
        .map_err(|_| corrupt())?;
    let proposed_release_class = stored
        .proposed_release_class
        .as_deref()
        .map(parse_release_class)
        .transpose()?;
    let effective_release_class = stored
        .effective_release_class
        .as_deref()
        .map(parse_release_class)
        .transpose()?;
    let source_attestation_digest = stored
        .source_attestation_digest
        .as_deref()
        .map(parse_digest)
        .transpose()?;
    let source_sequence = stored
        .source_sequence
        .map(u64::try_from)
        .transpose()
        .map_err(|_| corrupt())?;
    let release_bundle_digest = stored
        .release_bundle_digest
        .as_deref()
        .map(parse_digest)
        .transpose()?;
    let build_attestation_digest = stored
        .build_attestation_digest
        .as_deref()
        .map(parse_digest)
        .transpose()?;
    let previous_release_bundle_digest = stored
        .previous_release_bundle_digest
        .as_deref()
        .map(parse_digest)
        .transpose()?;
    validate_accepted_mutation_shape(&AcceptedMutationShape {
        operation_kind,
        target_commit: &target_commit,
        proposed_release_class,
        effective_release_class,
        source_attestation_digest: &source_attestation_digest,
        source_sequence,
        release_bundle_digest: &release_bundle_digest,
        build_attestation_digest: &build_attestation_digest,
        migration_id: &stored.migration_id,
        previous_release_bundle_digest: &previous_release_bundle_digest,
    })?;

    Ok(AcceptedMutationV1 {
        intent_id,
        intent_digest: parse_digest(&stored.intent_digest)?,
        signed_intent: stored.compact_token,
        attempt_id: grant.attempt_id,
        request_id,
        project_id,
        operation_kind,
        target_commit,
        proposed_release_class,
        effective_release_class,
        installed_policy_digest: parse_digest(&stored.installed_policy_digest)?,
        source_attestation_digest,
        source_sequence,
        release_bundle_digest,
        build_attestation_digest,
        migration_id: stored.migration_id,
        previous_release_bundle_digest,
        intent_expires_at_ms: stored.intent_expires_at_ms,
        actor_id: grant.actor_id,
        action_grant_role: grant.role,
        action_grant_nonce: grant.nonce,
        action_grant_digest: grant.digest,
        lease_id: grant.lease_id,
        lease_generation: grant.lease_generation,
        grant_expires_at_ms: grant.expires_at_ms,
        accepted_at_ms: grant.accepted_at_ms,
    })
}

fn decode_accepted_grant_binding(
    stored: &AcceptedMutationStorageRow,
) -> Result<AcceptedMutationGrantBinding, StoreError> {
    let corrupt = || StoreError::CorruptSecurityJournal("accepted mutation binding");
    let attempt = stored.attempt_id.as_deref().ok_or_else(corrupt)?;
    let accepted_at_ms = stored.consumed_at_ms.ok_or_else(corrupt)?;
    let intent_nonce = stored.action_grant_nonce.as_deref().ok_or_else(corrupt)?;
    let intent_grant_digest = stored
        .intent_action_grant_digest
        .as_deref()
        .ok_or_else(corrupt)?;
    let nonce = stored.grant_nonce.as_deref().ok_or_else(corrupt)?;
    let digest = stored.grant_digest.as_deref().ok_or_else(corrupt)?;
    let grant_attempt = stored.grant_attempt_id.as_deref().ok_or_else(corrupt)?;
    let grant_intent = stored.grant_intent_id.as_deref().ok_or_else(corrupt)?;
    let grant_intent_digest = stored.grant_intent_digest.as_deref().ok_or_else(corrupt)?;
    let grant_request = stored.grant_request_id.as_deref().ok_or_else(corrupt)?;
    let grant_policy = stored
        .grant_installed_policy_digest
        .as_deref()
        .ok_or_else(corrupt)?;
    let expires_at_ms = stored.grant_expires_at_ms.ok_or_else(corrupt)?;
    if intent_nonce != nonce
        || intent_grant_digest != digest
        || attempt != grant_attempt
        || stored.intent_id != grant_intent
        || stored.intent_digest != grant_intent_digest
        || stored.request_id != grant_request
        || stored.installed_policy_digest != grant_policy
        || stored.compact_token.is_empty()
        || stored.compact_token.len() > 24 * 1024
        || accepted_at_ms < 0
        || accepted_at_ms >= stored.intent_expires_at_ms
        || accepted_at_ms >= expires_at_ms
    {
        return Err(corrupt());
    }
    let role = match stored.role.as_deref().ok_or_else(corrupt)? {
        "operator" => ActionGrantRoleV1::Operator,
        "admin" => ActionGrantRoleV1::Admin,
        _ => return Err(corrupt()),
    };
    let binding = AcceptedMutationGrantBinding {
        attempt_id: parse_uuid(attempt, "accepted mutation attempt ID")?,
        actor_id: parse_uuid(
            stored.actor_id.as_deref().ok_or_else(corrupt)?,
            "accepted mutation actor ID",
        )?,
        role,
        nonce: parse_uuid(nonce, "accepted mutation grant nonce")?,
        digest: parse_digest(digest)?,
        lease_id: parse_uuid(
            stored.lease_id.as_deref().ok_or_else(corrupt)?,
            "accepted mutation lease ID",
        )?,
        lease_generation: u64::try_from(stored.lease_generation.ok_or_else(corrupt)?)
            .map_err(|_| corrupt())?,
        expires_at_ms,
        accepted_at_ms,
    };
    if binding.attempt_id.is_nil()
        || binding.actor_id.is_nil()
        || binding.nonce.is_nil()
        || binding.lease_id.is_nil()
        || binding.lease_generation == 0
    {
        return Err(corrupt());
    }
    Ok(binding)
}

fn validate_accepted_mutation_shape(shape: &AcceptedMutationShape<'_>) -> Result<(), StoreError> {
    let proposed_valid = match shape.operation_kind {
        OperationKind::Deploy => matches!(
            shape.proposed_release_class,
            Some(
                ReleaseClass::CodeOnlyCompatible
                    | ReleaseClass::StatefulCompatible
                    | ReleaseClass::StatefulBreaking
            )
        ),
        OperationKind::CodeRollback => shape.proposed_release_class == Some(ReleaseClass::Rollback),
        OperationKind::BackupOnly => shape.proposed_release_class.is_none(),
    };
    let source_present = shape.source_attestation_digest.is_some();
    let migration_required = matches!(
        shape.effective_release_class,
        Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking)
    );
    let candidate_binding_valid = match shape.operation_kind {
        OperationKind::Deploy => {
            shape.release_bundle_digest.is_some() && shape.build_attestation_digest.is_some()
        }
        OperationKind::CodeRollback => {
            shape.release_bundle_digest.is_some() && shape.build_attestation_digest.is_none()
        }
        OperationKind::BackupOnly => {
            shape.release_bundle_digest.is_none() && shape.build_attestation_digest.is_none()
        }
    };
    let valid = shape.operation_kind.requires_commit() == shape.target_commit.is_some()
        && shape
            .operation_kind
            .required_phases(shape.effective_release_class)
            .is_ok()
        && proposed_valid
        && source_present == shape.source_sequence.is_some()
        && source_present == shape.operation_kind.requires_commit()
        && shape.source_sequence.is_none_or(|value| value > 0)
        && candidate_binding_valid
        && shape.migration_id.is_some() == migration_required
        && shape.migration_id.as_deref().is_none_or(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        && ((shape.operation_kind == OperationKind::CodeRollback)
            == shape.previous_release_bundle_digest.is_some()
            || shape.operation_kind == OperationKind::Deploy);
    if valid {
        Ok(())
    } else {
        Err(StoreError::CorruptSecurityJournal(
            "accepted mutation operation binding",
        ))
    }
}

fn parse_operation_kind(value: &str) -> Result<OperationKind, StoreError> {
    match value {
        "deploy" => Ok(OperationKind::Deploy),
        "code_rollback" => Ok(OperationKind::CodeRollback),
        "backup_only" => Ok(OperationKind::BackupOnly),
        _ => Err(StoreError::CorruptSecurityJournal(
            "accepted mutation operation kind",
        )),
    }
}

fn parse_release_class(value: &str) -> Result<ReleaseClass, StoreError> {
    match value {
        "code_only_compatible" => Ok(ReleaseClass::CodeOnlyCompatible),
        "stateful_compatible" => Ok(ReleaseClass::StatefulCompatible),
        "stateful_breaking" => Ok(ReleaseClass::StatefulBreaking),
        "rollback" => Ok(ReleaseClass::Rollback),
        _ => Err(StoreError::CorruptSecurityJournal(
            "accepted mutation release class",
        )),
    }
}

fn parse_digest(value: &str) -> Result<EvidenceDigest, StoreError> {
    EvidenceDigest::from_str(value)
        .map_err(|_| StoreError::CorruptSecurityJournal("evidence digest"))
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(value).map_err(|_| StoreError::CorruptSecurityJournal(field))
}

const fn phase_name(phase: OperationPhase) -> &'static str {
    match phase {
        OperationPhase::Queued => "queued",
        OperationPhase::SyncingSource => "syncing_source",
        OperationPhase::VerifyingSource => "verifying_source",
        OperationPhase::Testing => "testing",
        OperationPhase::Building => "building",
        OperationPhase::Preflight => "preflight",
        OperationPhase::BackingUp => "backing_up",
        OperationPhase::Draining => "draining",
        OperationPhase::CutoverSnapshotting => "cutover_snapshotting",
        OperationPhase::Migrating => "migrating",
        OperationPhase::Deploying => "deploying",
        OperationPhase::HealthChecking => "health_checking",
        OperationPhase::Soaking => "soaking",
        OperationPhase::Rollback => "rollback",
        OperationPhase::Reconciliation => "reconciliation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{InstalledPolicyIdentity, OperationKind, ReleaseClass};
    use crate::phase6::{AUTHORIZED_PHASE_SPEC_SCHEMA_VERSION, RimgTimeoutPolicyV1};
    use tempfile::tempdir;

    fn ledger_spec(grant_id: Uuid, grant_digest: EvidenceDigest) -> AuthorizedPhaseSpecV1 {
        AuthorizedPhaseSpecV1 {
            schema_version: AUTHORIZED_PHASE_SPEC_SCHEMA_VERSION,
            attempt_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            project_id: ProjectId::from_str("grant-ledger")
                .unwrap_or_else(|error| panic!("project: {error}")),
            operation_kind: OperationKind::Deploy,
            phase: OperationPhase::Migrating,
            branch: ExecutorPhaseBranch::Primary,
            intent_digest: EvidenceDigest::sha256("intent"),
            executor_authorization_digest: EvidenceDigest::sha256("authorization"),
            installed_policy: InstalledPolicyIdentity {
                digest: EvidenceDigest::sha256("policy"),
                version: 1,
            },
            installed_rimg_policy_digest: EvidenceDigest::sha256("rimg-policy"),
            release_bundle_digest: None,
            deployment_plan_digest: None,
            timeouts: RimgTimeoutPolicyV1 {
                backup_ms: 300_000,
                drain_ms: 60_000,
                migration_ms: 300_000,
                deploy_ms: 300_000,
                readiness_ms: 60_000,
                smoke_ms: 180_000,
                soak_ms: 600_000,
            },
            proposed_release_class: Some(ReleaseClass::StatefulBreaking),
            effective_release_class: Some(ReleaseClass::StatefulBreaking),
            classification_evidence_digest: Some(EvidenceDigest::sha256("classification")),
            migration_id: Some("migration-v1".to_owned()),
            backup: None,
            verified_base_backup_chain_digest: Some(EvidenceDigest::sha256("base-chain")),
            verified_cutover_backup_chain_digest: Some(EvidenceDigest::sha256("cutover-chain")),
            trusted_clock_evidence_digest: Some(EvidenceDigest::sha256("clock")),
            boundary_now_ms: Some(10),
            prerequisites_valid_through_ms: Some(20),
            fencing_epoch: Some(1),
            fence_receipt_digest: Some(EvidenceDigest::sha256("fence")),
            mutation_grant_id: Some(grant_id),
            mutation_grant_digest: Some(grant_digest),
            runtime_release_state: None,
            runtime_release_state_evidence_digest: None,
            expected_observation_artifacts: PhaseArtifacts::default(),
            steps: Vec::new(),
            spec_digest: EvidenceDigest::sha256(Uuid::new_v4().as_bytes()),
        }
    }

    #[test]
    fn mutation_grant_ledger_allows_exact_replay_and_rejects_reuse() {
        let mut connection = Connection::open_in_memory()
            .unwrap_or_else(|error| panic!("open grant ledger: {error}"));
        connection
            .execute_batch(
                "CREATE TABLE consumed_mutation_grants (
                    grant_id TEXT PRIMARY KEY,
                    grant_digest TEXT NOT NULL UNIQUE,
                    attempt_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    spec_digest TEXT NOT NULL,
                    consumed_at_ms INTEGER NOT NULL
                 ) STRICT;",
            )
            .unwrap_or_else(|error| panic!("create grant ledger: {error}"));
        let grant_id = Uuid::new_v4();
        let grant_digest = EvidenceDigest::sha256("single-use grant");
        let spec = ledger_spec(grant_id, grant_digest.clone());
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap_or_else(|error| panic!("grant transaction: {error}"));
        consume_mutation_grant(&transaction, &spec, "migrating", 10)
            .unwrap_or_else(|error| panic!("consume grant: {error}"));
        consume_mutation_grant(&transaction, &spec, "migrating", 11)
            .unwrap_or_else(|error| panic!("idempotent grant: {error}"));

        let mut reused_id = spec.clone();
        reused_id.attempt_id = Uuid::new_v4();
        reused_id.spec_digest = EvidenceDigest::sha256("another spec");
        assert!(matches!(
            consume_mutation_grant(&transaction, &reused_id, "migrating", 12),
            Err(StoreError::MutationGrantReplay)
        ));

        let reused_digest = ledger_spec(Uuid::new_v4(), grant_digest);
        assert!(matches!(
            consume_mutation_grant(&transaction, &reused_digest, "migrating", 12),
            Err(StoreError::MutationGrantReplay)
        ));
    }

    #[test]
    fn bound_deploy_specs_require_proofs_only_for_the_live_admission_window() {
        let mut spec = ledger_spec(Uuid::new_v4(), EvidenceDigest::sha256("grant"));
        spec.effective_release_class = Some(ReleaseClass::CodeOnlyCompatible);
        assert!(bound_spec_requires_source_gate_proof(
            &spec,
            OperationPhase::Deploying
        ));
        assert!(!bound_spec_requires_source_gate_proof(
            &spec,
            OperationPhase::BackingUp
        ));

        spec.effective_release_class = Some(ReleaseClass::StatefulCompatible);
        assert!(bound_spec_requires_source_gate_proof(
            &spec,
            OperationPhase::BackingUp
        ));
        assert!(bound_spec_requires_source_gate_proof(
            &spec,
            OperationPhase::Draining
        ));
        assert!(!bound_spec_requires_source_gate_proof(
            &spec,
            OperationPhase::Deploying
        ));

        spec.operation_kind = OperationKind::BackupOnly;
        assert!(!bound_spec_requires_source_gate_proof(
            &spec,
            OperationPhase::BackingUp
        ));
    }

    #[test]
    fn phase_artifacts_require_the_exact_persisted_source_proof() {
        let mut connection = Connection::open_in_memory()
            .unwrap_or_else(|error| panic!("open source proof ledger: {error}"));
        connection
            .execute_batch(
                "CREATE TABLE source_gate_proofs (
                    attempt_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    proof_digest TEXT NOT NULL,
                    PRIMARY KEY(attempt_id, phase)
                 ) STRICT;",
            )
            .unwrap_or_else(|error| panic!("create source proof ledger: {error}"));
        let attempt_id = Uuid::new_v4();
        let backing_up_proof = EvidenceDigest::sha256("backing-up source proof");
        let deploying_proof = EvidenceDigest::sha256("deploying source proof");
        connection
            .execute(
                "INSERT INTO source_gate_proofs(attempt_id, phase, proof_digest)
                 VALUES (?1, 'backing_up', ?2), (?1, 'deploying', ?3)",
                params![
                    attempt_id.to_string(),
                    backing_up_proof.as_str(),
                    deploying_proof.as_str()
                ],
            )
            .unwrap_or_else(|error| panic!("insert source proofs: {error}"));
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap_or_else(|error| panic!("source proof transaction: {error}"));

        let draining = PhaseArtifacts {
            source_gate_proof_digest: Some(backing_up_proof.clone()),
            ..PhaseArtifacts::default()
        };
        validate_artifact_source_gate_proof(
            &transaction,
            attempt_id,
            OperationPhase::Draining,
            &draining,
            false,
        )
        .unwrap_or_else(|error| panic!("drain should carry backing-up proof: {error}"));

        let substituted = PhaseArtifacts {
            source_gate_proof_digest: Some(deploying_proof.clone()),
            ..PhaseArtifacts::default()
        };
        assert!(matches!(
            validate_artifact_source_gate_proof(
                &transaction,
                attempt_id,
                OperationPhase::Draining,
                &substituted,
                false,
            ),
            Err(StoreError::SourceGateProofMismatch)
        ));

        assert!(matches!(
            validate_artifact_source_gate_proof(
                &transaction,
                attempt_id,
                OperationPhase::Draining,
                &PhaseArtifacts::default(),
                false,
            ),
            Err(StoreError::SourceGateProofMismatch)
        ));

        let deploying = PhaseArtifacts {
            source_gate_proof_digest: Some(deploying_proof),
            ..PhaseArtifacts::default()
        };
        validate_artifact_source_gate_proof(
            &transaction,
            attempt_id,
            OperationPhase::Deploying,
            &deploying,
            false,
        )
        .unwrap_or_else(|error| panic!("deploy should carry deploying proof: {error}"));
    }

    struct MutationStatusFixture {
        _directory: tempfile::TempDir,
        store: SecurityStore,
        intent_id: Uuid,
        attempt_id: Uuid,
        project_id: ProjectId,
    }

    fn mutation_status_fixture() -> MutationStatusFixture {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = SecurityStore::open(directory.path().join("security.sqlite"))
            .unwrap_or_else(|error| panic!("security store: {error}"));
        let fixture = MutationStatusFixture {
            _directory: directory,
            store,
            intent_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            project_id: ProjectId::from_str("rollback-status")
                .unwrap_or_else(|error| panic!("project: {error}")),
        };
        insert_status_admission(&fixture);
        fixture
    }

    fn insert_status_admission(fixture: &MutationStatusFixture) {
        let request_id = Uuid::new_v4();
        let nonce = Uuid::new_v4();
        let intent_digest = EvidenceDigest::sha256("status intent");
        let grant_digest = EvidenceDigest::sha256("status grant");
        let policy_digest = EvidenceDigest::sha256("status policy");
        let connection = lock_connection(&fixture.store.connection)
            .unwrap_or_else(|error| panic!("security connection: {error}"));
        connection
            .execute(
                "INSERT INTO executor_action_grants(
                    nonce, grant_digest, attempt_id, schema_version, issuer,
                    executor_audience, intent_id, intent_digest, request_id,
                    actor_id, role, lease_id, lease_generation, key_id, key_epoch,
                    installed_policy_digest, issued_at_ms, not_before_ms,
                    expires_at_ms, consumed_at_ms
                 ) VALUES (?1, ?2, ?3, 1, 'issuer', 'executor', ?4, ?5, ?6,
                    ?7, 'operator', ?8, 1, 'key', 1, ?9, 1, 1, 10000, 2)",
                params![
                    nonce.to_string(),
                    grant_digest.as_str(),
                    fixture.attempt_id.to_string(),
                    fixture.intent_id.to_string(),
                    intent_digest.as_str(),
                    request_id.to_string(),
                    Uuid::new_v4().to_string(),
                    Uuid::new_v4().to_string(),
                    policy_digest.as_str(),
                ],
            )
            .unwrap_or_else(|error| panic!("insert action grant: {error}"));
        connection
            .execute(
                "INSERT INTO executor_operation_intents(
                    intent_id, intent_digest, request_id, compact_token,
                    schema_version, issuer, authorizer_audience, project_id,
                    operation_kind, target_commit, proposed_release_class,
                    effective_release_class, installed_policy_digest,
                    source_attestation_digest, source_sequence,
                    release_bundle_digest, build_attestation_digest, migration_id,
                    previous_release_bundle_digest, consequences_json,
                    minimum_role, key_id, key_epoch, issued_at_ms, not_before_ms,
                    expires_at_ms, prepared_at_ms, state, attempt_id,
                    action_grant_nonce, action_grant_digest, consumed_at_ms
                 ) VALUES (?1, ?2, ?3, 'compact-token', 2, 'issuer', 'authorizer',
                    ?4, 'deploy', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'code_only_compatible', 'code_only_compatible', ?5, ?6, 1,
                    ?7, ?8, NULL, ?9, '[]', 'operator', 'key', 1, 1, 1, 10000,
                    1, 'consumed', ?10, ?11, ?12, 2)",
                params![
                    fixture.intent_id.to_string(),
                    intent_digest.as_str(),
                    request_id.to_string(),
                    fixture.project_id.as_str(),
                    policy_digest.as_str(),
                    EvidenceDigest::sha256("source").as_str(),
                    EvidenceDigest::sha256("candidate").as_str(),
                    EvidenceDigest::sha256("build").as_str(),
                    EvidenceDigest::sha256("previous").as_str(),
                    fixture.attempt_id.to_string(),
                    nonce.to_string(),
                    grant_digest.as_str(),
                ],
            )
            .unwrap_or_else(|error| panic!("insert accepted intent: {error}"));
    }

    fn insert_status_rollback_takeover(fixture: &MutationStatusFixture) {
        let artifacts = serde_json::to_string(&PhaseArtifacts::default())
            .unwrap_or_else(|error| panic!("artifacts: {error}"));
        let connection = lock_connection(&fixture.store.connection)
            .unwrap_or_else(|error| panic!("security connection: {error}"));
        for (index, phase) in OperationKind::Deploy
            .required_phases(Some(ReleaseClass::CodeOnlyCompatible))
            .unwrap_or_else(|error| panic!("deploy phases: {error}"))
            .iter()
            .take_while(|phase| **phase != OperationPhase::HealthChecking)
            .enumerate()
        {
            insert_committed_phase_for_status(
                &connection,
                fixture.attempt_id,
                &fixture.project_id,
                *phase,
                ExecutorPhaseBranch::Primary,
                10 + i64::try_from(index).unwrap_or_else(|error| panic!("phase index: {error}")),
            );
        }
        let forward_intent = EvidenceDigest::sha256("forward health intent");
        connection
            .execute(
                "INSERT INTO executor_phase_journal(
                    attempt_id, phase, project_id, intent_digest,
                    observation_digest, artifacts_json, status,
                    started_at_ms, updated_at_ms
                 ) VALUES (?1, 'health_checking', ?2, ?3, NULL, ?4,
                    'needs_reconcile', 30, 30)",
                params![
                    fixture.attempt_id.to_string(),
                    fixture.project_id.as_str(),
                    forward_intent.as_str(),
                    artifacts,
                ],
            )
            .unwrap_or_else(|error| panic!("insert forward health: {error}"));
        connection
            .execute(
                "INSERT INTO executor_rollback_takeovers(
                    attempt_id, project_id, forward_phase, forward_status,
                    forward_intent_digest, created_at_ms
                 ) VALUES (?1, ?2, 'health_checking', 'needs_reconcile', ?3, 31)",
                params![
                    fixture.attempt_id.to_string(),
                    fixture.project_id.as_str(),
                    forward_intent.as_str(),
                ],
            )
            .unwrap_or_else(|error| panic!("insert rollback takeover: {error}"));
    }

    #[test]
    fn mutation_status_projects_rollback_recovery_until_its_terminal_soak() {
        let fixture = mutation_status_fixture();
        insert_status_rollback_takeover(&fixture);

        let started = fixture
            .store
            .mutation_status(fixture.intent_id, fixture.attempt_id)
            .unwrap_or_else(|error| panic!("started rollback status: {error}"))
            .unwrap_or_else(|| panic!("started rollback status missing"));
        assert_eq!(started.state, MutationExecutionStateV1::Running);
        assert_eq!(started.current_phase, OperationPhase::Rollback);

        let connection = lock_connection(&fixture.store.connection)
            .unwrap_or_else(|error| panic!("security connection: {error}"));
        for (index, phase) in [
            OperationPhase::Rollback,
            OperationPhase::HealthChecking,
            OperationPhase::Soaking,
        ]
        .into_iter()
        .enumerate()
        {
            insert_committed_phase_for_status(
                &connection,
                fixture.attempt_id,
                &fixture.project_id,
                phase,
                ExecutorPhaseBranch::RollbackRecovery,
                40 + i64::try_from(index).unwrap_or_else(|error| panic!("phase index: {error}")),
            );
        }
        drop(connection);

        let completed = fixture
            .store
            .mutation_status(fixture.intent_id, fixture.attempt_id)
            .unwrap_or_else(|error| panic!("completed rollback status: {error}"))
            .unwrap_or_else(|| panic!("completed rollback status missing"));
        assert_eq!(completed.state, MutationExecutionStateV1::RolledBack);
        assert_eq!(completed.current_phase, OperationPhase::Soaking);
        assert_eq!(completed.updated_at_ms, 42);
    }

    fn insert_committed_phase_for_status(
        connection: &Connection,
        attempt_id: Uuid,
        project_id: &ProjectId,
        phase: OperationPhase,
        branch: ExecutorPhaseBranch,
        timestamp: i64,
    ) {
        let storage_phase = branch
            .storage_key(phase)
            .unwrap_or_else(|error| panic!("storage phase: {error}"));
        let intent = EvidenceDigest::sha256(format!("{storage_phase} intent"));
        let observation = EvidenceDigest::sha256(format!("{storage_phase} observation"));
        let artifacts = PhaseArtifacts::default();
        let receipt = PhaseReceipt::new(
            attempt_id,
            phase,
            branch,
            intent.clone(),
            observation.clone(),
            artifacts.clone(),
            timestamp,
        )
        .unwrap_or_else(|error| panic!("phase receipt: {error}"));
        connection
            .execute(
                "INSERT INTO executor_phase_journal(
                    attempt_id, phase, project_id, intent_digest,
                    observation_digest, artifacts_json, status,
                    started_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'committed', ?7, ?7)",
                params![
                    attempt_id.to_string(),
                    storage_phase,
                    project_id.as_str(),
                    intent.as_str(),
                    observation.as_str(),
                    serde_json::to_string(&artifacts)
                        .unwrap_or_else(|error| panic!("artifacts JSON: {error}")),
                    timestamp,
                ],
            )
            .unwrap_or_else(|error| panic!("insert {storage_phase} journal: {error}"));
        connection
            .execute(
                "INSERT INTO executor_phase_receipts(
                    attempt_id, phase, receipt_digest, receipt_json, committed_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    attempt_id.to_string(),
                    storage_phase,
                    receipt.receipt_digest.as_str(),
                    serde_json::to_string(&receipt)
                        .unwrap_or_else(|error| panic!("receipt JSON: {error}")),
                    timestamp,
                ],
            )
            .unwrap_or_else(|error| panic!("insert {storage_phase} receipt: {error}"));
    }
}
