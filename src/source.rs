use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use crate::{
    controller::{
        ActionGrantClaims, AdmissionOutcome, DeliveryChannel, DurableController, NewOperation,
        TabLeaseClaim, VerifiedAutomationAdmission, VerifiedInteractiveDeployAdmission,
    },
    domain::{
        EvidenceDigest, GitCommitId, InstalledPolicyIdentity, OperationKind, OperationPhase,
        OperationRecord, ProjectId, ReleaseClass,
    },
    store::StoreError,
};

mod git_repository;

pub use git_repository::{GitSourceProjectConfig, GitSourceRepository, GitSshTransportConfig};

pub const ACCEPTED_HEAD_SCHEMA_VERSION: u16 = 1;
pub const SOURCE_OUTBOX_SCHEMA_VERSION: u16 = 1;
const SOURCE_SCHEMA_VERSION: i64 = 3;
const PREVIOUS_SOURCE_SCHEMA_VERSION: i64 = 2;
const LEGACY_SOURCE_SCHEMA_VERSION: i64 = 1;
const MAX_DELIVERY_ID_BYTES: usize = 128;
const MAX_WEBHOOK_BODY_BYTES: usize = 1_048_576;
const MAX_OUTBOX_BATCH: usize = 64;
const SETTLED_OUTBOX_RETENTION: i64 = 2_048;
const ACCEPTED_HEAD_DOMAIN: &[u8] = b"rdashboard.accepted-head.v1\0";
const SOURCE_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS source_meta (
        key TEXT PRIMARY KEY,
        integer_value INTEGER NOT NULL
    ) STRICT;
    INSERT OR IGNORE INTO source_meta(key, integer_value)
        VALUES ('schema_version', 3);

    CREATE TABLE IF NOT EXISTS source_projects (
        project_id TEXT PRIMARY KEY,
        canonical_head TEXT,
        sequence INTEGER NOT NULL CHECK(sequence >= 0),
        state TEXT NOT NULL CHECK(state IN ('ready', 'source_diverged_needs_owner')),
        blocked_sha TEXT,
        reconcile_paused_until_ms INTEGER,
        attestation_json TEXT,
        attestation_digest TEXT,
        divergent_candidate TEXT,
        divergence_channel TEXT,
        divergence_evidence_digest TEXT,
        updated_at_ms INTEGER NOT NULL,
        CHECK((canonical_head IS NULL AND sequence = 0 AND attestation_json IS NULL
            AND attestation_digest IS NULL)
            OR (canonical_head IS NOT NULL AND sequence > 0 AND attestation_json IS NOT NULL
            AND attestation_digest IS NOT NULL)),
        CHECK((state = 'ready' AND divergent_candidate IS NULL
            AND divergence_channel IS NULL AND divergence_evidence_digest IS NULL)
            OR (state = 'source_diverged_needs_owner'
            AND divergent_candidate IS NOT NULL AND divergence_channel IS NOT NULL
            AND divergence_evidence_digest IS NOT NULL))
    ) STRICT;

    CREATE TABLE IF NOT EXISTS accepted_heads (
        project_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK(sequence > 0),
        canonical_head TEXT NOT NULL,
        previous_head TEXT,
        accepted_via TEXT NOT NULL,
        attestation_json TEXT NOT NULL,
        attestation_digest TEXT NOT NULL,
        accepted_at_ms INTEGER NOT NULL,
        PRIMARY KEY(project_id, sequence),
        UNIQUE(project_id, attestation_digest)
    ) STRICT;

    CREATE TABLE IF NOT EXISTS source_deliveries (
        project_id TEXT NOT NULL,
        channel TEXT NOT NULL,
        delivery_id TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        processing_token TEXT,
        status TEXT NOT NULL CHECK(status IN ('processing', 'recoverable', 'completed')),
        outcome_json TEXT,
        received_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        PRIMARY KEY(project_id, channel, delivery_id),
        CHECK((status = 'completed' AND outcome_json IS NOT NULL AND processing_token IS NULL)
            OR (status != 'completed' AND outcome_json IS NULL AND processing_token IS NOT NULL))
    ) STRICT;

    CREATE TABLE IF NOT EXISTS source_ref_update_journal (
        project_id TEXT PRIMARY KEY,
        expected_head TEXT,
        new_head TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK(sequence > 0),
        signed_attestation_json TEXT NOT NULL,
        attestation_digest TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('intent_persisted', 'ref_updated')),
        started_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS source_divergence_events (
        project_id TEXT NOT NULL,
        evidence_digest TEXT NOT NULL,
        canonical_head TEXT,
        divergent_candidate TEXT NOT NULL,
        divergence_channel TEXT NOT NULL,
        detected_at_ms INTEGER NOT NULL,
        resolved_at_ms INTEGER,
        resolution TEXT,
        PRIMARY KEY(project_id, evidence_digest),
        CHECK((resolved_at_ms IS NULL AND resolution IS NULL)
            OR (resolved_at_ms IS NOT NULL AND resolution IS NOT NULL))
    ) STRICT;

    CREATE TABLE IF NOT EXISTS source_mutation_tickets (
        project_id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL,
        phase TEXT NOT NULL CHECK(phase IN ('backing_up', 'draining', 'deploying')),
        source_sequence INTEGER NOT NULL CHECK(source_sequence > 0),
        attestation_digest TEXT NOT NULL,
        acquired_at_ms INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE IF NOT EXISTS source_outbox (
        outbox_sequence INTEGER PRIMARY KEY,
        project_id TEXT NOT NULL,
        source_sequence INTEGER NOT NULL CHECK(source_sequence > 0),
        attestation_json TEXT NOT NULL,
        attestation_digest TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL CHECK(status IN ('pending', 'delivered', 'superseded')),
        enqueued_at_ms INTEGER NOT NULL,
        settled_at_ms INTEGER,
        UNIQUE(project_id, source_sequence),
        CHECK((status = 'pending' AND settled_at_ms IS NULL)
            OR (status != 'pending' AND settled_at_ms IS NOT NULL))
    ) STRICT;

    CREATE INDEX IF NOT EXISTS source_outbox_pending_sequence
        ON source_outbox(status, outbox_sequence);
";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceChannel {
    GithubWebhook,
    SourceReconciliation,
    DirectPush,
}

impl SourceChannel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::GithubWebhook => "github_webhook",
            Self::SourceReconciliation => "source_reconciliation",
            Self::DirectPush => "direct_push",
        }
    }

    const fn controller_channel(self) -> DeliveryChannel {
        match self {
            Self::GithubWebhook => DeliveryChannel::GithubWebhook,
            Self::SourceReconciliation => DeliveryChannel::SourceReconciliation,
            Self::DirectPush => DeliveryChannel::DirectPush,
        }
    }

    fn parse(value: &str) -> Result<Self, SourceError> {
        match value {
            "github_webhook" => Ok(Self::GithubWebhook),
            "source_reconciliation" => Ok(Self::SourceReconciliation),
            "direct_push" => Ok(Self::DirectPush),
            _ => Err(SourceError::CorruptLedger("source channel")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedHeadV1 {
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub head: GitCommitId,
    pub sequence: u64,
    pub previous_head: Option<GitCommitId>,
    pub accepted_via: SourceChannel,
    pub repository_identity: EvidenceDigest,
    pub installed_policy: InstalledPolicyIdentity,
    pub accepted_at_ms: i64,
    pub expires_at_ms: i64,
}

impl AcceptedHeadV1 {
    fn validate(&self) -> Result<(), SourceAttestationError> {
        if self.schema_version != ACCEPTED_HEAD_SCHEMA_VERSION {
            return Err(SourceAttestationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.sequence == 0 {
            return Err(SourceAttestationError::ZeroSequence);
        }
        if self.installed_policy.version == 0 {
            return Err(SourceAttestationError::ZeroPolicyVersion);
        }
        if self.expires_at_ms <= self.accepted_at_ms {
            return Err(SourceAttestationError::InvalidValidityWindow);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, SourceAttestationError> {
        let canonical =
            serde_jcs::to_vec(self).map_err(SourceAttestationError::CanonicalEncoding)?;
        let mut domain_separated = Vec::with_capacity(ACCEPTED_HEAD_DOMAIN.len() + canonical.len());
        domain_separated.extend_from_slice(ACCEPTED_HEAD_DOMAIN);
        domain_separated.extend_from_slice(&canonical);
        Ok(domain_separated)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAcceptedHeadV1 {
    pub key_id: String,
    pub payload: AcceptedHeadV1,
    pub signature: String,
}

impl SignedAcceptedHeadV1 {
    fn sign(
        key_id: &str,
        payload: AcceptedHeadV1,
        signing_key: &SigningKey,
    ) -> Result<Self, SourceAttestationError> {
        payload.validate()?;
        validate_key_id(key_id)?;
        let signature = signing_key.sign(&payload.canonical_bytes()?);
        Ok(Self {
            key_id: key_id.to_owned(),
            payload,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn digest(&self) -> Result<EvidenceDigest, SourceAttestationError> {
        let canonical =
            serde_jcs::to_vec(self).map_err(SourceAttestationError::CanonicalEncoding)?;
        Ok(EvidenceDigest::sha256(canonical))
    }
}

#[derive(Clone, Debug)]
pub struct SourceAttestationVerifier {
    keys: BTreeMap<String, VerifyingKey>,
}

impl SourceAttestationVerifier {
    pub fn new(keys: BTreeMap<String, VerifyingKey>) -> Result<Self, SourceAttestationError> {
        if keys.is_empty() {
            return Err(SourceAttestationError::EmptyKeyring);
        }
        for key_id in keys.keys() {
            validate_key_id(key_id)?;
        }
        Ok(Self { keys })
    }

    pub fn verify<'a>(
        &self,
        signed: &'a SignedAcceptedHeadV1,
        now_ms: i64,
    ) -> Result<&'a AcceptedHeadV1, SourceAttestationError> {
        self.verify_inner(signed, Some(now_ms))
    }

    fn verify_live<'a>(
        &self,
        signed: &'a SignedAcceptedHeadV1,
    ) -> Result<&'a AcceptedHeadV1, SourceAttestationError> {
        // Admission expiry limits replay at the untrusted ingress. The executor's live broker
        // query is itself the fresh authorization and must not fail merely because CI ran long.
        self.verify_inner(signed, None)
    }

    fn verify_inner<'a>(
        &self,
        signed: &'a SignedAcceptedHeadV1,
        now_ms: Option<i64>,
    ) -> Result<&'a AcceptedHeadV1, SourceAttestationError> {
        signed.payload.validate()?;
        validate_key_id(&signed.key_id)?;
        if now_ms.is_some_and(|now| now >= signed.payload.expires_at_ms) {
            return Err(SourceAttestationError::Expired);
        }
        let key = self
            .keys
            .get(&signed.key_id)
            .ok_or_else(|| SourceAttestationError::UnknownKey(signed.key_id.clone()))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&signed.signature)
            .map_err(SourceAttestationError::InvalidSignatureEncoding)?;
        let signature =
            Signature::from_slice(&bytes).map_err(SourceAttestationError::InvalidSignature)?;
        key.verify_strict(&signed.payload.canonical_bytes()?, &signature)
            .map_err(SourceAttestationError::SignatureVerification)?;
        Ok(&signed.payload)
    }
}

fn validate_key_id(key_id: &str) -> Result<(), SourceAttestationError> {
    if key_id.is_empty()
        || key_id.len() > 64
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SourceAttestationError::InvalidKeyId);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceProjectState {
    Ready,
    SourceDivergedNeedsOwner,
}

impl SourceProjectState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::SourceDivergedNeedsOwner => "source_diverged_needs_owner",
        }
    }

    fn parse(value: &str) -> Result<Self, SourceError> {
        match value {
            "ready" => Ok(Self::Ready),
            "source_diverged_needs_owner" => Ok(Self::SourceDivergedNeedsOwner),
            _ => Err(SourceError::CorruptLedger("source project state")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    pub project_id: ProjectId,
    pub head: Option<GitCommitId>,
    pub sequence: u64,
    pub state: SourceProjectState,
    pub blocked_sha: Option<GitCommitId>,
    pub reconcile_paused_until_ms: Option<i64>,
    pub attestation: Option<SignedAcceptedHeadV1>,
    pub attestation_digest: Option<EvidenceDigest>,
    pub divergent_candidate: Option<GitCommitId>,
    pub divergence_channel: Option<SourceChannel>,
    pub divergence_evidence_digest: Option<EvidenceDigest>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTreeObservationV1 {
    pub project_id: ProjectId,
    pub head: GitCommitId,
    pub file_count: u64,
    pub total_bytes: u64,
}

impl SourceSnapshot {
    fn empty(project_id: ProjectId) -> Self {
        Self {
            project_id,
            head: None,
            sequence: 0,
            state: SourceProjectState::Ready,
            blocked_sha: None,
            reconcile_paused_until_ms: None,
            attestation: None,
            attestation_digest: None,
            divergent_candidate: None,
            divergence_channel: None,
            divergence_evidence_digest: None,
        }
    }
}

#[derive(Clone, Debug)]
struct PendingRefUpdate {
    project_id: ProjectId,
    expected_head: Option<GitCommitId>,
    new_head: GitCommitId,
    signed: SignedAcceptedHeadV1,
    attestation_digest: EvidenceDigest,
    ref_updated: bool,
}

#[derive(Clone, Debug)]
pub struct SourceStore {
    connection: Arc<Mutex<Connection>>,
    database_path: PathBuf,
    bound_broker_epoch: u64,
}

#[derive(Debug)]
struct SourceBrokerLease {
    lock_file: File,
    epoch: u64,
}

fn migrate_source_schema_v2(connection: &mut Connection) -> Result<(), SourceError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE source_mutation_tickets_v2 (
            project_id TEXT PRIMARY KEY,
            attempt_id TEXT NOT NULL,
            phase TEXT NOT NULL CHECK(phase IN ('backing_up', 'draining', 'deploying')),
            source_sequence INTEGER NOT NULL CHECK(source_sequence > 0),
            attestation_digest TEXT NOT NULL,
            acquired_at_ms INTEGER NOT NULL
         ) STRICT;
         INSERT INTO source_mutation_tickets_v2(
            project_id, attempt_id, phase, source_sequence,
            attestation_digest, acquired_at_ms
         )
         SELECT project_id, attempt_id, phase, source_sequence,
                attestation_digest, acquired_at_ms
         FROM source_mutation_tickets;
         DROP TABLE source_mutation_tickets;
         ALTER TABLE source_mutation_tickets_v2 RENAME TO source_mutation_tickets;
         UPDATE source_meta SET integer_value = 2 WHERE key = 'schema_version';",
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_source_schema_v3(connection: &mut Connection) -> Result<(), SourceError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = transaction.execute(
        "UPDATE source_meta SET integer_value = 3
         WHERE key = 'schema_version' AND integer_value = 2",
        [],
    )?;
    if changed != 1 {
        return Err(SourceError::CorruptLedger("source schema migration"));
    }
    transaction.commit()?;
    Ok(())
}

impl SourceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SourceError> {
        let database_path = path.as_ref().to_path_buf();
        let mut connection = Connection::open(&database_path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.execute_batch(SOURCE_SCHEMA_SQL)?;
        let version: i64 = connection.query_row(
            "SELECT integer_value FROM source_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )?;
        match version {
            SOURCE_SCHEMA_VERSION => {}
            PREVIOUS_SOURCE_SCHEMA_VERSION => migrate_source_schema_v3(&mut connection)?,
            LEGACY_SOURCE_SCHEMA_VERSION => {
                migrate_source_schema_v2(&mut connection)?;
                migrate_source_schema_v3(&mut connection)?;
            }
            _ => return Err(SourceError::UnsupportedSchemaVersion(version)),
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            database_path,
            bound_broker_epoch: 0,
        })
    }

    pub fn snapshot(&self, project_id: &ProjectId) -> Result<SourceSnapshot, SourceError> {
        let connection = self.lock()?;
        load_snapshot(&connection, project_id)
    }

    fn acquire_broker_lease(
        &mut self,
        started_at_ms: i64,
    ) -> Result<Arc<SourceBrokerLease>, SourceError> {
        use fs2::FileExt as _;

        if started_at_ms < 0 {
            return Err(SourceError::TimeRange);
        }
        let lock_path = self.database_path.with_extension("broker.lock");
        validate_source_lock_environment(&self.database_path, &lock_path)?;
        let lock_file = open_source_lock_file(&lock_path)?;
        lock_file
            .try_lock_exclusive()
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::WouldBlock => SourceError::BrokerAlreadyRunning,
                _ => SourceError::Io(error),
            })?;
        validate_open_source_lock_file(&self.database_path, &lock_path, &lock_file)?;

        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = transaction
            .query_row(
                "SELECT integer_value FROM source_meta WHERE key = 'broker_epoch'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0);
        let epoch = u64::try_from(previous)
            .map_err(|_| SourceError::CorruptLedger("broker epoch"))?
            .checked_add(1)
            .ok_or(SourceError::SequenceExhausted)?;
        let epoch_i64 = i64::try_from(epoch).map_err(|_| SourceError::SequenceRange)?;
        transaction.execute(
            "INSERT INTO source_meta(key, integer_value) VALUES ('broker_epoch', ?1)
             ON CONFLICT(key) DO UPDATE SET integer_value = excluded.integer_value",
            [epoch_i64],
        )?;
        transaction.execute(
            "INSERT INTO source_meta(key, integer_value) VALUES ('broker_started_at_ms', ?1)
             ON CONFLICT(key) DO UPDATE SET integer_value = excluded.integer_value",
            [started_at_ms],
        )?;
        transaction.commit()?;
        drop(connection);
        self.bound_broker_epoch = epoch;
        Ok(Arc::new(SourceBrokerLease { lock_file, epoch }))
    }

    fn require_broker_epoch(&self, expected: u64) -> Result<(), SourceError> {
        let expected = i64::try_from(expected).map_err(|_| SourceError::SequenceRange)?;
        let connection = self.lock()?;
        let current = connection
            .query_row(
                "SELECT integer_value FROM source_meta WHERE key = 'broker_epoch'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if current == Some(expected) {
            Ok(())
        } else {
            Err(SourceError::BrokerLeaseSuperseded)
        }
    }

    fn require_bound_broker_epoch(&self, transaction: &Transaction<'_>) -> Result<(), SourceError> {
        let expected = self.bound_broker_epoch;
        if expected == 0 {
            return Err(SourceError::BrokerLeaseSuperseded);
        }
        let expected = i64::try_from(expected).map_err(|_| SourceError::SequenceRange)?;
        let current = transaction
            .query_row(
                "SELECT integer_value FROM source_meta WHERE key = 'broker_epoch'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if current == Some(expected) {
            Ok(())
        } else {
            Err(SourceError::BrokerLeaseSuperseded)
        }
    }

    fn reserve_delivery(
        &self,
        project_id: &ProjectId,
        channel: SourceChannel,
        delivery_id: &str,
        payload_digest: &EvidenceDigest,
        received_at_ms: i64,
    ) -> Result<DeliveryReservation, SourceError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        if let Some((stored_digest, status, outcome_json)) = transaction
            .query_row(
                "SELECT payload_digest, status, outcome_json FROM source_deliveries
                 WHERE project_id = ?1 AND channel = ?2 AND delivery_id = ?3",
                params![project_id.as_str(), channel.as_str(), delivery_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?
        {
            if stored_digest != payload_digest.as_str() {
                return Err(SourceError::DeliveryConflict);
            }
            return match status.as_str() {
                "completed" => Ok(DeliveryReservation::Completed(serde_json::from_str(
                    outcome_json
                        .as_deref()
                        .ok_or(SourceError::CorruptLedger("completed delivery outcome"))?,
                )?)),
                "processing" => Err(SourceError::DeliveryInProgress),
                "recoverable" => {
                    let token = Uuid::new_v4();
                    transaction.execute(
                        "UPDATE source_deliveries
                         SET status = 'processing', processing_token = ?4, updated_at_ms = ?5
                         WHERE project_id = ?1 AND channel = ?2 AND delivery_id = ?3
                           AND status = 'recoverable'",
                        params![
                            project_id.as_str(),
                            channel.as_str(),
                            delivery_id,
                            token.to_string(),
                            received_at_ms
                        ],
                    )?;
                    transaction.commit()?;
                    Ok(DeliveryReservation::Claimed(DeliveryClaim {
                        project_id: project_id.clone(),
                        channel,
                        delivery_id: delivery_id.to_owned(),
                        payload_digest: payload_digest.clone(),
                        processing_token: token,
                    }))
                }
                _ => Err(SourceError::CorruptLedger("delivery status")),
            };
        }
        let token = Uuid::new_v4();
        transaction.execute(
            "INSERT INTO source_deliveries(
                project_id, channel, delivery_id, payload_digest, processing_token,
                status, received_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'processing', ?6, ?6)",
            params![
                project_id.as_str(),
                channel.as_str(),
                delivery_id,
                payload_digest.as_str(),
                token.to_string(),
                received_at_ms
            ],
        )?;
        transaction.commit()?;
        Ok(DeliveryReservation::Claimed(DeliveryClaim {
            project_id: project_id.clone(),
            channel,
            delivery_id: delivery_id.to_owned(),
            payload_digest: payload_digest.clone(),
            processing_token: token,
        }))
    }

    fn finish_delivery(
        &self,
        claim: &DeliveryClaim,
        outcome: &SourceIngressOutcome,
        enqueue_deployable: bool,
        completed_at_ms: i64,
    ) -> Result<SourceIngressOutcome, SourceError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        validate_delivery_outcome(claim, outcome)?;
        let outcome_json = serde_json::to_string(outcome)?;
        let changed = transaction.execute(
            "UPDATE source_deliveries
             SET status = 'completed', outcome_json = ?7, processing_token = NULL,
                 updated_at_ms = ?8
             WHERE project_id = ?1 AND channel = ?2 AND delivery_id = ?3
               AND payload_digest = ?4 AND processing_token = ?5 AND status = ?6",
            params![
                claim.project_id.as_str(),
                claim.channel.as_str(),
                claim.delivery_id,
                claim.payload_digest.as_str(),
                claim.processing_token.to_string(),
                "processing",
                outcome_json,
                completed_at_ms
            ],
        )?;
        if changed != 1 {
            return Err(SourceError::DeliveryReservationLost);
        }
        if enqueue_deployable {
            enqueue_deployable_outcome(&transaction, outcome, completed_at_ms)?;
        }
        transaction.commit()?;
        Ok(outcome.clone())
    }

    fn pending_outbox(&self, limit: usize) -> Result<Vec<SourceOutboxEntryV1>, SourceError> {
        if !(1..=MAX_OUTBOX_BATCH).contains(&limit) {
            return Err(SourceError::InvalidOutboxLimit);
        }
        let query_limit = i64::try_from(limit).map_err(|_| SourceError::InvalidOutboxLimit)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        self.require_bound_broker_epoch(&transaction)?;
        let mut statement = transaction.prepare(
            "SELECT outbox_sequence, project_id, source_sequence, attestation_json,
                    attestation_digest, enqueued_at_ms
             FROM source_outbox
             WHERE status = 'pending'
             ORDER BY outbox_sequence ASC
             LIMIT ?1",
        )?;
        let rows = statement
            .query_map([query_limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        transaction.commit()?;
        rows.iter().map(decode_outbox_row).collect()
    }

    fn reconcile_outbox_policy(
        &self,
        enabled_projects: &BTreeSet<String>,
        reconciled_at_ms: i64,
    ) -> Result<(), SourceError> {
        if reconciled_at_ms < 0 {
            return Err(SourceError::TimeRange);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        let pending_projects = {
            let mut statement = transaction.prepare(
                "SELECT DISTINCT project_id FROM source_outbox WHERE status = 'pending'",
            )?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for value in pending_projects {
            let project_id = ProjectId::from_str(&value)
                .map_err(|_| SourceError::CorruptLedger("source outbox project"))?;
            if !enabled_projects.contains(project_id.as_str()) {
                transaction.execute(
                    "UPDATE source_outbox
                     SET status = 'superseded',
                         settled_at_ms = MAX(enqueued_at_ms, ?2)
                     WHERE project_id = ?1 AND status = 'pending'",
                    params![project_id.as_str(), reconciled_at_ms],
                )?;
            }
        }
        prune_settled_outbox(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    fn acknowledge_outbox(
        &self,
        outbox_sequence: u64,
        attestation_digest: &EvidenceDigest,
        acknowledged_at_ms: i64,
    ) -> Result<(), SourceError> {
        if outbox_sequence == 0 || acknowledged_at_ms < 0 {
            return Err(SourceError::InvalidOutboxAcknowledgement);
        }
        let outbox_sequence = i64::try_from(outbox_sequence)
            .map_err(|_| SourceError::InvalidOutboxAcknowledgement)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        let stored = transaction
            .query_row(
                "SELECT attestation_digest, status, enqueued_at_ms
                 FROM source_outbox WHERE outbox_sequence = ?1",
                [outbox_sequence],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(SourceError::OutboxEntryMissing)?;
        if stored.0 != attestation_digest.as_str() {
            return Err(SourceError::OutboxAcknowledgementConflict);
        }
        if acknowledged_at_ms < stored.2 {
            return Err(SourceError::InvalidOutboxAcknowledgement);
        }
        match stored.1.as_str() {
            "pending" => {
                let changed = transaction.execute(
                    "UPDATE source_outbox
                     SET status = 'delivered', settled_at_ms = ?3
                     WHERE outbox_sequence = ?1 AND attestation_digest = ?2
                       AND status = 'pending'",
                    params![
                        outbox_sequence,
                        attestation_digest.as_str(),
                        acknowledged_at_ms
                    ],
                )?;
                if changed != 1 {
                    return Err(SourceError::OutboxAcknowledgementConflict);
                }
            }
            "delivered" | "superseded" => {}
            _ => return Err(SourceError::CorruptLedger("source outbox status")),
        }
        prune_settled_outbox(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    fn abandon_delivery(
        &self,
        claim: &DeliveryClaim,
        updated_at_ms: i64,
    ) -> Result<(), SourceError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        transaction.execute(
            "UPDATE source_deliveries
             SET status = 'recoverable', updated_at_ms = ?5
             WHERE project_id = ?1 AND channel = ?2 AND delivery_id = ?3
               AND processing_token = ?4 AND status = 'processing'",
            params![
                claim.project_id.as_str(),
                claim.channel.as_str(),
                claim.delivery_id,
                claim.processing_token.to_string(),
                updated_at_ms
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn recover_incomplete_deliveries(&self, recovered_at_ms: i64) -> Result<usize, SourceError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        let changed = transaction.execute(
            "UPDATE source_deliveries
             SET status = 'recoverable', updated_at_ms = ?1
             WHERE status = 'processing'",
            [recovered_at_ms],
        )?;
        transaction.commit()?;
        Ok(changed)
    }

    fn recorded_delivery(
        &self,
        project_id: &ProjectId,
        channel: SourceChannel,
        delivery_id: &str,
    ) -> Result<Option<SourceIngressOutcome>, SourceError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT outcome_json FROM source_deliveries
                 WHERE project_id = ?1 AND channel = ?2 AND delivery_id = ?3
                   AND status = 'completed'",
                params![project_id.as_str(), channel.as_str(), delivery_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .map(|json| serde_json::from_str(&json).map_err(SourceError::Json))
            .transpose()
    }

    fn has_pending_ref_update(&self, project_id: &ProjectId) -> Result<bool, SourceError> {
        let connection = self.lock()?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM source_ref_update_journal WHERE project_id = ?1",
                [project_id.as_str()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    fn acquire_mutation_ticket(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<(), SourceError> {
        let target = operation
            .target_commit
            .as_ref()
            .ok_or(SourceError::HeadNotCurrent)?;
        let sequence = operation
            .evidence
            .source_sequence
            .ok_or(SourceError::HeadNotCurrent)?;
        let sequence_i64 = i64::try_from(sequence).map_err(|_| SourceError::SequenceRange)?;
        let attestation_digest = operation
            .evidence
            .source_attestation_digest
            .as_ref()
            .ok_or(SourceError::HeadNotCurrent)?;
        let phase = mutation_phase_name(operation.state.phase)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        let current = load_snapshot(&transaction, &operation.project_id)?;
        if current.state != SourceProjectState::Ready
            || current.head.as_ref() != Some(target)
            || current.sequence != sequence
            || current.attestation_digest.as_ref() != Some(attestation_digest)
        {
            return Err(SourceError::HeadNotCurrent);
        }
        if current.blocked_sha.as_ref() == Some(target) {
            return Err(SourceError::BlockedSha);
        }
        if transaction
            .query_row(
                "SELECT 1 FROM source_ref_update_journal WHERE project_id = ?1",
                [operation.project_id.as_str()],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(SourceError::MutationAdmissionBusy);
        }
        if let Some((attempt_id, stored_phase, stored_sequence, stored_attestation)) = transaction
            .query_row(
                "SELECT attempt_id, phase, source_sequence, attestation_digest
                 FROM source_mutation_tickets WHERE project_id = ?1",
                [operation.project_id.as_str()],
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
            if attempt_id == operation.attempt_id.to_string()
                && stored_phase == phase
                && stored_sequence == sequence_i64
                && stored_attestation == attestation_digest.as_str()
            {
                return Ok(());
            }
            return Err(SourceError::MutationAdmissionBusy);
        }
        transaction.execute(
            "INSERT INTO source_mutation_tickets(
                project_id, attempt_id, phase, source_sequence,
                attestation_digest, acquired_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                operation.project_id.as_str(),
                operation.attempt_id.to_string(),
                phase,
                sequence_i64,
                attestation_digest.as_str(),
                now_ms
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn release_mutation_ticket(&self, operation: &OperationRecord) -> Result<(), SourceError> {
        let release_phase = operation.state.phase;
        if !matches!(
            release_phase,
            OperationPhase::BackingUp
                | OperationPhase::Draining
                | OperationPhase::CutoverSnapshotting
                | OperationPhase::Deploying
                | OperationPhase::Reconciliation
        ) {
            return Err(SourceError::InvalidMutationTicketPhase);
        }
        let source_sequence = operation
            .evidence
            .source_sequence
            .ok_or(SourceError::MutationTicketMismatch)?;
        let source_sequence =
            i64::try_from(source_sequence).map_err(|_| SourceError::SequenceRange)?;
        let source_attestation_digest = operation
            .evidence
            .source_attestation_digest
            .as_ref()
            .ok_or(SourceError::MutationTicketMismatch)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        let existing = transaction
            .query_row(
                "SELECT attempt_id, phase, source_sequence, attestation_digest
                 FROM source_mutation_tickets WHERE project_id = ?1",
                [operation.project_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((attempt_id, stored_phase, stored_sequence, stored_attestation_digest)) =
            existing
        {
            let phase_matches = match release_phase {
                OperationPhase::Draining => stored_phase == "draining",
                OperationPhase::BackingUp | OperationPhase::CutoverSnapshotting => {
                    stored_phase == "backing_up"
                }
                OperationPhase::Deploying => stored_phase == "deploying",
                OperationPhase::Reconciliation => {
                    matches!(
                        stored_phase.as_str(),
                        "backing_up" | "draining" | "deploying"
                    )
                }
                _ => unreachable!("release phase was validated above"),
            };
            if attempt_id != operation.attempt_id.to_string()
                || !phase_matches
                || stored_sequence != source_sequence
                || stored_attestation_digest != source_attestation_digest.as_str()
            {
                return Err(SourceError::MutationTicketMismatch);
            }
            let changed = transaction.execute(
                "DELETE FROM source_mutation_tickets
                 WHERE project_id = ?1 AND attempt_id = ?2",
                params![
                    operation.project_id.as_str(),
                    operation.attempt_id.to_string()
                ],
            )?;
            if changed != 1 {
                return Err(SourceError::MutationTicketMismatch);
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn begin_ref_update(
        &self,
        expected: &SourceSnapshot,
        signed: &SignedAcceptedHeadV1,
        digest: &EvidenceDigest,
    ) -> Result<(), SourceError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        let current = load_snapshot(&transaction, &expected.project_id)?;
        if current.head != expected.head
            || current.sequence != expected.sequence
            || current.state != SourceProjectState::Ready
        {
            return Err(SourceError::ConcurrentSourceUpdate);
        }
        if transaction
            .query_row(
                "SELECT 1 FROM source_mutation_tickets WHERE project_id = ?1",
                [expected.project_id.as_str()],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(SourceError::MutationAdmissionBusy);
        }
        if let Some((expected_head, new_head, sequence, stored_digest)) = transaction
            .query_row(
                "SELECT expected_head, new_head, sequence, attestation_digest
                 FROM source_ref_update_journal WHERE project_id = ?1",
                [expected.project_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?
        {
            if expected_head.as_deref() == expected.head.as_ref().map(GitCommitId::as_str)
                && new_head == signed.payload.head.as_str()
                && sequence
                    == i64::try_from(signed.payload.sequence)
                        .map_err(|_| SourceError::SequenceRange)?
                && stored_digest == digest.as_str()
            {
                return Ok(());
            }
            return Err(SourceError::PendingRefUpdateConflict);
        }
        transaction.execute(
            "INSERT INTO source_ref_update_journal(
                project_id, expected_head, new_head, sequence, signed_attestation_json,
                attestation_digest, state, started_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'intent_persisted', ?7, ?7)",
            params![
                expected.project_id.as_str(),
                expected.head.as_ref().map(GitCommitId::as_str),
                signed.payload.head.as_str(),
                i64::try_from(signed.payload.sequence).map_err(|_| SourceError::SequenceRange)?,
                serde_json::to_string(signed)?,
                digest.as_str(),
                signed.payload.accepted_at_ms
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn mark_ref_updated(
        &self,
        project_id: &ProjectId,
        digest: &EvidenceDigest,
        updated_at_ms: i64,
    ) -> Result<(), SourceError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        let changed = transaction.execute(
            "UPDATE source_ref_update_journal
             SET state = 'ref_updated', updated_at_ms = ?3
             WHERE project_id = ?1 AND attestation_digest = ?2
               AND state IN ('intent_persisted', 'ref_updated')",
            params![project_id.as_str(), digest.as_str(), updated_at_ms],
        )?;
        if changed != 1 {
            return Err(SourceError::PendingRefUpdateConflict);
        }
        transaction.commit()?;
        Ok(())
    }

    fn pending_ref_updates(&self) -> Result<Vec<PendingRefUpdate>, SourceError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT project_id, expected_head, new_head, signed_attestation_json,
                    attestation_digest, state
             FROM source_ref_update_journal ORDER BY project_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        let mut pending = Vec::new();
        for row in rows {
            let (project, expected, new_head, signed, digest, state) = row?;
            pending.push(PendingRefUpdate {
                project_id: ProjectId::from_str(&project)
                    .map_err(|_| SourceError::CorruptLedger("pending project"))?,
                expected_head: expected
                    .map(|value| GitCommitId::from_str(&value))
                    .transpose()
                    .map_err(|_| SourceError::CorruptLedger("pending expected head"))?,
                new_head: GitCommitId::from_str(&new_head)
                    .map_err(|_| SourceError::CorruptLedger("pending new head"))?,
                signed: serde_json::from_str(&signed)?,
                attestation_digest: EvidenceDigest::from_str(&digest)
                    .map_err(|_| SourceError::CorruptLedger("pending attestation digest"))?,
                ref_updated: match state.as_str() {
                    "intent_persisted" => false,
                    "ref_updated" => true,
                    _ => return Err(SourceError::CorruptLedger("pending ref state")),
                },
            });
        }
        Ok(pending)
    }

    fn accept_if_current(
        &self,
        expected: &SourceSnapshot,
        signed: &SignedAcceptedHeadV1,
        digest: &EvidenceDigest,
    ) -> Result<(), SourceError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        let current = load_snapshot(&transaction, &expected.project_id)?;
        if current.state == SourceProjectState::Ready
            && current.head.as_ref() == Some(&signed.payload.head)
            && current.sequence == signed.payload.sequence
            && current.attestation_digest.as_ref() == Some(digest)
        {
            transaction.execute(
                "DELETE FROM source_ref_update_journal
                 WHERE project_id = ?1 AND attestation_digest = ?2",
                params![expected.project_id.as_str(), digest.as_str()],
            )?;
            transaction.commit()?;
            return Ok(());
        }
        if current.head != expected.head
            || current.sequence != expected.sequence
            || current.state != SourceProjectState::Ready
        {
            return Err(SourceError::ConcurrentSourceUpdate);
        }
        let journal_matches = transaction
            .query_row(
                "SELECT 1 FROM source_ref_update_journal
                 WHERE project_id = ?1 AND expected_head IS ?2 AND new_head = ?3
                   AND sequence = ?4 AND attestation_digest = ?5 AND state = 'ref_updated'",
                params![
                    expected.project_id.as_str(),
                    expected.head.as_ref().map(GitCommitId::as_str),
                    signed.payload.head.as_str(),
                    i64::try_from(signed.payload.sequence)
                        .map_err(|_| SourceError::SequenceRange)?,
                    digest.as_str()
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !journal_matches {
            return Err(SourceError::PendingRefUpdateConflict);
        }
        let sequence =
            i64::try_from(signed.payload.sequence).map_err(|_| SourceError::SequenceRange)?;
        let attestation_json = serde_json::to_string(signed)?;
        transaction.execute(
            "INSERT INTO accepted_heads(
                project_id, sequence, canonical_head, previous_head, accepted_via,
                attestation_json, attestation_digest, accepted_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                signed.payload.project_id.as_str(),
                sequence,
                signed.payload.head.as_str(),
                signed
                    .payload
                    .previous_head
                    .as_ref()
                    .map(GitCommitId::as_str),
                signed.payload.accepted_via.as_str(),
                attestation_json,
                digest.as_str(),
                signed.payload.accepted_at_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO source_projects(
                project_id, canonical_head, sequence, state, blocked_sha,
                reconcile_paused_until_ms, attestation_json, attestation_digest, updated_at_ms
             ) VALUES (?1, ?2, ?3, 'ready', ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(project_id) DO UPDATE SET
                canonical_head = excluded.canonical_head,
                sequence = excluded.sequence,
                state = 'ready',
                divergent_candidate = NULL,
                divergence_channel = NULL,
                divergence_evidence_digest = NULL,
                attestation_json = excluded.attestation_json,
                attestation_digest = excluded.attestation_digest,
                updated_at_ms = excluded.updated_at_ms",
            params![
                signed.payload.project_id.as_str(),
                signed.payload.head.as_str(),
                sequence,
                expected.blocked_sha.as_ref().map(GitCommitId::as_str),
                expected.reconcile_paused_until_ms,
                serde_json::to_string(signed)?,
                digest.as_str(),
                signed.payload.accepted_at_ms
            ],
        )?;
        transaction.execute(
            "DELETE FROM source_ref_update_journal
             WHERE project_id = ?1 AND attestation_digest = ?2 AND state = 'ref_updated'",
            params![expected.project_id.as_str(), digest.as_str()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn mark_diverged(
        &self,
        project_id: &ProjectId,
        candidate: &GitCommitId,
        channel: SourceChannel,
        evidence_digest: &EvidenceDigest,
        now_ms: i64,
    ) -> Result<(), SourceError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        let current = load_snapshot(&transaction, project_id)?;
        transaction.execute(
            "INSERT INTO source_divergence_events(
                project_id, evidence_digest, canonical_head, divergent_candidate,
                divergence_channel, detected_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(project_id, evidence_digest) DO NOTHING",
            params![
                project_id.as_str(),
                evidence_digest.as_str(),
                current.head.as_ref().map(GitCommitId::as_str),
                candidate.as_str(),
                channel.as_str(),
                now_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO source_projects(
                project_id, canonical_head, sequence, state, blocked_sha,
                reconcile_paused_until_ms, attestation_json, attestation_digest,
                divergent_candidate, divergence_channel, divergence_evidence_digest, updated_at_ms
             ) VALUES (?1, ?2, ?3, 'source_diverged_needs_owner', ?4, ?5, ?6, ?7,
                       ?8, ?9, ?10, ?11)
             ON CONFLICT(project_id) DO UPDATE SET
                state = 'source_diverged_needs_owner',
                divergent_candidate = CASE
                    WHEN source_projects.state = 'source_diverged_needs_owner'
                    THEN source_projects.divergent_candidate
                    ELSE excluded.divergent_candidate END,
                divergence_channel = CASE
                    WHEN source_projects.state = 'source_diverged_needs_owner'
                    THEN source_projects.divergence_channel
                    ELSE excluded.divergence_channel END,
                divergence_evidence_digest = CASE
                    WHEN source_projects.state = 'source_diverged_needs_owner'
                    THEN source_projects.divergence_evidence_digest
                    ELSE excluded.divergence_evidence_digest END,
                updated_at_ms = excluded.updated_at_ms",
            params![
                project_id.as_str(),
                current.head.as_ref().map(GitCommitId::as_str),
                i64::try_from(current.sequence).map_err(|_| SourceError::SequenceRange)?,
                current.blocked_sha.as_ref().map(GitCommitId::as_str),
                current.reconcile_paused_until_ms,
                current
                    .attestation
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
                current
                    .attestation_digest
                    .as_ref()
                    .map(EvidenceDigest::as_str),
                candidate.as_str(),
                channel.as_str(),
                evidence_digest.as_str(),
                now_ms
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn set_controls(
        &self,
        project_id: &ProjectId,
        blocked_sha: Option<&GitCommitId>,
        reconcile_paused_until_ms: Option<i64>,
        now_ms: i64,
    ) -> Result<(), SourceError> {
        if reconcile_paused_until_ms.is_some_and(|until| until <= now_ms) {
            return Err(SourceError::InvalidControl("pause must end in the future"));
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        let current = load_snapshot(&transaction, project_id)?;
        transaction.execute(
            "INSERT INTO source_projects(
                project_id, canonical_head, sequence, state, blocked_sha,
                reconcile_paused_until_ms, attestation_json, attestation_digest, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(project_id) DO UPDATE SET
                blocked_sha = excluded.blocked_sha,
                reconcile_paused_until_ms = excluded.reconcile_paused_until_ms,
                updated_at_ms = excluded.updated_at_ms",
            params![
                project_id.as_str(),
                current.head.as_ref().map(GitCommitId::as_str),
                i64::try_from(current.sequence).map_err(|_| SourceError::SequenceRange)?,
                current.state.as_str(),
                blocked_sha.map(GitCommitId::as_str),
                reconcile_paused_until_ms,
                current
                    .attestation
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
                current
                    .attestation_digest
                    .as_ref()
                    .map(EvidenceDigest::as_str),
                now_ms
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn resolve_divergence_keep_canonical(
        &self,
        project_id: &ProjectId,
        expected_head: Option<&GitCommitId>,
        divergence_evidence_digest: &EvidenceDigest,
        now_ms: i64,
    ) -> Result<(), SourceError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.require_bound_broker_epoch(&transaction)?;
        let current = load_snapshot(&transaction, project_id)?;
        if current.state != SourceProjectState::SourceDivergedNeedsOwner
            || current.head.as_ref() != expected_head
            || current.divergence_evidence_digest.as_ref() != Some(divergence_evidence_digest)
        {
            return Err(SourceError::OwnerResolutionMismatch);
        }
        let changed = transaction.execute(
            "UPDATE source_projects SET
                state = 'ready', divergent_candidate = NULL, divergence_channel = NULL,
                divergence_evidence_digest = NULL, updated_at_ms = ?4
             WHERE project_id = ?1 AND canonical_head IS ?2
               AND divergence_evidence_digest = ?3
               AND state = 'source_diverged_needs_owner'",
            params![
                project_id.as_str(),
                expected_head.map(GitCommitId::as_str),
                divergence_evidence_digest.as_str(),
                now_ms
            ],
        )?;
        if changed != 1 {
            return Err(SourceError::OwnerResolutionMismatch);
        }
        transaction.execute(
            "DELETE FROM source_ref_update_journal WHERE project_id = ?1",
            [project_id.as_str()],
        )?;
        let resolved = transaction.execute(
            "UPDATE source_divergence_events
             SET resolved_at_ms = ?3, resolution = 'keep_canonical_head'
             WHERE project_id = ?1 AND resolved_at_ms IS NULL
               AND EXISTS (
                   SELECT 1 FROM source_divergence_events active
                   WHERE active.project_id = ?1 AND active.evidence_digest = ?2
               )",
            params![
                project_id.as_str(),
                divergence_evidence_digest.as_str(),
                now_ms
            ],
        )?;
        if resolved == 0 {
            return Err(SourceError::CorruptLedger("divergence audit event"));
        }
        transaction.commit()?;
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, SourceError> {
        self.connection
            .lock()
            .map_err(|_| SourceError::LockPoisoned)
    }
}

fn validate_delivery_outcome(
    claim: &DeliveryClaim,
    outcome: &SourceIngressOutcome,
) -> Result<(), SourceError> {
    let SourceIngressOutcome::Deployable(delivery) = outcome else {
        return Ok(());
    };
    if delivery.channel != claim.channel
        || delivery.delivery_id != claim.delivery_id
        || delivery.payload_digest != claim.payload_digest
        || delivery.attestation.payload.project_id != claim.project_id
        || delivery.attestation_digest != delivery.attestation.digest()?
    {
        return Err(SourceError::CorruptLedger("deployable delivery binding"));
    }
    Ok(())
}

fn enqueue_deployable_outcome(
    transaction: &Transaction<'_>,
    outcome: &SourceIngressOutcome,
    enqueued_at_ms: i64,
) -> Result<(), SourceError> {
    let SourceIngressOutcome::Deployable(delivery) = outcome else {
        return Ok(());
    };
    let payload = &delivery.attestation.payload;
    if enqueued_at_ms < payload.accepted_at_ms {
        return Err(SourceError::TimeRange);
    }
    let source_sequence =
        i64::try_from(payload.sequence).map_err(|_| SourceError::SequenceRange)?;
    let canonical = String::from_utf8(serde_jcs::to_vec(&delivery.attestation)?)
        .map_err(|_| SourceError::CorruptLedger("source outbox encoding"))?;
    transaction.execute(
        "UPDATE source_outbox
         SET status = 'superseded', settled_at_ms = MAX(enqueued_at_ms, ?3)
         WHERE project_id = ?1 AND source_sequence < ?2 AND status = 'pending'",
        params![payload.project_id.as_str(), source_sequence, enqueued_at_ms],
    )?;
    transaction.execute(
        "INSERT INTO source_outbox(
            project_id, source_sequence, attestation_json, attestation_digest,
            status, enqueued_at_ms, settled_at_ms
         ) VALUES (?1, ?2, ?3, ?4, 'pending', ?5, NULL)
         ON CONFLICT(attestation_digest) DO NOTHING",
        params![
            payload.project_id.as_str(),
            source_sequence,
            canonical,
            delivery.attestation_digest.as_str(),
            enqueued_at_ms
        ],
    )?;
    transaction.execute(
        "UPDATE source_outbox
         SET status = 'pending', enqueued_at_ms = ?4, settled_at_ms = NULL
         WHERE project_id = ?1 AND source_sequence = ?2 AND attestation_digest = ?3
           AND status = 'superseded'",
        params![
            payload.project_id.as_str(),
            source_sequence,
            delivery.attestation_digest.as_str(),
            enqueued_at_ms
        ],
    )?;
    let persisted = transaction.query_row(
        "SELECT outbox_sequence, project_id, source_sequence, attestation_json,
                attestation_digest, enqueued_at_ms
         FROM source_outbox WHERE attestation_digest = ?1",
        [delivery.attestation_digest.as_str()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let persisted = decode_outbox_row(&persisted)?;
    if persisted.project_id != payload.project_id
        || persisted.source_sequence != payload.sequence
        || persisted.attestation != delivery.attestation
        || persisted.attestation_digest != delivery.attestation_digest
    {
        return Err(SourceError::CorruptLedger("source outbox replay binding"));
    }
    prune_settled_outbox(transaction)?;
    Ok(())
}

fn prune_settled_outbox(transaction: &Transaction<'_>) -> Result<(), SourceError> {
    transaction.execute(
        "DELETE FROM source_outbox
         WHERE status != 'pending' AND outbox_sequence NOT IN (
             SELECT outbox_sequence FROM source_outbox
             WHERE status != 'pending'
             ORDER BY outbox_sequence DESC
             LIMIT ?1
         )",
        [SETTLED_OUTBOX_RETENTION],
    )?;
    Ok(())
}

fn decode_outbox_row(
    row: &(i64, String, i64, String, String, i64),
) -> Result<SourceOutboxEntryV1, SourceError> {
    let attestation: SignedAcceptedHeadV1 = serde_json::from_str(&row.3)?;
    if String::from_utf8(serde_jcs::to_vec(&attestation)?)
        .map_err(|_| SourceError::CorruptLedger("source outbox encoding"))?
        != row.3
    {
        return Err(SourceError::CorruptLedger(
            "source outbox canonical encoding",
        ));
    }
    let entry = SourceOutboxEntryV1 {
        schema_version: SOURCE_OUTBOX_SCHEMA_VERSION,
        outbox_sequence: u64::try_from(row.0)
            .map_err(|_| SourceError::CorruptLedger("source outbox sequence"))?,
        project_id: ProjectId::from_str(&row.1)
            .map_err(|_| SourceError::CorruptLedger("source outbox project"))?,
        source_sequence: u64::try_from(row.2)
            .map_err(|_| SourceError::CorruptLedger("source outbox source sequence"))?,
        attestation,
        attestation_digest: EvidenceDigest::from_str(&row.4)
            .map_err(|_| SourceError::CorruptLedger("source outbox attestation digest"))?,
        enqueued_at_ms: row.5,
    };
    entry.validate()?;
    Ok(entry)
}

fn load_snapshot(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<SourceSnapshot, SourceError> {
    let row = connection
        .query_row(
            "SELECT canonical_head, sequence, state, blocked_sha,
                    reconcile_paused_until_ms, attestation_json, attestation_digest,
                    divergent_candidate, divergence_channel, divergence_evidence_digest
             FROM source_projects WHERE project_id = ?1",
            [project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        head,
        sequence,
        state,
        blocked_sha,
        paused,
        attestation,
        digest,
        divergent_candidate,
        divergence_channel,
        divergence_evidence_digest,
    )) = row
    else {
        return Ok(SourceSnapshot::empty(project_id.clone()));
    };
    let sequence = u64::try_from(sequence).map_err(|_| SourceError::CorruptLedger("sequence"))?;
    let head = head
        .map(|value| GitCommitId::from_str(&value))
        .transpose()
        .map_err(|_| SourceError::CorruptLedger("canonical head"))?;
    let blocked_sha = blocked_sha
        .map(|value| GitCommitId::from_str(&value))
        .transpose()
        .map_err(|_| SourceError::CorruptLedger("blocked SHA"))?;
    let attestation = attestation
        .map(|value| serde_json::from_str(&value))
        .transpose()?;
    let attestation_digest = digest
        .map(|value| EvidenceDigest::from_str(&value))
        .transpose()
        .map_err(|_| SourceError::CorruptLedger("attestation digest"))?;
    let divergent_candidate = divergent_candidate
        .map(|value| GitCommitId::from_str(&value))
        .transpose()
        .map_err(|_| SourceError::CorruptLedger("divergent candidate"))?;
    let divergence_channel = divergence_channel
        .as_deref()
        .map(SourceChannel::parse)
        .transpose()?;
    let divergence_evidence_digest = divergence_evidence_digest
        .map(|value| EvidenceDigest::from_str(&value))
        .transpose()
        .map_err(|_| SourceError::CorruptLedger("divergence evidence digest"))?;
    let state = SourceProjectState::parse(&state)?;
    if head.is_some() != attestation.is_some()
        || head.is_some() != attestation_digest.is_some()
        || head.is_some() != (sequence > 0)
    {
        return Err(SourceError::CorruptLedger("head/attestation invariant"));
    }
    let complete_divergence_evidence = divergent_candidate.is_some()
        && divergence_channel.is_some()
        && divergence_evidence_digest.is_some();
    if (state == SourceProjectState::Ready && complete_divergence_evidence)
        || (state == SourceProjectState::SourceDivergedNeedsOwner && !complete_divergence_evidence)
        || divergent_candidate.is_some() != divergence_channel.is_some()
        || divergent_candidate.is_some() != divergence_evidence_digest.is_some()
    {
        return Err(SourceError::CorruptLedger("divergence evidence invariant"));
    }
    Ok(SourceSnapshot {
        project_id: project_id.clone(),
        head,
        sequence,
        state,
        blocked_sha,
        reconcile_paused_until_ms: paused,
        attestation,
        attestation_digest,
        divergent_candidate,
        divergence_channel,
        divergence_evidence_digest,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitRelationship {
    Same,
    FastForward,
    Rewind,
    Diverged,
}

pub trait SourceRepository: Send + Sync + std::fmt::Debug {
    fn repository_identity(&self, project_id: &ProjectId) -> Result<EvidenceDigest, SourceError>;

    fn fetch_remote_main(&self, project_id: &ProjectId) -> Result<GitCommitId, SourceError>;

    fn contains_commit(
        &self,
        project_id: &ProjectId,
        commit: &GitCommitId,
    ) -> Result<bool, SourceError>;

    fn relationship(
        &self,
        project_id: &ProjectId,
        current: &GitCommitId,
        candidate: &GitCommitId,
    ) -> Result<CommitRelationship, SourceError>;

    fn accepted_head(&self, project_id: &ProjectId) -> Result<Option<GitCommitId>, SourceError>;

    fn compare_and_swap_accepted_head(
        &self,
        project_id: &ProjectId,
        expected: Option<&GitCommitId>,
        candidate: &GitCommitId,
    ) -> Result<bool, SourceError>;

    fn accepted_tree_metrics(
        &self,
        project_id: &ProjectId,
        head: &GitCommitId,
    ) -> Result<(u64, u64), SourceError> {
        let _ = (project_id, head);
        Err(SourceError::Repository(
            "accepted source tree metrics are unavailable".to_owned(),
        ))
    }
}

#[derive(Clone, Debug, Default)]
pub struct DeterministicSourceRepository {
    state: Arc<Mutex<DeterministicRepositoryState>>,
}

#[derive(Debug, Default)]
struct DeterministicRepositoryState {
    repository_identities: BTreeMap<String, EvidenceDigest>,
    remote_heads: BTreeMap<String, GitCommitId>,
    accepted_heads: BTreeMap<String, GitCommitId>,
    parents: BTreeMap<(String, String), Option<GitCommitId>>,
}

impl DeterministicSourceRepository {
    pub fn set_repository_identity(
        &self,
        project_id: &ProjectId,
        identity: EvidenceDigest,
    ) -> Result<(), SourceError> {
        self.state
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?
            .repository_identities
            .insert(project_id.to_string(), identity);
        Ok(())
    }

    pub fn insert_commit(
        &self,
        project_id: &ProjectId,
        commit: &GitCommitId,
        parent: Option<GitCommitId>,
    ) -> Result<(), SourceError> {
        let mut state = self.state.lock().map_err(|_| SourceError::LockPoisoned)?;
        state
            .parents
            .insert((project_id.to_string(), commit.to_string()), parent);
        Ok(())
    }

    pub fn set_remote_head(
        &self,
        project_id: &ProjectId,
        head: GitCommitId,
    ) -> Result<(), SourceError> {
        let mut state = self.state.lock().map_err(|_| SourceError::LockPoisoned)?;
        if !state
            .parents
            .contains_key(&(project_id.to_string(), head.to_string()))
        {
            return Err(SourceError::Repository(
                "remote head is not present in the canonical object model".to_owned(),
            ));
        }
        state.remote_heads.insert(project_id.to_string(), head);
        Ok(())
    }
}

impl SourceRepository for DeterministicSourceRepository {
    fn repository_identity(&self, project_id: &ProjectId) -> Result<EvidenceDigest, SourceError> {
        self.state
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?
            .repository_identities
            .get(project_id.as_str())
            .cloned()
            .ok_or_else(|| SourceError::UnknownProject(project_id.to_string()))
    }

    fn fetch_remote_main(&self, project_id: &ProjectId) -> Result<GitCommitId, SourceError> {
        self.state
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?
            .remote_heads
            .get(project_id.as_str())
            .cloned()
            .ok_or_else(|| SourceError::Repository("remote main is unavailable".to_owned()))
    }

    fn contains_commit(
        &self,
        project_id: &ProjectId,
        commit: &GitCommitId,
    ) -> Result<bool, SourceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?
            .parents
            .contains_key(&(project_id.to_string(), commit.to_string())))
    }

    fn relationship(
        &self,
        project_id: &ProjectId,
        current: &GitCommitId,
        candidate: &GitCommitId,
    ) -> Result<CommitRelationship, SourceError> {
        if current == candidate {
            return Ok(CommitRelationship::Same);
        }
        let state = self.state.lock().map_err(|_| SourceError::LockPoisoned)?;
        let current_is_ancestor = is_ancestor(&state, project_id, current, candidate)?;
        let candidate_is_ancestor = is_ancestor(&state, project_id, candidate, current)?;
        Ok(match (current_is_ancestor, candidate_is_ancestor) {
            (true, false) => CommitRelationship::FastForward,
            (false, true) => CommitRelationship::Rewind,
            (false, false) => CommitRelationship::Diverged,
            (true, true) => return Err(SourceError::Repository("commit graph cycle".to_owned())),
        })
    }

    fn accepted_head(&self, project_id: &ProjectId) -> Result<Option<GitCommitId>, SourceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| SourceError::LockPoisoned)?
            .accepted_heads
            .get(project_id.as_str())
            .cloned())
    }

    fn compare_and_swap_accepted_head(
        &self,
        project_id: &ProjectId,
        expected: Option<&GitCommitId>,
        candidate: &GitCommitId,
    ) -> Result<bool, SourceError> {
        let mut state = self.state.lock().map_err(|_| SourceError::LockPoisoned)?;
        if !state
            .parents
            .contains_key(&(project_id.to_string(), candidate.to_string()))
        {
            return Err(SourceError::Repository(
                "accepted candidate is missing from the object model".to_owned(),
            ));
        }
        let current = state.accepted_heads.get(project_id.as_str());
        if current != expected {
            return Ok(false);
        }
        state
            .accepted_heads
            .insert(project_id.to_string(), candidate.clone());
        Ok(true)
    }
}

fn is_ancestor(
    state: &DeterministicRepositoryState,
    project_id: &ProjectId,
    ancestor: &GitCommitId,
    descendant: &GitCommitId,
) -> Result<bool, SourceError> {
    let mut cursor = Some(descendant.clone());
    let mut visited = BTreeSet::new();
    while let Some(commit) = cursor.as_ref() {
        if commit == ancestor {
            return Ok(true);
        }
        if !visited.insert(commit.to_string()) {
            return Err(SourceError::Repository("commit graph cycle".to_owned()));
        }
        cursor.clone_from(
            state
                .parents
                .get(&(project_id.to_string(), commit.to_string()))
                .ok_or_else(|| SourceError::Repository("commit graph is incomplete".to_owned()))?,
        );
    }
    Ok(false)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSourceDelivery {
    channel: SourceChannel,
    delivery_id: String,
    payload_digest: EvidenceDigest,
    attestation: SignedAcceptedHeadV1,
    attestation_digest: EvidenceDigest,
}

impl VerifiedSourceDelivery {
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }

    pub const fn attestation(&self) -> &SignedAcceptedHeadV1 {
        &self.attestation
    }

    pub const fn attestation_digest(&self) -> &EvidenceDigest {
        &self.attestation_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "details")]
pub enum SourceIngressOutcome {
    Deployable(Box<VerifiedSourceDelivery>),
    StaleNoop { announced_head: GitCommitId },
    IgnoredRef,
    SourceDivergedNeedsOwner,
    ReconciliationPaused,
    BlockedSha { head: GitCommitId },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceOutboxEntryV1 {
    pub schema_version: u16,
    pub outbox_sequence: u64,
    pub project_id: ProjectId,
    pub source_sequence: u64,
    pub attestation: SignedAcceptedHeadV1,
    pub attestation_digest: EvidenceDigest,
    pub enqueued_at_ms: i64,
}

impl SourceOutboxEntryV1 {
    pub fn validate(&self) -> Result<(), SourceError> {
        if self.schema_version != SOURCE_OUTBOX_SCHEMA_VERSION
            || self.outbox_sequence == 0
            || self.source_sequence == 0
            || self.enqueued_at_ms < self.attestation.payload.accepted_at_ms
            || self.project_id != self.attestation.payload.project_id
            || self.source_sequence != self.attestation.payload.sequence
            || self.attestation_digest != self.attestation.digest()?
        {
            return Err(SourceError::CorruptLedger("source outbox entry"));
        }
        Ok(())
    }

    pub fn scheduler_delivery_id(&self) -> String {
        format!("source-{}", self.attestation_digest)
    }
}

enum DeliveryReservation {
    Claimed(DeliveryClaim),
    Completed(SourceIngressOutcome),
}

#[derive(Clone, Debug)]
struct DeliveryClaim {
    project_id: ProjectId,
    channel: SourceChannel,
    delivery_id: String,
    payload_digest: EvidenceDigest,
    processing_token: Uuid,
}

struct CandidateIngress<'a> {
    project_id: &'a ProjectId,
    candidate: GitCommitId,
    announced_previous_head: Option<&'a GitCommitId>,
    channel: SourceChannel,
    delivery_id: &'a str,
    payload_digest: EvidenceDigest,
    installed_policy: &'a InstalledSourceProjectPolicy,
    now_ms: i64,
}

#[derive(Clone, Debug)]
pub struct DurableSourceBroker<R> {
    store: SourceStore,
    repository: R,
    broker_lease: Arc<SourceBrokerLease>,
    coordination: Arc<BTreeMap<String, Arc<Mutex<()>>>>,
    key_id: String,
    signing_key: SigningKey,
    verifier: SourceAttestationVerifier,
    attestation_ttl_ms: i64,
    policies: BTreeMap<String, InstalledSourceProjectPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledSourceProjectPolicy {
    pub project_id: ProjectId,
    pub repository_identity: EvidenceDigest,
    pub installed_policy: InstalledPolicyIdentity,
    pub auto_deploy: bool,
    pub maximum_attempts: u32,
    pub release_class: ReleaseClass,
}

impl InstalledSourceProjectPolicy {
    fn validate(&self) -> Result<(), SourceError> {
        if self.installed_policy.version == 0 || !(1..=10).contains(&self.maximum_attempts) {
            return Err(SourceError::InvalidInstalledPolicy);
        }
        if self.release_class == ReleaseClass::Rollback {
            return Err(SourceError::InvalidInstalledPolicy);
        }
        Ok(())
    }
}

impl<R: SourceRepository> DurableSourceBroker<R> {
    pub fn new(
        mut store: SourceStore,
        repository: R,
        key_id: impl Into<String>,
        signing_key: SigningKey,
        attestation_ttl_ms: i64,
        installed_policies: Vec<InstalledSourceProjectPolicy>,
        started_at_ms: i64,
    ) -> Result<Self, SourceError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        if !(10_000..=3_600_000).contains(&attestation_ttl_ms) {
            return Err(SourceError::InvalidControl(
                "attestation TTL must be between 10 seconds and one hour",
            ));
        }
        let verifier = SourceAttestationVerifier::new(BTreeMap::from([(
            key_id.clone(),
            signing_key.verifying_key(),
        )]))?;
        if installed_policies.is_empty() {
            return Err(SourceError::InvalidInstalledPolicy);
        }
        let mut policies = BTreeMap::new();
        for policy in installed_policies {
            policy.validate()?;
            if repository.repository_identity(&policy.project_id)? != policy.repository_identity {
                return Err(SourceError::RepositoryIdentityMismatch);
            }
            if policies
                .insert(policy.project_id.to_string(), policy)
                .is_some()
            {
                return Err(SourceError::DuplicateInstalledProject);
            }
        }
        let coordination = policies
            .keys()
            .map(|project_id| (project_id.clone(), Arc::new(Mutex::new(()))))
            .collect();
        let broker_lease = store.acquire_broker_lease(started_at_ms)?;
        let broker = Self {
            store,
            repository,
            broker_lease,
            coordination: Arc::new(coordination),
            key_id,
            signing_key,
            verifier,
            attestation_ttl_ms,
            policies,
        };
        broker.recover_source_state(started_at_ms)?;
        let enabled_projects = broker
            .policies
            .values()
            .filter(|policy| policy.auto_deploy)
            .map(|policy| policy.project_id.to_string())
            .collect();
        broker
            .store
            .reconcile_outbox_policy(&enabled_projects, started_at_ms)?;
        Ok(broker)
    }

    pub const fn store(&self) -> &SourceStore {
        &self.store
    }

    pub fn pending_outbox(&self, limit: usize) -> Result<Vec<SourceOutboxEntryV1>, SourceError> {
        self.require_current_lease()?;
        self.store.pending_outbox(limit)
    }

    pub fn acknowledge_outbox(
        &self,
        outbox_sequence: u64,
        attestation_digest: &EvidenceDigest,
        acknowledged_at_ms: i64,
    ) -> Result<(), SourceError> {
        self.require_current_lease()?;
        self.store
            .acknowledge_outbox(outbox_sequence, attestation_digest, acknowledged_at_ms)
    }

    pub fn broker_epoch(&self) -> u64 {
        self.broker_lease.epoch
    }

    pub fn source_tree_observation(
        &self,
        project_id: &ProjectId,
    ) -> Result<SourceTreeObservationV1, SourceError> {
        let _coordination = self.lock_coordination(project_id)?;
        let snapshot = self.store.snapshot(project_id)?;
        if snapshot.state != SourceProjectState::Ready {
            return Err(SourceError::Repository(
                "accepted source tree is unavailable while source reconciliation needs owner action"
                    .to_owned(),
            ));
        }
        let head = snapshot.head.ok_or_else(|| {
            SourceError::Repository("accepted source tree has no canonical head".to_owned())
        })?;
        let (file_count, total_bytes) = self.repository.accepted_tree_metrics(project_id, &head)?;
        Ok(SourceTreeObservationV1 {
            project_id: project_id.clone(),
            head,
            file_count,
            total_bytes,
        })
    }

    fn require_current_lease(&self) -> Result<(), SourceError> {
        if self.store.bound_broker_epoch != self.broker_lease.epoch {
            return Err(SourceError::BrokerLeaseSuperseded);
        }
        self.store.require_broker_epoch(self.broker_lease.epoch)?;
        let lock_path = self.store.database_path.with_extension("broker.lock");
        validate_source_lock_environment(&self.store.database_path, &lock_path)?;
        validate_open_source_lock_file(
            &self.store.database_path,
            &lock_path,
            &self.broker_lease.lock_file,
        )?;
        Ok(())
    }

    fn lock_coordination(&self, project_id: &ProjectId) -> Result<MutexGuard<'_, ()>, SourceError> {
        self.require_current_lease()?;
        let coordination = self
            .coordination
            .get(project_id.as_str())
            .map(Arc::as_ref)
            .ok_or_else(|| SourceError::UnknownProject(project_id.to_string()))?;
        let guard = coordination.lock().map_err(|_| SourceError::LockPoisoned)?;
        self.require_current_lease()?;
        Ok(guard)
    }

    pub fn resolve_divergence_keep_canonical(
        &self,
        project_id: &ProjectId,
        expected_head: Option<&GitCommitId>,
        divergence_evidence_digest: &EvidenceDigest,
        now_ms: i64,
    ) -> Result<(), SourceError> {
        let _coordination = self.lock_coordination(project_id)?;
        let repository_head = self.repository.accepted_head(project_id)?;
        if repository_head.as_ref() != expected_head {
            return Err(SourceError::OwnerResolutionMismatch);
        }
        self.store.resolve_divergence_keep_canonical(
            project_id,
            expected_head,
            divergence_evidence_digest,
            now_ms,
        )
    }

    pub fn set_controls(
        &self,
        project_id: &ProjectId,
        blocked_sha: Option<&GitCommitId>,
        reconcile_paused_until_ms: Option<i64>,
        now_ms: i64,
    ) -> Result<(), SourceError> {
        let _coordination = self.lock_coordination(project_id)?;
        self.store
            .set_controls(project_id, blocked_sha, reconcile_paused_until_ms, now_ms)
    }

    fn recover_source_state(&self, recovered_at_ms: i64) -> Result<(), SourceError> {
        self.require_current_lease()?;
        let pending_updates = self.store.pending_ref_updates()?;
        let pending_projects = pending_updates
            .iter()
            .map(|pending| pending.project_id.to_string())
            .collect::<BTreeSet<_>>();

        for pending in pending_updates {
            self.recover_ref_update(&pending, recovered_at_ms)?;
        }

        for policy in self.policies.values() {
            if pending_projects.contains(policy.project_id.as_str()) {
                continue;
            }
            let snapshot = self.store.snapshot(&policy.project_id)?;
            if snapshot.state == SourceProjectState::SourceDivergedNeedsOwner {
                continue;
            }
            let repository_head = self.repository.accepted_head(&policy.project_id)?;
            if repository_head != snapshot.head {
                let candidate = repository_head
                    .clone()
                    .or_else(|| snapshot.head.clone())
                    .ok_or(SourceError::CorruptLedger("empty source ref mismatch"))?;
                let evidence = EvidenceDigest::sha256(format!(
                    "source-ref-startup-mismatch.v1\n{}\n{}\n{}",
                    policy.project_id,
                    snapshot.head.as_ref().map_or("-", GitCommitId::as_str),
                    repository_head.as_ref().map_or("-", GitCommitId::as_str)
                ));
                self.store.mark_diverged(
                    &policy.project_id,
                    &candidate,
                    SourceChannel::SourceReconciliation,
                    &evidence,
                    recovered_at_ms,
                )?;
            }
        }

        self.store.recover_incomplete_deliveries(recovered_at_ms)?;
        Ok(())
    }

    fn recover_ref_update(
        &self,
        pending: &PendingRefUpdate,
        recovered_at_ms: i64,
    ) -> Result<(), SourceError> {
        let payload = self.verifier.verify_live(&pending.signed)?;
        let policy = self.policy(&pending.project_id)?;
        if pending.signed.digest()? != pending.attestation_digest
            || payload.project_id != pending.project_id
            || payload.head != pending.new_head
            || payload.previous_head != pending.expected_head
            || payload.installed_policy != policy.installed_policy
            || payload.repository_identity != policy.repository_identity
        {
            return Err(SourceError::CorruptLedger(
                "pending ref attestation binding",
            ));
        }
        let expected_snapshot = self.store.snapshot(&pending.project_id)?;
        if expected_snapshot.state == SourceProjectState::SourceDivergedNeedsOwner {
            return Ok(());
        }
        if expected_snapshot.head.as_ref() == Some(&pending.new_head)
            && expected_snapshot.sequence == payload.sequence
            && expected_snapshot.attestation_digest.as_ref() == Some(&pending.attestation_digest)
        {
            self.store.accept_if_current(
                &expected_snapshot,
                &pending.signed,
                &pending.attestation_digest,
            )?;
            return Ok(());
        }
        if expected_snapshot.head != pending.expected_head
            || expected_snapshot.sequence.checked_add(1) != Some(payload.sequence)
        {
            return Err(SourceError::CorruptLedger("pending ref sequence binding"));
        }

        let observed = self.repository.accepted_head(&pending.project_id)?;
        let mut ref_is_candidate = if observed.as_ref() == Some(&pending.new_head) {
            true
        } else if !pending.ref_updated && observed == pending.expected_head {
            self.require_current_lease()?;
            self.repository.compare_and_swap_accepted_head(
                &pending.project_id,
                pending.expected_head.as_ref(),
                &pending.new_head,
            )? || self.repository.accepted_head(&pending.project_id)?.as_ref()
                == Some(&pending.new_head)
        } else {
            false
        };
        let observed_after_cas = if ref_is_candidate {
            None
        } else {
            Some(self.repository.accepted_head(&pending.project_id)?)
        };
        if observed_after_cas
            .as_ref()
            .is_some_and(|head| head.as_ref() == Some(&pending.new_head))
        {
            ref_is_candidate = true;
        }
        if !ref_is_candidate {
            self.mark_ref_diverged(
                &pending.project_id,
                &pending.new_head,
                pending.signed.payload.accepted_via,
                &pending.attestation_digest,
                observed_after_cas.as_ref().and_then(Option::as_ref),
                recovered_at_ms,
            )?;
            return Ok(());
        }
        self.store.mark_ref_updated(
            &pending.project_id,
            &pending.attestation_digest,
            recovered_at_ms,
        )?;
        self.store.accept_if_current(
            &expected_snapshot,
            &pending.signed,
            &pending.attestation_digest,
        )
    }

    fn advance_ref_update(
        &self,
        expected: &SourceSnapshot,
        signed: &SignedAcceptedHeadV1,
        digest: &EvidenceDigest,
        now_ms: i64,
    ) -> Result<bool, SourceError> {
        self.store.begin_ref_update(expected, signed, digest)?;
        let observed = self.repository.accepted_head(&expected.project_id)?;
        let mut ref_is_candidate = if observed.as_ref() == Some(&signed.payload.head) {
            true
        } else if observed == expected.head {
            self.require_current_lease()?;
            self.repository.compare_and_swap_accepted_head(
                &expected.project_id,
                expected.head.as_ref(),
                &signed.payload.head,
            )? || self
                .repository
                .accepted_head(&expected.project_id)?
                .as_ref()
                == Some(&signed.payload.head)
        } else {
            false
        };
        let observed_after_cas = if ref_is_candidate {
            None
        } else {
            Some(self.repository.accepted_head(&expected.project_id)?)
        };
        if observed_after_cas
            .as_ref()
            .is_some_and(|head| head.as_ref() == Some(&signed.payload.head))
        {
            ref_is_candidate = true;
        }
        if !ref_is_candidate {
            self.mark_ref_diverged(
                &expected.project_id,
                &signed.payload.head,
                signed.payload.accepted_via,
                digest,
                observed_after_cas.as_ref().and_then(Option::as_ref),
                now_ms,
            )?;
            return Ok(false);
        }
        self.store
            .mark_ref_updated(&expected.project_id, digest, now_ms)?;
        self.store.accept_if_current(expected, signed, digest)?;
        Ok(true)
    }

    fn mark_ref_diverged(
        &self,
        project_id: &ProjectId,
        intended_head: &GitCommitId,
        channel: SourceChannel,
        intent_digest: &EvidenceDigest,
        observed_head: Option<&GitCommitId>,
        now_ms: i64,
    ) -> Result<(), SourceError> {
        let evidence = EvidenceDigest::sha256(format!(
            "source-ref-cas-divergence.v1\n{}\n{}\n{}\n{}",
            project_id,
            intended_head,
            observed_head.map_or("-", GitCommitId::as_str),
            intent_digest
        ));
        self.store.mark_diverged(
            project_id,
            observed_head.unwrap_or(intended_head),
            channel,
            &evidence,
            now_ms,
        )
    }

    pub fn process_github_push(
        &self,
        project_id: &ProjectId,
        delivery_id: &str,
        signature_header: &str,
        webhook_secret: &[u8],
        raw_body: &[u8],
        now_ms: i64,
    ) -> Result<SourceIngressOutcome, SourceError> {
        let _coordination = self.lock_coordination(project_id)?;
        validate_delivery_id(delivery_id)?;
        if raw_body.len() > MAX_WEBHOOK_BODY_BYTES {
            return Err(SourceError::WebhookBodyTooLarge);
        }
        verify_github_hmac(signature_header, webhook_secret, raw_body)?;
        let payload_digest = EvidenceDigest::sha256(raw_body);
        let payload: GithubPushPayload = serde_json::from_slice(raw_body)?;
        let installed_policy = self.policy(project_id)?;
        let delivery_claim = match self.store.reserve_delivery(
            project_id,
            SourceChannel::GithubWebhook,
            delivery_id,
            &payload_digest,
            now_ms,
        )? {
            DeliveryReservation::Completed(outcome) => return Ok(outcome),
            DeliveryReservation::Claimed(claim) => claim,
        };
        let result = (|| {
            if payload.git_ref != "refs/heads/main" {
                return Ok(SourceIngressOutcome::IgnoredRef);
            }
            let announced_head = GitCommitId::from_str(&payload.after)
                .map_err(|_| SourceError::InvalidWebhookPayload)?;
            let fetched_head = self.repository.fetch_remote_main(project_id)?;
            if announced_head != fetched_head {
                return match self.repository.relationship(
                    project_id,
                    &announced_head,
                    &fetched_head,
                )? {
                    CommitRelationship::FastForward => {
                        Ok(SourceIngressOutcome::StaleNoop { announced_head })
                    }
                    CommitRelationship::Same => unreachable!("different commits cannot be same"),
                    CommitRelationship::Rewind | CommitRelationship::Diverged => {
                        let evidence = EvidenceDigest::sha256(format!(
                            "github-mismatch\n{announced_head}\n{fetched_head}"
                        ));
                        self.store.mark_diverged(
                            project_id,
                            &fetched_head,
                            SourceChannel::GithubWebhook,
                            &evidence,
                            now_ms,
                        )?;
                        Ok(SourceIngressOutcome::SourceDivergedNeedsOwner)
                    }
                };
            }
            self.process_candidate(&CandidateIngress {
                project_id,
                candidate: fetched_head,
                announced_previous_head: None,
                channel: SourceChannel::GithubWebhook,
                delivery_id,
                payload_digest: payload_digest.clone(),
                installed_policy,
                now_ms,
            })
        })();
        match result {
            Ok(outcome) => self.store.finish_delivery(
                &delivery_claim,
                &outcome,
                installed_policy.auto_deploy,
                now_ms,
            ),
            Err(error) => {
                self.store.abandon_delivery(&delivery_claim, now_ms)?;
                Err(error)
            }
        }
    }

    pub fn reconcile_remote_main(
        &self,
        project_id: &ProjectId,
        now_ms: i64,
    ) -> Result<SourceIngressOutcome, SourceError> {
        let _coordination = self.lock_coordination(project_id)?;
        let installed_policy = self.policy(project_id)?;
        let fetched_head = self.repository.fetch_remote_main(project_id)?;
        let snapshot = self.store.snapshot(project_id)?;
        let pause_active = snapshot
            .reconcile_paused_until_ms
            .is_some_and(|until| now_ms < until);
        let attestation_expired = snapshot
            .attestation
            .as_ref()
            .is_some_and(|attestation| now_ms >= attestation.payload.expires_at_ms);
        let payload_digest = EvidenceDigest::sha256(format!(
            "reconcile.v3\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            project_id,
            fetched_head,
            installed_policy.repository_identity,
            installed_policy.installed_policy.digest,
            installed_policy.installed_policy.version,
            installed_policy.auto_deploy,
            snapshot.head.as_ref().map_or("-", GitCommitId::as_str),
            snapshot.sequence,
            snapshot.state.as_str(),
            snapshot
                .blocked_sha
                .as_ref()
                .map_or("-", GitCommitId::as_str),
            pause_active,
            snapshot
                .divergence_evidence_digest
                .as_ref()
                .map_or("-", EvidenceDigest::as_str),
            attestation_expired
        ));
        let delivery_id = format!("reconcile-{payload_digest}");
        let delivery_claim = match self.store.reserve_delivery(
            project_id,
            SourceChannel::SourceReconciliation,
            &delivery_id,
            &payload_digest,
            now_ms,
        )? {
            DeliveryReservation::Completed(outcome) => return Ok(outcome),
            DeliveryReservation::Claimed(claim) => claim,
        };
        let result = self.process_candidate(&CandidateIngress {
            project_id,
            candidate: fetched_head,
            announced_previous_head: None,
            channel: SourceChannel::SourceReconciliation,
            delivery_id: &delivery_id,
            payload_digest: payload_digest.clone(),
            installed_policy,
            now_ms,
        });
        match result {
            Ok(outcome) => self.store.finish_delivery(
                &delivery_claim,
                &outcome,
                installed_policy.auto_deploy,
                now_ms,
            ),
            Err(error) => {
                self.store.abandon_delivery(&delivery_claim, now_ms)?;
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_direct_push(
        &self,
        project_id: &ProjectId,
        delivery_id: &str,
        git_ref: &str,
        old_head: Option<&GitCommitId>,
        new_head: GitCommitId,
        now_ms: i64,
    ) -> Result<SourceIngressOutcome, SourceError> {
        let _coordination = self.lock_coordination(project_id)?;
        let installed_policy = self.policy(project_id)?;
        validate_delivery_id(delivery_id)?;
        if git_ref != "refs/heads/main" {
            return Err(SourceError::DirectPushRefRejected);
        }
        if !self.repository.contains_commit(project_id, &new_head)? {
            return Err(SourceError::Repository(
                "direct-push commit is absent from quarantine".to_owned(),
            ));
        }
        let payload_digest = EvidenceDigest::sha256(format!(
            "{}\n{}\n{}\n{}",
            git_ref,
            old_head.map_or("-", GitCommitId::as_str),
            new_head,
            project_id
        ));
        let delivery_claim = match self.store.reserve_delivery(
            project_id,
            SourceChannel::DirectPush,
            delivery_id,
            &payload_digest,
            now_ms,
        )? {
            DeliveryReservation::Completed(outcome) => return Ok(outcome),
            DeliveryReservation::Claimed(claim) => claim,
        };
        let result = self.process_candidate(&CandidateIngress {
            project_id,
            candidate: new_head,
            announced_previous_head: old_head,
            channel: SourceChannel::DirectPush,
            delivery_id,
            payload_digest: payload_digest.clone(),
            installed_policy,
            now_ms,
        });
        match result {
            Ok(outcome) => self.store.finish_delivery(
                &delivery_claim,
                &outcome,
                installed_policy.auto_deploy,
                now_ms,
            ),
            Err(error) => {
                self.store.abandon_delivery(&delivery_claim, now_ms)?;
                Err(error)
            }
        }
    }

    pub fn admit_recorded_deploy(
        &self,
        controller: &DurableController,
        project_id: &ProjectId,
        channel: SourceChannel,
        delivery_id: &str,
        now_ms: i64,
    ) -> Result<AdmissionOutcome, SourceError> {
        let _coordination = self.lock_coordination(project_id)?;
        let (delivery, payload, installed_policy) =
            self.verified_recorded_delivery(project_id, channel, delivery_id, now_ms)?;
        if !installed_policy.auto_deploy {
            return Err(SourceError::AutoDeployDisabled);
        }
        let operation = NewOperation {
            project_id: payload.project_id.clone(),
            operation_kind: OperationKind::Deploy,
            target_commit: Some(payload.head.clone()),
            release_class: Some(installed_policy.release_class),
            installed_policy: payload.installed_policy.clone(),
        };
        controller
            .admit_automation(
                &VerifiedAutomationAdmission {
                    operation,
                    delivery_channel: delivery.channel.controller_channel(),
                    delivery_id: format!(
                        "source-{}",
                        EvidenceDigest::sha256(format!(
                            "{}\n{}\n{}\n{}",
                            project_id,
                            channel.as_str(),
                            delivery.delivery_id,
                            delivery.payload_digest
                        ))
                    ),
                    payload_digest: delivery.payload_digest,
                    source_attestation_digest: delivery.attestation_digest,
                    accepted_head: payload.head.clone(),
                    accepted_sequence: payload.sequence,
                    maximum_attempts: installed_policy.maximum_attempts,
                },
                now_ms,
            )
            .map_err(SourceError::Controller)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit_recorded_interactive_deploy(
        &self,
        controller: &DurableController,
        project_id: &ProjectId,
        channel: SourceChannel,
        delivery_id: &str,
        lease: &TabLeaseClaim,
        grant: &ActionGrantClaims,
        now_ms: i64,
    ) -> Result<AdmissionOutcome, SourceError> {
        let _coordination = self.lock_coordination(project_id)?;
        let (delivery, payload, installed_policy) =
            self.verified_recorded_delivery(project_id, channel, delivery_id, now_ms)?;
        let operation = NewOperation {
            project_id: payload.project_id,
            operation_kind: OperationKind::Deploy,
            target_commit: Some(payload.head.clone()),
            release_class: Some(installed_policy.release_class),
            installed_policy: payload.installed_policy,
        };
        controller
            .admit_verified_interactive_deploy(
                &VerifiedInteractiveDeployAdmission {
                    operation,
                    source_attestation_digest: delivery.attestation_digest,
                    accepted_head: payload.head,
                    accepted_sequence: payload.sequence,
                },
                lease,
                grant,
                now_ms,
            )
            .map_err(SourceError::Controller)
    }

    fn verified_recorded_delivery(
        &self,
        project_id: &ProjectId,
        channel: SourceChannel,
        delivery_id: &str,
        now_ms: i64,
    ) -> Result<
        (
            VerifiedSourceDelivery,
            AcceptedHeadV1,
            InstalledSourceProjectPolicy,
        ),
        SourceError,
    > {
        validate_delivery_id(delivery_id)?;
        let outcome = self
            .store
            .recorded_delivery(project_id, channel, delivery_id)?
            .ok_or(SourceError::DeliveryNotRecorded)?;
        let SourceIngressOutcome::Deployable(delivery) = outcome else {
            return Err(SourceError::DeliveryNotDeployable);
        };
        let delivery = *delivery;
        if delivery.channel != channel || delivery.delivery_id != delivery_id {
            return Err(SourceError::CorruptLedger("delivery binding"));
        }
        if delivery.attestation.payload.project_id != *project_id {
            return Err(SourceError::CorruptLedger("delivery project binding"));
        }
        let payload = self.verifier.verify(&delivery.attestation, now_ms)?.clone();
        if delivery.attestation.digest()? != delivery.attestation_digest {
            return Err(SourceError::Attestation(
                SourceAttestationError::DigestMismatch,
            ));
        }
        self.verify_delivery_live(&delivery, true, now_ms)?;
        let installed_policy = self.policy(&payload.project_id)?.clone();
        if payload.installed_policy != installed_policy.installed_policy
            || payload.repository_identity != installed_policy.repository_identity
        {
            return Err(SourceError::InstalledPolicyChanged);
        }
        Ok((delivery, payload, installed_policy))
    }

    fn process_candidate(
        &self,
        ingress: &CandidateIngress<'_>,
    ) -> Result<SourceIngressOutcome, SourceError> {
        let project_id = ingress.project_id;
        let candidate = &ingress.candidate;
        let channel = ingress.channel;
        let now_ms = ingress.now_ms;
        for _ in 0..4 {
            let current = self.store.snapshot(project_id)?;
            if current.state == SourceProjectState::SourceDivergedNeedsOwner {
                return Ok(SourceIngressOutcome::SourceDivergedNeedsOwner);
            }
            if channel == SourceChannel::SourceReconciliation
                && current
                    .reconcile_paused_until_ms
                    .is_some_and(|until| now_ms < until)
            {
                return Ok(SourceIngressOutcome::ReconciliationPaused);
            }
            if current.blocked_sha.as_ref() == Some(candidate) {
                return Ok(SourceIngressOutcome::BlockedSha {
                    head: candidate.clone(),
                });
            }

            let relationship = current
                .head
                .as_ref()
                .map(|head| self.repository.relationship(project_id, head, candidate))
                .transpose()?;
            match relationship {
                Some(CommitRelationship::Rewind)
                    if channel == SourceChannel::DirectPush
                        && ingress.announced_previous_head != current.head.as_ref() =>
                {
                    return Ok(SourceIngressOutcome::StaleNoop {
                        announced_head: candidate.clone(),
                    });
                }
                Some(CommitRelationship::Rewind | CommitRelationship::Diverged) => {
                    self.store.mark_diverged(
                        project_id,
                        candidate,
                        channel,
                        &ingress.payload_digest,
                        now_ms,
                    )?;
                    return Ok(SourceIngressOutcome::SourceDivergedNeedsOwner);
                }
                Some(CommitRelationship::Same) => {
                    if let Some(outcome) = existing_same_head_delivery(&current, ingress)? {
                        return Ok(outcome);
                    }
                    // A root-owned policy change deliberately re-attests the unchanged head and
                    // advances the sequence, invalidating work authorized by the old policy.
                }
                None | Some(CommitRelationship::FastForward) => {}
            }

            let sequence = current
                .sequence
                .checked_add(1)
                .ok_or(SourceError::SequenceExhausted)?;
            let expires_at_ms = now_ms
                .checked_add(self.attestation_ttl_ms)
                .ok_or(SourceError::TimeRange)?;
            let signed = SignedAcceptedHeadV1::sign(
                &self.key_id,
                AcceptedHeadV1 {
                    schema_version: ACCEPTED_HEAD_SCHEMA_VERSION,
                    project_id: project_id.clone(),
                    head: candidate.clone(),
                    sequence,
                    previous_head: current.head.clone(),
                    accepted_via: channel,
                    repository_identity: ingress.installed_policy.repository_identity.clone(),
                    installed_policy: ingress.installed_policy.installed_policy.clone(),
                    accepted_at_ms: now_ms,
                    expires_at_ms,
                },
                &self.signing_key,
            )?;
            let attestation_digest = signed.digest()?;
            match self.advance_ref_update(&current, &signed, &attestation_digest, now_ms) {
                Ok(true) => {
                    return Ok(SourceIngressOutcome::Deployable(Box::new(
                        VerifiedSourceDelivery {
                            channel,
                            delivery_id: ingress.delivery_id.to_owned(),
                            payload_digest: ingress.payload_digest.clone(),
                            attestation: signed,
                            attestation_digest,
                        },
                    )));
                }
                Ok(false) => return Ok(SourceIngressOutcome::SourceDivergedNeedsOwner),
                Err(SourceError::ConcurrentSourceUpdate) => {}
                Err(error) => return Err(error),
            }
        }
        Err(SourceError::ConcurrentSourceUpdate)
    }

    fn verify_delivery_live(
        &self,
        delivery: &VerifiedSourceDelivery,
        enforce_expiry: bool,
        now_ms: i64,
    ) -> Result<(), SourceError> {
        let payload = if enforce_expiry {
            self.verifier.verify(&delivery.attestation, now_ms)?
        } else {
            self.verifier.verify_live(&delivery.attestation)?
        };
        let current = self.store.snapshot(&payload.project_id)?;
        if current.state != SourceProjectState::Ready
            || current.head.as_ref() != Some(&payload.head)
            || current.sequence != payload.sequence
            || current.attestation_digest.as_ref() != Some(&delivery.attestation_digest)
        {
            return Err(SourceError::HeadNotCurrent);
        }
        if current.blocked_sha.as_ref() == Some(&payload.head) {
            return Err(SourceError::BlockedSha);
        }
        Ok(())
    }

    fn policy(&self, project_id: &ProjectId) -> Result<&InstalledSourceProjectPolicy, SourceError> {
        self.policies
            .get(project_id.as_str())
            .ok_or_else(|| SourceError::UnknownProject(project_id.to_string()))
    }
}

fn existing_same_head_delivery(
    current: &SourceSnapshot,
    ingress: &CandidateIngress<'_>,
) -> Result<Option<SourceIngressOutcome>, SourceError> {
    let attestation = current
        .attestation
        .as_ref()
        .ok_or(SourceError::CorruptLedger("current head lacks attestation"))?;
    if attestation.payload.installed_policy != ingress.installed_policy.installed_policy
        || attestation.payload.repository_identity != ingress.installed_policy.repository_identity
        || ingress.now_ms >= attestation.payload.expires_at_ms
    {
        return Ok(None);
    }
    let attestation_digest =
        current
            .attestation_digest
            .clone()
            .ok_or(SourceError::CorruptLedger(
                "current head lacks attestation digest",
            ))?;
    Ok(Some(SourceIngressOutcome::Deployable(Box::new(
        VerifiedSourceDelivery {
            channel: ingress.channel,
            delivery_id: ingress.delivery_id.to_owned(),
            payload_digest: ingress.payload_digest.clone(),
            attestation: attestation.clone(),
            attestation_digest,
        },
    ))))
}

pub trait LiveSourceGate: Send + Sync + std::fmt::Debug {
    /// Atomically acquires or replays the operation's mutation ticket and returns its proof.
    /// An error may be ambiguous to the caller, so the same operation and phase must be safe to
    /// retry while ownership remains held.
    fn check_live(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<SourceGateProof, SourceGateError>;

    fn complete_live(&self, _operation: &OperationRecord) -> Result<(), SourceGateError> {
        Ok(())
    }

    /// Idempotently releases a pre-effect mutation ticket. On error the ticket must be treated as
    /// still held and the original phase retried; it is not evidence of an ambiguous phase effect.
    fn abort_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        self.complete_live(operation)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceGateProof {
    pub digest: EvidenceDigest,
    pub project_id: ProjectId,
    pub sequence: u64,
    pub attestation_digest: EvidenceDigest,
    pub checked_at_ms: i64,
}

#[derive(Serialize)]
struct SourceGateProofPayload<'a> {
    purpose: &'static str,
    attempt_id: uuid::Uuid,
    project_id: &'a ProjectId,
    phase: OperationPhase,
    target: &'a GitCommitId,
    sequence: u64,
    attestation_digest: &'a EvidenceDigest,
    installed_policy: &'a InstalledPolicyIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LiveSourceBinding {
    target: GitCommitId,
    sequence: u64,
    attestation_digest: EvidenceDigest,
    installed_policy: InstalledPolicyIdentity,
}

impl<R: SourceRepository> DurableSourceBroker<R> {
    fn verify_live_binding(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<LiveSourceBinding, SourceGateError> {
        let target = operation
            .target_commit
            .clone()
            .ok_or(SourceGateError::AttestationInvalid)?;
        let attestation_digest = operation
            .evidence
            .source_attestation_digest
            .clone()
            .ok_or(SourceGateError::AttestationInvalid)?;
        let installed_policy = operation
            .evidence
            .installed_policy
            .clone()
            .ok_or(SourceGateError::AttestationInvalid)?;
        let broker_policy = self
            .policy(&operation.project_id)
            .map_err(|_| SourceGateError::AttestationInvalid)?;
        let current = self
            .store
            .snapshot(&operation.project_id)
            .map_err(|_| SourceGateError::Unavailable)?;
        if self
            .store
            .has_pending_ref_update(&operation.project_id)
            .map_err(|_| SourceGateError::Unavailable)?
        {
            return Err(SourceGateError::Unavailable);
        }
        if current
            .reconcile_paused_until_ms
            .is_some_and(|until_ms| now_ms < until_ms)
        {
            return Err(SourceGateError::Paused);
        }
        let repository_head = self
            .repository
            .accepted_head(&operation.project_id)
            .map_err(|_| SourceGateError::Unavailable)?;
        if repository_head != current.head
            || current.state == SourceProjectState::SourceDivergedNeedsOwner
        {
            return Err(SourceGateError::Diverged);
        }
        if current.head.as_ref() != Some(&target)
            || current.sequence != operation.evidence.source_sequence.unwrap_or_default()
        {
            return Err(SourceGateError::HeadSuperseded);
        }
        if current.blocked_sha.as_ref() == Some(&target) {
            return Err(SourceGateError::BlockedSha);
        }
        let signed = current
            .attestation
            .as_ref()
            .ok_or(SourceGateError::AttestationInvalid)?;
        let payload = self
            .verifier
            .verify_live(signed)
            .map_err(|_| SourceGateError::AttestationInvalid)?;
        if current.sequence != payload.sequence
            || payload.project_id != operation.project_id
            || payload.head != target
            || payload.installed_policy != installed_policy
            || payload.installed_policy != broker_policy.installed_policy
            || payload.repository_identity != broker_policy.repository_identity
            || operation.evidence.source_sequence != Some(payload.sequence)
            || current.attestation_digest.as_ref() != Some(&attestation_digest)
            || signed
                .digest()
                .map_err(|_| SourceGateError::AttestationInvalid)?
                != attestation_digest
        {
            return Err(SourceGateError::AttestationInvalid);
        }
        Ok(LiveSourceBinding {
            target,
            sequence: payload.sequence,
            attestation_digest,
            installed_policy,
        })
    }
}

impl<R: SourceRepository> LiveSourceGate for DurableSourceBroker<R> {
    fn check_live(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<SourceGateProof, SourceGateError> {
        let _coordination = self
            .lock_coordination(&operation.project_id)
            .map_err(|_| SourceGateError::Unavailable)?;
        if operation.operation_kind != OperationKind::Deploy {
            return Ok(SourceGateProof {
                digest: EvidenceDigest::sha256("source-gate-not-required"),
                project_id: operation.project_id.clone(),
                sequence: 0,
                attestation_digest: EvidenceDigest::sha256("source-gate-not-required"),
                checked_at_ms: now_ms,
            });
        }
        let binding = self.verify_live_binding(operation, now_ms)?;
        let proof_payload = SourceGateProofPayload {
            purpose: "rdashboard.source-live-proof.v1",
            attempt_id: operation.attempt_id,
            project_id: &operation.project_id,
            phase: mutation_ticket_phase(operation.state.phase)
                .map_err(|error| source_ticket_gate_error(&error))?,
            target: &binding.target,
            sequence: binding.sequence,
            attestation_digest: &binding.attestation_digest,
            installed_policy: &binding.installed_policy,
        };
        let canonical =
            serde_jcs::to_vec(&proof_payload).map_err(|_| SourceGateError::AttestationInvalid)?;
        self.store
            .acquire_mutation_ticket(operation, now_ms)
            .map_err(|error| source_ticket_gate_error(&error))?;
        Ok(SourceGateProof {
            digest: EvidenceDigest::sha256(canonical),
            project_id: operation.project_id.clone(),
            sequence: binding.sequence,
            attestation_digest: binding.attestation_digest,
            checked_at_ms: now_ms,
        })
    }

    fn complete_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        let _coordination = self
            .lock_coordination(&operation.project_id)
            .map_err(|_| SourceGateError::Unavailable)?;
        self.store
            .release_mutation_ticket(operation)
            .map_err(|_| SourceGateError::Unavailable)
    }

    fn abort_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        let _coordination = self
            .lock_coordination(&operation.project_id)
            .map_err(|_| SourceGateError::Unavailable)?;
        self.store
            .release_mutation_ticket(operation)
            .map_err(|_| SourceGateError::Unavailable)
    }
}

fn source_ticket_gate_error(error: &SourceError) -> SourceGateError {
    match error {
        SourceError::HeadNotCurrent => SourceGateError::HeadSuperseded,
        SourceError::BlockedSha => SourceGateError::BlockedSha,
        _ => SourceGateError::Unavailable,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceGateError {
    #[error("source broker is unavailable")]
    Unavailable,
    #[error("source head was superseded")]
    HeadSuperseded,
    #[error("source attestation is invalid")]
    AttestationInvalid,
    #[error("source histories diverged and require an owner decision")]
    Diverged,
    #[error("source SHA is blocked by policy")]
    BlockedSha,
    #[error("source reconciliation is paused")]
    Paused,
}

fn mutation_ticket_phase(phase: OperationPhase) -> Result<OperationPhase, SourceError> {
    match phase {
        OperationPhase::CutoverSnapshotting => Ok(OperationPhase::BackingUp),
        OperationPhase::BackingUp | OperationPhase::Draining | OperationPhase::Deploying => {
            Ok(phase)
        }
        _ => Err(SourceError::InvalidMutationTicketPhase),
    }
}

fn mutation_phase_name(phase: OperationPhase) -> Result<&'static str, SourceError> {
    match mutation_ticket_phase(phase)? {
        OperationPhase::BackingUp => Ok("backing_up"),
        OperationPhase::Draining => Ok("draining"),
        OperationPhase::Deploying => Ok("deploying"),
        _ => unreachable!("mutation ticket phase was normalized above"),
    }
}

#[derive(Deserialize)]
struct GithubPushPayload {
    #[serde(rename = "ref")]
    git_ref: String,
    after: String,
}

pub fn verify_github_hmac(
    signature_header: &str,
    secret: &[u8],
    raw_body: &[u8],
) -> Result<(), SourceError> {
    if secret.len() < 16 {
        return Err(SourceError::WebhookSecretTooShort);
    }
    let Some(encoded) = signature_header.strip_prefix("sha256=") else {
        return Err(SourceError::InvalidWebhookSignature);
    };
    let received = decode_hex_32(encoded).ok_or(SourceError::InvalidWebhookSignature)?;
    let expected = hmac_sha256(secret, raw_body);
    if !bool::from(expected.ct_eq(&received)) {
        return Err(SourceError::InvalidWebhookSignature);
    }
    Ok(())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut normalized = [0_u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];
    for ((inner, outer), byte) in inner_pad
        .iter_mut()
        .zip(outer_pad.iter_mut())
        .zip(normalized)
    {
        *inner ^= byte;
        *outer ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Some(output)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn validate_delivery_id(delivery_id: &str) -> Result<(), SourceError> {
    if delivery_id.is_empty()
        || delivery_id.len() > MAX_DELIVERY_ID_BYTES
        || !delivery_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(SourceError::InvalidDeliveryId);
    }
    Ok(())
}

pub fn validate_forced_receive_command(
    original_command: &str,
    canonical_repo_path: &str,
) -> Result<(), SourceError> {
    if !canonical_repo_path.starts_with('/')
        || canonical_repo_path.contains('\'')
        || canonical_repo_path.contains('\n')
        || canonical_repo_path.contains('\r')
    {
        return Err(SourceError::InvalidCanonicalRepositoryPath);
    }
    let expected = format!("git-receive-pack '{canonical_repo_path}'");
    if original_command
        .as_bytes()
        .ct_eq(expected.as_bytes())
        .into()
    {
        Ok(())
    } else {
        Err(SourceError::ForcedCommandRejected)
    }
}

fn open_source_lock_file(path: &Path) -> Result<File, SourceError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn validate_source_lock_environment(
    database_path: &Path,
    lock_path: &Path,
) -> Result<(), SourceError> {
    let parent = database_path
        .parent()
        .ok_or(SourceError::UntrustedBrokerLock)?;
    if !database_path.is_absolute()
        || fs::canonicalize(database_path)? != database_path
        || fs::canonicalize(parent)? != parent
        || lock_path.parent() != Some(parent)
    {
        return Err(SourceError::UntrustedBrokerLock);
    }
    let database = fs::symlink_metadata(database_path)?;
    let directory = fs::symlink_metadata(parent)?;
    if database.file_type().is_symlink() || !database.is_file() || !directory.is_dir() {
        return Err(SourceError::UntrustedBrokerLock);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if database.uid() != directory.uid()
            || database.permissions().mode() & 0o022 != 0
            || directory.permissions().mode() & 0o022 != 0
            || database.nlink() != 1
        {
            return Err(SourceError::UntrustedBrokerLock);
        }
        if lock_path.try_exists()? {
            let lock = fs::symlink_metadata(lock_path)?;
            if lock.file_type().is_symlink()
                || !lock.is_file()
                || lock.uid() != database.uid()
                || lock.permissions().mode() & 0o777 != 0o600
                || lock.nlink() != 1
            {
                return Err(SourceError::UntrustedBrokerLock);
            }
        }
    }
    Ok(())
}

fn validate_source_lock_file(database_path: &Path, lock_path: &Path) -> Result<(), SourceError> {
    let lock = fs::symlink_metadata(lock_path)?;
    if lock.file_type().is_symlink() || !lock.is_file() {
        return Err(SourceError::UntrustedBrokerLock);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let database = fs::metadata(database_path)?;
        if lock.uid() != database.uid()
            || lock.permissions().mode() & 0o777 != 0o600
            || lock.nlink() != 1
        {
            return Err(SourceError::UntrustedBrokerLock);
        }
    }
    Ok(())
}

fn validate_open_source_lock_file(
    database_path: &Path,
    lock_path: &Path,
    lock_file: &File,
) -> Result<(), SourceError> {
    validate_source_lock_file(database_path, lock_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let path_metadata = fs::symlink_metadata(lock_path)?;
        let open_metadata = lock_file.metadata()?;
        let database_metadata = fs::metadata(database_path)?;
        if path_metadata.dev() != open_metadata.dev()
            || path_metadata.ino() != open_metadata.ino()
            || open_metadata.uid() != database_metadata.uid()
            || open_metadata.permissions().mode() & 0o777 != 0o600
            || open_metadata.nlink() != 1
        {
            return Err(SourceError::UntrustedBrokerLock);
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SourceAttestationError {
    #[error("unsupported accepted-head schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("accepted-head sequence must be positive")]
    ZeroSequence,
    #[error("accepted-head policy version must be positive")]
    ZeroPolicyVersion,
    #[error("accepted-head validity window is invalid")]
    InvalidValidityWindow,
    #[error("accepted-head attestation expired")]
    Expired,
    #[error("accepted-head keyring must not be empty")]
    EmptyKeyring,
    #[error("accepted-head key identifier is invalid")]
    InvalidKeyId,
    #[error("accepted-head key {0} is unknown")]
    UnknownKey(String),
    #[error("accepted-head canonical encoding failed: {0}")]
    CanonicalEncoding(serde_json::Error),
    #[error("accepted-head signature is not base64url: {0}")]
    InvalidSignatureEncoding(base64::DecodeError),
    #[error("accepted-head signature has the wrong length: {0}")]
    InvalidSignature(ed25519_dalek::SignatureError),
    #[error("accepted-head signature verification failed: {0}")]
    SignatureVerification(ed25519_dalek::SignatureError),
    #[error("accepted-head digest does not match its signed payload")]
    DigestMismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("source filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("source SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("source JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Attestation(#[from] SourceAttestationError),
    #[error("controller rejected verified source admission: {0}")]
    Controller(#[source] StoreError),
    #[error("source database mutex was poisoned")]
    LockPoisoned,
    #[error("another source broker process already holds the singleton lease")]
    BrokerAlreadyRunning,
    #[error("source broker epoch was superseded by a newer process")]
    BrokerLeaseSuperseded,
    #[error("source broker lock path, ownership, or permissions are not trusted")]
    UntrustedBrokerLock,
    #[error("source schema version {0} is unsupported")]
    UnsupportedSchemaVersion(i64),
    #[error("persisted source ledger is corrupt: {0}")]
    CorruptLedger(&'static str),
    #[error("source sequence is outside the supported range")]
    SequenceRange,
    #[error("source sequence exhausted")]
    SequenceExhausted,
    #[error("source clock range exhausted")]
    TimeRange,
    #[error("source delivery identifier is invalid")]
    InvalidDeliveryId,
    #[error("source delivery identity was reused with different content")]
    DeliveryConflict,
    #[error("source delivery is already being processed")]
    DeliveryInProgress,
    #[error("source delivery reservation was lost before completion")]
    DeliveryReservationLost,
    #[error("source delivery is not present in the durable inbox")]
    DeliveryNotRecorded,
    #[error("source delivery did not produce a deployable accepted head")]
    DeliveryNotDeployable,
    #[error("source outbox batch limit is invalid")]
    InvalidOutboxLimit,
    #[error("source outbox acknowledgement is invalid")]
    InvalidOutboxAcknowledgement,
    #[error("source outbox entry does not exist")]
    OutboxEntryMissing,
    #[error("source outbox acknowledgement conflicts with durable state")]
    OutboxAcknowledgementConflict,
    #[error("webhook secret must contain at least 16 bytes")]
    WebhookSecretTooShort,
    #[error("GitHub webhook signature is invalid")]
    InvalidWebhookSignature,
    #[error("GitHub webhook body exceeds the configured limit")]
    WebhookBodyTooLarge,
    #[error("GitHub webhook payload is invalid")]
    InvalidWebhookPayload,
    #[error("source repository operation failed: {0}")]
    Repository(String),
    #[error("installed source policy does not match the configured canonical repository")]
    RepositoryIdentityMismatch,
    #[error("source changed concurrently; retry from a fresh ledger snapshot")]
    ConcurrentSourceUpdate,
    #[error("source advancement is fenced while an admitted mutation begins")]
    MutationAdmissionBusy,
    #[error("source mutation ticket does not match its admitted attempt and phase")]
    MutationTicketMismatch,
    #[error("source mutation ticket phase is invalid for this operation")]
    InvalidMutationTicketPhase,
    #[error("a different canonical source ref update is already pending")]
    PendingRefUpdateConflict,
    #[error("direct push may update only refs/heads/main")]
    DirectPushRefRejected,
    #[error("source head is no longer current")]
    HeadNotCurrent,
    #[error("source SHA is blocked")]
    BlockedSha,
    #[error("source reconciliation is paused")]
    ReconciliationPaused,
    #[error("invalid source control: {0}")]
    InvalidControl(&'static str),
    #[error("owner divergence resolution did not match the current canonical head")]
    OwnerResolutionMismatch,
    #[error("canonical source repository path is invalid")]
    InvalidCanonicalRepositoryPath,
    #[error("SSH forced command was rejected")]
    ForcedCommandRejected,
    #[error("installed source policy is invalid")]
    InvalidInstalledPolicy,
    #[error("installed source policy contains a duplicate project")]
    DuplicateInstalledProject,
    #[error("source project {0} is not installed")]
    UnknownProject(String),
    #[error("automatic deployment is disabled for this project")]
    AutoDeployDisabled,
    #[error("installed source policy changed after the head was accepted")]
    InstalledPolicyChanged,
}
