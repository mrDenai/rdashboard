use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::{
        EvidenceDigest, GitCommitId, OperationKind, ProjectId, ProjectManifestV2,
        WorkflowCacheClassV1, WorkflowCleanupReceiptV1, WorkflowCleanupResultV1,
        WorkflowExecutionProfileV1, WorkflowLeaseInputV1, WorkflowLeaseV1,
        WorkflowNodeActivationV1, WorkflowNodeId, WorkflowNodeKindV1, WorkflowNodeOutcomeV1,
        WorkflowNodeReceiptV1, WorkflowOperationStateV1, WorkflowProfileId,
        WorkflowReductionInputV1, WorkflowReductionReceiptV1, WorkflowWorkerPoolV1,
        valid_workflow_identity,
    },
    store::{ControlStore, StoreError},
};

const MIN_LEASE_MS: i64 = 1_000;
const MAX_LEASE_MS: i64 = 15 * 60 * 1_000;
const MAX_OPERATION_STATE_BYTES: u64 = 6 * 1024 * 1024 * 1024;
const MAX_OPERATION_STATE_INODES: u64 = 500_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowTriggerChannelV1 {
    GithubWebhook,
    SourceReconciliation,
    DirectPush,
}

impl WorkflowTriggerChannelV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::GithubWebhook => "github_webhook",
            Self::SourceReconciliation => "source_reconciliation",
            Self::DirectPush => "direct_push",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowAdmissionV1 {
    pub project_id: ProjectId,
    pub workflow_policy_digest: EvidenceDigest,
    pub source_sha: GitCommitId,
    pub operation_kind: OperationKind,
    pub source_sequence: u64,
    pub source_attestation_digest: EvidenceDigest,
    pub trigger_channel: WorkflowTriggerChannelV1,
    pub delivery_id: String,
    pub payload_digest: EvidenceDigest,
    pub priority: u8,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowAttemptStateV1 {
    Queued,
    WaitingForMutation,
    Running,
    Succeeded,
    Failed,
    Superseded,
    NeedsReconcile,
}

impl WorkflowAttemptStateV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::WaitingForMutation => "waiting_for_mutation",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Superseded => "superseded",
            Self::NeedsReconcile => "needs_reconcile",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "queued" => Ok(Self::Queued),
            "waiting_for_mutation" => Ok(Self::WaitingForMutation),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "superseded" => Ok(Self::Superseded),
            "needs_reconcile" => Ok(Self::NeedsReconcile),
            _ => Err(StoreError::CorruptWorkflowJournal("attempt state")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowMutationStateV1 {
    NotStarted,
    Owned,
    NeedsReconcile,
    Complete,
}

impl WorkflowMutationStateV1 {
    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "not_started" => Ok(Self::NotStarted),
            "owned" => Ok(Self::Owned),
            "needs_reconcile" => Ok(Self::NeedsReconcile),
            "complete" => Ok(Self::Complete),
            _ => Err(StoreError::CorruptWorkflowJournal("mutation state")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowCleanupStateV1 {
    Complete,
    Pending,
}

impl WorkflowCleanupStateV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Pending => "pending",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "complete" => Ok(Self::Complete),
            "pending" => Ok(Self::Pending),
            _ => Err(StoreError::CorruptWorkflowJournal("cleanup state")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowNodeStateV1 {
    Dormant,
    Blocked,
    Ready,
    Leased,
    Succeeded,
    Failed,
    Cancelled,
    NeedsReconcile,
}

impl WorkflowNodeStateV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Dormant => "dormant",
            Self::Blocked => "blocked",
            Self::Ready => "ready",
            Self::Leased => "leased",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::NeedsReconcile => "needs_reconcile",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "dormant" => Ok(Self::Dormant),
            "blocked" => Ok(Self::Blocked),
            "ready" => Ok(Self::Ready),
            "leased" => Ok(Self::Leased),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "needs_reconcile" => Ok(Self::NeedsReconcile),
            _ => Err(StoreError::CorruptWorkflowJournal("node state")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkflowNodeSnapshotV1 {
    pub node_id: WorkflowNodeId,
    pub kind: WorkflowNodeKindV1,
    pub profile_id: WorkflowProfileId,
    pub worker_pool: WorkflowWorkerPoolV1,
    pub state: WorkflowNodeStateV1,
    pub lease_generation: u32,
    pub output_digest: Option<EvidenceDigest>,
    pub receipt_digest: Option<EvidenceDigest>,
    pub completed_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkflowAttemptSnapshotV1 {
    pub request_id: Uuid,
    pub attempt_id: Uuid,
    pub attempt_number: u32,
    pub project_id: ProjectId,
    pub source_sha: GitCommitId,
    pub source_sequence: u64,
    pub workflow_policy_digest: EvidenceDigest,
    pub source_attestation_digest: EvidenceDigest,
    pub preparation_key: EvidenceDigest,
    pub priority: u8,
    pub state: WorkflowAttemptStateV1,
    pub mutation_state: WorkflowMutationStateV1,
    pub cleanup_state: WorkflowCleanupStateV1,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub terminal_at_ms: Option<i64>,
    pub nodes: Vec<WorkflowNodeSnapshotV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowAdmissionOutcomeV1 {
    Created(WorkflowAttemptSnapshotV1),
    Existing(WorkflowAttemptSnapshotV1),
}

impl WorkflowAdmissionOutcomeV1 {
    pub const fn attempt(&self) -> &WorkflowAttemptSnapshotV1 {
        match self {
            Self::Created(attempt) | Self::Existing(attempt) => attempt,
        }
    }

    pub const fn created(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkflowWorkerRegistrationV1 {
    pub worker_id: String,
    pub host_id: String,
    pub pools: BTreeSet<WorkflowWorkerPoolV1>,
}

impl WorkflowWorkerRegistrationV1 {
    pub fn validate(&self) -> Result<(), StoreError> {
        if !valid_workflow_identity(&self.worker_id)
            || !valid_workflow_identity(&self.host_id)
            || self.pools.is_empty()
            || self.pools.len() > 4
        {
            return Err(StoreError::InvalidWorkflowSchedulerInput(
                "worker registration",
            ));
        }
        Ok(())
    }

    pub fn validate_unprivileged(&self) -> Result<(), StoreError> {
        self.validate()?;
        if self.pools.iter().any(|pool| {
            matches!(
                pool,
                WorkflowWorkerPoolV1::Controller | WorkflowWorkerPoolV1::PrivilegedExecutor
            )
        }) {
            return Err(StoreError::InvalidWorkflowSchedulerInput(
                "unprivileged worker pools",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowCleanupReasonV1 {
    LeaseExpired,
    LeaseRevoked,
    TerminalReceiptPending,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkflowCleanupObligationV1 {
    pub lease: WorkflowLeaseV1,
    pub terminal_receipt: Option<WorkflowNodeReceiptV1>,
    pub reason: WorkflowCleanupReasonV1,
}

#[derive(Clone, Debug)]
pub struct DurableWorkflowScheduler {
    store: ControlStore,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkflowAttemptPageV1 {
    pub truncated: bool,
    pub attempts: Vec<WorkflowAttemptSnapshotV1>,
}

#[derive(Clone, Debug)]
pub struct WorkflowJournalReaderV1 {
    store: ControlStore,
}

impl WorkflowJournalReaderV1 {
    pub const fn new(store: ControlStore) -> Self {
        Self { store }
    }

    pub fn recent_attempts(&self, limit: usize) -> Result<WorkflowAttemptPageV1, StoreError> {
        if !(1..=50).contains(&limit) {
            return Err(StoreError::InvalidWorkflowSchedulerInput(
                "workflow overview limit",
            ));
        }
        let query_limit = i64::try_from(limit.saturating_add(1))
            .map_err(|_| StoreError::InvalidWorkflowSchedulerInput("workflow overview limit"))?;
        self.store.read_transaction(|transaction| {
            let mut statement = transaction.prepare(
                "SELECT attempt_id FROM workflow_attempts
                 ORDER BY updated_at_ms DESC, created_at_ms DESC, attempt_id ASC
                 LIMIT ?1",
            )?;
            let mut attempt_ids = statement
                .query_map([query_limit], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            let truncated = attempt_ids.len() > limit;
            attempt_ids.truncate(limit);
            let attempts = attempt_ids
                .into_iter()
                .map(|attempt_id| {
                    let attempt_id = parse_uuid(&attempt_id, "workflow overview attempt ID")?;
                    load_attempt_snapshot(transaction, attempt_id)
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            Ok(WorkflowAttemptPageV1 {
                truncated,
                attempts,
            })
        })
    }
}

impl DurableWorkflowScheduler {
    pub const fn new(store: ControlStore) -> Self {
        Self { store }
    }

    pub const fn store(&self) -> &ControlStore {
        &self.store
    }

    pub fn admit(
        &self,
        manifest: &ProjectManifestV2,
        admission: &WorkflowAdmissionV1,
        admitted_at_ms: i64,
    ) -> Result<WorkflowAdmissionOutcomeV1, StoreError> {
        validate_admission(manifest, admission, admitted_at_ms)?;
        let manifest_bytes = manifest.canonical_bytes()?;
        let manifest_json = std::str::from_utf8(&manifest_bytes)
            .map_err(|_| StoreError::InvalidWorkflowSchedulerInput("manifest encoding"))?
            .to_owned();
        self.store.immediate_transaction(|transaction| {
            if let Some(existing) = replayed_trigger(transaction, admission)? {
                return Ok(WorkflowAdmissionOutcomeV1::Existing(existing));
            }
            validate_project_head(transaction, admission)?;
            if let Some(request_id) = find_stable_request(transaction, admission)? {
                let attempt = load_latest_attempt_for_request(transaction, request_id)?;
                record_trigger(transaction, admission, request_id, admitted_at_ms)?;
                update_project_head(transaction, admission, request_id, admitted_at_ms)?;
                return Ok(WorkflowAdmissionOutcomeV1::Existing(attempt));
            }

            let request_id = Uuid::new_v4();
            transaction.execute(
                "INSERT INTO workflow_requests(
                    request_id, project_id, workflow_policy_digest, source_sha,
                    operation_kind, source_sequence, source_attestation_digest,
                    manifest_json, priority, state, superseded_by_request_id,
                    created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, 'deploy', ?5, ?6, ?7, ?8,
                    'active', NULL, ?9, ?9)",
                params![
                    request_id.to_string(),
                    admission.project_id.as_str(),
                    admission.workflow_policy_digest.as_str(),
                    admission.source_sha.as_str(),
                    to_i64(admission.source_sequence, "source sequence")?,
                    admission.source_attestation_digest.as_str(),
                    manifest_json,
                    i64::from(admission.priority),
                    admitted_at_ms,
                ],
            )?;

            let waiting_for_mutation = supersede_pre_mutation_attempts(
                transaction,
                &admission.project_id,
                request_id,
                admitted_at_ms,
            )?;
            let attempt = create_attempt(
                transaction,
                manifest,
                admission,
                request_id,
                waiting_for_mutation,
                admitted_at_ms,
            )?;
            record_trigger(transaction, admission, request_id, admitted_at_ms)?;
            update_project_head(transaction, admission, request_id, admitted_at_ms)?;
            Ok(WorkflowAdmissionOutcomeV1::Created(attempt))
        })
    }

    pub fn attempt(
        &self,
        attempt_id: Uuid,
    ) -> Result<Option<WorkflowAttemptSnapshotV1>, StoreError> {
        if attempt_id.is_nil() {
            return Err(StoreError::InvalidWorkflowSchedulerInput("attempt ID"));
        }
        self.store.read_connection(|connection| {
            let exists = connection
                .query_row(
                    "SELECT 1 FROM workflow_attempts WHERE attempt_id = ?1",
                    [attempt_id.to_string()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            exists
                .then(|| load_attempt_snapshot(connection, attempt_id))
                .transpose()
        })
    }
}

fn validate_admission(
    manifest: &ProjectManifestV2,
    admission: &WorkflowAdmissionV1,
    admitted_at_ms: i64,
) -> Result<(), StoreError> {
    manifest.validate()?;
    if admission.project_id != manifest.project_id
        || admission.workflow_policy_digest != manifest.workflow_policy_digest()?
    {
        return Err(StoreError::WorkflowPolicyMismatch);
    }
    if admission.operation_kind != OperationKind::Deploy
        || admission.source_sequence == 0
        || admitted_at_ms < 0
        || admission.priority > 3
        || !valid_delivery_id(&admission.delivery_id)
    {
        return Err(StoreError::InvalidWorkflowSchedulerInput("admission"));
    }
    Ok(())
}

fn valid_delivery_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\'))
}

fn replayed_trigger(
    transaction: &Transaction<'_>,
    admission: &WorkflowAdmissionV1,
) -> Result<Option<WorkflowAttemptSnapshotV1>, StoreError> {
    let row = transaction
        .query_row(
            "SELECT payload_digest, request_id FROM workflow_triggers
             WHERE channel = ?1 AND delivery_id = ?2",
            params![admission.trigger_channel.as_str(), admission.delivery_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((payload_digest, request_id)) = row else {
        return Ok(None);
    };
    if payload_digest != admission.payload_digest.as_str() {
        return Err(StoreError::WorkflowDeliveryConflict);
    }
    let request_id = parse_uuid(&request_id, "trigger request ID")?;
    Ok(Some(load_latest_attempt_for_request(
        transaction,
        request_id,
    )?))
}

fn validate_project_head(
    transaction: &Transaction<'_>,
    admission: &WorkflowAdmissionV1,
) -> Result<(), StoreError> {
    let current = transaction
        .query_row(
            "SELECT source_sequence, source_sha FROM workflow_project_heads WHERE project_id = ?1",
            [admission.project_id.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((sequence, source_sha)) = current else {
        return Ok(());
    };
    let sequence = to_u64(sequence, "project source sequence")?;
    if admission.source_sequence < sequence {
        return Err(StoreError::WorkflowStaleSource);
    }
    if admission.source_sequence == sequence && admission.source_sha.as_str() != source_sha {
        return Err(StoreError::WorkflowSourceConflict);
    }
    Ok(())
}

fn find_stable_request(
    transaction: &Transaction<'_>,
    admission: &WorkflowAdmissionV1,
) -> Result<Option<Uuid>, StoreError> {
    transaction
        .query_row(
            "SELECT request_id FROM workflow_requests
             WHERE project_id = ?1 AND workflow_policy_digest = ?2
               AND source_sha = ?3 AND operation_kind = 'deploy'",
            params![
                admission.project_id.as_str(),
                admission.workflow_policy_digest.as_str(),
                admission.source_sha.as_str(),
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|value| parse_uuid(&value, "workflow request ID"))
        .transpose()
}

fn record_trigger(
    transaction: &Transaction<'_>,
    admission: &WorkflowAdmissionV1,
    request_id: Uuid,
    admitted_at_ms: i64,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO workflow_triggers(
            channel, delivery_id, payload_digest, request_id, received_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            admission.trigger_channel.as_str(),
            admission.delivery_id,
            admission.payload_digest.as_str(),
            request_id.to_string(),
            admitted_at_ms,
        ],
    )?;
    Ok(())
}

fn update_project_head(
    transaction: &Transaction<'_>,
    admission: &WorkflowAdmissionV1,
    request_id: Uuid,
    admitted_at_ms: i64,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO workflow_project_heads(
            project_id, source_sequence, source_sha, request_id, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(project_id) DO UPDATE SET
            source_sequence = excluded.source_sequence,
            source_sha = excluded.source_sha,
            request_id = excluded.request_id,
            updated_at_ms = excluded.updated_at_ms
         WHERE excluded.source_sequence >= workflow_project_heads.source_sequence",
        params![
            admission.project_id.as_str(),
            to_i64(admission.source_sequence, "source sequence")?,
            admission.source_sha.as_str(),
            request_id.to_string(),
            admitted_at_ms,
        ],
    )?;
    Ok(())
}

fn supersede_pre_mutation_attempts(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    new_request_id: Uuid,
    recorded_at_ms: i64,
) -> Result<bool, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT attempt.attempt_id, attempt.request_id, attempt.state,
                attempt.mutation_state
         FROM workflow_attempts AS attempt
         JOIN workflow_requests AS request ON request.request_id = attempt.request_id
         WHERE request.project_id = ?1
           AND request.request_id != ?2
           AND attempt.state IN ('queued', 'waiting_for_mutation', 'running', 'needs_reconcile')
         ORDER BY attempt.created_at_ms ASC",
    )?;
    let rows = statement
        .query_map(
            params![project_id.as_str(), new_request_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    let mut waiting_for_mutation = false;
    for (attempt_id, request_id, state, mutation_state) in rows {
        let attempt_id = parse_uuid(&attempt_id, "superseded attempt ID")?;
        let request_id = parse_uuid(&request_id, "superseded request ID")?;
        WorkflowAttemptStateV1::parse(&state)?;
        let mutation_state = WorkflowMutationStateV1::parse(&mutation_state)?;
        if mutation_state != WorkflowMutationStateV1::NotStarted {
            waiting_for_mutation = true;
            continue;
        }

        let active_leases = transaction.query_row(
            "SELECT COUNT(*) FROM workflow_lease_journal
             WHERE attempt_id = ?1 AND state = 'active'",
            [attempt_id.to_string()],
            |row| row.get::<_, i64>(0),
        )?;
        transaction.execute(
            "UPDATE workflow_lease_journal
             SET state = 'revoked', closed_at_ms = ?2
             WHERE attempt_id = ?1 AND state = 'active'",
            params![attempt_id.to_string(), recorded_at_ms],
        )?;
        transaction.execute(
            "UPDATE workflow_nodes
             SET state = 'cancelled', completed_at_ms = ?2
             WHERE attempt_id = ?1
               AND state IN ('dormant', 'blocked', 'ready', 'leased')",
            params![attempt_id.to_string(), recorded_at_ms],
        )?;
        transaction.execute(
            "UPDATE workflow_attempts
             SET state = 'superseded', cleanup_state = ?2,
                 updated_at_ms = ?3, terminal_at_ms = ?3
             WHERE attempt_id = ?1 AND mutation_state = 'not_started'",
            params![
                attempt_id.to_string(),
                if active_leases == 0 {
                    WorkflowCleanupStateV1::Complete.as_str()
                } else {
                    WorkflowCleanupStateV1::Pending.as_str()
                },
                recorded_at_ms,
            ],
        )?;
        transaction.execute(
            "UPDATE workflow_requests
             SET state = 'superseded', superseded_by_request_id = ?2, updated_at_ms = ?3
             WHERE request_id = ?1 AND state = 'active'",
            params![
                request_id.to_string(),
                new_request_id.to_string(),
                recorded_at_ms,
            ],
        )?;
        append_transition(
            transaction,
            attempt_id,
            "attempt",
            &attempt_id.to_string(),
            Some(&state),
            WorkflowAttemptStateV1::Superseded.as_str(),
            "newer_source_head",
            None,
            recorded_at_ms,
        )?;
    }
    Ok(waiting_for_mutation)
}

fn create_attempt(
    transaction: &Transaction<'_>,
    manifest: &ProjectManifestV2,
    admission: &WorkflowAdmissionV1,
    request_id: Uuid,
    waiting_for_mutation: bool,
    created_at_ms: i64,
) -> Result<WorkflowAttemptSnapshotV1, StoreError> {
    let attempt_id = Uuid::new_v4();
    let preparation_key = preparation_key(admission)?;
    let state = if waiting_for_mutation {
        WorkflowAttemptStateV1::WaitingForMutation
    } else {
        WorkflowAttemptStateV1::Queued
    };
    transaction.execute(
        "INSERT INTO workflow_attempts(
            attempt_id, request_id, attempt_number, preparation_key, state,
            mutation_state, cleanup_state, created_at_ms, updated_at_ms, terminal_at_ms
         ) VALUES (?1, ?2, 1, ?3, ?4, 'not_started', 'complete', ?5, ?5, NULL)",
        params![
            attempt_id.to_string(),
            request_id.to_string(),
            preparation_key.as_str(),
            state.as_str(),
            created_at_ms,
        ],
    )?;

    let ordered = manifest.workflow.ordered_nodes()?;
    for (ordinal, node) in ordered.iter().enumerate() {
        let profile = manifest
            .workflow
            .profile(&node.profile_id)
            .ok_or(StoreError::CorruptWorkflowJournal("manifest node profile"))?;
        let (node_state, output_digest, receipt_digest, completed_at_ms) = match node.kind {
            WorkflowNodeKindV1::SourceAdmission => (
                WorkflowNodeStateV1::Succeeded,
                Some(admission.source_attestation_digest.as_str()),
                Some(admission.source_attestation_digest.as_str()),
                Some(created_at_ms),
            ),
            WorkflowNodeKindV1::HostPrepare if !waiting_for_mutation => {
                (WorkflowNodeStateV1::Ready, None, None, None)
            }
            WorkflowNodeKindV1::Rollback => (WorkflowNodeStateV1::Dormant, None, None, None),
            _ => (WorkflowNodeStateV1::Blocked, None, None, None),
        };
        transaction.execute(
            "INSERT INTO workflow_nodes(
                attempt_id, node_id, ordinal, node_kind, activation, profile_id,
                worker_pool, state, lease_generation, output_digest,
                receipt_digest, completed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11)",
            params![
                attempt_id.to_string(),
                node.node_id.as_str(),
                i64::try_from(ordinal)
                    .map_err(|_| StoreError::InvalidWorkflowSchedulerInput("node ordinal"))?,
                node_kind_name(node.kind),
                activation_name(node.activation),
                node.profile_id.as_str(),
                worker_pool_name(profile.worker_pool),
                node_state.as_str(),
                output_digest,
                receipt_digest,
                completed_at_ms,
            ],
        )?;
        for dependency in &node.depends_on {
            transaction.execute(
                "INSERT INTO workflow_node_dependencies(
                    attempt_id, node_id, dependency_node_id
                 ) VALUES (?1, ?2, ?3)",
                params![
                    attempt_id.to_string(),
                    node.node_id.as_str(),
                    dependency.as_str(),
                ],
            )?;
        }
    }
    append_transition(
        transaction,
        attempt_id,
        "attempt",
        &attempt_id.to_string(),
        None,
        state.as_str(),
        "source_admitted",
        Some(&admission.source_attestation_digest),
        created_at_ms,
    )?;
    load_attempt_snapshot(transaction, attempt_id)
}

#[derive(Serialize)]
struct PreparationKeyPayload<'a> {
    purpose: &'static str,
    project_id: &'a ProjectId,
    source_sha: &'a GitCommitId,
    workflow_policy_digest: &'a EvidenceDigest,
}

fn preparation_key(admission: &WorkflowAdmissionV1) -> Result<EvidenceDigest, StoreError> {
    Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
        &PreparationKeyPayload {
            purpose: "rdashboard.prepared-run-key.v1",
            project_id: &admission.project_id,
            source_sha: &admission.source_sha,
            workflow_policy_digest: &admission.workflow_policy_digest,
        },
    )?))
}

impl DurableWorkflowScheduler {
    pub fn claim_next(
        &self,
        worker: &WorkflowWorkerRegistrationV1,
        now_ms: i64,
        lease_duration_ms: i64,
    ) -> Result<Option<WorkflowLeaseV1>, StoreError> {
        worker.validate()?;
        if now_ms < 0 || !(MIN_LEASE_MS..=MAX_LEASE_MS).contains(&lease_duration_ms) {
            return Err(StoreError::InvalidWorkflowSchedulerInput("lease time"));
        }
        self.store.immediate_transaction(|transaction| {
            expire_leases_transaction(transaction, now_ms)?;
            if worker_has_pending_cleanup(transaction, worker)? {
                return Ok(None);
            }
            claim_next_transaction(transaction, worker, now_ms, lease_duration_ms)
        })
    }

    pub fn expire_leases(&self, now_ms: i64) -> Result<usize, StoreError> {
        if now_ms < 0 {
            return Err(StoreError::InvalidWorkflowSchedulerInput(
                "lease expiry time",
            ));
        }
        self.store
            .immediate_transaction(|transaction| expire_leases_transaction(transaction, now_ms))
    }

    pub fn renew_lease(
        &self,
        worker: &WorkflowWorkerRegistrationV1,
        lease: &WorkflowLeaseV1,
        now_ms: i64,
        lease_duration_ms: i64,
    ) -> Result<WorkflowLeaseV1, StoreError> {
        worker.validate()?;
        lease.validate()?;
        if now_ms < 0
            || !(MIN_LEASE_MS..=MAX_LEASE_MS).contains(&lease_duration_ms)
            || worker.worker_id != lease.worker_id
            || worker.host_id != lease.host_id
            || !worker.pools.contains(&lease.worker_pool)
        {
            return Err(StoreError::InvalidWorkflowSchedulerInput("lease renewal"));
        }
        self.store.immediate_transaction(|transaction| {
            expire_leases_transaction(transaction, now_ms)?;
            renew_lease_transaction(transaction, lease, now_ms, lease_duration_ms)
        })
    }

    pub fn pending_cleanup(
        &self,
        worker: &WorkflowWorkerRegistrationV1,
        limit: usize,
    ) -> Result<Vec<WorkflowCleanupObligationV1>, StoreError> {
        worker.validate()?;
        if !(1..=64).contains(&limit) {
            return Err(StoreError::InvalidWorkflowSchedulerInput("cleanup limit"));
        }
        self.store.read_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT lease.lease_json, lease.state, receipt.receipt_json
                 FROM workflow_lease_journal AS lease
                 LEFT JOIN workflow_node_receipts AS receipt ON receipt.lease_id = lease.lease_id
                 LEFT JOIN workflow_cleanup_receipts AS cleanup ON cleanup.lease_id = lease.lease_id
                 WHERE lease.worker_id = ?1 AND lease.host_id = ?2
                   AND cleanup.lease_id IS NULL
                   AND (
                     lease.state IN ('expired', 'revoked')
                     OR (
                       lease.state = 'committed'
                       AND json_extract(receipt.receipt_json, '$.cleanup_result') = 'pending'
                     )
                   )
                 ORDER BY lease.closed_at_ms ASC, lease.lease_id ASC
                 LIMIT ?3",
            )?;
            let rows = statement
                .query_map(
                    params![
                        worker.worker_id,
                        worker.host_id,
                        i64::try_from(limit).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            rows.into_iter()
                .map(|(lease_json, state, receipt_json)| {
                    decode_cleanup_obligation(worker, &lease_json, &state, receipt_json.as_deref())
                })
                .collect()
        })
    }

    pub fn commit_cleanup_receipt(
        &self,
        receipt: &WorkflowCleanupReceiptV1,
        recorded_at_ms: i64,
    ) -> Result<WorkflowAttemptSnapshotV1, StoreError> {
        receipt.validate()?;
        if recorded_at_ms < 0 || receipt.completed_at_ms > recorded_at_ms {
            return Err(StoreError::InvalidWorkflowSchedulerInput(
                "cleanup receipt time",
            ));
        }
        let receipt_json = canonical_string(&receipt.canonical_bytes()?)?;
        self.store.immediate_transaction(|transaction| {
            commit_cleanup_receipt_transaction(transaction, receipt, &receipt_json, recorded_at_ms)
        })
    }

    pub fn reconcile_controller_nodes(&self, now_ms: i64) -> Result<usize, StoreError> {
        if now_ms < 0 {
            return Err(StoreError::InvalidWorkflowSchedulerInput(
                "controller reconciliation time",
            ));
        }
        self.expire_leases(now_ms)?;
        let attempts: Vec<Uuid> = self.store.read_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT DISTINCT attempt_id FROM workflow_nodes
                 WHERE node_kind = 'deterministic_reduce' AND state = 'ready'
                 ORDER BY attempt_id ASC",
            )?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter()
                .map(|attempt_id| parse_uuid(&attempt_id, "controller reconcile attempt ID"))
                .collect::<Result<Vec<_>, _>>()
        })?;
        for attempt_id in &attempts {
            self.reduce_attempt(*attempt_id, now_ms)?;
        }
        Ok(attempts.len())
    }
}

fn renew_lease_transaction(
    transaction: &Transaction<'_>,
    supplied: &WorkflowLeaseV1,
    now_ms: i64,
    lease_duration_ms: i64,
) -> Result<WorkflowLeaseV1, StoreError> {
    let (lease_json, state) = transaction
        .query_row(
            "SELECT lease_json, state FROM workflow_lease_journal WHERE lease_id = ?1",
            [supplied.lease_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or(StoreError::WorkflowLeaseConflict)?;
    if state != "active" {
        return Err(StoreError::WorkflowLeaseConflict);
    }
    let current = WorkflowLeaseV1::decode_canonical(lease_json.as_bytes())?;
    if !same_lease_assignment(&current, supplied) || supplied.expires_at_ms > current.expires_at_ms
    {
        return Err(StoreError::WorkflowLeaseConflict);
    }
    if supplied.lease_digest != current.lease_digest {
        return Ok(current);
    }
    let expires_at_ms = bounded_lease_expiry(
        current.leased_at_ms,
        now_ms,
        lease_duration_ms,
        current.timeout_ms,
    )?;
    if expires_at_ms <= current.expires_at_ms {
        return Ok(current);
    }
    let renewed = current.renewed(expires_at_ms)?;
    let renewed_json = canonical_string(&renewed.canonical_bytes()?)?;
    let changed = transaction.execute(
        "UPDATE workflow_lease_journal
         SET lease_digest = ?2, lease_json = ?3, expires_at_ms = ?4
         WHERE lease_id = ?1 AND state = 'active' AND lease_digest = ?5",
        params![
            renewed.lease_id.to_string(),
            renewed.lease_digest.as_str(),
            renewed_json,
            renewed.expires_at_ms,
            current.lease_digest.as_str(),
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowLeaseConflict);
    }
    append_transition(
        transaction,
        renewed.attempt_id,
        "lease",
        &renewed.lease_id.to_string(),
        Some("active"),
        "active",
        "worker_lease_renewed",
        Some(&renewed.lease_digest),
        now_ms,
    )?;
    Ok(renewed)
}

fn same_lease_assignment(left: &WorkflowLeaseV1, right: &WorkflowLeaseV1) -> bool {
    let mut normalized = left.clone();
    normalized.expires_at_ms = right.expires_at_ms;
    normalized.lease_digest = right.lease_digest.clone();
    normalized == *right
}

fn decode_cleanup_obligation(
    worker: &WorkflowWorkerRegistrationV1,
    lease_json: &str,
    state: &str,
    receipt_json: Option<&str>,
) -> Result<WorkflowCleanupObligationV1, StoreError> {
    let lease = WorkflowLeaseV1::decode_canonical(lease_json.as_bytes())?;
    if lease.worker_id != worker.worker_id || lease.host_id != worker.host_id {
        return Err(StoreError::CorruptWorkflowJournal("cleanup worker binding"));
    }
    let terminal_receipt = receipt_json
        .map(|json| WorkflowNodeReceiptV1::decode_canonical(json.as_bytes()))
        .transpose()?;
    let reason = match (state, terminal_receipt.as_ref()) {
        ("expired", None) => WorkflowCleanupReasonV1::LeaseExpired,
        ("revoked", None) => WorkflowCleanupReasonV1::LeaseRevoked,
        ("committed", Some(receipt))
            if receipt.cleanup_result == WorkflowCleanupResultV1::Pending
                && receipt_matches_lease(receipt, &lease) =>
        {
            WorkflowCleanupReasonV1::TerminalReceiptPending
        }
        _ => return Err(StoreError::CorruptWorkflowJournal("cleanup obligation")),
    };
    Ok(WorkflowCleanupObligationV1 {
        lease,
        terminal_receipt,
        reason,
    })
}

fn worker_has_pending_cleanup(
    transaction: &Transaction<'_>,
    worker: &WorkflowWorkerRegistrationV1,
) -> Result<bool, StoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(
               SELECT 1
               FROM workflow_lease_journal AS lease
               LEFT JOIN workflow_node_receipts AS receipt ON receipt.lease_id = lease.lease_id
               LEFT JOIN workflow_cleanup_receipts AS cleanup ON cleanup.lease_id = lease.lease_id
               WHERE lease.worker_id = ?1 AND lease.host_id = ?2
                 AND cleanup.lease_id IS NULL
                 AND (
                   lease.state IN ('expired', 'revoked')
                   OR (
                     lease.state = 'committed'
                     AND json_extract(receipt.receipt_json, '$.cleanup_result') = 'pending'
                   )
                 )
             )",
            params![worker.worker_id, worker.host_id],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn expire_leases_transaction(
    transaction: &Transaction<'_>,
    now_ms: i64,
) -> Result<usize, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT lease_id, attempt_id, node_id, lease_json
         FROM workflow_lease_journal
         WHERE state = 'active' AND expires_at_ms <= ?1
         ORDER BY expires_at_ms ASC, lease_id ASC",
    )?;
    let rows = statement
        .query_map([now_ms], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for (lease_id, attempt_id, node_id, lease_json) in &rows {
        expire_one_lease(
            transaction,
            lease_id,
            attempt_id,
            node_id,
            lease_json,
            now_ms,
        )?;
    }
    Ok(rows.len())
}

fn expire_one_lease(
    transaction: &Transaction<'_>,
    lease_id: &str,
    attempt_id: &str,
    node_id: &str,
    lease_json: &str,
    now_ms: i64,
) -> Result<(), StoreError> {
    let lease = WorkflowLeaseV1::decode_canonical(lease_json.as_bytes())?;
    if lease.lease_id.to_string() != lease_id
        || lease.attempt_id.to_string() != attempt_id
        || lease.node_id.as_str() != node_id
    {
        return Err(StoreError::CorruptWorkflowJournal("expired lease binding"));
    }
    let (node_kind, node_state) = transaction.query_row(
        "SELECT node_kind, state FROM workflow_nodes
         WHERE attempt_id = ?1 AND node_id = ?2",
        params![attempt_id, node_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    let node_kind = parse_node_kind(&node_kind)?;
    if WorkflowNodeStateV1::parse(&node_state)? != WorkflowNodeStateV1::Leased {
        return Err(StoreError::CorruptWorkflowJournal(
            "active lease node state",
        ));
    }
    let changed = transaction.execute(
        "UPDATE workflow_lease_journal
         SET state = 'expired', closed_at_ms = ?2
         WHERE lease_id = ?1 AND state = 'active'",
        params![lease_id, now_ms],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowLeaseConflict);
    }
    if node_kind.is_mutation() {
        expire_mutation_lease(transaction, attempt_id, node_id, now_ms)?;
    } else {
        let changed = transaction.execute(
            "UPDATE workflow_nodes SET state = 'ready'
             WHERE attempt_id = ?1 AND node_id = ?2 AND state = 'leased'",
            params![attempt_id, node_id],
        )?;
        if changed != 1 {
            return Err(StoreError::WorkflowStateConflict);
        }
        let changed = transaction.execute(
            "UPDATE workflow_attempts
             SET cleanup_state = 'pending', updated_at_ms = ?2
             WHERE attempt_id = ?1",
            params![attempt_id, now_ms],
        )?;
        if changed != 1 {
            return Err(StoreError::WorkflowStateConflict);
        }
    }
    append_transition(
        transaction,
        parse_uuid(attempt_id, "expired attempt ID")?,
        "lease",
        lease_id,
        Some("active"),
        "expired",
        if node_kind.is_mutation() {
            "mutation_requires_reconciliation"
        } else {
            "worker_lease_expired"
        },
        Some(&lease.lease_digest),
        now_ms,
    )
}

fn expire_mutation_lease(
    transaction: &Transaction<'_>,
    attempt_id: &str,
    node_id: &str,
    now_ms: i64,
) -> Result<(), StoreError> {
    let changed = transaction.execute(
        "UPDATE workflow_nodes
         SET state = 'needs_reconcile', completed_at_ms = ?3
         WHERE attempt_id = ?1 AND node_id = ?2 AND state = 'leased'",
        params![attempt_id, node_id, now_ms],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowStateConflict);
    }
    let changed = transaction.execute(
        "UPDATE workflow_attempts
         SET state = 'needs_reconcile', mutation_state = 'needs_reconcile',
             cleanup_state = 'pending', updated_at_ms = ?2
         WHERE attempt_id = ?1",
        params![attempt_id, now_ms],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowStateConflict);
    }
    let changed = transaction.execute(
        "UPDATE workflow_mutation_locks
         SET state = 'needs_reconcile', updated_at_ms = ?2
         WHERE attempt_id = ?1",
        params![attempt_id, now_ms],
    )?;
    if changed != 1 {
        return Err(StoreError::CorruptWorkflowJournal(
            "mutation lease without project lock",
        ));
    }
    Ok(())
}

fn claim_next_transaction(
    transaction: &Transaction<'_>,
    worker: &WorkflowWorkerRegistrationV1,
    now_ms: i64,
    lease_duration_ms: i64,
) -> Result<Option<WorkflowLeaseV1>, StoreError> {
    wake_waiting_attempts(transaction, now_ms)?;
    let candidates = load_ready_candidates(transaction, worker)?;
    if candidates.is_empty() {
        return Ok(None);
    }
    let (last_project_id, remaining_weight) = load_fairness_cursor(transaction)?;
    let ordered = fair_candidate_order(&candidates, last_project_id.as_deref(), remaining_weight)?;
    for candidate in ordered {
        if candidate.node.kind.is_mutation()
            && !acquire_mutation_lock(transaction, &candidate, now_ms)?
        {
            continue;
        }
        let operation_state =
            match operation_state_for_candidate(transaction, &candidate, worker, now_ms)? {
                OperationStateSelection::NotUsed => None,
                OperationStateSelection::Ready(state) => Some(state),
                OperationStateSelection::Busy => continue,
            };
        let (expected_input_digest, input_artifacts) =
            expected_input_digest(transaction, &candidate)?;
        let generation = candidate
            .lease_generation
            .checked_add(1)
            .ok_or(StoreError::CorruptWorkflowJournal("lease generation"))?;
        let expires_at_ms = bounded_lease_expiry(
            now_ms,
            now_ms,
            lease_duration_ms,
            candidate.profile.timeout_ms,
        )?;
        let mut lease = WorkflowLeaseV1::new(
            Uuid::new_v4(),
            generation,
            candidate.request_id,
            candidate.attempt_id,
            candidate.project_id.clone(),
            candidate.source_sha.clone(),
            candidate.source_sequence,
            candidate.source_attestation_digest.clone(),
            candidate.workflow_policy_digest.clone(),
            candidate.preparation_key.clone(),
            candidate.node,
            candidate.profile,
            if candidate.node.kind == WorkflowNodeKindV1::HostPrepare {
                candidate.manifest.host_preparation.clone()
            } else {
                None
            },
            input_artifacts,
            expected_input_digest,
            worker.worker_id.clone(),
            worker.host_id.clone(),
            now_ms,
            expires_at_ms,
        )?;
        if let Some(operation_state) = operation_state {
            lease = lease.with_operation_state(operation_state)?;
        }
        persist_active_lease(transaction, &lease, candidate.lease_generation, now_ms)?;
        update_fairness_cursor(
            transaction,
            &candidate,
            last_project_id.as_deref(),
            remaining_weight,
        )?;
        return Ok(Some(lease));
    }
    Ok(None)
}

enum OperationStateSelection {
    NotUsed,
    Ready(WorkflowOperationStateV1),
    Busy,
}

fn operation_state_for_candidate(
    transaction: &Transaction<'_>,
    candidate: &ReadyCandidate<'_>,
    worker: &WorkflowWorkerRegistrationV1,
    now_ms: i64,
) -> Result<OperationStateSelection, StoreError> {
    if !matches!(
        candidate.node.kind,
        WorkflowNodeKindV1::Verification | WorkflowNodeKindV1::ReleaseBuild
    ) || candidate.profile.cache_class != WorkflowCacheClassV1::PreparedRun
    {
        return Ok(OperationStateSelection::NotUsed);
    }

    let binding = transaction
        .query_row(
            "SELECT worker_id, host_id, state_json
             FROM workflow_operation_state_bindings WHERE attempt_id = ?1",
            [candidate.attempt_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    let vps_capable = worker.pools.contains(&WorkflowWorkerPoolV1::VpsRequired);

    if let Some((bound_worker, bound_host, state_json)) = binding.as_ref() {
        if bound_worker == &worker.worker_id && bound_host == &worker.host_id {
            let state = decode_bound_operation_state(candidate, worker, state_json)?;
            if !state.consumer_nodes.contains(&candidate.node.node_id) {
                return Err(StoreError::CorruptWorkflowJournal(
                    "operation-state consumer not bound",
                ));
            }
            return if active_operation_state_on_host(
                transaction,
                candidate.attempt_id,
                &worker.worker_id,
                &worker.host_id,
            )? {
                Ok(OperationStateSelection::Busy)
            } else {
                Ok(OperationStateSelection::Ready(state))
            };
        }
        // Once the always-available VPS owns the compiled state, every consumer in that
        // attempt must stay on the same host. Letting an optional accelerator retry one
        // consumer would leave the VPS record waiting for files that were never transferred.
        return Ok(OperationStateSelection::Busy);
    }

    if vps_capable
        && active_operation_state_on_host(
            transaction,
            candidate.attempt_id,
            &worker.worker_id,
            &worker.host_id,
        )?
    {
        return Ok(OperationStateSelection::Busy);
    }

    let consumers = if vps_capable {
        remaining_operation_state_consumers(transaction, candidate, worker)?
    } else {
        vec![candidate.node.node_id.clone()]
    };
    let state = operation_state_contract(candidate, worker, consumers)?;
    if vps_capable && binding.is_none() {
        let state_json = canonical_string(&serde_jcs::to_vec(&state)?)?;
        transaction.execute(
            "INSERT INTO workflow_operation_state_bindings(
                attempt_id, worker_id, host_id, state_key, state_json, bound_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                candidate.attempt_id.to_string(),
                worker.worker_id,
                worker.host_id,
                state.state_key.as_str(),
                state_json,
                now_ms,
            ],
        )?;
    }
    Ok(OperationStateSelection::Ready(state))
}

fn remaining_operation_state_consumers(
    transaction: &Transaction<'_>,
    candidate: &ReadyCandidate<'_>,
    worker: &WorkflowWorkerRegistrationV1,
) -> Result<Vec<WorkflowNodeId>, StoreError> {
    let mut consumers = Vec::new();
    for node in &candidate.manifest.workflow.nodes {
        if !matches!(
            node.kind,
            WorkflowNodeKindV1::Verification | WorkflowNodeKindV1::ReleaseBuild
        ) {
            continue;
        }
        let profile = candidate
            .manifest
            .workflow
            .profile(&node.profile_id)
            .ok_or(StoreError::CorruptWorkflowJournal(
                "operation-state profile absent",
            ))?;
        if profile.cache_class != WorkflowCacheClassV1::PreparedRun
            || !worker.pools.contains(&profile.worker_pool)
        {
            continue;
        }
        let state = transaction.query_row(
            "SELECT state FROM workflow_nodes WHERE attempt_id = ?1 AND node_id = ?2",
            params![candidate.attempt_id.to_string(), node.node_id.as_str()],
            |row| row.get::<_, String>(0),
        )?;
        if matches!(state.as_str(), "blocked" | "ready") {
            consumers.push(node.node_id.clone());
        }
    }
    if !consumers.contains(&candidate.node.node_id) {
        return Err(StoreError::CorruptWorkflowJournal(
            "operation-state candidate absent",
        ));
    }
    consumers.sort();
    Ok(consumers)
}

fn operation_state_contract(
    candidate: &ReadyCandidate<'_>,
    worker: &WorkflowWorkerRegistrationV1,
    consumers: Vec<WorkflowNodeId>,
) -> Result<WorkflowOperationStateV1, StoreError> {
    let mut max_bytes = 0;
    let mut max_inodes = 0;
    for consumer in &consumers {
        let node = candidate.manifest.workflow.node(consumer).ok_or(
            StoreError::CorruptWorkflowJournal("operation-state consumer absent"),
        )?;
        let resources = candidate
            .manifest
            .workflow
            .profile(&node.profile_id)
            .and_then(|profile| profile.resources.as_ref())
            .ok_or(StoreError::CorruptWorkflowJournal(
                "operation-state resources absent",
            ))?;
        max_bytes = max_bytes.max(resources.scratch_max_bytes);
        max_inodes = max_inodes.max(resources.scratch_max_inodes);
    }
    WorkflowOperationStateV1::new(
        candidate.attempt_id,
        &candidate.project_id,
        &candidate.source_sha,
        &candidate.workflow_policy_digest,
        &candidate.preparation_key,
        &worker.worker_id,
        &worker.host_id,
        consumers,
        max_bytes.min(MAX_OPERATION_STATE_BYTES),
        max_inodes.min(MAX_OPERATION_STATE_INODES),
    )
    .map_err(StoreError::from)
}

fn decode_bound_operation_state(
    candidate: &ReadyCandidate<'_>,
    worker: &WorkflowWorkerRegistrationV1,
    state_json: &str,
) -> Result<WorkflowOperationStateV1, StoreError> {
    let state: WorkflowOperationStateV1 = serde_json::from_str(state_json)?;
    if serde_jcs::to_vec(&state)? != state_json.as_bytes()
        || state
            .validate_for(
                candidate.attempt_id,
                &candidate.project_id,
                &candidate.source_sha,
                &candidate.workflow_policy_digest,
                &candidate.preparation_key,
                &worker.worker_id,
                &worker.host_id,
            )
            .is_err()
    {
        return Err(StoreError::CorruptWorkflowJournal(
            "operation-state binding",
        ));
    }
    Ok(state)
}

fn active_operation_state_on_host(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    worker_id: &str,
    host_id: &str,
) -> Result<bool, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT lease_json FROM workflow_lease_journal
         WHERE attempt_id = ?1 AND worker_id = ?2 AND host_id = ?3 AND state = 'active'",
    )?;
    let leases = statement
        .query_map(params![attempt_id.to_string(), worker_id, host_id], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for lease_json in leases {
        let lease = WorkflowLeaseV1::decode_canonical(lease_json.as_bytes())?;
        if lease.operation_state.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn bounded_lease_expiry(
    leased_at_ms: i64,
    now_ms: i64,
    lease_duration_ms: i64,
    execution_timeout_ms: u64,
) -> Result<i64, StoreError> {
    let timeout_ms = i64::try_from(execution_timeout_ms)
        .map_err(|_| StoreError::InvalidWorkflowSchedulerInput("execution timeout"))?;
    let execution_deadline =
        leased_at_ms
            .checked_add(timeout_ms)
            .ok_or(StoreError::InvalidWorkflowSchedulerInput(
                "execution deadline",
            ))?;
    let requested_expiry = now_ms
        .checked_add(lease_duration_ms)
        .ok_or(StoreError::InvalidWorkflowSchedulerInput("lease expiry"))?;
    let expires_at_ms = requested_expiry.min(execution_deadline);
    if expires_at_ms <= now_ms {
        return Err(StoreError::WorkflowLeaseConflict);
    }
    Ok(expires_at_ms)
}

fn persist_active_lease(
    transaction: &Transaction<'_>,
    lease: &WorkflowLeaseV1,
    previous_generation: u32,
    now_ms: i64,
) -> Result<(), StoreError> {
    let lease_json = canonical_string(&lease.canonical_bytes()?)?;
    transaction.execute(
        "INSERT INTO workflow_lease_journal(
            lease_id, attempt_id, node_id, generation, worker_id, host_id,
            expected_input_digest, lease_digest, lease_json, state,
            leased_at_ms, expires_at_ms, closed_at_ms, receipt_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
            'active', ?10, ?11, NULL, NULL)",
        params![
            lease.lease_id.to_string(),
            lease.attempt_id.to_string(),
            lease.node_id.as_str(),
            i64::from(lease.lease_generation),
            lease.worker_id,
            lease.host_id,
            lease.expected_input_digest.as_str(),
            lease.lease_digest.as_str(),
            lease_json,
            lease.leased_at_ms,
            lease.expires_at_ms,
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE workflow_nodes
         SET state = 'leased', lease_generation = ?3
         WHERE attempt_id = ?1 AND node_id = ?2
           AND state = 'ready' AND lease_generation = ?4",
        params![
            lease.attempt_id.to_string(),
            lease.node_id.as_str(),
            i64::from(lease.lease_generation),
            i64::from(previous_generation),
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowStateConflict);
    }
    let changed = transaction.execute(
        "UPDATE workflow_attempts
         SET state = 'running', updated_at_ms = ?2
         WHERE attempt_id = ?1 AND state IN ('queued', 'running')",
        params![lease.attempt_id.to_string(), now_ms],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowStateConflict);
    }
    append_transition(
        transaction,
        lease.attempt_id,
        "lease",
        &lease.lease_id.to_string(),
        None,
        "active",
        "worker_claimed",
        Some(&lease.lease_digest),
        now_ms,
    )
}

struct ReadyCandidate<'a> {
    request_id: Uuid,
    attempt_id: Uuid,
    project_id: ProjectId,
    source_sha: GitCommitId,
    source_sequence: u64,
    source_attestation_digest: EvidenceDigest,
    workflow_policy_digest: EvidenceDigest,
    preparation_key: EvidenceDigest,
    lease_generation: u32,
    manifest: ProjectManifestV2,
    node: &'a crate::domain::WorkflowNodeV1,
    profile: &'a WorkflowExecutionProfileV1,
}

#[derive(Clone)]
struct ReadyCandidateOwned {
    request_id: Uuid,
    attempt_id: Uuid,
    project_id: ProjectId,
    source_sha: GitCommitId,
    source_sequence: u64,
    source_attestation_digest: EvidenceDigest,
    workflow_policy_digest: EvidenceDigest,
    preparation_key: EvidenceDigest,
    lease_generation: u32,
    manifest: ProjectManifestV2,
    node_id: WorkflowNodeId,
}

struct ReadyCandidateStorageRow {
    request_id: String,
    attempt_id: String,
    project_id: String,
    source_sha: String,
    source_sequence: i64,
    source_attestation_digest: String,
    workflow_policy_digest: String,
    preparation_key: String,
    node_id: String,
    node_kind: String,
    profile_id: String,
    worker_pool: String,
    lease_generation: i64,
    manifest_json: String,
}

impl ReadyCandidateOwned {
    fn borrowed(&self) -> Result<ReadyCandidate<'_>, StoreError> {
        let node = self.manifest.workflow.node(&self.node_id).ok_or(
            StoreError::CorruptWorkflowJournal("candidate manifest node"),
        )?;
        let profile = self.manifest.workflow.profile(&node.profile_id).ok_or(
            StoreError::CorruptWorkflowJournal("candidate manifest profile"),
        )?;
        Ok(ReadyCandidate {
            request_id: self.request_id,
            attempt_id: self.attempt_id,
            project_id: self.project_id.clone(),
            source_sha: self.source_sha.clone(),
            source_sequence: self.source_sequence,
            source_attestation_digest: self.source_attestation_digest.clone(),
            workflow_policy_digest: self.workflow_policy_digest.clone(),
            preparation_key: self.preparation_key.clone(),
            lease_generation: self.lease_generation,
            manifest: self.manifest.clone(),
            node,
            profile,
        })
    }
}

fn load_ready_candidates(
    transaction: &Transaction<'_>,
    worker: &WorkflowWorkerRegistrationV1,
) -> Result<Vec<ReadyCandidateOwned>, StoreError> {
    let rows = read_ready_candidate_rows(transaction)?;
    let mut by_project = BTreeMap::new();
    for row in rows {
        let pool = parse_worker_pool(&row.worker_pool)?;
        if !worker.pools.contains(&pool) {
            continue;
        }
        let project_id = ProjectId::from_str(&row.project_id)
            .map_err(|_| StoreError::CorruptWorkflowJournal("candidate project ID"))?;
        if by_project.contains_key(&project_id) {
            continue;
        }
        let manifest = ProjectManifestV2::decode_canonical(row.manifest_json.as_bytes())?;
        let persisted_policy =
            parse_digest(&row.workflow_policy_digest, "candidate policy digest")?;
        if manifest.project_id != project_id
            || manifest.workflow_policy_digest()? != persisted_policy
        {
            return Err(StoreError::WorkflowPolicyMismatch);
        }
        let node_id = WorkflowNodeId::from_str(&row.node_id)
            .map_err(|_| StoreError::CorruptWorkflowJournal("candidate node ID"))?;
        let manifest_node = manifest
            .workflow
            .node(&node_id)
            .ok_or(StoreError::CorruptWorkflowJournal("candidate node absent"))?;
        let manifest_profile = manifest.workflow.profile(&manifest_node.profile_id).ok_or(
            StoreError::CorruptWorkflowJournal("candidate profile absent"),
        )?;
        if manifest_node.kind != parse_node_kind(&row.node_kind)?
            || manifest_node.profile_id.as_str() != row.profile_id
            || manifest_profile.worker_pool != pool
        {
            return Err(StoreError::CorruptWorkflowJournal(
                "candidate manifest binding",
            ));
        }
        by_project.insert(
            project_id.clone(),
            ReadyCandidateOwned {
                request_id: parse_uuid(&row.request_id, "candidate request ID")?,
                attempt_id: parse_uuid(&row.attempt_id, "candidate attempt ID")?,
                project_id,
                source_sha: parse_source_sha(&row.source_sha)?,
                source_sequence: u64::try_from(row.source_sequence)
                    .map_err(|_| StoreError::CorruptWorkflowJournal("source sequence"))?,
                source_attestation_digest: parse_digest(
                    &row.source_attestation_digest,
                    "source attestation digest",
                )?,
                workflow_policy_digest: persisted_policy,
                preparation_key: parse_digest(&row.preparation_key, "preparation key")?,
                lease_generation: u32::try_from(row.lease_generation)
                    .map_err(|_| StoreError::CorruptWorkflowJournal("lease generation"))?,
                manifest,
                node_id,
            },
        );
    }
    Ok(by_project.into_values().collect())
}

fn read_ready_candidate_rows(
    transaction: &Transaction<'_>,
) -> Result<Vec<ReadyCandidateStorageRow>, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT request.request_id, attempt.attempt_id, request.project_id,
                request.source_sha, request.source_sequence,
                request.source_attestation_digest, request.workflow_policy_digest,
                attempt.preparation_key, node.node_id, node.node_kind,
                node.profile_id, node.worker_pool,
                node.lease_generation, request.manifest_json
         FROM workflow_nodes AS node
         JOIN workflow_attempts AS attempt ON attempt.attempt_id = node.attempt_id
         JOIN workflow_requests AS request ON request.request_id = attempt.request_id
         WHERE node.state = 'ready'
           AND node.node_kind != 'deterministic_reduce'
           AND attempt.state IN ('queued', 'running')
           AND request.state = 'active'
         ORDER BY request.priority DESC, request.created_at_ms ASC,
                  node.ordinal ASC, node.node_id ASC",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok(ReadyCandidateStorageRow {
                request_id: row.get(0)?,
                attempt_id: row.get(1)?,
                project_id: row.get(2)?,
                source_sha: row.get(3)?,
                source_sequence: row.get(4)?,
                source_attestation_digest: row.get(5)?,
                workflow_policy_digest: row.get(6)?,
                preparation_key: row.get(7)?,
                node_id: row.get(8)?,
                node_kind: row.get(9)?,
                profile_id: row.get(10)?,
                worker_pool: row.get(11)?,
                lease_generation: row.get(12)?,
                manifest_json: row.get(13)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    Ok(rows)
}

fn fair_candidate_order<'a>(
    candidates: &'a [ReadyCandidateOwned],
    last_project_id: Option<&str>,
    remaining_weight: u16,
) -> Result<Vec<ReadyCandidate<'a>>, StoreError> {
    let mut borrowed = candidates
        .iter()
        .map(ReadyCandidateOwned::borrowed)
        .collect::<Result<Vec<_>, _>>()?;
    borrowed.sort_by(|left, right| left.project_id.cmp(&right.project_id));
    if let Some(last) = last_project_id {
        if remaining_weight > 0
            && let Some(index) = borrowed
                .iter()
                .position(|candidate| candidate.project_id.as_str() == last)
        {
            borrowed.rotate_left(index);
            return Ok(borrowed);
        }
        let index = borrowed
            .iter()
            .position(|candidate| candidate.project_id.as_str() > last)
            .unwrap_or(0);
        borrowed.rotate_left(index);
    }
    Ok(borrowed)
}

fn load_fairness_cursor(
    transaction: &Transaction<'_>,
) -> Result<(Option<String>, u16), StoreError> {
    let (project, weight) = transaction.query_row(
        "SELECT last_project_id, remaining_weight
         FROM workflow_scheduler_cursor WHERE singleton = 1",
        [],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok((
        project,
        u16::try_from(weight).map_err(|_| StoreError::CorruptWorkflowJournal("fairness weight"))?,
    ))
}

fn update_fairness_cursor(
    transaction: &Transaction<'_>,
    candidate: &ReadyCandidate<'_>,
    previous_project: Option<&str>,
    previous_remaining: u16,
) -> Result<(), StoreError> {
    let same_project = previous_project == Some(candidate.project_id.as_str());
    let remaining = if same_project && previous_remaining > 0 {
        previous_remaining - 1
    } else {
        candidate
            .manifest
            .workflow
            .fairness_weight
            .saturating_sub(1)
    };
    transaction.execute(
        "UPDATE workflow_scheduler_cursor
         SET last_project_id = ?1, remaining_weight = ?2
         WHERE singleton = 1",
        params![candidate.project_id.as_str(), i64::from(remaining)],
    )?;
    Ok(())
}

fn acquire_mutation_lock(
    transaction: &Transaction<'_>,
    candidate: &ReadyCandidate<'_>,
    now_ms: i64,
) -> Result<bool, StoreError> {
    let owner = transaction
        .query_row(
            "SELECT attempt_id, state FROM workflow_mutation_locks WHERE project_id = ?1",
            [candidate.project_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((attempt_id, state)) = owner {
        if parse_uuid(&attempt_id, "mutation lock attempt ID")? != candidate.attempt_id {
            return Ok(false);
        }
        if state != "held" {
            return Err(StoreError::WorkflowStateConflict);
        }
        return Ok(true);
    }
    transaction.execute(
        "INSERT INTO workflow_mutation_locks(
            project_id, attempt_id, state, acquired_at_ms, updated_at_ms
         ) VALUES (?1, ?2, 'held', ?3, ?3)",
        params![
            candidate.project_id.as_str(),
            candidate.attempt_id.to_string(),
            now_ms,
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE workflow_attempts
         SET mutation_state = 'owned', updated_at_ms = ?2
         WHERE attempt_id = ?1 AND mutation_state = 'not_started'",
        params![candidate.attempt_id.to_string(), now_ms],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowStateConflict);
    }
    Ok(true)
}

#[derive(Serialize)]
struct ExpectedInputPayload<'a> {
    purpose: &'static str,
    project_id: &'a ProjectId,
    source_sha: &'a GitCommitId,
    workflow_policy_digest: &'a EvidenceDigest,
    preparation_key: &'a EvidenceDigest,
    node_id: &'a WorkflowNodeId,
    dependencies: &'a [WorkflowLeaseInputV1],
}

fn expected_input_digest(
    transaction: &Transaction<'_>,
    candidate: &ReadyCandidate<'_>,
) -> Result<(EvidenceDigest, Vec<WorkflowLeaseInputV1>), StoreError> {
    let mut statement = transaction.prepare(
        "SELECT dependency.dependency_node_id, node.state, node.output_digest
         FROM workflow_node_dependencies AS dependency
         JOIN workflow_nodes AS node
           ON node.attempt_id = dependency.attempt_id
          AND node.node_id = dependency.dependency_node_id
         WHERE dependency.attempt_id = ?1 AND dependency.node_id = ?2
         ORDER BY dependency.dependency_node_id ASC",
    )?;
    let rows = statement
        .query_map(
            params![
                candidate.attempt_id.to_string(),
                candidate.node.node_id.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let mut dependencies = Vec::with_capacity(rows.len());
    for (node_id, state, output_digest) in rows {
        if WorkflowNodeStateV1::parse(&state)? != WorkflowNodeStateV1::Succeeded {
            return Err(StoreError::WorkflowStateConflict);
        }
        let node_id = WorkflowNodeId::from_str(&node_id)
            .map_err(|_| StoreError::CorruptWorkflowJournal("dependency node ID"))?;
        let manifest_node = candidate.manifest.workflow.node(&node_id).ok_or(
            StoreError::CorruptWorkflowJournal("dependency absent from manifest"),
        )?;
        dependencies.push(WorkflowLeaseInputV1 {
            node_id,
            artifact_kind: manifest_node.output_contract,
            output_digest: parse_digest(
                output_digest
                    .as_deref()
                    .ok_or(StoreError::CorruptWorkflowJournal("dependency output"))?,
                "dependency output",
            )?,
        });
    }
    if dependencies.len() != candidate.node.depends_on.len() {
        return Err(StoreError::CorruptWorkflowJournal("dependency cardinality"));
    }
    let digest = EvidenceDigest::sha256(serde_jcs::to_vec(&ExpectedInputPayload {
        purpose: "rdashboard.workflow-node-input.v1",
        project_id: &candidate.project_id,
        source_sha: &candidate.source_sha,
        workflow_policy_digest: &candidate.workflow_policy_digest,
        preparation_key: &candidate.preparation_key,
        node_id: &candidate.node.node_id,
        dependencies: &dependencies,
    })?);
    Ok((digest, dependencies))
}

fn wake_waiting_attempts(transaction: &Transaction<'_>, now_ms: i64) -> Result<(), StoreError> {
    let mut statement = transaction.prepare(
        "SELECT attempt.attempt_id
         FROM workflow_attempts AS attempt
         JOIN workflow_requests AS request ON request.request_id = attempt.request_id
         LEFT JOIN workflow_mutation_locks AS lock ON lock.project_id = request.project_id
         WHERE attempt.state = 'waiting_for_mutation'
           AND request.state = 'active'
           AND lock.project_id IS NULL
         ORDER BY attempt.created_at_ms ASC",
    )?;
    let attempts = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for attempt_id in attempts {
        transaction.execute(
            "UPDATE workflow_attempts
             SET state = 'queued', updated_at_ms = ?2
             WHERE attempt_id = ?1 AND state = 'waiting_for_mutation'",
            params![attempt_id, now_ms],
        )?;
        transaction.execute(
            "UPDATE workflow_nodes
             SET state = 'ready'
             WHERE attempt_id = ?1 AND node_kind = 'host_prepare' AND state = 'blocked'",
            [attempt_id],
        )?;
    }
    Ok(())
}

impl DurableWorkflowScheduler {
    pub fn commit_node_receipt(
        &self,
        receipt: &WorkflowNodeReceiptV1,
        recorded_at_ms: i64,
    ) -> Result<WorkflowAttemptSnapshotV1, StoreError> {
        receipt.validate()?;
        if recorded_at_ms < 0 || receipt.completed_at_ms > recorded_at_ms {
            return Err(StoreError::InvalidWorkflowSchedulerInput("receipt time"));
        }
        // Expiry must commit even when the subsequently submitted receipt is rejected as late.
        // Folding both operations into one transaction would roll the expiry back with that error.
        self.expire_leases(recorded_at_ms)?;
        let receipt_json = canonical_string(&receipt.canonical_bytes()?)?;
        self.store.immediate_transaction(|transaction| {
            commit_node_receipt_transaction(transaction, receipt, &receipt_json, recorded_at_ms)
        })
    }

    pub fn reduce_attempt(
        &self,
        attempt_id: Uuid,
        reduced_at_ms: i64,
    ) -> Result<WorkflowReductionReceiptV1, StoreError> {
        if attempt_id.is_nil() || reduced_at_ms < 0 {
            return Err(StoreError::InvalidWorkflowSchedulerInput(
                "reduction identity or time",
            ));
        }
        self.store.immediate_transaction(|transaction| {
            let context = load_attempt_context(transaction, attempt_id)?;
            let reduce_node = context
                .manifest
                .workflow
                .nodes
                .iter()
                .find(|node| node.kind == WorkflowNodeKindV1::DeterministicReduce)
                .ok_or(StoreError::CorruptWorkflowJournal("reduce node"))?;
            if let Some(persisted) = load_persisted_reduction(transaction, attempt_id)? {
                return validate_persisted_reduction(
                    transaction,
                    &context,
                    reduce_node,
                    &persisted,
                );
            }
            let reduce_state = transaction.query_row(
                "SELECT state FROM workflow_nodes WHERE attempt_id = ?1 AND node_id = ?2",
                params![attempt_id.to_string(), reduce_node.node_id.as_str()],
                |row| row.get::<_, String>(0),
            )?;
            if WorkflowNodeStateV1::parse(&reduce_state)? != WorkflowNodeStateV1::Ready {
                return Err(StoreError::WorkflowReductionConflict);
            }

            let collected = collect_reduction_inputs(transaction, &context, reduce_node)?;
            if reduced_at_ms < collected.latest_committed_at_ms {
                return Err(StoreError::WorkflowReductionConflict);
            }
            let reduction = WorkflowReductionReceiptV1::new(
                context.request_id,
                attempt_id,
                context.project_id,
                context.source_sha,
                context.workflow_policy_digest,
                context.preparation_key,
                reduce_node.node_id.clone(),
                collected.inputs,
                reduced_at_ms,
            )?;
            let receipt_json = canonical_string(&reduction.canonical_bytes()?)?;
            transaction.execute(
                "INSERT INTO workflow_reductions(
                    attempt_id, reduce_node_id, receipt_digest, receipt_json, committed_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    attempt_id.to_string(),
                    reduce_node.node_id.as_str(),
                    reduction.receipt_digest.as_str(),
                    receipt_json,
                    reduced_at_ms,
                ],
            )?;
            let changed = transaction.execute(
                "UPDATE workflow_nodes
                 SET state = 'succeeded', output_digest = ?3, receipt_digest = ?3,
                     completed_at_ms = ?4
                 WHERE attempt_id = ?1 AND node_id = ?2 AND state = 'ready'",
                params![
                    attempt_id.to_string(),
                    reduce_node.node_id.as_str(),
                    reduction.receipt_digest.as_str(),
                    reduced_at_ms,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::WorkflowStateConflict);
            }
            transaction.execute(
                "UPDATE workflow_attempts SET updated_at_ms = ?2 WHERE attempt_id = ?1",
                params![attempt_id.to_string(), reduced_at_ms],
            )?;
            append_transition(
                transaction,
                attempt_id,
                "node",
                reduce_node.node_id.as_str(),
                Some("ready"),
                "succeeded",
                "deterministic_reduction",
                Some(&reduction.receipt_digest),
                reduced_at_ms,
            )?;
            advance_ready_nodes(transaction, attempt_id)?;
            Ok(reduction)
        })
    }
}

struct PersistedReductionRow {
    reduce_node_id: String,
    receipt_digest: String,
    receipt_json: String,
    committed_at_ms: i64,
}

fn load_persisted_reduction(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
) -> Result<Option<PersistedReductionRow>, StoreError> {
    transaction
        .query_row(
            "SELECT reduce_node_id, receipt_digest, receipt_json, committed_at_ms
             FROM workflow_reductions WHERE attempt_id = ?1",
            [attempt_id.to_string()],
            |row| {
                Ok(PersistedReductionRow {
                    reduce_node_id: row.get(0)?,
                    receipt_digest: row.get(1)?,
                    receipt_json: row.get(2)?,
                    committed_at_ms: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(StoreError::from)
}

fn validate_persisted_reduction(
    transaction: &Transaction<'_>,
    context: &AttemptContext,
    reduce_node: &crate::domain::WorkflowNodeV1,
    persisted: &PersistedReductionRow,
) -> Result<WorkflowReductionReceiptV1, StoreError> {
    let receipt = WorkflowReductionReceiptV1::decode_canonical(persisted.receipt_json.as_bytes())?;
    let collected = collect_reduction_inputs(transaction, context, reduce_node)?;
    let (node_state, output_digest, receipt_digest, completed_at_ms) = transaction.query_row(
        "SELECT state, output_digest, receipt_digest, completed_at_ms
         FROM workflow_nodes WHERE attempt_id = ?1 AND node_id = ?2",
        params![context.attempt_id.to_string(), reduce_node.node_id.as_str()],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        },
    )?;
    let valid = persisted.reduce_node_id == reduce_node.node_id.as_str()
        && persisted.receipt_digest == receipt.receipt_digest.as_str()
        && persisted.committed_at_ms == receipt.reduced_at_ms
        && receipt.reduced_at_ms >= collected.latest_committed_at_ms
        && receipt.request_id == context.request_id
        && receipt.attempt_id == context.attempt_id
        && receipt.project_id == context.project_id
        && receipt.source_sha == context.source_sha
        && receipt.workflow_policy_digest == context.workflow_policy_digest
        && receipt.preparation_key == context.preparation_key
        && receipt.reduce_node_id == reduce_node.node_id
        && receipt.inputs == collected.inputs
        && WorkflowNodeStateV1::parse(&node_state)? == WorkflowNodeStateV1::Succeeded
        && output_digest.as_deref() == Some(receipt.receipt_digest.as_str())
        && receipt_digest.as_deref() == Some(receipt.receipt_digest.as_str())
        && completed_at_ms == Some(receipt.reduced_at_ms);
    if valid {
        Ok(receipt)
    } else {
        Err(StoreError::WorkflowReductionConflict)
    }
}

struct ReductionEvidenceRow {
    receipt_json: String,
    committed_at_ms: i64,
    lease_json: String,
    lease_state: String,
    node_state: String,
    output_digest: Option<String>,
    node_receipt_digest: Option<String>,
}

struct CollectedReductionInputs {
    inputs: Vec<WorkflowReductionInputV1>,
    latest_committed_at_ms: i64,
}

fn collect_reduction_inputs(
    transaction: &Transaction<'_>,
    context: &AttemptContext,
    reduce_node: &crate::domain::WorkflowNodeV1,
) -> Result<CollectedReductionInputs, StoreError> {
    let mut inputs = Vec::with_capacity(reduce_node.depends_on.len());
    let mut receipt_digests = BTreeSet::new();
    let mut latest_committed_at_ms = 0;
    for dependency_id in &reduce_node.depends_on {
        let dependency = context
            .manifest
            .workflow
            .node(dependency_id)
            .ok_or(StoreError::CorruptWorkflowJournal("reduce dependency"))?;
        if !matches!(
            dependency.kind,
            WorkflowNodeKindV1::Verification | WorkflowNodeKindV1::ReleaseBuild
        ) {
            return Err(StoreError::WorkflowReductionConflict);
        }
        let row = load_reduction_evidence(transaction, context.attempt_id, dependency_id)?;
        let receipt = WorkflowNodeReceiptV1::decode_canonical(row.receipt_json.as_bytes())?;
        let lease = WorkflowLeaseV1::decode_canonical(row.lease_json.as_bytes())?;
        validate_reduction_evidence(
            context,
            dependency_id,
            &row,
            &receipt,
            &lease,
            &mut receipt_digests,
        )?;
        latest_committed_at_ms = latest_committed_at_ms.max(row.committed_at_ms);
        inputs.push(WorkflowReductionInputV1 {
            node_id: dependency_id.clone(),
            node_kind: dependency.kind,
            receipt_digest: receipt.receipt_digest,
            output_digest: receipt
                .output_digest
                .ok_or(StoreError::WorkflowReductionConflict)?,
        });
    }
    if inputs.len() != reduce_node.depends_on.len() {
        return Err(StoreError::WorkflowReductionConflict);
    }
    Ok(CollectedReductionInputs {
        inputs,
        latest_committed_at_ms,
    })
}

fn load_reduction_evidence(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    dependency_id: &WorkflowNodeId,
) -> Result<ReductionEvidenceRow, StoreError> {
    transaction
        .query_row(
            "SELECT receipt.receipt_json, receipt.committed_at_ms,
                    lease.lease_json, lease.state, node.state,
                    node.output_digest, node.receipt_digest
             FROM workflow_node_receipts AS receipt
             JOIN workflow_lease_journal AS lease ON lease.lease_id = receipt.lease_id
             JOIN workflow_nodes AS node
               ON node.attempt_id = receipt.attempt_id AND node.node_id = receipt.node_id
             WHERE receipt.attempt_id = ?1 AND receipt.node_id = ?2",
            params![attempt_id.to_string(), dependency_id.as_str()],
            |row| {
                Ok(ReductionEvidenceRow {
                    receipt_json: row.get(0)?,
                    committed_at_ms: row.get(1)?,
                    lease_json: row.get(2)?,
                    lease_state: row.get(3)?,
                    node_state: row.get(4)?,
                    output_digest: row.get(5)?,
                    node_receipt_digest: row.get(6)?,
                })
            },
        )
        .optional()?
        .ok_or(StoreError::WorkflowReductionConflict)
}

fn validate_reduction_evidence(
    context: &AttemptContext,
    dependency_id: &WorkflowNodeId,
    row: &ReductionEvidenceRow,
    receipt: &WorkflowNodeReceiptV1,
    lease: &WorkflowLeaseV1,
    receipt_digests: &mut BTreeSet<EvidenceDigest>,
) -> Result<(), StoreError> {
    let valid = row.lease_state == "committed"
        && WorkflowNodeStateV1::parse(&row.node_state)? == WorkflowNodeStateV1::Succeeded
        && receipt.outcome == WorkflowNodeOutcomeV1::Succeeded
        && receipt.cleanup_result == WorkflowCleanupResultV1::Complete
        && receipt_matches_lease(receipt, lease)
        && receipt.attempt_id == context.attempt_id
        && receipt.node_id == *dependency_id
        && receipt.project_id == context.project_id
        && receipt.source_sha == context.source_sha
        && receipt.workflow_policy_digest == context.workflow_policy_digest
        && receipt.preparation_key == context.preparation_key
        && receipt.completed_at_ms >= lease.leased_at_ms
        && receipt.completed_at_ms < lease.expires_at_ms
        && row.committed_at_ms >= receipt.completed_at_ms
        && row.committed_at_ms < lease.expires_at_ms
        && row.output_digest.as_deref()
            == receipt.output_digest.as_ref().map(EvidenceDigest::as_str)
        && row.node_receipt_digest.as_deref() == Some(receipt.receipt_digest.as_str())
        && receipt_digests.insert(receipt.receipt_digest.clone());
    if valid {
        Ok(())
    } else {
        Err(StoreError::WorkflowReductionConflict)
    }
}

fn commit_cleanup_receipt_transaction(
    transaction: &Transaction<'_>,
    receipt: &WorkflowCleanupReceiptV1,
    receipt_json: &str,
    recorded_at_ms: i64,
) -> Result<WorkflowAttemptSnapshotV1, StoreError> {
    if let Some((persisted_digest, persisted_json)) = transaction
        .query_row(
            "SELECT receipt_digest, receipt_json FROM workflow_cleanup_receipts
             WHERE lease_id = ?1",
            [receipt.lease_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
    {
        if persisted_digest != receipt.receipt_digest.as_str() || persisted_json != receipt_json {
            return Err(StoreError::WorkflowCleanupConflict);
        }
        return load_attempt_snapshot(transaction, receipt.attempt_id);
    }

    let (lease_json, lease_state, closed_at_ms, terminal_json) = transaction
        .query_row(
            "SELECT lease.lease_json, lease.state, lease.closed_at_ms, receipt.receipt_json
             FROM workflow_lease_journal AS lease
             LEFT JOIN workflow_node_receipts AS receipt ON receipt.lease_id = lease.lease_id
             WHERE lease.lease_id = ?1",
            [receipt.lease_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::WorkflowCleanupConflict)?;
    let lease = WorkflowLeaseV1::decode_canonical(lease_json.as_bytes())?;
    if !cleanup_receipt_matches_lease(receipt, &lease) {
        return Err(StoreError::WorkflowCleanupConflict);
    }
    let closed_at_ms = closed_at_ms.ok_or(StoreError::WorkflowCleanupConflict)?;
    if receipt.completed_at_ms < closed_at_ms {
        return Err(StoreError::WorkflowCleanupConflict);
    }
    match (lease_state.as_str(), terminal_json.as_deref()) {
        ("expired" | "revoked", None) if receipt.terminal_receipt_digest.is_none() => {}
        ("committed", Some(terminal_json)) => {
            let terminal = WorkflowNodeReceiptV1::decode_canonical(terminal_json.as_bytes())?;
            if terminal.cleanup_result != WorkflowCleanupResultV1::Pending
                || !receipt_matches_lease(&terminal, &lease)
                || receipt.terminal_receipt_digest.as_ref() != Some(&terminal.receipt_digest)
                || receipt.completed_at_ms < terminal.completed_at_ms
            {
                return Err(StoreError::WorkflowCleanupConflict);
            }
        }
        _ => return Err(StoreError::WorkflowCleanupConflict),
    }

    transaction.execute(
        "INSERT INTO workflow_cleanup_receipts(
            receipt_digest, lease_id, attempt_id, node_id, receipt_json, committed_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            receipt.receipt_digest.as_str(),
            receipt.lease_id.to_string(),
            receipt.attempt_id.to_string(),
            receipt.node_id.as_str(),
            receipt_json,
            recorded_at_ms,
        ],
    )?;
    let cleanup_state = if unresolved_cleanup_count(transaction, receipt.attempt_id)? == 0 {
        WorkflowCleanupStateV1::Complete
    } else {
        WorkflowCleanupStateV1::Pending
    };
    let changed = transaction.execute(
        "UPDATE workflow_attempts
         SET cleanup_state = ?2, updated_at_ms = MAX(updated_at_ms, ?3)
         WHERE attempt_id = ?1",
        params![
            receipt.attempt_id.to_string(),
            cleanup_state.as_str(),
            recorded_at_ms,
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowStateConflict);
    }
    append_transition(
        transaction,
        receipt.attempt_id,
        "lease",
        &receipt.lease_id.to_string(),
        Some(&lease_state),
        &lease_state,
        "worker_cleanup_reconciled",
        Some(&receipt.receipt_digest),
        recorded_at_ms,
    )?;
    load_attempt_snapshot(transaction, receipt.attempt_id)
}

fn cleanup_receipt_matches_lease(
    receipt: &WorkflowCleanupReceiptV1,
    lease: &WorkflowLeaseV1,
) -> bool {
    receipt.lease_digest == lease.lease_digest
        && receipt.lease_id == lease.lease_id
        && receipt.lease_generation == lease.lease_generation
        && receipt.attempt_id == lease.attempt_id
        && receipt.project_id == lease.project_id
        && receipt.node_id == lease.node_id
        && receipt.worker_id == lease.worker_id
        && receipt.host_id == lease.host_id
}

fn unresolved_cleanup_count(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
) -> Result<i64, StoreError> {
    transaction
        .query_row(
            "SELECT COUNT(*)
             FROM workflow_lease_journal AS lease
             LEFT JOIN workflow_node_receipts AS receipt ON receipt.lease_id = lease.lease_id
             LEFT JOIN workflow_cleanup_receipts AS cleanup ON cleanup.lease_id = lease.lease_id
             WHERE lease.attempt_id = ?1
               AND cleanup.lease_id IS NULL
               AND (
                 lease.state IN ('expired', 'revoked')
                 OR (
                   lease.state = 'committed'
                   AND json_extract(receipt.receipt_json, '$.cleanup_result') = 'pending'
                 )
               )",
            [attempt_id.to_string()],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn commit_node_receipt_transaction(
    transaction: &Transaction<'_>,
    receipt: &WorkflowNodeReceiptV1,
    receipt_json: &str,
    recorded_at_ms: i64,
) -> Result<WorkflowAttemptSnapshotV1, StoreError> {
    if let Some(replayed) = replayed_node_receipt(transaction, receipt, receipt_json)? {
        return Ok(replayed);
    }
    validate_active_receipt_lease(transaction, receipt, recorded_at_ms)?;
    persist_node_receipt(transaction, receipt, receipt_json, recorded_at_ms)?;
    apply_node_receipt_outcome(transaction, receipt, recorded_at_ms)?;
    load_attempt_snapshot(transaction, receipt.attempt_id)
}

fn replayed_node_receipt(
    transaction: &Transaction<'_>,
    receipt: &WorkflowNodeReceiptV1,
    receipt_json: &str,
) -> Result<Option<WorkflowAttemptSnapshotV1>, StoreError> {
    let persisted = transaction
        .query_row(
            "SELECT receipt_digest, receipt_json FROM workflow_node_receipts
             WHERE attempt_id = ?1 AND node_id = ?2",
            params![receipt.attempt_id.to_string(), receipt.node_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((persisted_digest, persisted_json)) = persisted else {
        return Ok(None);
    };
    if persisted_digest != receipt.receipt_digest.as_str() || persisted_json != receipt_json {
        return Err(StoreError::WorkflowReceiptConflict);
    }
    load_attempt_snapshot(transaction, receipt.attempt_id).map(Some)
}

fn validate_active_receipt_lease(
    transaction: &Transaction<'_>,
    receipt: &WorkflowNodeReceiptV1,
    recorded_at_ms: i64,
) -> Result<(), StoreError> {
    let (lease_json, lease_state) = transaction
        .query_row(
            "SELECT lease_json, state FROM workflow_lease_journal WHERE lease_id = ?1",
            [receipt.lease_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or(StoreError::WorkflowLeaseConflict)?;
    if lease_state != "active" {
        return Err(StoreError::WorkflowLeaseConflict);
    }
    let lease = WorkflowLeaseV1::decode_canonical(lease_json.as_bytes())?;
    if !receipt_matches_lease(receipt, &lease)
        || receipt.completed_at_ms < lease.leased_at_ms
        || receipt.completed_at_ms >= lease.expires_at_ms
        || recorded_at_ms >= lease.expires_at_ms
    {
        return Err(StoreError::WorkflowReceiptConflict);
    }
    let node_state = transaction.query_row(
        "SELECT state FROM workflow_nodes WHERE attempt_id = ?1 AND node_id = ?2",
        params![receipt.attempt_id.to_string(), receipt.node_id.as_str()],
        |row| row.get::<_, String>(0),
    )?;
    if WorkflowNodeStateV1::parse(&node_state)? != WorkflowNodeStateV1::Leased {
        return Err(StoreError::WorkflowStateConflict);
    }
    Ok(())
}

fn persist_node_receipt(
    transaction: &Transaction<'_>,
    receipt: &WorkflowNodeReceiptV1,
    receipt_json: &str,
    recorded_at_ms: i64,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO workflow_node_receipts(
            receipt_digest, attempt_id, node_id, lease_id, receipt_json, committed_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            receipt.receipt_digest.as_str(),
            receipt.attempt_id.to_string(),
            receipt.node_id.as_str(),
            receipt.lease_id.to_string(),
            receipt_json,
            recorded_at_ms,
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE workflow_lease_journal
         SET state = 'committed', closed_at_ms = ?2, receipt_digest = ?3
         WHERE lease_id = ?1 AND state = 'active'",
        params![
            receipt.lease_id.to_string(),
            recorded_at_ms,
            receipt.receipt_digest.as_str(),
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowLeaseConflict);
    }
    let node_state = receipt_terminal_node_state(receipt);
    let changed = transaction.execute(
        "UPDATE workflow_nodes
         SET state = ?3, output_digest = ?4, receipt_digest = ?5, completed_at_ms = ?6
         WHERE attempt_id = ?1 AND node_id = ?2 AND state = 'leased'",
        params![
            receipt.attempt_id.to_string(),
            receipt.node_id.as_str(),
            node_state.as_str(),
            receipt.output_digest.as_ref().map(EvidenceDigest::as_str),
            receipt.receipt_digest.as_str(),
            receipt.completed_at_ms,
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowStateConflict);
    }
    if receipt.cleanup_result == WorkflowCleanupResultV1::Pending {
        transaction.execute(
            "UPDATE workflow_attempts SET cleanup_state = 'pending' WHERE attempt_id = ?1",
            [receipt.attempt_id.to_string()],
        )?;
    }
    append_transition(
        transaction,
        receipt.attempt_id,
        "node",
        receipt.node_id.as_str(),
        Some("leased"),
        node_state.as_str(),
        match receipt.outcome {
            WorkflowNodeOutcomeV1::Succeeded => "receipt_succeeded",
            WorkflowNodeOutcomeV1::Failed => "receipt_failed",
        },
        Some(&receipt.receipt_digest),
        recorded_at_ms,
    )
}

fn receipt_terminal_node_state(receipt: &WorkflowNodeReceiptV1) -> WorkflowNodeStateV1 {
    match receipt.outcome {
        WorkflowNodeOutcomeV1::Succeeded => WorkflowNodeStateV1::Succeeded,
        WorkflowNodeOutcomeV1::Failed if receipt.node_kind.is_mutation() => {
            WorkflowNodeStateV1::NeedsReconcile
        }
        WorkflowNodeOutcomeV1::Failed => WorkflowNodeStateV1::Failed,
    }
}

fn apply_node_receipt_outcome(
    transaction: &Transaction<'_>,
    receipt: &WorkflowNodeReceiptV1,
    recorded_at_ms: i64,
) -> Result<(), StoreError> {
    match receipt.outcome {
        WorkflowNodeOutcomeV1::Succeeded
            if receipt.node_kind == WorkflowNodeKindV1::ReleasedObservation =>
        {
            complete_workflow(transaction, receipt.attempt_id, recorded_at_ms)
        }
        WorkflowNodeOutcomeV1::Succeeded => {
            transaction.execute(
                "UPDATE workflow_attempts SET updated_at_ms = ?2 WHERE attempt_id = ?1",
                params![receipt.attempt_id.to_string(), recorded_at_ms],
            )?;
            advance_ready_nodes(transaction, receipt.attempt_id)
        }
        WorkflowNodeOutcomeV1::Failed => fail_workflow(
            transaction,
            receipt.attempt_id,
            receipt.node_kind,
            receipt.cleanup_result,
            recorded_at_ms,
        ),
    }
}

fn receipt_matches_lease(receipt: &WorkflowNodeReceiptV1, lease: &WorkflowLeaseV1) -> bool {
    receipt.lease_digest == lease.lease_digest
        && receipt.lease_id == lease.lease_id
        && receipt.lease_generation == lease.lease_generation
        && receipt.request_id == lease.request_id
        && receipt.attempt_id == lease.attempt_id
        && receipt.project_id == lease.project_id
        && receipt.source_sha == lease.source_sha
        && receipt.workflow_policy_digest == lease.workflow_policy_digest
        && receipt.preparation_key == lease.preparation_key
        && receipt.node_id == lease.node_id
        && receipt.node_kind == lease.node_kind
        && receipt.worker_id == lease.worker_id
        && receipt.host_id == lease.host_id
        && receipt.expected_input_digest == lease.expected_input_digest
}

fn advance_ready_nodes(transaction: &Transaction<'_>, attempt_id: Uuid) -> Result<(), StoreError> {
    loop {
        let mut statement = transaction.prepare(
            "SELECT node.node_id
             FROM workflow_nodes AS node
             WHERE node.attempt_id = ?1
               AND node.state = 'blocked'
               AND node.activation = 'always'
               AND NOT EXISTS (
                   SELECT 1 FROM workflow_node_dependencies AS dependency
                   JOIN workflow_nodes AS prerequisite
                     ON prerequisite.attempt_id = dependency.attempt_id
                    AND prerequisite.node_id = dependency.dependency_node_id
                   WHERE dependency.attempt_id = node.attempt_id
                     AND dependency.node_id = node.node_id
                     AND prerequisite.state != 'succeeded'
               )
             ORDER BY node.ordinal ASC",
        )?;
        let ready = statement
            .query_map([attempt_id.to_string()], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if ready.is_empty() {
            break;
        }
        for node_id in ready {
            transaction.execute(
                "UPDATE workflow_nodes SET state = 'ready'
                 WHERE attempt_id = ?1 AND node_id = ?2 AND state = 'blocked'",
                params![attempt_id.to_string(), node_id],
            )?;
        }
    }
    Ok(())
}

fn fail_workflow(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    node_kind: WorkflowNodeKindV1,
    cleanup_result: WorkflowCleanupResultV1,
    recorded_at_ms: i64,
) -> Result<(), StoreError> {
    if node_kind.is_mutation() {
        let changed = transaction.execute(
            "UPDATE workflow_attempts
             SET state = 'needs_reconcile', mutation_state = 'needs_reconcile',
                 cleanup_state = ?2, updated_at_ms = ?3
             WHERE attempt_id = ?1",
            params![
                attempt_id.to_string(),
                match cleanup_result {
                    WorkflowCleanupResultV1::Complete => WorkflowCleanupStateV1::Complete.as_str(),
                    WorkflowCleanupResultV1::Pending => WorkflowCleanupStateV1::Pending.as_str(),
                },
                recorded_at_ms,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::WorkflowStateConflict);
        }
        let changed = transaction.execute(
            "UPDATE workflow_mutation_locks
             SET state = 'needs_reconcile', updated_at_ms = ?2
             WHERE attempt_id = ?1",
            params![attempt_id.to_string(), recorded_at_ms],
        )?;
        if changed != 1 {
            return Err(StoreError::CorruptWorkflowJournal(
                "mutation failure without lock",
            ));
        }
        return Ok(());
    }

    let active_leases = transaction.query_row(
        "SELECT COUNT(*) FROM workflow_lease_journal
         WHERE attempt_id = ?1 AND state = 'active'",
        [attempt_id.to_string()],
        |row| row.get::<_, i64>(0),
    )?;
    transaction.execute(
        "UPDATE workflow_lease_journal
         SET state = 'revoked', closed_at_ms = ?2
         WHERE attempt_id = ?1 AND state = 'active'",
        params![attempt_id.to_string(), recorded_at_ms],
    )?;
    transaction.execute(
        "UPDATE workflow_nodes
         SET state = 'cancelled', completed_at_ms = ?2
         WHERE attempt_id = ?1
           AND state IN ('dormant', 'blocked', 'ready', 'leased')",
        params![attempt_id.to_string(), recorded_at_ms],
    )?;
    let cleanup_state = if active_leases == 0 && cleanup_result == WorkflowCleanupResultV1::Complete
    {
        WorkflowCleanupStateV1::Complete
    } else {
        WorkflowCleanupStateV1::Pending
    };
    let changed = transaction.execute(
        "UPDATE workflow_attempts
         SET state = 'failed', cleanup_state = ?2, updated_at_ms = ?3, terminal_at_ms = ?3
         WHERE attempt_id = ?1 AND mutation_state = 'not_started'",
        params![
            attempt_id.to_string(),
            cleanup_state.as_str(),
            recorded_at_ms,
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowStateConflict);
    }
    let changed = transaction.execute(
        "UPDATE workflow_requests SET state = 'terminal', updated_at_ms = ?2
         WHERE request_id = (
            SELECT request_id FROM workflow_attempts WHERE attempt_id = ?1
        ) AND state = 'active'",
        params![attempt_id.to_string(), recorded_at_ms],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowStateConflict);
    }
    Ok(())
}

fn complete_workflow(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    recorded_at_ms: i64,
) -> Result<(), StoreError> {
    let incomplete: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM workflow_nodes
         WHERE attempt_id = ?1 AND activation = 'always' AND state != 'succeeded'",
        [attempt_id.to_string()],
        |row| row.get(0),
    )?;
    let pending_cleanup = unresolved_cleanup_count(transaction, attempt_id)?;
    if incomplete != 0 || pending_cleanup != 0 {
        return Err(StoreError::WorkflowStateConflict);
    }
    transaction.execute(
        "UPDATE workflow_nodes
         SET state = 'cancelled', completed_at_ms = ?2
         WHERE attempt_id = ?1 AND activation = 'on_mutation_failure' AND state = 'dormant'",
        params![attempt_id.to_string(), recorded_at_ms],
    )?;
    let changed = transaction.execute(
        "UPDATE workflow_attempts
         SET state = 'succeeded', mutation_state = 'complete', cleanup_state = 'complete',
             updated_at_ms = ?2, terminal_at_ms = ?2
         WHERE attempt_id = ?1 AND state = 'running'",
        params![attempt_id.to_string(), recorded_at_ms],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowStateConflict);
    }
    let changed = transaction.execute(
        "UPDATE workflow_requests SET state = 'terminal', updated_at_ms = ?2
         WHERE request_id = (
            SELECT request_id FROM workflow_attempts WHERE attempt_id = ?1
        ) AND state = 'active'",
        params![attempt_id.to_string(), recorded_at_ms],
    )?;
    if changed != 1 {
        return Err(StoreError::WorkflowStateConflict);
    }
    let changed = transaction.execute(
        "DELETE FROM workflow_mutation_locks WHERE attempt_id = ?1 AND state = 'held'",
        [attempt_id.to_string()],
    )?;
    if changed != 1 {
        return Err(StoreError::CorruptWorkflowJournal(
            "completed mutation without held project lock",
        ));
    }
    wake_waiting_attempts(transaction, recorded_at_ms)?;
    Ok(())
}

struct AttemptContext {
    request_id: Uuid,
    attempt_id: Uuid,
    attempt_number: u32,
    project_id: ProjectId,
    source_sha: GitCommitId,
    source_sequence: u64,
    workflow_policy_digest: EvidenceDigest,
    source_attestation_digest: EvidenceDigest,
    preparation_key: EvidenceDigest,
    priority: u8,
    attempt_state: WorkflowAttemptStateV1,
    mutation_state: WorkflowMutationStateV1,
    cleanup_state: WorkflowCleanupStateV1,
    created_at_ms: i64,
    updated_at_ms: i64,
    terminal_at_ms: Option<i64>,
    manifest: ProjectManifestV2,
}

struct AttemptContextStorageRow {
    request_id: String,
    attempt_number: i64,
    project_id: String,
    source_sha: String,
    source_sequence: i64,
    workflow_policy_digest: String,
    source_attestation_digest: String,
    preparation_key: String,
    priority: i64,
    attempt_state: String,
    mutation_state: String,
    cleanup_state: String,
    created_at_ms: i64,
    updated_at_ms: i64,
    terminal_at_ms: Option<i64>,
    manifest_json: String,
    operation_kind: String,
}

fn load_attempt_context(
    connection: &rusqlite::Connection,
    attempt_id: Uuid,
) -> Result<AttemptContext, StoreError> {
    let row = read_attempt_context_row(connection, attempt_id)?;
    if row.operation_kind != "deploy"
        || row.created_at_ms < 0
        || row.updated_at_ms < row.created_at_ms
    {
        return Err(StoreError::CorruptWorkflowJournal(
            "attempt timestamps or kind",
        ));
    }
    let request_id = parse_uuid(&row.request_id, "request ID")?;
    let project_id = ProjectId::from_str(&row.project_id)
        .map_err(|_| StoreError::CorruptWorkflowJournal("project ID"))?;
    let source_sha = parse_source_sha(&row.source_sha)?;
    let workflow_policy_digest =
        parse_digest(&row.workflow_policy_digest, "workflow policy digest")?;
    let source_attestation_digest =
        parse_digest(&row.source_attestation_digest, "source attestation digest")?;
    let preparation_key_value = parse_digest(&row.preparation_key, "preparation key")?;
    let manifest = ProjectManifestV2::decode_canonical(row.manifest_json.as_bytes())?;
    if manifest.project_id != project_id
        || manifest.workflow_policy_digest()? != workflow_policy_digest
    {
        return Err(StoreError::WorkflowPolicyMismatch);
    }
    let expected_preparation_key =
        EvidenceDigest::sha256(serde_jcs::to_vec(&PreparationKeyPayload {
            purpose: "rdashboard.prepared-run-key.v1",
            project_id: &project_id,
            source_sha: &source_sha,
            workflow_policy_digest: &workflow_policy_digest,
        })?);
    if preparation_key_value != expected_preparation_key {
        return Err(StoreError::CorruptWorkflowJournal(
            "preparation key binding",
        ));
    }
    Ok(AttemptContext {
        request_id,
        attempt_id,
        attempt_number: u32::try_from(row.attempt_number)
            .map_err(|_| StoreError::CorruptWorkflowJournal("attempt number"))?,
        project_id,
        source_sha,
        source_sequence: to_u64(row.source_sequence, "source sequence")?,
        workflow_policy_digest,
        source_attestation_digest,
        preparation_key: preparation_key_value,
        priority: u8::try_from(row.priority)
            .map_err(|_| StoreError::CorruptWorkflowJournal("request priority"))?,
        attempt_state: WorkflowAttemptStateV1::parse(&row.attempt_state)?,
        mutation_state: WorkflowMutationStateV1::parse(&row.mutation_state)?,
        cleanup_state: WorkflowCleanupStateV1::parse(&row.cleanup_state)?,
        created_at_ms: row.created_at_ms,
        updated_at_ms: row.updated_at_ms,
        terminal_at_ms: row.terminal_at_ms,
        manifest,
    })
}

fn read_attempt_context_row(
    connection: &rusqlite::Connection,
    attempt_id: Uuid,
) -> Result<AttemptContextStorageRow, StoreError> {
    connection
        .query_row(
            "SELECT request.request_id, attempt.attempt_number, request.project_id,
                    request.source_sha, request.source_sequence,
                    request.workflow_policy_digest, request.source_attestation_digest,
                    attempt.preparation_key, request.priority, attempt.state,
                    attempt.mutation_state, attempt.cleanup_state,
                    attempt.created_at_ms, attempt.updated_at_ms, attempt.terminal_at_ms,
                    request.manifest_json, request.operation_kind
             FROM workflow_attempts AS attempt
             JOIN workflow_requests AS request ON request.request_id = attempt.request_id
             WHERE attempt.attempt_id = ?1",
            [attempt_id.to_string()],
            |row| {
                Ok(AttemptContextStorageRow {
                    request_id: row.get(0)?,
                    attempt_number: row.get(1)?,
                    project_id: row.get(2)?,
                    source_sha: row.get(3)?,
                    source_sequence: row.get(4)?,
                    workflow_policy_digest: row.get(5)?,
                    source_attestation_digest: row.get(6)?,
                    preparation_key: row.get(7)?,
                    priority: row.get(8)?,
                    attempt_state: row.get(9)?,
                    mutation_state: row.get(10)?,
                    cleanup_state: row.get(11)?,
                    created_at_ms: row.get(12)?,
                    updated_at_ms: row.get(13)?,
                    terminal_at_ms: row.get(14)?,
                    manifest_json: row.get(15)?,
                    operation_kind: row.get(16)?,
                })
            },
        )
        .optional()?
        .ok_or(StoreError::WorkflowAttemptNotFound(attempt_id))
}

fn load_attempt_snapshot(
    connection: &rusqlite::Connection,
    attempt_id: Uuid,
) -> Result<WorkflowAttemptSnapshotV1, StoreError> {
    let context = load_attempt_context(connection, attempt_id)?;
    let ordered_manifest = context.manifest.workflow.ordered_nodes()?;
    let mut statement = connection.prepare(
        "SELECT node_id, ordinal, node_kind, activation, profile_id, worker_pool,
                state, lease_generation, output_digest, receipt_digest, completed_at_ms
         FROM workflow_nodes WHERE attempt_id = ?1 ORDER BY ordinal ASC",
    )?;
    let rows = statement
        .query_map([attempt_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<i64>>(10)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if rows.len() != ordered_manifest.len() {
        return Err(StoreError::CorruptWorkflowJournal("node cardinality"));
    }

    let mut nodes = Vec::with_capacity(rows.len());
    for (index, row) in rows.into_iter().enumerate() {
        let (
            node_id,
            ordinal,
            node_kind,
            activation,
            profile_id,
            worker_pool,
            state,
            lease_generation,
            output_digest,
            receipt_digest,
            completed_at_ms,
        ) = row;
        let manifest_node = ordered_manifest[index];
        let profile = context
            .manifest
            .workflow
            .profile(&manifest_node.profile_id)
            .ok_or(StoreError::CorruptWorkflowJournal("snapshot profile"))?;
        if usize::try_from(ordinal).ok() != Some(index)
            || node_id != manifest_node.node_id.as_str()
            || parse_node_kind(&node_kind)? != manifest_node.kind
            || activation != activation_name(manifest_node.activation)
            || profile_id != manifest_node.profile_id.as_str()
            || parse_worker_pool(&worker_pool)? != profile.worker_pool
        {
            return Err(StoreError::CorruptWorkflowJournal("node manifest binding"));
        }
        validate_persisted_dependencies(connection, attempt_id, manifest_node)?;
        nodes.push(WorkflowNodeSnapshotV1 {
            node_id: manifest_node.node_id.clone(),
            kind: manifest_node.kind,
            profile_id: manifest_node.profile_id.clone(),
            worker_pool: profile.worker_pool,
            state: WorkflowNodeStateV1::parse(&state)?,
            lease_generation: u32::try_from(lease_generation)
                .map_err(|_| StoreError::CorruptWorkflowJournal("node lease generation"))?,
            output_digest: output_digest
                .as_deref()
                .map(|value| parse_digest(value, "node output digest"))
                .transpose()?,
            receipt_digest: receipt_digest
                .as_deref()
                .map(|value| parse_digest(value, "node receipt digest"))
                .transpose()?,
            completed_at_ms,
        });
    }
    Ok(WorkflowAttemptSnapshotV1 {
        request_id: context.request_id,
        attempt_id: context.attempt_id,
        attempt_number: context.attempt_number,
        project_id: context.project_id,
        source_sha: context.source_sha,
        source_sequence: context.source_sequence,
        workflow_policy_digest: context.workflow_policy_digest,
        source_attestation_digest: context.source_attestation_digest,
        preparation_key: context.preparation_key,
        priority: context.priority,
        state: context.attempt_state,
        mutation_state: context.mutation_state,
        cleanup_state: context.cleanup_state,
        created_at_ms: context.created_at_ms,
        updated_at_ms: context.updated_at_ms,
        terminal_at_ms: context.terminal_at_ms,
        nodes,
    })
}

fn validate_persisted_dependencies(
    connection: &rusqlite::Connection,
    attempt_id: Uuid,
    manifest_node: &crate::domain::WorkflowNodeV1,
) -> Result<(), StoreError> {
    let mut statement = connection.prepare(
        "SELECT dependency_node_id FROM workflow_node_dependencies
         WHERE attempt_id = ?1 AND node_id = ?2 ORDER BY dependency_node_id ASC",
    )?;
    let dependencies = statement
        .query_map(
            params![attempt_id.to_string(), manifest_node.node_id.as_str()],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = manifest_node
        .depends_on
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if dependencies != expected {
        return Err(StoreError::CorruptWorkflowJournal(
            "node dependency binding",
        ));
    }
    Ok(())
}

fn load_latest_attempt_for_request(
    connection: &rusqlite::Connection,
    request_id: Uuid,
) -> Result<WorkflowAttemptSnapshotV1, StoreError> {
    let attempt_id = connection
        .query_row(
            "SELECT attempt_id FROM workflow_attempts
             WHERE request_id = ?1 ORDER BY attempt_number DESC LIMIT 1",
            [request_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StoreError::CorruptWorkflowJournal(
            "request without attempt",
        ))?;
    load_attempt_snapshot(connection, parse_uuid(&attempt_id, "latest attempt ID")?)
}

#[allow(clippy::too_many_arguments)]
fn append_transition(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
    subject_kind: &str,
    subject_id: &str,
    from_state: Option<&str>,
    to_state: &str,
    reason: &str,
    evidence_digest: Option<&EvidenceDigest>,
    occurred_at_ms: i64,
) -> Result<(), StoreError> {
    let current: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM workflow_transitions WHERE attempt_id = ?1",
        [attempt_id.to_string()],
        |row| row.get(0),
    )?;
    let sequence = current
        .checked_add(1)
        .ok_or(StoreError::CorruptWorkflowJournal("transition sequence"))?;
    transaction.execute(
        "INSERT INTO workflow_transitions(
            attempt_id, sequence, subject_kind, subject_id, from_state, to_state,
            reason, evidence_digest, occurred_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            attempt_id.to_string(),
            sequence,
            subject_kind,
            subject_id,
            from_state,
            to_state,
            reason,
            evidence_digest.map(EvidenceDigest::as_str),
            occurred_at_ms,
        ],
    )?;
    Ok(())
}

fn node_kind_name(kind: WorkflowNodeKindV1) -> &'static str {
    match kind {
        WorkflowNodeKindV1::SourceAdmission => "source_admission",
        WorkflowNodeKindV1::HostPrepare => "host_prepare",
        WorkflowNodeKindV1::Verification => "verification",
        WorkflowNodeKindV1::ReleaseBuild => "release_build",
        WorkflowNodeKindV1::DeterministicReduce => "deterministic_reduce",
        WorkflowNodeKindV1::ResourceReservation => "resource_reservation",
        WorkflowNodeKindV1::Backup => "backup",
        WorkflowNodeKindV1::Migration => "migration",
        WorkflowNodeKindV1::CandidateHealth => "candidate_health",
        WorkflowNodeKindV1::Cutover => "cutover",
        WorkflowNodeKindV1::ReleasedObservation => "released_observation",
        WorkflowNodeKindV1::Rollback => "rollback",
    }
}

fn parse_node_kind(value: &str) -> Result<WorkflowNodeKindV1, StoreError> {
    match value {
        "source_admission" => Ok(WorkflowNodeKindV1::SourceAdmission),
        "host_prepare" => Ok(WorkflowNodeKindV1::HostPrepare),
        "verification" => Ok(WorkflowNodeKindV1::Verification),
        "release_build" => Ok(WorkflowNodeKindV1::ReleaseBuild),
        "deterministic_reduce" => Ok(WorkflowNodeKindV1::DeterministicReduce),
        "resource_reservation" => Ok(WorkflowNodeKindV1::ResourceReservation),
        "backup" => Ok(WorkflowNodeKindV1::Backup),
        "migration" => Ok(WorkflowNodeKindV1::Migration),
        "candidate_health" => Ok(WorkflowNodeKindV1::CandidateHealth),
        "cutover" => Ok(WorkflowNodeKindV1::Cutover),
        "released_observation" => Ok(WorkflowNodeKindV1::ReleasedObservation),
        "rollback" => Ok(WorkflowNodeKindV1::Rollback),
        _ => Err(StoreError::CorruptWorkflowJournal("node kind")),
    }
}

fn activation_name(activation: WorkflowNodeActivationV1) -> &'static str {
    match activation {
        WorkflowNodeActivationV1::Always => "always",
        WorkflowNodeActivationV1::OnMutationFailure => "on_mutation_failure",
    }
}

fn worker_pool_name(pool: WorkflowWorkerPoolV1) -> &'static str {
    match pool {
        WorkflowWorkerPoolV1::Controller => "controller",
        WorkflowWorkerPoolV1::VpsRequired => "vps_required",
        WorkflowWorkerPoolV1::BuildCompute => "build_compute",
        WorkflowWorkerPoolV1::PrivilegedExecutor => "privileged_executor",
    }
}

fn parse_worker_pool(value: &str) -> Result<WorkflowWorkerPoolV1, StoreError> {
    match value {
        "controller" => Ok(WorkflowWorkerPoolV1::Controller),
        "vps_required" => Ok(WorkflowWorkerPoolV1::VpsRequired),
        "build_compute" => Ok(WorkflowWorkerPoolV1::BuildCompute),
        "privileged_executor" => Ok(WorkflowWorkerPoolV1::PrivilegedExecutor),
        _ => Err(StoreError::CorruptWorkflowJournal("worker pool")),
    }
}

fn canonical_string(bytes: &[u8]) -> Result<String, StoreError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| StoreError::CorruptWorkflowJournal("canonical UTF-8"))
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(value).map_err(|_| StoreError::CorruptWorkflowJournal(field))
}

fn parse_digest(value: &str, field: &'static str) -> Result<EvidenceDigest, StoreError> {
    EvidenceDigest::from_str(value).map_err(|_| StoreError::CorruptWorkflowJournal(field))
}

fn parse_source_sha(value: &str) -> Result<GitCommitId, StoreError> {
    GitCommitId::from_str(value).map_err(|_| StoreError::CorruptWorkflowJournal("source SHA"))
}

fn to_i64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidWorkflowSchedulerInput(field))
}

fn to_u64(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptWorkflowJournal(field))
}
