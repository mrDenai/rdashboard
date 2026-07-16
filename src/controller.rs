use rusqlite::{OptionalExtension, Transaction, params};
use uuid::Uuid;

use crate::{
    domain::{
        AuthorizedPhaseSpecDigestV1, AutomationSource, BlockingReason, EvidenceDigest,
        ExecutorPhaseBranch, FailureCapsule, FenceAcquisitionReceiptV1, GitCommitId,
        InstalledPolicyIdentity, OperationActor, OperationEvidence, OperationKind, OperationPhase,
        OperationRecord, OperationRecoveryMode, OperationResult, OperationState,
        OperationTransition, PhaseArtifacts, PhaseReceipt, ProjectId, ReleaseClass,
    },
    store::{ControlStore, StoreError},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TabLease {
    pub user_id: Uuid,
    pub lease_id: Uuid,
    pub generation: u64,
    pub acquired_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TabLeaseClaim {
    pub user_id: Uuid,
    pub lease_id: Uuid,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewOperation {
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub target_commit: Option<GitCommitId>,
    pub release_class: Option<ReleaseClass>,
    pub installed_policy: InstalledPolicyIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionGrantClaims {
    pub nonce: Uuid,
    pub digest: EvidenceDigest,
    pub user_id: Uuid,
    pub project_id: ProjectId,
    pub operation_kind: OperationKind,
    pub target_commit: Option<GitCommitId>,
    pub retry_request_id: Option<Uuid>,
    pub expires_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryChannel {
    GithubWebhook,
    SourceReconciliation,
    DirectPush,
}

impl DeliveryChannel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::GithubWebhook => "github_webhook",
            Self::SourceReconciliation => "source_reconciliation",
            Self::DirectPush => "direct_push",
        }
    }

    const fn actor_source(self) -> AutomationSource {
        match self {
            Self::GithubWebhook => AutomationSource::GithubWebhook,
            Self::SourceReconciliation => AutomationSource::SourceReconciliation,
            Self::DirectPush => AutomationSource::DirectPush,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAutomationAdmission {
    pub(crate) operation: NewOperation,
    pub(crate) delivery_channel: DeliveryChannel,
    pub(crate) delivery_id: String,
    pub(crate) payload_digest: EvidenceDigest,
    pub(crate) source_attestation_digest: EvidenceDigest,
    pub(crate) accepted_head: GitCommitId,
    pub(crate) accepted_sequence: u64,
    pub(crate) maximum_attempts: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedInteractiveDeployAdmission {
    pub(crate) operation: NewOperation,
    pub(crate) source_attestation_digest: EvidenceDigest,
    pub(crate) accepted_head: GitCommitId,
    pub(crate) accepted_sequence: u64,
}

#[derive(Clone, Copy)]
struct InteractiveSourceEvidence<'a> {
    attestation_digest: &'a EvidenceDigest,
    sequence: u64,
}

struct InteractiveAdmissionContext<'a> {
    operation: &'a NewOperation,
    lease: &'a TabLeaseClaim,
    grant: &'a ActionGrantClaims,
    source: Option<InteractiveSourceEvidence<'a>>,
    admitted_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionOutcome {
    Created(OperationRecord),
    Existing(OperationRecord),
}

impl AdmissionOutcome {
    pub const fn operation(&self) -> &OperationRecord {
        match self {
            Self::Created(operation) | Self::Existing(operation) => operation,
        }
    }

    pub const fn created(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

#[derive(Clone, Debug)]
pub struct DurableController {
    store: ControlStore,
}

impl DurableController {
    pub const fn new(store: ControlStore) -> Self {
        Self { store }
    }

    pub const fn store(&self) -> &ControlStore {
        &self.store
    }

    pub fn takeover_lease(
        &self,
        user_id: Uuid,
        lease_id: Uuid,
        acquired_at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<TabLease, StoreError> {
        if user_id.is_nil() || lease_id.is_nil() {
            return Err(StoreError::InvalidControllerInput(
                "lease identities must not be nil",
            ));
        }
        if expires_at_ms <= acquired_at_ms {
            return Err(StoreError::InvalidControllerInput(
                "lease expiry must be later than acquisition",
            ));
        }

        self.store.immediate_transaction(|transaction| {
            let previous = transaction
                .query_row(
                    "SELECT generation FROM tab_leases WHERE user_id = ?1",
                    [user_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            let generation = previous.map_or(Ok(1_u64), |value| {
                u64::try_from(value)
                    .ok()
                    .and_then(|generation| generation.checked_add(1))
                    .ok_or(StoreError::CorruptController("tab lease generation"))
            })?;
            let generation_i64 = i64::try_from(generation)
                .map_err(|_| StoreError::InvalidControllerInput("lease generation overflow"))?;
            transaction.execute(
                "INSERT INTO tab_leases(
                    user_id, lease_id, generation, acquired_at_ms, expires_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(user_id) DO UPDATE SET
                    lease_id = excluded.lease_id,
                    generation = excluded.generation,
                    acquired_at_ms = excluded.acquired_at_ms,
                    expires_at_ms = excluded.expires_at_ms",
                params![
                    user_id.to_string(),
                    lease_id.to_string(),
                    generation_i64,
                    acquired_at_ms,
                    expires_at_ms
                ],
            )?;
            Ok(TabLease {
                user_id,
                lease_id,
                generation,
                acquired_at_ms,
                expires_at_ms,
            })
        })
    }

    pub fn admit_interactive(
        &self,
        operation: &NewOperation,
        lease: &TabLeaseClaim,
        grant: &ActionGrantClaims,
        admitted_at_ms: i64,
    ) -> Result<AdmissionOutcome, StoreError> {
        if operation.operation_kind == OperationKind::Deploy {
            return Err(StoreError::SourceAdmissionRequired);
        }
        self.admit_interactive_inner(operation, lease, grant, None, admitted_at_ms)
    }

    pub fn validate_tab_lease(&self, lease: &TabLeaseClaim, now_ms: i64) -> Result<(), StoreError> {
        if lease.user_id.is_nil() || lease.lease_id.is_nil() || lease.generation == 0 || now_ms < 0
        {
            return Err(StoreError::InvalidControllerInput(
                "lease identity or validation time is invalid",
            ));
        }
        self.store.read_connection(|connection| {
            validate_current_lease_connection(connection, lease, now_ms)
        })
    }

    pub(crate) fn admit_verified_interactive_deploy(
        &self,
        admission: &VerifiedInteractiveDeployAdmission,
        lease: &TabLeaseClaim,
        grant: &ActionGrantClaims,
        admitted_at_ms: i64,
    ) -> Result<AdmissionOutcome, StoreError> {
        if admission.operation.operation_kind != OperationKind::Deploy
            || admission.operation.target_commit.as_ref() != Some(&admission.accepted_head)
            || admission.accepted_sequence == 0
        {
            return Err(StoreError::SourceAdmissionRequired);
        }
        self.admit_interactive_inner(
            &admission.operation,
            lease,
            grant,
            Some((
                &admission.source_attestation_digest,
                admission.accepted_sequence,
            )),
            admitted_at_ms,
        )
    }

    fn admit_interactive_inner(
        &self,
        operation: &NewOperation,
        lease: &TabLeaseClaim,
        grant: &ActionGrantClaims,
        source_evidence: Option<(&EvidenceDigest, u64)>,
        admitted_at_ms: i64,
    ) -> Result<AdmissionOutcome, StoreError> {
        validate_operation(operation)?;
        validate_grant_binding(operation, lease, grant, admitted_at_ms)?;
        let context = InteractiveAdmissionContext {
            operation,
            lease,
            grant,
            source: source_evidence.map(|(attestation_digest, sequence)| {
                InteractiveSourceEvidence {
                    attestation_digest,
                    sequence,
                }
            }),
            admitted_at_ms,
        };
        self.store.immediate_transaction(|transaction| {
            admit_interactive_transaction(transaction, &context)
        })
    }

    pub fn admit_automation(
        &self,
        admission: &VerifiedAutomationAdmission,
        admitted_at_ms: i64,
    ) -> Result<AdmissionOutcome, StoreError> {
        validate_automation(admission)?;
        self.store.immediate_transaction(|transaction| {
            admit_automation_transaction(transaction, admission, admitted_at_ms)
        })
    }

    pub fn operation(&self, attempt_id: Uuid) -> Result<Option<OperationRecord>, StoreError> {
        self.store.read_connection(|connection| {
            connection
                .query_row(
                    "SELECT operation_json FROM operation_attempts WHERE attempt_id = ?1",
                    [attempt_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|json| decode_operation(&json))
                .transpose()
        })
    }

    pub fn attempts_for_request(
        &self,
        request_id: Uuid,
    ) -> Result<Vec<OperationRecord>, StoreError> {
        self.store.read_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT operation_json FROM operation_attempts
                 WHERE request_id = ?1 ORDER BY attempt_number ASC",
            )?;
            let rows =
                statement.query_map([request_id.to_string()], |row| row.get::<_, String>(0))?;
            let mut operations = Vec::new();
            for row in rows {
                operations.push(decode_operation(&row?)?);
            }
            Ok(operations)
        })
    }

    pub fn commit_phase_receipt(
        &self,
        receipt: &PhaseReceipt,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        if !receipt.has_valid_digest()? {
            return Err(StoreError::ReceiptDigestMismatch);
        }
        receipt.artifacts.validate_for_phase(receipt.phase)?;
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, receipt.attempt_id)?;
            if operation.evidence.transitions.iter().any(|transition| {
                transition.receipt_digest.as_ref() == Some(&receipt.receipt_digest)
            }) {
                return Ok(operation);
            }
            if operation.state.result != OperationResult::Running
                || operation.state.phase != receipt.phase
            {
                return Err(StoreError::ReceiptMismatch);
            }

            let is_rollback_recovery =
                operation.evidence.recovery_mode == Some(OperationRecoveryMode::Rollback);
            let next_state =
                next_state_for_phase_receipt(&operation, receipt, is_rollback_recovery)?;
            merge_artifacts(
                &mut operation.evidence,
                &receipt.artifacts,
                receipt.phase,
                receipt.branch,
                is_rollback_recovery,
            )?;
            persist_transition(
                transaction,
                &mut operation,
                next_state,
                Some(receipt.receipt_digest.clone()),
                recorded_at_ms,
            )?;
            Ok(operation)
        })
    }

    pub fn commit_reconciled_phase_receipt(
        &self,
        receipt: &PhaseReceipt,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        if !receipt.has_valid_digest()? {
            return Err(StoreError::ReceiptDigestMismatch);
        }
        receipt.artifacts.validate_for_phase(receipt.phase)?;
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, receipt.attempt_id)?;
            if let Some(index) = operation
                .evidence
                .transitions
                .iter()
                .position(|transition| {
                    transition.receipt_digest.as_ref() == Some(&receipt.receipt_digest)
                })
            {
                let transition = &operation.evidence.transitions[index];
                if transition.from.phase == OperationPhase::Reconciliation
                    && receipt_phase_for_transition(&operation.evidence.transitions, index)
                        == Some(receipt.phase)
                {
                    return Ok(operation);
                }
                return Err(StoreError::ReceiptMismatch);
            }
            if operation.state.result != OperationResult::Running
                || operation.state.phase != OperationPhase::Reconciliation
                || operation.evidence.recovery_mode != Some(OperationRecoveryMode::Reconciliation)
                || receipt.branch != ExecutorPhaseBranch::Primary
            {
                return Err(StoreError::ReceiptMismatch);
            }
            let entered_from_receipt_phase =
                operation
                    .evidence
                    .transitions
                    .last()
                    .is_some_and(|transition| {
                        transition.from.phase == receipt.phase
                            && transition.to.phase == OperationPhase::Reconciliation
                            && transition.to.result == OperationResult::Running
                            && transition.receipt_digest.is_none()
                    });
            if !entered_from_receipt_phase {
                return Err(StoreError::ReceiptMismatch);
            }
            let next_state = next_state_for_phase_receipt(&operation, receipt, false)?;
            merge_artifacts(
                &mut operation.evidence,
                &receipt.artifacts,
                receipt.phase,
                receipt.branch,
                false,
            )?;
            operation.evidence.recovery_mode = None;
            operation.failure_capsule = None;
            persist_transition(
                transaction,
                &mut operation,
                next_state,
                Some(receipt.receipt_digest.clone()),
                recorded_at_ms,
            )?;
            Ok(operation)
        })
    }

    pub fn mark_needs_reconcile(
        &self,
        attempt_id: Uuid,
        failure_capsule: FailureCapsule,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, attempt_id)?;
            if operation.state.phase == OperationPhase::Reconciliation
                && operation.state.result == OperationResult::Running
            {
                return Ok(operation);
            }
            if operation.state.result != OperationResult::Running {
                return Err(StoreError::TransitionRejected);
            }
            let next = OperationState {
                phase: OperationPhase::Reconciliation,
                result: OperationResult::Running,
                blocking_reason: BlockingReason::SecurityStateInvalid,
            };
            operation.evidence.recovery_mode = Some(OperationRecoveryMode::Reconciliation);
            operation.failure_capsule = Some(failure_capsule);
            persist_transition(transaction, &mut operation, next, None, recorded_at_ms)?;
            Ok(operation)
        })
    }

    pub(crate) fn validate_rollback(
        &self,
        attempt_id: Uuid,
    ) -> Result<OperationRecord, StoreError> {
        let operation = self
            .operation(attempt_id)?
            .ok_or(StoreError::OperationNotFound(attempt_id))?;
        require_rollback_transition(&operation)?;
        Ok(operation)
    }

    pub(crate) fn begin_rollback(
        &self,
        attempt_id: Uuid,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, attempt_id)?;
            if require_rollback_transition(&operation)? {
                return Ok(operation);
            }
            let next = OperationState {
                phase: OperationPhase::Rollback,
                result: OperationResult::Running,
                blocking_reason: BlockingReason::None,
            };
            operation.evidence.recovery_mode = Some(OperationRecoveryMode::Rollback);
            persist_transition(transaction, &mut operation, next, None, recorded_at_ms)?;
            Ok(operation)
        })
    }

    pub(crate) fn set_source_block(
        &self,
        attempt_id: Uuid,
        reason: BlockingReason,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        if !matches!(
            reason,
            BlockingReason::SourceDivergence
                | BlockingReason::SourceBrokerUnavailable
                | BlockingReason::SourceAttestationInvalid
                | BlockingReason::OperatorHold
        ) {
            return Err(StoreError::InvalidControllerInput(
                "invalid source blocking reason",
            ));
        }
        self.set_pre_mutation_block(attempt_id, reason, true, recorded_at_ms)
    }

    pub(crate) fn set_stateful_cutover_source_block(
        &self,
        attempt_id: Uuid,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, attempt_id)?;
            if !is_stateful_cutover_retry(&operation) {
                return Err(StoreError::TransitionRejected);
            }
            if operation.state.blocking_reason == BlockingReason::SourceBrokerUnavailable {
                return Ok(operation);
            }
            if operation.state.blocking_reason != BlockingReason::None {
                return Err(StoreError::TransitionRejected);
            }
            let next = OperationState {
                phase: operation.state.phase,
                result: OperationResult::Running,
                blocking_reason: BlockingReason::SourceBrokerUnavailable,
            };
            persist_transition(transaction, &mut operation, next, None, recorded_at_ms)?;
            Ok(operation)
        })
    }

    pub(crate) fn clear_stateful_cutover_source_block(
        &self,
        attempt_id: Uuid,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, attempt_id)?;
            if !is_stateful_cutover_retry(&operation) {
                return Err(StoreError::TransitionRejected);
            }
            match operation.state.blocking_reason {
                BlockingReason::None => Ok(operation),
                BlockingReason::SourceBrokerUnavailable => {
                    let next = OperationState {
                        phase: operation.state.phase,
                        result: OperationResult::Running,
                        blocking_reason: BlockingReason::None,
                    };
                    persist_transition(transaction, &mut operation, next, None, recorded_at_ms)?;
                    Ok(operation)
                }
                _ => Err(StoreError::TransitionRejected),
            }
        })
    }

    pub(crate) fn set_disk_block(
        &self,
        attempt_id: Uuid,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        self.set_pre_mutation_block(
            attempt_id,
            BlockingReason::DiskReserve,
            false,
            recorded_at_ms,
        )
    }

    fn set_pre_mutation_block(
        &self,
        attempt_id: Uuid,
        reason: BlockingReason,
        requires_source_admission: bool,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, attempt_id)?;
            if operation.state.result != OperationResult::Running
                || (requires_source_admission && !has_trusted_source_admission(&operation))
                || has_committed_mutation(&operation)
            {
                return Err(StoreError::TransitionRejected);
            }
            if operation.state.blocking_reason == reason {
                return Ok(operation);
            }
            if operation.state.blocking_reason != BlockingReason::None
                && operation.state.blocking_reason != BlockingReason::SourceBrokerUnavailable
            {
                return Ok(operation);
            }
            let next = OperationState {
                phase: operation.state.phase,
                result: OperationResult::Running,
                blocking_reason: reason,
            };
            persist_transition(transaction, &mut operation, next, None, recorded_at_ms)?;
            Ok(operation)
        })
    }

    pub(crate) fn clear_disk_block(
        &self,
        attempt_id: Uuid,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, attempt_id)?;
            if operation.state.result != OperationResult::Running
                || operation.state.blocking_reason != BlockingReason::DiskReserve
                || has_committed_mutation(&operation)
            {
                return Err(StoreError::TransitionRejected);
            }
            let next = OperationState {
                phase: operation.state.phase,
                result: OperationResult::Running,
                blocking_reason: BlockingReason::None,
            };
            persist_transition(transaction, &mut operation, next, None, recorded_at_ms)?;
            Ok(operation)
        })
    }

    pub(crate) fn supersede_source_attempt(
        &self,
        attempt_id: Uuid,
        failure_capsule: FailureCapsule,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, attempt_id)?;
            if operation.state.result != OperationResult::Running {
                return Ok(operation);
            }
            if !has_trusted_source_admission(&operation) || has_committed_mutation(&operation) {
                return Err(StoreError::TransitionRejected);
            }
            let next = OperationState {
                phase: operation.state.phase,
                result: OperationResult::Superseded,
                blocking_reason: BlockingReason::None,
            };
            operation.failure_capsule = Some(failure_capsule);
            persist_transition(transaction, &mut operation, next, None, recorded_at_ms)?;
            Ok(operation)
        })
    }

    pub(crate) fn record_fence_acquisition(
        &self,
        attempt_id: Uuid,
        receipt: &FenceAcquisitionReceiptV1,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        if receipt.attempt_id != attempt_id
            || !receipt
                .has_valid_digest()
                .map_err(|_| StoreError::InvalidControllerInput("invalid fence receipt"))?
        {
            return Err(StoreError::InvalidControllerInput(
                "invalid fence acquisition receipt",
            ));
        }
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, attempt_id)?;
            if operation.state.result != OperationResult::Running
                || operation.state.phase != OperationPhase::CutoverSnapshotting
                || operation.project_id != receipt.project_id
            {
                return Err(StoreError::TransitionRejected);
            }
            match operation.evidence.fencing_epoch {
                Some(current) if current == receipt.epoch => {}
                Some(_) => return Err(StoreError::ArtifactEvidenceConflict("fencing_epoch")),
                None => operation.evidence.fencing_epoch = Some(receipt.epoch),
            }
            match operation.evidence.fence_acquisition_receipt_digest.as_ref() {
                Some(current) if current == &receipt.receipt_digest => return Ok(operation),
                Some(_) => {
                    return Err(StoreError::ArtifactEvidenceConflict(
                        "fence_acquisition_receipt_digest",
                    ));
                }
                None => {
                    operation.evidence.fence_acquisition_receipt_digest =
                        Some(receipt.receipt_digest.clone());
                }
            }
            operation.updated_at_ms = recorded_at_ms;
            let operation_json = serde_json::to_string(&operation)?;
            let changed = transaction.execute(
                "UPDATE operation_attempts
                 SET operation_json = ?2, updated_at_ms = ?3
                 WHERE attempt_id = ?1 AND result = 'running'",
                params![attempt_id.to_string(), operation_json, recorded_at_ms],
            )?;
            if changed != 1 {
                return Err(StoreError::OperationNotFound(attempt_id));
            }
            Ok(operation)
        })
    }

    pub(crate) fn fail_attempt(
        &self,
        attempt_id: Uuid,
        failure_capsule: FailureCapsule,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, attempt_id)?;
            if operation.state.result != OperationResult::Running {
                return Ok(operation);
            }
            if operation.state.phase.crosses_mutation_boundary() {
                return Err(StoreError::FailureAfterMutationRequiresReconcile);
            }
            let next = OperationState {
                phase: operation.state.phase,
                result: OperationResult::Failed,
                blocking_reason: BlockingReason::None,
            };
            operation.failure_capsule = Some(failure_capsule);
            persist_transition(transaction, &mut operation, next, None, recorded_at_ms)?;
            Ok(operation)
        })
    }

    pub(crate) fn cancel_before_mutation(
        &self,
        attempt_id: Uuid,
        recorded_at_ms: i64,
    ) -> Result<OperationRecord, StoreError> {
        self.store.immediate_transaction(|transaction| {
            let mut operation = load_attempt(transaction, attempt_id)?;
            if operation.state.result != OperationResult::Running {
                return Ok(operation);
            }
            if operation.state.phase.crosses_mutation_boundary() {
                return Err(StoreError::CancellationAfterMutation);
            }
            let next = OperationState {
                phase: operation.state.phase,
                result: OperationResult::Cancelled,
                blocking_reason: BlockingReason::None,
            };
            persist_transition(transaction, &mut operation, next, None, recorded_at_ms)?;
            Ok(operation)
        })
    }
}

fn has_trusted_source_admission(operation: &OperationRecord) -> bool {
    operation.operation_kind == OperationKind::Deploy
        && operation.target_commit.is_some()
        && operation.evidence.installed_policy.is_some()
        && operation.evidence.source_attestation_digest.is_some()
        && operation
            .evidence
            .source_sequence
            .is_some_and(|sequence| sequence > 0)
}

fn is_stateful_cutover_retry(operation: &OperationRecord) -> bool {
    operation.state.result == OperationResult::Running
        && operation.state.phase == OperationPhase::CutoverSnapshotting
        && operation.operation_kind == OperationKind::Deploy
        && matches!(
            operation.release_class,
            Some(ReleaseClass::StatefulCompatible | ReleaseClass::StatefulBreaking)
        )
        && has_trusted_source_admission(operation)
        && has_committed_phase(operation, OperationPhase::BackingUp)
        && has_committed_phase(operation, OperationPhase::Draining)
}

#[derive(Clone, Copy)]
struct RequestIdentity {
    request_id: Uuid,
}

fn admit_interactive_transaction(
    transaction: &Transaction<'_>,
    context: &InteractiveAdmissionContext<'_>,
) -> Result<AdmissionOutcome, StoreError> {
    validate_current_lease(transaction, context.lease, context.admitted_at_ms)?;
    if let Some(replayed) = replayed_interactive_grant(transaction, context.grant)? {
        return Ok(replayed);
    }
    let request = find_or_create_request(transaction, context.operation, context.admitted_at_ms)?;
    let latest = latest_attempt(transaction, request.request_id)?;
    interactive_admission_outcome(transaction, &request, latest, context)
}

fn replayed_interactive_grant(
    transaction: &Transaction<'_>,
    grant: &ActionGrantClaims,
) -> Result<Option<AdmissionOutcome>, StoreError> {
    let replay = transaction
        .query_row(
            "SELECT g.grant_digest, a.operation_json
             FROM controller_action_grants AS g
             JOIN operation_attempts AS a ON a.attempt_id = g.attempt_id
             WHERE g.nonce = ?1",
            [grant.nonce.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((stored_digest, operation_json)) = replay else {
        return Ok(None);
    };
    if stored_digest != grant.digest.as_str() {
        return Err(StoreError::GrantReplay);
    }
    Ok(Some(AdmissionOutcome::Existing(decode_operation(
        &operation_json,
    )?)))
}

fn interactive_admission_outcome(
    transaction: &Transaction<'_>,
    request: &RequestIdentity,
    existing: Option<OperationRecord>,
    context: &InteractiveAdmissionContext<'_>,
) -> Result<AdmissionOutcome, StoreError> {
    let Some(existing) = existing else {
        if context.grant.retry_request_id.is_some() {
            return Err(StoreError::GrantBindingMismatch);
        }
        return create_interactive_attempt(transaction, request, 1, context);
    };
    if is_new_source_generation(&existing, context.source)? {
        if matches!(
            existing.state.result,
            OperationResult::ManualRecoveryRequired | OperationResult::RollbackFailed
        ) {
            return Err(StoreError::RecoveryRequired(request.request_id));
        }
        if context.grant.retry_request_id.is_some() {
            return Err(StoreError::GrantBindingMismatch);
        }
        return create_interactive_attempt(
            transaction,
            request,
            next_attempt_number(existing.attempt_number)?,
            context,
        );
    }
    match existing.state.result {
        OperationResult::Running
        | OperationResult::Succeeded
        | OperationResult::RolledBack
        | OperationResult::Superseded => Ok(AdmissionOutcome::Existing(existing)),
        OperationResult::ManualRecoveryRequired | OperationResult::RollbackFailed => {
            Err(StoreError::RecoveryRequired(request.request_id))
        }
        OperationResult::Failed | OperationResult::Cancelled => {
            if context.grant.retry_request_id != Some(request.request_id) {
                return Err(StoreError::RetryGrantRequired(request.request_id));
            }
            create_interactive_attempt(
                transaction,
                request,
                next_attempt_number(existing.attempt_number)?,
                context,
            )
        }
    }
}

fn is_new_source_generation(
    existing: &OperationRecord,
    source: Option<InteractiveSourceEvidence<'_>>,
) -> Result<bool, StoreError> {
    let Some(source) = source else {
        return Ok(false);
    };
    let existing_sequence = existing.evidence.source_sequence.unwrap_or_default();
    if source.sequence < existing_sequence {
        return Err(StoreError::StaleSourceSequence);
    }
    Ok(source.sequence > existing_sequence)
}

fn create_interactive_attempt(
    transaction: &Transaction<'_>,
    request: &RequestIdentity,
    attempt_number: u32,
    context: &InteractiveAdmissionContext<'_>,
) -> Result<AdmissionOutcome, StoreError> {
    let record = create_attempt(
        transaction,
        request,
        context.operation,
        attempt_number,
        OperationActor::Interactive {
            user_id: context.lease.user_id,
        },
        Some(context.grant.digest.clone()),
        context
            .source
            .map(|source| source.attestation_digest.clone()),
        context.source.map(|source| source.sequence),
        context.admitted_at_ms,
    )?;
    consume_controller_grant(
        transaction,
        context.grant,
        request.request_id,
        record.attempt_id,
        context.admitted_at_ms,
    )?;
    Ok(AdmissionOutcome::Created(record))
}

fn admit_automation_transaction(
    transaction: &Transaction<'_>,
    admission: &VerifiedAutomationAdmission,
    admitted_at_ms: i64,
) -> Result<AdmissionOutcome, StoreError> {
    if let Some(replayed) = replayed_automation_delivery(transaction, admission)? {
        return Ok(replayed);
    }
    let request = find_or_create_request(transaction, &admission.operation, admitted_at_ms)?;
    let latest = latest_attempt(transaction, request.request_id)?;
    let outcome =
        automation_admission_outcome(transaction, &request, latest, admission, admitted_at_ms)?;
    transaction.execute(
        "INSERT INTO transport_deliveries(
            channel, delivery_id, payload_digest, request_id, received_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            admission.delivery_channel.as_str(),
            admission.delivery_id,
            admission.payload_digest.as_str(),
            request.request_id.to_string(),
            admitted_at_ms
        ],
    )?;
    Ok(outcome)
}

fn replayed_automation_delivery(
    transaction: &Transaction<'_>,
    admission: &VerifiedAutomationAdmission,
) -> Result<Option<AdmissionOutcome>, StoreError> {
    let replay = transaction
        .query_row(
            "SELECT payload_digest, request_id FROM transport_deliveries
             WHERE channel = ?1 AND delivery_id = ?2",
            params![admission.delivery_channel.as_str(), admission.delivery_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((payload_digest, request_id)) = replay else {
        return Ok(None);
    };
    if payload_digest != admission.payload_digest.as_str() {
        return Err(StoreError::DeliveryConflict);
    }
    let operation = latest_attempt_by_request_text(transaction, &request_id)?.ok_or(
        StoreError::CorruptController("delivery references a request without attempts"),
    )?;
    Ok(Some(AdmissionOutcome::Existing(operation)))
}

fn automation_admission_outcome(
    transaction: &Transaction<'_>,
    request: &RequestIdentity,
    existing: Option<OperationRecord>,
    admission: &VerifiedAutomationAdmission,
    admitted_at_ms: i64,
) -> Result<AdmissionOutcome, StoreError> {
    let Some(existing) = existing else {
        return create_automation_attempt(transaction, request, admission, 1, admitted_at_ms);
    };
    let existing_sequence =
        existing
            .evidence
            .source_sequence
            .ok_or(StoreError::CorruptController(
                "automated attempt lacks source sequence",
            ))?;
    if admission.accepted_sequence < existing_sequence {
        return Err(StoreError::StaleSourceSequence);
    }
    if matches!(
        existing.state.result,
        OperationResult::ManualRecoveryRequired | OperationResult::RollbackFailed
    ) {
        return Err(StoreError::RecoveryRequired(request.request_id));
    }
    let next_attempt = next_attempt_number(existing.attempt_number)?;
    if admission.accepted_sequence > existing_sequence {
        return create_automation_attempt(
            transaction,
            request,
            admission,
            next_attempt,
            admitted_at_ms,
        );
    }
    match existing.state.result {
        OperationResult::Running
        | OperationResult::Succeeded
        | OperationResult::RolledBack
        | OperationResult::Superseded => Ok(AdmissionOutcome::Existing(existing)),
        OperationResult::ManualRecoveryRequired | OperationResult::RollbackFailed => {
            unreachable!("recovery terminals are handled before generation logic")
        }
        OperationResult::Failed | OperationResult::Cancelled => {
            if attempt_count_for_source_sequence(
                transaction,
                request.request_id,
                admission.accepted_sequence,
            )? >= admission.maximum_attempts
            {
                return Err(StoreError::AutomationAdmissionRejected);
            }
            create_automation_attempt(
                transaction,
                request,
                admission,
                next_attempt,
                admitted_at_ms,
            )
        }
    }
}

fn create_automation_attempt(
    transaction: &Transaction<'_>,
    request: &RequestIdentity,
    admission: &VerifiedAutomationAdmission,
    attempt_number: u32,
    admitted_at_ms: i64,
) -> Result<AdmissionOutcome, StoreError> {
    Ok(AdmissionOutcome::Created(create_attempt(
        transaction,
        request,
        &admission.operation,
        attempt_number,
        OperationActor::Automation {
            source: admission.delivery_channel.actor_source(),
        },
        None,
        Some(admission.source_attestation_digest.clone()),
        Some(admission.accepted_sequence),
        admitted_at_ms,
    )?))
}

fn next_attempt_number(current: u32) -> Result<u32, StoreError> {
    current
        .checked_add(1)
        .ok_or(StoreError::CorruptController("attempt number overflow"))
}

fn validate_operation(operation: &NewOperation) -> Result<(), StoreError> {
    if operation.operation_kind.requires_commit() != operation.target_commit.is_some() {
        return Err(StoreError::InvalidControllerInput(
            "target commit does not match operation kind",
        ));
    }
    operation
        .operation_kind
        .required_phases(operation.release_class)?;
    if operation.installed_policy.version == 0 {
        return Err(StoreError::InvalidControllerInput(
            "installed policy version must be positive",
        ));
    }
    Ok(())
}

fn validate_grant_binding(
    operation: &NewOperation,
    lease: &TabLeaseClaim,
    grant: &ActionGrantClaims,
    admitted_at_ms: i64,
) -> Result<(), StoreError> {
    if lease.user_id.is_nil()
        || lease.lease_id.is_nil()
        || lease.generation == 0
        || grant.nonce.is_nil()
    {
        return Err(StoreError::InvalidControllerInput(
            "lease and grant identities must not be nil",
        ));
    }
    if admitted_at_ms >= grant.expires_at_ms {
        return Err(StoreError::GrantExpired);
    }
    if grant.user_id != lease.user_id
        || grant.project_id != operation.project_id
        || grant.operation_kind != operation.operation_kind
        || grant.target_commit != operation.target_commit
    {
        return Err(StoreError::GrantBindingMismatch);
    }
    Ok(())
}

fn validate_current_lease(
    transaction: &Transaction<'_>,
    lease: &TabLeaseClaim,
    admitted_at_ms: i64,
) -> Result<(), StoreError> {
    validate_current_lease_connection(transaction, lease, admitted_at_ms)
}

fn validate_current_lease_connection(
    connection: &rusqlite::Connection,
    lease: &TabLeaseClaim,
    admitted_at_ms: i64,
) -> Result<(), StoreError> {
    let generation = i64::try_from(lease.generation)
        .map_err(|_| StoreError::InvalidControllerInput("lease generation overflow"))?;
    let expires_at_ms = connection
        .query_row(
            "SELECT expires_at_ms FROM tab_leases
             WHERE user_id = ?1 AND lease_id = ?2 AND generation = ?3",
            params![
                lease.user_id.to_string(),
                lease.lease_id.to_string(),
                generation
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(StoreError::LeaseRevoked)?;
    if admitted_at_ms >= expires_at_ms {
        return Err(StoreError::LeaseExpired);
    }
    Ok(())
}

fn validate_automation(admission: &VerifiedAutomationAdmission) -> Result<(), StoreError> {
    validate_operation(&admission.operation)?;
    let target = admission
        .operation
        .target_commit
        .as_ref()
        .ok_or(StoreError::AutomationAdmissionRejected)?;
    if admission.operation.operation_kind != OperationKind::Deploy
        || admission.maximum_attempts == 0
        || admission.accepted_sequence == 0
        || target != &admission.accepted_head
        || admission.delivery_id.is_empty()
        || admission.delivery_id.len() > 128
        || !admission.delivery_id.is_ascii()
    {
        return Err(StoreError::AutomationAdmissionRejected);
    }
    Ok(())
}

fn has_committed_mutation(operation: &OperationRecord) -> bool {
    operation
        .evidence
        .transitions
        .iter()
        .enumerate()
        .any(|(index, transition)| {
            transition.receipt_digest.is_some()
                && receipt_phase_for_transition(&operation.evidence.transitions, index)
                    .is_some_and(OperationPhase::crosses_mutation_boundary)
        })
}

fn has_committed_phase(operation: &OperationRecord, phase: OperationPhase) -> bool {
    operation
        .evidence
        .transitions
        .iter()
        .enumerate()
        .any(|(index, transition)| {
            transition.receipt_digest.is_some()
                && receipt_phase_for_transition(&operation.evidence.transitions, index)
                    == Some(phase)
        })
}

fn receipt_phase_for_transition(
    transitions: &[OperationTransition],
    index: usize,
) -> Option<OperationPhase> {
    let transition = transitions.get(index)?;
    if transition.from.phase != OperationPhase::Reconciliation {
        return Some(transition.from.phase);
    }
    let reconciliation = index
        .checked_sub(1)
        .and_then(|prior| transitions.get(prior))?;
    (reconciliation.to.phase == OperationPhase::Reconciliation
        && reconciliation.receipt_digest.is_none())
    .then_some(reconciliation.from.phase)
}

fn next_state_for_phase_receipt(
    operation: &OperationRecord,
    receipt: &PhaseReceipt,
    is_rollback_recovery: bool,
) -> Result<OperationState, StoreError> {
    const ROLLBACK_PHASES: [OperationPhase; 3] = [
        OperationPhase::Rollback,
        OperationPhase::HealthChecking,
        OperationPhase::Soaking,
    ];
    let expected_branch = if is_rollback_recovery {
        ExecutorPhaseBranch::RollbackRecovery
    } else {
        ExecutorPhaseBranch::Primary
    };
    if receipt.branch != expected_branch {
        return Err(StoreError::ReceiptMismatch);
    }
    let phases = if is_rollback_recovery {
        ROLLBACK_PHASES.as_slice()
    } else {
        operation
            .operation_kind
            .required_phases(operation.release_class)?
    };
    let Some(index) = phases.iter().position(|phase| *phase == receipt.phase) else {
        return Err(StoreError::TransitionRejected);
    };
    if let Some(next_phase) = phases.get(index + 1).copied() {
        if !is_rollback_recovery
            && !operation.operation_kind.permits_transition(
                operation.release_class,
                receipt.phase,
                next_phase,
            )?
        {
            return Err(StoreError::TransitionRejected);
        }
        Ok(OperationState {
            phase: next_phase,
            result: OperationResult::Running,
            blocking_reason: BlockingReason::None,
        })
    } else {
        Ok(OperationState {
            phase: receipt.phase,
            result: if is_rollback_recovery
                || operation.operation_kind == OperationKind::CodeRollback
            {
                OperationResult::RolledBack
            } else {
                OperationResult::Succeeded
            },
            blocking_reason: BlockingReason::None,
        })
    }
}

fn require_rollback_transition(operation: &OperationRecord) -> Result<bool, StoreError> {
    if operation.evidence.recovery_mode == Some(OperationRecoveryMode::Rollback) {
        return if operation.state.phase == OperationPhase::Rollback
            && operation.state.result == OperationResult::Running
        {
            Ok(true)
        } else {
            Err(StoreError::TransitionRejected)
        };
    }
    if operation.operation_kind != OperationKind::Deploy
        || operation.state.result != OperationResult::Running
        || !operation.state.phase.crosses_mutation_boundary()
        || !has_committed_phase(operation, OperationPhase::Deploying)
        || !matches!(
            operation.release_class,
            Some(ReleaseClass::CodeOnlyCompatible | ReleaseClass::StatefulCompatible)
        )
    {
        return Err(StoreError::TransitionRejected);
    }
    Ok(false)
}

fn find_or_create_request(
    transaction: &Transaction<'_>,
    operation: &NewOperation,
    created_at_ms: i64,
) -> Result<RequestIdentity, StoreError> {
    let target_key = operation
        .target_commit
        .as_ref()
        .map_or_else(|| "-".to_owned(), ToString::to_string);
    let kind = operation_kind_name(operation.operation_kind);
    if let Some(request_id) = transaction
        .query_row(
            "SELECT request_id FROM deployment_requests
             WHERE project_id = ?1 AND target_key = ?2 AND operation_kind = ?3",
            params![operation.project_id.as_str(), target_key, kind],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        return Ok(RequestIdentity {
            request_id: parse_uuid(&request_id)?,
        });
    }

    let request_id = Uuid::new_v4();
    transaction.execute(
        "INSERT INTO deployment_requests(
            request_id, project_id, target_key, target_commit, operation_kind, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            request_id.to_string(),
            operation.project_id.as_str(),
            target_key,
            operation.target_commit.as_ref().map(ToString::to_string),
            kind,
            created_at_ms
        ],
    )?;
    Ok(RequestIdentity { request_id })
}

#[allow(clippy::too_many_arguments)]
fn create_attempt(
    transaction: &Transaction<'_>,
    request: &RequestIdentity,
    operation: &NewOperation,
    attempt_number: u32,
    actor: OperationActor,
    action_grant_digest: Option<EvidenceDigest>,
    source_attestation_digest: Option<EvidenceDigest>,
    source_sequence: Option<u64>,
    created_at_ms: i64,
) -> Result<OperationRecord, StoreError> {
    let state = OperationState {
        phase: OperationPhase::Queued,
        result: OperationResult::Running,
        blocking_reason: BlockingReason::None,
    };
    state.validate()?;
    let record = OperationRecord {
        operation_id: Uuid::new_v4(),
        request_id: request.request_id,
        attempt_id: Uuid::new_v4(),
        attempt_number,
        project_id: operation.project_id.clone(),
        operation_kind: operation.operation_kind,
        target_commit: operation.target_commit.clone(),
        release_class: operation.release_class,
        state,
        actor,
        evidence: OperationEvidence {
            installed_policy: Some(operation.installed_policy.clone()),
            source_attestation_digest,
            source_sequence,
            action_grant_digest,
            ..OperationEvidence::default()
        },
        failure_capsule: None,
        created_at_ms,
        updated_at_ms: created_at_ms,
    };
    let json = serde_json::to_string(&record)?;
    transaction.execute(
        "INSERT INTO operation_attempts(
            operation_id, request_id, attempt_id, attempt_number, phase, result,
            operation_json, created_at_ms, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
        params![
            record.operation_id.to_string(),
            record.request_id.to_string(),
            record.attempt_id.to_string(),
            i64::from(record.attempt_number),
            phase_name(record.state.phase),
            result_name(record.state.result),
            json,
            created_at_ms
        ],
    )?;
    Ok(record)
}

fn consume_controller_grant(
    transaction: &Transaction<'_>,
    grant: &ActionGrantClaims,
    request_id: Uuid,
    attempt_id: Uuid,
    consumed_at_ms: i64,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO controller_action_grants(
            nonce, grant_digest, request_id, attempt_id, consumed_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            grant.nonce.to_string(),
            grant.digest.as_str(),
            request_id.to_string(),
            attempt_id.to_string(),
            consumed_at_ms
        ],
    )?;
    Ok(())
}

fn merge_artifacts(
    evidence: &mut OperationEvidence,
    artifacts: &PhaseArtifacts,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
    is_rollback_recovery: bool,
) -> Result<(), StoreError> {
    merge_authorized_phase_spec_digest(
        &mut evidence.authorized_phase_spec_digests,
        phase,
        branch,
        artifacts.authorized_phase_spec_digest.as_ref(),
    )?;
    merge_optional(
        &mut evidence.source_gate_proof_digest,
        artifacts.source_gate_proof_digest.as_ref(),
        "source_gate_proof_digest",
    )?;
    merge_optional(
        &mut evidence.drain_evidence_digest,
        artifacts.drain_evidence_digest.as_ref(),
        "drain_evidence_digest",
    )?;
    merge_optional(
        &mut evidence.source_export_digest,
        artifacts.source_export_digest.as_ref(),
        "source_export_digest",
    )?;
    merge_optional(
        &mut evidence.prefetch_evidence_digest,
        artifacts.prefetch_evidence_digest.as_ref(),
        "prefetch_evidence_digest",
    )?;
    merge_optional(
        &mut evidence.ci_evidence_digest,
        artifacts.ci_evidence_digest.as_ref(),
        "ci_evidence_digest",
    )?;
    merge_optional(
        &mut evidence.build_plan_digest,
        artifacts.build_plan_digest.as_ref(),
        "build_plan_digest",
    )?;
    merge_optional(
        &mut evidence.deployment_plan_digest,
        artifacts.deployment_plan_digest.as_ref(),
        "deployment_plan_digest",
    )?;
    merge_optional(
        &mut evidence.release_bundle_digest,
        artifacts.release_bundle_digest.as_ref(),
        "release_bundle_digest",
    )?;
    merge_optional(
        &mut evidence.resource_reservation_digest,
        artifacts.resource_reservation_digest.as_ref(),
        "resource_reservation_digest",
    )?;
    merge_optional(
        &mut evidence.build_context_digest,
        artifacts.build_context_digest.as_ref(),
        "build_context_digest",
    )?;
    merge_vector(
        &mut evidence.generated_output_digests,
        &artifacts.generated_output_digests,
        "generated_output_digests",
    )?;
    merge_optional(
        &mut evidence.image_digest,
        artifacts.image_digest.as_ref(),
        "image_digest",
    )?;
    merge_optional(
        &mut evidence.image_id_digest,
        artifacts.image_id_digest.as_ref(),
        "image_id_digest",
    )?;
    merge_vector(
        &mut evidence.base_image_digests,
        &artifacts.base_image_digests,
        "base_image_digests",
    )?;
    merge_optional(
        &mut evidence.schema_version,
        artifacts.schema_version.as_ref(),
        "schema_version",
    )?;
    merge_backup_artifacts(evidence, artifacts)?;
    merge_release_health_artifacts(evidence, artifacts, phase, is_rollback_recovery)
}

fn merge_release_health_artifacts(
    evidence: &mut OperationEvidence,
    artifacts: &PhaseArtifacts,
    phase: OperationPhase,
    is_rollback_recovery: bool,
) -> Result<(), StoreError> {
    merge_optional(
        &mut evidence.previous_release_bundle_digest,
        artifacts.previous_release_bundle_digest.as_ref(),
        "previous_release_bundle_digest",
    )?;
    if is_rollback_recovery {
        merge_health_artifact(
            &mut evidence.rollback_health_evidence_digest,
            artifacts.health_evidence_digest.as_ref(),
            phase,
            "rollback_health_evidence_digest",
        )?;
    } else {
        merge_health_artifact(
            &mut evidence.health_evidence_digest,
            artifacts.health_evidence_digest.as_ref(),
            phase,
            "health_evidence_digest",
        )?;
    }
    Ok(())
}

fn merge_health_artifact(
    target: &mut Option<EvidenceDigest>,
    incoming: Option<&EvidenceDigest>,
    phase: OperationPhase,
    field: &'static str,
) -> Result<(), StoreError> {
    if phase == OperationPhase::Soaking && incoming.is_some() {
        *target = incoming.cloned();
        Ok(())
    } else {
        merge_optional(target, incoming, field)
    }
}

fn merge_backup_artifacts(
    evidence: &mut OperationEvidence,
    artifacts: &PhaseArtifacts,
) -> Result<(), StoreError> {
    merge_optional(
        &mut evidence.backup_id,
        artifacts.backup_id.as_ref(),
        "backup_id",
    )?;
    merge_optional(
        &mut evidence.backup_set_id,
        artifacts.backup_set_id.as_ref(),
        "backup_set_id",
    )?;
    merge_optional(
        &mut evidence.base_backup_id,
        artifacts.base_backup_id.as_ref(),
        "base_backup_id",
    )?;
    merge_optional(
        &mut evidence.base_backup_manifest_digest,
        artifacts.base_backup_manifest_digest.as_ref(),
        "base_backup_manifest_digest",
    )?;
    merge_optional(
        &mut evidence.base_backup_evidence_digest,
        artifacts.base_backup_evidence_digest.as_ref(),
        "base_backup_evidence_digest",
    )?;
    merge_optional(
        &mut evidence.base_backup_offsite_evidence_digest,
        artifacts.base_backup_offsite_evidence_digest.as_ref(),
        "base_backup_offsite_evidence_digest",
    )?;
    merge_optional(
        &mut evidence.base_backup_verification_digest,
        artifacts.base_backup_verification_digest.as_ref(),
        "base_backup_verification_digest",
    )?;
    merge_optional(
        &mut evidence.cutover_backup_id,
        artifacts.cutover_backup_id.as_ref(),
        "cutover_backup_id",
    )?;
    merge_optional(
        &mut evidence.cutover_backup_manifest_digest,
        artifacts.cutover_backup_manifest_digest.as_ref(),
        "cutover_backup_manifest_digest",
    )?;
    merge_optional(
        &mut evidence.cutover_backup_evidence_digest,
        artifacts.cutover_backup_evidence_digest.as_ref(),
        "cutover_backup_evidence_digest",
    )?;
    merge_optional(
        &mut evidence.cutover_backup_verification_digest,
        artifacts.cutover_backup_verification_digest.as_ref(),
        "cutover_backup_verification_digest",
    )?;
    merge_optional(
        &mut evidence.fencing_epoch,
        artifacts.fencing_epoch.as_ref(),
        "fencing_epoch",
    )
}

fn merge_authorized_phase_spec_digest(
    history: &mut Vec<AuthorizedPhaseSpecDigestV1>,
    phase: OperationPhase,
    branch: ExecutorPhaseBranch,
    incoming: Option<&EvidenceDigest>,
) -> Result<(), StoreError> {
    let Some(incoming) = incoming else {
        return Ok(());
    };
    match history
        .iter()
        .find(|entry| entry.phase == phase && entry.branch == branch)
    {
        Some(entry) if &entry.spec_digest == incoming => Ok(()),
        Some(_) => Err(StoreError::ArtifactEvidenceConflict(
            "authorized_phase_spec_digest",
        )),
        None => {
            history.push(AuthorizedPhaseSpecDigestV1 {
                branch,
                phase,
                spec_digest: incoming.clone(),
            });
            Ok(())
        }
    }
}

fn merge_optional<T: Clone + Eq>(
    target: &mut Option<T>,
    incoming: Option<&T>,
    field: &'static str,
) -> Result<(), StoreError> {
    match (&*target, incoming) {
        (_, None) => Ok(()),
        (None, Some(value)) => {
            *target = Some(value.clone());
            Ok(())
        }
        (Some(current), Some(value)) if current == value => Ok(()),
        (Some(_), Some(_)) => Err(StoreError::ArtifactEvidenceConflict(field)),
    }
}

fn merge_vector<T: Clone + Eq>(
    target: &mut Vec<T>,
    incoming: &[T],
    field: &'static str,
) -> Result<(), StoreError> {
    if incoming.is_empty() || target.as_slice() == incoming {
        return Ok(());
    }
    if target.is_empty() {
        target.extend_from_slice(incoming);
        Ok(())
    } else {
        Err(StoreError::ArtifactEvidenceConflict(field))
    }
}

fn latest_attempt(
    transaction: &Transaction<'_>,
    request_id: Uuid,
) -> Result<Option<OperationRecord>, StoreError> {
    latest_attempt_by_request_text(transaction, &request_id.to_string())
}

fn latest_attempt_by_request_text(
    transaction: &Transaction<'_>,
    request_id: &str,
) -> Result<Option<OperationRecord>, StoreError> {
    transaction
        .query_row(
            "SELECT operation_json FROM operation_attempts
             WHERE request_id = ?1 ORDER BY attempt_number DESC LIMIT 1",
            [request_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|json| decode_operation(&json))
        .transpose()
}

fn attempt_count_for_source_sequence(
    transaction: &Transaction<'_>,
    request_id: Uuid,
    source_sequence: u64,
) -> Result<u32, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT operation_json FROM operation_attempts
         WHERE request_id = ?1 ORDER BY attempt_number ASC",
    )?;
    let rows = statement.query_map([request_id.to_string()], |row| row.get::<_, String>(0))?;
    let mut count = 0_u32;
    for row in rows {
        let operation = decode_operation(&row?)?;
        if operation.evidence.source_sequence == Some(source_sequence) {
            count = count.checked_add(1).ok_or(StoreError::CorruptController(
                "source attempt count overflow",
            ))?;
        }
    }
    Ok(count)
}

fn load_attempt(
    transaction: &Transaction<'_>,
    attempt_id: Uuid,
) -> Result<OperationRecord, StoreError> {
    let json = transaction
        .query_row(
            "SELECT operation_json FROM operation_attempts WHERE attempt_id = ?1",
            [attempt_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(StoreError::OperationNotFound(attempt_id))?;
    decode_operation(&json)
}

fn persist_transition(
    transaction: &Transaction<'_>,
    operation: &mut OperationRecord,
    next_state: OperationState,
    receipt_digest: Option<EvidenceDigest>,
    occurred_at_ms: i64,
) -> Result<(), StoreError> {
    next_state.validate()?;
    let sequence = u32::try_from(operation.evidence.transitions.len())
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(StoreError::CorruptController(
            "transition sequence overflow",
        ))?;
    let transition = OperationTransition {
        sequence,
        from: operation.state.clone(),
        to: next_state.clone(),
        receipt_digest,
        occurred_at_ms,
    };
    operation.state = next_state;
    operation.updated_at_ms = occurred_at_ms;
    operation.evidence.transitions.push(transition.clone());
    let transition_json = serde_json::to_string(&transition)?;
    let operation_json = serde_json::to_string(operation)?;
    transaction.execute(
        "INSERT INTO operation_transitions(
            attempt_id, sequence, transition_json, occurred_at_ms
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            operation.attempt_id.to_string(),
            i64::from(sequence),
            transition_json,
            occurred_at_ms
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE operation_attempts
         SET phase = ?2, result = ?3, operation_json = ?4, updated_at_ms = ?5
         WHERE attempt_id = ?1",
        params![
            operation.attempt_id.to_string(),
            phase_name(operation.state.phase),
            result_name(operation.state.result),
            operation_json,
            occurred_at_ms
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::OperationNotFound(operation.attempt_id));
    }
    Ok(())
}

fn decode_operation(json: &str) -> Result<OperationRecord, StoreError> {
    let operation: OperationRecord = serde_json::from_str(json)?;
    operation.state.validate()?;
    operation
        .operation_kind
        .required_phases(operation.release_class)?;
    validate_authorized_phase_spec_history(&operation.evidence.authorized_phase_spec_digests)?;
    Ok(operation)
}

fn validate_authorized_phase_spec_history(
    history: &[AuthorizedPhaseSpecDigestV1],
) -> Result<(), StoreError> {
    for (index, entry) in history.iter().enumerate() {
        entry.branch.storage_key(entry.phase)?;
        if history[..index]
            .iter()
            .any(|previous| previous.branch == entry.branch && previous.phase == entry.phase)
        {
            return Err(StoreError::CorruptController(
                "duplicate authorized phase spec history key",
            ));
        }
    }
    Ok(())
}

fn parse_uuid(value: &str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(value).map_err(|_| StoreError::CorruptController("UUID"))
}

const fn operation_kind_name(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::Deploy => "deploy",
        OperationKind::CodeRollback => "code_rollback",
        OperationKind::BackupOnly => "backup_only",
    }
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

const fn result_name(result: OperationResult) -> &'static str {
    match result {
        OperationResult::Running => "running",
        OperationResult::Succeeded => "succeeded",
        OperationResult::Failed => "failed",
        OperationResult::RolledBack => "rolled_back",
        OperationResult::RollbackFailed => "rollback_failed",
        OperationResult::Cancelled => "cancelled",
        OperationResult::Superseded => "superseded",
        OperationResult::ManualRecoveryRequired => "manual_recovery_required",
    }
}
