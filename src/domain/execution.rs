use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{EvidenceDigest, OperationPhase, ProjectId};

pub const EXECUTION_TERMINAL_RECEIPT_SCHEMA_VERSION: u16 = 1;
pub const EXECUTION_CLEANUP_RECEIPT_SCHEMA_VERSION: u16 = 1;
const MAX_STEP_ID_BYTES: usize = 96;
const MAX_CLEANUP_ERROR_CODE_BYTES: usize = 96;

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionResultV1 {
    Succeeded,
    Failed,
    TimedOut,
    OomKilled,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProcessOutcomeV1 {
    pub result: ExecutionResultV1,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub timed_out: bool,
    pub oom_killed: bool,
}

impl ExecutionProcessOutcomeV1 {
    pub fn validate(&self) -> Result<(), ExecutionReceiptError> {
        if self.exit_code.is_some_and(|code| code < 0)
            || self
                .signal
                .as_deref()
                .is_some_and(|signal| !valid_token(signal, 32))
        {
            return Err(ExecutionReceiptError::InvalidDocument);
        }
        let valid = match self.result {
            ExecutionResultV1::Succeeded => {
                self.exit_code == Some(0)
                    && self.signal.is_none()
                    && !self.timed_out
                    && !self.oom_killed
            }
            ExecutionResultV1::Failed => {
                !self.timed_out && !self.oom_killed && self.exit_code != Some(0)
            }
            ExecutionResultV1::TimedOut => self.timed_out && !self.oom_killed,
            ExecutionResultV1::OomKilled => self.oom_killed && !self.timed_out,
            ExecutionResultV1::Cancelled => !self.timed_out && !self.oom_killed,
        };
        if valid {
            Ok(())
        } else {
            Err(ExecutionReceiptError::InvalidDocument)
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionMemoryEventsV1 {
    pub low: u64,
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionIoUsageV1 {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_operations: u64,
    pub write_operations: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionResourceUsageV1 {
    pub cpu_usage_usec: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub memory_events: Option<ExecutionMemoryEventsV1>,
    pub io: Option<ExecutionIoUsageV1>,
    pub tasks_peak: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionStorageUsageV1 {
    pub scratch_before_bytes: Option<u64>,
    pub scratch_after_bytes: Option<u64>,
    pub scratch_peak_bytes: Option<u64>,
    pub cache_delta_bytes: Option<i64>,
    pub log_delta_bytes: Option<i64>,
    pub filesystem_available_after_bytes: Option<u64>,
    pub emergency_reserve_required_bytes: Option<u64>,
    pub emergency_reserve_remaining_bytes: Option<u64>,
    pub emergency_reserve_deficit_bytes: Option<u64>,
}

impl ExecutionStorageUsageV1 {
    pub(crate) fn validate(&self) -> Result<(), ExecutionReceiptError> {
        if self
            .scratch_peak_bytes
            .zip(self.scratch_before_bytes)
            .is_some_and(|(peak, before)| peak < before)
            || self
                .scratch_peak_bytes
                .zip(self.scratch_after_bytes)
                .is_some_and(|(peak, after)| peak < after)
        {
            return Err(ExecutionReceiptError::InvalidDocument);
        }
        match (
            self.filesystem_available_after_bytes,
            self.emergency_reserve_required_bytes,
            self.emergency_reserve_remaining_bytes,
            self.emergency_reserve_deficit_bytes,
        ) {
            (Some(available), Some(required), Some(remaining), Some(deficit))
                if remaining == available.saturating_sub(required)
                    && deficit == required.saturating_sub(available) => {}
            (_, None, None, None) => {}
            _ => return Err(ExecutionReceiptError::InvalidDocument),
        }
        Ok(())
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEvidenceGapV1 {
    CpuUsage,
    MemoryPeak,
    MemoryEvents,
    Io,
    TasksPeak,
    ScratchBefore,
    ScratchAfter,
    ScratchPeak,
    CacheDelta,
    LogDelta,
    FilesystemAvailable,
    EmergencyReserve,
    ProcessStatus,
}

impl ExecutionEvidenceGapV1 {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CpuUsage => "cpu_usage",
            Self::MemoryPeak => "memory_peak",
            Self::MemoryEvents => "memory_events",
            Self::Io => "io",
            Self::TasksPeak => "tasks_peak",
            Self::ScratchBefore => "scratch_before",
            Self::ScratchAfter => "scratch_after",
            Self::ScratchPeak => "scratch_peak",
            Self::CacheDelta => "cache_delta",
            Self::LogDelta => "log_delta",
            Self::FilesystemAvailable => "filesystem_available",
            Self::EmergencyReserve => "emergency_reserve",
            Self::ProcessStatus => "process_status",
        }
    }
}

pub fn expected_execution_gaps(
    process: &ExecutionProcessOutcomeV1,
    resources: &ExecutionResourceUsageV1,
    storage: &ExecutionStorageUsageV1,
) -> Vec<ExecutionEvidenceGapV1> {
    let mut gaps = Vec::new();
    if resources.cpu_usage_usec.is_none() {
        gaps.push(ExecutionEvidenceGapV1::CpuUsage);
    }
    if resources.memory_peak_bytes.is_none() {
        gaps.push(ExecutionEvidenceGapV1::MemoryPeak);
    }
    if resources.memory_events.is_none() {
        gaps.push(ExecutionEvidenceGapV1::MemoryEvents);
    }
    if resources.io.is_none() {
        gaps.push(ExecutionEvidenceGapV1::Io);
    }
    if resources.tasks_peak.is_none() {
        gaps.push(ExecutionEvidenceGapV1::TasksPeak);
    }
    if storage.scratch_before_bytes.is_none() {
        gaps.push(ExecutionEvidenceGapV1::ScratchBefore);
    }
    if storage.scratch_after_bytes.is_none() {
        gaps.push(ExecutionEvidenceGapV1::ScratchAfter);
    }
    if storage.scratch_peak_bytes.is_none() {
        gaps.push(ExecutionEvidenceGapV1::ScratchPeak);
    }
    if storage.cache_delta_bytes.is_none() {
        gaps.push(ExecutionEvidenceGapV1::CacheDelta);
    }
    if storage.log_delta_bytes.is_none() {
        gaps.push(ExecutionEvidenceGapV1::LogDelta);
    }
    if storage.filesystem_available_after_bytes.is_none() {
        gaps.push(ExecutionEvidenceGapV1::FilesystemAvailable);
    }
    if storage.emergency_reserve_required_bytes.is_none()
        || storage.emergency_reserve_remaining_bytes.is_none()
        || storage.emergency_reserve_deficit_bytes.is_none()
    {
        gaps.push(ExecutionEvidenceGapV1::EmergencyReserve);
    }
    if process.result != ExecutionResultV1::Succeeded
        && process.exit_code.is_none()
        && process.signal.is_none()
    {
        gaps.push(ExecutionEvidenceGapV1::ProcessStatus);
    }
    gaps
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTerminalReceiptV1 {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub attempt_id: Uuid,
    pub start_evidence_digest: EvidenceDigest,
    pub project_id: ProjectId,
    pub phase: OperationPhase,
    pub step_id: String,
    pub sequence: u16,
    pub started_at_ms: i64,
    pub finished_at_ms: i64,
    pub duration_ms: u64,
    pub process: ExecutionProcessOutcomeV1,
    pub resources: ExecutionResourceUsageV1,
    pub storage: ExecutionStorageUsageV1,
    pub evidence_gaps: Vec<ExecutionEvidenceGapV1>,
    pub receipt_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct ExecutionTerminalReceiptDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    request_id: Uuid,
    attempt_id: Uuid,
    start_evidence_digest: &'a EvidenceDigest,
    project_id: &'a ProjectId,
    phase: OperationPhase,
    step_id: &'a str,
    sequence: u16,
    started_at_ms: i64,
    finished_at_ms: i64,
    duration_ms: u64,
    process: &'a ExecutionProcessOutcomeV1,
    resources: &'a ExecutionResourceUsageV1,
    storage: &'a ExecutionStorageUsageV1,
    evidence_gaps: &'a [ExecutionEvidenceGapV1],
}

impl ExecutionTerminalReceiptV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: Uuid,
        attempt_id: Uuid,
        start_evidence_digest: EvidenceDigest,
        project_id: ProjectId,
        phase: OperationPhase,
        step_id: String,
        sequence: u16,
        started_at_ms: i64,
        finished_at_ms: i64,
        process: ExecutionProcessOutcomeV1,
        resources: ExecutionResourceUsageV1,
        storage: ExecutionStorageUsageV1,
    ) -> Result<Self, ExecutionReceiptError> {
        let duration_ms = elapsed_ms(started_at_ms, finished_at_ms)?;
        let evidence_gaps = expected_execution_gaps(&process, &resources, &storage);
        let mut receipt = Self {
            schema_version: EXECUTION_TERMINAL_RECEIPT_SCHEMA_VERSION,
            request_id,
            attempt_id,
            start_evidence_digest,
            project_id,
            phase,
            step_id,
            sequence,
            started_at_ms,
            finished_at_ms,
            duration_ms,
            process,
            resources,
            storage,
            evidence_gaps,
            receipt_digest: EvidenceDigest::sha256([]),
        };
        receipt.receipt_digest = receipt.calculate_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ExecutionReceiptError> {
        if self.schema_version != EXECUTION_TERMINAL_RECEIPT_SCHEMA_VERSION
            || self.request_id.is_nil()
            || self.attempt_id.is_nil()
            || self.sequence == 0
            || !valid_token(&self.step_id, MAX_STEP_ID_BYTES)
            || self.duration_ms != elapsed_ms(self.started_at_ms, self.finished_at_ms)?
        {
            return Err(ExecutionReceiptError::InvalidDocument);
        }
        self.process.validate()?;
        self.storage.validate()?;
        if !strictly_sorted_unique(&self.evidence_gaps)
            || self.evidence_gaps
                != expected_execution_gaps(&self.process, &self.resources, &self.storage)
        {
            return Err(ExecutionReceiptError::InvalidDocument);
        }
        if self.receipt_digest != self.calculate_digest()? {
            return Err(ExecutionReceiptError::DigestMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionReceiptError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ExecutionReceiptError> {
        let receipt: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&receipt)? != bytes {
            return Err(ExecutionReceiptError::InvalidDocument);
        }
        receipt.validate()?;
        Ok(receipt)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, ExecutionReceiptError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &ExecutionTerminalReceiptDigestPayload {
                purpose: "rdashboard.execution-terminal-receipt.v1",
                schema_version: self.schema_version,
                request_id: self.request_id,
                attempt_id: self.attempt_id,
                start_evidence_digest: &self.start_evidence_digest,
                project_id: &self.project_id,
                phase: self.phase,
                step_id: &self.step_id,
                sequence: self.sequence,
                started_at_ms: self.started_at_ms,
                finished_at_ms: self.finished_at_ms,
                duration_ms: self.duration_ms,
                process: &self.process,
                resources: &self.resources,
                storage: &self.storage,
                evidence_gaps: &self.evidence_gaps,
            },
        )?))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCleanupStateV1 {
    Complete,
    Pending,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCleanupEvidenceGapV1 {
    ScratchRemoved,
    FilesystemAvailable,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCleanupReceiptV1 {
    pub schema_version: u16,
    pub attempt_id: Uuid,
    pub terminal_receipt_digest: EvidenceDigest,
    pub state: ExecutionCleanupStateV1,
    pub unit_collected: bool,
    pub scratch_removed_bytes: Option<u64>,
    pub remaining_transient_items: u32,
    pub filesystem_available_after_bytes: Option<u64>,
    pub evidence_gaps: Vec<ExecutionCleanupEvidenceGapV1>,
    pub error_code: Option<String>,
    pub completed_at_ms: i64,
    pub receipt_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct ExecutionCleanupReceiptDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    attempt_id: Uuid,
    terminal_receipt_digest: &'a EvidenceDigest,
    state: ExecutionCleanupStateV1,
    unit_collected: bool,
    scratch_removed_bytes: Option<u64>,
    remaining_transient_items: u32,
    filesystem_available_after_bytes: Option<u64>,
    evidence_gaps: &'a [ExecutionCleanupEvidenceGapV1],
    error_code: Option<&'a str>,
    completed_at_ms: i64,
}

impl ExecutionCleanupReceiptV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attempt_id: Uuid,
        terminal_receipt_digest: EvidenceDigest,
        state: ExecutionCleanupStateV1,
        unit_collected: bool,
        scratch_removed_bytes: Option<u64>,
        remaining_transient_items: u32,
        filesystem_available_after_bytes: Option<u64>,
        error_code: Option<String>,
        completed_at_ms: i64,
    ) -> Result<Self, ExecutionReceiptError> {
        let evidence_gaps =
            expected_cleanup_gaps(scratch_removed_bytes, filesystem_available_after_bytes);
        let mut receipt = Self {
            schema_version: EXECUTION_CLEANUP_RECEIPT_SCHEMA_VERSION,
            attempt_id,
            terminal_receipt_digest,
            state,
            unit_collected,
            scratch_removed_bytes,
            remaining_transient_items,
            filesystem_available_after_bytes,
            evidence_gaps,
            error_code,
            completed_at_ms,
            receipt_digest: EvidenceDigest::sha256([]),
        };
        receipt.receipt_digest = receipt.calculate_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ExecutionReceiptError> {
        if self.schema_version != EXECUTION_CLEANUP_RECEIPT_SCHEMA_VERSION
            || self.attempt_id.is_nil()
            || self.completed_at_ms < 0
            || self
                .error_code
                .as_deref()
                .is_some_and(|code| !valid_token(code, MAX_CLEANUP_ERROR_CODE_BYTES))
        {
            return Err(ExecutionReceiptError::InvalidDocument);
        }
        let state_valid = match self.state {
            ExecutionCleanupStateV1::Complete => {
                self.unit_collected
                    && self.remaining_transient_items == 0
                    && self.error_code.is_none()
            }
            ExecutionCleanupStateV1::Pending => {
                !self.unit_collected
                    && self.remaining_transient_items > 0
                    && self.error_code.is_some()
            }
        };
        if !state_valid {
            return Err(ExecutionReceiptError::InvalidDocument);
        }
        if self.evidence_gaps
            != expected_cleanup_gaps(
                self.scratch_removed_bytes,
                self.filesystem_available_after_bytes,
            )
        {
            return Err(ExecutionReceiptError::InvalidDocument);
        }
        if self.receipt_digest != self.calculate_digest()? {
            return Err(ExecutionReceiptError::DigestMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionReceiptError> {
        self.validate()?;
        Ok(serde_jcs::to_vec(self)?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ExecutionReceiptError> {
        let receipt: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&receipt)? != bytes {
            return Err(ExecutionReceiptError::InvalidDocument);
        }
        receipt.validate()?;
        Ok(receipt)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, ExecutionReceiptError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &ExecutionCleanupReceiptDigestPayload {
                purpose: "rdashboard.execution-cleanup-receipt.v1",
                schema_version: self.schema_version,
                attempt_id: self.attempt_id,
                terminal_receipt_digest: &self.terminal_receipt_digest,
                state: self.state,
                unit_collected: self.unit_collected,
                scratch_removed_bytes: self.scratch_removed_bytes,
                remaining_transient_items: self.remaining_transient_items,
                filesystem_available_after_bytes: self.filesystem_available_after_bytes,
                evidence_gaps: &self.evidence_gaps,
                error_code: self.error_code.as_deref(),
                completed_at_ms: self.completed_at_ms,
            },
        )?))
    }
}

fn expected_cleanup_gaps(
    scratch_removed_bytes: Option<u64>,
    filesystem_available_after_bytes: Option<u64>,
) -> Vec<ExecutionCleanupEvidenceGapV1> {
    let mut gaps = Vec::new();
    if scratch_removed_bytes.is_none() {
        gaps.push(ExecutionCleanupEvidenceGapV1::ScratchRemoved);
    }
    if filesystem_available_after_bytes.is_none() {
        gaps.push(ExecutionCleanupEvidenceGapV1::FilesystemAvailable);
    }
    gaps
}

fn elapsed_ms(started_at_ms: i64, finished_at_ms: i64) -> Result<u64, ExecutionReceiptError> {
    if started_at_ms < 0 || finished_at_ms < started_at_ms {
        return Err(ExecutionReceiptError::InvalidDocument);
    }
    u64::try_from(finished_at_ms - started_at_ms)
        .map_err(|_| ExecutionReceiptError::InvalidDocument)
}

fn valid_token(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionReceiptError {
    #[error("execution receipt is structurally invalid")]
    InvalidDocument,
    #[error("execution receipt digest does not match its canonical payload")]
    DigestMismatch,
    #[error("execution receipt canonical encoding failed")]
    CanonicalEncoding(#[from] serde_json::Error),
}
