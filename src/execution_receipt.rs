use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::{
        EvidenceDigest, ExecutionCleanupReceiptV1, ExecutionCleanupStateV1, ExecutionIoUsageV1,
        ExecutionMemoryEventsV1, ExecutionProcessOutcomeV1, ExecutionReceiptError,
        ExecutionResourceUsageV1, ExecutionResultV1, ExecutionStorageUsageV1,
        ExecutionTerminalReceiptV1, GIB,
    },
    phase6::{AuthorizedPhaseSpecV1, FixedAdapterRequestV1, Phase6ContractError},
};

pub const EXECUTION_START_FILE_NAME: &str = "execution-start.jcs";
pub const EXECUTION_TERMINAL_FILE_NAME: &str = "terminal-receipt.jcs";
pub const EXECUTION_CLEANUP_FILE_NAME: &str = "cleanup-receipt.jcs";
pub const EXECUTION_TERMINATION_INTENT_FILE_NAME: &str = "termination-intent.jcs";
pub const INSTALLED_ADAPTER_RECEIPT_EXECUTABLE: &str =
    "/usr/libexec/rdashboard/rdashboard-adapter-receipt";
pub const INSTALLED_JOB_DIRECTORY: &str = "/job";

const SPEC_FILE_NAME: &str = "spec.jcs";
const REQUEST_FILE_NAME: &str = "request.jcs";
const MAX_RECEIPT_FILE_BYTES: u64 = 256 * 1024;
const MAX_CGROUP_FILE_BYTES: u64 = 64 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const MAX_DIRECTORY_DEPTH: usize = 32;
const EXECUTION_START_SCHEMA_VERSION: u16 = 1;
const TERMINATION_INTENT_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStartEvidenceV1 {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub attempt_id: Uuid,
    pub project_id: crate::domain::ProjectId,
    pub phase: crate::domain::OperationPhase,
    pub step_id: String,
    pub sequence: u16,
    pub started_at_ms: i64,
    pub scratch_before_bytes: Option<u64>,
    pub filesystem_available_before_bytes: Option<u64>,
    pub evidence_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct ExecutionStartDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    request_id: Uuid,
    attempt_id: Uuid,
    project_id: &'a crate::domain::ProjectId,
    phase: crate::domain::OperationPhase,
    step_id: &'a str,
    sequence: u16,
    started_at_ms: i64,
    scratch_before_bytes: Option<u64>,
    filesystem_available_before_bytes: Option<u64>,
}

impl ExecutionStartEvidenceV1 {
    fn new(
        request: &FixedAdapterRequestV1,
        started_at_ms: i64,
        scratch_before_bytes: Option<u64>,
        filesystem_available_before_bytes: Option<u64>,
    ) -> Result<Self, ExecutionReceiptRuntimeError> {
        if started_at_ms < 0 {
            return Err(ExecutionReceiptRuntimeError::InvalidStartEvidence);
        }
        let mut evidence = Self {
            schema_version: EXECUTION_START_SCHEMA_VERSION,
            request_id: request.request_id,
            attempt_id: request.attempt_id,
            project_id: request.project_id.clone(),
            phase: request.phase,
            step_id: request.profile.id().to_owned(),
            sequence: request.sequence,
            started_at_ms,
            scratch_before_bytes,
            filesystem_available_before_bytes,
            evidence_digest: EvidenceDigest::sha256([]),
        };
        evidence.evidence_digest = evidence.calculate_digest()?;
        Ok(evidence)
    }

    fn validate_for(
        &self,
        request: &FixedAdapterRequestV1,
    ) -> Result<(), ExecutionReceiptRuntimeError> {
        if self.schema_version != EXECUTION_START_SCHEMA_VERSION
            || self.request_id != request.request_id
            || self.attempt_id != request.attempt_id
            || self.project_id != request.project_id
            || self.phase != request.phase
            || self.step_id != request.profile.id()
            || self.sequence != request.sequence
            || self.started_at_ms < 0
            || self.evidence_digest != self.calculate_digest()?
        {
            return Err(ExecutionReceiptRuntimeError::InvalidStartEvidence);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionReceiptRuntimeError> {
        Ok(serde_jcs::to_vec(self)?)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, ExecutionReceiptRuntimeError> {
        let evidence: Self = serde_json::from_slice(bytes)?;
        if serde_jcs::to_vec(&evidence)? != bytes
            || evidence.schema_version != EXECUTION_START_SCHEMA_VERSION
            || evidence.request_id.is_nil()
            || evidence.attempt_id.is_nil()
            || evidence.sequence == 0
            || evidence.started_at_ms < 0
            || !valid_step_id(&evidence.step_id)
            || evidence.evidence_digest != evidence.calculate_digest()?
        {
            return Err(ExecutionReceiptRuntimeError::InvalidStartEvidence);
        }
        Ok(evidence)
    }

    fn calculate_digest(&self) -> Result<EvidenceDigest, ExecutionReceiptRuntimeError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &ExecutionStartDigestPayload {
                purpose: "rdashboard.execution-start-evidence.v1",
                schema_version: self.schema_version,
                request_id: self.request_id,
                attempt_id: self.attempt_id,
                project_id: &self.project_id,
                phase: self.phase,
                step_id: &self.step_id,
                sequence: self.sequence,
                started_at_ms: self.started_at_ms,
                scratch_before_bytes: self.scratch_before_bytes,
                filesystem_available_before_bytes: self.filesystem_available_before_bytes,
            },
        )?))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTerminationKindV1 {
    Cancelled,
    DeadlineExceeded,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionTerminationIntentV1 {
    schema_version: u16,
    attempt_id: Uuid,
    kind: ExecutionTerminationKindV1,
    recorded_at_ms: i64,
    intent_digest: EvidenceDigest,
}

#[derive(Serialize)]
struct ExecutionTerminationIntentDigestPayload<'a> {
    purpose: &'static str,
    schema_version: u16,
    attempt_id: Uuid,
    kind: ExecutionTerminationKindV1,
    recorded_at_ms: i64,
    start_evidence_digest: &'a EvidenceDigest,
}

impl ExecutionTerminationIntentV1 {
    fn new(
        start: &ExecutionStartEvidenceV1,
        kind: ExecutionTerminationKindV1,
        recorded_at_ms: i64,
    ) -> Result<Self, ExecutionReceiptRuntimeError> {
        if recorded_at_ms < start.started_at_ms {
            return Err(ExecutionReceiptRuntimeError::InvalidTerminationIntent);
        }
        let mut intent = Self {
            schema_version: TERMINATION_INTENT_SCHEMA_VERSION,
            attempt_id: start.attempt_id,
            kind,
            recorded_at_ms,
            intent_digest: EvidenceDigest::sha256([]),
        };
        intent.intent_digest = intent.calculate_digest(&start.evidence_digest)?;
        Ok(intent)
    }

    fn validate_for(
        &self,
        start: &ExecutionStartEvidenceV1,
    ) -> Result<(), ExecutionReceiptRuntimeError> {
        if self.schema_version != TERMINATION_INTENT_SCHEMA_VERSION
            || self.attempt_id != start.attempt_id
            || self.recorded_at_ms < start.started_at_ms
            || self.intent_digest != self.calculate_digest(&start.evidence_digest)?
        {
            return Err(ExecutionReceiptRuntimeError::InvalidTerminationIntent);
        }
        Ok(())
    }

    fn calculate_digest(
        &self,
        start_evidence_digest: &EvidenceDigest,
    ) -> Result<EvidenceDigest, ExecutionReceiptRuntimeError> {
        Ok(EvidenceDigest::sha256(serde_jcs::to_vec(
            &ExecutionTerminationIntentDigestPayload {
                purpose: "rdashboard.execution-termination-intent.v1",
                schema_version: self.schema_version,
                attempt_id: self.attempt_id,
                kind: self.kind,
                recorded_at_ms: self.recorded_at_ms,
                start_evidence_digest,
            },
        )?))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CaptureEnvironmentV1 {
    pub service_result: Option<String>,
    pub exit_code: Option<String>,
    pub exit_status: Option<String>,
}

impl CaptureEnvironmentV1 {
    pub fn installed() -> Self {
        Self {
            service_result: env::var("SERVICE_RESULT").ok(),
            exit_code: env::var("EXIT_CODE").ok(),
            exit_status: env::var("EXIT_STATUS").ok(),
        }
    }
}

pub fn execution_started(
    job_directory: &Path,
    required_uid: u32,
) -> Result<bool, ExecutionReceiptRuntimeError> {
    validate_private_directory(job_directory, required_uid)?;
    match read_owner_only_file(&job_directory.join(EXECUTION_START_FILE_NAME), required_uid) {
        Ok(bytes) => {
            ExecutionStartEvidenceV1::decode_canonical(&bytes)?;
            Ok(true)
        }
        Err(ExecutionReceiptRuntimeError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

pub fn materialize_execution_start(
    job_directory: &Path,
    required_uid: u32,
    request: &FixedAdapterRequestV1,
    started_at_ms: i64,
) -> Result<ExecutionStartEvidenceV1, ExecutionReceiptRuntimeError> {
    validate_private_directory(job_directory, required_uid)?;
    let path = job_directory.join(EXECUTION_START_FILE_NAME);
    match fs::symlink_metadata(&path) {
        Ok(_) => return Err(ExecutionReceiptRuntimeError::ExecutionAlreadyStarted),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let start = ExecutionStartEvidenceV1::new(
        request,
        started_at_ms,
        directory_size(job_directory).ok(),
        fs2::available_space(job_directory).ok(),
    )?;
    write_owner_only_new(
        &path,
        required_uid,
        &start.canonical_bytes()?,
        ExecutionReceiptRuntimeError::ExecutionAlreadyStarted,
    )?;
    sync_directory(job_directory, required_uid)?;
    Ok(start)
}

pub fn materialize_termination_intent(
    job_directory: &Path,
    required_uid: u32,
    kind: ExecutionTerminationKindV1,
    recorded_at_ms: i64,
) -> Result<(), ExecutionReceiptRuntimeError> {
    let start = read_start(job_directory, required_uid)?;
    let intent = ExecutionTerminationIntentV1::new(&start, kind, recorded_at_ms)?;
    let bytes = serde_jcs::to_vec(&intent)?;
    write_owner_only_new(
        &job_directory.join(EXECUTION_TERMINATION_INTENT_FILE_NAME),
        required_uid,
        &bytes,
        ExecutionReceiptRuntimeError::TerminationIntentAlreadyExists,
    )?;
    sync_directory(job_directory, required_uid)
}

pub fn capture_installed_terminal_receipt(
    environment: &CaptureEnvironmentV1,
    finished_at_ms: i64,
) -> Result<ExecutionTerminalReceiptV1, ExecutionReceiptRuntimeError> {
    capture_terminal_receipt_in(
        Path::new(INSTALLED_JOB_DIRECTORY),
        0,
        environment,
        Path::new("/proc/self/cgroup"),
        Path::new("/sys/fs/cgroup"),
        finished_at_ms,
    )
}

pub fn capture_terminal_receipt_in(
    job_directory: &Path,
    required_uid: u32,
    environment: &CaptureEnvironmentV1,
    proc_cgroup_path: &Path,
    cgroup_root: &Path,
    finished_at_ms: i64,
) -> Result<ExecutionTerminalReceiptV1, ExecutionReceiptRuntimeError> {
    validate_private_directory(job_directory, required_uid)?;
    let (spec, request) = read_authorized_request(job_directory, required_uid)?;
    let start = read_start(job_directory, required_uid)?;
    start.validate_for(&request)?;
    if let Some(existing) = read_optional_terminal(job_directory, required_uid)? {
        validate_terminal_binding(&existing, &request, &start)?;
        return Ok(existing);
    }
    let termination = read_termination_intent(job_directory, required_uid, &start)?;
    let cgroup_directory = resolve_cgroup_directory(proc_cgroup_path, cgroup_root).ok();
    let resources = read_resources(cgroup_directory.as_deref());
    let process = classify_process(environment, termination.as_ref(), &resources);
    let scratch_after_bytes = directory_size(job_directory).ok();
    let filesystem_available_after_bytes = fs2::available_space(job_directory).ok();
    let emergency_reserve = filesystem_available_after_bytes.and_then(|available| {
        fs2::total_space(job_directory).ok().map(|total| {
            let required = (8 * GIB).max(total.saturating_mul(15).div_ceil(100));
            (
                required,
                available.saturating_sub(required),
                required.saturating_sub(available),
            )
        })
    });
    let storage = ExecutionStorageUsageV1 {
        scratch_before_bytes: start.scratch_before_bytes,
        scratch_after_bytes,
        scratch_peak_bytes: None,
        cache_delta_bytes: None,
        log_delta_bytes: None,
        filesystem_available_after_bytes,
        emergency_reserve_required_bytes: emergency_reserve.map(|value| value.0),
        emergency_reserve_remaining_bytes: emergency_reserve.map(|value| value.1),
        emergency_reserve_deficit_bytes: emergency_reserve.map(|value| value.2),
    };
    let receipt = ExecutionTerminalReceiptV1::new(
        request.request_id,
        request.attempt_id,
        start.evidence_digest.clone(),
        request.project_id.clone(),
        request.phase,
        request.profile.id().to_owned(),
        request.sequence,
        start.started_at_ms,
        finished_at_ms,
        process,
        resources,
        storage,
    )?;
    let path = job_directory.join(EXECUTION_TERMINAL_FILE_NAME);
    write_owner_only_new(
        &path,
        required_uid,
        &receipt.canonical_bytes()?,
        ExecutionReceiptRuntimeError::TerminalReceiptAlreadyExists,
    )?;
    sync_directory(job_directory, required_uid)?;
    let stored = read_terminal_receipt(job_directory, required_uid, &spec, request.sequence)?;
    if stored != receipt {
        return Err(ExecutionReceiptRuntimeError::TerminalReceiptConflict);
    }
    Ok(receipt)
}

pub fn read_terminal_receipt(
    job_directory: &Path,
    required_uid: u32,
    spec: &AuthorizedPhaseSpecV1,
    sequence: u16,
) -> Result<ExecutionTerminalReceiptV1, ExecutionReceiptRuntimeError> {
    let request = spec.fixed_adapter_request(sequence)?;
    let start = read_start(job_directory, required_uid)?;
    start.validate_for(&request)?;
    let bytes = read_owner_only_file(
        &job_directory.join(EXECUTION_TERMINAL_FILE_NAME),
        required_uid,
    )?;
    let receipt = ExecutionTerminalReceiptV1::decode_canonical(&bytes)?;
    validate_terminal_binding(&receipt, &request, &start)?;
    Ok(receipt)
}

pub fn materialize_cleanup_receipt(
    job_directory: &Path,
    required_uid: u32,
    terminal: &ExecutionTerminalReceiptV1,
    unit_collected: bool,
    error_code: Option<String>,
    completed_at_ms: i64,
) -> Result<ExecutionCleanupReceiptV1, ExecutionReceiptRuntimeError> {
    validate_private_directory(job_directory, required_uid)?;
    let path = job_directory.join(EXECUTION_CLEANUP_FILE_NAME);
    match read_owner_only_file(&path, required_uid) {
        Ok(bytes) => {
            let existing = ExecutionCleanupReceiptV1::decode_canonical(&bytes)?;
            if existing.attempt_id != terminal.attempt_id
                || existing.terminal_receipt_digest != terminal.receipt_digest
            {
                return Err(ExecutionReceiptRuntimeError::CleanupReceiptConflict);
            }
            return Ok(existing);
        }
        Err(ExecutionReceiptRuntimeError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let (state, remaining_transient_items) = if unit_collected {
        (ExecutionCleanupStateV1::Complete, 0)
    } else {
        (ExecutionCleanupStateV1::Pending, 1)
    };
    let receipt = ExecutionCleanupReceiptV1::new(
        terminal.attempt_id,
        terminal.receipt_digest.clone(),
        state,
        unit_collected,
        None,
        remaining_transient_items,
        fs2::available_space(job_directory).ok(),
        error_code,
        completed_at_ms,
    )?;
    write_owner_only_new(
        &path,
        required_uid,
        &receipt.canonical_bytes()?,
        ExecutionReceiptRuntimeError::CleanupReceiptAlreadyExists,
    )?;
    sync_directory(job_directory, required_uid)?;
    Ok(receipt)
}

pub fn read_cleanup_receipt(
    job_directory: &Path,
    required_uid: u32,
    terminal: &ExecutionTerminalReceiptV1,
) -> Result<ExecutionCleanupReceiptV1, ExecutionReceiptRuntimeError> {
    let bytes = read_owner_only_file(
        &job_directory.join(EXECUTION_CLEANUP_FILE_NAME),
        required_uid,
    )?;
    let receipt = ExecutionCleanupReceiptV1::decode_canonical(&bytes)?;
    if receipt.attempt_id != terminal.attempt_id
        || receipt.terminal_receipt_digest != terminal.receipt_digest
    {
        return Err(ExecutionReceiptRuntimeError::CleanupReceiptConflict);
    }
    Ok(receipt)
}

fn read_authorized_request(
    job_directory: &Path,
    required_uid: u32,
) -> Result<(AuthorizedPhaseSpecV1, FixedAdapterRequestV1), ExecutionReceiptRuntimeError> {
    let spec_bytes = read_owner_only_file(&job_directory.join(SPEC_FILE_NAME), required_uid)?;
    let spec = AuthorizedPhaseSpecV1::decode_canonical(&spec_bytes)?;
    let request_bytes = read_owner_only_file(&job_directory.join(REQUEST_FILE_NAME), required_uid)?;
    let start = read_start(job_directory, required_uid)?;
    let request = FixedAdapterRequestV1::decode_authorized(&request_bytes, &spec, start.sequence)?;
    Ok((spec, request))
}

fn read_start(
    job_directory: &Path,
    required_uid: u32,
) -> Result<ExecutionStartEvidenceV1, ExecutionReceiptRuntimeError> {
    let bytes = read_owner_only_file(&job_directory.join(EXECUTION_START_FILE_NAME), required_uid)?;
    ExecutionStartEvidenceV1::decode_canonical(&bytes)
}

fn read_termination_intent(
    job_directory: &Path,
    required_uid: u32,
    start: &ExecutionStartEvidenceV1,
) -> Result<Option<ExecutionTerminationIntentV1>, ExecutionReceiptRuntimeError> {
    let path = job_directory.join(EXECUTION_TERMINATION_INTENT_FILE_NAME);
    let bytes = match read_owner_only_file(&path, required_uid) {
        Ok(bytes) => bytes,
        Err(ExecutionReceiptRuntimeError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let intent: ExecutionTerminationIntentV1 = serde_json::from_slice(&bytes)?;
    if serde_jcs::to_vec(&intent)? != bytes {
        return Err(ExecutionReceiptRuntimeError::InvalidTerminationIntent);
    }
    intent.validate_for(start)?;
    Ok(Some(intent))
}

fn read_optional_terminal(
    job_directory: &Path,
    required_uid: u32,
) -> Result<Option<ExecutionTerminalReceiptV1>, ExecutionReceiptRuntimeError> {
    let path = job_directory.join(EXECUTION_TERMINAL_FILE_NAME);
    match read_owner_only_file(&path, required_uid) {
        Ok(bytes) => Ok(Some(ExecutionTerminalReceiptV1::decode_canonical(&bytes)?)),
        Err(ExecutionReceiptRuntimeError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn validate_terminal_binding(
    receipt: &ExecutionTerminalReceiptV1,
    request: &FixedAdapterRequestV1,
    start: &ExecutionStartEvidenceV1,
) -> Result<(), ExecutionReceiptRuntimeError> {
    if receipt.request_id != request.request_id
        || receipt.attempt_id != request.attempt_id
        || receipt.start_evidence_digest != start.evidence_digest
        || receipt.project_id != request.project_id
        || receipt.phase != request.phase
        || receipt.step_id != request.profile.id()
        || receipt.sequence != request.sequence
    {
        return Err(ExecutionReceiptRuntimeError::TerminalReceiptConflict);
    }
    Ok(())
}

fn classify_process(
    environment: &CaptureEnvironmentV1,
    termination: Option<&ExecutionTerminationIntentV1>,
    resources: &ExecutionResourceUsageV1,
) -> ExecutionProcessOutcomeV1 {
    let exit_code = match environment.exit_code.as_deref() {
        Some("exited") => environment
            .exit_status
            .as_deref()
            .and_then(|status| status.parse::<i32>().ok())
            .filter(|status| *status >= 0),
        _ => None,
    };
    let signal = match environment.exit_code.as_deref() {
        Some("killed" | "dumped") => environment
            .exit_status
            .as_deref()
            .map(str::to_ascii_lowercase)
            .filter(|signal| valid_signal(signal)),
        _ => None,
    };
    let oom_killed = environment.service_result.as_deref() == Some("oom-kill")
        || resources
            .memory_events
            .as_ref()
            .is_some_and(|events| events.oom_kill > 0 || events.oom_group_kill > 0);
    let timed_out = matches!(
        environment.service_result.as_deref(),
        Some("timeout" | "watchdog")
    );
    let result = match termination.map(|intent| intent.kind) {
        Some(ExecutionTerminationKindV1::Cancelled) => ExecutionResultV1::Cancelled,
        Some(ExecutionTerminationKindV1::DeadlineExceeded) => ExecutionResultV1::TimedOut,
        None if oom_killed => ExecutionResultV1::OomKilled,
        None if timed_out => ExecutionResultV1::TimedOut,
        None if environment.service_result.as_deref() == Some("success") => {
            ExecutionResultV1::Succeeded
        }
        None => ExecutionResultV1::Failed,
    };
    ExecutionProcessOutcomeV1 {
        result,
        exit_code: if result == ExecutionResultV1::Succeeded {
            Some(0)
        } else {
            exit_code.filter(|code| *code != 0)
        },
        signal,
        timed_out: result == ExecutionResultV1::TimedOut,
        oom_killed: result == ExecutionResultV1::OomKilled,
    }
}

fn read_resources(cgroup_directory: Option<&Path>) -> ExecutionResourceUsageV1 {
    let Some(directory) = cgroup_directory else {
        return ExecutionResourceUsageV1::default();
    };
    ExecutionResourceUsageV1 {
        cpu_usage_usec: read_bounded_text(&directory.join("cpu.stat"))
            .ok()
            .and_then(|text| parse_keyed_u64(&text, "usage_usec")),
        memory_peak_bytes: read_bounded_text(&directory.join("memory.peak"))
            .ok()
            .and_then(|text| parse_single_u64(&text)),
        memory_events: read_bounded_text(&directory.join("memory.events"))
            .ok()
            .and_then(|text| parse_memory_events(&text)),
        io: read_bounded_text(&directory.join("io.stat"))
            .ok()
            .and_then(|text| parse_io_stat(&text)),
        tasks_peak: read_bounded_text(&directory.join("pids.peak"))
            .ok()
            .and_then(|text| parse_single_u64(&text)),
    }
}

fn resolve_cgroup_directory(
    proc_cgroup_path: &Path,
    cgroup_root: &Path,
) -> Result<PathBuf, ExecutionReceiptRuntimeError> {
    let text = read_bounded_text(proc_cgroup_path)?;
    let relative = text
        .lines()
        .find_map(|line| {
            let mut fields = line.splitn(3, ':');
            match (fields.next(), fields.next(), fields.next()) {
                (Some("0"), Some(""), Some(path)) => Some(path),
                _ => None,
            }
        })
        .ok_or(ExecutionReceiptRuntimeError::InvalidCgroupPath)?;
    let path = Path::new(relative);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(ExecutionReceiptRuntimeError::InvalidCgroupPath);
    }
    let stripped = path
        .strip_prefix("/")
        .map_err(|_| ExecutionReceiptRuntimeError::InvalidCgroupPath)?;
    Ok(cgroup_root.join(stripped))
}

fn parse_keyed_u64(input: &str, key: &str) -> Option<u64> {
    input.lines().find_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        (fields.next() == Some(key))
            .then(|| fields.next()?.parse::<u64>().ok())
            .flatten()
    })
}

fn parse_single_u64(input: &str) -> Option<u64> {
    let value = input.trim();
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse::<u64>().ok())
        .flatten()
}

fn parse_memory_events(input: &str) -> Option<ExecutionMemoryEventsV1> {
    let values = parse_key_value_lines(input)?;
    Some(ExecutionMemoryEventsV1 {
        low: *values.get("low")?,
        high: *values.get("high")?,
        max: *values.get("max")?,
        oom: *values.get("oom")?,
        oom_kill: *values.get("oom_kill")?,
        oom_group_kill: values.get("oom_group_kill").copied().unwrap_or(0),
    })
}

fn parse_key_value_lines(input: &str) -> Option<BTreeMap<&str, u64>> {
    let mut values = BTreeMap::new();
    for line in input.lines() {
        let mut fields = line.split_ascii_whitespace();
        let key = fields.next()?;
        let value = fields.next()?.parse::<u64>().ok()?;
        if fields.next().is_some() || values.insert(key, value).is_some() {
            return None;
        }
    }
    Some(values)
}

fn parse_io_stat(input: &str) -> Option<ExecutionIoUsageV1> {
    let mut usage = ExecutionIoUsageV1 {
        read_bytes: 0,
        write_bytes: 0,
        read_operations: 0,
        write_operations: 0,
    };
    let mut rows = 0_usize;
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let device = fields.next()?;
        if !device.contains(':') {
            return None;
        }
        let mut row = BTreeMap::new();
        for field in fields {
            let (key, value) = field.split_once('=')?;
            if row.insert(key, value.parse::<u64>().ok()?).is_some() {
                return None;
            }
        }
        usage.read_bytes = usage.read_bytes.checked_add(*row.get("rbytes")?)?;
        usage.write_bytes = usage.write_bytes.checked_add(*row.get("wbytes")?)?;
        usage.read_operations = usage.read_operations.checked_add(*row.get("rios")?)?;
        usage.write_operations = usage.write_operations.checked_add(*row.get("wios")?)?;
        rows = rows.saturating_add(1);
    }
    (rows > 0).then_some(usage)
}

fn valid_signal(signal: &str) -> bool {
    !signal.is_empty()
        && signal.len() <= 32
        && signal
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_step_id(step_id: &str) -> bool {
    !step_id.is_empty()
        && step_id.len() <= 96
        && step_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn directory_size(path: &Path) -> Result<u64, ExecutionReceiptRuntimeError> {
    let mut total = 0_u64;
    let mut entries = 0_usize;
    let mut pending = vec![(path.to_path_buf(), 0_usize)];
    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_DIRECTORY_DEPTH {
            return Err(ExecutionReceiptRuntimeError::DirectoryMeasurementBound);
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            entries = entries.saturating_add(1);
            if entries > MAX_DIRECTORY_ENTRIES {
                return Err(ExecutionReceiptRuntimeError::DirectoryMeasurementBound);
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(ExecutionReceiptRuntimeError::UnsafeReceiptPath);
            }
            if metadata.is_dir() {
                pending.push((entry.path(), depth.saturating_add(1)));
            } else if metadata.is_file() {
                total = total
                    .checked_add(metadata.len())
                    .ok_or(ExecutionReceiptRuntimeError::DirectoryMeasurementBound)?;
            }
        }
    }
    Ok(total)
}

fn read_bounded_text(path: &Path) -> Result<String, ExecutionReceiptRuntimeError> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_CGROUP_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > usize::try_from(MAX_CGROUP_FILE_BYTES).unwrap_or(usize::MAX) {
        return Err(ExecutionReceiptRuntimeError::CgroupMeasurementTooLarge);
    }
    String::from_utf8(bytes).map_err(|_| ExecutionReceiptRuntimeError::InvalidCgroupMeasurement)
}

fn read_owner_only_file(
    path: &Path,
    required_uid: u32,
) -> Result<Vec<u8>, ExecutionReceiptRuntimeError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.uid() != required_uid
        || path_metadata.mode() & 0o077 != 0
        || path_metadata.len() == 0
        || path_metadata.len() > MAX_RECEIPT_FILE_BYTES
    {
        return Err(ExecutionReceiptRuntimeError::UnsafeReceiptPath);
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(ExecutionReceiptRuntimeError::ReceiptPathChanged);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.take(MAX_RECEIPT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != opened_metadata.len()
    {
        return Err(ExecutionReceiptRuntimeError::ReceiptPathChanged);
    }
    Ok(bytes)
}

fn write_owner_only_new(
    path: &Path,
    required_uid: u32,
    bytes: &[u8],
    conflict: ExecutionReceiptRuntimeError,
) -> Result<(), ExecutionReceiptRuntimeError> {
    if bytes.is_empty() || bytes.len() > usize::try_from(MAX_RECEIPT_FILE_BYTES).unwrap_or(0) {
        return Err(ExecutionReceiptRuntimeError::ReceiptTooLarge);
    }
    validate_private_directory(
        path.parent()
            .ok_or(ExecutionReceiptRuntimeError::UnsafeReceiptPath)?,
        required_uid,
    )?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Err(conflict),
        Err(error) => return Err(error.into()),
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != required_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(ExecutionReceiptRuntimeError::UnsafeReceiptPath);
    }
    Ok(())
}

fn validate_private_directory(
    path: &Path,
    required_uid: u32,
) -> Result<(), ExecutionReceiptRuntimeError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || path_metadata.uid() != required_uid
        || path_metadata.mode() & 0o077 != 0
    {
        return Err(ExecutionReceiptRuntimeError::UnsafeReceiptPath);
    }
    let directory = File::open(path)?;
    let opened_metadata = directory.metadata()?;
    let final_metadata = fs::symlink_metadata(path)?;
    if final_metadata.file_type().is_symlink()
        || path_metadata.dev() != opened_metadata.dev()
        || path_metadata.ino() != opened_metadata.ino()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
    {
        return Err(ExecutionReceiptRuntimeError::ReceiptPathChanged);
    }
    Ok(())
}

fn sync_directory(path: &Path, required_uid: u32) -> Result<(), ExecutionReceiptRuntimeError> {
    validate_private_directory(path, required_uid)?;
    File::open(path)?.sync_all()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionReceiptRuntimeError {
    #[error("execution receipt filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("execution receipt JSON/JCS encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("fixed adapter authorization for an execution receipt is invalid: {0}")]
    Phase6(#[from] Phase6ContractError),
    #[error(transparent)]
    Receipt(#[from] ExecutionReceiptError),
    #[error("execution start evidence already exists and requires reconciliation")]
    ExecutionAlreadyStarted,
    #[error("execution start evidence is invalid")]
    InvalidStartEvidence,
    #[error("execution termination intent is invalid")]
    InvalidTerminationIntent,
    #[error("execution termination intent already exists")]
    TerminationIntentAlreadyExists,
    #[error("execution terminal receipt already exists")]
    TerminalReceiptAlreadyExists,
    #[error("execution terminal receipt conflicts with the authorized request")]
    TerminalReceiptConflict,
    #[error("execution cleanup receipt already exists")]
    CleanupReceiptAlreadyExists,
    #[error("execution cleanup receipt conflicts with the terminal receipt")]
    CleanupReceiptConflict,
    #[error("execution receipt path is not a stable owner-only file or directory")]
    UnsafeReceiptPath,
    #[error("execution receipt path changed while it was being validated")]
    ReceiptPathChanged,
    #[error("execution receipt exceeds its size bound")]
    ReceiptTooLarge,
    #[error("execution directory measurement exceeded its traversal bound")]
    DirectoryMeasurementBound,
    #[error("the unified cgroup path is invalid")]
    InvalidCgroupPath,
    #[error("a cgroup measurement exceeds its size bound")]
    CgroupMeasurementTooLarge,
    #[error("a cgroup measurement is not valid UTF-8")]
    InvalidCgroupMeasurement,
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tempfile::tempdir;

    use super::*;
    use crate::phase6::tests::test_bootstrap_phase_spec;

    #[test]
    fn parses_cgroup_v2_resource_files_without_accepting_partial_rows() {
        assert_eq!(
            parse_keyed_u64("usage_usec 42\nuser_usec 10\n", "usage_usec"),
            Some(42)
        );
        assert_eq!(parse_single_u64("4096\n"), Some(4096));
        assert_eq!(
            parse_memory_events("low 1\nhigh 2\nmax 3\noom 4\noom_kill 5\noom_group_kill 6\n"),
            Some(ExecutionMemoryEventsV1 {
                low: 1,
                high: 2,
                max: 3,
                oom: 4,
                oom_kill: 5,
                oom_group_kill: 6,
            })
        );
        assert_eq!(
            parse_io_stat(
                "8:0 rbytes=10 wbytes=20 rios=1 wios=2 dbytes=0 dios=0\n8:1 rbytes=30 wbytes=40 rios=3 wios=4\n"
            ),
            Some(ExecutionIoUsageV1 {
                read_bytes: 40,
                write_bytes: 60,
                read_operations: 4,
                write_operations: 6,
            })
        );
        assert_eq!(parse_io_stat("8:0 rbytes=10 wbytes=20 rios=1\n"), None);
    }

    #[test]
    fn classifies_exit_timeout_oom_and_cancellation_truthfully() {
        let failed = classify_process(
            &CaptureEnvironmentV1 {
                service_result: Some("exit-code".to_owned()),
                exit_code: Some("exited".to_owned()),
                exit_status: Some("7".to_owned()),
            },
            None,
            &ExecutionResourceUsageV1::default(),
        );
        assert_eq!(failed.result, ExecutionResultV1::Failed);
        assert_eq!(failed.exit_code, Some(7));

        let timed_out = classify_process(
            &CaptureEnvironmentV1 {
                service_result: Some("timeout".to_owned()),
                ..CaptureEnvironmentV1::default()
            },
            None,
            &ExecutionResourceUsageV1::default(),
        );
        assert_eq!(timed_out.result, ExecutionResultV1::TimedOut);

        let resources = ExecutionResourceUsageV1 {
            memory_events: Some(ExecutionMemoryEventsV1 {
                oom_kill: 1,
                ..ExecutionMemoryEventsV1::default()
            }),
            ..ExecutionResourceUsageV1::default()
        };
        let oom = classify_process(&CaptureEnvironmentV1::default(), None, &resources);
        assert_eq!(oom.result, ExecutionResultV1::OomKilled);

        let start_digest = EvidenceDigest::sha256("start");
        let cancelled = classify_process(
            &CaptureEnvironmentV1::default(),
            Some(&ExecutionTerminationIntentV1 {
                schema_version: TERMINATION_INTENT_SCHEMA_VERSION,
                attempt_id: Uuid::new_v4(),
                kind: ExecutionTerminationKindV1::Cancelled,
                recorded_at_ms: 1,
                intent_digest: start_digest,
            }),
            &ExecutionResourceUsageV1::default(),
        );
        assert_eq!(cancelled.result, ExecutionResultV1::Cancelled);
    }

    #[test]
    fn captures_terminal_cgroup_evidence_before_cleanup_and_replays_it() {
        let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let job = temp.path().join("job");
        fs::create_dir(&job).unwrap_or_else(|error| panic!("job directory: {error}"));
        fs::set_permissions(&job, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("job permissions: {error}"));
        let uid = fs::metadata(&job)
            .unwrap_or_else(|error| panic!("job metadata: {error}"))
            .uid();
        let spec = test_bootstrap_phase_spec();
        let request = spec
            .fixed_adapter_request(1)
            .unwrap_or_else(|error| panic!("request: {error}"));
        write_private(
            &job.join(SPEC_FILE_NAME),
            &spec
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("spec bytes: {error}")),
        );
        write_private(
            &job.join(REQUEST_FILE_NAME),
            &request
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("request bytes: {error}")),
        );
        materialize_execution_start(&job, uid, &request, 1_000)
            .unwrap_or_else(|error| panic!("start: {error}"));

        let proc_cgroup = temp.path().join("proc-self-cgroup");
        fs::write(&proc_cgroup, "0::/system.slice/test.service\n")
            .unwrap_or_else(|error| panic!("proc cgroup: {error}"));
        let cgroup = temp.path().join("cgroup/system.slice/test.service");
        fs::create_dir_all(&cgroup).unwrap_or_else(|error| panic!("cgroup: {error}"));
        fs::write(
            cgroup.join("cpu.stat"),
            "usage_usec 42000\nuser_usec 12000\n",
        )
        .unwrap_or_else(|error| panic!("cpu: {error}"));
        fs::write(cgroup.join("memory.peak"), "134217728\n")
            .unwrap_or_else(|error| panic!("memory peak: {error}"));
        fs::write(
            cgroup.join("memory.events"),
            "low 0\nhigh 1\nmax 2\noom 0\noom_kill 0\noom_group_kill 0\n",
        )
        .unwrap_or_else(|error| panic!("memory events: {error}"));
        fs::write(
            cgroup.join("io.stat"),
            "8:0 rbytes=10 wbytes=20 rios=1 wios=2\n",
        )
        .unwrap_or_else(|error| panic!("io: {error}"));
        fs::write(cgroup.join("pids.peak"), "7\n").unwrap_or_else(|error| panic!("pids: {error}"));

        let environment = CaptureEnvironmentV1 {
            service_result: Some("success".to_owned()),
            exit_code: Some("exited".to_owned()),
            exit_status: Some("0".to_owned()),
        };
        let terminal = capture_terminal_receipt_in(
            &job,
            uid,
            &environment,
            &proc_cgroup,
            &temp.path().join("cgroup"),
            1_250,
        )
        .unwrap_or_else(|error| panic!("terminal: {error}"));
        assert_eq!(terminal.process.result, ExecutionResultV1::Succeeded);
        assert_eq!(terminal.resources.cpu_usage_usec, Some(42_000));
        assert_eq!(terminal.resources.memory_peak_bytes, Some(134_217_728));
        assert_eq!(terminal.resources.tasks_peak, Some(7));
        assert!(job.join(EXECUTION_TERMINAL_FILE_NAME).is_file());
        assert!(!job.join(EXECUTION_CLEANUP_FILE_NAME).exists());
        assert_eq!(
            fs::metadata(job.join(EXECUTION_TERMINAL_FILE_NAME))
                .unwrap_or_else(|error| panic!("terminal metadata: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let replay = capture_terminal_receipt_in(
            &job,
            uid,
            &environment,
            &proc_cgroup,
            &temp.path().join("cgroup"),
            9_999,
        )
        .unwrap_or_else(|error| panic!("terminal replay: {error}"));
        assert_eq!(replay, terminal);

        let cleanup = materialize_cleanup_receipt(&job, uid, &terminal, true, None, 1_260)
            .unwrap_or_else(|error| panic!("cleanup: {error}"));
        assert_eq!(cleanup.state, ExecutionCleanupStateV1::Complete);
        assert!(job.join(EXECUTION_CLEANUP_FILE_NAME).is_file());

        assert_start_substitution_rejected(&job, uid, &spec);
    }

    fn assert_start_substitution_rejected(job: &Path, uid: u32, spec: &AuthorizedPhaseSpecV1) {
        let mut substituted = read_start(job, uid)
            .unwrap_or_else(|error| panic!("read start for substitution: {error}"));
        substituted.scratch_before_bytes = Some(999_999);
        substituted.evidence_digest = substituted
            .calculate_digest()
            .unwrap_or_else(|error| panic!("substituted start digest: {error}"));
        write_private(
            &job.join(EXECUTION_START_FILE_NAME),
            &substituted
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("substituted start bytes: {error}")),
        );
        assert!(matches!(
            read_terminal_receipt(job, uid, spec, 1),
            Err(ExecutionReceiptRuntimeError::TerminalReceiptConflict)
        ));
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("permissions {}: {error}", path.display()));
    }
}
