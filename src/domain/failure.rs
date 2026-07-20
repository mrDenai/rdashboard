use std::fmt::Write as _;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    EvidenceDigest, ExecutionEvidenceGapV1, ExecutionProcessOutcomeV1, ExecutionResourceUsageV1,
    ExecutionStorageUsageV1, FAILURE_CAPSULE_CAP_BYTES, GitCommitId, OperationPhase, ProjectId,
    Redactor, Retryability, RunbookId, expected_execution_gaps, truncate_utf8,
};

pub const FAILURE_CAPSULE_V1_SCHEMA_VERSION: u16 = 1;
pub const FAILURE_CAPSULE_V2_SCHEMA_VERSION: u16 = 2;
pub const FAILURE_CAPSULE_RENDER_TEMPLATE_VERSION: u16 = 1;
const MAX_CODE_BYTES: usize = 96;
const MAX_WORKFLOW_KIND_BYTES: usize = 96;
const MAX_STEP_ID_BYTES: usize = 96;
const MAX_STEP_DISPLAY_BYTES: usize = 160;
const MAX_SUMMARY_BYTES: usize = 1_024;
const MAX_CAUSE_BYTES: usize = 4 * 1_024;
const MAX_CONTEXT_SUMMARY_BYTES: usize = 2 * 1_024;
const MAX_ARTIFACTS: usize = 32;
const MAX_CONTEXT_EVENTS: usize = 24;
const FAILURE_CAPSULE_TRUNCATED: &str = "\n[FAILURE CAPSULE TRUNCATED]";
const FAILURE_RENDER_TRUNCATED: &str = "\n\n[FAILURE RENDER TRUNCATED]";

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredError {
    pub code: String,
    pub summary: String,
    pub retryability: Retryability,
    pub runbook_id: Option<RunbookId>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureArtifactV2 {
    pub kind: String,
    pub digest: EvidenceDigest,
    pub size_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureContextRelationV2 {
    Before,
    Cause,
    After,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureContextEventV2 {
    pub at_ms: i64,
    pub relation: FailureContextRelationV2,
    pub kind: String,
    pub summary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureRawLogReferenceV2 {
    pub redacted_log_digest: EvidenceDigest,
    pub compressed_size_bytes: u64,
    pub retained_until_ms: i64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureRedactionEvidenceV2 {
    pub ruleset_digest: EvidenceDigest,
    pub replacement_count: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionMutationStateV2 {
    NotStarted,
    Started,
    Completed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureRollbackStateV2 {
    NotRequired,
    Eligible,
    Started,
    Succeeded,
    Failed,
    Unknown,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FailureContextGapV2 {
    RawLog,
    TerminalReceipt,
    CleanupReceipt,
    PreviousRelease,
    AttemptedRelease,
    HealthEvidence,
}

impl FailureContextGapV2 {
    const fn label(self) -> &'static str {
        match self {
            Self::RawLog => "raw_log",
            Self::TerminalReceipt => "terminal_receipt",
            Self::CleanupReceipt => "cleanup_receipt",
            Self::PreviousRelease => "previous_release",
            Self::AttemptedRelease => "attempted_release",
            Self::HealthEvidence => "health_evidence",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureCapsuleV2Evidence {
    pub failure_id: Uuid,
    pub project_id: ProjectId,
    pub workflow_kind: String,
    pub source_sha: Option<GitCommitId>,
    pub policy_digest: Option<EvidenceDigest>,
    pub request_id: Uuid,
    pub operation_id: Uuid,
    pub attempt_id: Uuid,
    pub phase: OperationPhase,
    pub step_id: String,
    pub step_display_name: String,
    pub started_at_ms: i64,
    pub failed_at_ms: i64,
    pub duration_ms: u64,
    pub first_cause: String,
    pub process: ExecutionProcessOutcomeV1,
    pub resources: ExecutionResourceUsageV1,
    pub storage: ExecutionStorageUsageV1,
    pub execution_gaps: Vec<ExecutionEvidenceGapV1>,
    pub artifacts: Vec<FailureArtifactV2>,
    pub context: Vec<FailureContextEventV2>,
    pub raw_log: Option<FailureRawLogReferenceV2>,
    pub redaction: FailureRedactionEvidenceV2,
    pub previous_release_digest: Option<EvidenceDigest>,
    pub attempted_release_digest: Option<EvidenceDigest>,
    pub health_evidence_digest: Option<EvidenceDigest>,
    pub terminal_receipt_digest: Option<EvidenceDigest>,
    pub cleanup_receipt_digest: Option<EvidenceDigest>,
    pub context_gaps: Vec<FailureContextGapV2>,
    pub production_mutation: ProductionMutationStateV2,
    pub rollback: FailureRollbackStateV2,
    pub render_template_version: u16,
}

#[derive(Clone, Debug)]
pub struct FailureCapsuleV2Input {
    pub failure_id: Uuid,
    pub project_id: ProjectId,
    pub workflow_kind: String,
    pub source_sha: Option<GitCommitId>,
    pub policy_digest: Option<EvidenceDigest>,
    pub request_id: Uuid,
    pub operation_id: Uuid,
    pub attempt_id: Uuid,
    pub phase: OperationPhase,
    pub step_id: String,
    pub step_display_name: String,
    pub started_at_ms: i64,
    pub failed_at_ms: i64,
    pub error: StructuredError,
    pub first_cause: String,
    pub raw_excerpt: String,
    pub process: ExecutionProcessOutcomeV1,
    pub resources: ExecutionResourceUsageV1,
    pub storage: ExecutionStorageUsageV1,
    pub artifacts: Vec<FailureArtifactV2>,
    pub context: Vec<FailureContextEventV2>,
    pub raw_log: Option<FailureRawLogReferenceV2>,
    pub previous_release_digest: Option<EvidenceDigest>,
    pub attempted_release_digest: Option<EvidenceDigest>,
    pub health_evidence_digest: Option<EvidenceDigest>,
    pub terminal_receipt_digest: Option<EvidenceDigest>,
    pub cleanup_receipt_digest: Option<EvidenceDigest>,
    pub production_mutation: ProductionMutationStateV2,
    pub rollback: FailureRollbackStateV2,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureCapsule {
    pub schema_version: u16,
    pub failing_step: String,
    pub error: StructuredError,
    pub excerpt: String,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v2: Option<FailureCapsuleV2Evidence>,
}

impl FailureCapsuleV2Evidence {
    fn validate(&self) -> Result<(), FailureCapsuleError> {
        if self.failure_id.is_nil()
            || self.request_id.is_nil()
            || self.operation_id.is_nil()
            || self.attempt_id.is_nil()
            || !valid_token(&self.workflow_kind, MAX_WORKFLOW_KIND_BYTES)
            || !valid_token(&self.step_id, MAX_STEP_ID_BYTES)
            || !valid_text(&self.step_display_name, MAX_STEP_DISPLAY_BYTES)
            || !valid_text(&self.first_cause, MAX_CAUSE_BYTES)
            || self.started_at_ms < 0
            || self.failed_at_ms < self.started_at_ms
            || self.duration_ms
                != u64::try_from(self.failed_at_ms - self.started_at_ms)
                    .map_err(|_| FailureCapsuleError::InvalidDocument)?
            || self.render_template_version != FAILURE_CAPSULE_RENDER_TEMPLATE_VERSION
        {
            return Err(FailureCapsuleError::InvalidDocument);
        }
        self.process
            .validate()
            .map_err(|_| FailureCapsuleError::InvalidDocument)?;
        self.storage
            .validate()
            .map_err(|_| FailureCapsuleError::InvalidDocument)?;
        if self.execution_gaps
            != expected_execution_gaps(&self.process, &self.resources, &self.storage)
        {
            return Err(FailureCapsuleError::InvalidDocument);
        }
        if self.artifacts.len() > MAX_ARTIFACTS
            || !self
                .artifacts
                .windows(2)
                .all(|pair| (&pair[0].kind, &pair[0].digest) < (&pair[1].kind, &pair[1].digest))
            || self
                .artifacts
                .iter()
                .any(|artifact| !valid_token(&artifact.kind, MAX_CODE_BYTES))
        {
            return Err(FailureCapsuleError::InvalidDocument);
        }
        if self.context.len() > MAX_CONTEXT_EVENTS
            || !self
                .context
                .windows(2)
                .all(|pair| (pair[0].at_ms, &pair[0].kind) <= (pair[1].at_ms, &pair[1].kind))
            || self.context.iter().any(|event| {
                event.at_ms < 0
                    || !valid_token(&event.kind, MAX_CODE_BYTES)
                    || !valid_text(&event.summary, MAX_CONTEXT_SUMMARY_BYTES)
            })
        {
            return Err(FailureCapsuleError::InvalidDocument);
        }
        if self.raw_log.as_ref().is_some_and(|reference| {
            reference.compressed_size_bytes == 0 || reference.retained_until_ms < self.failed_at_ms
        }) {
            return Err(FailureCapsuleError::InvalidDocument);
        }
        if self.context_gaps != expected_context_gaps(self) {
            return Err(FailureCapsuleError::InvalidDocument);
        }
        Ok(())
    }
}

impl FailureCapsule {
    pub fn from_raw(
        failing_step: impl Into<String>,
        error: StructuredError,
        raw_excerpt: &str,
        redactor: &Redactor,
    ) -> Self {
        let redacted = redactor.redact(raw_excerpt);
        let excerpt = truncate_utf8(
            &redacted,
            FAILURE_CAPSULE_CAP_BYTES,
            FAILURE_CAPSULE_TRUNCATED,
        );
        Self {
            schema_version: FAILURE_CAPSULE_V1_SCHEMA_VERSION,
            failing_step: failing_step.into(),
            error,
            truncated: excerpt.len() < redacted.len(),
            excerpt,
            v2: None,
        }
    }

    pub fn from_v2_raw(
        input: FailureCapsuleV2Input,
        redactor: &Redactor,
    ) -> Result<Self, FailureCapsuleError> {
        let mut replacement_count = 0_u64;

        let mut error = input.error;
        let (summary, replacements) = redact_bounded(redactor, &error.summary, MAX_SUMMARY_BYTES);
        error.summary = summary;
        replacement_count = replacement_count.saturating_add(replacements);
        let (step_display_name, replacements) =
            redact_bounded(redactor, &input.step_display_name, MAX_STEP_DISPLAY_BYTES);
        replacement_count = replacement_count.saturating_add(replacements);
        let (first_cause, replacements) =
            redact_bounded(redactor, &input.first_cause, MAX_CAUSE_BYTES);
        replacement_count = replacement_count.saturating_add(replacements);
        let redacted_excerpt = redactor.redact_with_evidence(&input.raw_excerpt);
        replacement_count = replacement_count.saturating_add(redacted_excerpt.replacement_count);
        let excerpt = truncate_utf8(
            &redacted_excerpt.text,
            FAILURE_CAPSULE_CAP_BYTES,
            FAILURE_CAPSULE_TRUNCATED,
        );
        let truncated = excerpt.len() < redacted_excerpt.text.len();

        let mut context = input.context;
        for event in &mut context {
            let (summary, replacements) =
                redact_bounded(redactor, &event.summary, MAX_CONTEXT_SUMMARY_BYTES);
            event.summary = summary;
            replacement_count = replacement_count.saturating_add(replacements);
        }
        context.sort_by(|left, right| (left.at_ms, &left.kind).cmp(&(right.at_ms, &right.kind)));
        let mut artifacts = input.artifacts;
        artifacts
            .sort_by(|left, right| (&left.kind, &left.digest).cmp(&(&right.kind, &right.digest)));

        let duration_ms = input
            .failed_at_ms
            .checked_sub(input.started_at_ms)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(FailureCapsuleError::InvalidDocument)?;
        let execution_gaps =
            expected_execution_gaps(&input.process, &input.resources, &input.storage);
        let mut evidence = FailureCapsuleV2Evidence {
            failure_id: input.failure_id,
            project_id: input.project_id,
            workflow_kind: input.workflow_kind,
            source_sha: input.source_sha,
            policy_digest: input.policy_digest,
            request_id: input.request_id,
            operation_id: input.operation_id,
            attempt_id: input.attempt_id,
            phase: input.phase,
            step_id: input.step_id,
            step_display_name,
            started_at_ms: input.started_at_ms,
            failed_at_ms: input.failed_at_ms,
            duration_ms,
            first_cause,
            process: input.process,
            resources: input.resources,
            storage: input.storage,
            execution_gaps,
            artifacts,
            context,
            raw_log: input.raw_log,
            redaction: FailureRedactionEvidenceV2 {
                ruleset_digest: redactor.ruleset_digest(),
                replacement_count,
            },
            previous_release_digest: input.previous_release_digest,
            attempted_release_digest: input.attempted_release_digest,
            health_evidence_digest: input.health_evidence_digest,
            terminal_receipt_digest: input.terminal_receipt_digest,
            cleanup_receipt_digest: input.cleanup_receipt_digest,
            context_gaps: Vec::new(),
            production_mutation: input.production_mutation,
            rollback: input.rollback,
            render_template_version: FAILURE_CAPSULE_RENDER_TEMPLATE_VERSION,
        };
        evidence.context_gaps = expected_context_gaps(&evidence);
        let mut capsule = Self {
            schema_version: FAILURE_CAPSULE_V2_SCHEMA_VERSION,
            failing_step: evidence.step_id.clone(),
            error,
            excerpt,
            truncated,
            v2: Some(evidence),
        };
        capsule.validate()?;
        let initial_bytes = serde_jcs::to_vec(&capsule)?;
        if initial_bytes.len() > FAILURE_CAPSULE_CAP_BYTES {
            let excess = initial_bytes.len() - FAILURE_CAPSULE_CAP_BYTES;
            let excerpt_cap = capsule.excerpt.len().saturating_sub(excess);
            capsule.excerpt =
                truncate_utf8(&capsule.excerpt, excerpt_cap, FAILURE_CAPSULE_TRUNCATED);
            capsule.truncated = true;
            capsule.validate()?;
            if serde_jcs::to_vec(&capsule)?.len() > FAILURE_CAPSULE_CAP_BYTES {
                return Err(FailureCapsuleError::CapsuleTooLarge);
            }
        }
        Ok(capsule)
    }

    pub fn validate(&self) -> Result<(), FailureCapsuleError> {
        if !valid_text(&self.failing_step, MAX_STEP_ID_BYTES)
            || !valid_text(&self.error.code, MAX_CODE_BYTES)
            || !valid_text(&self.error.summary, MAX_SUMMARY_BYTES)
            || self.excerpt.len() > FAILURE_CAPSULE_CAP_BYTES
        {
            return Err(FailureCapsuleError::InvalidDocument);
        }
        match (self.schema_version, &self.v2) {
            (FAILURE_CAPSULE_V1_SCHEMA_VERSION, None) => Ok(()),
            (FAILURE_CAPSULE_V2_SCHEMA_VERSION, Some(evidence)) => {
                evidence.validate()?;
                if self.failing_step != evidence.step_id
                    || !valid_token(&self.failing_step, MAX_STEP_ID_BYTES)
                    || !valid_token(&self.error.code, MAX_CODE_BYTES)
                {
                    return Err(FailureCapsuleError::InvalidDocument);
                }
                Ok(())
            }
            _ => Err(FailureCapsuleError::InvalidDocument),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FailureCapsuleError> {
        self.validate()?;
        let bytes = serde_jcs::to_vec(self)?;
        if self.schema_version == FAILURE_CAPSULE_V2_SCHEMA_VERSION
            && bytes.len() > FAILURE_CAPSULE_CAP_BYTES
        {
            return Err(FailureCapsuleError::CapsuleTooLarge);
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FailureCapsuleError> {
        let capsule: Self = serde_json::from_slice(bytes)?;
        if capsule.canonical_bytes()? != bytes {
            return Err(FailureCapsuleError::InvalidDocument);
        }
        Ok(capsule)
    }

    pub fn render_markdown(&self) -> Result<String, FailureCapsuleError> {
        self.validate()?;
        let mut output = String::new();
        let _ = writeln!(output, "# Failure: {}", inline_text(&self.error.summary));
        if let Some(v2) = &self.v2 {
            let _ = writeln!(output, "\nCause: {}", inline_text(&v2.first_cause));
            let _ = writeln!(
                output,
                "\n- Step: `{}` ({})",
                v2.step_id,
                inline_text(&v2.step_display_name)
            );
            let _ = writeln!(output, "- Phase: `{:?}`", v2.phase);
            let _ = writeln!(output, "- Result: `{:?}`", v2.process.result);
            let _ = writeln!(output, "- Duration: {} ms", v2.duration_ms);
            let _ = writeln!(output, "- Retry: `{:?}`", self.error.retryability);
            let _ = writeln!(
                output,
                "- Production mutation: `{:?}`",
                v2.production_mutation
            );
            let _ = writeln!(output, "- Rollback: `{:?}`", v2.rollback);
            output.push_str("\n## Resource evidence\n");
            render_optional(&mut output, "CPU", v2.resources.cpu_usage_usec, "us");
            render_optional(
                &mut output,
                "Memory peak",
                v2.resources.memory_peak_bytes,
                "bytes",
            );
            render_optional(&mut output, "Task peak", v2.resources.tasks_peak, "tasks");
            render_optional(
                &mut output,
                "Scratch after",
                v2.storage.scratch_after_bytes,
                "bytes",
            );
            render_reserve(&mut output, &v2.storage);
            if !v2.execution_gaps.is_empty() || !v2.context_gaps.is_empty() {
                output.push_str("\n## Evidence gaps\n");
                for gap in &v2.execution_gaps {
                    let _ = writeln!(output, "- `{}`", gap.label());
                }
                for gap in &v2.context_gaps {
                    let _ = writeln!(output, "- `{}`", gap.label());
                }
            }
            if !v2.artifacts.is_empty() {
                output.push_str("\n## Artifacts\n");
                for artifact in &v2.artifacts {
                    let _ = writeln!(
                        output,
                        "- `{}`: `{}` ({} bytes)",
                        artifact.kind, artifact.digest, artifact.size_bytes
                    );
                }
            }
            if !v2.context.is_empty() {
                output.push_str("\n## Nearby events\n");
                for event in &v2.context {
                    let _ = writeln!(
                        output,
                        "- {} `{:?}` `{}`: {}",
                        event.at_ms,
                        event.relation,
                        event.kind,
                        inline_text(&event.summary)
                    );
                }
            }
        } else {
            output.push_str(
                "\nLegacy capsule (v1): terminal resource, cleanup, release, and context evidence were not recorded.\n",
            );
            let _ = writeln!(output, "\n- Step: `{}`", inline_text(&self.failing_step));
            let _ = writeln!(output, "- Retry: `{:?}`", self.error.retryability);
        }
        output.push_str("\n## Redacted excerpt\n");
        for line in safe_block_text(&self.excerpt).lines() {
            let _ = writeln!(output, "    {line}");
        }
        Ok(truncate_utf8(
            &output,
            FAILURE_CAPSULE_CAP_BYTES,
            FAILURE_RENDER_TRUNCATED,
        ))
    }
}

fn expected_context_gaps(evidence: &FailureCapsuleV2Evidence) -> Vec<FailureContextGapV2> {
    let mut gaps = Vec::new();
    if evidence.raw_log.is_none() {
        gaps.push(FailureContextGapV2::RawLog);
    }
    if evidence.terminal_receipt_digest.is_none() {
        gaps.push(FailureContextGapV2::TerminalReceipt);
    }
    if evidence.cleanup_receipt_digest.is_none() {
        gaps.push(FailureContextGapV2::CleanupReceipt);
    }
    if evidence.previous_release_digest.is_none() {
        gaps.push(FailureContextGapV2::PreviousRelease);
    }
    if evidence.attempted_release_digest.is_none() {
        gaps.push(FailureContextGapV2::AttemptedRelease);
    }
    if evidence.health_evidence_digest.is_none() {
        gaps.push(FailureContextGapV2::HealthEvidence);
    }
    gaps
}

fn render_optional(output: &mut String, label: &str, value: Option<u64>, unit: &str) {
    if let Some(value) = value {
        let _ = writeln!(output, "- {label}: {value} {unit}");
    }
}

fn render_reserve(output: &mut String, storage: &ExecutionStorageUsageV1) {
    render_optional(
        output,
        "Emergency reserve required",
        storage.emergency_reserve_required_bytes,
        "bytes",
    );
    render_optional(
        output,
        "Emergency reserve remaining",
        storage.emergency_reserve_remaining_bytes,
        "bytes",
    );
    render_optional(
        output,
        "Emergency reserve deficit",
        storage.emergency_reserve_deficit_bytes,
        "bytes",
    );
}

fn redact_bounded(redactor: &Redactor, value: &str, cap: usize) -> (String, u64) {
    let result = redactor.redact_with_evidence(value);
    (
        truncate_utf8(&result.text, cap, " [TRUNCATED]"),
        result.replacement_count,
    )
}

fn valid_token(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && value.chars().all(safe_text_character)
}

fn safe_text_character(character: char) -> bool {
    character == '\n' || character == '\t' || (!character.is_control() && character != '\u{7f}')
}

fn inline_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| safe_text_character(*character))
        .flat_map(|character| match character {
            '\n' | '\r' => " ".chars().collect::<Vec<_>>(),
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '#' => {
                vec!['\\', character]
            }
            _ => vec![character],
        })
        .collect()
}

fn safe_block_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| safe_text_character(*character))
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum FailureCapsuleError {
    #[error("failure capsule is structurally invalid")]
    InvalidDocument,
    #[error("failure capsule exceeds its canonical size bound")]
    CapsuleTooLarge,
    #[error("failure capsule canonical encoding failed")]
    CanonicalEncoding(#[from] serde_json::Error),
}
