use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{FAILURE_CAPSULE_CAP_BYTES, Redactor, Retryability, RunbookId, truncate_utf8};

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
pub struct FailureCapsule {
    pub schema_version: u16,
    pub failing_step: String,
    pub error: StructuredError,
    pub excerpt: String,
    pub truncated: bool,
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
            "\n[FAILURE CAPSULE TRUNCATED]",
        );
        Self {
            schema_version: 1,
            failing_step: failing_step.into(),
            error,
            truncated: excerpt.len() < redacted.len(),
            excerpt,
        }
    }
}
