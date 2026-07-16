use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::DashboardSnapshot;

pub const EVENT_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub version: u16,
    pub sequence: u64,
    pub emitted_at_ms: i64,
    pub event: DashboardEvent,
}

impl EventEnvelope {
    pub fn validate(&self) -> Result<(), EventValidationError> {
        if self.version != EVENT_PROTOCOL_VERSION {
            return Err(EventValidationError::UnsupportedVersion(self.version));
        }
        if self.sequence == 0 {
            return Err(EventValidationError::ZeroSequence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum DashboardEvent {
    Snapshot(Box<DashboardSnapshot>),
    ResyncRequired {
        requested_after: Option<u64>,
        oldest_available: u64,
        latest_available: u64,
        reason: ResyncReason,
    },
}

impl DashboardEvent {
    pub const fn event_name(&self) -> &'static str {
        match self {
            Self::Snapshot(_) => "snapshot",
            Self::ResyncRequired { .. } => "resync_required",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResyncReason {
    HistoryUnavailable,
    SubscriberLagged,
    InvalidLastEventId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EventValidationError {
    #[error("unsupported event protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("event sequence must be non-zero")]
    ZeroSequence,
}
