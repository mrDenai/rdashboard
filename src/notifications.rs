use serde::{Deserialize, Serialize};

use crate::domain::{EvidenceDigest, ProjectId};

pub const NOTIFICATION_SCHEMA_VERSION: u16 = 1;
const MAX_EVENT_KEY_BYTES: usize = 128;
const MAX_NOTIFICATION_TEXT_BYTES: usize = 3_500;
const MAX_OCCURRENCE_KEY_BYTES: usize = 256;
const MAX_GATEWAY_PROJECT_BYTES: usize = 32;
const MAX_BROWSER_SAFE_TIMESTAMP: i64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKindV1 {
    ErrorPriorityChanged,
    ErrorCollectionFailed,
    ErrorCollectionRecovered,
    DependencyUpdateChanged,
    DependencyChecksFailed,
    DependencyChecksRecovered,
    DependencyCollectionFailed,
    DependencyCollectionRecovered,
    OperationStarted,
    OperationSucceeded,
    OperationFailed,
    BackupVerified,
    BackupFailed,
    DeploySucceeded,
    DeployRolledBack,
    DeployFailed,
    SourceSignalLost,
    SourceRecovered,
    ControllerFailed,
}

impl NotificationKindV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ErrorPriorityChanged => "error_priority_changed",
            Self::ErrorCollectionFailed => "error_collection_failed",
            Self::ErrorCollectionRecovered => "error_collection_recovered",
            Self::DependencyUpdateChanged => "dependency_update_changed",
            Self::DependencyChecksFailed => "dependency_checks_failed",
            Self::DependencyChecksRecovered => "dependency_checks_recovered",
            Self::DependencyCollectionFailed => "dependency_collection_failed",
            Self::DependencyCollectionRecovered => "dependency_collection_recovered",
            Self::OperationStarted => "operation_started",
            Self::OperationSucceeded => "operation_succeeded",
            Self::OperationFailed => "operation_failed",
            Self::BackupVerified => "backup_verified",
            Self::BackupFailed => "backup_failed",
            Self::DeploySucceeded => "deploy_succeeded",
            Self::DeployRolledBack => "deploy_rolled_back",
            Self::DeployFailed => "deploy_failed",
            Self::SourceSignalLost => "source_signal_lost",
            Self::SourceRecovered => "source_recovered",
            Self::ControllerFailed => "controller_failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationDeliveryStateV1 {
    Pending,
    Sending,
    DeliveryUnknown,
    RetryScheduled,
    Delivered,
    DeliveredPossibleDuplicate,
    PermanentlyFailed,
}

impl NotificationDeliveryStateV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sending => "sending",
            Self::DeliveryUnknown => "delivery_unknown",
            Self::RetryScheduled => "retry_scheduled",
            Self::Delivered => "delivered",
            Self::DeliveredPossibleDuplicate => "delivered_possible_duplicate",
            Self::PermanentlyFailed => "permanently_failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationRouteV1 {
    TelegramGateway,
}

impl NotificationRouteV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TelegramGateway => "telegram_gateway",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationDeliveryRecordV1 {
    pub schema_version: u16,
    pub event: NotificationEventV1,
    pub state: NotificationDeliveryStateV1,
    pub attempt_count: u32,
    pub route: Option<NotificationRouteV1>,
    pub provider_message_id: Option<uuid::Uuid>,
    pub last_error_code: Option<String>,
    pub retry_at_ms: i64,
    pub updated_at_ms: i64,
}

impl NotificationDeliveryRecordV1 {
    pub fn validate(&self) -> Result<(), NotificationContractError> {
        self.event.validate()?;
        if self.schema_version != NOTIFICATION_SCHEMA_VERSION
            || !(0..=MAX_BROWSER_SAFE_TIMESTAMP).contains(&self.retry_at_ms)
            || !(self.event.created_at_ms..=MAX_BROWSER_SAFE_TIMESTAMP)
                .contains(&self.updated_at_ms)
            || self
                .last_error_code
                .as_deref()
                .is_some_and(|code| !valid_error_code(code))
        {
            return Err(NotificationContractError::InvalidDeliveryRecord);
        }
        let valid_shape = match self.state {
            NotificationDeliveryStateV1::Pending => {
                self.attempt_count == 0
                    && self.route.is_none()
                    && self.provider_message_id.is_none()
                    && self.last_error_code.is_none()
                    && self.retry_at_ms == self.updated_at_ms
            }
            NotificationDeliveryStateV1::Sending => {
                self.attempt_count > 0
                    && self.route == Some(NotificationRouteV1::TelegramGateway)
                    && self.last_error_code.is_none()
            }
            NotificationDeliveryStateV1::DeliveryUnknown => {
                self.attempt_count > 0
                    && self.route == Some(NotificationRouteV1::TelegramGateway)
                    && self.provider_message_id.is_none()
                    && self.last_error_code.is_some()
                    && self.retry_at_ms > self.updated_at_ms
            }
            NotificationDeliveryStateV1::RetryScheduled => {
                self.attempt_count > 0
                    && self.route == Some(NotificationRouteV1::TelegramGateway)
                    && self.last_error_code.is_some()
                    && self.retry_at_ms > self.updated_at_ms
            }
            NotificationDeliveryStateV1::Delivered
            | NotificationDeliveryStateV1::DeliveredPossibleDuplicate => {
                self.attempt_count > 0
                    && self.route == Some(NotificationRouteV1::TelegramGateway)
                    && self.provider_message_id.is_some()
                    && self.last_error_code.is_none()
                    && self.retry_at_ms == self.updated_at_ms
            }
            NotificationDeliveryStateV1::PermanentlyFailed => {
                self.attempt_count > 0
                    && self.route == Some(NotificationRouteV1::TelegramGateway)
                    && self.last_error_code.is_some()
                    && self.retry_at_ms == self.updated_at_ms
            }
        };
        if !valid_shape {
            return Err(NotificationContractError::InvalidDeliveryRecord);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationEventV1 {
    pub schema_version: u16,
    pub project_id: ProjectId,
    pub kind: NotificationKindV1,
    pub event_key: String,
    pub occurrence_digest: EvidenceDigest,
    pub dedup_key: EvidenceDigest,
    pub text: String,
    pub created_at_ms: i64,
}

impl NotificationEventV1 {
    pub fn new(
        project_id: ProjectId,
        kind: NotificationKindV1,
        event_key: impl Into<String>,
        occurrence_key: &str,
        text: impl Into<String>,
        created_at_ms: i64,
    ) -> Result<Self, NotificationContractError> {
        if occurrence_key.is_empty()
            || occurrence_key.len() > MAX_OCCURRENCE_KEY_BYTES
            || occurrence_key.chars().any(char::is_control)
        {
            return Err(NotificationContractError::InvalidOccurrenceKey);
        }
        let event_key = event_key.into();
        let occurrence_digest = EvidenceDigest::sha256(occurrence_key.as_bytes());
        let dedup_material = serde_jcs::to_vec(&NotificationDedupMaterial {
            schema_version: NOTIFICATION_SCHEMA_VERSION,
            project_id: &project_id,
            kind,
            event_key: &event_key,
            occurrence_digest: &occurrence_digest,
        })
        .map_err(|_| NotificationContractError::DedupEncoding)?;
        let event = Self {
            schema_version: NOTIFICATION_SCHEMA_VERSION,
            project_id,
            kind,
            event_key,
            occurrence_digest,
            dedup_key: EvidenceDigest::sha256(dedup_material),
            text: text.into(),
            created_at_ms,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> Result<(), NotificationContractError> {
        if self.schema_version != NOTIFICATION_SCHEMA_VERSION
            || !(0..=MAX_BROWSER_SAFE_TIMESTAMP).contains(&self.created_at_ms)
            || !valid_event_key(&self.event_key)
            || !valid_notification_text(&self.text)
        {
            return Err(NotificationContractError::InvalidEvent);
        }
        let material = serde_jcs::to_vec(&NotificationDedupMaterial {
            schema_version: self.schema_version,
            project_id: &self.project_id,
            kind: self.kind,
            event_key: &self.event_key,
            occurrence_digest: &self.occurrence_digest,
        })
        .map_err(|_| NotificationContractError::DedupEncoding)?;
        if self.dedup_key != EvidenceDigest::sha256(material) {
            return Err(NotificationContractError::DedupMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct NotificationDedupMaterial<'a> {
    schema_version: u16,
    project_id: &'a ProjectId,
    kind: NotificationKindV1,
    event_key: &'a str,
    occurrence_digest: &'a EvidenceDigest,
}

/// Exact JSON body accepted by `telegram-gateway`'s `POST /api/v1/messages` route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TelegramGatewayMessageV1 {
    pub project_id: String,
    pub chat_id: i64,
    pub message_thread_id: i32,
    pub text: String,
    pub format: String,
    pub disable_web_page_preview: bool,
    pub event_key: String,
    pub dedup_key: String,
}

impl TelegramGatewayMessageV1 {
    pub fn from_event(
        event: &NotificationEventV1,
        gateway_project_id: impl Into<String>,
        chat_id: i64,
        message_thread_id: i32,
    ) -> Result<Self, NotificationContractError> {
        event.validate()?;
        let request = Self {
            project_id: gateway_project_id.into(),
            chat_id,
            message_thread_id,
            text: event.text.clone(),
            format: "plain".to_owned(),
            disable_web_page_preview: true,
            event_key: event.event_key.clone(),
            dedup_key: event.dedup_key.to_string(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), NotificationContractError> {
        if !valid_gateway_project(&self.project_id)
            || self.chat_id == 0
            || self.message_thread_id < 0
            || self.format != "plain"
            || !self.disable_web_page_preview
            || !valid_event_key(&self.event_key)
            || !valid_notification_text(&self.text)
            || self.dedup_key.len() != 64
            || !self
                .dedup_key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(NotificationContractError::InvalidGatewayRequest);
        }
        Ok(())
    }
}

fn valid_event_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EVENT_KEY_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b':')
        })
}

fn valid_notification_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && value.len() <= MAX_NOTIFICATION_TEXT_BYTES
        && !value
            .chars()
            .any(|character| character.is_control() && character != '\n')
}

fn valid_gateway_project(value: &str) -> bool {
    (3..=MAX_GATEWAY_PROJECT_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NotificationContractError {
    #[error("notification occurrence key is invalid")]
    InvalidOccurrenceKey,
    #[error("notification deduplication material could not be encoded")]
    DedupEncoding,
    #[error("notification event is invalid")]
    InvalidEvent,
    #[error("notification deduplication key does not match its typed occurrence")]
    DedupMismatch,
    #[error("Telegram gateway request is invalid")]
    InvalidGatewayRequest,
    #[error("notification delivery record is invalid")]
    InvalidDeliveryRecord,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> ProjectId {
        "rimg".parse().expect("project")
    }

    #[test]
    fn occurrence_identity_is_deterministic_and_content_bound() {
        let first = NotificationEventV1::new(
            project(),
            NotificationKindV1::DeploySucceeded,
            "rdashboard.rimg.deploy",
            "commit:0123",
            "rimg: deploy succeeded",
            10,
        )
        .expect("first");
        let replay = NotificationEventV1::new(
            project(),
            NotificationKindV1::DeploySucceeded,
            "rdashboard.rimg.deploy",
            "commit:0123",
            "rimg: deploy succeeded",
            10,
        )
        .expect("replay");
        let next = NotificationEventV1::new(
            project(),
            NotificationKindV1::DeploySucceeded,
            "rdashboard.rimg.deploy",
            "commit:4567",
            "rimg: deploy succeeded",
            11,
        )
        .expect("next");
        assert_eq!(first.dedup_key, replay.dedup_key);
        assert_ne!(first.dedup_key, next.dedup_key);
    }

    #[test]
    fn gateway_request_reuses_event_and_dedup_keys_exactly() {
        let event = NotificationEventV1::new(
            project(),
            NotificationKindV1::ErrorPriorityChanged,
            "rdashboard.rimg.errors",
            "facts:abcd",
            "rimg: error priority is high",
            10,
        )
        .expect("event");
        let request =
            TelegramGatewayMessageV1::from_event(&event, "rdashboard", -100, 0).expect("request");
        assert_eq!(request.event_key, event.event_key);
        assert_eq!(request.dedup_key, event.dedup_key.as_str());
        assert_eq!(request.format, "plain");
        assert!(request.disable_web_page_preview);
    }

    #[test]
    fn deserialized_event_revalidates_its_typed_deduplication_binding() {
        let event = NotificationEventV1::new(
            project(),
            NotificationKindV1::BackupVerified,
            "rdashboard.rimg.backup",
            "chain:abcd",
            "rimg: backup verified",
            10,
        )
        .expect("event");
        let mut tampered = event;
        tampered.kind = NotificationKindV1::BackupFailed;
        assert_eq!(
            tampered.validate(),
            Err(NotificationContractError::DedupMismatch)
        );
    }
}
