use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    domain::ProjectId,
    notifications::{
        NOTIFICATION_SCHEMA_VERSION, NotificationContractError, NotificationDeliveryRecordV1,
        NotificationDeliveryStateV1, NotificationEventV1, NotificationRouteV1,
    },
};

use super::{lock_connection, verify_sqlite_version};

const NOTIFICATION_STORE_SCHEMA_VERSION: i64 = 2;
const LEGACY_NOTIFICATION_STORE_SCHEMA_VERSION: i64 = 1;
const MAX_LEASE: Duration = Duration::from_mins(5);
const MAX_RETRY: Duration = Duration::from_hours(24);
const MAX_PROJECT_RECORDS: usize = 50;
const MAX_OUTBOX_ROWS: i64 = 4_096;

#[derive(Clone, Debug)]
pub struct NotificationStore {
    connection: Arc<Mutex<Connection>>,
}

impl NotificationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NotificationStoreError> {
        verify_sqlite_version().map_err(NotificationStoreError::ControlStore)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        initialize_schema(&transaction)?;
        validate_schema(&transaction)?;
        transaction.commit()?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn enqueue(
        &self,
        event: &NotificationEventV1,
        now_ms: i64,
    ) -> Result<NotificationEnqueueResult, NotificationStoreError> {
        self.enqueue_with_limit(event, now_ms, MAX_OUTBOX_ROWS)
    }

    fn enqueue_with_limit(
        &self,
        event: &NotificationEventV1,
        now_ms: i64,
        maximum_rows: i64,
    ) -> Result<NotificationEnqueueResult, NotificationStoreError> {
        event.validate()?;
        if now_ms < event.created_at_ms {
            return Err(NotificationStoreError::InvalidTimestamp);
        }
        if maximum_rows <= 0 || maximum_rows > MAX_OUTBOX_ROWS {
            return Err(NotificationStoreError::InvalidCapacity);
        }
        let event_json = serde_jcs::to_string(event)?;
        let mut connection =
            lock_connection(&self.connection).map_err(NotificationStoreError::ControlStore)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT event_json FROM notification_outbox WHERE dedup_key = ?1",
                [event.dedup_key.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != event_json {
                return Err(NotificationStoreError::DedupConflict);
            }
            transaction.commit()?;
            return Ok(NotificationEnqueueResult::Duplicate);
        }
        let row_count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM notification_outbox", [], |row| {
                row.get(0)
            })?;
        if row_count >= maximum_rows {
            return Err(NotificationStoreError::BacklogFull);
        }
        transaction.execute(
            "INSERT INTO notification_outbox(
                dedup_key, project_id, event_json, state, attempts, lease_id,
                lease_expires_at_ms, retry_at_ms, route, provider_message_id,
                possible_duplicate, last_error_code, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, 'pending', 0, NULL, NULL, ?4, NULL, NULL, 0, NULL, ?5, ?4)",
            params![
                event.dedup_key.as_str(),
                event.project_id.as_str(),
                event_json,
                now_ms,
                event.created_at_ms
            ],
        )?;
        transaction.commit()?;
        Ok(NotificationEnqueueResult::Inserted)
    }

    pub fn claim_next(
        &self,
        now_ms: i64,
        lease_duration: Duration,
    ) -> Result<Option<NotificationClaimV1>, NotificationStoreError> {
        let lease_ms = bounded_duration_ms(lease_duration, MAX_LEASE)?;
        if now_ms < 0 {
            return Err(NotificationStoreError::InvalidTimestamp);
        }
        let lease_expires_at_ms = now_ms
            .checked_add(lease_ms)
            .ok_or(NotificationStoreError::InvalidTimestamp)?;
        let mut connection =
            lock_connection(&self.connection).map_err(NotificationStoreError::ControlStore)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let selected: Option<NotificationClaimCandidate> = transaction
            .query_row(
                "SELECT dedup_key, project_id, event_json, state, attempts, provider_message_id,
                        possible_duplicate
                 FROM notification_outbox
                 WHERE (
                    state IN ('pending', 'delivery_unknown', 'retry_scheduled')
                    AND retry_at_ms <= ?1
                 ) OR (
                    state = 'sending' AND lease_expires_at_ms <= ?1
                 )
                 ORDER BY created_at_ms ASC, dedup_key ASC
                 LIMIT 1",
                [now_ms],
                |row| {
                    Ok(NotificationClaimCandidate {
                        dedup_key: row.get(0)?,
                        project_id: row.get(1)?,
                        event_json: row.get(2)?,
                        previous_state: row.get(3)?,
                        attempts: row.get(4)?,
                        provider_id: row.get(5)?,
                        possible_duplicate: row.get(6)?,
                    })
                },
            )
            .optional()?;
        let Some(selected) = selected else {
            transaction.commit()?;
            return Ok(None);
        };
        let event = decode_event(&selected.dedup_key, &selected.event_json)?;
        if event.project_id.as_str() != selected.project_id {
            return Err(NotificationStoreError::CorruptProjectBinding);
        }
        let provider_message_id = selected
            .provider_id
            .map(|value| {
                Uuid::parse_str(&value)
                    .map_err(|_| NotificationStoreError::CorruptProviderMessageId)
            })
            .transpose()?;
        let attempt = selected
            .attempts
            .checked_add(1)
            .ok_or(NotificationStoreError::AttemptRange)?;
        let attempt_number =
            u32::try_from(attempt).map_err(|_| NotificationStoreError::AttemptRange)?;
        let possible_duplicate = selected.possible_duplicate != 0
            || (selected.previous_state == "sending" && provider_message_id.is_none());
        let lease_id = Uuid::new_v4();
        transaction.execute(
            "UPDATE notification_outbox
             SET state = 'sending', attempts = ?2, lease_id = ?3,
                 lease_expires_at_ms = ?4, route = 'telegram_gateway',
                 possible_duplicate = ?5, last_error_code = NULL, updated_at_ms = ?1
             WHERE dedup_key = ?6",
            params![
                now_ms,
                attempt,
                lease_id.to_string(),
                lease_expires_at_ms,
                i64::from(possible_duplicate),
                selected.dedup_key
            ],
        )?;
        transaction.commit()?;
        Ok(Some(NotificationClaimV1 {
            event,
            lease_id,
            attempt_number,
            lease_expires_at_ms,
            provider_message_id,
            possible_duplicate,
        }))
    }

    pub fn mark_gateway_accepted(
        &self,
        claim: &NotificationClaimV1,
        provider_message_id: Uuid,
        now_ms: i64,
        poll_after: Duration,
    ) -> Result<(), NotificationStoreError> {
        if claim.provider_message_id.is_some() {
            return Err(NotificationStoreError::ProviderMessageAlreadyBound);
        }
        let retry_at_ms = retry_timestamp(now_ms, poll_after)?;
        self.complete_claim(
            claim,
            NotificationCompletion::GatewayAccepted {
                provider_message_id,
                retry_at_ms,
            },
            now_ms,
        )
    }

    pub fn mark_retry_scheduled(
        &self,
        claim: &NotificationClaimV1,
        error_code: &str,
        now_ms: i64,
        retry_after: Duration,
    ) -> Result<(), NotificationStoreError> {
        validate_error_code(error_code)?;
        let retry_at_ms = retry_timestamp(now_ms, retry_after)?;
        self.complete_claim(
            claim,
            NotificationCompletion::RetryScheduled {
                error_code,
                retry_at_ms,
            },
            now_ms,
        )
    }

    pub fn mark_delivery_unknown(
        &self,
        claim: &NotificationClaimV1,
        error_code: &str,
        now_ms: i64,
        retry_after: Duration,
    ) -> Result<(), NotificationStoreError> {
        if claim.provider_message_id.is_some() {
            return Err(NotificationStoreError::ProviderMessageAlreadyBound);
        }
        validate_error_code(error_code)?;
        let retry_at_ms = retry_timestamp(now_ms, retry_after)?;
        self.complete_claim(
            claim,
            NotificationCompletion::DeliveryUnknown {
                error_code,
                retry_at_ms,
            },
            now_ms,
        )
    }

    pub fn mark_delivered(
        &self,
        claim: &NotificationClaimV1,
        now_ms: i64,
    ) -> Result<(), NotificationStoreError> {
        if claim.provider_message_id.is_none() {
            return Err(NotificationStoreError::ProviderMessageMissing);
        }
        self.complete_claim(claim, NotificationCompletion::Delivered, now_ms)
    }

    pub fn mark_permanent_failure(
        &self,
        claim: &NotificationClaimV1,
        error_code: &str,
        now_ms: i64,
    ) -> Result<(), NotificationStoreError> {
        validate_error_code(error_code)?;
        self.complete_claim(
            claim,
            NotificationCompletion::PermanentFailure(error_code),
            now_ms,
        )
    }

    pub fn project_records(
        &self,
        project_id: &ProjectId,
        limit: usize,
    ) -> Result<Vec<NotificationDeliveryRecordV1>, NotificationStoreError> {
        if !(1..=MAX_PROJECT_RECORDS).contains(&limit) {
            return Err(NotificationStoreError::InvalidLimit);
        }
        let limit = i64::try_from(limit).map_err(|_| NotificationStoreError::InvalidLimit)?;
        let connection =
            lock_connection(&self.connection).map_err(NotificationStoreError::ControlStore)?;
        let mut statement = connection.prepare(
            "SELECT dedup_key, event_json, state, attempts, route, provider_message_id,
                    last_error_code, retry_at_ms, updated_at_ms
             FROM notification_outbox
             WHERE project_id = ?1
             ORDER BY updated_at_ms DESC, dedup_key ASC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![project_id.as_str(), limit], |row| {
            Ok(PersistedNotificationRow {
                dedup_key: row.get(0)?,
                event_json: row.get(1)?,
                state: row.get(2)?,
                attempts: row.get(3)?,
                route: row.get(4)?,
                provider_message_id: row.get(5)?,
                last_error_code: row.get(6)?,
                retry_at_ms: row.get(7)?,
                updated_at_ms: row.get(8)?,
            })
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?.decode(project_id)?);
        }
        Ok(records)
    }

    fn complete_claim(
        &self,
        claim: &NotificationClaimV1,
        completion: NotificationCompletion<'_>,
        now_ms: i64,
    ) -> Result<(), NotificationStoreError> {
        claim.event.validate()?;
        if now_ms < claim.event.created_at_ms {
            return Err(NotificationStoreError::InvalidTimestamp);
        }
        let connection =
            lock_connection(&self.connection).map_err(NotificationStoreError::ControlStore)?;
        let (state, retry_at_ms, provider_id, possible_duplicate, error_code) = match completion {
            NotificationCompletion::GatewayAccepted {
                provider_message_id,
                retry_at_ms,
            } => (
                "retry_scheduled",
                retry_at_ms,
                Some(provider_message_id.to_string()),
                claim.possible_duplicate,
                Some("gateway_pending"),
            ),
            NotificationCompletion::RetryScheduled {
                error_code,
                retry_at_ms,
            } => (
                "retry_scheduled",
                retry_at_ms,
                claim.provider_message_id.map(|id| id.to_string()),
                claim.possible_duplicate,
                Some(error_code),
            ),
            NotificationCompletion::DeliveryUnknown {
                error_code,
                retry_at_ms,
            } => (
                "delivery_unknown",
                retry_at_ms,
                None,
                true,
                Some(error_code),
            ),
            NotificationCompletion::Delivered => (
                if claim.possible_duplicate {
                    "delivered_possible_duplicate"
                } else {
                    "delivered"
                },
                now_ms,
                claim.provider_message_id.map(|id| id.to_string()),
                claim.possible_duplicate,
                None,
            ),
            NotificationCompletion::PermanentFailure(error_code) => (
                "permanently_failed",
                now_ms,
                claim.provider_message_id.map(|id| id.to_string()),
                claim.possible_duplicate,
                Some(error_code),
            ),
        };
        let changed = connection.execute(
            "UPDATE notification_outbox
             SET state = ?1, lease_id = NULL, lease_expires_at_ms = NULL,
                 retry_at_ms = ?2, provider_message_id = ?3,
                 possible_duplicate = ?4, last_error_code = ?5, updated_at_ms = ?6
             WHERE dedup_key = ?7 AND state = 'sending' AND lease_id = ?8",
            params![
                state,
                retry_at_ms,
                provider_id,
                i64::from(possible_duplicate),
                error_code,
                now_ms,
                claim.event.dedup_key.as_str(),
                claim.lease_id.to_string()
            ],
        )?;
        if changed != 1 {
            return Err(NotificationStoreError::LeaseMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum NotificationCompletion<'a> {
    GatewayAccepted {
        provider_message_id: Uuid,
        retry_at_ms: i64,
    },
    RetryScheduled {
        error_code: &'a str,
        retry_at_ms: i64,
    },
    DeliveryUnknown {
        error_code: &'a str,
        retry_at_ms: i64,
    },
    Delivered,
    PermanentFailure(&'a str),
}

struct NotificationClaimCandidate {
    dedup_key: String,
    project_id: String,
    event_json: String,
    previous_state: String,
    attempts: i64,
    provider_id: Option<String>,
    possible_duplicate: i64,
}

struct PersistedNotificationRow {
    dedup_key: String,
    event_json: String,
    state: String,
    attempts: i64,
    route: Option<String>,
    provider_message_id: Option<String>,
    last_error_code: Option<String>,
    retry_at_ms: i64,
    updated_at_ms: i64,
}

impl PersistedNotificationRow {
    fn decode(
        self,
        expected_project: &ProjectId,
    ) -> Result<NotificationDeliveryRecordV1, NotificationStoreError> {
        let event = decode_event(&self.dedup_key, &self.event_json)?;
        if &event.project_id != expected_project {
            return Err(NotificationStoreError::CorruptProjectBinding);
        }
        let record = NotificationDeliveryRecordV1 {
            schema_version: NOTIFICATION_SCHEMA_VERSION,
            event,
            state: parse_state(&self.state)?,
            attempt_count: u32::try_from(self.attempts)
                .map_err(|_| NotificationStoreError::AttemptRange)?,
            route: self.route.map(|route| parse_route(&route)).transpose()?,
            provider_message_id: self
                .provider_message_id
                .map(|value| {
                    Uuid::parse_str(&value)
                        .map_err(|_| NotificationStoreError::CorruptProviderMessageId)
                })
                .transpose()?,
            last_error_code: self.last_error_code,
            retry_at_ms: self.retry_at_ms,
            updated_at_ms: self.updated_at_ms,
        };
        record.validate()?;
        Ok(record)
    }
}

fn initialize_schema(connection: &Connection) -> Result<(), NotificationStoreError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS notification_meta (
            key TEXT PRIMARY KEY,
            integer_value INTEGER NOT NULL
        ) STRICT;",
    )?;
    let version = connection
        .query_row(
            "SELECT integer_value FROM notification_meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    match version {
        None => {
            create_outbox_v2(connection, "notification_outbox")?;
            connection.execute(
                "INSERT INTO notification_meta(key, integer_value) VALUES ('schema_version', ?1)",
                [NOTIFICATION_STORE_SCHEMA_VERSION],
            )?;
        }
        Some(LEGACY_NOTIFICATION_STORE_SCHEMA_VERSION) => migrate_v1(connection)?,
        Some(NOTIFICATION_STORE_SCHEMA_VERSION) => {}
        Some(version) => return Err(NotificationStoreError::UnsupportedSchemaVersion(version)),
    }
    connection.execute(
        "CREATE INDEX IF NOT EXISTS notification_outbox_ready
         ON notification_outbox(state, retry_at_ms, created_at_ms)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS notification_outbox_project
         ON notification_outbox(project_id, updated_at_ms DESC)",
        [],
    )?;
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS notification_outbox_provider_message
         ON notification_outbox(provider_message_id)
         WHERE provider_message_id IS NOT NULL",
        [],
    )?;
    Ok(())
}

fn create_outbox_v2(
    connection: &Connection,
    table_name: &'static str,
) -> Result<(), NotificationStoreError> {
    let statement = format!(
        "CREATE TABLE {table_name} (
            dedup_key TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            event_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN (
                'pending', 'sending', 'delivery_unknown', 'retry_scheduled',
                'delivered', 'delivered_possible_duplicate', 'permanently_failed'
            )),
            attempts INTEGER NOT NULL CHECK(attempts >= 0),
            lease_id TEXT,
            lease_expires_at_ms INTEGER,
            retry_at_ms INTEGER NOT NULL CHECK(retry_at_ms >= 0),
            route TEXT CHECK(route IS NULL OR route = 'telegram_gateway'),
            provider_message_id TEXT,
            possible_duplicate INTEGER NOT NULL CHECK(possible_duplicate IN (0, 1)),
            last_error_code TEXT,
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
            CHECK((state = 'sending') = (lease_id IS NOT NULL)),
            CHECK((state = 'sending') = (lease_expires_at_ms IS NOT NULL)),
            CHECK((attempts = 0) = (route IS NULL)),
            CHECK((state = 'pending') = (attempts = 0)),
            CHECK(state NOT IN ('delivered', 'delivered_possible_duplicate')
                  OR provider_message_id IS NOT NULL),
            CHECK(state != 'delivery_unknown' OR possible_duplicate = 1),
            CHECK(state != 'delivered' OR possible_duplicate = 0),
            CHECK(state != 'delivered_possible_duplicate' OR possible_duplicate = 1)
        ) STRICT;"
    );
    connection.execute_batch(&statement)?;
    Ok(())
}

fn migrate_v1(connection: &Connection) -> Result<(), NotificationStoreError> {
    let exists = table_exists(connection, "notification_outbox")?;
    if !exists {
        return Err(NotificationStoreError::CorruptSchema(
            "legacy notification_outbox",
        ));
    }
    create_outbox_v2(connection, "notification_outbox_v2")?;
    let legacy_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM notification_outbox", [], |row| {
            row.get(0)
        })?;
    connection.execute(
        "INSERT INTO notification_outbox_v2(
            dedup_key, project_id, event_json, state, attempts, lease_id,
            lease_expires_at_ms, retry_at_ms, route, provider_message_id,
            possible_duplicate, last_error_code, created_at_ms, updated_at_ms
         )
         SELECT dedup_key,
                json_extract(event_json, '$.project_id'),
                event_json,
                CASE state
                    WHEN 'pending' THEN 'pending'
                    WHEN 'leased' THEN 'sending'
                    WHEN 'ambiguous' THEN 'delivery_unknown'
                    WHEN 'retryable_failure' THEN 'retry_scheduled'
                    WHEN 'delivered' THEN 'delivered'
                    WHEN 'permanent_failure' THEN 'permanently_failed'
                END,
                attempts, lease_id, lease_expires_at_ms, retry_at_ms,
                CASE WHEN attempts = 0 THEN NULL ELSE 'telegram_gateway' END,
                gateway_message_id,
                CASE WHEN state = 'ambiguous' THEN 1 ELSE 0 END,
                last_error_code, created_at_ms, updated_at_ms
         FROM notification_outbox",
        [],
    )?;
    let migrated_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM notification_outbox_v2", [], |row| {
            row.get(0)
        })?;
    if legacy_count != migrated_count {
        return Err(NotificationStoreError::MigrationCountMismatch {
            expected: legacy_count,
            migrated: migrated_count,
        });
    }
    connection.execute_batch(
        "DROP TABLE notification_outbox;
         ALTER TABLE notification_outbox_v2 RENAME TO notification_outbox;",
    )?;
    connection.execute(
        "UPDATE notification_meta SET integer_value = ?1 WHERE key = 'schema_version'",
        [NOTIFICATION_STORE_SCHEMA_VERSION],
    )?;
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<(), NotificationStoreError> {
    let version: i64 = connection.query_row(
        "SELECT integer_value FROM notification_meta WHERE key = 'schema_version'",
        [],
        |row| row.get(0),
    )?;
    if version != NOTIFICATION_STORE_SCHEMA_VERSION {
        return Err(NotificationStoreError::UnsupportedSchemaVersion(version));
    }
    for table in ["notification_meta", "notification_outbox"] {
        if !table_exists(connection, table)? {
            return Err(NotificationStoreError::CorruptSchema(table));
        }
    }
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, NotificationStoreError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn decode_event(
    expected_dedup_key: &str,
    event_json: &str,
) -> Result<NotificationEventV1, NotificationStoreError> {
    let event: NotificationEventV1 = serde_json::from_str(event_json)?;
    event.validate()?;
    if event.dedup_key.as_str() != expected_dedup_key {
        return Err(NotificationStoreError::CorruptBinding);
    }
    Ok(event)
}

fn parse_state(value: &str) -> Result<NotificationDeliveryStateV1, NotificationStoreError> {
    match value {
        "pending" => Ok(NotificationDeliveryStateV1::Pending),
        "sending" => Ok(NotificationDeliveryStateV1::Sending),
        "delivery_unknown" => Ok(NotificationDeliveryStateV1::DeliveryUnknown),
        "retry_scheduled" => Ok(NotificationDeliveryStateV1::RetryScheduled),
        "delivered" => Ok(NotificationDeliveryStateV1::Delivered),
        "delivered_possible_duplicate" => {
            Ok(NotificationDeliveryStateV1::DeliveredPossibleDuplicate)
        }
        "permanently_failed" => Ok(NotificationDeliveryStateV1::PermanentlyFailed),
        _ => Err(NotificationStoreError::CorruptState),
    }
}

fn parse_route(value: &str) -> Result<NotificationRouteV1, NotificationStoreError> {
    match value {
        "telegram_gateway" => Ok(NotificationRouteV1::TelegramGateway),
        _ => Err(NotificationStoreError::CorruptRoute),
    }
}

fn retry_timestamp(now_ms: i64, duration: Duration) -> Result<i64, NotificationStoreError> {
    let retry_ms = bounded_duration_ms(duration, MAX_RETRY)?;
    now_ms
        .checked_add(retry_ms)
        .ok_or(NotificationStoreError::InvalidTimestamp)
}

fn bounded_duration_ms(
    duration: Duration,
    maximum: Duration,
) -> Result<i64, NotificationStoreError> {
    if duration.is_zero() || duration > maximum {
        return Err(NotificationStoreError::InvalidDuration);
    }
    i64::try_from(duration.as_millis()).map_err(|_| NotificationStoreError::InvalidDuration)
}

fn validate_error_code(value: &str) -> Result<(), NotificationStoreError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(NotificationStoreError::InvalidErrorCode);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEnqueueResult {
    Inserted,
    Duplicate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationClaimV1 {
    pub event: NotificationEventV1,
    pub lease_id: Uuid,
    pub attempt_number: u32,
    pub lease_expires_at_ms: i64,
    pub provider_message_id: Option<Uuid>,
    pub possible_duplicate: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum NotificationStoreError {
    #[error("notification SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("notification JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Contract(#[from] NotificationContractError),
    #[error("controller store prerequisite failed: {0}")]
    ControlStore(super::StoreError),
    #[error("notification store schema version {0} is unsupported")]
    UnsupportedSchemaVersion(i64),
    #[error("notification store schema is missing or corrupt: {0}")]
    CorruptSchema(&'static str),
    #[error("notification timestamp is invalid")]
    InvalidTimestamp,
    #[error("notification lease or retry duration is invalid")]
    InvalidDuration,
    #[error("notification error code is invalid")]
    InvalidErrorCode,
    #[error("notification deduplication key was reused with different content")]
    DedupConflict,
    #[error("notification claim does not match the active lease")]
    LeaseMismatch,
    #[error("notification attempt count is outside the supported range")]
    AttemptRange,
    #[error("notification event does not match its durable key")]
    CorruptBinding,
    #[error("notification event is bound to another project")]
    CorruptProjectBinding,
    #[error("notification delivery state is corrupt")]
    CorruptState,
    #[error("notification delivery route is corrupt")]
    CorruptRoute,
    #[error("notification provider message identifier is corrupt")]
    CorruptProviderMessageId,
    #[error("notification provider message is already bound")]
    ProviderMessageAlreadyBound,
    #[error("notification cannot be delivered without a provider message identifier")]
    ProviderMessageMissing,
    #[error("notification project record limit must be between 1 and 50")]
    InvalidLimit,
    #[error("notification outbox reached its bounded capacity")]
    BacklogFull,
    #[error("notification outbox capacity is invalid")]
    InvalidCapacity,
    #[error("notification schema migration expected {expected} rows but migrated {migrated}")]
    MigrationCountMismatch { expected: i64, migrated: i64 },
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::notifications::NotificationKindV1;

    fn project() -> ProjectId {
        "rimg".parse().expect("project")
    }

    fn event(occurrence: &str, text: &str) -> NotificationEventV1 {
        NotificationEventV1::new(
            project(),
            NotificationKindV1::BackupVerified,
            "rdashboard.rimg.backup",
            occurrence,
            text,
            10,
        )
        .expect("event")
    }

    fn only_record(store: &NotificationStore) -> NotificationDeliveryRecordV1 {
        store
            .project_records(&project(), 10)
            .expect("records")
            .into_iter()
            .next()
            .expect("record")
    }

    #[test]
    fn enqueue_is_idempotent_but_rejects_dedup_conflict() {
        let directory = tempdir().expect("directory");
        let store =
            NotificationStore::open(directory.path().join("notifications.sqlite")).expect("store");
        let first = event("chain:1", "backup verified");
        assert_eq!(
            store.enqueue(&first, 10).expect("insert"),
            NotificationEnqueueResult::Inserted
        );
        assert_eq!(
            store.enqueue(&first, 11).expect("duplicate"),
            NotificationEnqueueResult::Duplicate
        );
        let mut conflict = first;
        conflict.text = "different text".to_owned();
        assert!(matches!(
            store.enqueue(&conflict, 12),
            Err(NotificationStoreError::DedupConflict)
        ));
    }

    #[test]
    fn bounded_outbox_still_accepts_an_idempotent_replay() {
        let directory = tempdir().expect("directory");
        let store =
            NotificationStore::open(directory.path().join("notifications.sqlite")).expect("store");
        let first = event("chain:1", "backup verified");
        let second = event("chain:2", "second backup verified");
        assert_eq!(
            store.enqueue_with_limit(&first, 10, 1).expect("insert"),
            NotificationEnqueueResult::Inserted
        );
        assert_eq!(
            store.enqueue_with_limit(&first, 11, 1).expect("duplicate"),
            NotificationEnqueueResult::Duplicate
        );
        assert!(matches!(
            store.enqueue_with_limit(&second, 11, 1),
            Err(NotificationStoreError::BacklogFull)
        ));
    }

    #[test]
    fn provider_message_identifier_cannot_be_bound_to_two_events() {
        let directory = tempdir().expect("directory");
        let store =
            NotificationStore::open(directory.path().join("notifications.sqlite")).expect("store");
        store
            .enqueue(&event("chain:1", "first backup verified"), 10)
            .expect("first enqueue");
        let first = store
            .claim_next(10, Duration::from_secs(30))
            .expect("first claim")
            .expect("first event");
        let provider_message_id = Uuid::new_v4();
        store
            .mark_gateway_accepted(&first, provider_message_id, 11, Duration::from_secs(100))
            .expect("first provider binding");

        store
            .enqueue(&event("chain:2", "second backup verified"), 12)
            .expect("second enqueue");
        let second = store
            .claim_next(12, Duration::from_secs(30))
            .expect("second claim")
            .expect("second event");
        assert!(matches!(
            store.mark_gateway_accepted(&second, provider_message_id, 13, Duration::from_secs(1),),
            Err(NotificationStoreError::Sqlite(_))
        ));
    }

    #[test]
    fn ambiguous_delivery_remains_possible_duplicate_after_success() {
        let directory = tempdir().expect("directory");
        let store =
            NotificationStore::open(directory.path().join("notifications.sqlite")).expect("store");
        store
            .enqueue(&event("chain:1", "backup verified"), 10)
            .expect("enqueue");
        let first = store
            .claim_next(10, Duration::from_secs(30))
            .expect("claim")
            .expect("first claim");
        store
            .mark_delivery_unknown(&first, "transport_closed", 11, Duration::from_secs(5))
            .expect("unknown");
        let unknown = only_record(&store);
        assert_eq!(unknown.state, NotificationDeliveryStateV1::DeliveryUnknown);

        let retry = store
            .claim_next(5_011, Duration::from_secs(30))
            .expect("retry claim")
            .expect("retry");
        assert!(retry.possible_duplicate);
        let provider_id = Uuid::new_v4();
        store
            .mark_gateway_accepted(&retry, provider_id, 5_012, Duration::from_secs(1))
            .expect("accepted");
        let poll = store
            .claim_next(6_012, Duration::from_secs(30))
            .expect("poll claim")
            .expect("poll");
        assert_eq!(poll.provider_message_id, Some(provider_id));
        assert!(poll.possible_duplicate);
        store.mark_delivered(&poll, 6_013).expect("delivered");
        assert_eq!(
            only_record(&store).state,
            NotificationDeliveryStateV1::DeliveredPossibleDuplicate
        );
    }

    #[test]
    fn known_retryable_rejection_does_not_invent_ambiguity() {
        let directory = tempdir().expect("directory");
        let store =
            NotificationStore::open(directory.path().join("notifications.sqlite")).expect("store");
        store
            .enqueue(&event("chain:2", "backup verified"), 10)
            .expect("enqueue");
        let first = store
            .claim_next(10, Duration::from_secs(30))
            .expect("claim")
            .expect("first");
        store
            .mark_retry_scheduled(&first, "gateway_overloaded", 11, Duration::from_secs(1))
            .expect("retry");
        let send = store
            .claim_next(1_011, Duration::from_secs(30))
            .expect("send")
            .expect("send claim");
        assert!(!send.possible_duplicate);
        let provider_id = Uuid::new_v4();
        store
            .mark_gateway_accepted(&send, provider_id, 1_012, Duration::from_secs(1))
            .expect("accepted");
        let poll = store
            .claim_next(2_012, Duration::from_secs(30))
            .expect("poll")
            .expect("poll claim");
        store.mark_delivered(&poll, 2_013).expect("delivered");
        assert_eq!(
            only_record(&store).state,
            NotificationDeliveryStateV1::Delivered
        );
    }

    #[test]
    fn expired_unrecorded_send_becomes_delivery_unknown_before_retry() {
        let directory = tempdir().expect("directory");
        let store =
            NotificationStore::open(directory.path().join("notifications.sqlite")).expect("store");
        store
            .enqueue(&event("chain:3", "backup verified"), 10)
            .expect("enqueue");
        store
            .claim_next(10, Duration::from_secs(1))
            .expect("claim")
            .expect("first");
        let recovered = store
            .claim_next(1_010, Duration::from_secs(30))
            .expect("reclaim")
            .expect("recovered");
        assert!(recovered.possible_duplicate);
    }

    #[test]
    fn schema_v1_ambiguous_state_migrates_without_losing_lineage() {
        let directory = tempdir().expect("directory");
        let path = directory.path().join("notifications.sqlite");
        let legacy_event = event("chain:4", "backup verified");
        let connection = Connection::open(&path).expect("legacy connection");
        connection
            .execute_batch(
                "CREATE TABLE notification_meta (
                    key TEXT PRIMARY KEY,
                    integer_value INTEGER NOT NULL
                ) STRICT;
                 INSERT INTO notification_meta VALUES ('schema_version', 1);
                 CREATE TABLE notification_outbox (
                    dedup_key TEXT PRIMARY KEY,
                    event_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'pending', 'leased', 'ambiguous', 'retryable_failure',
                        'delivered', 'permanent_failure'
                    )),
                    attempts INTEGER NOT NULL CHECK(attempts >= 0),
                    lease_id TEXT,
                    lease_expires_at_ms INTEGER,
                    retry_at_ms INTEGER NOT NULL CHECK(retry_at_ms >= 0),
                    gateway_message_id TEXT,
                    last_error_code TEXT,
                    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
                    CHECK((state = 'leased') = (lease_id IS NOT NULL)),
                    CHECK((state = 'leased') = (lease_expires_at_ms IS NOT NULL)),
                    CHECK((state = 'delivered') = (gateway_message_id IS NOT NULL))
                 ) STRICT;",
            )
            .expect("legacy schema");
        connection
            .execute(
                "INSERT INTO notification_outbox VALUES (
                    ?1, ?2, 'ambiguous', 1, NULL, NULL, 1000, NULL,
                    'transport_closed', 10, 11
                )",
                params![
                    legacy_event.dedup_key.as_str(),
                    serde_jcs::to_string(&legacy_event).expect("event json")
                ],
            )
            .expect("legacy row");
        drop(connection);

        let migrated = NotificationStore::open(path).expect("migrated store");
        let record = only_record(&migrated);
        assert_eq!(record.state, NotificationDeliveryStateV1::DeliveryUnknown);
        assert_eq!(record.attempt_count, 1);
    }
}
