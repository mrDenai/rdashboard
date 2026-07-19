use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use uuid::Uuid;

use crate::notifications::{NotificationContractError, NotificationEventV1};

use super::{lock_connection, verify_sqlite_version};

const NOTIFICATION_STORE_SCHEMA_VERSION: i64 = 1;
const MAX_LEASE: Duration = Duration::from_mins(5);
const MAX_RETRY: Duration = Duration::from_hours(24);

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
        transaction.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS notification_meta (
                key TEXT PRIMARY KEY,
                integer_value INTEGER NOT NULL
            ) STRICT;
            INSERT OR IGNORE INTO notification_meta(key, integer_value)
                VALUES ('schema_version', 1);

            CREATE TABLE IF NOT EXISTS notification_outbox (
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
            ) STRICT;
            CREATE INDEX IF NOT EXISTS notification_outbox_ready
                ON notification_outbox(state, retry_at_ms, created_at_ms);
            ",
        )?;
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
        event.validate()?;
        if now_ms < event.created_at_ms {
            return Err(NotificationStoreError::InvalidTimestamp);
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
        transaction.execute(
            "INSERT INTO notification_outbox(
                dedup_key, event_json, state, attempts, lease_id, lease_expires_at_ms,
                retry_at_ms, gateway_message_id, last_error_code, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, 'pending', 0, NULL, NULL, ?3, NULL, NULL, ?4, ?3)",
            params![
                event.dedup_key.as_str(),
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
        let selected: Option<(String, String, i64)> = transaction
            .query_row(
                "SELECT dedup_key, event_json, attempts
                 FROM notification_outbox
                 WHERE (
                    state IN ('pending', 'ambiguous', 'retryable_failure')
                    AND retry_at_ms <= ?1
                 ) OR (
                    state = 'leased' AND lease_expires_at_ms <= ?1
                 )
                 ORDER BY created_at_ms ASC, dedup_key ASC
                 LIMIT 1",
                [now_ms],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((dedup_key, event_json, attempts)) = selected else {
            transaction.commit()?;
            return Ok(None);
        };
        let event: NotificationEventV1 = serde_json::from_str(&event_json)?;
        event.validate()?;
        if event.dedup_key.as_str() != dedup_key {
            return Err(NotificationStoreError::CorruptBinding);
        }
        let attempt = attempts
            .checked_add(1)
            .ok_or(NotificationStoreError::AttemptRange)?;
        let lease_id = Uuid::new_v4();
        transaction.execute(
            "UPDATE notification_outbox
             SET state = 'leased', attempts = ?2, lease_id = ?3,
                 lease_expires_at_ms = ?4, gateway_message_id = NULL,
                 last_error_code = NULL, updated_at_ms = ?1
             WHERE dedup_key = ?5",
            params![
                now_ms,
                attempt,
                lease_id.to_string(),
                lease_expires_at_ms,
                dedup_key
            ],
        )?;
        transaction.commit()?;
        Ok(Some(NotificationClaimV1 {
            event,
            lease_id,
            attempt_number: u32::try_from(attempt)
                .map_err(|_| NotificationStoreError::AttemptRange)?,
            lease_expires_at_ms,
        }))
    }

    pub fn mark_delivered(
        &self,
        claim: &NotificationClaimV1,
        gateway_message_id: Uuid,
        now_ms: i64,
    ) -> Result<(), NotificationStoreError> {
        self.complete_claim(
            claim,
            NotificationCompletion::Delivered(gateway_message_id),
            now_ms,
        )
    }

    pub fn mark_ambiguous(
        &self,
        claim: &NotificationClaimV1,
        error_code: &str,
        now_ms: i64,
        retry_after: Duration,
    ) -> Result<(), NotificationStoreError> {
        validate_error_code(error_code)?;
        let retry_ms = bounded_duration_ms(retry_after, MAX_RETRY)?;
        let retry_at_ms = now_ms
            .checked_add(retry_ms)
            .ok_or(NotificationStoreError::InvalidTimestamp)?;
        self.complete_claim(
            claim,
            NotificationCompletion::Ambiguous {
                error_code,
                retry_at_ms,
            },
            now_ms,
        )
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
        let (state, retry_at_ms, gateway_message_id, error_code) = match completion {
            NotificationCompletion::Delivered(message_id) => {
                ("delivered", now_ms, Some(message_id.to_string()), None)
            }
            NotificationCompletion::Ambiguous {
                error_code,
                retry_at_ms,
            } => ("ambiguous", retry_at_ms, None, Some(error_code)),
            NotificationCompletion::PermanentFailure(error_code) => {
                ("permanent_failure", now_ms, None, Some(error_code))
            }
        };
        let changed = connection.execute(
            "UPDATE notification_outbox
             SET state = ?1, lease_id = NULL, lease_expires_at_ms = NULL,
                 retry_at_ms = ?2, gateway_message_id = ?3,
                 last_error_code = ?4, updated_at_ms = ?5
             WHERE dedup_key = ?6 AND state = 'leased' AND lease_id = ?7",
            params![
                state,
                retry_at_ms,
                gateway_message_id,
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
    Delivered(Uuid),
    Ambiguous {
        error_code: &'a str,
        retry_at_ms: i64,
    },
    PermanentFailure(&'a str),
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

fn validate_schema(connection: &Connection) -> Result<(), NotificationStoreError> {
    let version: i64 = connection.query_row(
        "SELECT integer_value FROM notification_meta WHERE key = 'schema_version'",
        [],
        |row| row.get(0),
    )?;
    if version != NOTIFICATION_STORE_SCHEMA_VERSION {
        return Err(NotificationStoreError::UnsupportedSchemaVersion(version));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
}

#[cfg(test)]
mod tests {
    use crate::{
        domain::ProjectId,
        notifications::{NotificationEventV1, NotificationKindV1},
    };
    use tempfile::tempdir;

    use super::*;

    fn event(occurrence: &str, text: &str) -> NotificationEventV1 {
        NotificationEventV1::new(
            "rimg".parse::<ProjectId>().expect("project"),
            NotificationKindV1::BackupVerified,
            "rdashboard.rimg.backup",
            occurrence,
            text,
            10,
        )
        .expect("event")
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
    fn ambiguous_delivery_retries_the_exact_same_dedup_key() {
        let directory = tempdir().expect("directory");
        let store =
            NotificationStore::open(directory.path().join("notifications.sqlite")).expect("store");
        let event = event("chain:1", "backup verified");
        store.enqueue(&event, 10).expect("enqueue");
        let first = store
            .claim_next(10, Duration::from_secs(30))
            .expect("claim")
            .expect("first claim");
        store
            .mark_ambiguous(&first, "transport_closed", 11, Duration::from_secs(5))
            .expect("ambiguous");
        assert!(
            store
                .claim_next(5_010, Duration::from_secs(30))
                .expect("early claim")
                .is_none()
        );
        let retry = store
            .claim_next(5_011, Duration::from_secs(30))
            .expect("retry claim")
            .expect("retry");
        assert_eq!(retry.event, first.event);
        assert_eq!(retry.attempt_number, 2);
        store
            .mark_delivered(&retry, Uuid::new_v4(), 5_012)
            .expect("delivered");
        assert!(
            store
                .claim_next(100, Duration::from_secs(30))
                .expect("empty")
                .is_none()
        );
    }
}
