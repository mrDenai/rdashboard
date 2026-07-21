use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{
    domain::ProjectId,
    integrations::{
        IntegrationContractError, IntegrationFailureV1, IntegrationKindV1,
        PROJECT_INTEGRATION_SCHEMA_VERSION, ProjectErrorsDataV1, ProjectErrorsRecordV1,
        ProjectUpdatesDataV1, ProjectUpdatesRecordV1,
    },
    notification_planner::{plan_error_notifications, plan_update_notifications},
    notifications::NotificationEventV1,
};

use super::{lock_connection, verify_sqlite_version};

const INTEGRATION_STORE_SCHEMA_VERSION: i64 = 2;
const LEGACY_INTEGRATION_STORE_SCHEMA_VERSION: i64 = 1;
const MAX_NOTIFICATION_HANDOFF_BATCH: usize = 100;
const MAX_NOTIFICATION_HANDOFF_ROWS: i64 = 512;

#[derive(Clone, Debug)]
pub struct IntegrationStore {
    connection: Arc<Mutex<Connection>>,
}

impl IntegrationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IntegrationStoreError> {
        verify_sqlite_version().map_err(IntegrationStoreError::ControlStore)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS integration_meta (
                key TEXT PRIMARY KEY,
                integer_value INTEGER NOT NULL
            ) STRICT;
            INSERT OR IGNORE INTO integration_meta(key, integer_value)
                VALUES ('schema_version', 1);

            CREATE TABLE IF NOT EXISTS project_integration_records (
                project_id TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('errors', 'updates')),
                attempted_at_ms INTEGER NOT NULL CHECK(attempted_at_ms >= 0),
                record_json TEXT NOT NULL,
                PRIMARY KEY(project_id, kind)
            ) STRICT;
            ",
        )?;
        migrate_schema(&transaction)?;
        validate_schema(&transaction)?;
        transaction.commit()?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn project_errors(
        &self,
        project_id: &ProjectId,
    ) -> Result<Option<ProjectErrorsRecordV1>, IntegrationStoreError> {
        let connection =
            lock_connection(&self.connection).map_err(IntegrationStoreError::ControlStore)?;
        load_record(&connection, project_id, IntegrationKindV1::Errors)?
            .map(|json| decode_errors(project_id, &json))
            .transpose()
    }

    pub fn project_updates(
        &self,
        project_id: &ProjectId,
    ) -> Result<Option<ProjectUpdatesRecordV1>, IntegrationStoreError> {
        let connection =
            lock_connection(&self.connection).map_err(IntegrationStoreError::ControlStore)?;
        load_record(&connection, project_id, IntegrationKindV1::Updates)?
            .map(|json| decode_updates(project_id, &json))
            .transpose()
    }

    pub fn record_errors_success(
        &self,
        attempted_at_ms: i64,
        data: ProjectErrorsDataV1,
    ) -> Result<ProjectErrorsRecordV1, IntegrationStoreError> {
        self.record_errors_transition(attempted_at_ms, ErrorsTransition::Success(data), false)
    }

    pub fn record_errors_success_with_notifications(
        &self,
        attempted_at_ms: i64,
        data: ProjectErrorsDataV1,
    ) -> Result<ProjectErrorsRecordV1, IntegrationStoreError> {
        self.record_errors_transition(attempted_at_ms, ErrorsTransition::Success(data), true)
    }

    pub fn record_updates_success(
        &self,
        attempted_at_ms: i64,
        data: ProjectUpdatesDataV1,
    ) -> Result<ProjectUpdatesRecordV1, IntegrationStoreError> {
        self.record_updates_transition(attempted_at_ms, UpdatesTransition::Success(data), false)
    }

    pub fn record_updates_success_with_notifications(
        &self,
        attempted_at_ms: i64,
        data: ProjectUpdatesDataV1,
    ) -> Result<ProjectUpdatesRecordV1, IntegrationStoreError> {
        self.record_updates_transition(attempted_at_ms, UpdatesTransition::Success(data), true)
    }

    pub fn record_errors_failure(
        &self,
        project_id: &ProjectId,
        attempted_at_ms: i64,
        failure: IntegrationFailureV1,
    ) -> Result<ProjectErrorsRecordV1, IntegrationStoreError> {
        self.record_errors_transition(
            attempted_at_ms,
            ErrorsTransition::Failure {
                project_id: project_id.clone(),
                failure,
            },
            false,
        )
    }

    pub fn record_errors_failure_with_notifications(
        &self,
        project_id: &ProjectId,
        attempted_at_ms: i64,
        failure: IntegrationFailureV1,
    ) -> Result<ProjectErrorsRecordV1, IntegrationStoreError> {
        self.record_errors_transition(
            attempted_at_ms,
            ErrorsTransition::Failure {
                project_id: project_id.clone(),
                failure,
            },
            true,
        )
    }

    pub fn record_updates_failure(
        &self,
        project_id: &ProjectId,
        attempted_at_ms: i64,
        failure: IntegrationFailureV1,
    ) -> Result<ProjectUpdatesRecordV1, IntegrationStoreError> {
        self.record_updates_transition(
            attempted_at_ms,
            UpdatesTransition::Failure {
                project_id: project_id.clone(),
                failure,
            },
            false,
        )
    }

    pub fn record_updates_failure_with_notifications(
        &self,
        project_id: &ProjectId,
        attempted_at_ms: i64,
        failure: IntegrationFailureV1,
    ) -> Result<ProjectUpdatesRecordV1, IntegrationStoreError> {
        self.record_updates_transition(
            attempted_at_ms,
            UpdatesTransition::Failure {
                project_id: project_id.clone(),
                failure,
            },
            true,
        )
    }

    pub fn pending_notification_events(
        &self,
        limit: usize,
    ) -> Result<Vec<NotificationEventV1>, IntegrationStoreError> {
        if !(1..=MAX_NOTIFICATION_HANDOFF_BATCH).contains(&limit) {
            return Err(IntegrationStoreError::InvalidNotificationLimit);
        }
        let connection =
            lock_connection(&self.connection).map_err(IntegrationStoreError::ControlStore)?;
        let limit =
            i64::try_from(limit).map_err(|_| IntegrationStoreError::InvalidNotificationLimit)?;
        let mut statement = connection.prepare(
            "SELECT dedup_key, event_json FROM integration_notification_handoff
             ORDER BY queued_at_ms ASC, dedup_key ASC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (dedup_key, event_json) = row?;
            let event: NotificationEventV1 = serde_json::from_str(&event_json)?;
            event.validate()?;
            if event.dedup_key.as_str() != dedup_key || serde_jcs::to_string(&event)? != event_json
            {
                return Err(IntegrationStoreError::CorruptNotificationHandoff);
            }
            events.push(event);
        }
        Ok(events)
    }

    pub fn acknowledge_notification_event(
        &self,
        event: &NotificationEventV1,
    ) -> Result<(), IntegrationStoreError> {
        event.validate()?;
        let event_json = serde_jcs::to_string(event)?;
        let connection =
            lock_connection(&self.connection).map_err(IntegrationStoreError::ControlStore)?;
        let deleted = connection.execute(
            "DELETE FROM integration_notification_handoff
             WHERE dedup_key = ?1 AND event_json = ?2",
            params![event.dedup_key.as_str(), event_json],
        )?;
        if deleted != 1 {
            return Err(IntegrationStoreError::NotificationHandoffMismatch);
        }
        Ok(())
    }

    fn record_errors_transition(
        &self,
        attempted_at_ms: i64,
        transition: ErrorsTransition,
        queue_notifications: bool,
    ) -> Result<ProjectErrorsRecordV1, IntegrationStoreError> {
        let mut connection =
            lock_connection(&self.connection).map_err(IntegrationStoreError::ControlStore)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let project_id = transition.project_id().clone();
        let previous = load_record(&transaction, &project_id, IntegrationKindV1::Errors)?
            .map(|json| decode_errors(&project_id, &json))
            .transpose()?;
        let record = transition.into_record(attempted_at_ms, previous.as_ref())?;
        let events = if queue_notifications {
            plan_error_notifications(previous.as_ref(), &record)?
        } else {
            Vec::new()
        };
        persist_record(
            &transaction,
            &project_id,
            IntegrationKindV1::Errors,
            attempted_at_ms,
            &record,
        )?;
        persist_notification_events(&transaction, attempted_at_ms, &events)?;
        transaction.commit()?;
        Ok(record)
    }

    fn record_updates_transition(
        &self,
        attempted_at_ms: i64,
        transition: UpdatesTransition,
        queue_notifications: bool,
    ) -> Result<ProjectUpdatesRecordV1, IntegrationStoreError> {
        let mut connection =
            lock_connection(&self.connection).map_err(IntegrationStoreError::ControlStore)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let project_id = transition.project_id().clone();
        let previous = load_record(&transaction, &project_id, IntegrationKindV1::Updates)?
            .map(|json| decode_updates(&project_id, &json))
            .transpose()?;
        let record = transition.into_record(attempted_at_ms, previous.as_ref())?;
        let events = if queue_notifications {
            plan_update_notifications(previous.as_ref(), &record)?
        } else {
            Vec::new()
        };
        persist_record(
            &transaction,
            &project_id,
            IntegrationKindV1::Updates,
            attempted_at_ms,
            &record,
        )?;
        persist_notification_events(&transaction, attempted_at_ms, &events)?;
        transaction.commit()?;
        Ok(record)
    }
}

enum ErrorsTransition {
    Success(ProjectErrorsDataV1),
    Failure {
        project_id: ProjectId,
        failure: IntegrationFailureV1,
    },
}

impl ErrorsTransition {
    fn project_id(&self) -> &ProjectId {
        match self {
            Self::Success(data) => &data.project_id,
            Self::Failure { project_id, .. } => project_id,
        }
    }

    fn into_record(
        self,
        attempted_at_ms: i64,
        previous: Option<&ProjectErrorsRecordV1>,
    ) -> Result<ProjectErrorsRecordV1, IntegrationStoreError> {
        let record = match self {
            Self::Success(data) => ProjectErrorsRecordV1 {
                schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
                project_id: data.project_id.clone(),
                attempted_at_ms,
                successful_at_ms: Some(attempted_at_ms),
                collection_error: None,
                data: Some(data),
            },
            Self::Failure {
                project_id,
                failure,
            } => {
                failure.validate()?;
                ProjectErrorsRecordV1 {
                    schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
                    project_id,
                    attempted_at_ms,
                    successful_at_ms: previous.and_then(|record| record.successful_at_ms),
                    collection_error: Some(failure),
                    data: previous.and_then(|record| record.data.clone()),
                }
            }
        };
        record.validate()?;
        Ok(record)
    }
}

enum UpdatesTransition {
    Success(ProjectUpdatesDataV1),
    Failure {
        project_id: ProjectId,
        failure: IntegrationFailureV1,
    },
}

impl UpdatesTransition {
    fn project_id(&self) -> &ProjectId {
        match self {
            Self::Success(data) => &data.project_id,
            Self::Failure { project_id, .. } => project_id,
        }
    }

    fn into_record(
        self,
        attempted_at_ms: i64,
        previous: Option<&ProjectUpdatesRecordV1>,
    ) -> Result<ProjectUpdatesRecordV1, IntegrationStoreError> {
        let record = match self {
            Self::Success(data) => ProjectUpdatesRecordV1 {
                schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
                project_id: data.project_id.clone(),
                attempted_at_ms,
                successful_at_ms: Some(attempted_at_ms),
                collection_error: None,
                data: Some(data),
            },
            Self::Failure {
                project_id,
                failure,
            } => {
                failure.validate()?;
                ProjectUpdatesRecordV1 {
                    schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
                    project_id,
                    attempted_at_ms,
                    successful_at_ms: previous.and_then(|record| record.successful_at_ms),
                    collection_error: Some(failure),
                    data: previous.and_then(|record| record.data.clone()),
                }
            }
        };
        record.validate()?;
        Ok(record)
    }
}

fn persist_notification_events(
    connection: &Connection,
    queued_at_ms: i64,
    events: &[NotificationEventV1],
) -> Result<(), IntegrationStoreError> {
    for event in events {
        event.validate()?;
        if queued_at_ms < event.created_at_ms {
            return Err(IntegrationStoreError::InvalidTimestamp);
        }
        let event_json = serde_jcs::to_string(event)?;
        let existing: Option<String> = connection
            .query_row(
                "SELECT event_json FROM integration_notification_handoff WHERE dedup_key = ?1",
                [event.dedup_key.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != event_json {
                return Err(IntegrationStoreError::NotificationHandoffConflict);
            }
            continue;
        }
        let row_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM integration_notification_handoff",
            [],
            |row| row.get(0),
        )?;
        if row_count >= MAX_NOTIFICATION_HANDOFF_ROWS {
            return Err(IntegrationStoreError::NotificationHandoffFull);
        }
        connection.execute(
            "INSERT INTO integration_notification_handoff(dedup_key, event_json, queued_at_ms)
             VALUES (?1, ?2, ?3)",
            params![event.dedup_key.as_str(), event_json, queued_at_ms],
        )?;
    }
    Ok(())
}

fn persist_record(
    connection: &Connection,
    project_id: &ProjectId,
    kind: IntegrationKindV1,
    attempted_at_ms: i64,
    record: &impl serde::Serialize,
) -> Result<(), IntegrationStoreError> {
    if attempted_at_ms < 0 {
        return Err(IntegrationStoreError::InvalidTimestamp);
    }
    let json = serde_json::to_string(record)?;
    connection.execute(
        "INSERT INTO project_integration_records(project_id, kind, attempted_at_ms, record_json)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(project_id, kind) DO UPDATE SET
             attempted_at_ms = excluded.attempted_at_ms,
             record_json = excluded.record_json",
        params![project_id.as_str(), kind.as_str(), attempted_at_ms, json],
    )?;
    Ok(())
}

fn load_record(
    connection: &Connection,
    project_id: &ProjectId,
    kind: IntegrationKindV1,
) -> Result<Option<String>, IntegrationStoreError> {
    connection
        .query_row(
            "SELECT record_json FROM project_integration_records
             WHERE project_id = ?1 AND kind = ?2",
            params![project_id.as_str(), kind.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(IntegrationStoreError::Sqlite)
}

fn decode_errors(
    expected_project: &ProjectId,
    json: &str,
) -> Result<ProjectErrorsRecordV1, IntegrationStoreError> {
    let record: ProjectErrorsRecordV1 = serde_json::from_str(json)?;
    record.validate()?;
    if &record.project_id != expected_project {
        return Err(IntegrationStoreError::CorruptRecordBinding);
    }
    Ok(record)
}

fn decode_updates(
    expected_project: &ProjectId,
    json: &str,
) -> Result<ProjectUpdatesRecordV1, IntegrationStoreError> {
    let record: ProjectUpdatesRecordV1 = serde_json::from_str(json)?;
    record.validate()?;
    if &record.project_id != expected_project {
        return Err(IntegrationStoreError::CorruptRecordBinding);
    }
    Ok(record)
}

fn migrate_schema(connection: &Connection) -> Result<(), IntegrationStoreError> {
    let version: i64 = connection.query_row(
        "SELECT integer_value FROM integration_meta WHERE key = 'schema_version'",
        [],
        |row| row.get(0),
    )?;
    match version {
        INTEGRATION_STORE_SCHEMA_VERSION => Ok(()),
        LEGACY_INTEGRATION_STORE_SCHEMA_VERSION => {
            connection.execute_batch(
                "
                CREATE TABLE integration_notification_handoff (
                    dedup_key TEXT PRIMARY KEY,
                    event_json TEXT NOT NULL,
                    queued_at_ms INTEGER NOT NULL CHECK(queued_at_ms >= 0)
                ) STRICT;
                UPDATE integration_meta
                   SET integer_value = 2
                 WHERE key = 'schema_version';
                ",
            )?;
            Ok(())
        }
        _ => Err(IntegrationStoreError::UnsupportedSchemaVersion(version)),
    }
}

fn validate_schema(connection: &Connection) -> Result<(), IntegrationStoreError> {
    let version: i64 = connection.query_row(
        "SELECT integer_value FROM integration_meta WHERE key = 'schema_version'",
        [],
        |row| row.get(0),
    )?;
    if version != INTEGRATION_STORE_SCHEMA_VERSION {
        return Err(IntegrationStoreError::UnsupportedSchemaVersion(version));
    }
    for table in [
        "integration_meta",
        "project_integration_records",
        "integration_notification_handoff",
    ] {
        let exists = connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            return Err(IntegrationStoreError::CorruptSchema(table));
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum IntegrationStoreError {
    #[error("integration SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("integration JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Contract(#[from] IntegrationContractError),
    #[error(transparent)]
    NotificationContract(#[from] crate::notifications::NotificationContractError),
    #[error("controller store prerequisite failed: {0}")]
    ControlStore(super::StoreError),
    #[error("integration store schema version {0} is unsupported")]
    UnsupportedSchemaVersion(i64),
    #[error("integration store schema is missing required table {0}")]
    CorruptSchema(&'static str),
    #[error("integration record is bound to another project")]
    CorruptRecordBinding,
    #[error("integration attempt timestamp must be non-negative")]
    InvalidTimestamp,
    #[error("integration notification handoff limit must be between 1 and 100")]
    InvalidNotificationLimit,
    #[error("integration notification handoff contains a corrupt event")]
    CorruptNotificationHandoff,
    #[error("integration notification handoff reused a deduplication key with different content")]
    NotificationHandoffConflict,
    #[error("integration notification handoff reached its bounded capacity")]
    NotificationHandoffFull,
    #[error("integration notification handoff acknowledgement did not match a pending event")]
    NotificationHandoffMismatch,
    #[error(transparent)]
    NotificationPlanning(#[from] crate::notification_planner::NotificationPlanningError),
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::{
        domain::EvidenceDigest,
        integrations::{
            ErrorInsightV1, ErrorLevelV1, InsightPriorityV1, InsightSourceV1, ProjectErrorsDataV1,
            ProjectUpdatesDataV1,
        },
    };

    use super::*;

    fn project(value: &str) -> ProjectId {
        value
            .parse()
            .unwrap_or_else(|error| panic!("project {value}: {error}"))
    }

    fn empty_errors(project_id: ProjectId, now_ms: i64) -> ProjectErrorsDataV1 {
        ProjectErrorsDataV1 {
            schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
            project_id,
            unresolved_groups: 0,
            truncated: false,
            total_events: 0,
            affected_users: 0,
            highest_level: ErrorLevelV1::Unknown,
            groups: Vec::new(),
            insight: ErrorInsightV1 {
                source: InsightSourceV1::Deterministic,
                priority: InsightPriorityV1::None,
                summary: "Открытых ошибок нет.".to_owned(),
                actions: Vec::new(),
                generated_at_ms: now_ms,
                input_digest: EvidenceDigest::sha256("empty error facts"),
            },
            analysis_error: None,
        }
    }

    #[test]
    fn last_success_survives_failure_and_reopen() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
        let path = directory.path().join("integrations.sqlite");
        let store = IntegrationStore::open(&path)
            .unwrap_or_else(|error| panic!("open integration store: {error}"));
        let project_id = project("rimg");
        let data = empty_errors(project_id.clone(), 10);
        store
            .record_errors_success(10, data.clone())
            .unwrap_or_else(|error| panic!("record success: {error}"));
        store
            .record_errors_failure(
                &project_id,
                20,
                IntegrationFailureV1::new("timeout", "GlitchTip не ответил.")
                    .unwrap_or_else(|error| panic!("failure: {error}")),
            )
            .unwrap_or_else(|error| panic!("record failure: {error}"));
        drop(store);

        let reopened = IntegrationStore::open(path)
            .unwrap_or_else(|error| panic!("reopen integration store: {error}"));
        let record = reopened
            .project_errors(&project_id)
            .unwrap_or_else(|error| panic!("load errors: {error}"))
            .unwrap_or_else(|| panic!("stored error record"));
        assert_eq!(record.attempted_at_ms, 20);
        assert_eq!(record.successful_at_ms, Some(10));
        assert_eq!(record.data, Some(data));
        assert_eq!(
            record
                .collection_error
                .as_ref()
                .map(|failure| failure.code.as_str()),
            Some("timeout")
        );
    }

    #[test]
    fn integration_transition_and_notification_handoff_survive_restart_together() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
        let path = directory.path().join("integrations.sqlite");
        let project_id = project("rimg");
        let store = IntegrationStore::open(&path)
            .unwrap_or_else(|error| panic!("open integration store: {error}"));
        store
            .record_errors_success(10, empty_errors(project_id.clone(), 10))
            .unwrap_or_else(|error| panic!("record success: {error}"));
        store
            .record_errors_failure_with_notifications(
                &project_id,
                20,
                IntegrationFailureV1::new("timeout", "Provider timed out.")
                    .unwrap_or_else(|error| panic!("failure: {error}")),
            )
            .unwrap_or_else(|error| panic!("record transition: {error}"));
        drop(store);

        let reopened = IntegrationStore::open(&path)
            .unwrap_or_else(|error| panic!("reopen integration store: {error}"));
        let record = reopened
            .project_errors(&project_id)
            .unwrap_or_else(|error| panic!("load errors: {error}"))
            .unwrap_or_else(|| panic!("stored error record"));
        assert_eq!(
            record
                .collection_error
                .as_ref()
                .map(|failure| failure.code.as_str()),
            Some("timeout")
        );
        let events = reopened
            .pending_notification_events(10)
            .unwrap_or_else(|error| panic!("load handoff: {error}"));
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].kind,
            crate::notifications::NotificationKindV1::ErrorCollectionFailed
        );
        reopened
            .acknowledge_notification_event(&events[0])
            .unwrap_or_else(|error| panic!("acknowledge handoff: {error}"));
        assert!(
            reopened
                .pending_notification_events(10)
                .unwrap_or_else(|error| panic!("reload handoff: {error}"))
                .is_empty()
        );
    }

    #[test]
    fn schema_v1_store_adds_an_empty_durable_notification_handoff() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
        let path = directory.path().join("integrations.sqlite");
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("open legacy integration store: {error}"));
        connection
            .execute_batch(
                "CREATE TABLE integration_meta (
                    key TEXT PRIMARY KEY,
                    integer_value INTEGER NOT NULL
                 ) STRICT;
                 INSERT INTO integration_meta(key, integer_value)
                    VALUES ('schema_version', 1);
                 CREATE TABLE project_integration_records (
                    project_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('errors', 'updates')),
                    attempted_at_ms INTEGER NOT NULL CHECK(attempted_at_ms >= 0),
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(project_id, kind)
                 ) STRICT;",
            )
            .unwrap_or_else(|error| panic!("create legacy integration store: {error}"));
        drop(connection);

        let migrated = IntegrationStore::open(&path)
            .unwrap_or_else(|error| panic!("migrate integration store: {error}"));
        assert!(
            migrated
                .pending_notification_events(10)
                .unwrap_or_else(|error| panic!("load migrated handoff: {error}"))
                .is_empty()
        );
    }

    #[test]
    fn integration_records_are_project_and_kind_scoped() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
        let store = IntegrationStore::open(directory.path().join("integrations.sqlite"))
            .unwrap_or_else(|error| panic!("open integration store: {error}"));
        let rimg = project("rimg");
        let other = project("other");
        store
            .record_errors_success(10, empty_errors(rimg.clone(), 10))
            .unwrap_or_else(|error| panic!("record errors: {error}"));
        store
            .record_updates_success(
                11,
                ProjectUpdatesDataV1 {
                    schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
                    project_id: rimg.clone(),
                    truncated: false,
                    updates: Vec::new(),
                },
            )
            .unwrap_or_else(|error| panic!("record updates: {error}"));
        assert!(
            store
                .project_errors(&other)
                .unwrap_or_else(|error| panic!("other errors: {error}"))
                .is_none()
        );
        assert!(
            store
                .project_updates(&rimg)
                .unwrap_or_else(|error| panic!("rimg updates: {error}"))
                .is_some()
        );
    }
}
