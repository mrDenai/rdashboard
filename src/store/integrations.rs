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
};

use super::{lock_connection, verify_sqlite_version};

const INTEGRATION_STORE_SCHEMA_VERSION: i64 = 1;

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
        let record = ProjectErrorsRecordV1 {
            schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
            project_id: data.project_id.clone(),
            attempted_at_ms,
            successful_at_ms: Some(attempted_at_ms),
            collection_error: None,
            data: Some(data),
        };
        record.validate()?;
        self.persist_record(
            &record.project_id,
            IntegrationKindV1::Errors,
            attempted_at_ms,
            &record,
        )?;
        Ok(record)
    }

    pub fn record_updates_success(
        &self,
        attempted_at_ms: i64,
        data: ProjectUpdatesDataV1,
    ) -> Result<ProjectUpdatesRecordV1, IntegrationStoreError> {
        let record = ProjectUpdatesRecordV1 {
            schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
            project_id: data.project_id.clone(),
            attempted_at_ms,
            successful_at_ms: Some(attempted_at_ms),
            collection_error: None,
            data: Some(data),
        };
        record.validate()?;
        self.persist_record(
            &record.project_id,
            IntegrationKindV1::Updates,
            attempted_at_ms,
            &record,
        )?;
        Ok(record)
    }

    pub fn record_errors_failure(
        &self,
        project_id: &ProjectId,
        attempted_at_ms: i64,
        failure: IntegrationFailureV1,
    ) -> Result<ProjectErrorsRecordV1, IntegrationStoreError> {
        failure.validate()?;
        let mut connection =
            lock_connection(&self.connection).map_err(IntegrationStoreError::ControlStore)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = load_record(&transaction, project_id, IntegrationKindV1::Errors)?
            .map(|json| decode_errors(project_id, &json))
            .transpose()?;
        let record = ProjectErrorsRecordV1 {
            schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
            project_id: project_id.clone(),
            attempted_at_ms,
            successful_at_ms: previous.as_ref().and_then(|record| record.successful_at_ms),
            collection_error: Some(failure),
            data: previous.and_then(|record| record.data),
        };
        record.validate()?;
        persist_record(
            &transaction,
            project_id,
            IntegrationKindV1::Errors,
            attempted_at_ms,
            &record,
        )?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn record_updates_failure(
        &self,
        project_id: &ProjectId,
        attempted_at_ms: i64,
        failure: IntegrationFailureV1,
    ) -> Result<ProjectUpdatesRecordV1, IntegrationStoreError> {
        failure.validate()?;
        let mut connection =
            lock_connection(&self.connection).map_err(IntegrationStoreError::ControlStore)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = load_record(&transaction, project_id, IntegrationKindV1::Updates)?
            .map(|json| decode_updates(project_id, &json))
            .transpose()?;
        let record = ProjectUpdatesRecordV1 {
            schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
            project_id: project_id.clone(),
            attempted_at_ms,
            successful_at_ms: previous.as_ref().and_then(|record| record.successful_at_ms),
            collection_error: Some(failure),
            data: previous.and_then(|record| record.data),
        };
        record.validate()?;
        persist_record(
            &transaction,
            project_id,
            IntegrationKindV1::Updates,
            attempted_at_ms,
            &record,
        )?;
        transaction.commit()?;
        Ok(record)
    }

    fn persist_record<T: serde::Serialize>(
        &self,
        project_id: &ProjectId,
        kind: IntegrationKindV1,
        attempted_at_ms: i64,
        record: &T,
    ) -> Result<(), IntegrationStoreError> {
        let mut connection =
            lock_connection(&self.connection).map_err(IntegrationStoreError::ControlStore)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        persist_record(&transaction, project_id, kind, attempted_at_ms, record)?;
        transaction.commit()?;
        Ok(())
    }
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

fn validate_schema(connection: &Connection) -> Result<(), IntegrationStoreError> {
    let version: i64 = connection.query_row(
        "SELECT integer_value FROM integration_meta WHERE key = 'schema_version'",
        [],
        |row| row.get(0),
    )?;
    if version != INTEGRATION_STORE_SCHEMA_VERSION {
        return Err(IntegrationStoreError::UnsupportedSchemaVersion(version));
    }
    for table in ["integration_meta", "project_integration_records"] {
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
