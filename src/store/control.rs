use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use uuid::Uuid;

use crate::domain::{DashboardEvent, EVENT_PROTOCOL_VERSION, EventEnvelope};

use super::{StoreError, lock_connection, verify_sqlite_version};

const EVENT_HISTORY_LIMIT: i64 = 512;
const CONTROL_SCHEMA_VERSION: i64 = 2;

#[derive(Clone, Debug)]
pub struct ControlStore {
    connection: Arc<Mutex<Connection>>,
}

#[derive(Clone, Debug)]
pub struct EventHistoryWindow {
    pub bounds: Option<(u64, u64)>,
    pub events_after: Vec<EventEnvelope>,
    pub latest_event: Option<EventEnvelope>,
}

impl ControlStore {
    // Keeping the complete STRICT schema in one immediate transaction makes a partially installed
    // control journal impossible; splitting the declarative DDL only to satisfy a line counter would
    // obscure that atomic boundary.
    #[allow(clippy::too_many_lines)]
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        verify_sqlite_version()?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS controller_meta (
                key TEXT PRIMARY KEY,
                integer_value INTEGER NOT NULL
            ) STRICT;
            INSERT OR IGNORE INTO controller_meta(key, integer_value)
                VALUES ('event_sequence', 0);

            CREATE TABLE IF NOT EXISTS observation_operations (
                operation_id TEXT PRIMARY KEY,
                started_at_ms INTEGER NOT NULL,
                completed_at_ms INTEGER,
                result TEXT NOT NULL CHECK(result IN ('running', 'succeeded', 'failed')),
                error_code TEXT
            ) STRICT;

            CREATE TABLE IF NOT EXISTS dashboard_events (
                sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
                emitted_at_ms INTEGER NOT NULL,
                event_name TEXT NOT NULL,
                event_json TEXT NOT NULL
            ) STRICT;
            CREATE INDEX IF NOT EXISTS dashboard_events_emitted_at
                ON dashboard_events(emitted_at_ms);

            CREATE TABLE IF NOT EXISTS tab_leases (
                user_id TEXT PRIMARY KEY,
                lease_id TEXT NOT NULL UNIQUE,
                generation INTEGER NOT NULL CHECK(generation > 0),
                acquired_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > acquired_at_ms)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS deployment_requests (
                request_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                target_key TEXT NOT NULL,
                target_commit TEXT,
                operation_kind TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                UNIQUE(project_id, target_key, operation_kind),
                CHECK((target_key = '-' AND target_commit IS NULL)
                    OR (target_key = target_commit AND target_commit IS NOT NULL))
            ) STRICT;

            CREATE TABLE IF NOT EXISTS operation_attempts (
                operation_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL REFERENCES deployment_requests(request_id),
                attempt_id TEXT NOT NULL UNIQUE,
                attempt_number INTEGER NOT NULL CHECK(attempt_number > 0),
                phase TEXT NOT NULL,
                result TEXT NOT NULL,
                operation_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                UNIQUE(request_id, attempt_number)
            ) STRICT;
            CREATE INDEX IF NOT EXISTS operation_attempts_request
                ON operation_attempts(request_id, attempt_number DESC);

            CREATE TABLE IF NOT EXISTS controller_action_grants (
                nonce TEXT PRIMARY KEY,
                grant_digest TEXT NOT NULL,
                request_id TEXT NOT NULL REFERENCES deployment_requests(request_id),
                attempt_id TEXT NOT NULL REFERENCES operation_attempts(attempt_id),
                consumed_at_ms INTEGER NOT NULL
            ) STRICT;

            CREATE TABLE IF NOT EXISTS transport_deliveries (
                channel TEXT NOT NULL,
                delivery_id TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                request_id TEXT NOT NULL REFERENCES deployment_requests(request_id),
                received_at_ms INTEGER NOT NULL,
                PRIMARY KEY(channel, delivery_id)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS operation_transitions (
                attempt_id TEXT NOT NULL REFERENCES operation_attempts(attempt_id),
                sequence INTEGER NOT NULL CHECK(sequence > 0),
                transition_json TEXT NOT NULL,
                occurred_at_ms INTEGER NOT NULL,
                PRIMARY KEY(attempt_id, sequence)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workflow_requests (
                request_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                workflow_policy_digest TEXT NOT NULL,
                source_sha TEXT NOT NULL,
                operation_kind TEXT NOT NULL CHECK(operation_kind IN ('deploy')),
                source_sequence INTEGER NOT NULL CHECK(source_sequence > 0),
                source_attestation_digest TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 3),
                state TEXT NOT NULL CHECK(state IN ('active', 'superseded', 'terminal')),
                superseded_by_request_id TEXT REFERENCES workflow_requests(request_id),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
                UNIQUE(project_id, workflow_policy_digest, source_sha, operation_kind),
                CHECK((state = 'superseded') = (superseded_by_request_id IS NOT NULL))
            ) STRICT;
            CREATE INDEX IF NOT EXISTS workflow_requests_project_state
                ON workflow_requests(project_id, state, created_at_ms);

            CREATE TABLE IF NOT EXISTS workflow_project_heads (
                project_id TEXT PRIMARY KEY,
                source_sequence INTEGER NOT NULL CHECK(source_sequence > 0),
                source_sha TEXT NOT NULL,
                request_id TEXT NOT NULL REFERENCES workflow_requests(request_id),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workflow_triggers (
                channel TEXT NOT NULL CHECK(channel IN (
                    'github_webhook', 'source_reconciliation', 'direct_push'
                )),
                delivery_id TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                request_id TEXT NOT NULL REFERENCES workflow_requests(request_id),
                received_at_ms INTEGER NOT NULL CHECK(received_at_ms >= 0),
                PRIMARY KEY(channel, delivery_id)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workflow_attempts (
                attempt_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL REFERENCES workflow_requests(request_id),
                attempt_number INTEGER NOT NULL CHECK(attempt_number > 0),
                preparation_key TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'queued', 'waiting_for_mutation', 'running', 'succeeded', 'failed',
                    'superseded', 'needs_reconcile'
                )),
                mutation_state TEXT NOT NULL CHECK(mutation_state IN (
                    'not_started', 'owned', 'needs_reconcile', 'complete'
                )),
                cleanup_state TEXT NOT NULL CHECK(cleanup_state IN ('complete', 'pending')),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
                terminal_at_ms INTEGER,
                UNIQUE(request_id, attempt_number),
                CHECK((state IN ('succeeded', 'failed', 'superseded')) =
                    (terminal_at_ms IS NOT NULL))
            ) STRICT;
            CREATE INDEX IF NOT EXISTS workflow_attempts_state
                ON workflow_attempts(state, created_at_ms);

            CREATE TABLE IF NOT EXISTS workflow_nodes (
                attempt_id TEXT NOT NULL REFERENCES workflow_attempts(attempt_id),
                node_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                node_kind TEXT NOT NULL,
                activation TEXT NOT NULL CHECK(activation IN ('always', 'on_mutation_failure')),
                profile_id TEXT NOT NULL,
                worker_pool TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'dormant', 'blocked', 'ready', 'leased', 'succeeded', 'failed',
                    'cancelled', 'needs_reconcile'
                )),
                lease_generation INTEGER NOT NULL DEFAULT 0 CHECK(lease_generation >= 0),
                output_digest TEXT,
                receipt_digest TEXT,
                completed_at_ms INTEGER,
                PRIMARY KEY(attempt_id, node_id),
                UNIQUE(attempt_id, ordinal),
                CHECK((state = 'succeeded') = (output_digest IS NOT NULL)),
                CHECK((state IN ('succeeded', 'failed', 'cancelled', 'needs_reconcile')) =
                    (completed_at_ms IS NOT NULL))
            ) STRICT;
            CREATE INDEX IF NOT EXISTS workflow_nodes_ready
                ON workflow_nodes(state, worker_pool, ordinal);

            CREATE TABLE IF NOT EXISTS workflow_node_dependencies (
                attempt_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                dependency_node_id TEXT NOT NULL,
                PRIMARY KEY(attempt_id, node_id, dependency_node_id),
                FOREIGN KEY(attempt_id, node_id)
                    REFERENCES workflow_nodes(attempt_id, node_id),
                FOREIGN KEY(attempt_id, dependency_node_id)
                    REFERENCES workflow_nodes(attempt_id, node_id)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workflow_lease_journal (
                lease_id TEXT PRIMARY KEY,
                attempt_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation > 0),
                worker_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                expected_input_digest TEXT NOT NULL,
                lease_digest TEXT NOT NULL UNIQUE,
                lease_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'active', 'expired', 'committed', 'revoked'
                )),
                leased_at_ms INTEGER NOT NULL CHECK(leased_at_ms >= 0),
                expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > leased_at_ms),
                closed_at_ms INTEGER,
                receipt_digest TEXT,
                UNIQUE(attempt_id, node_id, generation),
                FOREIGN KEY(attempt_id, node_id)
                    REFERENCES workflow_nodes(attempt_id, node_id),
                CHECK((state = 'active') = (closed_at_ms IS NULL))
            ) STRICT;
            CREATE UNIQUE INDEX IF NOT EXISTS workflow_active_node_lease
                ON workflow_lease_journal(attempt_id, node_id) WHERE state = 'active';

            CREATE TABLE IF NOT EXISTS workflow_node_receipts (
                receipt_digest TEXT PRIMARY KEY,
                attempt_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                lease_id TEXT NOT NULL UNIQUE REFERENCES workflow_lease_journal(lease_id),
                receipt_json TEXT NOT NULL,
                committed_at_ms INTEGER NOT NULL CHECK(committed_at_ms >= 0),
                UNIQUE(attempt_id, node_id),
                FOREIGN KEY(attempt_id, node_id)
                    REFERENCES workflow_nodes(attempt_id, node_id)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workflow_reductions (
                attempt_id TEXT PRIMARY KEY REFERENCES workflow_attempts(attempt_id),
                reduce_node_id TEXT NOT NULL,
                receipt_digest TEXT NOT NULL UNIQUE,
                receipt_json TEXT NOT NULL,
                committed_at_ms INTEGER NOT NULL CHECK(committed_at_ms >= 0),
                FOREIGN KEY(attempt_id, reduce_node_id)
                    REFERENCES workflow_nodes(attempt_id, node_id)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workflow_mutation_locks (
                project_id TEXT PRIMARY KEY,
                attempt_id TEXT NOT NULL UNIQUE REFERENCES workflow_attempts(attempt_id),
                state TEXT NOT NULL CHECK(state IN ('held', 'needs_reconcile')),
                acquired_at_ms INTEGER NOT NULL CHECK(acquired_at_ms >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= acquired_at_ms)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workflow_transitions (
                attempt_id TEXT NOT NULL REFERENCES workflow_attempts(attempt_id),
                sequence INTEGER NOT NULL CHECK(sequence > 0),
                subject_kind TEXT NOT NULL CHECK(subject_kind IN ('attempt', 'node', 'lease')),
                subject_id TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                reason TEXT NOT NULL,
                evidence_digest TEXT,
                occurred_at_ms INTEGER NOT NULL CHECK(occurred_at_ms >= 0),
                PRIMARY KEY(attempt_id, sequence)
            ) STRICT;

            CREATE TABLE IF NOT EXISTS workflow_scheduler_cursor (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                last_project_id TEXT,
                remaining_weight INTEGER NOT NULL DEFAULT 0 CHECK(remaining_weight >= 0)
            ) STRICT;
            INSERT OR IGNORE INTO workflow_scheduler_cursor(
                singleton, last_project_id, remaining_weight
            ) VALUES (1, NULL, 0);
            ",
        )?;
        initialize_control_schema_version(&transaction)?;
        validate_control_schema(&transaction)?;
        transaction.commit()?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub(crate) fn immediate_transaction<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut connection = lock_connection(&self.connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let output = operation(&transaction)?;
        transaction.commit()?;
        Ok(output)
    }

    pub(crate) fn read_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let connection = lock_connection(&self.connection)?;
        operation(&connection)
    }

    pub fn start_observation(&self, started_at_ms: i64) -> Result<Uuid, StoreError> {
        let operation_id = Uuid::new_v4();
        let connection = lock_connection(&self.connection)?;
        connection.execute(
            "INSERT INTO observation_operations(
                operation_id, started_at_ms, result
             ) VALUES (?1, ?2, 'running')",
            params![operation_id.to_string(), started_at_ms],
        )?;
        Ok(operation_id)
    }

    pub fn recover_interrupted_observations(
        &self,
        recovered_at_ms: i64,
    ) -> Result<usize, StoreError> {
        let connection = lock_connection(&self.connection)?;
        let changed = connection.execute(
            "UPDATE observation_operations
             SET completed_at_ms = MAX(started_at_ms, ?1),
                 result = 'failed',
                 error_code = 'controller_restarted'
             WHERE result = 'running'",
            [recovered_at_ms],
        )?;
        Ok(changed)
    }

    pub fn finish_observation(
        &self,
        operation_id: Uuid,
        completed_at_ms: i64,
        error_code: Option<&str>,
    ) -> Result<(), StoreError> {
        let result = if error_code.is_some() {
            "failed"
        } else {
            "succeeded"
        };
        let connection = lock_connection(&self.connection)?;
        let changed = connection.execute(
            "UPDATE observation_operations
             SET completed_at_ms = ?2, result = ?3, error_code = ?4
             WHERE operation_id = ?1 AND result = 'running'",
            params![
                operation_id.to_string(),
                completed_at_ms,
                result,
                error_code
            ],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StoreError::ObservationNotRunning(operation_id))
        }
    }

    pub fn append_event(
        &self,
        emitted_at_ms: i64,
        event: DashboardEvent,
    ) -> Result<EventEnvelope, StoreError> {
        let mut connection = lock_connection(&self.connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: i64 = transaction.query_row(
            "SELECT integer_value FROM controller_meta WHERE key = 'event_sequence'",
            [],
            |row| row.get(0),
        )?;
        let current = u64::try_from(current).map_err(|_| StoreError::SequenceRange)?;
        let sequence = current
            .checked_add(1)
            .ok_or(StoreError::SequenceExhausted)?;
        let sequence_i64 = i64::try_from(sequence).map_err(|_| StoreError::SequenceRange)?;
        let event_json = serde_json::to_string(&event)?;
        transaction.execute(
            "INSERT INTO dashboard_events(sequence, emitted_at_ms, event_name, event_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![sequence_i64, emitted_at_ms, event.event_name(), event_json],
        )?;
        transaction.execute(
            "UPDATE controller_meta SET integer_value = ?1 WHERE key = 'event_sequence'",
            [sequence_i64],
        )?;
        let delete_through = sequence_i64.saturating_sub(EVENT_HISTORY_LIMIT);
        transaction.execute(
            "DELETE FROM dashboard_events WHERE sequence <= ?1",
            [delete_through],
        )?;
        transaction.commit()?;
        Ok(EventEnvelope {
            version: EVENT_PROTOCOL_VERSION,
            sequence,
            emitted_at_ms,
            event,
        })
    }

    pub fn event_bounds(&self) -> Result<Option<(u64, u64)>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        let (oldest, latest) = connection.query_row(
            "SELECT MIN(sequence), MAX(sequence) FROM dashboard_events",
            [],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )?;
        oldest
            .zip(latest)
            .map(|(oldest, latest)| {
                Ok::<_, StoreError>((
                    u64::try_from(oldest).map_err(|_| StoreError::SequenceRange)?,
                    u64::try_from(latest).map_err(|_| StoreError::SequenceRange)?,
                ))
            })
            .transpose()
    }

    pub fn event_history_window(
        &self,
        after: Option<u64>,
        limit: usize,
    ) -> Result<EventHistoryWindow, StoreError> {
        let after = after
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StoreError::SequenceRange)?;
        let limit = i64::try_from(limit).map_err(|_| StoreError::SequenceRange)?;
        let connection = lock_connection(&self.connection)?;
        let (oldest, latest) = connection.query_row(
            "SELECT MIN(sequence), MAX(sequence) FROM dashboard_events",
            [],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )?;
        let bounds = oldest
            .zip(latest)
            .map(|(oldest, latest)| {
                Ok::<_, StoreError>((
                    u64::try_from(oldest).map_err(|_| StoreError::SequenceRange)?,
                    u64::try_from(latest).map_err(|_| StoreError::SequenceRange)?,
                ))
            })
            .transpose()?;
        let latest_event = connection
            .query_row(
                "SELECT sequence, emitted_at_ms, event_json
                 FROM dashboard_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
            .map(decode_event_row)
            .transpose()?;
        let mut events_after = Vec::new();
        if let Some(after) = after {
            let mut statement = connection.prepare(
                "SELECT sequence, emitted_at_ms, event_json
                 FROM dashboard_events
                 WHERE sequence > ?1
                 ORDER BY sequence ASC
                 LIMIT ?2",
            )?;
            let rows = statement.query_map(params![after, limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                events_after.push(decode_event_row(row?)?);
            }
        }
        Ok(EventHistoryWindow {
            bounds,
            events_after,
            latest_event,
        })
    }

    pub fn events_after(
        &self,
        sequence: u64,
        limit: usize,
    ) -> Result<Vec<EventEnvelope>, StoreError> {
        let sequence = i64::try_from(sequence).map_err(|_| StoreError::SequenceRange)?;
        let limit = i64::try_from(limit).map_err(|_| StoreError::SequenceRange)?;
        let connection = lock_connection(&self.connection)?;
        let mut statement = connection.prepare(
            "SELECT sequence, emitted_at_ms, event_json
             FROM dashboard_events
             WHERE sequence > ?1
             ORDER BY sequence ASC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![sequence, limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (sequence, emitted_at_ms, event_json) = row?;
            events.push(EventEnvelope {
                version: EVENT_PROTOCOL_VERSION,
                sequence: u64::try_from(sequence).map_err(|_| StoreError::SequenceRange)?,
                emitted_at_ms,
                event: serde_json::from_str(&event_json)?,
            });
        }
        Ok(events)
    }

    pub fn latest_event(&self) -> Result<Option<EventEnvelope>, StoreError> {
        let connection = lock_connection(&self.connection)?;
        let row = connection
            .query_row(
                "SELECT sequence, emitted_at_ms, event_json
                 FROM dashboard_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(sequence, emitted_at_ms, event_json)| {
            Ok(EventEnvelope {
                version: EVENT_PROTOCOL_VERSION,
                sequence: u64::try_from(sequence).map_err(|_| StoreError::SequenceRange)?,
                emitted_at_ms,
                event: serde_json::from_str(&event_json)?,
            })
        })
        .transpose()
    }
}

fn initialize_control_schema_version(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let version = transaction
        .query_row(
            "SELECT integer_value FROM controller_meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    match version {
        Some(CONTROL_SCHEMA_VERSION) => Ok(()),
        Some(1) => {
            transaction.execute(
                "UPDATE controller_meta SET integer_value = ?1 WHERE key = 'schema_version'",
                [CONTROL_SCHEMA_VERSION],
            )?;
            Ok(())
        }
        Some(actual) => Err(StoreError::UnsupportedControlSchemaVersion {
            actual,
            supported: CONTROL_SCHEMA_VERSION,
        }),
        None => {
            transaction.execute(
                "INSERT INTO controller_meta(key, integer_value)
                 VALUES ('schema_version', ?1)",
                [CONTROL_SCHEMA_VERSION],
            )?;
            Ok(())
        }
    }
}

fn validate_control_schema(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let required_tables = [
        "controller_meta",
        "observation_operations",
        "dashboard_events",
        "tab_leases",
        "deployment_requests",
        "operation_attempts",
        "controller_action_grants",
        "transport_deliveries",
        "operation_transitions",
        "workflow_requests",
        "workflow_project_heads",
        "workflow_triggers",
        "workflow_attempts",
        "workflow_nodes",
        "workflow_node_dependencies",
        "workflow_lease_journal",
        "workflow_node_receipts",
        "workflow_reductions",
        "workflow_mutation_locks",
        "workflow_transitions",
        "workflow_scheduler_cursor",
    ];
    for table in required_tables {
        if !control_table_exists(transaction, table)? {
            return Err(StoreError::CorruptControlSchema(table));
        }
    }
    for (table, column) in [
        ("observation_operations", "error_code"),
        ("dashboard_events", "event_json"),
        ("tab_leases", "generation"),
        ("deployment_requests", "target_key"),
        ("operation_attempts", "operation_json"),
        ("controller_action_grants", "grant_digest"),
        ("transport_deliveries", "payload_digest"),
        ("operation_transitions", "transition_json"),
        ("workflow_requests", "manifest_json"),
        ("workflow_project_heads", "source_sequence"),
        ("workflow_triggers", "payload_digest"),
        ("workflow_attempts", "preparation_key"),
        ("workflow_nodes", "worker_pool"),
        ("workflow_node_dependencies", "dependency_node_id"),
        ("workflow_lease_journal", "lease_json"),
        ("workflow_node_receipts", "receipt_json"),
        ("workflow_reductions", "receipt_json"),
        ("workflow_mutation_locks", "state"),
        ("workflow_transitions", "reason"),
        ("workflow_scheduler_cursor", "last_project_id"),
        ("workflow_scheduler_cursor", "remaining_weight"),
    ] {
        if !control_column_exists(transaction, table, column)? {
            return Err(StoreError::CorruptControlSchema(column));
        }
    }
    Ok(())
}

fn control_table_exists(
    transaction: &Transaction<'_>,
    table: &'static str,
) -> Result<bool, StoreError> {
    Ok(transaction
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn control_column_exists(
    transaction: &Transaction<'_>,
    table: &'static str,
    column: &'static str,
) -> Result<bool, StoreError> {
    let mut statement = transaction.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for existing in columns {
        if existing? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn decode_event_row(
    (sequence, emitted_at_ms, event_json): (i64, i64, String),
) -> Result<EventEnvelope, StoreError> {
    Ok(EventEnvelope {
        version: EVENT_PROTOCOL_VERSION,
        sequence: u64::try_from(sequence).map_err(|_| StoreError::SequenceRange)?,
        emitted_at_ms,
        event: serde_json::from_str(&event_json)?,
    })
}
