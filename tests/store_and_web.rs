use std::{path::Path, str::FromStr, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt as _;
use rdashboard::{
    controller::DurableController,
    domain::{
        ControlSummary, DashboardEvent, DashboardSnapshot, EvidenceDigest, GitCommitId,
        HostHistoryWindowKind, HostTelemetry, ObservationStatus, ProjectCondition, ProjectId,
        ProjectResourceTelemetry, ProjectTelemetry, PsiMeasurement,
    },
    integrations::{
        ErrorInsightV1, ErrorLevelV1, InsightPriorityV1, InsightSourceV1, IntegrationFailureV1,
        PROJECT_INTEGRATION_SCHEMA_VERSION, ProjectErrorsDataV1, ProjectUpdatesDataV1,
    },
    source::SourceTreeObservationV1,
    store::{
        ControlStore, IntegrationStore, MINIMUM_SAFE_SQLITE_VERSION_NUMBER, MetricsStore,
        PROJECT_REPOSITORY_SAMPLE_INTERVAL_MS, RepositorySampleWrite, StoreError,
    },
    unix_time_ms,
    web::{DashboardState, EventHub, HubError, RequestedAfter, router},
};
use tempfile::tempdir;
use tower::ServiceExt as _;
use uuid::Uuid;

fn host_sample(observed_at_ms: i64) -> HostTelemetry {
    HostTelemetry {
        observed_at_ms,
        status: ObservationStatus::Fresh,
        cpu_percent: Some(12.5),
        load_1: Some(0.2),
        load_5: Some(0.3),
        load_15: Some(0.4),
        memory_total_bytes: Some(1024),
        memory_available_bytes: Some(512),
        swap_total_bytes: Some(0),
        swap_free_bytes: Some(0),
        disk_total_bytes: Some(4096),
        disk_available_bytes: Some(2048),
        network_rx_bytes: Some(100),
        network_tx_bytes: Some(200),
        network_rx_bytes_per_second: Some(10),
        network_tx_bytes_per_second: Some(20),
        psi: PsiMeasurement {
            cpu_some_avg10: Some(0.0),
            memory_some_avg10: Some(0.0),
            io_some_avg10: Some(0.0),
        },
        partial_reasons: Vec::new(),
    }
}

fn snapshot(observed_at_ms: i64, operation_id: Uuid) -> DashboardSnapshot {
    DashboardSnapshot {
        generated_at_ms: observed_at_ms,
        host: host_sample(observed_at_ms),
        projects: Vec::new(),
        control: ControlSummary {
            sqlite_version: "fixture".to_owned(),
            observation_operation_id: operation_id,
            sample_interval_seconds: 5,
        },
    }
}

fn project_sample(observed_at_ms: Option<i64>) -> ProjectTelemetry {
    ProjectTelemetry {
        project_id: ProjectId::from_str("rimg")
            .unwrap_or_else(|error| panic!("project fixture: {error}")),
        display_name: "rimg".to_owned(),
        condition: ProjectCondition::Degraded,
        observed_at_ms,
        detail: "legacy health contract".to_owned(),
        resources: ProjectResourceTelemetry {
            status: ObservationStatus::Fresh,
            observed_at_ms,
            cpu_percent: Some(0.5),
            memory_used_bytes: Some(20 * 1_024 * 1_024),
            memory_limit_bytes: Some(16 * 1_024 * 1_024 * 1_024),
            network_rx_bytes: observed_at_ms.and_then(|value| u64::try_from(value).ok()),
            network_tx_bytes: observed_at_ms
                .and_then(|value| u64::try_from(value.saturating_mul(2)).ok()),
            block_read_bytes: Some(1_000),
            block_write_bytes: Some(2_000),
            detail: "fixture resources".to_owned(),
        },
    }
}

fn repository_observation(total_bytes: u64) -> SourceTreeObservationV1 {
    SourceTreeObservationV1 {
        project_id: ProjectId::from_str("rimg")
            .unwrap_or_else(|error| panic!("project fixture: {error}")),
        head: GitCommitId::from_str("0123456789abcdef0123456789abcdef01234567")
            .unwrap_or_else(|error| panic!("commit fixture: {error}")),
        file_count: 42,
        total_bytes,
    }
}

fn create_legacy_metrics(path: &Path, project_id: &str) {
    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("open legacy metrics: {error}"));
    connection
        .execute_batch(
            "CREATE TABLE host_samples (
                observed_at_ms INTEGER PRIMARY KEY,
                status_json TEXT NOT NULL,
                cpu_percent REAL,
                load_1 REAL,
                load_5 REAL,
                load_15 REAL,
                memory_total_bytes INTEGER,
                memory_available_bytes INTEGER,
                swap_total_bytes INTEGER,
                swap_free_bytes INTEGER,
                disk_total_bytes INTEGER,
                disk_available_bytes INTEGER,
                network_rx_bytes INTEGER,
                network_tx_bytes INTEGER,
                network_rx_bytes_per_second INTEGER,
                network_tx_bytes_per_second INTEGER,
                psi_cpu_some_avg10 REAL,
                psi_memory_some_avg10 REAL,
                psi_io_some_avg10 REAL,
                partial_reasons_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE project_samples (
                collected_at_ms INTEGER NOT NULL,
                project_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                condition_json TEXT NOT NULL,
                observed_at_ms INTEGER,
                detail TEXT NOT NULL,
                PRIMARY KEY (collected_at_ms, project_id)
             ) STRICT;
             CREATE INDEX project_samples_project_time
                ON project_samples(project_id, collected_at_ms DESC);
             INSERT INTO host_samples(observed_at_ms, status_json, partial_reasons_json)
                VALUES (100, '\"fresh\"', '[]');",
        )
        .unwrap_or_else(|error| panic!("create legacy schema: {error}"));
    connection
        .execute(
            "INSERT INTO project_samples(
                collected_at_ms, project_id, display_name, condition_json,
                observed_at_ms, detail
             ) VALUES (100, ?1, 'rimg', '\"degraded\"', 100, 'legacy')",
            [project_id],
        )
        .unwrap_or_else(|error| panic!("create legacy project: {error}"));
}

#[test]
fn control_store_persists_monotonic_events_and_observation_receipts() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control_path = directory.path().join("control.sqlite");
    let operation_id = Uuid::new_v4();

    {
        let control = ControlStore::open(&control_path)
            .unwrap_or_else(|error| panic!("open control: {error}"));
        let started = control
            .start_observation(100)
            .unwrap_or_else(|error| panic!("start observation: {error}"));
        control
            .finish_observation(started, 200, None)
            .unwrap_or_else(|error| panic!("finish observation: {error}"));
        assert!(matches!(
            control.finish_observation(started, 300, None),
            Err(StoreError::ObservationNotRunning(_))
        ));

        let interrupted = control
            .start_observation(400)
            .unwrap_or_else(|error| panic!("start interrupted observation: {error}"));
        assert_eq!(
            control
                .recover_interrupted_observations(350)
                .unwrap_or_else(|error| panic!("recover interrupted observation: {error}")),
            1
        );
        assert!(matches!(
            control.finish_observation(interrupted, 500, None),
            Err(StoreError::ObservationNotRunning(_))
        ));
        assert_eq!(
            control
                .recover_interrupted_observations(600)
                .unwrap_or_else(|error| panic!("repeat recovery: {error}")),
            0
        );

        for index in 1..=513_i64 {
            let event = control
                .append_event(
                    index,
                    DashboardEvent::Snapshot(Box::new(snapshot(index, operation_id))),
                )
                .unwrap_or_else(|error| panic!("append event {index}: {error}"));
            assert_eq!(
                event.sequence,
                u64::try_from(index).unwrap_or_else(|error| panic!("fixture index: {error}"))
            );
        }
        assert_eq!(
            control
                .event_bounds()
                .unwrap_or_else(|error| panic!("event bounds: {error}")),
            Some((2, 513))
        );
    }

    let reopened =
        ControlStore::open(&control_path).unwrap_or_else(|error| panic!("reopen control: {error}"));
    let next = reopened
        .append_event(
            514,
            DashboardEvent::Snapshot(Box::new(snapshot(514, operation_id))),
        )
        .unwrap_or_else(|error| panic!("append after reopen: {error}"));
    assert_eq!(next.sequence, 514);
}

#[test]
fn control_store_rejects_unknown_schema_versions_at_open() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("future-control.sqlite");
    let future = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open future control store: {error}"));
    future
        .execute_batch(
            "CREATE TABLE controller_meta (
                key TEXT PRIMARY KEY,
                integer_value INTEGER NOT NULL
             ) STRICT;
             INSERT INTO controller_meta(key, integer_value) VALUES ('schema_version', 99);",
        )
        .unwrap_or_else(|error| panic!("create future control schema: {error}"));
    drop(future);
    assert!(matches!(
        ControlStore::open(&path),
        Err(StoreError::UnsupportedControlSchemaVersion {
            actual: 99,
            supported: 5
        })
    ));
}

#[test]
fn control_store_migrates_v1_to_the_durable_workflow_journal() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("v1-control.sqlite");
    let store =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("create control store: {error}"));
    drop(store);

    let legacy = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open simulated v1 store: {error}"));
    legacy
        .execute_batch(
            "DROP TABLE workflow_operation_state_bindings;
             DROP TABLE workflow_reductions;
             DROP TABLE workflow_cleanup_receipts;
             DROP TABLE workflow_node_receipts;
             DROP TABLE workflow_lease_journal;
             DROP TABLE workflow_node_dependencies;
             DROP TABLE workflow_nodes;
             DROP TABLE workflow_mutation_locks;
             DROP TABLE workflow_transitions;
             DROP TABLE workflow_attempts;
             DROP TABLE workflow_triggers;
             DROP TABLE workflow_project_heads;
             DROP TABLE workflow_requests;
             DROP TABLE workflow_scheduler_cursor;
             UPDATE controller_meta SET integer_value = 1 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade fixture to v1: {error}"));
    drop(legacy);

    let migrated =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("migrate v1 store: {error}"));
    drop(migrated);
    let inspected = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect migrated store: {error}"));
    let version: i64 = inspected
        .query_row(
            "SELECT integer_value FROM controller_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("read migrated version: {error}"));
    assert_eq!(version, 5);
    let scheduler_tables: i64 = inspected
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name IN (
                'workflow_requests', 'workflow_attempts', 'workflow_nodes',
                'workflow_lease_journal', 'workflow_node_receipts',
                'workflow_cleanup_receipts', 'workflow_operation_state_bindings',
                'workflow_reductions', 'workflow_mutation_locks',
                'workflow_transitions', 'workflow_scheduler_cursor'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count migrated scheduler tables: {error}"));
    assert_eq!(scheduler_tables, 11);
}

#[test]
fn control_store_migrates_v2_cleanup_debt_atomically() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("v2-control.sqlite");
    let store =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("create control store: {error}"));
    drop(store);

    let legacy = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open simulated v2 store: {error}"));
    legacy
        .execute_batch(
            "DROP TABLE workflow_operation_state_bindings;
             DROP TABLE workflow_cleanup_receipts;
             UPDATE controller_meta SET integer_value = 2 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade fixture to v2: {error}"));
    drop(legacy);

    let migrated =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("migrate v2 store: {error}"));
    drop(migrated);
    let inspected = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect migrated store: {error}"));
    let version: i64 = inspected
        .query_row(
            "SELECT integer_value FROM controller_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("read migrated version: {error}"));
    assert_eq!(version, 5);
    let cleanup_table: i64 = inspected
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'workflow_cleanup_receipts'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("inspect cleanup table: {error}"));
    assert_eq!(cleanup_table, 1);
}

#[test]
fn control_store_migrates_v3_operation_state_binding_atomically() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("v3-control.sqlite");
    let store =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("create control store: {error}"));
    drop(store);

    let legacy = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open simulated v3 store: {error}"));
    legacy
        .execute_batch(
            "DROP TABLE workflow_operation_state_bindings;
             UPDATE controller_meta SET integer_value = 3 WHERE key = 'schema_version';",
        )
        .unwrap_or_else(|error| panic!("downgrade fixture to v3: {error}"));
    drop(legacy);

    let migrated =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("migrate v3 store: {error}"));
    drop(migrated);
    let inspected = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect migrated store: {error}"));
    let (version, binding_table): (i64, i64) = inspected
        .query_row(
            "SELECT
                (SELECT integer_value FROM controller_meta WHERE key = 'schema_version'),
                (SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'workflow_operation_state_bindings')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| panic!("inspect operation-state migration: {error}"));
    assert_eq!(version, 5);
    assert_eq!(binding_table, 1);
}

#[test]
fn control_store_migrates_v4_requests_and_triggers_without_losing_bindings() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("v4-control.sqlite");
    let (manifest, admission) = workflow_web_fixture();
    let scheduler = rdashboard::scheduler::DurableWorkflowScheduler::new(
        ControlStore::open(&path).unwrap_or_else(|error| panic!("create control store: {error}")),
    );
    let created = scheduler
        .admit(&manifest, &admission, 1)
        .unwrap_or_else(|error| panic!("seed v4 workflow: {error}"));
    let attempt_id = created.attempt().attempt_id;
    drop(scheduler);

    let legacy = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open simulated v4 store: {error}"));
    legacy
        .execute(
            "UPDATE controller_meta SET integer_value = 4 WHERE key = 'schema_version'",
            [],
        )
        .unwrap_or_else(|error| panic!("downgrade schema marker: {error}"));
    drop(legacy);

    let migrated =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("migrate v4 store: {error}"));
    let scheduler = rdashboard::scheduler::DurableWorkflowScheduler::new(migrated);
    let restored = scheduler
        .attempt(attempt_id)
        .unwrap_or_else(|error| panic!("read migrated attempt: {error}"))
        .unwrap_or_else(|| panic!("migrated attempt missing"));
    assert_eq!(restored.request_id, created.attempt().request_id);
    assert_eq!(
        restored.execution_mode,
        rdashboard::scheduler::WorkflowExecutionModeV1::Deploy
    );
    drop(scheduler);

    let inspected = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect migrated v4 store: {error}"));
    let version: i64 = inspected
        .query_row(
            "SELECT integer_value FROM controller_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("read migrated version: {error}"));
    let foreign_key_violations: i64 = inspected
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("inspect migrated foreign keys: {error}"));
    assert_eq!(version, 5);
    assert_eq!(foreign_key_violations, 0);
}

#[test]
fn control_store_detects_legacy_column_drift_before_stamping_the_schema() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("broken-control.sqlite");
    let legacy = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open legacy control store: {error}"));
    legacy
        .execute_batch(
            "CREATE TABLE controller_meta (
                key TEXT PRIMARY KEY,
                integer_value INTEGER NOT NULL
             ) STRICT;
             INSERT INTO controller_meta(key, integer_value) VALUES ('event_sequence', 0);
             CREATE TABLE deployment_requests (
                request_id TEXT PRIMARY KEY
             ) STRICT;",
        )
        .unwrap_or_else(|error| panic!("create drifted control schema: {error}"));
    drop(legacy);
    assert!(matches!(
        ControlStore::open(&path),
        Err(StoreError::CorruptControlSchema("target_key"))
    ));
    let inspected = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect drifted control store: {error}"));
    let stamped: i64 = inspected
        .query_row(
            "SELECT COUNT(*) FROM controller_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("inspect rolled-back schema stamp: {error}"));
    assert_eq!(stamped, 0);
}

#[test]
fn metrics_store_rolls_up_before_pruning_and_accepts_repeated_wall_time() {
    assert!(rusqlite::version_number() >= MINIMUM_SAFE_SQLITE_VERSION_NUMBER);
    assert_eq!(rusqlite::version(), "3.53.2");
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let metrics_path = directory.path().join("metrics.sqlite");
    let metrics =
        MetricsStore::open(&metrics_path).unwrap_or_else(|error| panic!("open metrics: {error}"));
    metrics
        .record_collection(&host_sample(100), &[project_sample(Some(100))])
        .unwrap_or_else(|error| panic!("record collection: {error}"));
    metrics
        .record_host_sample(&host_sample(100))
        .unwrap_or_else(|error| panic!("record duplicate timestamp: {error}"));
    metrics
        .record_host_sample(&host_sample(200))
        .unwrap_or_else(|error| panic!("record sample: {error}"));
    assert_eq!(metrics.sample_count().unwrap_or(0), 3);
    assert_eq!(metrics.project_sample_count().unwrap_or(0), 1);

    let duplicated_project = project_sample(Some(300));
    assert!(matches!(
        metrics.record_collection(
            &host_sample(300),
            &[duplicated_project.clone(), duplicated_project]
        ),
        Err(StoreError::Sqlite(_))
    ));
    assert_eq!(metrics.sample_count().unwrap_or(0), 3);
    assert_eq!(metrics.project_sample_count().unwrap_or(0), 1);

    let retention = metrics
        .apply_retention(150, 0)
        .unwrap_or_else(|error| panic!("apply retention: {error}"));
    assert_eq!(retention.raw_host_deleted, 2);
    assert_eq!(retention.raw_project_deleted, 1);
    assert_eq!(retention.raw_deleted(), 3);
    assert_eq!(metrics.sample_count().unwrap_or(0), 1);
    assert_eq!(metrics.project_sample_count().unwrap_or(0), 0);
    assert_eq!(metrics.host_rollup_count().unwrap_or(0), 1);
    assert_eq!(metrics.project_rollup_count().unwrap_or(0), 1);

    let rollup = metrics
        .host_minute_rollup(0)
        .unwrap_or_else(|error| panic!("load host rollup: {error}"))
        .unwrap_or_else(|| panic!("host rollup is missing"));
    assert_eq!(rollup.sample_count, 2);
    assert_eq!(rollup.statuses.fresh, 2);
    assert_eq!(rollup.metrics.cpu_percent.count(), 2);
    assert!(
        rollup
            .metrics
            .cpu_percent
            .quantile(0.5)
            .is_some_and(|value| (12.0..=13.0).contains(&value))
    );

    let project_rollup = metrics
        .project_minute_rollup(0, "rimg")
        .unwrap_or_else(|error| panic!("load project rollup: {error}"))
        .unwrap_or_else(|| panic!("project rollup is missing"));
    assert_eq!(project_rollup.sample_count, 1);
    assert_eq!(project_rollup.conditions.degraded, 1);

    let mut late_partial = host_sample(120);
    late_partial.status = ObservationStatus::Partial;
    late_partial.partial_reasons = vec!["meminfo: temporarily unavailable".to_owned()];
    metrics
        .record_host_sample(&late_partial)
        .unwrap_or_else(|error| panic!("record late sample: {error}"));
    metrics
        .record_host_sample(&host_sample(130))
        .unwrap_or_else(|error| panic!("record recovery sample: {error}"));
    metrics
        .apply_retention(150, 0)
        .unwrap_or_else(|error| panic!("merge late sample into rollup: {error}"));
    let merged = metrics
        .host_minute_rollup(0)
        .unwrap_or_else(|error| panic!("load merged rollup: {error}"))
        .unwrap_or_else(|| panic!("merged rollup is missing"));
    assert_eq!(merged.sample_count, 4);
    assert_eq!(merged.metrics.memory_used_percent.count(), 4);
    assert_eq!(merged.statuses.partial, 1);
    assert!(merged.last_partial_sample_id.is_some());
    assert_eq!(
        merged.last_partial_reasons,
        vec!["meminfo: temporarily unavailable"]
    );

    let deletion = metrics
        .apply_retention(60_000, 60_000)
        .unwrap_or_else(|error| panic!("delete expired rollups: {error}"));
    assert_eq!(deletion.host_rollups_deleted, 1);
    assert_eq!(deletion.project_rollups_deleted, 1);
    assert_eq!(metrics.host_rollup_count().unwrap_or(0), 0);
    assert_eq!(metrics.project_rollup_count().unwrap_or(0), 0);
}

#[test]
fn metrics_store_migrates_the_timestamp_key_schema_without_losing_samples() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("metrics.sqlite");
    create_legacy_metrics(&path, "rimg");

    let metrics =
        MetricsStore::open(&path).unwrap_or_else(|error| panic!("migrate metrics: {error}"));
    assert_eq!(metrics.sample_count().unwrap_or(0), 1);
    assert_eq!(metrics.project_sample_count().unwrap_or(0), 1);
    metrics
        .record_host_sample(&host_sample(100))
        .unwrap_or_else(|error| panic!("record duplicate timestamp after migration: {error}"));
    assert_eq!(metrics.sample_count().unwrap_or(0), 2);
}

#[test]
fn metrics_store_migrates_v4_project_samples_before_recording_resources() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("metrics.sqlite");
    {
        let metrics = MetricsStore::open(&path)
            .unwrap_or_else(|error| panic!("create current metrics: {error}"));
        metrics
            .record_collection(&host_sample(100), &[project_sample(Some(100))])
            .unwrap_or_else(|error| panic!("record pre-migration sample: {error}"));
    }
    let legacy = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open v4 metrics fixture: {error}"));
    legacy
        .execute_batch(
            "ALTER TABLE project_samples DROP COLUMN resource_detail;
             ALTER TABLE project_samples DROP COLUMN resource_block_write_bytes;
             ALTER TABLE project_samples DROP COLUMN resource_block_read_bytes;
             ALTER TABLE project_samples DROP COLUMN resource_network_tx_bytes;
             ALTER TABLE project_samples DROP COLUMN resource_network_rx_bytes;
             ALTER TABLE project_samples DROP COLUMN resource_memory_limit_bytes;
             ALTER TABLE project_samples DROP COLUMN resource_memory_used_bytes;
             ALTER TABLE project_samples DROP COLUMN resource_cpu_percent;
             ALTER TABLE project_samples DROP COLUMN resource_observed_at_ms;
             ALTER TABLE project_samples DROP COLUMN resource_status_json;
             PRAGMA user_version = 4;",
        )
        .unwrap_or_else(|error| panic!("create v4 metrics fixture: {error}"));
    drop(legacy);

    let metrics =
        MetricsStore::open(&path).unwrap_or_else(|error| panic!("migrate v4 metrics: {error}"));
    assert_eq!(metrics.project_sample_count().unwrap_or(0), 1);
    metrics
        .record_collection(&host_sample(200), &[project_sample(Some(200))])
        .unwrap_or_else(|error| panic!("record post-migration resources: {error}"));
    let project_id =
        ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project fixture: {error}"));
    let history = metrics
        .project_resource_history(&project_id, 3_600_500)
        .unwrap_or_else(|error| panic!("read migrated resources: {error}"));
    let hour = history
        .windows
        .iter()
        .find(|window| window.window == HostHistoryWindowKind::Hour)
        .unwrap_or_else(|| panic!("hour resource window is missing"));
    assert_eq!(hour.sample_count, 1);
    assert_eq!(hour.covered_minutes, 1);
    drop(metrics);
    let inspected = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect migrated metrics: {error}"));
    let version: i64 = inspected
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap_or_else(|error| panic!("read migrated version: {error}"));
    assert_eq!(version, 5);
}

#[test]
fn metrics_store_rejects_invalid_legacy_project_ids_before_migration() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("metrics.sqlite");
    create_legacy_metrics(&path, "Invalid Project");

    assert!(matches!(
        MetricsStore::open(&path),
        Err(StoreError::InvalidLegacyProjectId { .. })
    ));
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("reopen rejected legacy metrics: {error}"));
    let legacy_tables: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name IN ('host_samples', 'project_samples')",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("check migration rollback: {error}"));
    assert_eq!(legacy_tables, 2);
}

#[test]
fn metric_retention_streams_multiple_minute_buckets() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let metrics = MetricsStore::open(directory.path().join("metrics.sqlite"))
        .unwrap_or_else(|error| panic!("open metrics: {error}"));
    for observed_at_ms in [10_000, 70_000, 130_000] {
        metrics
            .record_collection(
                &host_sample(observed_at_ms),
                &[project_sample(Some(observed_at_ms))],
            )
            .unwrap_or_else(|error| panic!("record bucket {observed_at_ms}: {error}"));
    }

    let outcome = metrics
        .apply_retention(180_000, 0)
        .unwrap_or_else(|error| panic!("stream rollups: {error}"));
    assert_eq!(outcome.host_rollups_written, 3);
    assert_eq!(outcome.project_rollups_written, 3);
    assert_eq!(metrics.host_rollup_count().unwrap_or(0), 3);
    assert_eq!(metrics.project_rollup_count().unwrap_or(0), 3);
    for bucket in [0, 60_000, 120_000] {
        assert_eq!(
            metrics
                .host_minute_rollup(bucket)
                .unwrap_or_else(|error| panic!("load bucket {bucket}: {error}"))
                .map(|rollup| rollup.sample_count),
            Some(1)
        );
        let project = metrics
            .project_minute_rollup(bucket, "rimg")
            .unwrap_or_else(|error| panic!("load project bucket {bucket}: {error}"))
            .unwrap_or_else(|| panic!("project bucket {bucket} is missing"));
        assert!(project.last_non_healthy_sample_id.is_some());
        assert_eq!(
            project.last_non_healthy_detail.as_deref(),
            Some("legacy health contract")
        );
    }
}

#[test]
fn host_history_combines_retained_rollups_and_raw_samples_into_named_medians() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let metrics = MetricsStore::open(directory.path().join("metrics.sqlite"))
        .unwrap_or_else(|error| panic!("open metrics: {error}"));
    for (observed_at_ms, cpu_percent, network_rx, network_tx) in [
        (10_000, 10.0, 100, 200),
        (70_000, 20.0, 160, 260),
        (130_000, 30.0, 260, 300),
    ] {
        let mut sample = host_sample(observed_at_ms);
        sample.cpu_percent = Some(cpu_percent);
        sample.network_rx_bytes = Some(network_rx);
        sample.network_tx_bytes = Some(network_tx);
        metrics
            .record_host_sample(&sample)
            .unwrap_or_else(|error| panic!("record history fixture: {error}"));
    }
    metrics
        .apply_retention(120_000, -30_i64 * 24 * 60 * 60 * 1_000)
        .unwrap_or_else(|error| panic!("roll up history fixture: {error}"));
    assert_eq!(metrics.host_rollup_count().unwrap_or(0), 2);
    assert_eq!(metrics.sample_count().unwrap_or(0), 1);

    let history = metrics
        .host_history(3_600_500)
        .unwrap_or_else(|error| panic!("calculate host history: {error}"));
    assert_eq!(history.schema_version, 2);
    assert_eq!(history.complete_through_ms, 3_600_000);
    assert_eq!(history.windows.len(), 4);
    let hour = history
        .windows
        .iter()
        .find(|window| window.window == HostHistoryWindowKind::Hour)
        .unwrap_or_else(|| panic!("hour history window is missing"));
    assert_eq!(hour.starts_at_ms, 0);
    assert_eq!(hour.ends_at_ms, 3_600_000);
    assert_eq!(hour.sample_count, 3);
    assert_eq!(hour.covered_minutes, 3);
    assert_eq!(hour.expected_minutes, 60);
    assert!(!hour.complete);
    assert!(
        hour.medians
            .cpu_percent
            .is_some_and(|value| (19.0..=21.0).contains(&value))
    );
    assert!(
        hour.medians
            .memory_used_percent
            .is_some_and(|value| (49.0..=51.0).contains(&value))
    );
    assert_eq!(hour.totals.network_rx_bytes, Some(160));
    assert_eq!(hour.totals.network_tx_bytes, Some(100));
    assert_eq!(hour.totals.network_rx_covered_ms, 120_000);
    assert_eq!(hour.totals.network_tx_covered_ms, 120_000);
}

#[test]
fn host_history_excludes_counter_reset_intervals_from_network_traffic() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let metrics = MetricsStore::open(directory.path().join("metrics.sqlite"))
        .unwrap_or_else(|error| panic!("open metrics: {error}"));
    for (observed_at_ms, network_rx, network_tx) in [
        (10_000, 1_000, 2_000),
        (70_000, 1_100, 2_200),
        (130_000, 50, 80),
        (190_000, 90, 110),
    ] {
        let mut sample = host_sample(observed_at_ms);
        sample.network_rx_bytes = Some(network_rx);
        sample.network_tx_bytes = Some(network_tx);
        metrics
            .record_host_sample(&sample)
            .unwrap_or_else(|error| panic!("record reset fixture: {error}"));
    }
    metrics
        .apply_retention(180_000, -30_i64 * 24 * 60 * 60 * 1_000)
        .unwrap_or_else(|error| panic!("roll up reset fixture: {error}"));

    let history = metrics
        .host_history(3_600_500)
        .unwrap_or_else(|error| panic!("calculate reset history: {error}"));
    let hour = history
        .windows
        .iter()
        .find(|window| window.window == HostHistoryWindowKind::Hour)
        .unwrap_or_else(|| panic!("hour history window is missing"));
    assert_eq!(hour.totals.network_rx_bytes, Some(140));
    assert_eq!(hour.totals.network_tx_bytes, Some(230));
    assert_eq!(hour.totals.network_rx_covered_ms, 120_000);
    assert_eq!(hour.totals.network_tx_covered_ms, 120_000);
}

#[test]
fn project_resource_history_combines_rollups_and_raw_samples_without_recounting_stale_data() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let metrics = MetricsStore::open(directory.path().join("metrics.sqlite"))
        .unwrap_or_else(|error| panic!("open metrics: {error}"));
    for (observed_at_ms, cpu_percent, memory_used, network_rx, network_tx) in [
        (10_000, 1.0, 100, 1_000, 2_000),
        (70_000, 2.0, 200, 1_100, 2_200),
        (130_000, 3.0, 300, 1_300, 2_500),
    ] {
        let mut project = project_sample(Some(observed_at_ms));
        project.resources.cpu_percent = Some(cpu_percent);
        project.resources.memory_used_bytes = Some(memory_used);
        project.resources.memory_limit_bytes = Some(1_000);
        project.resources.network_rx_bytes = Some(network_rx);
        project.resources.network_tx_bytes = Some(network_tx);
        metrics
            .record_collection(&host_sample(observed_at_ms), &[project])
            .unwrap_or_else(|error| panic!("record project resources: {error}"));
    }
    let mut stale = project_sample(Some(130_000));
    stale.resources.status = ObservationStatus::Stale;
    stale.resources.cpu_percent = Some(99.0);
    metrics
        .record_collection(&host_sample(140_000), &[stale])
        .unwrap_or_else(|error| panic!("record stale resources: {error}"));
    metrics
        .apply_retention(120_000, -30_i64 * 24 * 60 * 60 * 1_000)
        .unwrap_or_else(|error| panic!("roll up project resources: {error}"));

    let project_id =
        ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project fixture: {error}"));
    let history = metrics
        .project_resource_history(&project_id, 3_600_500)
        .unwrap_or_else(|error| panic!("calculate project resources: {error}"));
    assert_eq!(history.schema_version, 1);
    assert_eq!(history.project_id, project_id);
    let hour = history
        .windows
        .iter()
        .find(|window| window.window == HostHistoryWindowKind::Hour)
        .unwrap_or_else(|| panic!("hour project resource window is missing"));
    assert_eq!(hour.sample_count, 3);
    assert_eq!(hour.covered_minutes, 3);
    assert!(
        hour.medians
            .cpu_percent
            .is_some_and(|value| (1.9..=2.1).contains(&value))
    );
    assert!(
        hour.medians
            .memory_used_bytes
            .is_some_and(|value| (190.0..=210.0).contains(&value))
    );
    assert_eq!(hour.totals.network_rx_bytes, Some(300));
    assert_eq!(hour.totals.network_tx_bytes, Some(500));
    assert_eq!(hour.totals.network_rx_covered_ms, 120_000);
}

#[test]
fn repository_history_enforces_hourly_sampling_and_preserves_commit_metrics() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let metrics = MetricsStore::open(directory.path().join("metrics.sqlite"))
        .unwrap_or_else(|error| panic!("open metrics: {error}"));
    let first_at = PROJECT_REPOSITORY_SAMPLE_INTERVAL_MS;
    assert_eq!(
        metrics
            .record_project_repository_sample(first_at, &repository_observation(1_000))
            .unwrap_or_else(|error| panic!("record first repository sample: {error}")),
        RepositorySampleWrite::Recorded
    );
    assert_eq!(
        metrics
            .record_project_repository_sample(
                first_at + PROJECT_REPOSITORY_SAMPLE_INTERVAL_MS - 1,
                &repository_observation(2_000),
            )
            .unwrap_or_else(|error| panic!("reject early repository sample: {error}")),
        RepositorySampleWrite::NotDue {
            next_observation_at_ms: first_at + PROJECT_REPOSITORY_SAMPLE_INTERVAL_MS,
        }
    );
    let second_at = first_at + PROJECT_REPOSITORY_SAMPLE_INTERVAL_MS;
    assert_eq!(
        metrics
            .record_project_repository_sample(second_at, &repository_observation(3_000))
            .unwrap_or_else(|error| panic!("record second repository sample: {error}")),
        RepositorySampleWrite::Recorded
    );
    let project_id =
        ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project fixture: {error}"));
    assert_eq!(
        metrics
            .next_project_repository_observation_at(&project_id)
            .unwrap_or_else(|error| panic!("load next repository observation: {error}")),
        Some(second_at + PROJECT_REPOSITORY_SAMPLE_INTERVAL_MS)
    );
    let history = metrics
        .project_repository_history(&project_id, 0)
        .unwrap_or_else(|error| panic!("load repository history: {error}"));
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].total_bytes, 1_000);
    assert_eq!(history[1].total_bytes, 3_000);
    assert_eq!(history[1].file_count, 42);
    assert_eq!(
        history[1].head.as_str(),
        "0123456789abcdef0123456789abcdef01234567"
    );
}

async fn assert_versioned_status_asset(app: Router, html: &str) {
    assert!(!html.contains("__ASSET_VERSION__"));
    let app_asset = html
        .split("<script src=\"")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .unwrap_or_else(|| panic!("versioned application asset is missing: {html}"));
    assert!(app_asset.starts_with("/assets/"));
    assert!(app_asset.ends_with("/app.js"));
    let status_asset = app_asset.replace("/app.js", "/status.js");
    let response = app
        .oneshot(
            Request::builder()
                .uri(status_asset)
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("status script response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static(
            "text/javascript; charset=utf-8"
        ))
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static(
            "public, max-age=31536000, immutable"
        ))
    );
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|error| panic!("read status script: {error}"))
        .to_bytes();
    assert!(
        body.windows(b"evaluateHostObservation".len())
            .any(|window| window == b"evaluateHostObservation")
    );
}

#[tokio::test]
async fn http_surface_is_loopback_slice_with_strict_headers_and_truthful_empty_state() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let hub = EventHub::new(control);
    let state = DashboardState::new(hub, Duration::from_secs(5));
    let operation_id = Uuid::new_v4();
    *state.latest_snapshot.write().await = Some(snapshot(1_000, operation_id));
    let app = router(state.clone());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("index response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::X_CONTENT_TYPE_OPTIONS),
        Some(&header::HeaderValue::from_static("nosniff"))
    );
    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("form-action 'none'"));

    let body = response
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|error| panic!("read index: {error}"))
        .to_bytes();
    let html = std::str::from_utf8(&body).unwrap_or("");
    assert!(html.contains("<main id=\"content\""));
    assert!(html.contains("<caption>"));
    assert!(html.contains("Проекты ещё не подключены"));
    assert!(html.contains("За месяц"));
    assert!(html.contains("<table class=\"project-table\">"));
    assert!(html.contains("<tbody id=\"project-list\">"));
    assert!(html.contains("Трафик"));
    assert!(!html.contains("Текущий узел"));
    assert!(!html.contains("История ещё накапливается"));
    assert!(!html.contains("id=\"host-heading\""));
    assert!(!html.contains("host-observation-status"));
    assert!(!html.contains("table-scroll"));
    assert!(!html.contains("metric-psi"));
    assert!(!html.contains("Контур операций"));
    assert!(!html.contains("<script>"));
    assert_versioned_status_asset(app.clone(), html).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/snapshot")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("snapshot response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("x-rdashboard-server-time-ms")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<i64>().ok())
            .is_some_and(|value| value > 0)
    );
}

#[tokio::test]
async fn host_history_http_surface_returns_all_named_windows() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let metrics = MetricsStore::open(directory.path().join("metrics.sqlite"))
        .unwrap_or_else(|error| panic!("open metrics: {error}"));
    metrics
        .record_host_sample(&host_sample(1_000))
        .unwrap_or_else(|error| panic!("record HTTP history fixture: {error}"));
    let app = router(
        DashboardState::new(EventHub::new(control), Duration::from_secs(5))
            .with_metrics_store(metrics),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/host-history")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("host history response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    let history: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("read host history: {error}"))
            .to_bytes(),
    )
    .unwrap_or_else(|error| panic!("decode host history: {error}"));
    assert_eq!(history["schema_version"], 2);
    assert_eq!(history["windows"].as_array().map(Vec::len), Some(4));
}

#[tokio::test]
async fn project_resource_history_http_surface_is_project_scoped() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let metrics = MetricsStore::open(directory.path().join("metrics.sqlite"))
        .unwrap_or_else(|error| panic!("open metrics: {error}"));
    metrics
        .record_collection(&host_sample(1_000), &[project_sample(Some(1_000))])
        .unwrap_or_else(|error| panic!("record resource HTTP fixture: {error}"));
    let app = router(
        DashboardState::new(EventHub::new(control), Duration::from_secs(5))
            .with_metrics_store(metrics),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/projects/rimg/resource-history")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("project resource history response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    let history: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("read project resource history: {error}"))
            .to_bytes(),
    )
    .unwrap_or_else(|error| panic!("decode project resource history: {error}"));
    assert_eq!(history["schema_version"], 1);
    assert_eq!(history["project_id"], "rimg");
    assert_eq!(history["windows"].as_array().map(Vec::len), Some(4));
}

fn workflow_web_fixture() -> (
    rdashboard::domain::ProjectManifestV2,
    rdashboard::scheduler::WorkflowAdmissionV1,
) {
    let manifest: rdashboard::domain::ProjectManifestV2 =
        serde_json::from_str(include_str!("../config/project-manifests/ralert.json"))
            .unwrap_or_else(|error| panic!("decode workflow manifest: {error}"));
    let admission = rdashboard::scheduler::WorkflowAdmissionV1 {
        project_id: manifest.project_id.clone(),
        workflow_policy_digest: manifest
            .workflow_policy_digest()
            .unwrap_or_else(|error| panic!("workflow policy digest: {error}")),
        source_sha: GitCommitId::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap_or_else(|error| panic!("source SHA: {error}")),
        execution_mode: rdashboard::scheduler::WorkflowExecutionModeV1::Deploy,
        source_sequence: 1,
        source_attestation_digest: EvidenceDigest::sha256("workflow web attestation"),
        trigger_channel: rdashboard::scheduler::WorkflowTriggerChannelV1::GithubWebhook,
        delivery_id: "workflow-web-1".to_owned(),
        payload_digest: EvidenceDigest::sha256("workflow web payload"),
        priority: 2,
    };
    (manifest, admission)
}

async fn json_response(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("read JSON response: {error}"))
            .to_bytes(),
    )
    .unwrap_or_else(|error| panic!("decode JSON response: {error}"))
}

#[tokio::test]
async fn workflow_overview_http_surface_is_empty_bounded_and_read_only() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let app = router(DashboardState::new(
        EventHub::new(control),
        Duration::from_secs(5),
    ));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/workflows?limit=20")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("workflow response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    let payload = json_response(response).await;
    assert_eq!(payload["schema_version"], 2);
    assert_eq!(payload["truncated"], false);
    assert_eq!(payload["deployments"].as_array().map(Vec::len), Some(0));
    assert!(
        payload["generated_at_ms"]
            .as_i64()
            .is_some_and(|time| time >= 0)
    );

    let invalid = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/workflows?limit=0")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("invalid request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("invalid workflow response: {error}"));
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn workflow_overview_serializes_the_exact_browser_contract() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let scheduler = rdashboard::scheduler::DurableWorkflowScheduler::new(control.clone());
    let app = router(DashboardState::new(
        EventHub::new(control),
        Duration::from_secs(5),
    ));
    let (manifest, admission) = workflow_web_fixture();
    scheduler
        .admit(&manifest, &admission, 1)
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));
    let populated = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/workflows?limit=1")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("populated request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("populated workflow response: {error}"));
    assert_eq!(populated.status(), StatusCode::OK);
    let populated = json_response(populated).await;
    assert_eq!(populated["truncated"], false);
    assert_eq!(populated["schema_version"], 2);
    let deployment = &populated["deployments"][0];
    assert_eq!(deployment["project_id"], "ralert");
    assert_eq!(deployment["source_sha"], admission.source_sha.as_str());
    assert_eq!(deployment["attempt_number"], 1);
    assert_eq!(deployment["state"], "queued");
    assert_eq!(deployment["current_stage"], "host_prepare");
    assert_eq!(deployment["test_duration_ms"], serde_json::Value::Null);
    assert_eq!(deployment["release_size_bytes"], serde_json::Value::Null);
    assert!(
        populated["generated_at_ms"]
            .as_i64()
            .zip(deployment["updated_at_ms"].as_i64())
            .is_some_and(|(generated, updated)| generated >= updated)
    );
    assert_eq!(
        deployment
            .as_object()
            .unwrap_or_else(|| panic!("workflow deployment is an object"))
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([
            "attempt_number",
            "completed_stages",
            "current_stage",
            "duration_ms",
            "project_id",
            "release_size_bytes",
            "source_sha",
            "state",
            "test_duration_ms",
            "total_stages",
            "updated_at_ms",
        ])
    );
}

#[tokio::test]
async fn workflow_overview_sanitizes_corrupt_journal_failures() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let path = directory.path().join("corrupt-workflow-control.sqlite");
    let control = ControlStore::open(&path).unwrap_or_else(|error| panic!("open control: {error}"));
    let scheduler = rdashboard::scheduler::DurableWorkflowScheduler::new(control.clone());
    let (manifest, admission) = workflow_web_fixture();
    scheduler
        .admit(&manifest, &admission, 1)
        .unwrap_or_else(|error| panic!("admit workflow: {error}"));
    drop(scheduler);
    drop(control);

    let corrupt = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open corrupt workflow fixture: {error}"));
    corrupt
        .execute(
            "UPDATE workflow_requests SET project_id = 'internal-secret-marker!'",
            [],
        )
        .unwrap_or_else(|error| panic!("corrupt workflow fixture: {error}"));
    drop(corrupt);

    let control =
        ControlStore::open(&path).unwrap_or_else(|error| panic!("reopen control: {error}"));
    let response = router(DashboardState::new(
        EventHub::new(control),
        Duration::from_secs(5),
    ))
    .oneshot(
        Request::builder()
            .uri("/api/v1/workflows")
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("request: {error}")),
    )
    .await
    .unwrap_or_else(|error| panic!("corrupt workflow response: {error}"));
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let problem = json_response(response).await;
    assert_eq!(problem["code"], "workflow_overview_failed");
    assert_eq!(problem["detail"], "Workflow overview could not be loaded.");
    assert!(!problem.to_string().contains("internal-secret-marker"));
    assert!(!problem.to_string().contains("project ID"));
}

#[tokio::test]
async fn project_operation_history_is_project_scoped_and_bounded() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let app = router(
        DashboardState::new(EventHub::new(control.clone()), Duration::from_secs(5))
            .with_operation_history(DurableController::new(control)),
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/projects/rimg/operations?limit=10")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("project operations response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    let history: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("read project operations: {error}"))
            .to_bytes(),
    )
    .unwrap_or_else(|error| panic!("decode project operations: {error}"));
    assert_eq!(history["schema_version"], 1);
    assert_eq!(history["project_id"], "rimg");
    assert_eq!(history["operations"].as_array().map(Vec::len), Some(0));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/projects/rimg/operations?limit=0")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("invalid operation limit response: {error}"));
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn project_repository_http_surface_retains_last_data_with_collection_error() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let metrics = MetricsStore::open(directory.path().join("metrics.sqlite"))
        .unwrap_or_else(|error| panic!("open metrics: {error}"));
    let observed_at_ms = unix_time_ms().unwrap_or_else(|error| panic!("fixture clock: {error}"));
    metrics
        .record_project_repository_sample(observed_at_ms, &repository_observation(9_999))
        .unwrap_or_else(|error| panic!("record repository HTTP fixture: {error}"));
    let state = DashboardState::new(EventHub::new(control), Duration::from_secs(5))
        .with_metrics_store(metrics);
    state.project_repository_errors.write().await.insert(
        "rimg".to_owned(),
        "source temporarily unavailable".to_owned(),
    );
    let app = router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/projects/rimg/repository-history")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("repository history response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    let history: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("read repository history: {error}"))
            .to_bytes(),
    )
    .unwrap_or_else(|error| panic!("decode repository history: {error}"));
    assert_eq!(history["schema_version"], 1);
    assert_eq!(history["project_id"], "rimg");
    assert_eq!(history["collection_interval_seconds"], 3_600);
    assert_eq!(
        history["last_collection_error"],
        "source temporarily unavailable"
    );
    assert_eq!(history["samples"][0]["total_bytes"], 9_999);
}

fn integration_store_with_last_known_success(path: &Path) -> IntegrationStore {
    let integrations = IntegrationStore::open(path.join("integrations.sqlite"))
        .unwrap_or_else(|error| panic!("open integrations: {error}"));
    let project_id =
        ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project fixture: {error}"));
    integrations
        .record_errors_success(
            10,
            ProjectErrorsDataV1 {
                schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
                project_id: project_id.clone(),
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
                    generated_at_ms: 10,
                    input_digest: EvidenceDigest::sha256("empty"),
                },
                analysis_error: None,
            },
        )
        .unwrap_or_else(|error| panic!("record errors: {error}"));
    integrations
        .record_errors_failure(
            &project_id,
            20,
            IntegrationFailureV1::new("timeout", "GlitchTip временно недоступен.")
                .unwrap_or_else(|error| panic!("failure: {error}")),
        )
        .unwrap_or_else(|error| panic!("record error failure: {error}"));
    integrations
        .record_updates_success(
            20,
            ProjectUpdatesDataV1 {
                schema_version: PROJECT_INTEGRATION_SCHEMA_VERSION,
                project_id: project_id.clone(),
                truncated: false,
                updates: Vec::new(),
            },
        )
        .unwrap_or_else(|error| panic!("record updates: {error}"));
    integrations
}

#[tokio::test]
async fn project_integration_http_surface_is_scoped_and_preserves_last_success() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let integrations = integration_store_with_last_known_success(directory.path());
    let app = router(
        DashboardState::new(EventHub::new(control), Duration::from_secs(5))
            .with_integration_store(integrations),
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/projects/rimg/errors")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("errors response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    let errors: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("read errors: {error}"))
            .to_bytes(),
    )
    .unwrap_or_else(|error| panic!("decode errors: {error}"));
    assert_eq!(errors["project_id"], "rimg");
    assert_eq!(errors["successful_at_ms"], 10);
    assert_eq!(errors["attempted_at_ms"], 20);
    assert_eq!(errors["collection_error"]["code"], "timeout");
    assert_eq!(errors["data"]["unresolved_groups"], 0);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/projects/rimg/updates")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("updates response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    let updates: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("read updates: {error}"))
            .to_bytes(),
    )
    .unwrap_or_else(|error| panic!("decode updates: {error}"));
    assert_eq!(updates["data"]["updates"].as_array().map(Vec::len), Some(0));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/projects/other/errors")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("foreign errors response: {error}"));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn project_notifications_surface_is_truthfully_unconfigured_without_notifier() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let app = router(DashboardState::new(
        EventHub::new(control),
        Duration::from_secs(5),
    ));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/projects/rimg/notifications")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("notification response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("read notifications: {error}"))
            .to_bytes(),
    )
    .unwrap_or_else(|error| panic!("decode notifications: {error}"));
    assert_eq!(payload["schema_version"], 1);
    assert_eq!(payload["project_id"], "rimg");
    assert_eq!(payload["configured"], false);
    assert_eq!(payload["records"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn mutation_http_surface_fails_closed_without_root_executor_configuration() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let app = router(DashboardState::new(
        EventHub::new(control),
        Duration::from_secs(5),
    ));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/mutations/capabilities")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("mutation capabilities response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    let capabilities: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("read capabilities: {error}"))
            .to_bytes(),
    )
    .unwrap_or_else(|error| panic!("decode capabilities: {error}"));
    assert_eq!(capabilities["schema_version"], 1);
    assert_eq!(capabilities["executor_socket_configured"], false);
    assert_eq!(capabilities["authorization_handoff_available"], false);
    assert!(capabilities["authorizer_url"].is_null());

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/mutations/status?intent_id={}&attempt_id={}",
                    Uuid::new_v4(),
                    Uuid::new_v4()
                ))
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("mutation status response: {error}"));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|error| panic!("read mutation problem: {error}"))
        .to_bytes();
    assert!(
        body.windows(b"mutation_unavailable".len())
            .any(|window| window == b"mutation_unavailable")
    );
}

#[tokio::test]
async fn health_reports_retention_failure_and_future_sample_time() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let state = DashboardState::new(EventHub::new(control), Duration::from_secs(5));
    let operation_id = Uuid::new_v4();
    *state.latest_snapshot.write().await = Some(snapshot(
        unix_time_ms().unwrap_or_else(|error| panic!("current time: {error}")),
        operation_id,
    ));
    *state.retention_error.write().await = Some("rollup JSON is corrupt".to_owned());
    let app = router(state.clone());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("retention health response: {error}"));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|error| panic!("read retention health response: {error}"))
        .to_bytes();
    assert!(
        body.windows(b"critical retention failed".len())
            .any(|window| window == b"critical retention failed")
    );
    assert!(
        !body
            .windows(b"rollup JSON is corrupt".len())
            .any(|window| window == b"rollup JSON is corrupt")
    );

    *state.retention_error.write().await = None;
    *state.latest_snapshot.write().await = Some(snapshot(i64::MAX, operation_id));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("health response: {error}"));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|error| panic!("read health problem: {error}"))
        .to_bytes();
    assert!(
        body.windows(b"sample_timestamp_in_future".len())
            .any(|window| window == b"sample_timestamp_in_future")
    );
}

#[test]
fn event_hub_enforces_connection_capacity_and_parses_resume_cursor() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let hub = EventHub::new(control);
    let streams = (0..32)
        .map(|_| {
            hub.subscribe(RequestedAfter::Absent)
                .unwrap_or_else(|error| panic!("capacity fixture: {error}"))
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        hub.subscribe(RequestedAfter::Absent),
        Err(HubError::Capacity)
    ));
    drop(streams);
    assert!(hub.subscribe(RequestedAfter::Absent).is_ok());

    assert_eq!(RequestedAfter::parse(None), RequestedAfter::Absent);
    assert_eq!(
        RequestedAfter::parse(Some("17")),
        RequestedAfter::Sequence(17)
    );
    assert_eq!(RequestedAfter::parse(Some("-1")), RequestedAfter::Invalid);
}

#[tokio::test]
async fn sse_history_gap_emits_explicit_resync_and_latest_snapshot() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let hub = EventHub::new(control);
    let operation_id = Uuid::new_v4();
    for sequence in 1..=513_i64 {
        hub.publish(
            sequence,
            DashboardEvent::Snapshot(Box::new(snapshot(sequence, operation_id))),
        )
        .unwrap_or_else(|error| panic!("publish fixture {sequence}: {error}"));
    }
    let app = router(DashboardState::new(hub, Duration::from_secs(5)));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/events?after=0")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("SSE response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);

    let mut body = response.into_body();
    let mut wire = Vec::new();
    for _ in 0..4 {
        let next = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .unwrap_or_else(|error| panic!("SSE frame timeout: {error}"));
        let Some(frame) = next else {
            break;
        };
        let frame = frame.unwrap_or_else(|error| panic!("SSE body: {error}"));
        if let Ok(data) = frame.into_data() {
            wire.extend_from_slice(&data);
        }
        let rendered = std::str::from_utf8(&wire).unwrap_or("");
        if rendered.contains("resync_required") && rendered.contains("snapshot") {
            break;
        }
    }
    let rendered = std::str::from_utf8(&wire).unwrap_or_else(|error| panic!("SSE UTF-8: {error}"));
    assert!(rendered.contains("event: resync_required"));
    assert!(rendered.contains("event: snapshot"));
    assert!(rendered.contains("id: 513"));
    assert!(rendered.contains("delivered_at_ms"));
    assert!(rendered.contains("history_unavailable"));
}

#[tokio::test]
async fn sse_empty_history_resets_a_stale_cursor_before_sequence_one() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let control = ControlStore::open(directory.path().join("control.sqlite"))
        .unwrap_or_else(|error| panic!("open control: {error}"));
    let hub = EventHub::new(control);
    let publisher = hub.clone();
    let app = router(DashboardState::new(hub, Duration::from_secs(5)));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/events?after=999")
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("request: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("SSE response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    publisher
        .publish(
            1,
            DashboardEvent::Snapshot(Box::new(snapshot(1, Uuid::new_v4()))),
        )
        .unwrap_or_else(|error| panic!("publish first snapshot: {error}"));

    let mut body = response.into_body();
    let mut wire = Vec::new();
    for _ in 0..4 {
        let next = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .unwrap_or_else(|error| panic!("SSE frame timeout: {error}"));
        let Some(frame) = next else {
            break;
        };
        let frame = frame.unwrap_or_else(|error| panic!("SSE body: {error}"));
        if let Ok(data) = frame.into_data() {
            wire.extend_from_slice(&data);
        }
        let rendered = std::str::from_utf8(&wire).unwrap_or("");
        if rendered.contains("id: 0") && rendered.contains("id: 1") {
            break;
        }
    }
    let rendered = std::str::from_utf8(&wire).unwrap_or_else(|error| panic!("SSE UTF-8: {error}"));
    let reset_position = rendered
        .find("id: 0")
        .unwrap_or_else(|| panic!("empty-history reset is missing: {rendered}"));
    let snapshot_position = rendered
        .find("id: 1")
        .unwrap_or_else(|| panic!("first snapshot is missing: {rendered}"));
    assert!(reset_position < snapshot_position);
    assert!(rendered.contains("event: resync_required"));
    assert!(rendered.contains("history_unavailable"));
    assert!(rendered.contains("\"latest_available\":0"));
}

#[test]
fn browser_assets_use_safe_dom_updates_and_central_live_regions() {
    let html = include_str!("../web/index.html");
    let javascript = include_str!("../web/app.js");
    let status_javascript = include_str!("../web/status.js");
    let css = include_str!("../web/app.css");

    assert_eq!(html.matches("aria-live=\"polite\"").count(), 1);
    assert_eq!(html.matches("aria-live=\"assertive\"").count(), 1);
    assert!(html.contains("class=\"skip-link\""));
    assert!(html.contains("scope=\"col\""));
    assert!(!javascript.contains("innerHTML"));
    assert!(javascript.contains("textContent"));
    assert!(javascript.contains("evaluateHostObservation"));
    assert!(javascript.contains("envelope.delivered_at_ms"));
    assert!(javascript.contains("performance.now()"));
    assert!(!javascript.contains("Date.now()"));
    assert!(html.contains("<th scope=\"col\">Уведомления</th>"));
    assert!(javascript.contains("validProjectNotifications"));
    assert!(javascript.contains("delivered_possible_duplicate"));
    assert!(javascript.contains("/notifications"));
    assert!(html.contains("id=\"workflow-heading\">Workflow и деплои</h2>"));
    assert!(html.contains("Текущее состояние и последние значимые деплои установленных проектов"));
    assert!(javascript.contains("validWorkflowOverview"));
    assert!(javascript.contains("/api/v1/workflows?limit=50"));
    assert!(status_javascript.contains("projectConditionLabels"));
    assert!(status_javascript.contains("notificationStateLabels"));
    assert!(status_javascript.contains("workflowAttemptLabels"));
    assert!(status_javascript.contains("signal_lost: \"× Сигнал потерян\""));
    assert!(status_javascript.contains("intervalMs * 2"));
    assert!(status_javascript.contains("intervalMs * 3"));
    assert!(css.contains("prefers-reduced-motion: reduce"));
    assert!(css.contains("@supports not (content-visibility: auto)"));
    assert!(css.contains("overflow-x: auto"));
    assert!(css.contains(".project-table th:nth-child(9)"));
    assert!(css.contains(".notification-timestamp"));
    assert!(css.contains("white-space: nowrap"));
    assert!(javascript.contains("Медиана CPU / RAM"));
    assert!(javascript.contains("Трафик за 1 час"));
    assert!(javascript.contains("appendProjectTimestamp"));
}
