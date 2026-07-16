use std::{path::Path, str::FromStr, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt as _;
use rdashboard::{
    domain::{
        ControlSummary, DashboardEvent, DashboardSnapshot, HostTelemetry, ObservationStatus,
        ProjectCondition, ProjectId, ProjectTelemetry, PsiMeasurement,
    },
    store::{ControlStore, MINIMUM_SAFE_SQLITE_VERSION_NUMBER, MetricsStore, StoreError},
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
            supported: 1
        })
    ));
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
    assert!(html.contains("Контур операций"));
    assert!(html.contains("Авторизатор действий не подключён"));
    assert!(!html.contains("<script>"));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/assets/status.js")
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
    assert!(status_javascript.contains("projectConditionLabels"));
    assert!(status_javascript.contains("signal_lost: \"× Сигнал потерян\""));
    assert!(status_javascript.contains("intervalMs * 2"));
    assert!(status_javascript.contains("intervalMs * 3"));
    assert!(css.contains("prefers-reduced-motion: reduce"));
    assert!(css.contains("@supports not (content-visibility: auto)"));
}
