#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use rdashboard::{
    domain::ProjectId,
    observer::{
        BoundObserverSocketV1, OBSERVER_PROTOCOL_VERSION, ObserverClientError, ObserverClientV1,
        ObserverQueryV1, ObserverRejectionCodeV1, ObserverRequestHandlerV1, ObserverRequestV1,
        ObserverServerConfig, ObserverSocketError, ObserverValidationError,
        PROJECT_RESOURCE_SNAPSHOT_SCHEMA_VERSION, ProjectResourceSnapshotV1, serve_connection,
    },
};
use uuid::Uuid;

#[derive(Debug)]
struct FixtureObserver {
    project_id: ProjectId,
}

#[derive(Debug)]
struct SlowObserver {
    completed: Arc<AtomicBool>,
}

impl ObserverRequestHandlerV1 for SlowObserver {
    fn observe_project_resources(
        &self,
        _project_id: &ProjectId,
    ) -> Result<ProjectResourceSnapshotV1, ObserverRejectionCodeV1> {
        std::thread::sleep(Duration::from_millis(150));
        self.completed.store(true, Ordering::Release);
        Ok(resource_snapshot(123))
    }
}

impl ObserverRequestHandlerV1 for FixtureObserver {
    fn observe_project_resources(
        &self,
        project_id: &ProjectId,
    ) -> Result<ProjectResourceSnapshotV1, ObserverRejectionCodeV1> {
        if project_id != &self.project_id {
            return Err(ObserverRejectionCodeV1::ProjectNotConfigured);
        }
        Ok(resource_snapshot(123))
    }
}

fn resource_snapshot(observed_at_ms: i64) -> ProjectResourceSnapshotV1 {
    ProjectResourceSnapshotV1 {
        schema_version: PROJECT_RESOURCE_SNAPSHOT_SCHEMA_VERSION,
        observed_at_ms,
        cpu_percent: 1.5,
        memory_used_bytes: 20,
        memory_limit_bytes: 100,
        network_rx_bytes: 1_000,
        network_tx_bytes: 2_000,
        block_read_bytes: 3_000,
        block_write_bytes: 4_000,
    }
}

fn project_id(value: &str) -> ProjectId {
    value
        .parse()
        .unwrap_or_else(|error| panic!("project fixture: {error}"))
}

fn protected_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))
        .unwrap_or_else(|error| panic!("protect temp dir: {error}"));
    directory
}

fn owner_uid(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("metadata: {error}"))
        .uid()
}

#[test]
fn request_and_snapshot_contracts_reject_ambiguous_evidence() {
    let request = ObserverRequestV1 {
        schema_version: OBSERVER_PROTOCOL_VERSION,
        request_id: Uuid::new_v4(),
        query: ObserverQueryV1::ProjectResources {
            project_id: project_id("rimg"),
        },
    };
    assert_eq!(request.validate(), Ok(()));

    let mut wrong_version = request.clone();
    wrong_version.schema_version = OBSERVER_PROTOCOL_VERSION + 1;
    assert_eq!(
        wrong_version.validate(),
        Err(ObserverValidationError::UnsupportedVersion(
            OBSERVER_PROTOCOL_VERSION + 1
        ))
    );
    let mut nil_request = request;
    nil_request.request_id = Uuid::nil();
    assert_eq!(
        nil_request.validate(),
        Err(ObserverValidationError::NilRequestId)
    );

    assert_eq!(resource_snapshot(123).validate(), Ok(()));
    let mut invalid = resource_snapshot(123);
    invalid.memory_used_bytes = invalid.memory_limit_bytes + 1;
    assert_eq!(
        invalid.validate(),
        Err(ObserverValidationError::InvalidResourceMeasurement)
    );
    let mut invalid = resource_snapshot(-1);
    assert_eq!(
        invalid.validate(),
        Err(ObserverValidationError::InvalidObservationTime)
    );
    invalid.observed_at_ms = 123;
    invalid.cpu_percent = f64::NAN;
    assert_eq!(
        invalid.validate(),
        Err(ObserverValidationError::InvalidResourceMeasurement)
    );
}

#[tokio::test]
async fn typed_client_receives_only_the_bound_project_resource_snapshot() {
    let directory = protected_directory();
    let socket_path = directory.path().join("observer.sock");
    let uid = owner_uid(directory.path());
    assert_ne!(uid, 0, "test requires the ordinary non-root workspace user");
    let mut socket = BoundObserverSocketV1::bind(&socket_path, uid)
        .unwrap_or_else(|error| panic!("bind observer: {error}"));
    let listener = socket.take_listener();
    let server_config = ObserverServerConfig::new(uid, 2, Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("server config: {error}"));
    let handler = Arc::new(FixtureObserver {
        project_id: project_id("rimg"),
    });
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("accept observer: {error}"));
        serve_connection(stream, handler, &server_config).await
    });
    let client = ObserverClientV1::new(&socket_path, Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("observer client: {error}"));

    let snapshot = client
        .observe_project_resources(project_id("rimg"))
        .await
        .unwrap_or_else(|error| panic!("observe project: {error}"));
    assert_eq!(snapshot, resource_snapshot(123));
    server
        .await
        .unwrap_or_else(|error| panic!("server task: {error}"))
        .unwrap_or_else(|error| panic!("server response: {error}"));
}

#[tokio::test]
async fn unknown_project_is_a_typed_non_retryable_rejection() {
    let directory = protected_directory();
    let socket_path = directory.path().join("observer.sock");
    let uid = owner_uid(directory.path());
    let mut socket = BoundObserverSocketV1::bind(&socket_path, uid)
        .unwrap_or_else(|error| panic!("bind observer: {error}"));
    let listener = socket.take_listener();
    let server_config = ObserverServerConfig::new(uid, 1, Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("server config: {error}"));
    let handler = Arc::new(FixtureObserver {
        project_id: project_id("rimg"),
    });
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("accept observer: {error}"));
        serve_connection(stream, handler, &server_config).await
    });
    let client = ObserverClientV1::new(&socket_path, Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("observer client: {error}"));

    assert!(matches!(
        client.observe_project_resources(project_id("other")).await,
        Err(ObserverClientError::Rejected {
            code: ObserverRejectionCodeV1::ProjectNotConfigured,
            retryable: false,
        })
    ));
    server
        .await
        .unwrap_or_else(|error| panic!("server task: {error}"))
        .unwrap_or_else(|error| panic!("server response: {error}"));
}

#[tokio::test]
async fn peer_uid_is_checked_before_any_request_is_processed() {
    let directory = protected_directory();
    let socket_path = directory.path().join("observer.sock");
    let uid = owner_uid(directory.path());
    let mut socket = BoundObserverSocketV1::bind(&socket_path, uid)
        .unwrap_or_else(|error| panic!("bind observer: {error}"));
    let listener = socket.take_listener();
    let wrong_uid = uid.checked_add(1).expect("ordinary UID has room");
    let server_config = ObserverServerConfig::new(wrong_uid, 1, Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("server config: {error}"));
    let handler = Arc::new(FixtureObserver {
        project_id: project_id("rimg"),
    });
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("accept observer: {error}"));
        serve_connection(stream, handler, &server_config).await
    });
    let client = ObserverClientV1::new(&socket_path, Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("observer client: {error}"));
    assert!(
        client
            .observe_project_resources(project_id("rimg"))
            .await
            .is_err()
    );
    assert!(matches!(
        server
            .await
            .unwrap_or_else(|error| panic!("server task: {error}")),
        Err(ObserverSocketError::UnauthorizedPeer { received }) if received == uid
    ));
}

#[tokio::test]
async fn expired_connection_drains_its_blocking_handler_before_releasing_the_slot() {
    let directory = protected_directory();
    let socket_path = directory.path().join("observer.sock");
    let uid = owner_uid(directory.path());
    let mut socket = BoundObserverSocketV1::bind(&socket_path, uid)
        .unwrap_or_else(|error| panic!("bind observer: {error}"));
    let listener = socket.take_listener();
    let server_config = ObserverServerConfig::new(uid, 1, Duration::from_millis(100))
        .unwrap_or_else(|error| panic!("server config: {error}"));
    let completed = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(SlowObserver {
        completed: Arc::clone(&completed),
    });
    let started_at = Instant::now();
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("accept observer: {error}"));
        serve_connection(stream, handler, &server_config).await
    });
    let client = ObserverClientV1::new(&socket_path, Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("observer client: {error}"));

    assert!(
        client
            .observe_project_resources(project_id("rimg"))
            .await
            .is_err()
    );
    assert!(matches!(
        server
            .await
            .unwrap_or_else(|error| panic!("server task: {error}")),
        Err(ObserverSocketError::DeadlineExceeded)
    ));
    assert!(completed.load(Ordering::Acquire));
    assert!(started_at.elapsed() >= Duration::from_millis(150));
}

#[tokio::test]
async fn stale_socket_is_reconciled_but_a_live_socket_is_never_replaced() {
    let directory = protected_directory();
    let socket_path = directory.path().join("observer.sock");
    let uid = owner_uid(directory.path());
    let stale = std::os::unix::net::UnixListener::bind(&socket_path)
        .unwrap_or_else(|error| panic!("bind stale socket: {error}"));
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))
        .unwrap_or_else(|error| panic!("protect stale socket: {error}"));
    drop(stale);

    let reconciled = BoundObserverSocketV1::bind(&socket_path, uid)
        .unwrap_or_else(|error| panic!("reconcile stale socket: {error}"));
    drop(reconciled);

    let live = std::os::unix::net::UnixListener::bind(&socket_path)
        .unwrap_or_else(|error| panic!("bind live socket: {error}"));
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))
        .unwrap_or_else(|error| panic!("protect live socket: {error}"));
    assert!(matches!(
        BoundObserverSocketV1::bind(&socket_path, uid),
        Err(ObserverSocketError::SocketPathExists)
    ));
    drop(live);
}
