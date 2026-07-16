#![cfg(unix)]

use std::{
    os::unix::fs::{FileTypeExt as _, PermissionsExt as _},
    path::PathBuf,
    str::FromStr as _,
    time::Duration,
};

use rdashboard::{
    domain::{
        MutationExecutionStateV1, MutationStatusV1, OperationKind, OperationPhase, ProjectId,
    },
    executor_socket::{
        BoundExecutorSocket, ControlRequestHandler, ExecutorConfigError, ExecutorServerConfig,
        ExecutorSocketError, ROOT_EXECUTOR_CONFIG_SCHEMA_VERSION, ROOT_EXECUTOR_SOCKET_PATH,
        ReadOnlyExecutorHandler, RootExecutorClient, RootExecutorConfigV1, serve_connection,
    },
    mutation_admission::{
        ExecuteMutationGrantV1, MutationAcceptanceV1, MutationControlFailureV1, MutationControlV1,
        ObserveMutationStatusV1, PrepareMutationIntentV1,
    },
    protocol::{
        CONTROL_PROTOCOL_VERSION, ControlRejectionCodeV1, ControlRequestEnvelope, ControlRequestV1,
        ControlResponseEnvelope, ControlResponseV1, NORMAL_FRAME_MAX_BYTES,
        OBSERVATION_FRAME_MAX_BYTES, encode_frame, read_frame, write_frame,
    },
};
use tempfile::tempdir;
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;
use uuid::Uuid;

#[derive(Debug)]
struct FakeMutationControl;

impl MutationControlV1 for FakeMutationControl {
    fn prepare_intent(
        &self,
        request: &PrepareMutationIntentV1,
        _now_ms: i64,
    ) -> Result<String, MutationControlFailureV1> {
        Ok(format!("signed-intent:{}", request.idempotency_key))
    }

    fn accept_grant(
        &self,
        request: &ExecuteMutationGrantV1,
        _now_ms: i64,
    ) -> Result<MutationAcceptanceV1, MutationControlFailureV1> {
        Ok(MutationAcceptanceV1 {
            intent_id: request.intent_id,
            attempt_id: request.attempt_id,
            replayed: false,
        })
    }

    fn mutation_status(
        &self,
        request: &ObserveMutationStatusV1,
    ) -> Result<MutationStatusV1, MutationControlFailureV1> {
        Ok(MutationStatusV1 {
            intent_id: request.intent_id,
            attempt_id: request.attempt_id,
            project_id: ProjectId::from_str("rimg")
                .unwrap_or_else(|error| panic!("project: {error}")),
            operation_kind: OperationKind::BackupOnly,
            target_commit: None,
            effective_release_class: None,
            state: MutationExecutionStateV1::Accepted,
            current_phase: OperationPhase::Queued,
            completed_phases: Vec::new(),
            accepted_at_ms: 10,
            updated_at_ms: 10,
        })
    }
}

fn request(request: ControlRequestV1) -> ControlRequestEnvelope {
    ControlRequestEnvelope {
        version: CONTROL_PROTOCOL_VERSION,
        request_id: Uuid::new_v4(),
        request,
    }
}

fn valid_config() -> RootExecutorConfigV1 {
    RootExecutorConfigV1 {
        schema_version: ROOT_EXECUTOR_CONFIG_SCHEMA_VERSION,
        controller_uid: 991,
        socket_path: PathBuf::from(ROOT_EXECUTOR_SOCKET_PATH),
        metrics_disk_path: PathBuf::from("/"),
        max_connections: 16,
        request_timeout_ms: 2_000,
        mutation_authority: None,
    }
}

#[test]
fn root_executor_config_is_fixed_bounded_and_non_root() {
    valid_config()
        .validate()
        .unwrap_or_else(|error| panic!("valid root executor config: {error}"));

    let mut config = valid_config();
    config.controller_uid = 0;
    assert_eq!(
        config.validate(),
        Err(ExecutorConfigError::InvalidControllerUid)
    );

    let mut config = valid_config();
    config.socket_path = PathBuf::from("/tmp/controller-selected.sock");
    assert_eq!(
        config.validate(),
        Err(ExecutorConfigError::InvalidSocketPath)
    );

    let mut config = valid_config();
    config.metrics_disk_path = PathBuf::from("/var/../etc");
    assert_eq!(
        config.validate(),
        Err(ExecutorConfigError::InvalidMetricsDiskPath)
    );

    let mut config = valid_config();
    config.request_timeout_ms = 30_001;
    assert_eq!(
        config.validate(),
        Err(ExecutorConfigError::InvalidRequestTimeout)
    );
}

#[test]
fn read_only_handler_reports_real_host_data_and_fails_mutation_closed() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let handler = ReadOnlyExecutorHandler::linux(temp.path());
    let host_request = request(ControlRequestV1::ObserveHostSnapshot);
    let host_response = handler.handle(host_request.clone());
    assert_eq!(host_response.request_id, host_request.request_id);
    match host_response.response {
        ControlResponseV1::HostSnapshot { snapshot } => {
            assert!(snapshot.observed_at_ms > 0);
            assert!(snapshot.disk_total_bytes.is_some());
        }
        response => panic!("unexpected host response: {response:?}"),
    }

    let mutation_request = request(ControlRequestV1::ExecuteGrantedOperation {
        intent_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        action_grant: "x".repeat(32),
    });
    assert!(matches!(
        handler.handle(mutation_request).response,
        ControlResponseV1::Rejected {
            code: ControlRejectionCodeV1::MutationAuthorityUnavailable,
            retryable: false,
        }
    ));

    let project_id = ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project: {error}"));
    let docker_request = request(ControlRequestV1::ObserveDockerSnapshot { project_id });
    assert!(matches!(
        handler.handle(docker_request).response,
        ControlResponseV1::Rejected {
            code: ControlRejectionCodeV1::ProjectObservationNotConfigured,
            retryable: false,
        }
    ));

    let prepare_request = request(ControlRequestV1::PrepareOperationIntent {
        project_id: ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project: {error}")),
        operation_kind: OperationKind::BackupOnly,
        target_commit: None,
        release_class: None,
        idempotency_key: Uuid::new_v4(),
    });
    assert!(matches!(
        handler.handle(prepare_request).response,
        ControlResponseV1::Rejected {
            code: ControlRejectionCodeV1::MutationAuthorityUnavailable,
            retryable: false,
        }
    ));
}

#[test]
fn mutation_handler_acknowledges_only_durable_admission_not_phase_completion() {
    let handler = ReadOnlyExecutorHandler::linux_with_mutation_control(
        "/",
        std::sync::Arc::new(FakeMutationControl),
    );
    assert!(handler.mutation_authority_loaded());
    assert!(handler.mutation_enabled());
    let idempotency_key = Uuid::new_v4();
    let prepared = handler.handle(request(ControlRequestV1::PrepareOperationIntent {
        project_id: ProjectId::from_str("rimg").unwrap_or_else(|error| panic!("project: {error}")),
        operation_kind: OperationKind::BackupOnly,
        target_commit: None,
        release_class: None,
        idempotency_key,
    }));
    assert_eq!(
        prepared.response,
        ControlResponseV1::OperationIntentPrepared {
            signed_intent: format!("signed-intent:{idempotency_key}"),
        }
    );

    let intent_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let accepted = handler.handle(request(ControlRequestV1::ExecuteGrantedOperation {
        intent_id,
        attempt_id,
        action_grant: "x".repeat(32),
    }));
    assert_eq!(
        accepted.response,
        ControlResponseV1::OperationAccepted {
            intent_id,
            attempt_id,
            replayed: false,
        }
    );
    let status = handler.handle(request(ControlRequestV1::ObserveMutationStatus {
        intent_id,
        attempt_id,
    }));
    assert!(matches!(
        status.response,
        ControlResponseV1::MutationStatus { status }
            if status.intent_id == intent_id
                && status.attempt_id == attempt_id
                && status.state == MutationExecutionStateV1::Accepted
    ));
}

#[tokio::test]
async fn socket_round_trip_requires_the_exact_peer_uid() {
    let (server, mut client) =
        UnixStream::pair().unwrap_or_else(|error| panic!("socket pair: {error}"));
    let peer_uid = server
        .peer_cred()
        .unwrap_or_else(|error| panic!("peer credentials: {error}"))
        .uid();
    let config = ExecutorServerConfig::new(peer_uid, 1, Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("server config: {error}"));
    let handler = ReadOnlyExecutorHandler::linux("/");
    let task = tokio::spawn(async move { serve_connection(server, &handler, &config).await });

    let negotiate = request(ControlRequestV1::Negotiate {
        supported_versions: vec![CONTROL_PROTOCOL_VERSION],
    });
    write_frame(&mut client, &negotiate, NORMAL_FRAME_MAX_BYTES)
        .await
        .unwrap_or_else(|error| panic!("write request: {error}"));
    client
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown request: {error}"));
    let response: ControlResponseEnvelope<ControlResponseV1> =
        read_frame(&mut client, OBSERVATION_FRAME_MAX_BYTES)
            .await
            .unwrap_or_else(|error| panic!("read response: {error}"));
    assert_eq!(response.request_id, negotiate.request_id);
    assert_eq!(
        response.response,
        ControlResponseV1::Negotiated {
            selected_version: CONTROL_PROTOCOL_VERSION,
        }
    );
    task.await
        .unwrap_or_else(|error| panic!("server task: {error}"))
        .unwrap_or_else(|error| panic!("serve connection: {error}"));

    let (server, _client) =
        UnixStream::pair().unwrap_or_else(|error| panic!("socket pair: {error}"));
    let unauthorized_uid = peer_uid.wrapping_add(1);
    let config = ExecutorServerConfig::new(unauthorized_uid, 1, Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("server config: {error}"));
    assert!(matches!(
        serve_connection(server, &ReadOnlyExecutorHandler::linux("/"), &config).await,
        Err(ExecutorSocketError::UnauthorizedPeer { received }) if received == peer_uid
    ));
}

#[tokio::test]
async fn incomplete_request_is_bounded_by_the_connection_deadline() {
    let (server, _client) =
        UnixStream::pair().unwrap_or_else(|error| panic!("socket pair: {error}"));
    let peer_uid = server
        .peer_cred()
        .unwrap_or_else(|error| panic!("peer credentials: {error}"))
        .uid();
    let config = ExecutorServerConfig::new(peer_uid, 1, Duration::from_millis(100))
        .unwrap_or_else(|error| panic!("server config: {error}"));
    assert!(matches!(
        serve_connection(server, &ReadOnlyExecutorHandler::linux("/"), &config).await,
        Err(ExecutorSocketError::DeadlineExceeded)
    ));
}

#[tokio::test]
async fn trailing_request_bytes_are_rejected_before_dispatch() {
    let (server, mut client) =
        UnixStream::pair().unwrap_or_else(|error| panic!("socket pair: {error}"));
    let peer_uid = server
        .peer_cred()
        .unwrap_or_else(|error| panic!("peer credentials: {error}"))
        .uid();
    let config = ExecutorServerConfig::new(peer_uid, 1, Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("server config: {error}"));
    let task = tokio::spawn(async move {
        serve_connection(server, &ReadOnlyExecutorHandler::linux("/"), &config).await
    });
    let negotiate = request(ControlRequestV1::Negotiate {
        supported_versions: vec![CONTROL_PROTOCOL_VERSION],
    });
    let mut frame = encode_frame(&negotiate, NORMAL_FRAME_MAX_BYTES)
        .unwrap_or_else(|error| panic!("encode request: {error}"));
    frame.push(0);
    client
        .write_all(&frame)
        .await
        .unwrap_or_else(|error| panic!("write request: {error}"));
    client
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown request: {error}"));
    assert!(matches!(
        task.await
            .unwrap_or_else(|error| panic!("server task: {error}")),
        Err(ExecutorSocketError::Frame(
            rdashboard::protocol::FrameError::TrailingBytes(1)
        ))
    ));
}

#[tokio::test]
async fn root_executor_client_negotiates_then_collects_a_bound_snapshot() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let socket_path = temp.path().join("executor.sock");
    let mut socket = BoundExecutorSocket::bind(&socket_path)
        .unwrap_or_else(|error| panic!("bind executor socket: {error}"));
    let listener = socket.take_listener();
    let server = tokio::spawn(async move {
        let _socket = socket;
        let handler = ReadOnlyExecutorHandler::linux("/");
        for _ in 0..2 {
            let (stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("accept: {error}"));
            let peer_uid = stream
                .peer_cred()
                .unwrap_or_else(|error| panic!("peer credentials: {error}"))
                .uid();
            let config = ExecutorServerConfig::new(peer_uid, 1, Duration::from_secs(1))
                .unwrap_or_else(|error| panic!("server config: {error}"));
            serve_connection(stream, &handler, &config)
                .await
                .unwrap_or_else(|error| panic!("serve connection: {error}"));
        }
    });
    let client = RootExecutorClient::new(&socket_path, Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("executor client: {error}"));
    let snapshot = client
        .observe_host()
        .await
        .unwrap_or_else(|error| panic!("observe host: {error}"));
    assert!(snapshot.observed_at_ms > 0);
    assert!(snapshot.memory_total_bytes.is_some());
    server
        .await
        .unwrap_or_else(|error| panic!("server task: {error}"));
}

#[tokio::test]
async fn bound_socket_refuses_replacement_and_removes_only_its_own_inode() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let socket_path = temp.path().join("executor.sock");
    let socket = BoundExecutorSocket::bind(&socket_path)
        .unwrap_or_else(|error| panic!("bind executor socket: {error}"));
    let metadata = std::fs::symlink_metadata(&socket_path)
        .unwrap_or_else(|error| panic!("socket metadata: {error}"));
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
    assert!(matches!(
        BoundExecutorSocket::bind(&socket_path),
        Err(ExecutorSocketError::SocketPathExists)
    ));
    drop(socket);
    assert!(!socket_path.exists());
}
