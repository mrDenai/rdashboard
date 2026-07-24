#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    sync::Arc,
    time::Duration,
};

use rdashboard::workflow_launcher_socket::{
    BoundWorkflowLauncherSocketV1, WORKFLOW_LAUNCHER_PROTOCOL_VERSION, WorkflowLauncherClientV1,
    WorkflowLauncherRequestEnvelopeV1, WorkflowLauncherRequestHandlerV1, WorkflowLauncherRequestV1,
    WorkflowLauncherResponseEnvelopeV1, WorkflowLauncherResponseV1, WorkflowLauncherServerConfigV1,
    WorkflowLauncherSocketError, serve_launcher_connection, serve_launcher_until,
};
use tempfile::tempdir;
use tokio::{net::UnixStream, sync::oneshot};
use uuid::Uuid;

#[derive(Debug)]
struct ReadOnlyTestHandler;

impl WorkflowLauncherRequestHandlerV1 for ReadOnlyTestHandler {
    fn handle(
        &self,
        request: WorkflowLauncherRequestEnvelopeV1,
    ) -> WorkflowLauncherResponseEnvelopeV1 {
        let response = match request.request {
            WorkflowLauncherRequestV1::Negotiate { supported_versions }
                if supported_versions.contains(&WORKFLOW_LAUNCHER_PROTOCOL_VERSION) =>
            {
                WorkflowLauncherResponseV1::Negotiated {
                    selected_version: WORKFLOW_LAUNCHER_PROTOCOL_VERSION,
                }
            }
            WorkflowLauncherRequestV1::Observe { .. } => WorkflowLauncherResponseV1::NotFound,
            _ => panic!("unexpected launcher request in read-only fixture"),
        };
        WorkflowLauncherResponseEnvelopeV1 {
            version: WORKFLOW_LAUNCHER_PROTOCOL_VERSION,
            request_id: request.request_id,
            response,
        }
    }
}

#[tokio::test]
async fn one_generic_client_negotiates_and_observes_over_the_protected_socket() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))
        .unwrap_or_else(|error| panic!("protect socket directory: {error}"));
    let metadata = fs::metadata(directory.path())
        .unwrap_or_else(|error| panic!("socket directory metadata: {error}"));
    assert_ne!(metadata.uid(), 0);
    assert_ne!(metadata.gid(), 0);
    let socket_path = directory.path().join("launcher.sock");
    let mut socket =
        BoundWorkflowLauncherSocketV1::bind(&socket_path, metadata.uid(), metadata.gid())
            .unwrap_or_else(|error| panic!("bind launcher socket: {error}"));
    let listener = socket.take_listener();
    let config = WorkflowLauncherServerConfigV1::new(metadata.uid(), 4, Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("server config: {error}"));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_launcher_until(
        listener,
        Arc::new(ReadOnlyTestHandler),
        config,
        async move {
            let _ = shutdown_rx.await;
        },
    ));
    let client = WorkflowLauncherClientV1::new(&socket_path, Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("launcher client: {error}"));
    let observed = client
        .observe(Uuid::from_u128(41), 1)
        .await
        .unwrap_or_else(|error| panic!("observe missing launch: {error}"));
    assert!(observed.is_none());
    let _ = shutdown_tx.send(());
    server
        .await
        .unwrap_or_else(|error| panic!("join launcher server: {error}"))
        .unwrap_or_else(|error| panic!("launcher server: {error}"));
}

#[tokio::test]
async fn peer_uid_is_checked_before_a_request_is_decoded() {
    let (client, server) = UnixStream::pair().expect("socket pair");
    let current_uid = server.peer_cred().expect("peer credentials").uid();
    let rejected_uid = current_uid.checked_add(1).expect("different UID");
    let config = WorkflowLauncherServerConfigV1::new(rejected_uid, 1, Duration::from_secs(1))
        .expect("server config");
    drop(client);
    let error = serve_launcher_connection(server, Arc::new(ReadOnlyTestHandler), &config)
        .await
        .expect_err("wrong peer UID must be rejected");
    assert!(matches!(
        error,
        WorkflowLauncherSocketError::UnauthorizedPeer {
            received
        } if received == current_uid
    ));
}

#[test]
fn malformed_protocol_inputs_fail_validation() {
    let invalid_version = WorkflowLauncherRequestEnvelopeV1 {
        version: WORKFLOW_LAUNCHER_PROTOCOL_VERSION + 1,
        request_id: Uuid::new_v4(),
        request: WorkflowLauncherRequestV1::Observe {
            lease_id: Uuid::new_v4(),
            lease_generation: 1,
        },
    };
    assert!(invalid_version.validate().is_err());
    let nil_locator = WorkflowLauncherRequestEnvelopeV1 {
        version: WORKFLOW_LAUNCHER_PROTOCOL_VERSION,
        request_id: Uuid::new_v4(),
        request: WorkflowLauncherRequestV1::Observe {
            lease_id: Uuid::nil(),
            lease_generation: 0,
        },
    };
    assert!(nil_locator.validate().is_err());

    let service = include_str!("../deploy/systemd/rdashboard-workflow-launcher.service");
    assert!(service.contains("User=root\nGroup=rdashboard-worker"));
    assert!(service.contains("PrivateNetwork=yes"));
    assert!(service.contains("RestrictAddressFamilies=AF_UNIX"));
    assert!(service.contains(
        "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID"
    ));
    assert!(service.contains(
        "AmbientCapabilities=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID"
    ));
    assert!(service.contains("/var/lib/rdashboard-build/operations"));
    assert!(service.contains("InaccessiblePaths="));
    assert!(!service.contains("ReadWritePaths=/run/docker.sock"));
    let tmpfiles = include_str!("../deploy/systemd/rdashboard-tmpfiles.conf");
    assert!(tmpfiles.contains("d /var/lib/rdashboard-workflow-launcher/jobs 0700 root root -"));
    assert!(tmpfiles.contains("d /var/lib/rdashboard-build/operations 0700 root root -"));
}
