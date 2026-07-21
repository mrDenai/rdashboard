#![cfg(unix)]

use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use ed25519_dalek::SigningKey;
use rdashboard::{
    domain::{
        AbsolutePolicyPath, EvidenceDigest, GitCommitId, HttpEndpoint, OperationKind, ProjectId,
        ProjectManifestV2, RemoteUrl, WorkflowCleanupReceiptV1, WorkflowCleanupResultV1,
        WorkflowNodeOutcomeV1, WorkflowNodeReceiptV1, WorkflowWorkerPoolV1,
    },
    scheduler::{
        DurableWorkflowScheduler, WorkflowAdmissionV1, WorkflowCleanupReasonV1,
        WorkflowTriggerChannelV1, WorkflowWorkerRegistrationV1,
    },
    store::ControlStore,
    worker_socket::{
        BoundWorkflowWorkerSocketV1, SchedulerWorkflowWorkerHandlerV1, WORKER_PROTOCOL_VERSION,
        WorkflowGatewayClockError, WorkflowGatewayClockV1, WorkflowWorkerAssignmentV1,
        WorkflowWorkerClientV1, WorkflowWorkerHandlerConfigError, WorkflowWorkerRequestEnvelopeV1,
        WorkflowWorkerRequestV1, WorkflowWorkerServerConfigV1, WorkflowWorkerSocketError,
        WorkflowWorkerValidationError, serve_worker_connection, serve_worker_until,
    },
    workflow_execution_grant::{
        WorkflowExecutionGrantSignerV1, WorkflowExecutionGrantVerificationKeyV1,
        WorkflowExecutionGrantVerifierV1,
    },
};
use tempfile::tempdir;
use tokio::{net::UnixStream, sync::oneshot};
use uuid::Uuid;

fn digest(label: impl AsRef<[u8]>) -> EvidenceDigest {
    EvidenceDigest::sha256(label)
}

fn manifest(project: &str, fairness_weight: u16) -> ProjectManifestV2 {
    let mut manifest: ProjectManifestV2 =
        serde_json::from_str(include_str!("../config/project-manifests/ralert.json"))
            .unwrap_or_else(|error| panic!("decode workflow manifest: {error}"));
    manifest.project_id =
        ProjectId::from_str(project).unwrap_or_else(|error| panic!("project fixture: {error}"));
    manifest.display_name = format!("{project} worker protocol fixture");
    manifest.source.remote_url =
        RemoteUrl::from_str(&format!("https://github.com/example/{project}.git"))
            .unwrap_or_else(|error| panic!("remote fixture: {error}"));
    for check in &mut manifest.health_checks {
        check.endpoint =
            HttpEndpoint::from_str(&format!("http://{project}:8080/health/{}", check.name))
                .unwrap_or_else(|error| panic!("health fixture: {error}"));
    }
    manifest.data_volumes[0].path =
        AbsolutePolicyPath::from_str(&format!("/var/lib/{project}/templates"))
            .unwrap_or_else(|error| panic!("data path fixture: {error}"));
    manifest.data_volumes[1].path =
        AbsolutePolicyPath::from_str(&format!("/var/lib/{project}/images"))
            .unwrap_or_else(|error| panic!("data path fixture: {error}"));
    manifest.workflow.fairness_weight = fairness_weight;
    manifest
        .validate()
        .unwrap_or_else(|error| panic!("validate workflow fixture: {error}"));
    manifest
}

fn admission(
    manifest: &ProjectManifestV2,
    sha_byte: char,
    sequence: u64,
    delivery_id: &str,
) -> WorkflowAdmissionV1 {
    WorkflowAdmissionV1 {
        project_id: manifest.project_id.clone(),
        workflow_policy_digest: manifest
            .workflow_policy_digest()
            .unwrap_or_else(|error| panic!("policy digest: {error}")),
        source_sha: GitCommitId::from_str(&sha_byte.to_string().repeat(40))
            .unwrap_or_else(|error| panic!("source SHA: {error}")),
        operation_kind: OperationKind::Deploy,
        source_sequence: sequence,
        source_attestation_digest: digest(format!("attestation-{delivery_id}")),
        trigger_channel: WorkflowTriggerChannelV1::GithubWebhook,
        delivery_id: delivery_id.to_owned(),
        payload_digest: digest(format!("payload-{delivery_id}")),
        priority: 2,
    }
}

fn worker() -> WorkflowWorkerRegistrationV1 {
    WorkflowWorkerRegistrationV1 {
        worker_id: "shared-vps-worker".to_owned(),
        host_id: "production-vps".to_owned(),
        pools: BTreeSet::from([
            WorkflowWorkerPoolV1::BuildCompute,
            WorkflowWorkerPoolV1::VpsRequired,
        ]),
    }
}

fn grant_signer() -> Arc<WorkflowExecutionGrantSignerV1> {
    Arc::new(
        WorkflowExecutionGrantSignerV1::new(
            "workflow-gateway",
            "workflow-launcher",
            "workflow-key-1",
            1,
            SigningKey::from_bytes(&[37_u8; 32]),
        )
        .expect("workflow grant signer"),
    )
}

fn grant_verifier() -> WorkflowExecutionGrantVerifierV1 {
    WorkflowExecutionGrantVerifierV1::new(
        "workflow-gateway",
        "workflow-launcher",
        1,
        [WorkflowExecutionGrantVerificationKeyV1::new(
            "workflow-key-1",
            1,
            SigningKey::from_bytes(&[37_u8; 32]).verifying_key(),
            0,
            None,
            None,
            None,
        )
        .expect("grant verification key")],
    )
    .expect("grant verifier")
}

fn verify_execution_grant(token: &str, lease: &rdashboard::domain::WorkflowLeaseV1, now_ms: i64) {
    grant_verifier()
        .verify(token, lease, now_ms)
        .expect("verify execution grant");
}

fn protected_directory() -> tempfile::TempDir {
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))
        .unwrap_or_else(|error| panic!("protect temp dir: {error}"));
    directory
}

#[derive(Clone, Debug)]
struct TestClock {
    now_ms: Arc<AtomicI64>,
}

impl TestClock {
    fn new(now_ms: i64) -> Self {
        Self {
            now_ms: Arc::new(AtomicI64::new(now_ms)),
        }
    }

    fn set(&self, now_ms: i64) {
        self.now_ms.store(now_ms, Ordering::Release);
    }

    fn get(&self) -> i64 {
        self.now_ms.load(Ordering::Acquire)
    }
}

impl WorkflowGatewayClockV1 for TestClock {
    fn now_ms(&self) -> Result<i64, WorkflowGatewayClockError> {
        Ok(self.now_ms.load(Ordering::Acquire))
    }
}

fn success_receipt(
    lease: &rdashboard::domain::WorkflowLeaseV1,
    label: &str,
) -> WorkflowNodeReceiptV1 {
    WorkflowNodeReceiptV1::new(
        lease,
        WorkflowNodeOutcomeV1::Succeeded,
        Some(digest(format!("output-{label}"))),
        digest(format!("execution-{label}")),
        digest(format!("cleanup-{label}")),
        WorkflowCleanupResultV1::Complete,
        lease.leased_at_ms + 10,
    )
    .unwrap_or_else(|error| panic!("success receipt: {error}"))
}

fn assert_worker_binding(
    first: &rdashboard::domain::WorkflowLeaseV1,
    second: &rdashboard::domain::WorkflowLeaseV1,
    registration: &WorkflowWorkerRegistrationV1,
) {
    assert_eq!(first.worker_id, registration.worker_id);
    assert_eq!(second.worker_id, registration.worker_id);
}

async fn exercise_two_project_worker_flow(
    client: &WorkflowWorkerClientV1,
    registration: &WorkflowWorkerRegistrationV1,
    clock: &TestClock,
) {
    let first_lease = match client
        .poll()
        .await
        .unwrap_or_else(|error| panic!("first poll: {error}"))
    {
        WorkflowWorkerAssignmentV1::Lease {
            lease,
            execution_grant,
        } => {
            verify_execution_grant(&execution_grant, &lease, clock.get());
            *lease
        }
        assignment => panic!("unexpected first assignment: {assignment:?}"),
    };
    let second_lease = match client
        .poll()
        .await
        .unwrap_or_else(|error| panic!("second poll: {error}"))
    {
        WorkflowWorkerAssignmentV1::Lease {
            lease,
            execution_grant,
        } => {
            verify_execution_grant(&execution_grant, &lease, clock.get());
            *lease
        }
        assignment => panic!("unexpected second assignment: {assignment:?}"),
    };
    assert_worker_binding(&first_lease, &second_lease, registration);
    assert_eq!(
        BTreeSet::from([
            first_lease.project_id.to_string(),
            second_lease.project_id.to_string(),
        ]),
        BTreeSet::from(["ralert".to_owned(), "second".to_owned()])
    );

    clock.set(1_000);
    let renewed = client
        .renew_lease(first_lease.clone())
        .await
        .unwrap_or_else(|error| panic!("renew lease: {error}"));
    assert!(renewed.lease.expires_at_ms > first_lease.expires_at_ms);
    verify_execution_grant(&renewed.execution_grant, &renewed.lease, clock.get());
    clock.set(1_100);
    client
        .complete_node(success_receipt(&renewed.lease, "first-project"))
        .await
        .unwrap_or_else(|error| panic!("complete renewed node: {error}"));

    clock.set(second_lease.expires_at_ms);
    let obligation = match client
        .poll()
        .await
        .unwrap_or_else(|error| panic!("cleanup poll: {error}"))
    {
        WorkflowWorkerAssignmentV1::Cleanup { obligation } => *obligation,
        assignment => panic!("cleanup must precede a replacement lease: {assignment:?}"),
    };
    assert_eq!(obligation.lease, second_lease);
    assert_eq!(obligation.reason, WorkflowCleanupReasonV1::LeaseExpired);
    let cleanup = WorkflowCleanupReceiptV1::new(
        &obligation.lease,
        obligation.terminal_receipt.as_ref(),
        digest("worker-socket-cleanup"),
        second_lease.expires_at_ms + 1,
    )
    .unwrap_or_else(|error| panic!("cleanup receipt: {error}"));
    clock.set(cleanup.completed_at_ms + 1);
    client
        .complete_cleanup(cleanup)
        .await
        .unwrap_or_else(|error| panic!("complete cleanup: {error}"));

    let mut replacement = None;
    for _ in 0..2 {
        let lease = match client
            .poll()
            .await
            .unwrap_or_else(|error| panic!("replacement poll: {error}"))
        {
            WorkflowWorkerAssignmentV1::Lease {
                lease,
                execution_grant,
            } => {
                verify_execution_grant(&execution_grant, &lease, clock.get());
                *lease
            }
            assignment => panic!("expected runnable lease: {assignment:?}"),
        };
        if lease.project_id == second_lease.project_id && lease.node_id == second_lease.node_id {
            replacement = Some(lease);
        }
    }
    let replacement = replacement.unwrap_or_else(|| panic!("expired node was reissued"));
    assert_eq!(replacement.project_id, second_lease.project_id);
    assert_eq!(replacement.node_id, second_lease.node_id);
    assert_eq!(
        replacement.lease_generation,
        second_lease.lease_generation + 1
    );
}

#[test]
fn protocol_and_handler_configuration_reject_privilege_or_ambiguity() {
    let request = WorkflowWorkerRequestEnvelopeV1 {
        version: WORKER_PROTOCOL_VERSION,
        request_id: Uuid::new_v4(),
        request: WorkflowWorkerRequestV1::Poll,
    };
    assert_eq!(request.validate(), Ok(()));
    let mut wrong_version = request.clone();
    wrong_version.version += 1;
    assert_eq!(
        wrong_version.validate(),
        Err(WorkflowWorkerValidationError::UnsupportedVersion(
            WORKER_PROTOCOL_VERSION + 1
        ))
    );
    let mut nil_request = request;
    nil_request.request_id = Uuid::nil();
    assert_eq!(
        nil_request.validate(),
        Err(WorkflowWorkerValidationError::NilRequestId)
    );

    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let scheduler = DurableWorkflowScheduler::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let privileged = WorkflowWorkerRegistrationV1 {
        worker_id: "bad-worker".to_owned(),
        host_id: "production-vps".to_owned(),
        pools: BTreeSet::from([WorkflowWorkerPoolV1::PrivilegedExecutor]),
    };
    assert!(matches!(
        SchedulerWorkflowWorkerHandlerV1::new(
            scheduler,
            privileged,
            Duration::from_secs(15),
            TestClock::new(1),
            grant_signer(),
        ),
        Err(WorkflowWorkerHandlerConfigError::InvalidRegistration)
    ));

    let service = include_str!("../deploy/systemd/rdashboard-workflow-gateway.service");
    assert!(service.contains("User=rdashboard\nGroup=rdashboard-worker"));
    assert!(service.contains("PrivateNetwork=yes"));
    assert!(service.contains("RestrictAddressFamilies=AF_UNIX"));
    assert!(service.contains(
        "LoadCredential=workflow-grant-seed:/etc/rdashboard/credentials/workflow-grant-seed"
    ));
    assert!(!service.contains("docker.sock"));
    assert!(!service.contains("executor.sock"));
    assert!(!service.contains("source.sock"));
    assert!(!service.contains("rimg-worker"));
}

#[tokio::test]
async fn one_authenticated_socket_serves_two_projects_and_recovers_cleanup_debt() {
    let directory = protected_directory();
    let socket_path = directory.path().join("worker.sock");
    let metadata = fs::symlink_metadata(directory.path())
        .unwrap_or_else(|error| panic!("directory metadata: {error}"));
    assert_ne!(
        metadata.uid(),
        0,
        "test requires an ordinary workspace user"
    );
    assert_ne!(
        metadata.gid(),
        0,
        "test requires an ordinary workspace group"
    );
    let mut socket =
        BoundWorkflowWorkerSocketV1::bind(&socket_path, metadata.uid(), metadata.gid())
            .unwrap_or_else(|error| panic!("bind worker socket: {error}"));
    let listener = socket.take_listener();

    let control_path = directory.path().join("control.sqlite");
    let scheduler = DurableWorkflowScheduler::new(
        ControlStore::open(&control_path)
            .unwrap_or_else(|error| panic!("open control store: {error}")),
    );
    let first = manifest("ralert", 1);
    let second = manifest("second", 1);
    scheduler
        .admit(&first, &admission(&first, 'a', 1, "worker-first"), 1)
        .unwrap_or_else(|error| panic!("admit first project: {error}"));
    scheduler
        .admit(&second, &admission(&second, 'b', 1, "worker-second"), 2)
        .unwrap_or_else(|error| panic!("admit second project: {error}"));

    let registration = worker();
    let clock = TestClock::new(10);
    let handler = Arc::new(
        SchedulerWorkflowWorkerHandlerV1::new(
            scheduler.clone(),
            registration.clone(),
            Duration::from_secs(15),
            clock.clone(),
            grant_signer(),
        )
        .unwrap_or_else(|error| panic!("worker handler: {error}")),
    );
    let server_config =
        WorkflowWorkerServerConfigV1::new(metadata.uid(), 4, Duration::from_secs(2))
            .unwrap_or_else(|error| panic!("server config: {error}"));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        serve_worker_until(listener, handler, server_config, async {
            let _ = shutdown_rx.await;
        })
        .await
    });
    let client =
        WorkflowWorkerClientV1::new(&socket_path, Duration::from_secs(2), registration.clone())
            .unwrap_or_else(|error| panic!("worker client: {error}"));

    exercise_two_project_worker_flow(&client, &registration, &clock).await;

    shutdown_tx
        .send(())
        .unwrap_or_else(|()| panic!("server shutdown receiver exists"));
    server
        .await
        .unwrap_or_else(|error| panic!("server task: {error}"))
        .unwrap_or_else(|error| panic!("server result: {error}"));
}

#[tokio::test]
async fn peer_uid_is_rejected_before_the_scheduler_is_touched() {
    let (server, _client) =
        UnixStream::pair().unwrap_or_else(|error| panic!("socket pair: {error}"));
    let peer_uid = server
        .peer_cred()
        .unwrap_or_else(|error| panic!("peer credentials: {error}"))
        .uid();
    let unauthorized_uid = peer_uid
        .checked_add(1)
        .unwrap_or(peer_uid.saturating_sub(1));
    assert_ne!(unauthorized_uid, 0);
    let config = WorkflowWorkerServerConfigV1::new(unauthorized_uid, 1, Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("server config: {error}"));
    let directory = tempdir().unwrap_or_else(|error| panic!("temp dir: {error}"));
    let scheduler = DurableWorkflowScheduler::new(
        ControlStore::open(directory.path().join("control.sqlite"))
            .unwrap_or_else(|error| panic!("control store: {error}")),
    );
    let handler = Arc::new(
        SchedulerWorkflowWorkerHandlerV1::new(
            scheduler,
            worker(),
            Duration::from_secs(15),
            TestClock::new(1),
            grant_signer(),
        )
        .unwrap_or_else(|error| panic!("handler: {error}")),
    );
    assert!(matches!(
        serve_worker_connection(server, handler, &config).await,
        Err(WorkflowWorkerSocketError::UnauthorizedPeer { received }) if received == peer_uid
    ));
}
