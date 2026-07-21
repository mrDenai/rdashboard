use std::{
    fs,
    future::Future,
    io,
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::UnixStream as StdUnixStream,
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tracing::warn;
use uuid::Uuid;

use crate::{
    domain::{WorkflowCleanupReceiptV1, WorkflowLeaseV1, WorkflowNodeReceiptV1},
    protocol::{FrameError, NORMAL_FRAME_MAX_BYTES, read_frame, write_frame},
    scheduler::{
        DurableWorkflowScheduler, WorkflowAttemptSnapshotV1, WorkflowCleanupObligationV1,
        WorkflowWorkerRegistrationV1,
    },
    store::StoreError,
    unix_time_ms,
    workflow_execution_grant::WorkflowExecutionGrantSignerV1,
};

pub const WORKER_PROTOCOL_VERSION: u16 = 2;
pub const WORKER_SOCKET_PATH: &str = "/run/rdashboard-workflow/worker.sock";

const MIN_REQUEST_TIMEOUT_MS: u64 = 100;
const MAX_REQUEST_TIMEOUT_MS: u64 = 10_000;
const MIN_LEASE_DURATION_MS: i64 = 1_000;
const MAX_LEASE_DURATION_MS: i64 = 60_000;
const MAX_CONNECTIONS: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowWorkerRequestEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub request: WorkflowWorkerRequestV1,
}

impl WorkflowWorkerRequestEnvelopeV1 {
    pub fn validate(&self) -> Result<(), WorkflowWorkerValidationError> {
        if self.version != WORKER_PROTOCOL_VERSION {
            return Err(WorkflowWorkerValidationError::UnsupportedVersion(
                self.version,
            ));
        }
        if self.request_id.is_nil() {
            return Err(WorkflowWorkerValidationError::NilRequestId);
        }
        self.request.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowWorkerRequestV1 {
    Negotiate {
        supported_versions: Vec<u16>,
    },
    Poll,
    RenewLease {
        lease: Box<WorkflowLeaseV1>,
    },
    CompleteNode {
        receipt: Box<WorkflowNodeReceiptV1>,
    },
    CompleteCleanup {
        receipt: Box<WorkflowCleanupReceiptV1>,
    },
}

impl WorkflowWorkerRequestV1 {
    fn validate(&self) -> Result<(), WorkflowWorkerValidationError> {
        match self {
            Self::Negotiate { supported_versions }
                if !supported_versions.is_empty() && supported_versions.len() <= 8 =>
            {
                Ok(())
            }
            Self::Negotiate { .. } => Err(WorkflowWorkerValidationError::InvalidVersionSet),
            Self::Poll => Ok(()),
            Self::RenewLease { lease } => lease
                .validate()
                .map_err(|_| WorkflowWorkerValidationError::InvalidLease),
            Self::CompleteNode { receipt } => receipt
                .validate()
                .map_err(|_| WorkflowWorkerValidationError::InvalidNodeReceipt),
            Self::CompleteCleanup { receipt } => receipt
                .validate()
                .map_err(|_| WorkflowWorkerValidationError::InvalidCleanupReceipt),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowWorkerResponseEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub response: WorkflowWorkerResponseV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowWorkerResponseV1 {
    Negotiated {
        selected_version: u16,
        registration: WorkflowWorkerRegistrationV1,
    },
    Assignment {
        assignment: WorkflowWorkerAssignmentV1,
    },
    LeaseRenewed {
        lease: Box<WorkflowLeaseV1>,
        execution_grant: String,
    },
    NodeAccepted {
        attempt: Box<WorkflowAttemptSnapshotV1>,
    },
    CleanupAccepted {
        attempt: Box<WorkflowAttemptSnapshotV1>,
    },
    Rejected {
        code: WorkflowWorkerRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowWorkerAssignmentV1 {
    Lease {
        lease: Box<WorkflowLeaseV1>,
        execution_grant: String,
    },
    Cleanup {
        obligation: Box<WorkflowCleanupObligationV1>,
    },
    Idle,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowWorkerRejectionCodeV1 {
    UnsupportedProtocolVersion,
    InvalidRequest,
    WorkerBindingMismatch,
    LeaseConflict,
    ReceiptConflict,
    CleanupConflict,
    SchedulerUnavailable,
    ClockUnavailable,
    GrantUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowWorkerLeaseGrantV1 {
    pub lease: WorkflowLeaseV1,
    pub execution_grant: String,
}

pub trait WorkflowGatewayClockV1: Send + Sync {
    fn now_ms(&self) -> Result<i64, WorkflowGatewayClockError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemWorkflowGatewayClockV1;

impl WorkflowGatewayClockV1 for SystemWorkflowGatewayClockV1 {
    fn now_ms(&self) -> Result<i64, WorkflowGatewayClockError> {
        unix_time_ms().map_err(|_| WorkflowGatewayClockError)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("workflow gateway clock is unavailable")]
pub struct WorkflowGatewayClockError;

pub trait WorkflowWorkerRequestHandlerV1: Send + Sync {
    fn handle(&self, request: WorkflowWorkerRequestEnvelopeV1) -> WorkflowWorkerResponseEnvelopeV1;
}

pub struct SchedulerWorkflowWorkerHandlerV1<C = SystemWorkflowGatewayClockV1> {
    scheduler: DurableWorkflowScheduler,
    registration: WorkflowWorkerRegistrationV1,
    lease_duration_ms: i64,
    clock: C,
    grant_signer: Arc<WorkflowExecutionGrantSignerV1>,
}

impl SchedulerWorkflowWorkerHandlerV1<SystemWorkflowGatewayClockV1> {
    pub fn system(
        scheduler: DurableWorkflowScheduler,
        registration: WorkflowWorkerRegistrationV1,
        lease_duration: Duration,
        grant_signer: Arc<WorkflowExecutionGrantSignerV1>,
    ) -> Result<Self, WorkflowWorkerHandlerConfigError> {
        Self::new(
            scheduler,
            registration,
            lease_duration,
            SystemWorkflowGatewayClockV1,
            grant_signer,
        )
    }
}

impl<C: WorkflowGatewayClockV1> SchedulerWorkflowWorkerHandlerV1<C> {
    pub fn new(
        scheduler: DurableWorkflowScheduler,
        registration: WorkflowWorkerRegistrationV1,
        lease_duration: Duration,
        clock: C,
        grant_signer: Arc<WorkflowExecutionGrantSignerV1>,
    ) -> Result<Self, WorkflowWorkerHandlerConfigError> {
        registration
            .validate_unprivileged()
            .map_err(|_| WorkflowWorkerHandlerConfigError::InvalidRegistration)?;
        let lease_duration_ms = i64::try_from(lease_duration.as_millis())
            .map_err(|_| WorkflowWorkerHandlerConfigError::InvalidLeaseDuration)?;
        if !(MIN_LEASE_DURATION_MS..=MAX_LEASE_DURATION_MS).contains(&lease_duration_ms) {
            return Err(WorkflowWorkerHandlerConfigError::InvalidLeaseDuration);
        }
        Ok(Self {
            scheduler,
            registration,
            lease_duration_ms,
            clock,
            grant_signer,
        })
    }

    fn response(
        request: &WorkflowWorkerRequestEnvelopeV1,
        response: WorkflowWorkerResponseV1,
    ) -> WorkflowWorkerResponseEnvelopeV1 {
        WorkflowWorkerResponseEnvelopeV1 {
            version: WORKER_PROTOCOL_VERSION,
            request_id: request.request_id,
            response,
        }
    }

    fn rejected(
        request: &WorkflowWorkerRequestEnvelopeV1,
        code: WorkflowWorkerRejectionCodeV1,
        retryable: bool,
    ) -> WorkflowWorkerResponseEnvelopeV1 {
        Self::response(
            request,
            WorkflowWorkerResponseV1::Rejected { code, retryable },
        )
    }

    fn now_or_reject(
        &self,
        request: &WorkflowWorkerRequestEnvelopeV1,
    ) -> Result<i64, WorkflowWorkerResponseEnvelopeV1> {
        self.clock.now_ms().map_err(|_| {
            Self::rejected(
                request,
                WorkflowWorkerRejectionCodeV1::ClockUnavailable,
                true,
            )
        })
    }

    fn worker_matches_lease(&self, lease: &WorkflowLeaseV1) -> bool {
        lease.worker_id == self.registration.worker_id
            && lease.host_id == self.registration.host_id
            && self.registration.pools.contains(&lease.worker_pool)
    }

    fn worker_matches_node_receipt(&self, receipt: &WorkflowNodeReceiptV1) -> bool {
        receipt.worker_id == self.registration.worker_id
            && receipt.host_id == self.registration.host_id
    }

    fn worker_matches_cleanup_receipt(&self, receipt: &WorkflowCleanupReceiptV1) -> bool {
        receipt.worker_id == self.registration.worker_id
            && receipt.host_id == self.registration.host_id
    }

    fn poll(
        &self,
        request: &WorkflowWorkerRequestEnvelopeV1,
        now_ms: i64,
    ) -> WorkflowWorkerResponseEnvelopeV1 {
        if let Err(error) = self.scheduler.reconcile_controller_nodes(now_ms) {
            return store_rejection(request, &error);
        }
        match self.scheduler.pending_cleanup(&self.registration, 1) {
            Ok(mut obligations) => {
                if let Some(obligation) = obligations.pop() {
                    return Self::response(
                        request,
                        WorkflowWorkerResponseV1::Assignment {
                            assignment: WorkflowWorkerAssignmentV1::Cleanup {
                                obligation: Box::new(obligation),
                            },
                        },
                    );
                }
            }
            Err(error) => return store_rejection(request, &error),
        }
        match self
            .scheduler
            .claim_next(&self.registration, now_ms, self.lease_duration_ms)
        {
            Ok(Some(lease)) => match self.grant_signer.issue(&lease, now_ms, Uuid::new_v4()) {
                Ok(execution_grant) => Self::response(
                    request,
                    WorkflowWorkerResponseV1::Assignment {
                        assignment: WorkflowWorkerAssignmentV1::Lease {
                            lease: Box::new(lease),
                            execution_grant,
                        },
                    },
                ),
                Err(_) => Self::rejected(
                    request,
                    WorkflowWorkerRejectionCodeV1::GrantUnavailable,
                    true,
                ),
            },
            Ok(None) => Self::response(
                request,
                WorkflowWorkerResponseV1::Assignment {
                    assignment: WorkflowWorkerAssignmentV1::Idle,
                },
            ),
            Err(error) => store_rejection(request, &error),
        }
    }

    fn negotiate(
        &self,
        request: &WorkflowWorkerRequestEnvelopeV1,
        supported_versions: &[u16],
    ) -> WorkflowWorkerResponseEnvelopeV1 {
        if supported_versions.contains(&WORKER_PROTOCOL_VERSION) {
            Self::response(
                request,
                WorkflowWorkerResponseV1::Negotiated {
                    selected_version: WORKER_PROTOCOL_VERSION,
                    registration: self.registration.clone(),
                },
            )
        } else {
            Self::rejected(
                request,
                WorkflowWorkerRejectionCodeV1::UnsupportedProtocolVersion,
                false,
            )
        }
    }

    fn renew_lease(
        &self,
        request: &WorkflowWorkerRequestEnvelopeV1,
        lease: &WorkflowLeaseV1,
    ) -> WorkflowWorkerResponseEnvelopeV1 {
        if !self.worker_matches_lease(lease) {
            return Self::rejected(
                request,
                WorkflowWorkerRejectionCodeV1::WorkerBindingMismatch,
                false,
            );
        }
        let now_ms = match self.now_or_reject(request) {
            Ok(now_ms) => now_ms,
            Err(rejected) => return rejected,
        };
        match self
            .scheduler
            .renew_lease(&self.registration, lease, now_ms, self.lease_duration_ms)
        {
            Ok(lease) => match self.grant_signer.issue(&lease, now_ms, Uuid::new_v4()) {
                Ok(execution_grant) => Self::response(
                    request,
                    WorkflowWorkerResponseV1::LeaseRenewed {
                        lease: Box::new(lease),
                        execution_grant,
                    },
                ),
                Err(_) => Self::rejected(
                    request,
                    WorkflowWorkerRejectionCodeV1::GrantUnavailable,
                    true,
                ),
            },
            Err(error) => store_rejection(request, &error),
        }
    }

    fn complete_node(
        &self,
        request: &WorkflowWorkerRequestEnvelopeV1,
        receipt: &WorkflowNodeReceiptV1,
    ) -> WorkflowWorkerResponseEnvelopeV1 {
        if !self.worker_matches_node_receipt(receipt) {
            return Self::rejected(
                request,
                WorkflowWorkerRejectionCodeV1::WorkerBindingMismatch,
                false,
            );
        }
        let now_ms = match self.now_or_reject(request) {
            Ok(now_ms) => now_ms,
            Err(rejected) => return rejected,
        };
        if let Err(error) = self.scheduler.commit_node_receipt(receipt, now_ms) {
            return store_rejection(request, &error);
        }
        if let Err(error) = self.scheduler.reconcile_controller_nodes(now_ms) {
            return store_rejection(request, &error);
        }
        match self.scheduler.attempt(receipt.attempt_id) {
            Ok(Some(attempt)) => Self::response(
                request,
                WorkflowWorkerResponseV1::NodeAccepted {
                    attempt: Box::new(attempt),
                },
            ),
            Ok(None) => Self::rejected(
                request,
                WorkflowWorkerRejectionCodeV1::SchedulerUnavailable,
                true,
            ),
            Err(error) => store_rejection(request, &error),
        }
    }

    fn complete_cleanup(
        &self,
        request: &WorkflowWorkerRequestEnvelopeV1,
        receipt: &WorkflowCleanupReceiptV1,
    ) -> WorkflowWorkerResponseEnvelopeV1 {
        if !self.worker_matches_cleanup_receipt(receipt) {
            return Self::rejected(
                request,
                WorkflowWorkerRejectionCodeV1::WorkerBindingMismatch,
                false,
            );
        }
        let now_ms = match self.now_or_reject(request) {
            Ok(now_ms) => now_ms,
            Err(rejected) => return rejected,
        };
        match self.scheduler.commit_cleanup_receipt(receipt, now_ms) {
            Ok(attempt) => Self::response(
                request,
                WorkflowWorkerResponseV1::CleanupAccepted {
                    attempt: Box::new(attempt),
                },
            ),
            Err(error) => store_rejection(request, &error),
        }
    }
}

impl<C: WorkflowGatewayClockV1> WorkflowWorkerRequestHandlerV1
    for SchedulerWorkflowWorkerHandlerV1<C>
{
    fn handle(&self, request: WorkflowWorkerRequestEnvelopeV1) -> WorkflowWorkerResponseEnvelopeV1 {
        if let Err(error) = request.validate() {
            let code = if matches!(error, WorkflowWorkerValidationError::UnsupportedVersion(_)) {
                WorkflowWorkerRejectionCodeV1::UnsupportedProtocolVersion
            } else {
                WorkflowWorkerRejectionCodeV1::InvalidRequest
            };
            return Self::rejected(&request, code, false);
        }
        match &request.request {
            WorkflowWorkerRequestV1::Negotiate { supported_versions } => {
                self.negotiate(&request, supported_versions)
            }
            WorkflowWorkerRequestV1::Poll => {
                let now_ms = match self.now_or_reject(&request) {
                    Ok(now_ms) => now_ms,
                    Err(rejected) => return rejected,
                };
                self.poll(&request, now_ms)
            }
            WorkflowWorkerRequestV1::RenewLease { lease } => self.renew_lease(&request, lease),
            WorkflowWorkerRequestV1::CompleteNode { receipt } => {
                self.complete_node(&request, receipt)
            }
            WorkflowWorkerRequestV1::CompleteCleanup { receipt } => {
                self.complete_cleanup(&request, receipt)
            }
        }
    }
}

fn store_rejection(
    request: &WorkflowWorkerRequestEnvelopeV1,
    error: &StoreError,
) -> WorkflowWorkerResponseEnvelopeV1 {
    let (code, retryable) = match error {
        StoreError::InvalidWorkflowSchedulerInput(_) | StoreError::WorkflowPolicyMismatch => {
            (WorkflowWorkerRejectionCodeV1::InvalidRequest, false)
        }
        StoreError::WorkflowLeaseConflict => (WorkflowWorkerRejectionCodeV1::LeaseConflict, false),
        StoreError::WorkflowReceiptConflict => {
            (WorkflowWorkerRejectionCodeV1::ReceiptConflict, false)
        }
        StoreError::WorkflowCleanupConflict => {
            (WorkflowWorkerRejectionCodeV1::CleanupConflict, false)
        }
        _ => (WorkflowWorkerRejectionCodeV1::SchedulerUnavailable, true),
    };
    WorkflowWorkerResponseEnvelopeV1 {
        version: WORKER_PROTOCOL_VERSION,
        request_id: request.request_id,
        response: WorkflowWorkerResponseV1::Rejected { code, retryable },
    }
}

#[derive(Debug)]
pub struct WorkflowWorkerClientV1 {
    socket_path: PathBuf,
    request_timeout: Duration,
    registration: WorkflowWorkerRegistrationV1,
    negotiated: AtomicBool,
}

impl WorkflowWorkerClientV1 {
    pub fn installed(
        request_timeout: Duration,
        registration: WorkflowWorkerRegistrationV1,
    ) -> Result<Self, WorkflowWorkerClientError> {
        Self::new(WORKER_SOCKET_PATH, request_timeout, registration)
    }

    pub fn new(
        socket_path: impl Into<PathBuf>,
        request_timeout: Duration,
        registration: WorkflowWorkerRegistrationV1,
    ) -> Result<Self, WorkflowWorkerClientError> {
        let socket_path = socket_path.into();
        if !is_normalized_absolute_path(&socket_path)
            || request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
            || registration.validate_unprivileged().is_err()
        {
            return Err(WorkflowWorkerClientError::InvalidConfig);
        }
        Ok(Self {
            socket_path,
            request_timeout,
            registration,
            negotiated: AtomicBool::new(false),
        })
    }

    pub async fn poll(&self) -> Result<WorkflowWorkerAssignmentV1, WorkflowWorkerClientError> {
        self.ensure_negotiated().await?;
        match self.exchange(WorkflowWorkerRequestV1::Poll).await? {
            WorkflowWorkerResponseV1::Assignment { assignment } => Ok(assignment),
            WorkflowWorkerResponseV1::Rejected { code, retryable } => {
                Err(WorkflowWorkerClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    pub async fn renew_lease(
        &self,
        lease: WorkflowLeaseV1,
    ) -> Result<WorkflowWorkerLeaseGrantV1, WorkflowWorkerClientError> {
        self.ensure_negotiated().await?;
        let lease_id = lease.lease_id;
        match self
            .exchange(WorkflowWorkerRequestV1::RenewLease {
                lease: Box::new(lease),
            })
            .await?
        {
            WorkflowWorkerResponseV1::LeaseRenewed {
                lease,
                execution_grant,
            } if lease.lease_id == lease_id
                && lease.worker_id == self.registration.worker_id
                && lease.host_id == self.registration.host_id
                && lease.validate().is_ok()
                && !execution_grant.is_empty() =>
            {
                Ok(WorkflowWorkerLeaseGrantV1 {
                    lease: *lease,
                    execution_grant,
                })
            }
            WorkflowWorkerResponseV1::Rejected { code, retryable } => {
                Err(WorkflowWorkerClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    pub async fn complete_node(
        &self,
        receipt: WorkflowNodeReceiptV1,
    ) -> Result<WorkflowAttemptSnapshotV1, WorkflowWorkerClientError> {
        self.ensure_negotiated().await?;
        let attempt_id = receipt.attempt_id;
        match self
            .exchange(WorkflowWorkerRequestV1::CompleteNode {
                receipt: Box::new(receipt),
            })
            .await?
        {
            WorkflowWorkerResponseV1::NodeAccepted { attempt }
                if attempt.attempt_id == attempt_id =>
            {
                Ok(*attempt)
            }
            WorkflowWorkerResponseV1::Rejected { code, retryable } => {
                Err(WorkflowWorkerClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    pub async fn complete_cleanup(
        &self,
        receipt: WorkflowCleanupReceiptV1,
    ) -> Result<WorkflowAttemptSnapshotV1, WorkflowWorkerClientError> {
        self.ensure_negotiated().await?;
        let attempt_id = receipt.attempt_id;
        match self
            .exchange(WorkflowWorkerRequestV1::CompleteCleanup {
                receipt: Box::new(receipt),
            })
            .await?
        {
            WorkflowWorkerResponseV1::CleanupAccepted { attempt }
                if attempt.attempt_id == attempt_id =>
            {
                Ok(*attempt)
            }
            WorkflowWorkerResponseV1::Rejected { code, retryable } => {
                Err(WorkflowWorkerClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    async fn ensure_negotiated(&self) -> Result<(), WorkflowWorkerClientError> {
        if self.negotiated.load(Ordering::Acquire) {
            return Ok(());
        }
        match self
            .exchange(WorkflowWorkerRequestV1::Negotiate {
                supported_versions: vec![WORKER_PROTOCOL_VERSION],
            })
            .await?
        {
            WorkflowWorkerResponseV1::Negotiated {
                selected_version,
                registration,
            } if selected_version == WORKER_PROTOCOL_VERSION
                && registration == self.registration =>
            {
                self.negotiated.store(true, Ordering::Release);
                Ok(())
            }
            WorkflowWorkerResponseV1::Rejected { code, retryable } => {
                Err(WorkflowWorkerClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    fn wrong_response<T>(&self) -> Result<T, WorkflowWorkerClientError> {
        self.negotiated.store(false, Ordering::Release);
        Err(WorkflowWorkerClientError::WrongResponse)
    }

    async fn exchange(
        &self,
        request: WorkflowWorkerRequestV1,
    ) -> Result<WorkflowWorkerResponseV1, WorkflowWorkerClientError> {
        let request_id = Uuid::new_v4();
        let request = WorkflowWorkerRequestEnvelopeV1 {
            version: WORKER_PROTOCOL_VERSION,
            request_id,
            request,
        };
        let response = timeout(self.request_timeout, async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(WorkflowWorkerClientError::Io)?;
            write_frame(&mut stream, &request, NORMAL_FRAME_MAX_BYTES).await?;
            stream
                .shutdown()
                .await
                .map_err(WorkflowWorkerClientError::Io)?;
            let response: WorkflowWorkerResponseEnvelopeV1 =
                read_frame(&mut stream, NORMAL_FRAME_MAX_BYTES).await?;
            let mut trailing = [0_u8; 1];
            if stream
                .read(&mut trailing)
                .await
                .map_err(WorkflowWorkerClientError::Io)?
                != 0
            {
                return Err(WorkflowWorkerClientError::TrailingResponse);
            }
            Ok::<_, WorkflowWorkerClientError>(response)
        })
        .await
        .map_err(|_| WorkflowWorkerClientError::DeadlineExceeded)??;
        if response.version != WORKER_PROTOCOL_VERSION || response.request_id != request_id {
            return self.wrong_response();
        }
        Ok(response.response)
    }
}

#[derive(Clone, Debug)]
pub struct WorkflowWorkerServerConfigV1 {
    allowed_uid: u32,
    max_connections: usize,
    request_timeout: Duration,
}

impl WorkflowWorkerServerConfigV1 {
    pub fn new(
        allowed_uid: u32,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Result<Self, WorkflowWorkerServerConfigError> {
        if allowed_uid == 0 || allowed_uid == u32::MAX {
            return Err(WorkflowWorkerServerConfigError::InvalidAllowedUid);
        }
        if !(1..=MAX_CONNECTIONS).contains(&max_connections) {
            return Err(WorkflowWorkerServerConfigError::InvalidConnectionLimit);
        }
        if request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(WorkflowWorkerServerConfigError::InvalidRequestTimeout);
        }
        Ok(Self {
            allowed_uid,
            max_connections,
            request_timeout,
        })
    }
}

pub async fn serve_worker_connection<H: WorkflowWorkerRequestHandlerV1 + 'static>(
    mut stream: UnixStream,
    handler: Arc<H>,
    config: &WorkflowWorkerServerConfigV1,
) -> Result<(), WorkflowWorkerSocketError> {
    let peer = stream
        .peer_cred()
        .map_err(WorkflowWorkerSocketError::PeerCredentials)?;
    if peer.uid() != config.allowed_uid {
        return Err(WorkflowWorkerSocketError::UnauthorizedPeer {
            received: peer.uid(),
        });
    }

    let deadline = Instant::now() + config.request_timeout;
    let request = timeout_at(deadline, async {
        let request = read_frame(&mut stream, NORMAL_FRAME_MAX_BYTES).await?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = stream.read(&mut trailing).await.map_err(FrameError::Io)?;
        if trailing_bytes != 0 {
            return Err(WorkflowWorkerSocketError::Frame(FrameError::TrailingBytes(
                trailing_bytes,
            )));
        }
        Ok::<WorkflowWorkerRequestEnvelopeV1, WorkflowWorkerSocketError>(request)
    })
    .await
    .map_err(|_| WorkflowWorkerSocketError::DeadlineExceeded)??;

    let mut handler_task = tokio::task::spawn_blocking(move || handler.handle(request));
    let response = if let Ok(result) = timeout_at(deadline, &mut handler_task).await {
        result.map_err(|_| WorkflowWorkerSocketError::HandlerTask)?
    } else {
        handler_task
            .await
            .map_err(|_| WorkflowWorkerSocketError::HandlerTask)?;
        return Err(WorkflowWorkerSocketError::DeadlineExceeded);
    };
    timeout_at(deadline, async {
        write_frame(&mut stream, &response, NORMAL_FRAME_MAX_BYTES).await?;
        stream
            .shutdown()
            .await
            .map_err(WorkflowWorkerSocketError::Write)?;
        Ok::<(), WorkflowWorkerSocketError>(())
    })
    .await
    .map_err(|_| WorkflowWorkerSocketError::DeadlineExceeded)??;
    Ok(())
}

pub async fn serve_worker_until<H, F>(
    listener: UnixListener,
    handler: Arc<H>,
    config: WorkflowWorkerServerConfigV1,
    shutdown: F,
) -> Result<(), WorkflowWorkerSocketError>
where
    H: WorkflowWorkerRequestHandlerV1 + 'static,
    F: Future<Output = ()>,
{
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    let serve_result = loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                log_worker_connection_result(result);
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                    ) => {
                        warn!(error = %error, "transient workflow worker socket accept failure");
                        continue;
                    }
                    Err(error) => break Err(WorkflowWorkerSocketError::Accept(error)),
                };
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    warn!("workflow worker connection limit reached");
                    continue;
                };
                let handler = Arc::clone(&handler);
                let config = config.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_worker_connection(stream, handler, &config).await
                });
            }
        }
    };
    drop(listener);
    while let Some(result) = tasks.join_next().await {
        log_worker_connection_result(result);
    }
    serve_result
}

fn log_worker_connection_result(
    result: Result<Result<(), WorkflowWorkerSocketError>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(error = %error, "workflow worker connection rejected"),
        Err(error) => warn!(error = %error, "workflow worker connection task failed"),
    }
}

pub struct BoundWorkflowWorkerSocketV1 {
    listener: Option<UnixListener>,
    cleanup: WorkflowWorkerSocketCleanupGuard,
}

impl BoundWorkflowWorkerSocketV1 {
    pub fn bind(
        path: &Path,
        required_owner_uid: u32,
        required_group_gid: u32,
    ) -> Result<Self, WorkflowWorkerSocketError> {
        if !is_normalized_absolute_path(path) {
            return Err(WorkflowWorkerSocketError::InvalidBindPath);
        }
        let parent = path
            .parent()
            .ok_or(WorkflowWorkerSocketError::InvalidBindPath)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(WorkflowWorkerSocketError::BindParent)?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != required_owner_uid
            || parent_metadata.gid() != required_group_gid
            || parent_metadata.permissions().mode() & 0o777 != 0o750
            || required_group_gid == 0
        {
            return Err(WorkflowWorkerSocketError::UnsafeBindParent);
        }
        match fs::symlink_metadata(path) {
            Ok(existing) => {
                let expected_stale_socket = existing.file_type().is_socket()
                    && existing.uid() == required_owner_uid
                    && existing.gid() == required_group_gid
                    && existing.permissions().mode() & 0o777 == 0o660;
                if !expected_stale_socket {
                    return Err(WorkflowWorkerSocketError::SocketPathExists);
                }
                match StdUnixStream::connect(path) {
                    Ok(stream) => {
                        let _ = stream.shutdown(Shutdown::Both);
                        return Err(WorkflowWorkerSocketError::SocketPathExists);
                    }
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                    Err(error) => {
                        return Err(WorkflowWorkerSocketError::InspectStaleSocket(error));
                    }
                }
                let rechecked = fs::symlink_metadata(path)
                    .map_err(WorkflowWorkerSocketError::InspectSocketPath)?;
                if !rechecked.file_type().is_socket()
                    || rechecked.dev() != existing.dev()
                    || rechecked.ino() != existing.ino()
                {
                    return Err(WorkflowWorkerSocketError::SocketPathChanged);
                }
                fs::remove_file(path).map_err(WorkflowWorkerSocketError::RemoveStaleSocket)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(WorkflowWorkerSocketError::InspectSocketPath(error)),
        }

        let listener = UnixListener::bind(path).map_err(WorkflowWorkerSocketError::Bind)?;
        let bound =
            fs::symlink_metadata(path).map_err(WorkflowWorkerSocketError::InspectSocketPath)?;
        if !bound.file_type().is_socket()
            || bound.uid() != required_owner_uid
            || bound.gid() != required_group_gid
        {
            return Err(WorkflowWorkerSocketError::BoundPathNotSocket);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))
            .map_err(WorkflowWorkerSocketError::SetPermissions)?;
        let protected =
            fs::symlink_metadata(path).map_err(WorkflowWorkerSocketError::InspectSocketPath)?;
        if !protected.file_type().is_socket()
            || protected.uid() != required_owner_uid
            || protected.gid() != required_group_gid
            || protected.permissions().mode() & 0o777 != 0o660
            || protected.dev() != bound.dev()
            || protected.ino() != bound.ino()
        {
            return Err(WorkflowWorkerSocketError::BoundPathNotSocket);
        }
        Ok(Self {
            listener: Some(listener),
            cleanup: WorkflowWorkerSocketCleanupGuard {
                path: path.to_owned(),
                device: protected.dev(),
                inode: protected.ino(),
            },
        })
    }

    pub fn take_listener(&mut self) -> UnixListener {
        self.listener
            .take()
            .expect("bound workflow worker listener can only be taken once")
    }

    pub fn path(&self) -> &Path {
        &self.cleanup.path
    }
}

struct WorkflowWorkerSocketCleanupGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for WorkflowWorkerSocketCleanupGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn is_normalized_absolute_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path.as_os_str().as_encoded_bytes().len() <= 512
        && path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>() == path
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorkflowWorkerValidationError {
    #[error("unsupported workflow worker protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("workflow worker request ID must not be nil")]
    NilRequestId,
    #[error("workflow worker version set must contain 1-8 versions")]
    InvalidVersionSet,
    #[error("workflow worker lease is invalid")]
    InvalidLease,
    #[error("workflow worker node receipt is invalid")]
    InvalidNodeReceipt,
    #[error("workflow worker cleanup receipt is invalid")]
    InvalidCleanupReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorkflowWorkerHandlerConfigError {
    #[error("workflow worker registration is invalid or privileged")]
    InvalidRegistration,
    #[error("workflow worker lease duration is outside the supported range")]
    InvalidLeaseDuration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorkflowWorkerServerConfigError {
    #[error("workflow worker UID must identify a non-root Unix account")]
    InvalidAllowedUid,
    #[error("workflow worker connection limit is outside the supported range")]
    InvalidConnectionLimit,
    #[error("workflow worker request timeout is outside the supported range")]
    InvalidRequestTimeout,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowWorkerClientError {
    #[error("workflow worker client configuration is invalid")]
    InvalidConfig,
    #[error("workflow worker request deadline elapsed")]
    DeadlineExceeded,
    #[error("workflow worker socket I/O failed: {0}")]
    Io(io::Error),
    #[error("workflow worker frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("workflow worker response contains trailing bytes")]
    TrailingResponse,
    #[error("workflow worker returned an unexpected or unbound response")]
    WrongResponse,
    #[error("workflow worker request was rejected with {code:?}; retryable={retryable}")]
    Rejected {
        code: WorkflowWorkerRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowWorkerSocketError {
    #[error("workflow worker bind path is invalid")]
    InvalidBindPath,
    #[error("workflow worker socket parent could not be inspected: {0}")]
    BindParent(io::Error),
    #[error("workflow worker socket parent is not the required protected directory")]
    UnsafeBindParent,
    #[error("workflow worker socket path already exists")]
    SocketPathExists,
    #[error("workflow worker stale socket could not be inspected: {0}")]
    InspectStaleSocket(io::Error),
    #[error("workflow worker socket path could not be inspected: {0}")]
    InspectSocketPath(io::Error),
    #[error("workflow worker socket path changed during reconciliation")]
    SocketPathChanged,
    #[error("workflow worker stale socket could not be removed: {0}")]
    RemoveStaleSocket(io::Error),
    #[error("workflow worker socket could not be bound: {0}")]
    Bind(io::Error),
    #[error("workflow worker bound path is not the required protected socket")]
    BoundPathNotSocket,
    #[error("workflow worker socket permissions could not be set: {0}")]
    SetPermissions(io::Error),
    #[error("workflow worker peer credentials could not be read: {0}")]
    PeerCredentials(io::Error),
    #[error("workflow worker peer UID {received} is not authorized")]
    UnauthorizedPeer { received: u32 },
    #[error("workflow worker request deadline elapsed")]
    DeadlineExceeded,
    #[error("workflow worker frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("workflow worker handler task failed")]
    HandlerTask,
    #[error("workflow worker response could not be closed: {0}")]
    Write(io::Error),
    #[error("workflow worker connection could not be accepted: {0}")]
    Accept(io::Error),
}
