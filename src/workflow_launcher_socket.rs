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
    domain::WorkflowLeaseV1,
    protocol::{FrameError, NORMAL_FRAME_MAX_BYTES, read_frame, write_frame},
    unix_time_ms,
    workflow_launcher::{
        WorkflowLaunchJournalError, WorkflowLaunchStatusV1, WorkflowLaunchSupervisorError,
        WorkflowLaunchSupervisorV1, WorkflowLauncherError,
    },
};

pub const WORKFLOW_LAUNCHER_PROTOCOL_VERSION: u16 = 1;
pub const WORKFLOW_LAUNCHER_SOCKET_PATH: &str = "/run/rdashboard-workflow-launcher/launcher.sock";

const MIN_REQUEST_TIMEOUT_MS: u64 = 100;
const MAX_REQUEST_TIMEOUT_MS: u64 = 30_000;
const MAX_CONNECTIONS: usize = 32;
const MAX_EXECUTION_GRANT_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLauncherRequestEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub request: WorkflowLauncherRequestV1,
}

impl WorkflowLauncherRequestEnvelopeV1 {
    pub fn validate(&self) -> Result<(), WorkflowLauncherValidationError> {
        if self.version != WORKFLOW_LAUNCHER_PROTOCOL_VERSION {
            return Err(WorkflowLauncherValidationError::UnsupportedVersion(
                self.version,
            ));
        }
        if self.request_id.is_nil() {
            return Err(WorkflowLauncherValidationError::NilRequestId);
        }
        self.request.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowLauncherRequestV1 {
    Negotiate {
        supported_versions: Vec<u16>,
    },
    Launch {
        lease: Box<WorkflowLeaseV1>,
        execution_grant: String,
    },
    Observe {
        lease_id: Uuid,
        lease_generation: u32,
    },
    Cleanup {
        lease: Box<WorkflowLeaseV1>,
    },
}

impl WorkflowLauncherRequestV1 {
    fn validate(&self) -> Result<(), WorkflowLauncherValidationError> {
        match self {
            Self::Negotiate { supported_versions }
                if !supported_versions.is_empty() && supported_versions.len() <= 8 =>
            {
                Ok(())
            }
            Self::Negotiate { .. } => Err(WorkflowLauncherValidationError::InvalidVersionSet),
            Self::Launch {
                lease,
                execution_grant,
            } => {
                lease
                    .validate()
                    .map_err(|_| WorkflowLauncherValidationError::InvalidLease)?;
                if execution_grant.is_empty()
                    || execution_grant.len() > MAX_EXECUTION_GRANT_BYTES
                    || !execution_grant.is_ascii()
                {
                    return Err(WorkflowLauncherValidationError::InvalidGrant);
                }
                Ok(())
            }
            Self::Observe {
                lease_id,
                lease_generation,
            } if !lease_id.is_nil() && *lease_generation != 0 => Ok(()),
            Self::Observe { .. } => Err(WorkflowLauncherValidationError::InvalidLocator),
            Self::Cleanup { lease } => lease
                .validate()
                .map_err(|_| WorkflowLauncherValidationError::InvalidLease),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLauncherResponseEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub response: WorkflowLauncherResponseV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowLauncherResponseV1 {
    Negotiated {
        selected_version: u16,
    },
    LaunchStatus {
        status: Box<WorkflowLaunchStatusV1>,
    },
    NotFound,
    CleanupStatus {
        status: Box<WorkflowLaunchStatusV1>,
    },
    Rejected {
        code: WorkflowLauncherRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowLauncherRejectionCodeV1 {
    UnsupportedProtocolVersion,
    InvalidRequest,
    AuthorizationRejected,
    IdentityConflict,
    StateConflict,
    CapacityUnavailable,
    RuntimeUnavailable,
    JournalUnavailable,
    ClockUnavailable,
}

pub trait WorkflowLauncherClockV1: Send + Sync {
    fn now_ms(&self) -> Result<i64, WorkflowLauncherClockError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemWorkflowLauncherClockV1;

impl WorkflowLauncherClockV1 for SystemWorkflowLauncherClockV1 {
    fn now_ms(&self) -> Result<i64, WorkflowLauncherClockError> {
        unix_time_ms().map_err(|_| WorkflowLauncherClockError)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("workflow launcher clock is unavailable")]
pub struct WorkflowLauncherClockError;

pub trait WorkflowLauncherRequestHandlerV1: Send + Sync {
    fn handle(
        &self,
        request: WorkflowLauncherRequestEnvelopeV1,
    ) -> WorkflowLauncherResponseEnvelopeV1;
}

pub struct SupervisorWorkflowLauncherHandlerV1<C = SystemWorkflowLauncherClockV1> {
    supervisor: Arc<WorkflowLaunchSupervisorV1>,
    clock: C,
}

impl SupervisorWorkflowLauncherHandlerV1<SystemWorkflowLauncherClockV1> {
    pub fn system(supervisor: Arc<WorkflowLaunchSupervisorV1>) -> Self {
        Self::new(supervisor, SystemWorkflowLauncherClockV1)
    }
}

impl<C: WorkflowLauncherClockV1> SupervisorWorkflowLauncherHandlerV1<C> {
    pub const fn new(supervisor: Arc<WorkflowLaunchSupervisorV1>, clock: C) -> Self {
        Self { supervisor, clock }
    }

    fn response(
        request: &WorkflowLauncherRequestEnvelopeV1,
        response: WorkflowLauncherResponseV1,
    ) -> WorkflowLauncherResponseEnvelopeV1 {
        WorkflowLauncherResponseEnvelopeV1 {
            version: WORKFLOW_LAUNCHER_PROTOCOL_VERSION,
            request_id: request.request_id,
            response,
        }
    }

    fn rejected(
        request: &WorkflowLauncherRequestEnvelopeV1,
        code: WorkflowLauncherRejectionCodeV1,
        retryable: bool,
    ) -> WorkflowLauncherResponseEnvelopeV1 {
        Self::response(
            request,
            WorkflowLauncherResponseV1::Rejected { code, retryable },
        )
    }

    fn now_or_reject(
        &self,
        request: &WorkflowLauncherRequestEnvelopeV1,
    ) -> Result<i64, WorkflowLauncherResponseEnvelopeV1> {
        self.clock.now_ms().map_err(|_| {
            Self::rejected(
                request,
                WorkflowLauncherRejectionCodeV1::ClockUnavailable,
                true,
            )
        })
    }
}

impl<C: WorkflowLauncherClockV1> WorkflowLauncherRequestHandlerV1
    for SupervisorWorkflowLauncherHandlerV1<C>
{
    fn handle(
        &self,
        request: WorkflowLauncherRequestEnvelopeV1,
    ) -> WorkflowLauncherResponseEnvelopeV1 {
        if let Err(error) = request.validate() {
            let code = if matches!(
                error,
                WorkflowLauncherValidationError::UnsupportedVersion(_)
            ) {
                WorkflowLauncherRejectionCodeV1::UnsupportedProtocolVersion
            } else {
                WorkflowLauncherRejectionCodeV1::InvalidRequest
            };
            return Self::rejected(&request, code, false);
        }
        match &request.request {
            WorkflowLauncherRequestV1::Negotiate { supported_versions } => {
                if supported_versions.contains(&WORKFLOW_LAUNCHER_PROTOCOL_VERSION) {
                    Self::response(
                        &request,
                        WorkflowLauncherResponseV1::Negotiated {
                            selected_version: WORKFLOW_LAUNCHER_PROTOCOL_VERSION,
                        },
                    )
                } else {
                    Self::rejected(
                        &request,
                        WorkflowLauncherRejectionCodeV1::UnsupportedProtocolVersion,
                        false,
                    )
                }
            }
            WorkflowLauncherRequestV1::Launch {
                lease,
                execution_grant,
            } => {
                let now_ms = match self.now_or_reject(&request) {
                    Ok(now_ms) => now_ms,
                    Err(response) => return response,
                };
                match self.supervisor.launch(lease, execution_grant, now_ms) {
                    Ok(status) => Self::response(
                        &request,
                        WorkflowLauncherResponseV1::LaunchStatus {
                            status: Box::new(status),
                        },
                    ),
                    Err(error) => supervisor_rejection(&request, &error),
                }
            }
            WorkflowLauncherRequestV1::Observe {
                lease_id,
                lease_generation,
            } => match self.supervisor.observe(*lease_id, *lease_generation) {
                Ok(Some(status)) => Self::response(
                    &request,
                    WorkflowLauncherResponseV1::LaunchStatus {
                        status: Box::new(status),
                    },
                ),
                Ok(None) => Self::response(&request, WorkflowLauncherResponseV1::NotFound),
                Err(error) => supervisor_rejection(&request, &error),
            },
            WorkflowLauncherRequestV1::Cleanup { lease } => {
                let now_ms = match self.now_or_reject(&request) {
                    Ok(now_ms) => now_ms,
                    Err(response) => return response,
                };
                match self.supervisor.cleanup(lease, now_ms) {
                    Ok(status) => Self::response(
                        &request,
                        WorkflowLauncherResponseV1::CleanupStatus {
                            status: Box::new(status),
                        },
                    ),
                    Err(error) => supervisor_rejection(&request, &error),
                }
            }
        }
    }
}

fn supervisor_rejection(
    request: &WorkflowLauncherRequestEnvelopeV1,
    error: &WorkflowLaunchSupervisorError,
) -> WorkflowLauncherResponseEnvelopeV1 {
    let (code, retryable) = match error {
        WorkflowLaunchSupervisorError::Launcher(WorkflowLauncherError::Preparation(_)) => {
            (WorkflowLauncherRejectionCodeV1::AuthorizationRejected, true)
        }
        WorkflowLaunchSupervisorError::Launcher(_)
        | WorkflowLaunchSupervisorError::PolicyJournalMismatch => (
            WorkflowLauncherRejectionCodeV1::AuthorizationRejected,
            false,
        ),
        WorkflowLaunchSupervisorError::Journal(WorkflowLaunchJournalError::IdentityConflict) => {
            (WorkflowLauncherRejectionCodeV1::IdentityConflict, false)
        }
        WorkflowLaunchSupervisorError::Journal(
            WorkflowLaunchJournalError::StateConflict | WorkflowLaunchJournalError::InvalidLocator,
        ) => (WorkflowLauncherRejectionCodeV1::StateConflict, false),
        WorkflowLaunchSupervisorError::Journal(
            WorkflowLaunchJournalError::JournalFull | WorkflowLaunchJournalError::ConcurrencyLimit,
        ) => (WorkflowLauncherRejectionCodeV1::CapacityUnavailable, true),
        WorkflowLaunchSupervisorError::Journal(_) => {
            (WorkflowLauncherRejectionCodeV1::JournalUnavailable, true)
        }
        WorkflowLaunchSupervisorError::Runtime(_) => {
            (WorkflowLauncherRejectionCodeV1::RuntimeUnavailable, true)
        }
    };
    WorkflowLauncherResponseEnvelopeV1 {
        version: WORKFLOW_LAUNCHER_PROTOCOL_VERSION,
        request_id: request.request_id,
        response: WorkflowLauncherResponseV1::Rejected { code, retryable },
    }
}

#[derive(Debug)]
pub struct WorkflowLauncherClientV1 {
    socket_path: PathBuf,
    request_timeout: Duration,
    negotiated: AtomicBool,
}

impl WorkflowLauncherClientV1 {
    pub fn installed(request_timeout: Duration) -> Result<Self, WorkflowLauncherClientError> {
        Self::new(WORKFLOW_LAUNCHER_SOCKET_PATH, request_timeout)
    }

    pub fn new(
        socket_path: impl Into<PathBuf>,
        request_timeout: Duration,
    ) -> Result<Self, WorkflowLauncherClientError> {
        let socket_path = socket_path.into();
        if !is_normalized_absolute_path(&socket_path)
            || request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(WorkflowLauncherClientError::InvalidConfig);
        }
        Ok(Self {
            socket_path,
            request_timeout,
            negotiated: AtomicBool::new(false),
        })
    }

    pub async fn launch(
        &self,
        lease: WorkflowLeaseV1,
        execution_grant: String,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError> {
        self.ensure_negotiated().await?;
        let lease_id = lease.lease_id;
        let lease_generation = lease.lease_generation;
        match self
            .exchange(WorkflowLauncherRequestV1::Launch {
                lease: Box::new(lease),
                execution_grant,
            })
            .await?
        {
            WorkflowLauncherResponseV1::LaunchStatus { status }
                if status.lease_id == lease_id && status.lease_generation == lease_generation =>
            {
                Ok(*status)
            }
            WorkflowLauncherResponseV1::Rejected { code, retryable } => {
                Err(WorkflowLauncherClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    pub async fn observe(
        &self,
        lease_id: Uuid,
        lease_generation: u32,
    ) -> Result<Option<WorkflowLaunchStatusV1>, WorkflowLauncherClientError> {
        self.ensure_negotiated().await?;
        match self
            .exchange(WorkflowLauncherRequestV1::Observe {
                lease_id,
                lease_generation,
            })
            .await?
        {
            WorkflowLauncherResponseV1::LaunchStatus { status }
                if status.lease_id == lease_id && status.lease_generation == lease_generation =>
            {
                Ok(Some(*status))
            }
            WorkflowLauncherResponseV1::NotFound => Ok(None),
            WorkflowLauncherResponseV1::Rejected { code, retryable } => {
                Err(WorkflowLauncherClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    pub async fn cleanup(
        &self,
        lease: WorkflowLeaseV1,
    ) -> Result<WorkflowLaunchStatusV1, WorkflowLauncherClientError> {
        self.ensure_negotiated().await?;
        let lease_id = lease.lease_id;
        let lease_generation = lease.lease_generation;
        match self
            .exchange(WorkflowLauncherRequestV1::Cleanup {
                lease: Box::new(lease),
            })
            .await?
        {
            WorkflowLauncherResponseV1::CleanupStatus { status }
                if status.lease_id == lease_id && status.lease_generation == lease_generation =>
            {
                Ok(*status)
            }
            WorkflowLauncherResponseV1::Rejected { code, retryable } => {
                Err(WorkflowLauncherClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    async fn ensure_negotiated(&self) -> Result<(), WorkflowLauncherClientError> {
        if self.negotiated.load(Ordering::Acquire) {
            return Ok(());
        }
        match self
            .exchange(WorkflowLauncherRequestV1::Negotiate {
                supported_versions: vec![WORKFLOW_LAUNCHER_PROTOCOL_VERSION],
            })
            .await?
        {
            WorkflowLauncherResponseV1::Negotiated { selected_version }
                if selected_version == WORKFLOW_LAUNCHER_PROTOCOL_VERSION =>
            {
                self.negotiated.store(true, Ordering::Release);
                Ok(())
            }
            WorkflowLauncherResponseV1::Rejected { code, retryable } => {
                Err(WorkflowLauncherClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    fn wrong_response<T>(&self) -> Result<T, WorkflowLauncherClientError> {
        self.negotiated.store(false, Ordering::Release);
        Err(WorkflowLauncherClientError::WrongResponse)
    }

    async fn exchange(
        &self,
        request: WorkflowLauncherRequestV1,
    ) -> Result<WorkflowLauncherResponseV1, WorkflowLauncherClientError> {
        let request_id = Uuid::new_v4();
        let request = WorkflowLauncherRequestEnvelopeV1 {
            version: WORKFLOW_LAUNCHER_PROTOCOL_VERSION,
            request_id,
            request,
        };
        let response = timeout(self.request_timeout, async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(WorkflowLauncherClientError::Io)?;
            write_frame(&mut stream, &request, NORMAL_FRAME_MAX_BYTES).await?;
            stream
                .shutdown()
                .await
                .map_err(WorkflowLauncherClientError::Io)?;
            let response: WorkflowLauncherResponseEnvelopeV1 =
                read_frame(&mut stream, NORMAL_FRAME_MAX_BYTES).await?;
            let mut trailing = [0_u8; 1];
            if stream
                .read(&mut trailing)
                .await
                .map_err(WorkflowLauncherClientError::Io)?
                != 0
            {
                return Err(WorkflowLauncherClientError::TrailingResponse);
            }
            Ok::<_, WorkflowLauncherClientError>(response)
        })
        .await
        .map_err(|_| WorkflowLauncherClientError::DeadlineExceeded)??;
        if response.version != WORKFLOW_LAUNCHER_PROTOCOL_VERSION
            || response.request_id != request_id
        {
            return self.wrong_response();
        }
        Ok(response.response)
    }
}

#[derive(Clone, Debug)]
pub struct WorkflowLauncherServerConfigV1 {
    allowed_uid: u32,
    max_connections: usize,
    request_timeout: Duration,
}

impl WorkflowLauncherServerConfigV1 {
    pub fn new(
        allowed_uid: u32,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Result<Self, WorkflowLauncherServerConfigError> {
        if allowed_uid == 0 || allowed_uid == u32::MAX {
            return Err(WorkflowLauncherServerConfigError::InvalidAllowedUid);
        }
        if !(1..=MAX_CONNECTIONS).contains(&max_connections) {
            return Err(WorkflowLauncherServerConfigError::InvalidConnectionLimit);
        }
        if request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(WorkflowLauncherServerConfigError::InvalidRequestTimeout);
        }
        Ok(Self {
            allowed_uid,
            max_connections,
            request_timeout,
        })
    }
}

pub async fn serve_launcher_connection<H: WorkflowLauncherRequestHandlerV1 + 'static>(
    mut stream: UnixStream,
    handler: Arc<H>,
    config: &WorkflowLauncherServerConfigV1,
) -> Result<(), WorkflowLauncherSocketError> {
    let peer = stream
        .peer_cred()
        .map_err(WorkflowLauncherSocketError::PeerCredentials)?;
    if peer.uid() != config.allowed_uid {
        return Err(WorkflowLauncherSocketError::UnauthorizedPeer {
            received: peer.uid(),
        });
    }
    let deadline = Instant::now() + config.request_timeout;
    let request = timeout_at(deadline, async {
        let request = read_frame(&mut stream, NORMAL_FRAME_MAX_BYTES).await?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = stream.read(&mut trailing).await.map_err(FrameError::Io)?;
        if trailing_bytes != 0 {
            return Err(WorkflowLauncherSocketError::Frame(
                FrameError::TrailingBytes(trailing_bytes),
            ));
        }
        Ok::<WorkflowLauncherRequestEnvelopeV1, WorkflowLauncherSocketError>(request)
    })
    .await
    .map_err(|_| WorkflowLauncherSocketError::DeadlineExceeded)??;

    let mut handler_task = tokio::task::spawn_blocking(move || handler.handle(request));
    let response = if let Ok(result) = timeout_at(deadline, &mut handler_task).await {
        result.map_err(|_| WorkflowLauncherSocketError::HandlerTask)?
    } else {
        handler_task
            .await
            .map_err(|_| WorkflowLauncherSocketError::HandlerTask)?;
        return Err(WorkflowLauncherSocketError::DeadlineExceeded);
    };
    timeout_at(deadline, async {
        write_frame(&mut stream, &response, NORMAL_FRAME_MAX_BYTES).await?;
        stream
            .shutdown()
            .await
            .map_err(WorkflowLauncherSocketError::Write)?;
        Ok::<(), WorkflowLauncherSocketError>(())
    })
    .await
    .map_err(|_| WorkflowLauncherSocketError::DeadlineExceeded)??;
    Ok(())
}

pub async fn serve_launcher_until<H, F>(
    listener: UnixListener,
    handler: Arc<H>,
    config: WorkflowLauncherServerConfigV1,
    shutdown: F,
) -> Result<(), WorkflowLauncherSocketError>
where
    H: WorkflowLauncherRequestHandlerV1 + 'static,
    F: Future<Output = ()>,
{
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    let serve_result = loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                log_launcher_connection_result(result);
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                    ) => {
                        warn!(error = %error, "transient workflow launcher socket accept failure");
                        continue;
                    }
                    Err(error) => break Err(WorkflowLauncherSocketError::Accept(error)),
                };
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    warn!("workflow launcher connection limit reached");
                    continue;
                };
                let handler = Arc::clone(&handler);
                let config = config.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_launcher_connection(stream, handler, &config).await
                });
            }
        }
    };
    drop(listener);
    while let Some(result) = tasks.join_next().await {
        log_launcher_connection_result(result);
    }
    serve_result
}

fn log_launcher_connection_result(
    result: Result<Result<(), WorkflowLauncherSocketError>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(error = %error, "workflow launcher connection rejected"),
        Err(error) => warn!(error = %error, "workflow launcher connection task failed"),
    }
}

pub struct BoundWorkflowLauncherSocketV1 {
    listener: Option<UnixListener>,
    cleanup: WorkflowLauncherSocketCleanupGuard,
}

impl BoundWorkflowLauncherSocketV1 {
    pub fn bind(
        path: &Path,
        required_owner_uid: u32,
        required_group_gid: u32,
    ) -> Result<Self, WorkflowLauncherSocketError> {
        if !is_normalized_absolute_path(path) {
            return Err(WorkflowLauncherSocketError::InvalidBindPath);
        }
        let parent = path
            .parent()
            .ok_or(WorkflowLauncherSocketError::InvalidBindPath)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(WorkflowLauncherSocketError::BindParent)?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != required_owner_uid
            || parent_metadata.gid() != required_group_gid
            || parent_metadata.permissions().mode() & 0o777 != 0o750
            || required_group_gid == 0
        {
            return Err(WorkflowLauncherSocketError::UnsafeBindParent);
        }
        match fs::symlink_metadata(path) {
            Ok(existing) => {
                let expected_stale_socket = existing.file_type().is_socket()
                    && existing.uid() == required_owner_uid
                    && existing.gid() == required_group_gid
                    && existing.permissions().mode() & 0o777 == 0o660;
                if !expected_stale_socket {
                    return Err(WorkflowLauncherSocketError::SocketPathExists);
                }
                match StdUnixStream::connect(path) {
                    Ok(stream) => {
                        let _ = stream.shutdown(Shutdown::Both);
                        return Err(WorkflowLauncherSocketError::SocketPathExists);
                    }
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                    Err(error) => {
                        return Err(WorkflowLauncherSocketError::InspectStaleSocket(error));
                    }
                }
                let rechecked = fs::symlink_metadata(path)
                    .map_err(WorkflowLauncherSocketError::InspectSocketPath)?;
                if !rechecked.file_type().is_socket()
                    || rechecked.dev() != existing.dev()
                    || rechecked.ino() != existing.ino()
                {
                    return Err(WorkflowLauncherSocketError::SocketPathChanged);
                }
                fs::remove_file(path).map_err(WorkflowLauncherSocketError::RemoveStaleSocket)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(WorkflowLauncherSocketError::InspectSocketPath(error)),
        }
        let listener = UnixListener::bind(path).map_err(WorkflowLauncherSocketError::Bind)?;
        let bound =
            fs::symlink_metadata(path).map_err(WorkflowLauncherSocketError::InspectSocketPath)?;
        if !bound.file_type().is_socket()
            || bound.uid() != required_owner_uid
            || bound.gid() != required_group_gid
        {
            return Err(WorkflowLauncherSocketError::BoundPathNotSocket);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))
            .map_err(WorkflowLauncherSocketError::SetPermissions)?;
        let protected =
            fs::symlink_metadata(path).map_err(WorkflowLauncherSocketError::InspectSocketPath)?;
        if !protected.file_type().is_socket()
            || protected.uid() != required_owner_uid
            || protected.gid() != required_group_gid
            || protected.permissions().mode() & 0o777 != 0o660
            || protected.dev() != bound.dev()
            || protected.ino() != bound.ino()
        {
            return Err(WorkflowLauncherSocketError::BoundPathNotSocket);
        }
        Ok(Self {
            listener: Some(listener),
            cleanup: WorkflowLauncherSocketCleanupGuard {
                path: path.to_owned(),
                device: protected.dev(),
                inode: protected.ino(),
            },
        })
    }

    pub fn take_listener(&mut self) -> UnixListener {
        self.listener
            .take()
            .expect("bound workflow launcher listener can only be taken once")
    }

    pub fn path(&self) -> &Path {
        &self.cleanup.path
    }
}

struct WorkflowLauncherSocketCleanupGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for WorkflowLauncherSocketCleanupGuard {
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
pub enum WorkflowLauncherValidationError {
    #[error("unsupported workflow launcher protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("workflow launcher request ID must not be nil")]
    NilRequestId,
    #[error("workflow launcher version set must contain 1-8 versions")]
    InvalidVersionSet,
    #[error("workflow launcher lease is invalid")]
    InvalidLease,
    #[error("workflow launcher execution grant is invalid")]
    InvalidGrant,
    #[error("workflow launcher locator is invalid")]
    InvalidLocator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorkflowLauncherServerConfigError {
    #[error("workflow launcher peer UID must identify a non-root Unix account")]
    InvalidAllowedUid,
    #[error("workflow launcher connection limit is outside the supported range")]
    InvalidConnectionLimit,
    #[error("workflow launcher request timeout is outside the supported range")]
    InvalidRequestTimeout,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowLauncherClientError {
    #[error("workflow launcher client configuration is invalid")]
    InvalidConfig,
    #[error("workflow launcher request deadline elapsed")]
    DeadlineExceeded,
    #[error("workflow launcher socket I/O failed: {0}")]
    Io(io::Error),
    #[error("workflow launcher frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("workflow launcher response contains trailing bytes")]
    TrailingResponse,
    #[error("workflow launcher returned an unexpected or unbound response")]
    WrongResponse,
    #[error("workflow launcher rejected the request with {code:?}; retryable={retryable}")]
    Rejected {
        code: WorkflowLauncherRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowLauncherSocketError {
    #[error("workflow launcher bind path is invalid")]
    InvalidBindPath,
    #[error("workflow launcher socket parent could not be inspected: {0}")]
    BindParent(io::Error),
    #[error("workflow launcher socket parent is not the required protected directory")]
    UnsafeBindParent,
    #[error("workflow launcher socket path already exists")]
    SocketPathExists,
    #[error("workflow launcher stale socket could not be inspected: {0}")]
    InspectStaleSocket(io::Error),
    #[error("workflow launcher socket path could not be inspected: {0}")]
    InspectSocketPath(io::Error),
    #[error("workflow launcher socket path changed during stale cleanup")]
    SocketPathChanged,
    #[error("workflow launcher stale socket could not be removed: {0}")]
    RemoveStaleSocket(io::Error),
    #[error("workflow launcher socket bind failed: {0}")]
    Bind(io::Error),
    #[error("workflow launcher bound path is not the required socket")]
    BoundPathNotSocket,
    #[error("workflow launcher socket permissions could not be set: {0}")]
    SetPermissions(io::Error),
    #[error("workflow launcher peer credentials could not be read: {0}")]
    PeerCredentials(io::Error),
    #[error("workflow launcher peer UID {received} is unauthorized")]
    UnauthorizedPeer { received: u32 },
    #[error("workflow launcher request deadline elapsed")]
    DeadlineExceeded,
    #[error("workflow launcher frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("workflow launcher response write failed: {0}")]
    Write(io::Error),
    #[error("workflow launcher request handler task failed")]
    HandlerTask,
    #[error("workflow launcher socket accept failed: {0}")]
    Accept(io::Error),
}
