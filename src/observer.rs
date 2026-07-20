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
    sync::Arc,
    time::Duration,
};

use schemars::JsonSchema;
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
    domain::ProjectId,
    protocol::{FrameError, NORMAL_FRAME_MAX_BYTES, read_frame, write_frame},
};

pub const OBSERVER_PROTOCOL_VERSION: u16 = 1;
pub const PROJECT_RESOURCE_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
pub const OBSERVER_SOCKET_PATH: &str = "/run/rdashboard-observer/observer.sock";
const MAX_CONNECTIONS: usize = 16;
const MIN_REQUEST_TIMEOUT_MS: u64 = 100;
const MAX_REQUEST_TIMEOUT_MS: u64 = 10_000;
const MAX_BROWSER_SAFE_TIMESTAMP: i64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverRequestV1 {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub query: ObserverQueryV1,
}

impl ObserverRequestV1 {
    pub fn project_resources(project_id: ProjectId) -> Self {
        Self {
            schema_version: OBSERVER_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            query: ObserverQueryV1::ProjectResources { project_id },
        }
    }

    pub fn validate(&self) -> Result<(), ObserverValidationError> {
        if self.schema_version != OBSERVER_PROTOCOL_VERSION {
            return Err(ObserverValidationError::UnsupportedVersion(
                self.schema_version,
            ));
        }
        if self.request_id.is_nil() {
            return Err(ObserverValidationError::NilRequestId);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObserverQueryV1 {
    ProjectResources { project_id: ProjectId },
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectResourceSnapshotV1 {
    pub schema_version: u16,
    pub observed_at_ms: i64,
    pub cpu_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_limit_bytes: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub block_read_bytes: u64,
    pub block_write_bytes: u64,
}

impl ProjectResourceSnapshotV1 {
    pub fn validate(&self) -> Result<(), ObserverValidationError> {
        if self.schema_version != PROJECT_RESOURCE_SNAPSHOT_SCHEMA_VERSION {
            return Err(ObserverValidationError::UnsupportedSnapshotVersion(
                self.schema_version,
            ));
        }
        if !(0..=MAX_BROWSER_SAFE_TIMESTAMP).contains(&self.observed_at_ms) {
            return Err(ObserverValidationError::InvalidObservationTime);
        }
        if !self.cpu_percent.is_finite()
            || !(0.0..=100_000.0).contains(&self.cpu_percent)
            || self.memory_limit_bytes == 0
            || self.memory_used_bytes > self.memory_limit_bytes
        {
            return Err(ObserverValidationError::InvalidResourceMeasurement);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverRejectionCodeV1 {
    UnsupportedProtocolVersion,
    InvalidRequest,
    ProjectNotConfigured,
    CollectionUnavailable,
    InternalFailure,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObserverResponseV1 {
    ProjectResources {
        schema_version: u16,
        request_id: Uuid,
        project_id: ProjectId,
        snapshot: ProjectResourceSnapshotV1,
    },
    Rejected {
        schema_version: u16,
        request_id: Uuid,
        code: ObserverRejectionCodeV1,
        retryable: bool,
    },
}

impl ObserverResponseV1 {
    const fn request_id(&self) -> Uuid {
        match self {
            Self::ProjectResources { request_id, .. } | Self::Rejected { request_id, .. } => {
                *request_id
            }
        }
    }
}

pub trait ObserverRequestHandlerV1: Send + Sync {
    fn observe_project_resources(
        &self,
        project_id: &ProjectId,
    ) -> Result<ProjectResourceSnapshotV1, ObserverRejectionCodeV1>;
}

fn handle_request(
    handler: &impl ObserverRequestHandlerV1,
    request: ObserverRequestV1,
) -> ObserverResponseV1 {
    let request_id = request.request_id;
    if let Err(error) = request.validate() {
        let code = if matches!(error, ObserverValidationError::UnsupportedVersion(_)) {
            ObserverRejectionCodeV1::UnsupportedProtocolVersion
        } else {
            ObserverRejectionCodeV1::InvalidRequest
        };
        return rejected(request_id, code, false);
    }
    match request.query {
        ObserverQueryV1::ProjectResources { project_id } => {
            match handler.observe_project_resources(&project_id) {
                Ok(snapshot) => match snapshot.validate() {
                    Ok(()) => ObserverResponseV1::ProjectResources {
                        schema_version: OBSERVER_PROTOCOL_VERSION,
                        request_id,
                        project_id,
                        snapshot,
                    },
                    Err(error) => {
                        warn!(
                            error = %error,
                            project_id = %project_id,
                            "observer handler returned invalid resource evidence"
                        );
                        rejected(request_id, ObserverRejectionCodeV1::InternalFailure, true)
                    }
                },
                Err(code) => rejected(
                    request_id,
                    code,
                    matches!(
                        code,
                        ObserverRejectionCodeV1::CollectionUnavailable
                            | ObserverRejectionCodeV1::InternalFailure
                    ),
                ),
            }
        }
    }
}

const fn rejected(
    request_id: Uuid,
    code: ObserverRejectionCodeV1,
    retryable: bool,
) -> ObserverResponseV1 {
    ObserverResponseV1::Rejected {
        schema_version: OBSERVER_PROTOCOL_VERSION,
        request_id,
        code,
        retryable,
    }
}

#[derive(Clone, Debug)]
pub struct ObserverClientV1 {
    socket_path: PathBuf,
    request_timeout: Duration,
}

impl ObserverClientV1 {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        request_timeout: Duration,
    ) -> Result<Self, ObserverClientError> {
        let socket_path = socket_path.into();
        if !is_normalized_absolute_path(&socket_path)
            || request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(ObserverClientError::InvalidConfig);
        }
        Ok(Self {
            socket_path,
            request_timeout,
        })
    }

    pub async fn observe_project_resources(
        &self,
        project_id: ProjectId,
    ) -> Result<ProjectResourceSnapshotV1, ObserverClientError> {
        let request = ObserverRequestV1::project_resources(project_id.clone());
        let request_id = request.request_id;
        let response = timeout(self.request_timeout, async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(ObserverClientError::Io)?;
            write_frame(&mut stream, &request, NORMAL_FRAME_MAX_BYTES).await?;
            stream.shutdown().await.map_err(ObserverClientError::Io)?;
            let response = read_frame(&mut stream, NORMAL_FRAME_MAX_BYTES).await?;
            let mut trailing = [0_u8; 1];
            let trailing_bytes = stream
                .read(&mut trailing)
                .await
                .map_err(ObserverClientError::Io)?;
            if trailing_bytes != 0 {
                return Err(ObserverClientError::TrailingResponse);
            }
            Ok::<ObserverResponseV1, ObserverClientError>(response)
        })
        .await
        .map_err(|_| ObserverClientError::DeadlineExceeded)??;

        if response.request_id() != request_id {
            return Err(ObserverClientError::RequestBinding);
        }
        match response {
            ObserverResponseV1::ProjectResources {
                schema_version,
                project_id: response_project,
                snapshot,
                ..
            } if schema_version == OBSERVER_PROTOCOL_VERSION
                && response_project == project_id
                && snapshot.validate().is_ok() =>
            {
                Ok(snapshot)
            }
            ObserverResponseV1::Rejected {
                schema_version,
                code,
                retryable,
                ..
            } if schema_version == OBSERVER_PROTOCOL_VERSION => {
                Err(ObserverClientError::Rejected { code, retryable })
            }
            ObserverResponseV1::ProjectResources { .. } | ObserverResponseV1::Rejected { .. } => {
                Err(ObserverClientError::WrongResponse)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ObserverServerConfig {
    allowed_uid: u32,
    max_connections: usize,
    request_timeout: Duration,
}

impl ObserverServerConfig {
    pub fn new(
        allowed_uid: u32,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Result<Self, ObserverServerConfigError> {
        if allowed_uid == 0 || allowed_uid == u32::MAX {
            return Err(ObserverServerConfigError::InvalidAllowedUid);
        }
        if !(1..=MAX_CONNECTIONS).contains(&max_connections) {
            return Err(ObserverServerConfigError::InvalidConnectionLimit);
        }
        if request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(ObserverServerConfigError::InvalidRequestTimeout);
        }
        Ok(Self {
            allowed_uid,
            max_connections,
            request_timeout,
        })
    }
}

pub async fn serve_connection<H: ObserverRequestHandlerV1 + 'static>(
    mut stream: UnixStream,
    handler: Arc<H>,
    config: &ObserverServerConfig,
) -> Result<(), ObserverSocketError> {
    let peer = stream
        .peer_cred()
        .map_err(ObserverSocketError::PeerCredentials)?;
    if peer.uid() != config.allowed_uid {
        return Err(ObserverSocketError::UnauthorizedPeer {
            received: peer.uid(),
        });
    }

    let deadline = Instant::now() + config.request_timeout;
    let request = timeout_at(deadline, async {
        let request = read_frame(&mut stream, NORMAL_FRAME_MAX_BYTES).await?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = stream.read(&mut trailing).await.map_err(FrameError::Io)?;
        if trailing_bytes != 0 {
            return Err(ObserverSocketError::Frame(FrameError::TrailingBytes(
                trailing_bytes,
            )));
        }
        Ok::<ObserverRequestV1, ObserverSocketError>(request)
    })
    .await
    .map_err(|_| ObserverSocketError::DeadlineExceeded)??;

    let mut handler_task =
        tokio::task::spawn_blocking(move || handle_request(handler.as_ref(), request));
    let response = if let Ok(result) = timeout_at(deadline, &mut handler_task).await {
        result.map_err(|_| ObserverSocketError::HandlerTask)?
    } else {
        handler_task
            .await
            .map_err(|_| ObserverSocketError::HandlerTask)?;
        return Err(ObserverSocketError::DeadlineExceeded);
    };
    timeout_at(deadline, async {
        write_frame(&mut stream, &response, NORMAL_FRAME_MAX_BYTES).await?;
        stream
            .shutdown()
            .await
            .map_err(ObserverSocketError::Write)?;
        Ok::<(), ObserverSocketError>(())
    })
    .await
    .map_err(|_| ObserverSocketError::DeadlineExceeded)??;
    Ok(())
}

pub async fn serve_until<H, F>(
    listener: UnixListener,
    handler: Arc<H>,
    config: ObserverServerConfig,
    shutdown: F,
) -> Result<(), ObserverSocketError>
where
    H: ObserverRequestHandlerV1 + 'static,
    F: Future<Output = ()>,
{
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => warn!(error = %error, "observer connection rejected"),
                    Err(error) => warn!(error = %error, "observer connection task failed"),
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(ObserverSocketError::Accept)?;
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    warn!("observer connection limit reached");
                    continue;
                };
                let handler = Arc::clone(&handler);
                let config = config.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_connection(stream, handler, &config).await
                });
            }
        }
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(error = %error, "observer connection ended during shutdown"),
            Err(error) => warn!(error = %error, "observer connection task failed during shutdown"),
        }
    }
    Ok(())
}

pub struct BoundObserverSocketV1 {
    listener: Option<UnixListener>,
    cleanup: ObserverSocketCleanupGuard,
}

impl BoundObserverSocketV1 {
    pub fn bind(path: &Path, required_uid: u32) -> Result<Self, ObserverSocketError> {
        if !is_normalized_absolute_path(path) {
            return Err(ObserverSocketError::InvalidBindPath);
        }
        let parent = path.parent().ok_or(ObserverSocketError::InvalidBindPath)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(ObserverSocketError::BindParent)?;
        let parent_mode = parent_metadata.permissions().mode() & 0o777;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != required_uid
            || parent_mode != 0o750
            || parent_metadata.gid() == 0
        {
            return Err(ObserverSocketError::UnsafeBindParent);
        }
        match fs::symlink_metadata(path) {
            Ok(existing) => {
                let expected_stale_socket = existing.file_type().is_socket()
                    && existing.uid() == required_uid
                    && existing.gid() == parent_metadata.gid()
                    && existing.permissions().mode() & 0o777 == 0o660;
                if !expected_stale_socket {
                    return Err(ObserverSocketError::SocketPathExists);
                }
                match StdUnixStream::connect(path) {
                    Ok(stream) => {
                        let _ = stream.shutdown(Shutdown::Both);
                        return Err(ObserverSocketError::SocketPathExists);
                    }
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                    Err(error) => return Err(ObserverSocketError::InspectStaleSocket(error)),
                }
                let rechecked =
                    fs::symlink_metadata(path).map_err(ObserverSocketError::InspectSocketPath)?;
                if !rechecked.file_type().is_socket()
                    || rechecked.dev() != existing.dev()
                    || rechecked.ino() != existing.ino()
                {
                    return Err(ObserverSocketError::SocketPathChanged);
                }
                fs::remove_file(path).map_err(ObserverSocketError::RemoveStaleSocket)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(ObserverSocketError::InspectSocketPath(error)),
        }

        let listener = UnixListener::bind(path).map_err(ObserverSocketError::Bind)?;
        let bound = fs::symlink_metadata(path).map_err(ObserverSocketError::InspectSocketPath)?;
        if !bound.file_type().is_socket()
            || bound.uid() != required_uid
            || bound.gid() != parent_metadata.gid()
        {
            return Err(ObserverSocketError::BoundPathNotSocket);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))
            .map_err(ObserverSocketError::SetPermissions)?;
        let protected =
            fs::symlink_metadata(path).map_err(ObserverSocketError::InspectSocketPath)?;
        if !protected.file_type().is_socket()
            || protected.uid() != required_uid
            || protected.gid() != parent_metadata.gid()
            || protected.permissions().mode() & 0o777 != 0o660
            || protected.dev() != bound.dev()
            || protected.ino() != bound.ino()
        {
            return Err(ObserverSocketError::BoundPathNotSocket);
        }
        Ok(Self {
            listener: Some(listener),
            cleanup: ObserverSocketCleanupGuard {
                path: path.to_owned(),
                device: protected.dev(),
                inode: protected.ino(),
            },
        })
    }

    pub fn take_listener(&mut self) -> UnixListener {
        self.listener
            .take()
            .expect("bound observer listener can only be taken once")
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.cleanup.path
    }
}

struct ObserverSocketCleanupGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for ObserverSocketCleanupGuard {
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
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>() == path
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ObserverValidationError {
    #[error("unsupported observer protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("observer request ID must not be nil")]
    NilRequestId,
    #[error("unsupported project-resource snapshot version {0}")]
    UnsupportedSnapshotVersion(u16),
    #[error("project-resource observation time is invalid")]
    InvalidObservationTime,
    #[error("project-resource measurement is invalid")]
    InvalidResourceMeasurement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ObserverServerConfigError {
    #[error("observer client UID must identify a non-root Unix account")]
    InvalidAllowedUid,
    #[error("observer connection limit must be between 1 and {MAX_CONNECTIONS}")]
    InvalidConnectionLimit,
    #[error(
        "observer request timeout must be between {MIN_REQUEST_TIMEOUT_MS} and {MAX_REQUEST_TIMEOUT_MS} milliseconds"
    )]
    InvalidRequestTimeout,
}

#[derive(Debug, thiserror::Error)]
pub enum ObserverClientError {
    #[error("observer client configuration is invalid")]
    InvalidConfig,
    #[error("observer request deadline elapsed")]
    DeadlineExceeded,
    #[error("observer socket I/O failed: {0}")]
    Io(io::Error),
    #[error("observer frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("observer response contains trailing bytes")]
    TrailingResponse,
    #[error("observer response does not match its request")]
    RequestBinding,
    #[error("observer returned an invalid response")]
    WrongResponse,
    #[error("observer rejected the request with {code:?}; retryable={retryable}")]
    Rejected {
        code: ObserverRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ObserverSocketError {
    #[error("observer bind path is invalid")]
    InvalidBindPath,
    #[error("observer socket parent could not be inspected: {0}")]
    BindParent(io::Error),
    #[error("observer socket parent is not the required protected directory")]
    UnsafeBindParent,
    #[error("observer socket path already exists")]
    SocketPathExists,
    #[error("observer stale socket could not be inspected: {0}")]
    InspectStaleSocket(io::Error),
    #[error("observer socket path could not be inspected: {0}")]
    InspectSocketPath(io::Error),
    #[error("observer socket path changed during reconciliation")]
    SocketPathChanged,
    #[error("observer stale socket could not be removed: {0}")]
    RemoveStaleSocket(io::Error),
    #[error("observer socket could not be bound: {0}")]
    Bind(io::Error),
    #[error("observer bound path is not the required protected socket")]
    BoundPathNotSocket,
    #[error("observer socket permissions could not be set: {0}")]
    SetPermissions(io::Error),
    #[error("observer peer credentials could not be read: {0}")]
    PeerCredentials(io::Error),
    #[error("observer peer UID {received} is not authorized")]
    UnauthorizedPeer { received: u32 },
    #[error("observer request deadline elapsed")]
    DeadlineExceeded,
    #[error("observer request frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("observer handler task failed")]
    HandlerTask,
    #[error("observer response could not be closed: {0}")]
    Write(io::Error),
    #[error("observer connection could not be accepted: {0}")]
    Accept(io::Error),
}
