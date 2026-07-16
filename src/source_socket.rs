use std::{
    fs,
    future::Future,
    io::{self, Read as _, Write as _},
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
    time::timeout,
};
use tracing::warn;
use uuid::Uuid;

use crate::{
    domain::{OperationRecord, ProjectId},
    protocol::{FrameError, decode_single_frame, encode_frame, read_frame, write_frame},
    source::{
        DurableSourceBroker, LiveSourceGate, SourceGateError, SourceGateProof, SourceRepository,
        SourceSnapshot,
    },
};

pub const SOURCE_PROTOCOL_VERSION: u16 = 1;
pub const SOURCE_SOCKET_PATH: &str = "/run/rdashboard-source/source.sock";

const SOURCE_REQUEST_MAX_BYTES: usize = 512 * 1024;
const SOURCE_RESPONSE_MAX_BYTES: usize = 512 * 1024;
const MIN_REQUEST_TIMEOUT_MS: u64 = 100;
const MAX_REQUEST_TIMEOUT_MS: u64 = 30_000;
const MAX_CONNECTIONS: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRequestEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub request: SourceRequestV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceRequestV1 {
    Negotiate {
        supported_versions: Vec<u16>,
    },
    Snapshot {
        project_id: ProjectId,
    },
    CheckLive {
        operation: Box<OperationRecord>,
        now_ms: i64,
    },
    CompleteLive {
        operation: Box<OperationRecord>,
    },
    AbortLive {
        operation: Box<OperationRecord>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceResponseEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub response: SourceResponseV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceResponseV1 {
    Negotiated {
        selected_version: u16,
    },
    Snapshot {
        snapshot: Box<SourceSnapshot>,
    },
    LiveProof {
        proof: SourceGateProof,
    },
    MutationTicketReleased,
    Rejected {
        code: SourceRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRejectionCodeV1 {
    UnsupportedProtocolVersion,
    InvalidRequest,
    ProjectUnavailable,
    HeadSuperseded,
    AttestationInvalid,
    SourceDiverged,
    ShaBlocked,
    ReconciliationPaused,
    InternalFailure,
}

pub trait SourceRequestHandlerV1: Send + Sync {
    fn handle(&self, request: SourceRequestEnvelopeV1) -> SourceResponseEnvelopeV1;
}

#[derive(Clone, Debug)]
pub struct BrokerSourceRequestHandlerV1<G> {
    gate: G,
}

impl<G> BrokerSourceRequestHandlerV1<G> {
    pub const fn new(gate: G) -> Self {
        Self { gate }
    }

    fn response(
        request: &SourceRequestEnvelopeV1,
        response: SourceResponseV1,
    ) -> SourceResponseEnvelopeV1 {
        SourceResponseEnvelopeV1 {
            version: SOURCE_PROTOCOL_VERSION,
            request_id: request.request_id,
            response,
        }
    }

    fn rejected(
        request: &SourceRequestEnvelopeV1,
        code: SourceRejectionCodeV1,
        retryable: bool,
    ) -> SourceResponseEnvelopeV1 {
        Self::response(request, SourceResponseV1::Rejected { code, retryable })
    }
}

pub trait SourceSnapshotReaderV1 {
    fn source_snapshot(&self, project_id: &ProjectId) -> Result<SourceSnapshot, SourceGateError>;
}

impl<R: SourceRepository> SourceSnapshotReaderV1 for DurableSourceBroker<R> {
    fn source_snapshot(&self, project_id: &ProjectId) -> Result<SourceSnapshot, SourceGateError> {
        self.store()
            .snapshot(project_id)
            .map_err(|_| SourceGateError::Unavailable)
    }
}

impl<G> SourceRequestHandlerV1 for BrokerSourceRequestHandlerV1<G>
where
    G: LiveSourceGate + SourceSnapshotReaderV1,
{
    fn handle(&self, request: SourceRequestEnvelopeV1) -> SourceResponseEnvelopeV1 {
        if request.version != SOURCE_PROTOCOL_VERSION || request.request_id.is_nil() {
            return Self::rejected(&request, SourceRejectionCodeV1::InvalidRequest, false);
        }
        match &request.request {
            SourceRequestV1::Negotiate { supported_versions } => {
                if supported_versions.len() <= 8
                    && supported_versions.contains(&SOURCE_PROTOCOL_VERSION)
                {
                    Self::response(
                        &request,
                        SourceResponseV1::Negotiated {
                            selected_version: SOURCE_PROTOCOL_VERSION,
                        },
                    )
                } else {
                    Self::rejected(
                        &request,
                        SourceRejectionCodeV1::UnsupportedProtocolVersion,
                        false,
                    )
                }
            }
            SourceRequestV1::Snapshot { project_id } => {
                match self.gate.source_snapshot(project_id) {
                    Ok(snapshot) => Self::response(
                        &request,
                        SourceResponseV1::Snapshot {
                            snapshot: Box::new(snapshot),
                        },
                    ),
                    Err(error) => source_error_response(&request, error),
                }
            }
            SourceRequestV1::CheckLive { operation, now_ms } if *now_ms >= 0 => {
                match self.gate.check_live(operation, *now_ms) {
                    Ok(proof) => Self::response(&request, SourceResponseV1::LiveProof { proof }),
                    Err(error) => source_error_response(&request, error),
                }
            }
            SourceRequestV1::CompleteLive { operation } => {
                match self.gate.complete_live(operation) {
                    Ok(()) => Self::response(&request, SourceResponseV1::MutationTicketReleased),
                    Err(error) => source_error_response(&request, error),
                }
            }
            SourceRequestV1::AbortLive { operation } => match self.gate.abort_live(operation) {
                Ok(()) => Self::response(&request, SourceResponseV1::MutationTicketReleased),
                Err(error) => source_error_response(&request, error),
            },
            SourceRequestV1::CheckLive { .. } => {
                Self::rejected(&request, SourceRejectionCodeV1::InvalidRequest, false)
            }
        }
    }
}

fn source_error_response(
    request: &SourceRequestEnvelopeV1,
    error: SourceGateError,
) -> SourceResponseEnvelopeV1 {
    let (code, retryable) = match error {
        SourceGateError::Unavailable => (SourceRejectionCodeV1::ProjectUnavailable, true),
        SourceGateError::HeadSuperseded => (SourceRejectionCodeV1::HeadSuperseded, false),
        SourceGateError::AttestationInvalid => (SourceRejectionCodeV1::AttestationInvalid, false),
        SourceGateError::Diverged => (SourceRejectionCodeV1::SourceDiverged, false),
        SourceGateError::BlockedSha => (SourceRejectionCodeV1::ShaBlocked, false),
        SourceGateError::Paused => (SourceRejectionCodeV1::ReconciliationPaused, false),
    };
    BrokerSourceRequestHandlerV1::<()>::rejected(request, code, retryable)
}

#[derive(Clone, Debug)]
pub struct SourceBrokerClientV1 {
    socket_path: PathBuf,
    request_timeout: Duration,
    negotiated: Arc<AtomicBool>,
}

impl SourceBrokerClientV1 {
    pub fn installed(request_timeout: Duration) -> Result<Self, SourceClientError> {
        Self::new(SOURCE_SOCKET_PATH, request_timeout)
    }

    pub fn new(
        socket_path: impl Into<PathBuf>,
        request_timeout: Duration,
    ) -> Result<Self, SourceClientError> {
        let socket_path = socket_path.into();
        if !is_normalized_absolute_path(&socket_path) {
            return Err(SourceClientError::InvalidSocketPath);
        }
        if request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(SourceClientError::InvalidRequestTimeout);
        }
        Ok(Self {
            socket_path,
            request_timeout,
            negotiated: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn snapshot(&self, project_id: &ProjectId) -> Result<SourceSnapshot, SourceClientError> {
        self.ensure_negotiated()?;
        match self.exchange(SourceRequestV1::Snapshot {
            project_id: project_id.clone(),
        })? {
            SourceResponseV1::Snapshot { snapshot } if snapshot.project_id == *project_id => {
                Ok(*snapshot)
            }
            SourceResponseV1::Rejected { code, retryable } => {
                Err(SourceClientError::Rejected { code, retryable })
            }
            _ => self.unexpected_response(),
        }
    }

    fn ensure_negotiated(&self) -> Result<(), SourceClientError> {
        if self.negotiated.load(Ordering::Acquire) {
            return Ok(());
        }
        match self.exchange(SourceRequestV1::Negotiate {
            supported_versions: vec![SOURCE_PROTOCOL_VERSION],
        })? {
            SourceResponseV1::Negotiated { selected_version }
                if selected_version == SOURCE_PROTOCOL_VERSION =>
            {
                self.negotiated.store(true, Ordering::Release);
                Ok(())
            }
            SourceResponseV1::Rejected { code, retryable } => {
                Err(SourceClientError::Rejected { code, retryable })
            }
            _ => self.unexpected_response(),
        }
    }

    fn unexpected_response<T>(&self) -> Result<T, SourceClientError> {
        self.negotiated.store(false, Ordering::Release);
        Err(SourceClientError::UnexpectedResponse)
    }

    fn exchange(&self, request: SourceRequestV1) -> Result<SourceResponseV1, SourceClientError> {
        let request_id = Uuid::new_v4();
        let envelope = SourceRequestEnvelopeV1 {
            version: SOURCE_PROTOCOL_VERSION,
            request_id,
            request,
        };
        let mut stream =
            StdUnixStream::connect(&self.socket_path).map_err(SourceClientError::Connect)?;
        stream
            .set_read_timeout(Some(self.request_timeout))
            .map_err(SourceClientError::Configure)?;
        stream
            .set_write_timeout(Some(self.request_timeout))
            .map_err(SourceClientError::Configure)?;
        let frame = encode_frame(&envelope, SOURCE_REQUEST_MAX_BYTES)?;
        stream.write_all(&frame).map_err(SourceClientError::Write)?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(SourceClientError::Shutdown)?;
        let response: SourceResponseEnvelopeV1 =
            read_blocking_frame(&mut stream, SOURCE_RESPONSE_MAX_BYTES)?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = stream
            .read(&mut trailing)
            .map_err(SourceClientError::Read)?;
        if trailing_bytes != 0 {
            return Err(SourceClientError::Frame(FrameError::TrailingBytes(
                trailing_bytes,
            )));
        }
        if response.version != SOURCE_PROTOCOL_VERSION || response.request_id != request_id {
            self.negotiated.store(false, Ordering::Release);
            return Err(SourceClientError::ResponseBindingMismatch);
        }
        Ok(response.response)
    }

    fn live_exchange(&self, request: SourceRequestV1) -> Result<SourceResponseV1, SourceGateError> {
        self.ensure_negotiated()
            .and_then(|()| self.exchange(request))
            .map_err(|error| source_client_gate_error(&error))
    }
}

impl SourceSnapshotReaderV1 for SourceBrokerClientV1 {
    fn source_snapshot(&self, project_id: &ProjectId) -> Result<SourceSnapshot, SourceGateError> {
        self.snapshot(project_id)
            .map_err(|error| source_client_gate_error(&error))
    }
}

impl LiveSourceGate for SourceBrokerClientV1 {
    fn check_live(
        &self,
        operation: &OperationRecord,
        now_ms: i64,
    ) -> Result<SourceGateProof, SourceGateError> {
        match self.live_exchange(SourceRequestV1::CheckLive {
            operation: Box::new(operation.clone()),
            now_ms,
        })? {
            SourceResponseV1::LiveProof { proof } => {
                if !live_proof_matches_operation(&proof, operation, now_ms) {
                    return Err(SourceGateError::AttestationInvalid);
                }
                Ok(proof)
            }
            SourceResponseV1::Rejected { code, .. } => Err(rejection_gate_error(code)),
            _ => Err(SourceGateError::Unavailable),
        }
    }

    fn complete_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        self.release_ticket(SourceRequestV1::CompleteLive {
            operation: Box::new(operation.clone()),
        })
    }

    fn abort_live(&self, operation: &OperationRecord) -> Result<(), SourceGateError> {
        self.release_ticket(SourceRequestV1::AbortLive {
            operation: Box::new(operation.clone()),
        })
    }
}

fn live_proof_matches_operation(
    proof: &SourceGateProof,
    operation: &OperationRecord,
    now_ms: i64,
) -> bool {
    operation.evidence.source_sequence == Some(proof.sequence)
        && operation.evidence.source_attestation_digest.as_ref() == Some(&proof.attestation_digest)
        && proof.project_id == operation.project_id
        && proof.checked_at_ms == now_ms
}

impl SourceBrokerClientV1 {
    fn release_ticket(&self, request: SourceRequestV1) -> Result<(), SourceGateError> {
        match self.live_exchange(request)? {
            SourceResponseV1::MutationTicketReleased => Ok(()),
            SourceResponseV1::Rejected { code, .. } => Err(rejection_gate_error(code)),
            _ => Err(SourceGateError::Unavailable),
        }
    }
}

fn source_client_gate_error(error: &SourceClientError) -> SourceGateError {
    match error {
        SourceClientError::Rejected { code, .. } => rejection_gate_error(*code),
        _ => SourceGateError::Unavailable,
    }
}

const fn rejection_gate_error(code: SourceRejectionCodeV1) -> SourceGateError {
    match code {
        SourceRejectionCodeV1::HeadSuperseded => SourceGateError::HeadSuperseded,
        SourceRejectionCodeV1::AttestationInvalid => SourceGateError::AttestationInvalid,
        SourceRejectionCodeV1::SourceDiverged => SourceGateError::Diverged,
        SourceRejectionCodeV1::ShaBlocked => SourceGateError::BlockedSha,
        SourceRejectionCodeV1::ReconciliationPaused => SourceGateError::Paused,
        SourceRejectionCodeV1::UnsupportedProtocolVersion
        | SourceRejectionCodeV1::InvalidRequest
        | SourceRejectionCodeV1::ProjectUnavailable
        | SourceRejectionCodeV1::InternalFailure => SourceGateError::Unavailable,
    }
}

fn read_blocking_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut StdUnixStream,
    maximum: usize,
) -> Result<T, SourceClientError> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(SourceClientError::Read)?;
    let declared = usize::try_from(u32::from_be_bytes(header)).map_err(|_| {
        SourceClientError::Frame(FrameError::Oversized {
            received: usize::MAX,
            maximum,
        })
    })?;
    if declared > maximum {
        return Err(SourceClientError::Frame(FrameError::Oversized {
            received: declared,
            maximum,
        }));
    }
    let mut frame = Vec::with_capacity(declared.saturating_add(4));
    frame.extend_from_slice(&header);
    frame.resize(declared.saturating_add(4), 0);
    stream
        .read_exact(&mut frame[4..])
        .map_err(SourceClientError::Read)?;
    decode_single_frame(&frame, maximum).map_err(Into::into)
}

#[derive(Clone, Debug)]
pub struct SourceServerConfigV1 {
    allowed_uid: u32,
    max_connections: usize,
    request_timeout: Duration,
}

impl SourceServerConfigV1 {
    pub fn new(
        allowed_uid: u32,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Result<Self, SourceSocketError> {
        if allowed_uid == u32::MAX
            || !(1..=MAX_CONNECTIONS).contains(&max_connections)
            || request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(SourceSocketError::InvalidServerConfig);
        }
        Ok(Self {
            allowed_uid,
            max_connections,
            request_timeout,
        })
    }
}

pub async fn serve_source_connection<H: SourceRequestHandlerV1 + 'static>(
    mut stream: UnixStream,
    handler: Arc<H>,
    config: &SourceServerConfigV1,
) -> Result<(), SourceSocketError> {
    let peer = stream
        .peer_cred()
        .map_err(SourceSocketError::PeerCredentials)?;
    if peer.uid() != config.allowed_uid {
        return Err(SourceSocketError::UnauthorizedPeer {
            received: peer.uid(),
        });
    }
    timeout(config.request_timeout, async move {
        let request = read_frame(&mut stream, SOURCE_REQUEST_MAX_BYTES).await?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = stream.read(&mut trailing).await.map_err(FrameError::Io)?;
        if trailing_bytes != 0 {
            return Err(SourceSocketError::Frame(FrameError::TrailingBytes(
                trailing_bytes,
            )));
        }
        let response = tokio::task::spawn_blocking(move || handler.handle(request))
            .await
            .map_err(SourceSocketError::HandlerTask)?;
        write_frame(&mut stream, &response, SOURCE_RESPONSE_MAX_BYTES).await?;
        stream
            .shutdown()
            .await
            .map_err(FrameError::Io)
            .map_err(SourceSocketError::Frame)
    })
    .await
    .map_err(|_| SourceSocketError::DeadlineExceeded)??;
    Ok(())
}

pub async fn serve_source_until<H, F>(
    listener: UnixListener,
    handler: Arc<H>,
    config: SourceServerConfigV1,
    shutdown: F,
) -> Result<(), SourceSocketError>
where
    H: SourceRequestHandlerV1 + 'static,
    F: Future<Output = ()>,
{
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    let serve_result = loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                log_source_connection_result(result);
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                    ) => {
                        warn!(error = %error, "transient source socket accept failure");
                        continue;
                    }
                    Err(error) => break Err(SourceSocketError::Accept(error)),
                };
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    warn!("source broker connection limit reached");
                    continue;
                };
                let handler = Arc::clone(&handler);
                let config = config.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_source_connection(stream, handler, &config).await
                });
            }
        }
    };
    drop(listener);
    while let Some(result) = tasks.join_next().await {
        log_source_connection_result(result);
    }
    serve_result
}

fn log_source_connection_result(
    result: Result<Result<(), SourceSocketError>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(error = %error, "source broker connection rejected"),
        Err(error) => warn!(error = %error, "source broker connection task failed"),
    }
}

pub struct BoundSourceSocketV1 {
    listener: Option<UnixListener>,
    cleanup: SourceSocketCleanupGuard,
}

impl BoundSourceSocketV1 {
    pub fn bind(path: &Path, required_uid: u32) -> Result<Self, SourceSocketError> {
        if !is_normalized_absolute_path(path) {
            return Err(SourceSocketError::InvalidBindPath);
        }
        let parent = path.parent().ok_or(SourceSocketError::InvalidBindPath)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(SourceSocketError::BindParent)?;
        let parent_mode = parent_metadata.permissions().mode() & 0o777;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != required_uid
            || !matches!(parent_mode, 0o700 | 0o750)
            || parent_mode == 0o750 && parent_metadata.gid() == 0
        {
            return Err(SourceSocketError::UnsafeBindParent);
        }
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(SourceSocketError::SocketPathExists),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(SourceSocketError::InspectSocketPath(error)),
        }
        let listener = UnixListener::bind(path).map_err(SourceSocketError::Bind)?;
        let bound = fs::symlink_metadata(path).map_err(SourceSocketError::InspectSocketPath)?;
        if !bound.file_type().is_socket()
            || bound.uid() != required_uid
            || bound.gid() != parent_metadata.gid()
        {
            return Err(SourceSocketError::BoundPathNotSocket);
        }
        let socket_mode = if parent_mode == 0o750 { 0o660 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(socket_mode))
            .map_err(SourceSocketError::SetPermissions)?;
        let protected = fs::symlink_metadata(path).map_err(SourceSocketError::InspectSocketPath)?;
        if !protected.file_type().is_socket()
            || protected.uid() != required_uid
            || protected.gid() != parent_metadata.gid()
            || protected.permissions().mode() & 0o777 != socket_mode
            || protected.dev() != bound.dev()
            || protected.ino() != bound.ino()
        {
            return Err(SourceSocketError::BoundPathNotSocket);
        }
        Ok(Self {
            listener: Some(listener),
            cleanup: SourceSocketCleanupGuard {
                path: path.to_owned(),
                device: protected.dev(),
                inode: protected.ino(),
            },
        })
    }

    pub fn take_listener(&mut self) -> UnixListener {
        self.listener
            .take()
            .expect("bound source listener can only be taken once")
    }

    pub fn path(&self) -> &Path {
        &self.cleanup.path
    }
}

struct SourceSocketCleanupGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SourceSocketCleanupGuard {
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

#[derive(Debug, thiserror::Error)]
pub enum SourceSocketError {
    #[error("source broker server configuration is invalid")]
    InvalidServerConfig,
    #[error("source broker socket bind path is invalid")]
    InvalidBindPath,
    #[error("source broker socket parent could not be inspected: {0}")]
    BindParent(io::Error),
    #[error("source broker socket parent is not an owner-only direct directory")]
    UnsafeBindParent,
    #[error("source broker socket path already exists")]
    SocketPathExists,
    #[error("source broker socket path could not be inspected: {0}")]
    InspectSocketPath(io::Error),
    #[error("source broker socket bind failed: {0}")]
    Bind(io::Error),
    #[error("source broker socket permissions could not be set: {0}")]
    SetPermissions(io::Error),
    #[error("source broker bind path is not an owned Unix socket")]
    BoundPathNotSocket,
    #[error("source broker peer credentials could not be read: {0}")]
    PeerCredentials(io::Error),
    #[error("source broker peer UID {received} is not authorized")]
    UnauthorizedPeer { received: u32 },
    #[error("source broker request deadline exceeded")]
    DeadlineExceeded,
    #[error("source broker frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("source broker blocking handler task failed: {0}")]
    HandlerTask(tokio::task::JoinError),
    #[error("source broker socket accept failed: {0}")]
    Accept(io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum SourceClientError {
    #[error("source broker client socket path must be absolute, normalized and bounded")]
    InvalidSocketPath,
    #[error("source broker client timeout is outside the supported range")]
    InvalidRequestTimeout,
    #[error("source broker connection failed: {0}")]
    Connect(io::Error),
    #[error("source broker socket configuration failed: {0}")]
    Configure(io::Error),
    #[error("source broker request write failed: {0}")]
    Write(io::Error),
    #[error("source broker request shutdown failed: {0}")]
    Shutdown(io::Error),
    #[error("source broker response read failed: {0}")]
    Read(io::Error),
    #[error("source broker frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("source broker response does not match its request")]
    ResponseBindingMismatch,
    #[error("source broker returned an unexpected response")]
    UnexpectedResponse,
    #[error("source broker rejected the request with {code:?} (retryable={retryable})")]
    Rejected {
        code: SourceRejectionCodeV1,
        retryable: bool,
    },
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        str::FromStr as _,
    };

    use tempfile::tempdir;

    use super::*;
    use crate::{
        domain::{EvidenceDigest, GitCommitId},
        source::SourceProjectState,
    };

    #[derive(Clone, Debug)]
    struct StaticGate {
        snapshot: SourceSnapshot,
    }

    struct SlowHandler;

    impl SourceRequestHandlerV1 for SlowHandler {
        fn handle(&self, request: SourceRequestEnvelopeV1) -> SourceResponseEnvelopeV1 {
            std::thread::sleep(Duration::from_millis(500));
            SourceResponseEnvelopeV1 {
                version: SOURCE_PROTOCOL_VERSION,
                request_id: request.request_id,
                response: SourceResponseV1::Negotiated {
                    selected_version: SOURCE_PROTOCOL_VERSION,
                },
            }
        }
    }

    impl SourceSnapshotReaderV1 for StaticGate {
        fn source_snapshot(
            &self,
            project_id: &ProjectId,
        ) -> Result<SourceSnapshot, SourceGateError> {
            if self.snapshot.project_id == *project_id {
                Ok(self.snapshot.clone())
            } else {
                Err(SourceGateError::Unavailable)
            }
        }
    }

    impl LiveSourceGate for StaticGate {
        fn check_live(
            &self,
            operation: &OperationRecord,
            now_ms: i64,
        ) -> Result<SourceGateProof, SourceGateError> {
            Ok(SourceGateProof {
                digest: EvidenceDigest::sha256("live proof"),
                project_id: operation.project_id.clone(),
                sequence: operation.evidence.source_sequence.unwrap_or_default(),
                attestation_digest: operation
                    .evidence
                    .source_attestation_digest
                    .clone()
                    .ok_or(SourceGateError::AttestationInvalid)?,
                checked_at_ms: now_ms,
            })
        }
    }

    fn snapshot() -> SourceSnapshot {
        SourceSnapshot {
            project_id: ProjectId::from_str("rimg").expect("project"),
            head: Some(
                GitCommitId::from_str("0123456789abcdef0123456789abcdef01234567").expect("commit"),
            ),
            sequence: 1,
            state: SourceProjectState::Ready,
            blocked_sha: None,
            reconcile_paused_until_ms: None,
            attestation: None,
            attestation_digest: None,
            divergent_candidate: None,
            divergence_channel: None,
            divergence_evidence_digest: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn source_client_negotiates_and_reads_a_request_bound_snapshot() {
        let directory = tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private tempdir");
        let socket_path = directory.path().join("source.sock");
        let required_uid = fs::metadata(directory.path()).expect("metadata").uid();
        let mut socket =
            BoundSourceSocketV1::bind(&socket_path, required_uid).expect("bind source socket");
        assert_eq!(
            fs::metadata(&socket_path)
                .expect("private source socket metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let listener = socket.take_listener();
        let config = SourceServerConfigV1::new(required_uid, 4, Duration::from_secs(2))
            .expect("server config");
        let expected = snapshot();
        let handler = Arc::new(BrokerSourceRequestHandlerV1::new(StaticGate {
            snapshot: expected.clone(),
        }));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_source_until(listener, handler, config, async {
            let _ = shutdown_rx.await;
        }));
        let project_id = expected.project_id.clone();
        let client_path = socket_path.clone();
        let observed = tokio::task::spawn_blocking(move || {
            SourceBrokerClientV1::new(client_path, Duration::from_secs(2))
                .and_then(|client| client.snapshot(&project_id))
        })
        .await
        .expect("client task")
        .expect("source snapshot");
        assert_eq!(observed, expected);
        let _ = shutdown_tx.send(());
        server.await.expect("server task").expect("source server");
    }

    #[tokio::test]
    async fn source_socket_shared_transport_requires_exact_non_root_group_modes() {
        let directory = tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750))
            .expect("shared source runtime directory");
        let parent = fs::metadata(directory.path()).expect("shared runtime metadata");
        assert_ne!(
            parent.gid(),
            0,
            "shared source transport needs a dedicated group"
        );
        let socket_path = directory.path().join("source.sock");
        let socket = BoundSourceSocketV1::bind(&socket_path, parent.uid())
            .expect("bind shared source socket");
        let metadata = fs::metadata(&socket_path).expect("shared source socket metadata");
        assert_eq!(metadata.gid(), parent.gid());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
        drop(socket);

        fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
            .expect("make source runtime overly broad");
        assert!(matches!(
            BoundSourceSocketV1::bind(&socket_path, parent.uid()),
            Err(SourceSocketError::UnsafeBindParent)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn source_connection_deadline_is_not_blocked_by_the_synchronous_handler() {
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let directory = tempdir().expect("tempdir");
        let required_uid = fs::metadata(directory.path()).expect("metadata").uid();
        let config = SourceServerConfigV1::new(required_uid, 1, Duration::from_millis(100))
            .expect("server config");
        let request = SourceRequestEnvelopeV1 {
            version: SOURCE_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            request: SourceRequestV1::Negotiate {
                supported_versions: vec![SOURCE_PROTOCOL_VERSION],
            },
        };
        let frame = encode_frame(&request, SOURCE_REQUEST_MAX_BYTES).expect("request frame");
        client.write_all(&frame).await.expect("write request");
        client.shutdown().await.expect("finish request");

        let started = std::time::Instant::now();
        let result = serve_source_connection(server, Arc::new(SlowHandler), &config).await;

        assert!(matches!(result, Err(SourceSocketError::DeadlineExceeded)));
        assert!(started.elapsed() < Duration::from_millis(400));
    }

    #[test]
    fn source_protocol_rejects_invalid_time_and_unsupported_negotiation() {
        let handler = BrokerSourceRequestHandlerV1::new(StaticGate {
            snapshot: snapshot(),
        });
        let invalid_time = handler.handle(SourceRequestEnvelopeV1 {
            version: SOURCE_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            request: SourceRequestV1::CheckLive {
                operation: Box::new(crate::domain::OperationRecord {
                    operation_id: Uuid::new_v4(),
                    request_id: Uuid::new_v4(),
                    attempt_id: Uuid::new_v4(),
                    attempt_number: 1,
                    project_id: ProjectId::from_str("rimg").expect("project"),
                    operation_kind: crate::domain::OperationKind::Deploy,
                    target_commit: None,
                    release_class: None,
                    state: crate::domain::OperationState {
                        phase: crate::domain::OperationPhase::Queued,
                        result: crate::domain::OperationResult::Running,
                        blocking_reason: crate::domain::BlockingReason::None,
                    },
                    actor: crate::domain::OperationActor::Interactive {
                        user_id: Uuid::new_v4(),
                    },
                    evidence: crate::domain::OperationEvidence::default(),
                    failure_capsule: None,
                    created_at_ms: 0,
                    updated_at_ms: 0,
                }),
                now_ms: -1,
            },
        });
        assert!(matches!(
            invalid_time.response,
            SourceResponseV1::Rejected {
                code: SourceRejectionCodeV1::InvalidRequest,
                retryable: false
            }
        ));
        let unsupported = handler.handle(SourceRequestEnvelopeV1 {
            version: SOURCE_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            request: SourceRequestV1::Negotiate {
                supported_versions: vec![SOURCE_PROTOCOL_VERSION + 1],
            },
        });
        assert!(matches!(
            unsupported.response,
            SourceResponseV1::Rejected {
                code: SourceRejectionCodeV1::UnsupportedProtocolVersion,
                retryable: false
            }
        ));
    }

    #[test]
    fn live_proof_requires_exact_operation_evidence_and_request_time() {
        let attestation_digest = EvidenceDigest::sha256("accepted head attestation");
        let mut operation = crate::domain::OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            attempt_number: 1,
            project_id: ProjectId::from_str("rimg").expect("project"),
            operation_kind: crate::domain::OperationKind::Deploy,
            target_commit: Some(
                crate::domain::GitCommitId::from_str("0123456789abcdef0123456789abcdef01234567")
                    .expect("commit"),
            ),
            release_class: Some(crate::domain::ReleaseClass::CodeOnlyCompatible),
            state: crate::domain::OperationState {
                phase: crate::domain::OperationPhase::Deploying,
                result: crate::domain::OperationResult::Running,
                blocking_reason: crate::domain::BlockingReason::None,
            },
            actor: crate::domain::OperationActor::Interactive {
                user_id: Uuid::new_v4(),
            },
            evidence: crate::domain::OperationEvidence::default(),
            failure_capsule: None,
            created_at_ms: 1,
            updated_at_ms: 1,
        };
        operation.evidence.source_sequence = Some(7);
        operation.evidence.source_attestation_digest = Some(attestation_digest.clone());
        let proof = SourceGateProof {
            digest: EvidenceDigest::sha256("live proof"),
            project_id: operation.project_id.clone(),
            sequence: 7,
            attestation_digest,
            checked_at_ms: 99,
        };

        assert!(live_proof_matches_operation(&proof, &operation, 99));

        let mut wrong_sequence = proof.clone();
        wrong_sequence.sequence += 1;
        assert!(!live_proof_matches_operation(
            &wrong_sequence,
            &operation,
            99
        ));

        operation.evidence.source_attestation_digest = None;
        assert!(!live_proof_matches_operation(&proof, &operation, 99));
        assert!(!live_proof_matches_operation(&proof, &operation, 100));
    }
}
