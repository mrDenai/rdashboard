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
    domain::EvidenceDigest,
    protocol::{FrameError, NORMAL_FRAME_MAX_BYTES, read_frame, write_frame},
    source::{DurableSourceBroker, SourceError, SourceOutboxEntryV1, SourceRepository},
    unix_time_ms,
};

pub const SOURCE_DELIVERY_PROTOCOL_VERSION: u16 = 1;
pub const SOURCE_DELIVERY_SOCKET_PATH: &str = "/run/rdashboard-source-delivery/delivery.sock";

const MIN_REQUEST_TIMEOUT_MS: u64 = 100;
const MAX_REQUEST_TIMEOUT_MS: u64 = 10_000;
const MAX_CONNECTIONS: usize = 64;
const MAX_PENDING_LIMIT: u8 = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDeliveryRequestEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub request: SourceDeliveryRequestV1,
}

impl SourceDeliveryRequestEnvelopeV1 {
    fn validate(&self) -> Result<(), SourceDeliveryValidationError> {
        if self.version != SOURCE_DELIVERY_PROTOCOL_VERSION {
            return Err(SourceDeliveryValidationError::UnsupportedVersion(
                self.version,
            ));
        }
        if self.request_id.is_nil() {
            return Err(SourceDeliveryValidationError::NilRequestId);
        }
        match &self.request {
            SourceDeliveryRequestV1::Negotiate { supported_versions }
                if !supported_versions.is_empty() && supported_versions.len() <= 8 =>
            {
                Ok(())
            }
            SourceDeliveryRequestV1::Negotiate { .. } => {
                Err(SourceDeliveryValidationError::InvalidVersionSet)
            }
            SourceDeliveryRequestV1::Pending { limit }
                if (1..=MAX_PENDING_LIMIT).contains(limit) =>
            {
                Ok(())
            }
            SourceDeliveryRequestV1::Pending { .. } => {
                Err(SourceDeliveryValidationError::InvalidPendingLimit)
            }
            SourceDeliveryRequestV1::Acknowledge {
                outbox_sequence, ..
            } if *outbox_sequence > 0 => Ok(()),
            SourceDeliveryRequestV1::Acknowledge { .. } => {
                Err(SourceDeliveryValidationError::InvalidAcknowledgement)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceDeliveryRequestV1 {
    Negotiate {
        supported_versions: Vec<u16>,
    },
    Pending {
        limit: u8,
    },
    Acknowledge {
        outbox_sequence: u64,
        attestation_digest: EvidenceDigest,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDeliveryResponseEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub response: SourceDeliveryResponseV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceDeliveryResponseV1 {
    Negotiated {
        selected_version: u16,
    },
    Pending {
        entries: Vec<SourceOutboxEntryV1>,
    },
    Acknowledged,
    Rejected {
        code: SourceDeliveryRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceDeliveryRejectionCodeV1 {
    UnsupportedProtocolVersion,
    InvalidRequest,
    EntryMissing,
    AcknowledgementConflict,
    SourceUnavailable,
    ClockUnavailable,
}

pub trait SourceOutboxReaderV1: Send + Sync {
    fn pending_outbox(&self, limit: usize) -> Result<Vec<SourceOutboxEntryV1>, SourceError>;

    fn acknowledge_outbox(
        &self,
        outbox_sequence: u64,
        attestation_digest: &EvidenceDigest,
        acknowledged_at_ms: i64,
    ) -> Result<(), SourceError>;
}

impl<R: SourceRepository> SourceOutboxReaderV1 for DurableSourceBroker<R> {
    fn pending_outbox(&self, limit: usize) -> Result<Vec<SourceOutboxEntryV1>, SourceError> {
        DurableSourceBroker::pending_outbox(self, limit)
    }

    fn acknowledge_outbox(
        &self,
        outbox_sequence: u64,
        attestation_digest: &EvidenceDigest,
        acknowledged_at_ms: i64,
    ) -> Result<(), SourceError> {
        DurableSourceBroker::acknowledge_outbox(
            self,
            outbox_sequence,
            attestation_digest,
            acknowledged_at_ms,
        )
    }
}

pub trait SourceDeliveryClockV1: Send + Sync {
    fn now_ms(&self) -> Result<i64, SourceDeliveryClockError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSourceDeliveryClockV1;

impl SourceDeliveryClockV1 for SystemSourceDeliveryClockV1 {
    fn now_ms(&self) -> Result<i64, SourceDeliveryClockError> {
        unix_time_ms().map_err(|_| SourceDeliveryClockError)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("source delivery clock is unavailable")]
pub struct SourceDeliveryClockError;

pub trait SourceDeliveryRequestHandlerV1: Send + Sync {
    fn handle(&self, request: SourceDeliveryRequestEnvelopeV1) -> SourceDeliveryResponseEnvelopeV1;
}

#[derive(Clone, Debug)]
pub struct BrokerSourceDeliveryHandlerV1<G, C = SystemSourceDeliveryClockV1> {
    gateway: G,
    clock: C,
}

impl<G> BrokerSourceDeliveryHandlerV1<G, SystemSourceDeliveryClockV1> {
    pub const fn system(gateway: G) -> Self {
        Self {
            gateway,
            clock: SystemSourceDeliveryClockV1,
        }
    }
}

impl<G, C> BrokerSourceDeliveryHandlerV1<G, C> {
    pub const fn new(gateway: G, clock: C) -> Self {
        Self { gateway, clock }
    }

    fn response(
        request: &SourceDeliveryRequestEnvelopeV1,
        response: SourceDeliveryResponseV1,
    ) -> SourceDeliveryResponseEnvelopeV1 {
        SourceDeliveryResponseEnvelopeV1 {
            version: SOURCE_DELIVERY_PROTOCOL_VERSION,
            request_id: request.request_id,
            response,
        }
    }

    fn rejected(
        request: &SourceDeliveryRequestEnvelopeV1,
        code: SourceDeliveryRejectionCodeV1,
        retryable: bool,
    ) -> SourceDeliveryResponseEnvelopeV1 {
        Self::response(
            request,
            SourceDeliveryResponseV1::Rejected { code, retryable },
        )
    }
}

impl<G, C> SourceDeliveryRequestHandlerV1 for BrokerSourceDeliveryHandlerV1<G, C>
where
    G: SourceOutboxReaderV1,
    C: SourceDeliveryClockV1,
{
    fn handle(&self, request: SourceDeliveryRequestEnvelopeV1) -> SourceDeliveryResponseEnvelopeV1 {
        if let Err(error) = request.validate() {
            let code = if matches!(error, SourceDeliveryValidationError::UnsupportedVersion(_)) {
                SourceDeliveryRejectionCodeV1::UnsupportedProtocolVersion
            } else {
                SourceDeliveryRejectionCodeV1::InvalidRequest
            };
            return Self::rejected(&request, code, false);
        }
        match &request.request {
            SourceDeliveryRequestV1::Negotiate { supported_versions } => {
                if supported_versions.contains(&SOURCE_DELIVERY_PROTOCOL_VERSION) {
                    Self::response(
                        &request,
                        SourceDeliveryResponseV1::Negotiated {
                            selected_version: SOURCE_DELIVERY_PROTOCOL_VERSION,
                        },
                    )
                } else {
                    Self::rejected(
                        &request,
                        SourceDeliveryRejectionCodeV1::UnsupportedProtocolVersion,
                        false,
                    )
                }
            }
            SourceDeliveryRequestV1::Pending { limit } => {
                match self.gateway.pending_outbox(usize::from(*limit)) {
                    Ok(entries) => {
                        Self::response(&request, SourceDeliveryResponseV1::Pending { entries })
                    }
                    Err(error) => source_rejection(&request, &error),
                }
            }
            SourceDeliveryRequestV1::Acknowledge {
                outbox_sequence,
                attestation_digest,
            } => {
                let acknowledged_at_ms = match self.clock.now_ms() {
                    Ok(now_ms) if now_ms >= 0 => now_ms,
                    _ => {
                        return Self::rejected(
                            &request,
                            SourceDeliveryRejectionCodeV1::ClockUnavailable,
                            true,
                        );
                    }
                };
                match self.gateway.acknowledge_outbox(
                    *outbox_sequence,
                    attestation_digest,
                    acknowledged_at_ms,
                ) {
                    Ok(()) => Self::response(&request, SourceDeliveryResponseV1::Acknowledged),
                    Err(error) => source_rejection(&request, &error),
                }
            }
        }
    }
}

fn source_rejection(
    request: &SourceDeliveryRequestEnvelopeV1,
    error: &SourceError,
) -> SourceDeliveryResponseEnvelopeV1 {
    let (code, retryable) = match error {
        SourceError::InvalidOutboxLimit | SourceError::InvalidOutboxAcknowledgement => {
            (SourceDeliveryRejectionCodeV1::InvalidRequest, false)
        }
        SourceError::OutboxEntryMissing => (SourceDeliveryRejectionCodeV1::EntryMissing, false),
        SourceError::OutboxAcknowledgementConflict => (
            SourceDeliveryRejectionCodeV1::AcknowledgementConflict,
            false,
        ),
        _ => (SourceDeliveryRejectionCodeV1::SourceUnavailable, true),
    };
    BrokerSourceDeliveryHandlerV1::<(), ()>::rejected(request, code, retryable)
}

#[derive(Debug)]
pub struct SourceDeliveryClientV1 {
    socket_path: PathBuf,
    expected_server_uid: u32,
    request_timeout: Duration,
    negotiated: AtomicBool,
}

impl SourceDeliveryClientV1 {
    pub fn installed(
        expected_server_uid: u32,
        request_timeout: Duration,
    ) -> Result<Self, SourceDeliveryClientError> {
        Self::new(
            SOURCE_DELIVERY_SOCKET_PATH,
            expected_server_uid,
            request_timeout,
        )
    }

    pub fn new(
        socket_path: impl Into<PathBuf>,
        expected_server_uid: u32,
        request_timeout: Duration,
    ) -> Result<Self, SourceDeliveryClientError> {
        let socket_path = socket_path.into();
        if !is_normalized_absolute_path(&socket_path)
            || expected_server_uid == 0
            || expected_server_uid == u32::MAX
            || request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(SourceDeliveryClientError::InvalidConfig);
        }
        Ok(Self {
            socket_path,
            expected_server_uid,
            request_timeout,
            negotiated: AtomicBool::new(false),
        })
    }

    pub async fn pending(
        &self,
        limit: u8,
    ) -> Result<Vec<SourceOutboxEntryV1>, SourceDeliveryClientError> {
        if !(1..=MAX_PENDING_LIMIT).contains(&limit) {
            return Err(SourceDeliveryClientError::InvalidPendingLimit);
        }
        self.ensure_negotiated().await?;
        match self
            .exchange(SourceDeliveryRequestV1::Pending { limit })
            .await?
        {
            SourceDeliveryResponseV1::Pending { entries }
                if entries.len() <= usize::from(limit)
                    && entries.iter().all(|entry| entry.validate().is_ok()) =>
            {
                Ok(entries)
            }
            SourceDeliveryResponseV1::Rejected { code, retryable } => {
                Err(SourceDeliveryClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    pub async fn acknowledge(
        &self,
        entry: &SourceOutboxEntryV1,
    ) -> Result<(), SourceDeliveryClientError> {
        entry
            .validate()
            .map_err(|_| SourceDeliveryClientError::InvalidAcknowledgement)?;
        self.ensure_negotiated().await?;
        match self
            .exchange(SourceDeliveryRequestV1::Acknowledge {
                outbox_sequence: entry.outbox_sequence,
                attestation_digest: entry.attestation_digest.clone(),
            })
            .await?
        {
            SourceDeliveryResponseV1::Acknowledged => Ok(()),
            SourceDeliveryResponseV1::Rejected { code, retryable } => {
                Err(SourceDeliveryClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    async fn ensure_negotiated(&self) -> Result<(), SourceDeliveryClientError> {
        if self.negotiated.load(Ordering::Acquire) {
            return Ok(());
        }
        match self
            .exchange(SourceDeliveryRequestV1::Negotiate {
                supported_versions: vec![SOURCE_DELIVERY_PROTOCOL_VERSION],
            })
            .await?
        {
            SourceDeliveryResponseV1::Negotiated { selected_version }
                if selected_version == SOURCE_DELIVERY_PROTOCOL_VERSION =>
            {
                self.negotiated.store(true, Ordering::Release);
                Ok(())
            }
            SourceDeliveryResponseV1::Rejected { code, retryable } => {
                Err(SourceDeliveryClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    fn wrong_response<T>(&self) -> Result<T, SourceDeliveryClientError> {
        self.negotiated.store(false, Ordering::Release);
        Err(SourceDeliveryClientError::WrongResponse)
    }

    async fn exchange(
        &self,
        request: SourceDeliveryRequestV1,
    ) -> Result<SourceDeliveryResponseV1, SourceDeliveryClientError> {
        let request_id = Uuid::new_v4();
        let envelope = SourceDeliveryRequestEnvelopeV1 {
            version: SOURCE_DELIVERY_PROTOCOL_VERSION,
            request_id,
            request,
        };
        let response = timeout(self.request_timeout, async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(SourceDeliveryClientError::Io)?;
            let peer = stream
                .peer_cred()
                .map_err(SourceDeliveryClientError::PeerCredentials)?;
            if peer.uid() != self.expected_server_uid {
                return Err(SourceDeliveryClientError::UnauthorizedServer {
                    received: peer.uid(),
                });
            }
            write_frame(&mut stream, &envelope, NORMAL_FRAME_MAX_BYTES).await?;
            stream
                .shutdown()
                .await
                .map_err(SourceDeliveryClientError::Io)?;
            let response: SourceDeliveryResponseEnvelopeV1 =
                read_frame(&mut stream, NORMAL_FRAME_MAX_BYTES).await?;
            let mut trailing = [0_u8; 1];
            if stream
                .read(&mut trailing)
                .await
                .map_err(SourceDeliveryClientError::Io)?
                != 0
            {
                return Err(SourceDeliveryClientError::TrailingResponse);
            }
            Ok::<_, SourceDeliveryClientError>(response)
        })
        .await
        .map_err(|_| SourceDeliveryClientError::DeadlineExceeded)??;
        if response.version != SOURCE_DELIVERY_PROTOCOL_VERSION || response.request_id != request_id
        {
            return self.wrong_response();
        }
        Ok(response.response)
    }
}

#[derive(Clone, Debug)]
pub struct SourceDeliveryServerConfigV1 {
    allowed_uid: u32,
    max_connections: usize,
    request_timeout: Duration,
}

impl SourceDeliveryServerConfigV1 {
    pub fn new(
        allowed_uid: u32,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Result<Self, SourceDeliveryServerConfigError> {
        if allowed_uid == 0 || allowed_uid == u32::MAX {
            return Err(SourceDeliveryServerConfigError::InvalidAllowedUid);
        }
        if !(1..=MAX_CONNECTIONS).contains(&max_connections) {
            return Err(SourceDeliveryServerConfigError::InvalidConnectionLimit);
        }
        if request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(SourceDeliveryServerConfigError::InvalidRequestTimeout);
        }
        Ok(Self {
            allowed_uid,
            max_connections,
            request_timeout,
        })
    }
}

pub async fn serve_source_delivery_connection<H: SourceDeliveryRequestHandlerV1 + 'static>(
    mut stream: UnixStream,
    handler: Arc<H>,
    config: &SourceDeliveryServerConfigV1,
) -> Result<(), SourceDeliverySocketError> {
    let peer = stream
        .peer_cred()
        .map_err(SourceDeliverySocketError::PeerCredentials)?;
    if peer.uid() != config.allowed_uid {
        return Err(SourceDeliverySocketError::UnauthorizedPeer {
            received: peer.uid(),
        });
    }
    let deadline = Instant::now() + config.request_timeout;
    let request = timeout_at(deadline, async {
        let request = read_frame(&mut stream, NORMAL_FRAME_MAX_BYTES).await?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = stream.read(&mut trailing).await.map_err(FrameError::Io)?;
        if trailing_bytes != 0 {
            return Err(SourceDeliverySocketError::Frame(FrameError::TrailingBytes(
                trailing_bytes,
            )));
        }
        Ok::<SourceDeliveryRequestEnvelopeV1, SourceDeliverySocketError>(request)
    })
    .await
    .map_err(|_| SourceDeliverySocketError::DeadlineExceeded)??;
    let mut handler_task = tokio::task::spawn_blocking(move || handler.handle(request));
    let response = if let Ok(result) = timeout_at(deadline, &mut handler_task).await {
        result.map_err(|_| SourceDeliverySocketError::HandlerTask)?
    } else {
        handler_task
            .await
            .map_err(|_| SourceDeliverySocketError::HandlerTask)?;
        return Err(SourceDeliverySocketError::DeadlineExceeded);
    };
    timeout_at(deadline, async {
        write_frame(&mut stream, &response, NORMAL_FRAME_MAX_BYTES).await?;
        stream
            .shutdown()
            .await
            .map_err(SourceDeliverySocketError::Write)?;
        Ok::<(), SourceDeliverySocketError>(())
    })
    .await
    .map_err(|_| SourceDeliverySocketError::DeadlineExceeded)??;
    Ok(())
}

pub async fn serve_source_delivery_until<H, F>(
    listener: UnixListener,
    handler: Arc<H>,
    config: SourceDeliveryServerConfigV1,
    shutdown: F,
) -> Result<(), SourceDeliverySocketError>
where
    H: SourceDeliveryRequestHandlerV1 + 'static,
    F: Future<Output = ()>,
{
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    let serve_result = loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                log_connection_result(result);
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                    ) => {
                        warn!(error = %error, "transient source delivery socket accept failure");
                        continue;
                    }
                    Err(error) => break Err(SourceDeliverySocketError::Accept(error)),
                };
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    warn!("source delivery connection limit reached");
                    continue;
                };
                let handler = Arc::clone(&handler);
                let config = config.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_source_delivery_connection(stream, handler, &config).await
                });
            }
        }
    };
    drop(listener);
    while let Some(result) = tasks.join_next().await {
        log_connection_result(result);
    }
    serve_result
}

fn log_connection_result(
    result: Result<Result<(), SourceDeliverySocketError>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(error = %error, "source delivery connection rejected"),
        Err(error) => warn!(error = %error, "source delivery connection task failed"),
    }
}

pub struct BoundSourceDeliverySocketV1 {
    listener: Option<UnixListener>,
    cleanup: SourceDeliverySocketCleanupGuard,
}

impl BoundSourceDeliverySocketV1 {
    pub fn bind(
        path: &Path,
        required_owner_uid: u32,
        required_group_gid: u32,
    ) -> Result<Self, SourceDeliverySocketError> {
        if !is_normalized_absolute_path(path) {
            return Err(SourceDeliverySocketError::InvalidBindPath);
        }
        let parent = path
            .parent()
            .ok_or(SourceDeliverySocketError::InvalidBindPath)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(SourceDeliverySocketError::BindParent)?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != required_owner_uid
            || parent_metadata.gid() != required_group_gid
            || parent_metadata.permissions().mode() & 0o7777 != 0o2750
            || required_owner_uid == 0
            || required_group_gid == 0
        {
            return Err(SourceDeliverySocketError::UnsafeBindParent);
        }
        reconcile_socket_path(path, required_owner_uid, required_group_gid)?;
        let listener = UnixListener::bind(path).map_err(SourceDeliverySocketError::Bind)?;
        let bound = fs::symlink_metadata(path).map_err(SourceDeliverySocketError::InspectPath)?;
        if !bound.file_type().is_socket()
            || bound.uid() != required_owner_uid
            || bound.gid() != required_group_gid
        {
            return Err(SourceDeliverySocketError::BoundPathNotSocket);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))
            .map_err(SourceDeliverySocketError::SetPermissions)?;
        let protected =
            fs::symlink_metadata(path).map_err(SourceDeliverySocketError::InspectPath)?;
        if !protected.file_type().is_socket()
            || protected.uid() != required_owner_uid
            || protected.gid() != required_group_gid
            || protected.permissions().mode() & 0o777 != 0o660
            || protected.dev() != bound.dev()
            || protected.ino() != bound.ino()
        {
            return Err(SourceDeliverySocketError::BoundPathNotSocket);
        }
        Ok(Self {
            listener: Some(listener),
            cleanup: SourceDeliverySocketCleanupGuard {
                path: path.to_owned(),
                device: protected.dev(),
                inode: protected.ino(),
            },
        })
    }

    pub fn take_listener(&mut self) -> UnixListener {
        self.listener
            .take()
            .expect("bound source delivery listener can only be taken once")
    }

    pub fn path(&self) -> &Path {
        &self.cleanup.path
    }
}

fn reconcile_socket_path(
    path: &Path,
    required_owner_uid: u32,
    required_group_gid: u32,
) -> Result<(), SourceDeliverySocketError> {
    match fs::symlink_metadata(path) {
        Ok(existing) => {
            if !existing.file_type().is_socket()
                || existing.uid() != required_owner_uid
                || existing.gid() != required_group_gid
                || existing.permissions().mode() & 0o777 != 0o660
            {
                return Err(SourceDeliverySocketError::SocketPathExists);
            }
            match StdUnixStream::connect(path) {
                Ok(stream) => {
                    let _ = stream.shutdown(Shutdown::Both);
                    return Err(SourceDeliverySocketError::SocketPathExists);
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(error) => return Err(SourceDeliverySocketError::InspectStaleSocket(error)),
            }
            let rechecked =
                fs::symlink_metadata(path).map_err(SourceDeliverySocketError::InspectPath)?;
            if !rechecked.file_type().is_socket()
                || rechecked.dev() != existing.dev()
                || rechecked.ino() != existing.ino()
            {
                return Err(SourceDeliverySocketError::SocketPathChanged);
            }
            fs::remove_file(path).map_err(SourceDeliverySocketError::RemoveStaleSocket)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(SourceDeliverySocketError::InspectPath(error)),
    }
    Ok(())
}

struct SourceDeliverySocketCleanupGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SourceDeliverySocketCleanupGuard {
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
pub enum SourceDeliveryValidationError {
    #[error("unsupported source delivery protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("source delivery request ID must not be nil")]
    NilRequestId,
    #[error("source delivery version set must contain 1-8 versions")]
    InvalidVersionSet,
    #[error("source delivery pending limit is invalid")]
    InvalidPendingLimit,
    #[error("source delivery acknowledgement is invalid")]
    InvalidAcknowledgement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceDeliveryServerConfigError {
    #[error("source delivery client UID must identify a non-root Unix account")]
    InvalidAllowedUid,
    #[error("source delivery connection limit is outside the supported range")]
    InvalidConnectionLimit,
    #[error("source delivery request timeout is outside the supported range")]
    InvalidRequestTimeout,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceDeliveryClientError {
    #[error("source delivery client configuration is invalid")]
    InvalidConfig,
    #[error("source delivery pending limit is invalid")]
    InvalidPendingLimit,
    #[error("source delivery acknowledgement is invalid")]
    InvalidAcknowledgement,
    #[error("source delivery request deadline elapsed")]
    DeadlineExceeded,
    #[error("source delivery socket I/O failed: {0}")]
    Io(io::Error),
    #[error("source delivery server credentials could not be read: {0}")]
    PeerCredentials(io::Error),
    #[error("source delivery server UID {received} is not authorized")]
    UnauthorizedServer { received: u32 },
    #[error("source delivery frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("source delivery response contains trailing bytes")]
    TrailingResponse,
    #[error("source delivery server returned an unexpected or unbound response")]
    WrongResponse,
    #[error("source delivery request was rejected with {code:?}; retryable={retryable}")]
    Rejected {
        code: SourceDeliveryRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum SourceDeliverySocketError {
    #[error("source delivery bind path is invalid")]
    InvalidBindPath,
    #[error("source delivery socket parent could not be inspected: {0}")]
    BindParent(io::Error),
    #[error("source delivery socket parent is not the required protected setgid directory")]
    UnsafeBindParent,
    #[error("source delivery socket path already exists")]
    SocketPathExists,
    #[error("source delivery stale socket could not be inspected: {0}")]
    InspectStaleSocket(io::Error),
    #[error("source delivery socket path could not be inspected: {0}")]
    InspectPath(io::Error),
    #[error("source delivery socket path changed during reconciliation")]
    SocketPathChanged,
    #[error("source delivery stale socket could not be removed: {0}")]
    RemoveStaleSocket(io::Error),
    #[error("source delivery socket could not be bound: {0}")]
    Bind(io::Error),
    #[error("source delivery bound path is not the required protected socket")]
    BoundPathNotSocket,
    #[error("source delivery socket permissions could not be set: {0}")]
    SetPermissions(io::Error),
    #[error("source delivery peer credentials could not be read: {0}")]
    PeerCredentials(io::Error),
    #[error("source delivery peer UID {received} is not authorized")]
    UnauthorizedPeer { received: u32 },
    #[error("source delivery request deadline elapsed")]
    DeadlineExceeded,
    #[error("source delivery frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("source delivery handler task failed")]
    HandlerTask,
    #[error("source delivery response could not be closed: {0}")]
    Write(io::Error),
    #[error("source delivery connection could not be accepted: {0}")]
    Accept(io::Error),
}
