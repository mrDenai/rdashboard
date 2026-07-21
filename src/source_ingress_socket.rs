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
    domain::ProjectId,
    installed_source::{SOURCE_INGRESS_SOCKET_PATH, SourceWebhookSecretsV1},
    protocol::{FrameError, read_frame, write_frame},
    source::{GithubWebhookAdmissionV1, SourceError},
    unix_time_ms,
};

pub const SOURCE_INGRESS_PROTOCOL_VERSION: u16 = 1;
pub const SOURCE_INGRESS_BODY_MAX_BYTES: usize = 1_048_576;
const SOURCE_INGRESS_ENCODED_BODY_MAX_BYTES: usize = SOURCE_INGRESS_BODY_MAX_BYTES.div_ceil(3) * 4;
pub const SOURCE_INGRESS_FRAME_MAX_BYTES: usize = SOURCE_INGRESS_ENCODED_BODY_MAX_BYTES + 64 * 1024;

const MIN_REQUEST_TIMEOUT_MS: u64 = 100;
const MAX_REQUEST_TIMEOUT_MS: u64 = 10_000;
const MAX_CONNECTIONS: usize = 64;
const MAX_DELIVERY_ID_BYTES: usize = 128;
const GITHUB_SIGNATURE_BYTES: usize = 71;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIngressRequestEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub request: SourceIngressRequestV1,
}

impl SourceIngressRequestEnvelopeV1 {
    fn validate(&self) -> Result<(), SourceIngressValidationError> {
        if self.version != SOURCE_INGRESS_PROTOCOL_VERSION {
            return Err(SourceIngressValidationError::UnsupportedVersion(
                self.version,
            ));
        }
        if self.request_id.is_nil() {
            return Err(SourceIngressValidationError::NilRequestId);
        }
        match &self.request {
            SourceIngressRequestV1::Negotiate { supported_versions }
                if !supported_versions.is_empty() && supported_versions.len() <= 8 =>
            {
                Ok(())
            }
            SourceIngressRequestV1::Negotiate { .. } => {
                Err(SourceIngressValidationError::InvalidVersionSet)
            }
            SourceIngressRequestV1::GithubPush {
                delivery_id,
                signature_header,
                raw_body,
                ..
            } if valid_delivery_id(delivery_id)
                && valid_signature_header(signature_header)
                && !raw_body.is_empty()
                && raw_body.len() <= SOURCE_INGRESS_BODY_MAX_BYTES =>
            {
                Ok(())
            }
            SourceIngressRequestV1::GithubPush { .. } => {
                Err(SourceIngressValidationError::InvalidGithubPush)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceIngressRequestV1 {
    Negotiate {
        supported_versions: Vec<u16>,
    },
    GithubPush {
        project_id: ProjectId,
        delivery_id: String,
        signature_header: String,
        #[serde(with = "canonical_base64url_bytes")]
        raw_body: Vec<u8>,
    },
}

mod canonical_base64url_bytes {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _, ser::Error as _};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        if encoded.len() > super::SOURCE_INGRESS_ENCODED_BODY_MAX_BYTES {
            return Err(S::Error::custom("source ingress body is oversized"));
        }
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() > super::SOURCE_INGRESS_ENCODED_BODY_MAX_BYTES {
            return Err(D::Error::custom("source ingress body is oversized"));
        }
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).map_err(D::Error::custom)?;
        if decoded.len() > super::SOURCE_INGRESS_BODY_MAX_BYTES
            || URL_SAFE_NO_PAD.encode(&decoded) != encoded
        {
            return Err(D::Error::custom(
                "source ingress body is not canonical base64url",
            ));
        }
        Ok(decoded)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIngressResponseEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub response: SourceIngressResponseV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceIngressResponseV1 {
    Negotiated {
        selected_version: u16,
    },
    Accepted {
        admission: GithubWebhookAdmissionV1,
    },
    Rejected {
        code: SourceIngressRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceIngressRejectionCodeV1 {
    UnsupportedProtocolVersion,
    InvalidRequest,
    UnknownProject,
    AuthenticationFailed,
    RepositoryMismatch,
    DeliveryConflict,
    QueueFull,
    SourceUnavailable,
    ClockUnavailable,
}

pub trait GithubWebhookAcceptorV1: Send + Sync {
    fn enqueue_github_push(
        &self,
        project_id: &ProjectId,
        delivery_id: &str,
        signature_header: &str,
        webhook_secret: &[u8],
        raw_body: &[u8],
        received_at_ms: i64,
    ) -> Result<GithubWebhookAdmissionV1, SourceError>;
}

pub trait SourceIngressClockV1: Send + Sync {
    fn now_ms(&self) -> Result<i64, SourceIngressClockError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSourceIngressClockV1;

impl SourceIngressClockV1 for SystemSourceIngressClockV1 {
    fn now_ms(&self) -> Result<i64, SourceIngressClockError> {
        unix_time_ms().map_err(|_| SourceIngressClockError)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("source ingress clock is unavailable")]
pub struct SourceIngressClockError;

pub trait SourceIngressRequestHandlerV1: Send + Sync {
    fn handle(&self, request: SourceIngressRequestEnvelopeV1) -> SourceIngressResponseEnvelopeV1;
}

pub struct BrokerSourceIngressHandlerV1<G, C = SystemSourceIngressClockV1> {
    gateway: G,
    secrets: Arc<SourceWebhookSecretsV1>,
    clock: C,
}

impl<G> BrokerSourceIngressHandlerV1<G, SystemSourceIngressClockV1> {
    pub const fn system(gateway: G, secrets: Arc<SourceWebhookSecretsV1>) -> Self {
        Self {
            gateway,
            secrets,
            clock: SystemSourceIngressClockV1,
        }
    }
}

impl<G, C> BrokerSourceIngressHandlerV1<G, C> {
    pub const fn new(gateway: G, secrets: Arc<SourceWebhookSecretsV1>, clock: C) -> Self {
        Self {
            gateway,
            secrets,
            clock,
        }
    }

    fn response(
        request: &SourceIngressRequestEnvelopeV1,
        response: SourceIngressResponseV1,
    ) -> SourceIngressResponseEnvelopeV1 {
        SourceIngressResponseEnvelopeV1 {
            version: SOURCE_INGRESS_PROTOCOL_VERSION,
            request_id: request.request_id,
            response,
        }
    }

    fn rejected(
        request: &SourceIngressRequestEnvelopeV1,
        code: SourceIngressRejectionCodeV1,
        retryable: bool,
    ) -> SourceIngressResponseEnvelopeV1 {
        Self::response(
            request,
            SourceIngressResponseV1::Rejected { code, retryable },
        )
    }
}

impl<G, C> SourceIngressRequestHandlerV1 for BrokerSourceIngressHandlerV1<G, C>
where
    G: GithubWebhookAcceptorV1,
    C: SourceIngressClockV1,
{
    fn handle(&self, request: SourceIngressRequestEnvelopeV1) -> SourceIngressResponseEnvelopeV1 {
        if let Err(error) = request.validate() {
            let code = if matches!(error, SourceIngressValidationError::UnsupportedVersion(_)) {
                SourceIngressRejectionCodeV1::UnsupportedProtocolVersion
            } else {
                SourceIngressRejectionCodeV1::InvalidRequest
            };
            return Self::rejected(&request, code, false);
        }
        match &request.request {
            SourceIngressRequestV1::Negotiate { supported_versions } => {
                if supported_versions.contains(&SOURCE_INGRESS_PROTOCOL_VERSION) {
                    Self::response(
                        &request,
                        SourceIngressResponseV1::Negotiated {
                            selected_version: SOURCE_INGRESS_PROTOCOL_VERSION,
                        },
                    )
                } else {
                    Self::rejected(
                        &request,
                        SourceIngressRejectionCodeV1::UnsupportedProtocolVersion,
                        false,
                    )
                }
            }
            SourceIngressRequestV1::GithubPush {
                project_id,
                delivery_id,
                signature_header,
                raw_body,
            } => {
                let Some(secret) = self.secrets.secret(project_id) else {
                    return Self::rejected(
                        &request,
                        SourceIngressRejectionCodeV1::UnknownProject,
                        false,
                    );
                };
                let received_at_ms = match self.clock.now_ms() {
                    Ok(now_ms) if now_ms >= 0 => now_ms,
                    _ => {
                        return Self::rejected(
                            &request,
                            SourceIngressRejectionCodeV1::ClockUnavailable,
                            true,
                        );
                    }
                };
                match self.gateway.enqueue_github_push(
                    project_id,
                    delivery_id,
                    signature_header,
                    secret,
                    raw_body,
                    received_at_ms,
                ) {
                    Ok(admission) => {
                        Self::response(&request, SourceIngressResponseV1::Accepted { admission })
                    }
                    Err(error) => source_rejection(&request, &error),
                }
            }
        }
    }
}

fn source_rejection(
    request: &SourceIngressRequestEnvelopeV1,
    error: &SourceError,
) -> SourceIngressResponseEnvelopeV1 {
    let (code, retryable) = match error {
        SourceError::UnknownProject(_) => (SourceIngressRejectionCodeV1::UnknownProject, false),
        SourceError::InvalidWebhookSignature | SourceError::WebhookSecretTooShort => {
            (SourceIngressRejectionCodeV1::AuthenticationFailed, false)
        }
        SourceError::GithubRepositoryMismatch => {
            (SourceIngressRejectionCodeV1::RepositoryMismatch, false)
        }
        SourceError::DeliveryConflict => (SourceIngressRejectionCodeV1::DeliveryConflict, false),
        SourceError::WebhookQueueFull => (SourceIngressRejectionCodeV1::QueueFull, true),
        SourceError::InvalidDeliveryId
        | SourceError::WebhookBodyTooLarge
        | SourceError::InvalidWebhookPayload => {
            (SourceIngressRejectionCodeV1::InvalidRequest, false)
        }
        _ => (SourceIngressRejectionCodeV1::SourceUnavailable, true),
    };
    BrokerSourceIngressHandlerV1::<(), ()>::rejected(request, code, retryable)
}

#[derive(Debug)]
pub struct SourceIngressClientV1 {
    socket_path: PathBuf,
    expected_server_uid: u32,
    request_timeout: Duration,
    negotiated: AtomicBool,
}

impl SourceIngressClientV1 {
    pub fn installed(
        expected_server_uid: u32,
        request_timeout: Duration,
    ) -> Result<Self, SourceIngressClientError> {
        Self::new(
            SOURCE_INGRESS_SOCKET_PATH,
            expected_server_uid,
            request_timeout,
        )
    }

    pub fn new(
        socket_path: impl Into<PathBuf>,
        expected_server_uid: u32,
        request_timeout: Duration,
    ) -> Result<Self, SourceIngressClientError> {
        let socket_path = socket_path.into();
        if !is_normalized_absolute_path(&socket_path)
            || expected_server_uid == 0
            || expected_server_uid == u32::MAX
            || request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(SourceIngressClientError::InvalidConfig);
        }
        Ok(Self {
            socket_path,
            expected_server_uid,
            request_timeout,
            negotiated: AtomicBool::new(false),
        })
    }

    pub async fn github_push(
        &self,
        project_id: ProjectId,
        delivery_id: String,
        signature_header: String,
        raw_body: Vec<u8>,
    ) -> Result<GithubWebhookAdmissionV1, SourceIngressClientError> {
        let validated = SourceIngressRequestEnvelopeV1 {
            version: SOURCE_INGRESS_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            request: SourceIngressRequestV1::GithubPush {
                project_id,
                delivery_id,
                signature_header,
                raw_body,
            },
        };
        validated
            .validate()
            .map_err(|_| SourceIngressClientError::InvalidRequest)?;
        self.ensure_negotiated().await?;
        match self.exchange(validated.request).await? {
            SourceIngressResponseV1::Accepted { admission } => Ok(admission),
            SourceIngressResponseV1::Rejected { code, retryable } => {
                Err(SourceIngressClientError::Rejected { code, retryable })
            }
            SourceIngressResponseV1::Negotiated { .. } => self.wrong_response(),
        }
    }

    async fn ensure_negotiated(&self) -> Result<(), SourceIngressClientError> {
        if self.negotiated.load(Ordering::Acquire) {
            return Ok(());
        }
        match self
            .exchange(SourceIngressRequestV1::Negotiate {
                supported_versions: vec![SOURCE_INGRESS_PROTOCOL_VERSION],
            })
            .await?
        {
            SourceIngressResponseV1::Negotiated { selected_version }
                if selected_version == SOURCE_INGRESS_PROTOCOL_VERSION =>
            {
                self.negotiated.store(true, Ordering::Release);
                Ok(())
            }
            SourceIngressResponseV1::Rejected { code, retryable } => {
                Err(SourceIngressClientError::Rejected { code, retryable })
            }
            _ => self.wrong_response(),
        }
    }

    async fn exchange(
        &self,
        request: SourceIngressRequestV1,
    ) -> Result<SourceIngressResponseV1, SourceIngressClientError> {
        let request_id = Uuid::new_v4();
        let envelope = SourceIngressRequestEnvelopeV1 {
            version: SOURCE_INGRESS_PROTOCOL_VERSION,
            request_id,
            request,
        };
        let response = timeout(self.request_timeout, async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(SourceIngressClientError::Io)?;
            let peer = stream
                .peer_cred()
                .map_err(SourceIngressClientError::PeerCredentials)?;
            if peer.uid() != self.expected_server_uid {
                return Err(SourceIngressClientError::UnauthorizedServer {
                    received: peer.uid(),
                });
            }
            write_frame(&mut stream, &envelope, SOURCE_INGRESS_FRAME_MAX_BYTES).await?;
            stream
                .shutdown()
                .await
                .map_err(SourceIngressClientError::Io)?;
            let response: SourceIngressResponseEnvelopeV1 =
                read_frame(&mut stream, SOURCE_INGRESS_FRAME_MAX_BYTES).await?;
            let mut trailing = [0_u8; 1];
            if stream
                .read(&mut trailing)
                .await
                .map_err(SourceIngressClientError::Io)?
                != 0
            {
                return Err(SourceIngressClientError::TrailingResponse);
            }
            Ok::<_, SourceIngressClientError>(response)
        })
        .await
        .map_err(|_| SourceIngressClientError::DeadlineExceeded)??;
        if response.version != SOURCE_INGRESS_PROTOCOL_VERSION || response.request_id != request_id
        {
            return self.wrong_response();
        }
        Ok(response.response)
    }

    fn wrong_response<T>(&self) -> Result<T, SourceIngressClientError> {
        self.negotiated.store(false, Ordering::Release);
        Err(SourceIngressClientError::WrongResponse)
    }
}

#[derive(Clone, Debug)]
pub struct SourceIngressServerConfigV1 {
    allowed_uid: u32,
    max_connections: usize,
    request_timeout: Duration,
}

impl SourceIngressServerConfigV1 {
    pub fn new(
        allowed_uid: u32,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Result<Self, SourceIngressServerConfigError> {
        if allowed_uid == 0 || allowed_uid == u32::MAX {
            return Err(SourceIngressServerConfigError::InvalidAllowedUid);
        }
        if !(1..=MAX_CONNECTIONS).contains(&max_connections) {
            return Err(SourceIngressServerConfigError::InvalidConnectionLimit);
        }
        if request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(SourceIngressServerConfigError::InvalidRequestTimeout);
        }
        Ok(Self {
            allowed_uid,
            max_connections,
            request_timeout,
        })
    }
}

pub async fn serve_source_ingress_connection<H: SourceIngressRequestHandlerV1 + 'static>(
    mut stream: UnixStream,
    handler: Arc<H>,
    config: &SourceIngressServerConfigV1,
) -> Result<(), SourceIngressSocketError> {
    let peer = stream
        .peer_cred()
        .map_err(SourceIngressSocketError::PeerCredentials)?;
    if peer.uid() != config.allowed_uid {
        return Err(SourceIngressSocketError::UnauthorizedPeer {
            received: peer.uid(),
        });
    }
    let deadline = Instant::now() + config.request_timeout;
    let request = timeout_at(deadline, async {
        let request = read_frame(&mut stream, SOURCE_INGRESS_FRAME_MAX_BYTES).await?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = stream.read(&mut trailing).await.map_err(FrameError::Io)?;
        if trailing_bytes != 0 {
            return Err(SourceIngressSocketError::Frame(FrameError::TrailingBytes(
                trailing_bytes,
            )));
        }
        Ok::<SourceIngressRequestEnvelopeV1, SourceIngressSocketError>(request)
    })
    .await
    .map_err(|_| SourceIngressSocketError::DeadlineExceeded)??;
    let mut handler_task = tokio::task::spawn_blocking(move || handler.handle(request));
    let response = if let Ok(result) = timeout_at(deadline, &mut handler_task).await {
        result.map_err(|_| SourceIngressSocketError::HandlerTask)?
    } else {
        handler_task
            .await
            .map_err(|_| SourceIngressSocketError::HandlerTask)?;
        return Err(SourceIngressSocketError::DeadlineExceeded);
    };
    timeout_at(deadline, async {
        write_frame(&mut stream, &response, SOURCE_INGRESS_FRAME_MAX_BYTES).await?;
        stream
            .shutdown()
            .await
            .map_err(SourceIngressSocketError::Write)?;
        Ok::<(), SourceIngressSocketError>(())
    })
    .await
    .map_err(|_| SourceIngressSocketError::DeadlineExceeded)??;
    Ok(())
}

pub async fn serve_source_ingress_until<H, F>(
    listener: UnixListener,
    handler: Arc<H>,
    config: SourceIngressServerConfigV1,
    shutdown: F,
) -> Result<(), SourceIngressSocketError>
where
    H: SourceIngressRequestHandlerV1 + 'static,
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
                        warn!(error = %error, "transient source ingress socket accept failure");
                        continue;
                    }
                    Err(error) => break Err(SourceIngressSocketError::Accept(error)),
                };
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    warn!("source ingress connection limit reached");
                    continue;
                };
                let handler = Arc::clone(&handler);
                let config = config.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_source_ingress_connection(stream, handler, &config).await
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
    result: Result<Result<(), SourceIngressSocketError>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(error = %error, "source ingress connection rejected"),
        Err(error) => warn!(error = %error, "source ingress connection task failed"),
    }
}

pub struct BoundSourceIngressSocketV1 {
    listener: Option<UnixListener>,
    cleanup: SourceIngressSocketCleanupGuard,
}

impl BoundSourceIngressSocketV1 {
    pub fn bind(
        path: &Path,
        required_owner_uid: u32,
        required_group_gid: u32,
    ) -> Result<Self, SourceIngressSocketError> {
        if !is_normalized_absolute_path(path) {
            return Err(SourceIngressSocketError::InvalidBindPath);
        }
        let parent = path
            .parent()
            .ok_or(SourceIngressSocketError::InvalidBindPath)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(SourceIngressSocketError::BindParent)?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != required_owner_uid
            || parent_metadata.gid() != required_group_gid
            || parent_metadata.permissions().mode() & 0o7777 != 0o2750
            || required_owner_uid == 0
            || required_group_gid == 0
        {
            return Err(SourceIngressSocketError::UnsafeBindParent);
        }
        reconcile_socket_path(path, required_owner_uid, required_group_gid)?;
        let listener = UnixListener::bind(path).map_err(SourceIngressSocketError::Bind)?;
        let bound = fs::symlink_metadata(path).map_err(SourceIngressSocketError::InspectPath)?;
        if !bound.file_type().is_socket()
            || bound.uid() != required_owner_uid
            || bound.gid() != required_group_gid
        {
            return Err(SourceIngressSocketError::BoundPathNotSocket);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))
            .map_err(SourceIngressSocketError::SetPermissions)?;
        let protected =
            fs::symlink_metadata(path).map_err(SourceIngressSocketError::InspectPath)?;
        if !protected.file_type().is_socket()
            || protected.uid() != required_owner_uid
            || protected.gid() != required_group_gid
            || protected.permissions().mode() & 0o777 != 0o660
            || protected.dev() != bound.dev()
            || protected.ino() != bound.ino()
        {
            return Err(SourceIngressSocketError::BoundPathNotSocket);
        }
        Ok(Self {
            listener: Some(listener),
            cleanup: SourceIngressSocketCleanupGuard {
                path: path.to_owned(),
                device: protected.dev(),
                inode: protected.ino(),
            },
        })
    }

    pub fn take_listener(&mut self) -> UnixListener {
        self.listener
            .take()
            .expect("bound source ingress listener can only be taken once")
    }

    pub fn path(&self) -> &Path {
        &self.cleanup.path
    }
}

fn reconcile_socket_path(
    path: &Path,
    required_owner_uid: u32,
    required_group_gid: u32,
) -> Result<(), SourceIngressSocketError> {
    match fs::symlink_metadata(path) {
        Ok(existing) => {
            if !existing.file_type().is_socket()
                || existing.uid() != required_owner_uid
                || existing.gid() != required_group_gid
                || existing.permissions().mode() & 0o777 != 0o660
            {
                return Err(SourceIngressSocketError::SocketPathExists);
            }
            match StdUnixStream::connect(path) {
                Ok(stream) => {
                    let _ = stream.shutdown(Shutdown::Both);
                    return Err(SourceIngressSocketError::SocketPathExists);
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(error) => return Err(SourceIngressSocketError::InspectStaleSocket(error)),
            }
            let rechecked =
                fs::symlink_metadata(path).map_err(SourceIngressSocketError::InspectPath)?;
            if !rechecked.file_type().is_socket()
                || rechecked.dev() != existing.dev()
                || rechecked.ino() != existing.ino()
            {
                return Err(SourceIngressSocketError::SocketPathChanged);
            }
            fs::remove_file(path).map_err(SourceIngressSocketError::RemoveStaleSocket)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(SourceIngressSocketError::InspectPath(error)),
    }
    Ok(())
}

struct SourceIngressSocketCleanupGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SourceIngressSocketCleanupGuard {
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

fn valid_delivery_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DELIVERY_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_signature_header(value: &str) -> bool {
    value.len() == GITHUB_SIGNATURE_BYTES
        && value.starts_with("sha256=")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
pub enum SourceIngressValidationError {
    #[error("unsupported source ingress protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("source ingress request ID must not be nil")]
    NilRequestId,
    #[error("source ingress version set must contain 1-8 versions")]
    InvalidVersionSet,
    #[error("source ingress GitHub push request is invalid")]
    InvalidGithubPush,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceIngressServerConfigError {
    #[error("source ingress client UID must identify a non-root Unix account")]
    InvalidAllowedUid,
    #[error("source ingress connection limit is outside the supported range")]
    InvalidConnectionLimit,
    #[error("source ingress request timeout is outside the supported range")]
    InvalidRequestTimeout,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceIngressClientError {
    #[error("source ingress client configuration is invalid")]
    InvalidConfig,
    #[error("source ingress request is invalid")]
    InvalidRequest,
    #[error("source ingress request deadline elapsed")]
    DeadlineExceeded,
    #[error("source ingress socket I/O failed: {0}")]
    Io(io::Error),
    #[error("source ingress server credentials could not be read: {0}")]
    PeerCredentials(io::Error),
    #[error("source ingress server UID {received} is not authorized")]
    UnauthorizedServer { received: u32 },
    #[error("source ingress frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("source ingress response contains trailing bytes")]
    TrailingResponse,
    #[error("source ingress server returned an unexpected or unbound response")]
    WrongResponse,
    #[error("source ingress request was rejected with {code:?}; retryable={retryable}")]
    Rejected {
        code: SourceIngressRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum SourceIngressSocketError {
    #[error("source ingress bind path is invalid")]
    InvalidBindPath,
    #[error("source ingress socket parent could not be inspected: {0}")]
    BindParent(io::Error),
    #[error("source ingress socket parent is not the required protected setgid directory")]
    UnsafeBindParent,
    #[error("source ingress socket path already exists")]
    SocketPathExists,
    #[error("source ingress stale socket could not be inspected: {0}")]
    InspectStaleSocket(io::Error),
    #[error("source ingress socket path could not be inspected: {0}")]
    InspectPath(io::Error),
    #[error("source ingress socket path changed during reconciliation")]
    SocketPathChanged,
    #[error("source ingress stale socket could not be removed: {0}")]
    RemoveStaleSocket(io::Error),
    #[error("source ingress socket could not be bound: {0}")]
    Bind(io::Error),
    #[error("source ingress bound path is not the required protected socket")]
    BoundPathNotSocket,
    #[error("source ingress socket permissions could not be set: {0}")]
    SetPermissions(io::Error),
    #[error("source ingress peer credentials could not be read: {0}")]
    PeerCredentials(io::Error),
    #[error("source ingress peer UID {received} is not authorized")]
    UnauthorizedPeer { received: u32 },
    #[error("source ingress request deadline elapsed")]
    DeadlineExceeded,
    #[error("source ingress frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("source ingress handler task failed")]
    HandlerTask,
    #[error("source ingress response could not be closed: {0}")]
    Write(io::Error),
    #[error("source ingress connection could not be accepted: {0}")]
    Accept(io::Error),
}
