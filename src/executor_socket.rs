use std::{
    fs,
    future::Future,
    io,
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use schemars::JsonSchema;
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
    domain::HostTelemetry,
    executor_authority::{RootExecutorAuthorityConfigV1, RootExecutorAuthorityV1},
    metrics::HostCollector,
    mutation_admission::{
        ExecuteMutationGrantV1, MutationAcceptanceV1, MutationControlV1, ObserveMutationStatusV1,
        PrepareMutationIntentV1,
    },
    protocol::{
        CONTROL_PROTOCOL_VERSION, ControlRejectionCodeV1, ControlRequestEnvelope, ControlRequestV1,
        ControlResponseEnvelope, ControlResponseV1, FrameError, NORMAL_FRAME_MAX_BYTES,
        OBSERVATION_FRAME_MAX_BYTES, ProtocolValidationError, read_frame, write_frame,
    },
    unix_time_ms,
};

pub const ROOT_EXECUTOR_CONFIG_SCHEMA_VERSION: u16 = 1;
pub const ROOT_EXECUTOR_CONFIG_PATH: &str = "/etc/rdashboard/executor.json";
pub const ROOT_EXECUTOR_SOCKET_PATH: &str = "/run/rdashboard/executor.sock";

const MIN_REQUEST_TIMEOUT_MS: u64 = 100;
const MAX_REQUEST_TIMEOUT_MS: u64 = 30_000;
const MAX_CONNECTIONS: u16 = 128;

#[derive(Debug)]
pub struct RootExecutorClient {
    socket_path: PathBuf,
    request_timeout: Duration,
    negotiated: AtomicBool,
}

impl RootExecutorClient {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        request_timeout: Duration,
    ) -> Result<Self, ExecutorClientError> {
        let socket_path = socket_path.into();
        if !is_normalized_absolute_path(&socket_path) {
            return Err(ExecutorClientError::InvalidSocketPath);
        }
        if request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(ExecutorClientError::InvalidRequestTimeout);
        }
        Ok(Self {
            socket_path,
            request_timeout,
            negotiated: AtomicBool::new(false),
        })
    }

    pub async fn observe_host(&self) -> Result<HostTelemetry, ExecutorClientError> {
        self.ensure_negotiated().await?;
        let response = self.exchange(ControlRequestV1::ObserveHostSnapshot).await?;
        match response {
            ControlResponseV1::HostSnapshot { snapshot } => Ok(*snapshot),
            ControlResponseV1::Rejected { code, retryable } => {
                Err(ExecutorClientError::Rejected { code, retryable })
            }
            ControlResponseV1::Negotiated { .. }
            | ControlResponseV1::OperationIntentPrepared { .. }
            | ControlResponseV1::OperationAccepted { .. }
            | ControlResponseV1::MutationStatus { .. } => {
                self.negotiated.store(false, Ordering::Release);
                Err(ExecutorClientError::UnexpectedResponse)
            }
        }
    }

    pub async fn prepare_operation_intent(
        &self,
        input: PrepareMutationIntentV1,
    ) -> Result<String, ExecutorClientError> {
        self.ensure_negotiated().await?;
        let response = self
            .exchange(ControlRequestV1::PrepareOperationIntent {
                project_id: input.project_id,
                operation_kind: input.operation_kind,
                target_commit: input.target_commit,
                release_class: input.proposed_release_class,
                idempotency_key: input.idempotency_key,
            })
            .await?;
        match response {
            ControlResponseV1::OperationIntentPrepared { signed_intent } => Ok(signed_intent),
            ControlResponseV1::Rejected { code, retryable } => {
                Err(ExecutorClientError::Rejected { code, retryable })
            }
            ControlResponseV1::Negotiated { .. }
            | ControlResponseV1::HostSnapshot { .. }
            | ControlResponseV1::OperationAccepted { .. }
            | ControlResponseV1::MutationStatus { .. } => {
                self.negotiated.store(false, Ordering::Release);
                Err(ExecutorClientError::UnexpectedResponse)
            }
        }
    }

    pub async fn execute_granted_operation(
        &self,
        input: ExecuteMutationGrantV1,
    ) -> Result<MutationAcceptanceV1, ExecutorClientError> {
        self.ensure_negotiated().await?;
        let response = self
            .exchange(ControlRequestV1::ExecuteGrantedOperation {
                intent_id: input.intent_id,
                attempt_id: input.attempt_id,
                action_grant: input.action_grant,
            })
            .await?;
        match response {
            ControlResponseV1::OperationAccepted {
                intent_id,
                attempt_id,
                replayed,
            } if intent_id == input.intent_id && attempt_id == input.attempt_id => {
                Ok(MutationAcceptanceV1 {
                    intent_id,
                    attempt_id,
                    replayed,
                })
            }
            ControlResponseV1::Rejected { code, retryable } => {
                Err(ExecutorClientError::Rejected { code, retryable })
            }
            ControlResponseV1::Negotiated { .. }
            | ControlResponseV1::HostSnapshot { .. }
            | ControlResponseV1::OperationIntentPrepared { .. }
            | ControlResponseV1::OperationAccepted { .. }
            | ControlResponseV1::MutationStatus { .. } => {
                self.negotiated.store(false, Ordering::Release);
                Err(ExecutorClientError::UnexpectedResponse)
            }
        }
    }

    pub async fn mutation_status(
        &self,
        input: ObserveMutationStatusV1,
    ) -> Result<crate::domain::MutationStatusV1, ExecutorClientError> {
        self.ensure_negotiated().await?;
        let response = self
            .exchange(ControlRequestV1::ObserveMutationStatus {
                intent_id: input.intent_id,
                attempt_id: input.attempt_id,
            })
            .await?;
        match response {
            ControlResponseV1::MutationStatus { status }
                if status.intent_id == input.intent_id && status.attempt_id == input.attempt_id =>
            {
                Ok(*status)
            }
            ControlResponseV1::Rejected { code, retryable } => {
                Err(ExecutorClientError::Rejected { code, retryable })
            }
            ControlResponseV1::Negotiated { .. }
            | ControlResponseV1::HostSnapshot { .. }
            | ControlResponseV1::OperationIntentPrepared { .. }
            | ControlResponseV1::OperationAccepted { .. }
            | ControlResponseV1::MutationStatus { .. } => {
                self.negotiated.store(false, Ordering::Release);
                Err(ExecutorClientError::UnexpectedResponse)
            }
        }
    }

    async fn ensure_negotiated(&self) -> Result<(), ExecutorClientError> {
        if self.negotiated.load(Ordering::Acquire) {
            return Ok(());
        }
        let response = self
            .exchange(ControlRequestV1::Negotiate {
                supported_versions: vec![CONTROL_PROTOCOL_VERSION],
            })
            .await?;
        match response {
            ControlResponseV1::Negotiated { selected_version }
                if selected_version == CONTROL_PROTOCOL_VERSION =>
            {
                self.negotiated.store(true, Ordering::Release);
                Ok(())
            }
            ControlResponseV1::Rejected { code, retryable } => {
                Err(ExecutorClientError::Rejected { code, retryable })
            }
            ControlResponseV1::Negotiated { .. }
            | ControlResponseV1::HostSnapshot { .. }
            | ControlResponseV1::OperationIntentPrepared { .. }
            | ControlResponseV1::OperationAccepted { .. }
            | ControlResponseV1::MutationStatus { .. } => {
                Err(ExecutorClientError::UnexpectedResponse)
            }
        }
    }

    async fn exchange(
        &self,
        request: ControlRequestV1,
    ) -> Result<ControlResponseV1, ExecutorClientError> {
        let request_id = Uuid::new_v4();
        let envelope = ControlRequestEnvelope {
            version: CONTROL_PROTOCOL_VERSION,
            request_id,
            request,
        };
        let result = timeout(self.request_timeout, async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(ExecutorClientError::Connect)?;
            write_frame(&mut stream, &envelope, NORMAL_FRAME_MAX_BYTES).await?;
            stream.shutdown().await.map_err(FrameError::Io)?;
            let response: ControlResponseEnvelope<ControlResponseV1> =
                read_frame(&mut stream, OBSERVATION_FRAME_MAX_BYTES).await?;
            Ok::<_, ExecutorClientError>(response)
        })
        .await
        .map_err(|_| ExecutorClientError::DeadlineExceeded)??;
        if result.version != CONTROL_PROTOCOL_VERSION || result.request_id != request_id {
            self.negotiated.store(false, Ordering::Release);
            return Err(ExecutorClientError::ResponseBindingMismatch);
        }
        Ok(result.response)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootExecutorConfigV1 {
    pub schema_version: u16,
    pub controller_uid: u32,
    pub socket_path: PathBuf,
    pub metrics_disk_path: PathBuf,
    pub max_connections: u16,
    pub request_timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_authority: Option<RootExecutorAuthorityConfigV1>,
}

impl RootExecutorConfigV1 {
    pub fn validate(&self) -> Result<(), ExecutorConfigError> {
        if self.schema_version != ROOT_EXECUTOR_CONFIG_SCHEMA_VERSION {
            return Err(ExecutorConfigError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.controller_uid == 0 || self.controller_uid == u32::MAX {
            return Err(ExecutorConfigError::InvalidControllerUid);
        }
        if self.socket_path != Path::new(ROOT_EXECUTOR_SOCKET_PATH) {
            return Err(ExecutorConfigError::InvalidSocketPath);
        }
        if !is_normalized_absolute_path(&self.metrics_disk_path) {
            return Err(ExecutorConfigError::InvalidMetricsDiskPath);
        }
        if !(1..=MAX_CONNECTIONS).contains(&self.max_connections) {
            return Err(ExecutorConfigError::InvalidConnectionLimit);
        }
        if !(MIN_REQUEST_TIMEOUT_MS..=MAX_REQUEST_TIMEOUT_MS).contains(&self.request_timeout_ms) {
            return Err(ExecutorConfigError::InvalidRequestTimeout);
        }
        if self
            .mutation_authority
            .as_ref()
            .is_some_and(|authority| authority.validate().is_err())
        {
            return Err(ExecutorConfigError::InvalidMutationAuthority);
        }
        Ok(())
    }

    pub fn server_config(&self) -> Result<ExecutorServerConfig, ExecutorConfigError> {
        self.validate()?;
        ExecutorServerConfig::new(
            self.controller_uid,
            usize::from(self.max_connections),
            Duration::from_millis(self.request_timeout_ms),
        )
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

#[derive(Clone, Debug)]
pub struct ExecutorServerConfig {
    allowed_uid: u32,
    max_connections: usize,
    request_timeout: Duration,
}

impl ExecutorServerConfig {
    pub fn new(
        allowed_uid: u32,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Result<Self, ExecutorConfigError> {
        if !(1..=usize::from(MAX_CONNECTIONS)).contains(&max_connections) {
            return Err(ExecutorConfigError::InvalidConnectionLimit);
        }
        if request_timeout < Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
            || request_timeout > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
        {
            return Err(ExecutorConfigError::InvalidRequestTimeout);
        }
        Ok(Self {
            allowed_uid,
            max_connections,
            request_timeout,
        })
    }
}

pub trait ControlRequestHandler: Send + Sync {
    fn handle(&self, request: ControlRequestEnvelope)
    -> ControlResponseEnvelope<ControlResponseV1>;
}

#[derive(Debug)]
pub struct ReadOnlyExecutorHandler {
    host_collector: Mutex<HostCollector>,
    mutation_authority: Option<RootExecutorAuthorityV1>,
    mutation_control: Option<Arc<dyn MutationControlV1>>,
}

impl ReadOnlyExecutorHandler {
    pub fn linux(metrics_disk_path: impl Into<PathBuf>) -> Self {
        Self {
            host_collector: Mutex::new(HostCollector::linux(metrics_disk_path)),
            mutation_authority: None,
            mutation_control: None,
        }
    }

    pub fn linux_with_mutation_authority(
        metrics_disk_path: impl Into<PathBuf>,
        mutation_authority: RootExecutorAuthorityV1,
    ) -> Self {
        Self {
            host_collector: Mutex::new(HostCollector::linux(metrics_disk_path)),
            mutation_authority: Some(mutation_authority),
            mutation_control: None,
        }
    }

    pub fn linux_with_mutation_control(
        metrics_disk_path: impl Into<PathBuf>,
        mutation_control: Arc<dyn MutationControlV1>,
    ) -> Self {
        Self {
            host_collector: Mutex::new(HostCollector::linux(metrics_disk_path)),
            mutation_authority: None,
            mutation_control: Some(mutation_control),
        }
    }

    pub const fn mutation_authority_loaded(&self) -> bool {
        self.mutation_authority.is_some() || self.mutation_control.is_some()
    }

    pub const fn mutation_enabled(&self) -> bool {
        self.mutation_control.is_some()
    }

    fn response(
        request: &ControlRequestEnvelope,
        response: ControlResponseV1,
    ) -> ControlResponseEnvelope<ControlResponseV1> {
        ControlResponseEnvelope {
            version: CONTROL_PROTOCOL_VERSION,
            request_id: request.request_id,
            response,
        }
    }

    fn rejected(
        request: &ControlRequestEnvelope,
        code: ControlRejectionCodeV1,
        retryable: bool,
    ) -> ControlResponseEnvelope<ControlResponseV1> {
        Self::response(request, ControlResponseV1::Rejected { code, retryable })
    }

    fn prepare_operation_intent(
        &self,
        envelope: &ControlRequestEnvelope,
        request: &PrepareMutationIntentV1,
    ) -> ControlResponseEnvelope<ControlResponseV1> {
        let Some(control) = self.mutation_control.as_ref() else {
            return Self::rejected(
                envelope,
                ControlRejectionCodeV1::MutationAuthorityUnavailable,
                false,
            );
        };
        let Ok(now_ms) = unix_time_ms() else {
            return Self::rejected(envelope, ControlRejectionCodeV1::InternalFailure, true);
        };
        match control.prepare_intent(request, now_ms) {
            Ok(signed_intent) => Self::response(
                envelope,
                ControlResponseV1::OperationIntentPrepared { signed_intent },
            ),
            Err(failure) => Self::rejected(envelope, failure.code, failure.retryable),
        }
    }

    fn execute_granted_operation(
        &self,
        envelope: &ControlRequestEnvelope,
        request: &ExecuteMutationGrantV1,
    ) -> ControlResponseEnvelope<ControlResponseV1> {
        let Some(control) = self.mutation_control.as_ref() else {
            return Self::rejected(
                envelope,
                ControlRejectionCodeV1::MutationAuthorityUnavailable,
                false,
            );
        };
        let Ok(now_ms) = unix_time_ms() else {
            return Self::rejected(envelope, ControlRejectionCodeV1::InternalFailure, true);
        };
        match control.accept_grant(request, now_ms) {
            Ok(acceptance) => Self::response(
                envelope,
                ControlResponseV1::OperationAccepted {
                    intent_id: acceptance.intent_id,
                    attempt_id: acceptance.attempt_id,
                    replayed: acceptance.replayed,
                },
            ),
            Err(failure) => Self::rejected(envelope, failure.code, failure.retryable),
        }
    }

    fn observe_mutation_status(
        &self,
        envelope: &ControlRequestEnvelope,
        request: &ObserveMutationStatusV1,
    ) -> ControlResponseEnvelope<ControlResponseV1> {
        let Some(control) = self.mutation_control.as_ref() else {
            return Self::rejected(
                envelope,
                ControlRejectionCodeV1::MutationAuthorityUnavailable,
                false,
            );
        };
        match control.mutation_status(request) {
            Ok(status) => Self::response(
                envelope,
                ControlResponseV1::MutationStatus {
                    status: Box::new(status),
                },
            ),
            Err(failure) => Self::rejected(envelope, failure.code, failure.retryable),
        }
    }
}

impl ControlRequestHandler for ReadOnlyExecutorHandler {
    fn handle(
        &self,
        request: ControlRequestEnvelope,
    ) -> ControlResponseEnvelope<ControlResponseV1> {
        if let Err(error) = request.validate() {
            let code = if matches!(error, ProtocolValidationError::UnsupportedVersion(_)) {
                ControlRejectionCodeV1::UnsupportedProtocolVersion
            } else {
                ControlRejectionCodeV1::InvalidRequest
            };
            return Self::rejected(&request, code, false);
        }

        match &request.request {
            ControlRequestV1::Negotiate { supported_versions } => {
                if supported_versions.contains(&CONTROL_PROTOCOL_VERSION) {
                    Self::response(
                        &request,
                        ControlResponseV1::Negotiated {
                            selected_version: CONTROL_PROTOCOL_VERSION,
                        },
                    )
                } else {
                    Self::rejected(
                        &request,
                        ControlRejectionCodeV1::UnsupportedProtocolVersion,
                        false,
                    )
                }
            }
            ControlRequestV1::ObserveHostSnapshot => {
                let Ok(mut collector) = self.host_collector.lock() else {
                    return Self::rejected(&request, ControlRejectionCodeV1::InternalFailure, true);
                };
                let Ok(observed_at_ms) = unix_time_ms() else {
                    return Self::rejected(&request, ControlRejectionCodeV1::InternalFailure, true);
                };
                let snapshot = collector.collect(observed_at_ms);
                Self::response(
                    &request,
                    ControlResponseV1::HostSnapshot {
                        snapshot: Box::new(snapshot),
                    },
                )
            }
            ControlRequestV1::ObserveDockerSnapshot { .. }
            | ControlRequestV1::ObserveSystemdUnits { .. } => Self::rejected(
                &request,
                ControlRejectionCodeV1::ProjectObservationNotConfigured,
                false,
            ),
            ControlRequestV1::PrepareOperationIntent {
                project_id,
                operation_kind,
                target_commit,
                release_class,
                idempotency_key,
            } => self.prepare_operation_intent(
                &request,
                &PrepareMutationIntentV1 {
                    project_id: project_id.clone(),
                    operation_kind: *operation_kind,
                    target_commit: target_commit.clone(),
                    proposed_release_class: *release_class,
                    idempotency_key: *idempotency_key,
                },
            ),
            ControlRequestV1::ExecuteGrantedOperation {
                intent_id,
                attempt_id,
                action_grant,
            } => self.execute_granted_operation(
                &request,
                &ExecuteMutationGrantV1 {
                    intent_id: *intent_id,
                    attempt_id: *attempt_id,
                    action_grant: action_grant.clone(),
                },
            ),
            ControlRequestV1::ObserveMutationStatus {
                intent_id,
                attempt_id,
            } => self.observe_mutation_status(
                &request,
                &ObserveMutationStatusV1 {
                    intent_id: *intent_id,
                    attempt_id: *attempt_id,
                },
            ),
        }
    }
}

pub async fn serve_connection<H: ControlRequestHandler + ?Sized>(
    mut stream: UnixStream,
    handler: &H,
    config: &ExecutorServerConfig,
) -> Result<(), ExecutorSocketError> {
    let peer = stream
        .peer_cred()
        .map_err(ExecutorSocketError::PeerCredentials)?;
    if peer.uid() != config.allowed_uid {
        return Err(ExecutorSocketError::UnauthorizedPeer {
            received: peer.uid(),
        });
    }

    timeout(config.request_timeout, async {
        let request = read_frame(&mut stream, NORMAL_FRAME_MAX_BYTES).await?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = stream.read(&mut trailing).await.map_err(FrameError::Io)?;
        if trailing_bytes != 0 {
            return Err(FrameError::TrailingBytes(trailing_bytes));
        }
        let response = handler.handle(request);
        write_frame(&mut stream, &response, OBSERVATION_FRAME_MAX_BYTES).await
    })
    .await
    .map_err(|_| ExecutorSocketError::DeadlineExceeded)??;
    Ok(())
}

pub async fn serve_until<H, F>(
    listener: UnixListener,
    handler: Arc<H>,
    config: ExecutorServerConfig,
    shutdown: F,
) -> Result<(), ExecutorSocketError>
where
    H: ControlRequestHandler + 'static,
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
                    Ok(Err(error)) => warn!(error = %error, "executor connection rejected"),
                    Err(error) => warn!(error = %error, "executor connection task failed"),
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(ExecutorSocketError::Accept)?;
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    warn!("executor connection limit reached");
                    continue;
                };
                let handler = Arc::clone(&handler);
                let config = config.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_connection(stream, handler.as_ref(), &config).await
                });
            }
        }
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(error = %error, "executor connection ended during shutdown"),
            Err(error) => warn!(error = %error, "executor connection task failed during shutdown"),
        }
    }
    Ok(())
}

pub struct BoundExecutorSocket {
    listener: Option<UnixListener>,
    cleanup: SocketCleanupGuard,
}

impl BoundExecutorSocket {
    pub fn bind(path: &Path) -> Result<Self, ExecutorSocketError> {
        if !is_normalized_absolute_path(path) {
            return Err(ExecutorSocketError::InvalidBindPath);
        }
        let parent = path.parent().ok_or(ExecutorSocketError::InvalidBindPath)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(ExecutorSocketError::BindParent)?;
        if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
            return Err(ExecutorSocketError::UnsafeBindParent);
        }
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(ExecutorSocketError::SocketPathExists),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(ExecutorSocketError::InspectSocketPath(error)),
        }

        let listener = UnixListener::bind(path).map_err(ExecutorSocketError::Bind)?;
        let metadata =
            fs::symlink_metadata(path).map_err(ExecutorSocketError::InspectSocketPath)?;
        if !metadata.file_type().is_socket() {
            return Err(ExecutorSocketError::BoundPathNotSocket);
        }
        let cleanup = SocketCleanupGuard {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))
            .map_err(ExecutorSocketError::SetPermissions)?;
        Ok(Self {
            listener: Some(listener),
            cleanup,
        })
    }

    pub fn take_listener(&mut self) -> UnixListener {
        self.listener
            .take()
            .expect("bound executor listener can only be taken once")
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.cleanup.path
    }
}

struct SocketCleanupGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketCleanupGuard {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExecutorConfigError {
    #[error("unsupported root executor config schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("controller UID must identify a non-root Unix account")]
    InvalidControllerUid,
    #[error("executor socket path must be the installed fixed path")]
    InvalidSocketPath,
    #[error("metrics disk path must be absolute, normalized and bounded")]
    InvalidMetricsDiskPath,
    #[error("executor connection limit must be between 1 and {MAX_CONNECTIONS}")]
    InvalidConnectionLimit,
    #[error(
        "executor request timeout must be between {MIN_REQUEST_TIMEOUT_MS} and {MAX_REQUEST_TIMEOUT_MS} milliseconds"
    )]
    InvalidRequestTimeout,
    #[error("root executor mutation authority configuration is invalid")]
    InvalidMutationAuthority,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutorSocketError {
    #[error("executor socket bind path is invalid")]
    InvalidBindPath,
    #[error("executor socket parent could not be inspected: {0}")]
    BindParent(io::Error),
    #[error("executor socket parent is not a direct non-symlink directory")]
    UnsafeBindParent,
    #[error("executor socket path already exists")]
    SocketPathExists,
    #[error("executor socket path could not be inspected: {0}")]
    InspectSocketPath(io::Error),
    #[error("executor socket bind failed: {0}")]
    Bind(io::Error),
    #[error("executor socket permissions could not be set: {0}")]
    SetPermissions(io::Error),
    #[error("executor bind path is not a Unix socket")]
    BoundPathNotSocket,
    #[error("executor peer credentials could not be read: {0}")]
    PeerCredentials(io::Error),
    #[error("executor peer UID {received} is not authorized")]
    UnauthorizedPeer { received: u32 },
    #[error("executor request deadline exceeded")]
    DeadlineExceeded,
    #[error("executor frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("executor socket accept failed: {0}")]
    Accept(io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutorClientError {
    #[error("executor client socket path must be absolute, normalized and bounded")]
    InvalidSocketPath,
    #[error(
        "executor client timeout must be between {MIN_REQUEST_TIMEOUT_MS} and {MAX_REQUEST_TIMEOUT_MS} milliseconds"
    )]
    InvalidRequestTimeout,
    #[error("executor connection failed: {0}")]
    Connect(io::Error),
    #[error("executor request deadline exceeded")]
    DeadlineExceeded,
    #[error("executor frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("executor response does not match the request or protocol version")]
    ResponseBindingMismatch,
    #[error("executor returned an unexpected response variant")]
    UnexpectedResponse,
    #[error("executor rejected the request with {code:?} (retryable={retryable})")]
    Rejected {
        code: ControlRejectionCodeV1,
        retryable: bool,
    },
}
