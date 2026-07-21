use std::{
    fs,
    future::Future,
    io,
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream as StdUnixStream,
    },
    path::{Component, Path, PathBuf},
    sync::Arc,
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
    domain::ProjectId,
    notifications::{NotificationDeliveryRecordV1, NotificationEventV1},
    protocol::{
        FrameError, NORMAL_FRAME_MAX_BYTES, OBSERVATION_FRAME_MAX_BYTES, decode_single_frame,
        encode_frame, read_frame, write_frame,
    },
    store::{NotificationEnqueueResult, NotificationStore, NotificationStoreError},
    unix_time_ms,
};

pub const NOTIFIER_PROTOCOL_VERSION: u16 = 1;
pub const NOTIFIER_SOCKET_PATH: &str = "/run/rdashboard-notify/notify.sock";
const MAX_CONNECTIONS: usize = 16;
const MAX_RECORDS: u8 = 50;
const MAX_REJECTION_DETAIL_BYTES: usize = 256;
const MAX_BROWSER_SAFE_TIMESTAMP: i64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NotifierRequestV1 {
    Enqueue {
        schema_version: u16,
        request_id: Uuid,
        event: NotificationEventV1,
    },
    ProjectRecords {
        schema_version: u16,
        request_id: Uuid,
        project_id: ProjectId,
        limit: u8,
    },
}

impl NotifierRequestV1 {
    pub fn enqueue(event: NotificationEventV1) -> Self {
        Self::Enqueue {
            schema_version: NOTIFIER_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            event,
        }
    }

    pub fn project_records(project_id: ProjectId, limit: u8) -> Self {
        Self::ProjectRecords {
            schema_version: NOTIFIER_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            project_id,
            limit,
        }
    }

    pub const fn request_id(&self) -> Uuid {
        match self {
            Self::Enqueue { request_id, .. } | Self::ProjectRecords { request_id, .. } => {
                *request_id
            }
        }
    }

    fn validate(&self) -> Result<(), NotifierRejectionCodeV1> {
        match self {
            Self::Enqueue {
                schema_version,
                event,
                ..
            } => {
                if *schema_version != NOTIFIER_PROTOCOL_VERSION {
                    return Err(NotifierRejectionCodeV1::UnsupportedProtocolVersion);
                }
                if event.validate().is_err() {
                    return Err(NotifierRejectionCodeV1::InvalidRequest);
                }
            }
            Self::ProjectRecords {
                schema_version,
                limit,
                ..
            } => {
                if *schema_version != NOTIFIER_PROTOCOL_VERSION {
                    return Err(NotifierRejectionCodeV1::UnsupportedProtocolVersion);
                }
                if !(1..=MAX_RECORDS).contains(limit) {
                    return Err(NotifierRejectionCodeV1::InvalidRequest);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifierRejectionCodeV1 {
    UnsupportedProtocolVersion,
    InvalidRequest,
    StoreUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NotifierResponseV1 {
    Enqueued {
        schema_version: u16,
        request_id: Uuid,
        result: NotificationEnqueueResult,
    },
    ProjectRecords {
        schema_version: u16,
        request_id: Uuid,
        generated_at_ms: i64,
        project_id: ProjectId,
        records: Vec<NotificationDeliveryRecordV1>,
    },
    Rejected {
        schema_version: u16,
        request_id: Uuid,
        code: NotifierRejectionCodeV1,
        detail: String,
    },
}

#[derive(Clone, Debug)]
pub struct StoreNotifierHandlerV1 {
    store: NotificationStore,
}

impl StoreNotifierHandlerV1 {
    pub const fn new(store: NotificationStore) -> Self {
        Self { store }
    }

    fn handle(&self, request: NotifierRequestV1) -> NotifierResponseV1 {
        let request_id = request.request_id();
        if let Err(code) = request.validate() {
            return rejected(request_id, code, "Notifier request is invalid.");
        }
        match request {
            NotifierRequestV1::Enqueue { event, .. } => {
                let Ok(now_ms) = unix_time_ms() else {
                    return rejected(
                        request_id,
                        NotifierRejectionCodeV1::StoreUnavailable,
                        "Notifier clock is unavailable.",
                    );
                };
                match self.store.enqueue(&event, now_ms) {
                    Ok(result) => NotifierResponseV1::Enqueued {
                        schema_version: NOTIFIER_PROTOCOL_VERSION,
                        request_id,
                        result,
                    },
                    Err(error) => store_rejection(request_id, &error),
                }
            }
            NotifierRequestV1::ProjectRecords {
                project_id, limit, ..
            } => match self.store.project_records(&project_id, usize::from(limit)) {
                Ok(records) => {
                    let Ok(generated_at_ms) = unix_time_ms() else {
                        return rejected(
                            request_id,
                            NotifierRejectionCodeV1::StoreUnavailable,
                            "Notifier clock is unavailable.",
                        );
                    };
                    NotifierResponseV1::ProjectRecords {
                        schema_version: NOTIFIER_PROTOCOL_VERSION,
                        request_id,
                        generated_at_ms,
                        project_id,
                        records,
                    }
                }
                Err(error) => store_rejection(request_id, &error),
            },
        }
    }
}

fn store_rejection(request_id: Uuid, error: &NotificationStoreError) -> NotifierResponseV1 {
    let code = if matches!(error, NotificationStoreError::InvalidLimit) {
        NotifierRejectionCodeV1::InvalidRequest
    } else {
        NotifierRejectionCodeV1::StoreUnavailable
    };
    rejected(request_id, code, "Notifier storage request failed.")
}

fn rejected(request_id: Uuid, code: NotifierRejectionCodeV1, detail: &str) -> NotifierResponseV1 {
    NotifierResponseV1::Rejected {
        schema_version: NOTIFIER_PROTOCOL_VERSION,
        request_id,
        code,
        detail: detail.to_owned(),
    }
}

#[derive(Clone, Debug)]
pub struct NotifierClientV1 {
    socket_path: PathBuf,
    request_timeout: Duration,
}

impl NotifierClientV1 {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        request_timeout: Duration,
    ) -> Result<Self, NotifierClientError> {
        let socket_path = socket_path.into();
        if !is_normalized_absolute_path(&socket_path)
            || request_timeout < Duration::from_millis(100)
            || request_timeout > Duration::from_secs(10)
        {
            return Err(NotifierClientError::InvalidConfig);
        }
        Ok(Self {
            socket_path,
            request_timeout,
        })
    }

    pub fn enqueue(
        &self,
        event: NotificationEventV1,
    ) -> Result<NotificationEnqueueResult, NotifierClientError> {
        let response = self.exchange(&NotifierRequestV1::enqueue(event))?;
        match response {
            NotifierResponseV1::Enqueued {
                schema_version,
                result,
                ..
            } if schema_version == NOTIFIER_PROTOCOL_VERSION => Ok(result),
            NotifierResponseV1::Rejected { code, detail, .. } => {
                Err(NotifierClientError::Rejected { code, detail })
            }
            NotifierResponseV1::Enqueued { .. } | NotifierResponseV1::ProjectRecords { .. } => {
                Err(NotifierClientError::WrongResponse)
            }
        }
    }

    pub fn project_records(
        &self,
        project_id: ProjectId,
        limit: u8,
    ) -> Result<NotifierProjectRecordsV1, NotifierClientError> {
        let expected_project = project_id.clone();
        let response = self.exchange(&NotifierRequestV1::project_records(project_id, limit))?;
        match response {
            NotifierResponseV1::ProjectRecords {
                schema_version,
                generated_at_ms,
                project_id,
                records,
                ..
            } if schema_version == NOTIFIER_PROTOCOL_VERSION
                && project_id == expected_project
                && records.len() <= usize::from(limit)
                && (0..=MAX_BROWSER_SAFE_TIMESTAMP).contains(&generated_at_ms)
                && valid_records(&records) =>
            {
                Ok(NotifierProjectRecordsV1 {
                    schema_version,
                    generated_at_ms,
                    project_id,
                    records,
                })
            }
            NotifierResponseV1::Rejected { code, detail, .. } => {
                Err(NotifierClientError::Rejected { code, detail })
            }
            NotifierResponseV1::Enqueued { .. } | NotifierResponseV1::ProjectRecords { .. } => {
                Err(NotifierClientError::WrongResponse)
            }
        }
    }

    fn exchange(
        &self,
        request: &NotifierRequestV1,
    ) -> Result<NotifierResponseV1, NotifierClientError> {
        let request_id = request.request_id();
        let frame = encode_frame(&request, NORMAL_FRAME_MAX_BYTES)?;
        let mut stream = StdUnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(self.request_timeout))?;
        stream.set_write_timeout(Some(self.request_timeout))?;
        io::Write::write_all(&mut stream, &frame)?;
        stream.shutdown(Shutdown::Write)?;
        let response = read_blocking_frame(&mut stream, OBSERVATION_FRAME_MAX_BYTES)?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = io::Read::read(&mut stream, &mut trailing)?;
        if trailing_bytes != 0 {
            return Err(NotifierClientError::Frame(FrameError::TrailingBytes(
                trailing_bytes,
            )));
        }
        let response_request_id = match &response {
            NotifierResponseV1::Enqueued { request_id, .. }
            | NotifierResponseV1::ProjectRecords { request_id, .. }
            | NotifierResponseV1::Rejected { request_id, .. } => *request_id,
        };
        if response_request_id != request_id {
            return Err(NotifierClientError::RequestBinding);
        }
        if let NotifierResponseV1::Rejected {
            schema_version,
            detail,
            ..
        } = &response
            && (*schema_version != NOTIFIER_PROTOCOL_VERSION
                || detail.is_empty()
                || detail.len() > MAX_REJECTION_DETAIL_BYTES
                || detail.chars().any(char::is_control))
        {
            return Err(NotifierClientError::WrongResponse);
        }
        Ok(response)
    }
}

fn valid_records(records: &[NotificationDeliveryRecordV1]) -> bool {
    let mut previous_updated_at_ms = MAX_BROWSER_SAFE_TIMESTAMP;
    for record in records {
        if record.validate().is_err() || record.updated_at_ms > previous_updated_at_ms {
            return false;
        }
        previous_updated_at_ms = record.updated_at_ms;
    }
    true
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotifierProjectRecordsV1 {
    pub schema_version: u16,
    pub generated_at_ms: i64,
    pub project_id: ProjectId,
    pub records: Vec<NotificationDeliveryRecordV1>,
}

fn read_blocking_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut StdUnixStream,
    maximum: usize,
) -> Result<T, NotifierClientError> {
    let mut header = [0_u8; 4];
    io::Read::read_exact(stream, &mut header)?;
    let declared = usize::try_from(u32::from_be_bytes(header)).map_err(|_| {
        NotifierClientError::Frame(FrameError::Oversized {
            received: usize::MAX,
            maximum,
        })
    })?;
    if declared > maximum {
        return Err(NotifierClientError::Frame(FrameError::Oversized {
            received: declared,
            maximum,
        }));
    }
    let mut frame = Vec::with_capacity(declared.saturating_add(4));
    frame.extend_from_slice(&header);
    frame.resize(declared.saturating_add(4), 0);
    io::Read::read_exact(stream, &mut frame[4..])?;
    decode_single_frame(&frame, maximum).map_err(Into::into)
}

#[derive(Clone, Debug)]
pub struct NotifierServerConfigV1 {
    allowed_uid: u32,
    max_connections: usize,
    request_timeout: Duration,
}

impl NotifierServerConfigV1 {
    pub fn new(
        allowed_uid: u32,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Result<Self, NotifierSocketError> {
        if allowed_uid == u32::MAX
            || !(1..=MAX_CONNECTIONS).contains(&max_connections)
            || request_timeout < Duration::from_millis(100)
            || request_timeout > Duration::from_secs(10)
        {
            return Err(NotifierSocketError::InvalidServerConfig);
        }
        Ok(Self {
            allowed_uid,
            max_connections,
            request_timeout,
        })
    }
}

pub async fn serve_notifier_connection(
    mut stream: UnixStream,
    handler: Arc<StoreNotifierHandlerV1>,
    config: &NotifierServerConfigV1,
) -> Result<(), NotifierSocketError> {
    let peer = stream
        .peer_cred()
        .map_err(NotifierSocketError::PeerCredentials)?;
    if peer.uid() != config.allowed_uid {
        return Err(NotifierSocketError::UnauthorizedPeer {
            received: peer.uid(),
        });
    }
    timeout(config.request_timeout, async move {
        let request = read_frame(&mut stream, NORMAL_FRAME_MAX_BYTES).await?;
        let mut trailing = [0_u8; 1];
        let trailing_bytes = stream.read(&mut trailing).await.map_err(FrameError::Io)?;
        if trailing_bytes != 0 {
            return Err(NotifierSocketError::Frame(FrameError::TrailingBytes(
                trailing_bytes,
            )));
        }
        let response = tokio::task::spawn_blocking(move || handler.handle(request))
            .await
            .map_err(NotifierSocketError::HandlerTask)?;
        write_frame(&mut stream, &response, OBSERVATION_FRAME_MAX_BYTES).await?;
        stream.shutdown().await.map_err(FrameError::Io)?;
        Ok(())
    })
    .await
    .map_err(|_| NotifierSocketError::DeadlineExceeded)??;
    Ok(())
}

pub async fn serve_notifier_until<F>(
    listener: UnixListener,
    handler: Arc<StoreNotifierHandlerV1>,
    config: NotifierServerConfigV1,
    shutdown: F,
) -> Result<(), NotifierSocketError>
where
    F: Future<Output = ()>,
{
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let config = Arc::new(config);
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                log_connection_result(result);
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(NotifierSocketError::Accept)?;
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    warn!("notifier connection rejected because capacity is exhausted");
                    continue;
                };
                let handler = Arc::clone(&handler);
                let config = Arc::clone(&config);
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_notifier_connection(stream, handler, &config).await
                });
            }
        }
    }
    drop(listener);
    while let Some(result) = tasks.join_next().await {
        log_connection_result(result);
    }
    Ok(())
}

fn log_connection_result(result: Result<Result<(), NotifierSocketError>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(error = %error, "notifier connection rejected"),
        Err(error) => warn!(error = %error, "notifier connection task failed"),
    }
}

pub struct BoundNotifierSocketV1 {
    listener: Option<UnixListener>,
    _cleanup: NotifierSocketCleanupGuard,
}

impl BoundNotifierSocketV1 {
    pub fn bind(path: &Path, required_uid: u32) -> Result<Self, NotifierSocketError> {
        if !is_normalized_absolute_path(path) {
            return Err(NotifierSocketError::InvalidBindPath);
        }
        let parent = path.parent().ok_or(NotifierSocketError::InvalidBindPath)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(NotifierSocketError::BindParent)?;
        let parent_mode = parent_metadata.permissions().mode() & 0o777;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.uid() != required_uid
            || parent_mode != 0o750
            || parent_metadata.gid() == 0
        {
            return Err(NotifierSocketError::UnsafeBindParent);
        }
        match fs::symlink_metadata(path) {
            Ok(existing) => {
                let expected_stale_socket = existing.file_type().is_socket()
                    && existing.uid() == required_uid
                    && existing.gid() == parent_metadata.gid()
                    && existing.permissions().mode() & 0o777 == 0o660;
                if !expected_stale_socket {
                    return Err(NotifierSocketError::SocketPathExists);
                }
                match StdUnixStream::connect(path) {
                    Ok(_) => return Err(NotifierSocketError::SocketPathExists),
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                    Err(error) => return Err(NotifierSocketError::InspectStaleSocket(error)),
                }
                let rechecked =
                    fs::symlink_metadata(path).map_err(NotifierSocketError::InspectSocketPath)?;
                if !rechecked.file_type().is_socket()
                    || rechecked.dev() != existing.dev()
                    || rechecked.ino() != existing.ino()
                {
                    return Err(NotifierSocketError::SocketPathChanged);
                }
                fs::remove_file(path).map_err(NotifierSocketError::RemoveStaleSocket)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(NotifierSocketError::InspectSocketPath(error)),
        }
        let listener = UnixListener::bind(path).map_err(NotifierSocketError::Bind)?;
        let bound = fs::symlink_metadata(path).map_err(NotifierSocketError::InspectSocketPath)?;
        if !bound.file_type().is_socket()
            || bound.uid() != required_uid
            || bound.gid() != parent_metadata.gid()
        {
            return Err(NotifierSocketError::BoundPathNotSocket);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))
            .map_err(NotifierSocketError::SetPermissions)?;
        let protected =
            fs::symlink_metadata(path).map_err(NotifierSocketError::InspectSocketPath)?;
        if !protected.file_type().is_socket()
            || protected.uid() != required_uid
            || protected.gid() != parent_metadata.gid()
            || protected.permissions().mode() & 0o777 != 0o660
            || protected.dev() != bound.dev()
            || protected.ino() != bound.ino()
        {
            return Err(NotifierSocketError::BoundPathNotSocket);
        }
        Ok(Self {
            listener: Some(listener),
            _cleanup: NotifierSocketCleanupGuard {
                path: path.to_owned(),
                device: protected.dev(),
                inode: protected.ino(),
            },
        })
    }

    pub fn take_listener(&mut self) -> UnixListener {
        self.listener
            .take()
            .expect("bound notifier listener can only be taken once")
    }
}

struct NotifierSocketCleanupGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for NotifierSocketCleanupGuard {
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

#[derive(Debug, thiserror::Error)]
pub enum NotifierClientError {
    #[error("notifier client configuration is invalid")]
    InvalidConfig,
    #[error("notifier socket I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("notifier frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("notifier response does not match its request")]
    RequestBinding,
    #[error("notifier returned the wrong response kind")]
    WrongResponse,
    #[error("notifier rejected the request with {code:?}: {detail}")]
    Rejected {
        code: NotifierRejectionCodeV1,
        detail: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum NotifierSocketError {
    #[error("notifier server configuration is invalid")]
    InvalidServerConfig,
    #[error("notifier socket bind path is invalid")]
    InvalidBindPath,
    #[error("notifier socket parent could not be inspected: {0}")]
    BindParent(io::Error),
    #[error("notifier socket parent ownership or mode is unsafe")]
    UnsafeBindParent,
    #[error("notifier socket path already exists")]
    SocketPathExists,
    #[error("notifier socket path could not be inspected: {0}")]
    InspectSocketPath(io::Error),
    #[error("notifier stale socket probe failed: {0}")]
    InspectStaleSocket(io::Error),
    #[error("notifier socket path changed during stale reconciliation")]
    SocketPathChanged,
    #[error("notifier stale socket could not be removed: {0}")]
    RemoveStaleSocket(io::Error),
    #[error("notifier socket could not be bound: {0}")]
    Bind(io::Error),
    #[error("notifier bound path is not the expected socket")]
    BoundPathNotSocket,
    #[error("notifier socket permissions could not be set: {0}")]
    SetPermissions(io::Error),
    #[error("notifier peer credentials could not be read: {0}")]
    PeerCredentials(io::Error),
    #[error("notifier peer uid {received} is not authorized")]
    UnauthorizedPeer { received: u32 },
    #[error("notifier request deadline was exceeded")]
    DeadlineExceeded,
    #[error("notifier frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("notifier handler task failed: {0}")]
    HandlerTask(tokio::task::JoinError),
    #[error("notifier socket accept failed: {0}")]
    Accept(io::Error),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use tempfile::tempdir;

    use super::*;
    use crate::notifications::NotificationKindV1;

    fn event() -> NotificationEventV1 {
        NotificationEventV1::new(
            "rimg".parse().expect("project"),
            NotificationKindV1::ControllerFailed,
            "rdashboard.rimg.controller",
            "failure:1",
            "rimg: dashboard controller failed",
            0,
        )
        .expect("event")
    }

    #[tokio::test]
    async fn peer_authenticated_protocol_enqueues_and_reads_bounded_records() {
        let directory = tempdir().expect("directory");
        let socket_directory = directory.path().join("socket");
        fs::create_dir(&socket_directory).expect("socket directory");
        fs::set_permissions(&socket_directory, fs::Permissions::from_mode(0o750))
            .expect("socket directory mode");
        let uid = fs::metadata(&socket_directory).expect("metadata").uid();
        let socket_path = socket_directory.join("notify.sock");
        let listener = UnixListener::bind(&socket_path).expect("listener");
        let store =
            NotificationStore::open(directory.path().join("notifications.sqlite")).expect("store");
        let handler = Arc::new(StoreNotifierHandlerV1::new(store));
        let config = NotifierServerConfigV1::new(uid, 4, Duration::from_secs(2)).expect("config");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            serve_notifier_until(listener, handler, config, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let client = NotifierClientV1::new(&socket_path, Duration::from_secs(2)).expect("client");
        let event = event();
        let enqueue_client = client.clone();
        let inserted = tokio::task::spawn_blocking(move || enqueue_client.enqueue(event))
            .await
            .expect("enqueue task")
            .expect("enqueue");
        assert_eq!(inserted, NotificationEnqueueResult::Inserted);
        let records_client = client.clone();
        let records = tokio::task::spawn_blocking(move || {
            records_client.project_records("rimg".parse().expect("project"), 10)
        })
        .await
        .expect("records task")
        .expect("records");
        assert_eq!(records.records.len(), 1);
        assert_eq!(
            records.records[0].event.kind,
            NotificationKindV1::ControllerFailed
        );

        shutdown_tx.send(()).expect("shutdown");
        server.await.expect("server task").expect("server");
    }

    #[tokio::test]
    async fn bind_reconciles_only_a_stale_owned_socket() {
        tokio::task::yield_now().await;
        let directory = tempdir().expect("directory");
        let socket_directory = directory.path().join("socket");
        fs::create_dir(&socket_directory).expect("socket directory");
        fs::set_permissions(&socket_directory, fs::Permissions::from_mode(0o750))
            .expect("socket directory mode");
        let uid = fs::metadata(&socket_directory).expect("metadata").uid();
        let socket_path = socket_directory.join("notify.sock");
        let stale = std::os::unix::net::UnixListener::bind(&socket_path).expect("stale socket");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))
            .expect("stale socket mode");
        drop(stale);

        let _bound = BoundNotifierSocketV1::bind(&socket_path, uid).expect("reconciled bind");
        assert!(
            fs::symlink_metadata(&socket_path)
                .expect("bound socket")
                .file_type()
                .is_socket()
        );
    }

    #[test]
    fn bind_never_replaces_a_live_owned_socket() {
        let directory = tempdir().expect("directory");
        let socket_directory = directory.path().join("socket");
        fs::create_dir(&socket_directory).expect("socket directory");
        fs::set_permissions(&socket_directory, fs::Permissions::from_mode(0o750))
            .expect("socket directory mode");
        let uid = fs::metadata(&socket_directory).expect("metadata").uid();
        let socket_path = socket_directory.join("notify.sock");
        let _live = std::os::unix::net::UnixListener::bind(&socket_path).expect("live socket");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))
            .expect("live socket mode");

        assert!(matches!(
            BoundNotifierSocketV1::bind(&socket_path, uid),
            Err(NotifierSocketError::SocketPathExists)
        ));
    }

    #[test]
    fn systemd_contract_keeps_gateway_secret_out_of_controller() {
        let notifier = include_str!("../deploy/systemd/rdashboard-notify.service");
        let controller = include_str!("../deploy/systemd/rdashboard.service");
        let drop_in = include_str!("../deploy/systemd/rdashboard-notifier.conf");

        assert!(notifier.contains("User=rdashboard-notify"));
        assert!(
            notifier
                .lines()
                .any(|line| line == "Group=rdashboard-notify")
        );
        assert!(!notifier.lines().any(|line| line == "Group=rdashboard"));
        assert!(notifier.contains("StateDirectoryMode=0700"));
        assert!(notifier.contains("RuntimeDirectoryMode=0750"));
        assert!(notifier.contains(
            "LoadCredential=telegram-gateway-secret:/etc/rdashboard/credentials/telegram-gateway-secret"
        ));
        assert!(notifier.contains("CapabilityBoundingSet=\n"));
        assert!(drop_in.contains(&format!(
            "Environment=RDASHBOARD_NOTIFIER_SOCKET={NOTIFIER_SOCKET_PATH}"
        )));
        assert!(drop_in.contains("Requires=rdashboard-notify.service"));
        assert!(drop_in.contains("SupplementaryGroups=rdashboard-notify"));
        assert!(!drop_in.contains("telegram-gateway-secret"));
        assert!(!controller.contains("RDASHBOARD_NOTIFIER_SOCKET"));
        assert!(!controller.contains("telegram-gateway-secret"));
    }
}
