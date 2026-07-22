use std::{
    fs,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown},
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

use futures_util::{FutureExt as _, StreamExt as _, future::BoxFuture};
use reqwest::{
    StatusCode,
    header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, HeaderValue, LOCATION},
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
use url::Url;
use uuid::Uuid;

use crate::{
    cargo_prefetch::{CRATE_ARCHIVE_MAX_BYTES, CargoRegistryPackageV1},
    domain::EvidenceDigest,
    oci_base::{OciRegistryObjectKindV1, OciRegistryObjectV1},
    protocol::{FrameError, NORMAL_FRAME_MAX_BYTES, read_frame, write_frame},
};

pub const DEPENDENCY_FETCH_PROTOCOL_VERSION: u16 = 2;
pub const DEPENDENCY_FETCH_SOCKET_PATH: &str = "/run/rdashboard-dependency-fetcher/fetch.sock";
const CRATES_IO_ORIGIN: &str = "https://static.crates.io/crates/";
const DOCKER_REGISTRY_ORIGIN: &str = "https://registry-1.docker.io/";
const DOCKER_AUTH_ORIGIN: &str = "https://auth.docker.io/token";
const OCI_MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_TOKEN_MAX_BYTES: usize = 64 * 1024;
const MIN_REQUEST_TIMEOUT_MS: u64 = 1_000;
const MAX_REQUEST_TIMEOUT_MS: u64 = 120_000;
const MAX_CONNECTIONS: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyFetchRequestEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub request: DependencyFetchRequestV1,
}

impl DependencyFetchRequestEnvelopeV1 {
    fn validate(&self) -> Result<(), DependencyFetchValidationError> {
        if self.version != DEPENDENCY_FETCH_PROTOCOL_VERSION {
            return Err(DependencyFetchValidationError::UnsupportedVersion(
                self.version,
            ));
        }
        if self.request_id.is_nil() {
            return Err(DependencyFetchValidationError::NilRequestId);
        }
        match &self.request {
            DependencyFetchRequestV1::Negotiate { supported_versions }
                if !supported_versions.is_empty() && supported_versions.len() <= 8 =>
            {
                Ok(())
            }
            DependencyFetchRequestV1::Negotiate { .. } => {
                Err(DependencyFetchValidationError::InvalidVersionSet)
            }
            DependencyFetchRequestV1::FetchCrate { package } => package
                .validate()
                .map_err(|_| DependencyFetchValidationError::InvalidPackage),
            DependencyFetchRequestV1::FetchOciObject { object } => object
                .validate()
                .map_err(|_| DependencyFetchValidationError::InvalidOciObject),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DependencyFetchRequestV1 {
    Negotiate { supported_versions: Vec<u16> },
    FetchCrate { package: CargoRegistryPackageV1 },
    FetchOciObject { object: OciRegistryObjectV1 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyFetchResponseEnvelopeV1 {
    pub version: u16,
    pub request_id: Uuid,
    pub response: DependencyFetchResponseV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DependencyFetchResponseV1 {
    Negotiated {
        selected_version: u16,
    },
    CrateAccepted {
        archive_bytes: u64,
        archive_digest: EvidenceDigest,
    },
    OciObjectAccepted {
        object_bytes: u64,
        object_digest: String,
    },
    Rejected {
        code: DependencyFetchRejectionCodeV1,
        retryable: bool,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyFetchRejectionCodeV1 {
    UnsupportedProtocolVersion,
    InvalidRequest,
    CrateNotFound,
    CrateUnavailable,
    ArchiveTooLarge,
    IntegrityMismatch,
    OciObjectNotFound,
    OciObjectUnavailable,
    OciObjectTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DependencyFetchFailureV1 {
    pub code: DependencyFetchRejectionCodeV1,
    pub retryable: bool,
}

impl DependencyFetchFailureV1 {
    pub const fn new(code: DependencyFetchRejectionCodeV1, retryable: bool) -> Self {
        Self { code, retryable }
    }
}

pub trait DependencyFetchHandlerV1: Send + Sync {
    fn fetch_crate(
        &self,
        package: CargoRegistryPackageV1,
    ) -> BoxFuture<'_, Result<Vec<u8>, DependencyFetchFailureV1>>;

    fn fetch_oci_object(
        &self,
        object: OciRegistryObjectV1,
    ) -> BoxFuture<'_, Result<Vec<u8>, DependencyFetchFailureV1>>;
}

#[derive(Clone, Debug)]
pub struct DependencyFetchClientV1 {
    socket_path: PathBuf,
    expected_server_uid: u32,
    request_timeout: Duration,
    negotiated: Arc<AtomicBool>,
}

impl DependencyFetchClientV1 {
    pub fn installed(
        expected_server_uid: u32,
        request_timeout: Duration,
    ) -> Result<Self, DependencyFetchClientError> {
        Self::new(
            DEPENDENCY_FETCH_SOCKET_PATH,
            expected_server_uid,
            request_timeout,
        )
    }

    pub fn new(
        socket_path: impl Into<PathBuf>,
        expected_server_uid: u32,
        request_timeout: Duration,
    ) -> Result<Self, DependencyFetchClientError> {
        let socket_path = socket_path.into();
        if !is_normalized_absolute_path(&socket_path)
            || expected_server_uid == 0
            || expected_server_uid == u32::MAX
            || !valid_request_timeout(request_timeout)
        {
            return Err(DependencyFetchClientError::InvalidConfiguration);
        }
        Ok(Self {
            socket_path,
            expected_server_uid,
            request_timeout,
            negotiated: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn fetch_crate(
        &self,
        package: &CargoRegistryPackageV1,
    ) -> Result<Vec<u8>, DependencyFetchClientError> {
        package
            .validate()
            .map_err(|_| DependencyFetchClientError::InvalidPackage)?;
        self.ensure_negotiated().await?;
        let response = self
            .exchange(DependencyFetchRequestV1::FetchCrate {
                package: package.clone(),
            })
            .await?;
        match response {
            DependencyFetchExchangeV1 {
                response:
                    DependencyFetchResponseV1::CrateAccepted {
                        archive_bytes,
                        archive_digest,
                    },
                archive: Some(archive),
            } if archive_bytes
                == u64::try_from(archive.len())
                    .map_err(|_| DependencyFetchClientError::InvalidResponse)?
                && archive_digest == package.checksum
                && EvidenceDigest::sha256(&archive) == package.checksum =>
            {
                Ok(archive)
            }
            DependencyFetchExchangeV1 {
                response: DependencyFetchResponseV1::Rejected { code, retryable },
                archive: None,
            } => Err(DependencyFetchClientError::Rejected { code, retryable }),
            _ => self.wrong_response(),
        }
    }

    pub async fn fetch_oci_object(
        &self,
        object: &OciRegistryObjectV1,
    ) -> Result<Vec<u8>, DependencyFetchClientError> {
        object
            .validate()
            .map_err(|_| DependencyFetchClientError::InvalidOciObject)?;
        self.ensure_negotiated().await?;
        let response = self
            .exchange(DependencyFetchRequestV1::FetchOciObject {
                object: object.clone(),
            })
            .await?;
        match response {
            DependencyFetchExchangeV1 {
                response:
                    DependencyFetchResponseV1::OciObjectAccepted {
                        object_bytes,
                        object_digest,
                    },
                archive: Some(bytes),
            } if object_bytes
                == u64::try_from(bytes.len())
                    .map_err(|_| DependencyFetchClientError::InvalidResponse)?
                && object_digest == object.digest.as_str()
                && object
                    .expected_bytes
                    .is_none_or(|expected| expected == object_bytes)
                && EvidenceDigest::sha256(&bytes).as_str() == object.digest.hex() =>
            {
                Ok(bytes)
            }
            DependencyFetchExchangeV1 {
                response: DependencyFetchResponseV1::Rejected { code, retryable },
                archive: None,
            } => Err(DependencyFetchClientError::Rejected { code, retryable }),
            _ => self.wrong_response(),
        }
    }

    async fn ensure_negotiated(&self) -> Result<(), DependencyFetchClientError> {
        if self.negotiated.load(Ordering::Acquire) {
            return Ok(());
        }
        match self
            .exchange(DependencyFetchRequestV1::Negotiate {
                supported_versions: vec![DEPENDENCY_FETCH_PROTOCOL_VERSION],
            })
            .await?
        {
            DependencyFetchExchangeV1 {
                response: DependencyFetchResponseV1::Negotiated { selected_version },
                archive: None,
            } if selected_version == DEPENDENCY_FETCH_PROTOCOL_VERSION => {
                self.negotiated.store(true, Ordering::Release);
                Ok(())
            }
            DependencyFetchExchangeV1 {
                response: DependencyFetchResponseV1::Rejected { code, retryable },
                archive: None,
            } => Err(DependencyFetchClientError::Rejected { code, retryable }),
            _ => self.wrong_response(),
        }
    }

    fn wrong_response<T>(&self) -> Result<T, DependencyFetchClientError> {
        self.negotiated.store(false, Ordering::Release);
        Err(DependencyFetchClientError::InvalidResponse)
    }

    async fn exchange(
        &self,
        request: DependencyFetchRequestV1,
    ) -> Result<DependencyFetchExchangeV1, DependencyFetchClientError> {
        let maximum_payload_bytes = match &request {
            DependencyFetchRequestV1::FetchCrate { .. } => CRATE_ARCHIVE_MAX_BYTES as u64,
            DependencyFetchRequestV1::FetchOciObject { object } => object.maximum_bytes,
            DependencyFetchRequestV1::Negotiate { .. } => 0,
        };
        let request_id = Uuid::new_v4();
        let envelope = DependencyFetchRequestEnvelopeV1 {
            version: DEPENDENCY_FETCH_PROTOCOL_VERSION,
            request_id,
            request,
        };
        timeout(self.request_timeout, async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(DependencyFetchClientError::Io)?;
            let peer = stream
                .peer_cred()
                .map_err(DependencyFetchClientError::PeerCredentials)?;
            if peer.uid() != self.expected_server_uid {
                return Err(DependencyFetchClientError::UnauthorizedServer {
                    received: peer.uid(),
                });
            }
            write_frame(&mut stream, &envelope, NORMAL_FRAME_MAX_BYTES).await?;
            stream
                .shutdown()
                .await
                .map_err(DependencyFetchClientError::Io)?;
            let response: DependencyFetchResponseEnvelopeV1 =
                read_frame(&mut stream, NORMAL_FRAME_MAX_BYTES).await?;
            if response.version != DEPENDENCY_FETCH_PROTOCOL_VERSION
                || response.request_id != request_id
            {
                return Err(DependencyFetchClientError::InvalidResponse);
            }
            let archive = match &response.response {
                DependencyFetchResponseV1::CrateAccepted { archive_bytes, .. } => {
                    let archive_bytes = usize::try_from(*archive_bytes)
                        .map_err(|_| DependencyFetchClientError::InvalidResponse)?;
                    if archive_bytes == 0 || archive_bytes > CRATE_ARCHIVE_MAX_BYTES {
                        return Err(DependencyFetchClientError::InvalidResponse);
                    }
                    let mut archive = vec![0_u8; archive_bytes];
                    stream
                        .read_exact(&mut archive)
                        .await
                        .map_err(DependencyFetchClientError::Io)?;
                    Some(archive)
                }
                DependencyFetchResponseV1::OciObjectAccepted { object_bytes, .. } => {
                    let object_bytes = usize::try_from(*object_bytes)
                        .map_err(|_| DependencyFetchClientError::InvalidResponse)?;
                    if object_bytes == 0
                        || u64::try_from(object_bytes)
                            .map_err(|_| DependencyFetchClientError::InvalidResponse)?
                            > maximum_payload_bytes
                    {
                        return Err(DependencyFetchClientError::InvalidResponse);
                    }
                    let mut object = vec![0_u8; object_bytes];
                    stream
                        .read_exact(&mut object)
                        .await
                        .map_err(DependencyFetchClientError::Io)?;
                    Some(object)
                }
                _ => None,
            };
            let mut trailing = [0_u8; 1];
            if stream
                .read(&mut trailing)
                .await
                .map_err(DependencyFetchClientError::Io)?
                != 0
            {
                return Err(DependencyFetchClientError::InvalidResponse);
            }
            Ok(DependencyFetchExchangeV1 {
                response: response.response,
                archive,
            })
        })
        .await
        .map_err(|_| DependencyFetchClientError::DeadlineExceeded)?
    }
}

struct DependencyFetchExchangeV1 {
    response: DependencyFetchResponseV1,
    archive: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct DependencyFetchServerConfigV1 {
    allowed_uid: u32,
    max_connections: usize,
    request_timeout: Duration,
}

impl DependencyFetchServerConfigV1 {
    pub fn new(
        allowed_uid: u32,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Result<Self, DependencyFetchServerConfigError> {
        if allowed_uid == 0
            || allowed_uid == u32::MAX
            || !(1..=MAX_CONNECTIONS).contains(&max_connections)
            || !valid_request_timeout(request_timeout)
        {
            return Err(DependencyFetchServerConfigError::InvalidConfiguration);
        }
        Ok(Self {
            allowed_uid,
            max_connections,
            request_timeout,
        })
    }
}

pub async fn serve_dependency_fetch_connection<H: DependencyFetchHandlerV1 + 'static>(
    mut stream: UnixStream,
    handler: Arc<H>,
    config: &DependencyFetchServerConfigV1,
) -> Result<(), DependencyFetchSocketError> {
    let peer = stream
        .peer_cred()
        .map_err(DependencyFetchSocketError::PeerCredentials)?;
    if peer.uid() != config.allowed_uid {
        return Err(DependencyFetchSocketError::UnauthorizedPeer {
            received: peer.uid(),
        });
    }
    let deadline = Instant::now() + config.request_timeout;
    let request = read_dependency_fetch_request(&mut stream, deadline).await?;
    let request_id = request.request_id;
    let exchange = handle_dependency_fetch_request(handler.as_ref(), request, deadline).await?;
    let envelope = DependencyFetchResponseEnvelopeV1 {
        version: DEPENDENCY_FETCH_PROTOCOL_VERSION,
        request_id,
        response: exchange.response,
    };
    write_dependency_fetch_response(&mut stream, &envelope, exchange.archive, deadline).await
}

async fn read_dependency_fetch_request(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<DependencyFetchRequestEnvelopeV1, DependencyFetchSocketError> {
    timeout_at(deadline, async {
        let request = read_frame(stream, NORMAL_FRAME_MAX_BYTES).await?;
        let mut trailing = [0_u8; 1];
        if stream.read(&mut trailing).await.map_err(FrameError::Io)? != 0 {
            return Err(DependencyFetchSocketError::Frame(
                FrameError::TrailingBytes(1),
            ));
        }
        Ok::<_, DependencyFetchSocketError>(request)
    })
    .await
    .map_err(|_| DependencyFetchSocketError::DeadlineExceeded)?
}

async fn handle_dependency_fetch_request<H: DependencyFetchHandlerV1>(
    handler: &H,
    request: DependencyFetchRequestEnvelopeV1,
    deadline: Instant,
) -> Result<DependencyFetchExchangeV1, DependencyFetchSocketError> {
    let exchange = match request.validate() {
        Ok(()) => match request.request {
            DependencyFetchRequestV1::Negotiate { supported_versions } => {
                negotiate_dependency_fetch_protocol(&supported_versions)
            }
            DependencyFetchRequestV1::FetchCrate { package } => {
                fetch_crate_response(handler, package, deadline).await?
            }
            DependencyFetchRequestV1::FetchOciObject { object } => {
                fetch_oci_object_response(handler, object, deadline).await?
            }
        },
        Err(DependencyFetchValidationError::UnsupportedVersion(_)) => rejected(
            DependencyFetchRejectionCodeV1::UnsupportedProtocolVersion,
            false,
        ),
        Err(_) => rejected(DependencyFetchRejectionCodeV1::InvalidRequest, false),
    };
    Ok(DependencyFetchExchangeV1 {
        response: exchange.0,
        archive: exchange.1,
    })
}

fn negotiate_dependency_fetch_protocol(
    supported_versions: &[u16],
) -> (DependencyFetchResponseV1, Option<Vec<u8>>) {
    if supported_versions.contains(&DEPENDENCY_FETCH_PROTOCOL_VERSION) {
        (
            DependencyFetchResponseV1::Negotiated {
                selected_version: DEPENDENCY_FETCH_PROTOCOL_VERSION,
            },
            None,
        )
    } else {
        rejected(
            DependencyFetchRejectionCodeV1::UnsupportedProtocolVersion,
            false,
        )
    }
}

async fn fetch_crate_response<H: DependencyFetchHandlerV1>(
    handler: &H,
    package: CargoRegistryPackageV1,
    deadline: Instant,
) -> Result<(DependencyFetchResponseV1, Option<Vec<u8>>), DependencyFetchSocketError> {
    let expected_checksum = package.checksum.clone();
    match timeout_at(deadline, handler.fetch_crate(package)).await {
        Ok(Ok(archive))
            if !archive.is_empty()
                && archive.len() <= CRATE_ARCHIVE_MAX_BYTES
                && EvidenceDigest::sha256(&archive) == expected_checksum =>
        {
            let archive_bytes = u64::try_from(archive.len())
                .map_err(|_| DependencyFetchSocketError::InvalidHandlerResponse)?;
            Ok((
                DependencyFetchResponseV1::CrateAccepted {
                    archive_bytes,
                    archive_digest: expected_checksum,
                },
                Some(archive),
            ))
        }
        Ok(Ok(archive)) if archive.len() > CRATE_ARCHIVE_MAX_BYTES => Ok(rejected(
            DependencyFetchRejectionCodeV1::ArchiveTooLarge,
            false,
        )),
        Ok(Ok(_)) => Ok(rejected(
            DependencyFetchRejectionCodeV1::IntegrityMismatch,
            false,
        )),
        Ok(Err(failure)) => Ok(rejected(failure.code, failure.retryable)),
        Err(_) => Err(DependencyFetchSocketError::DeadlineExceeded),
    }
}

async fn fetch_oci_object_response<H: DependencyFetchHandlerV1>(
    handler: &H,
    object: OciRegistryObjectV1,
    deadline: Instant,
) -> Result<(DependencyFetchResponseV1, Option<Vec<u8>>), DependencyFetchSocketError> {
    let expected_digest = object.digest.clone();
    let maximum_bytes = object.maximum_bytes;
    let expected_bytes = object.expected_bytes;
    match timeout_at(deadline, handler.fetch_oci_object(object)).await {
        Ok(Ok(bytes)) => {
            let object_bytes = u64::try_from(bytes.len())
                .map_err(|_| DependencyFetchSocketError::InvalidHandlerResponse)?;
            if object_bytes == 0 || object_bytes > maximum_bytes {
                Ok(rejected(
                    DependencyFetchRejectionCodeV1::OciObjectTooLarge,
                    false,
                ))
            } else if expected_bytes.is_some_and(|expected| expected != object_bytes)
                || EvidenceDigest::sha256(&bytes).as_str() != expected_digest.hex()
            {
                Ok(rejected(
                    DependencyFetchRejectionCodeV1::IntegrityMismatch,
                    false,
                ))
            } else {
                Ok((
                    DependencyFetchResponseV1::OciObjectAccepted {
                        object_bytes,
                        object_digest: expected_digest.as_str().to_owned(),
                    },
                    Some(bytes),
                ))
            }
        }
        Ok(Err(failure)) => Ok(rejected(failure.code, failure.retryable)),
        Err(_) => Err(DependencyFetchSocketError::DeadlineExceeded),
    }
}

async fn write_dependency_fetch_response(
    stream: &mut UnixStream,
    envelope: &DependencyFetchResponseEnvelopeV1,
    archive: Option<Vec<u8>>,
    deadline: Instant,
) -> Result<(), DependencyFetchSocketError> {
    timeout_at(deadline, async {
        write_frame(stream, envelope, NORMAL_FRAME_MAX_BYTES).await?;
        if let Some(archive) = archive {
            stream
                .write_all(&archive)
                .await
                .map_err(DependencyFetchSocketError::Write)?;
        }
        stream
            .shutdown()
            .await
            .map_err(DependencyFetchSocketError::Write)?;
        Ok::<_, DependencyFetchSocketError>(())
    })
    .await
    .map_err(|_| DependencyFetchSocketError::DeadlineExceeded)?
}

fn rejected(
    code: DependencyFetchRejectionCodeV1,
    retryable: bool,
) -> (DependencyFetchResponseV1, Option<Vec<u8>>) {
    (
        DependencyFetchResponseV1::Rejected { code, retryable },
        None,
    )
}

pub async fn serve_dependency_fetch_until<H, F>(
    listener: UnixListener,
    handler: Arc<H>,
    config: DependencyFetchServerConfigV1,
    shutdown: F,
) -> Result<(), DependencyFetchSocketError>
where
    H: DependencyFetchHandlerV1 + 'static,
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
                let (stream, _) = accepted.map_err(DependencyFetchSocketError::Accept)?;
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    warn!("dependency fetch connection limit reached");
                    continue;
                };
                let handler = Arc::clone(&handler);
                let config = config.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    serve_dependency_fetch_connection(stream, handler, &config).await
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
    result: Result<Result<(), DependencyFetchSocketError>, tokio::task::JoinError>,
) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!(error = %error, "dependency fetch connection rejected"),
        Err(error) => warn!(error = %error, "dependency fetch connection task failed"),
    }
}

pub struct BoundDependencyFetchSocketV1 {
    listener: Option<UnixListener>,
    cleanup: DependencyFetchSocketCleanupGuard,
}

impl BoundDependencyFetchSocketV1 {
    pub fn bind(
        path: &Path,
        required_owner_uid: u32,
        required_group_gid: u32,
    ) -> Result<Self, DependencyFetchSocketError> {
        if !is_normalized_absolute_path(path) {
            return Err(DependencyFetchSocketError::InvalidBindPath);
        }
        let parent = path
            .parent()
            .ok_or(DependencyFetchSocketError::InvalidBindPath)?;
        let metadata =
            fs::symlink_metadata(parent).map_err(DependencyFetchSocketError::BindParent)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != required_owner_uid
            || metadata.gid() != required_group_gid
            || metadata.permissions().mode() & 0o7777 != 0o750
            || required_owner_uid == 0
            || required_group_gid == 0
        {
            return Err(DependencyFetchSocketError::UnsafeBindParent);
        }
        reconcile_socket_path(path, required_owner_uid, required_group_gid)?;
        let listener = UnixListener::bind(path).map_err(DependencyFetchSocketError::Bind)?;
        let bound = fs::symlink_metadata(path).map_err(DependencyFetchSocketError::InspectPath)?;
        if !bound.file_type().is_socket()
            || bound.uid() != required_owner_uid
            || bound.gid() != required_group_gid
        {
            return Err(DependencyFetchSocketError::BoundPathNotSocket);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))
            .map_err(DependencyFetchSocketError::SetPermissions)?;
        let protected =
            fs::symlink_metadata(path).map_err(DependencyFetchSocketError::InspectPath)?;
        if !protected.file_type().is_socket()
            || protected.uid() != required_owner_uid
            || protected.gid() != required_group_gid
            || protected.permissions().mode() & 0o777 != 0o660
            || protected.dev() != bound.dev()
            || protected.ino() != bound.ino()
        {
            return Err(DependencyFetchSocketError::BoundPathNotSocket);
        }
        Ok(Self {
            listener: Some(listener),
            cleanup: DependencyFetchSocketCleanupGuard {
                path: path.to_owned(),
                device: protected.dev(),
                inode: protected.ino(),
            },
        })
    }

    pub fn take_listener(&mut self) -> UnixListener {
        self.listener
            .take()
            .expect("bound dependency fetch listener can only be taken once")
    }

    pub fn path(&self) -> &Path {
        &self.cleanup.path
    }
}

fn reconcile_socket_path(
    path: &Path,
    required_owner_uid: u32,
    required_group_gid: u32,
) -> Result<(), DependencyFetchSocketError> {
    match fs::symlink_metadata(path) {
        Ok(existing) => {
            if !existing.file_type().is_socket()
                || existing.uid() != required_owner_uid
                || existing.gid() != required_group_gid
                || existing.permissions().mode() & 0o777 != 0o660
            {
                return Err(DependencyFetchSocketError::SocketPathExists);
            }
            match StdUnixStream::connect(path) {
                Ok(stream) => {
                    let _ = stream.shutdown(Shutdown::Both);
                    return Err(DependencyFetchSocketError::SocketPathExists);
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(error) => return Err(DependencyFetchSocketError::InspectStaleSocket(error)),
            }
            let rechecked =
                fs::symlink_metadata(path).map_err(DependencyFetchSocketError::InspectPath)?;
            if !rechecked.file_type().is_socket()
                || rechecked.dev() != existing.dev()
                || rechecked.ino() != existing.ino()
            {
                return Err(DependencyFetchSocketError::SocketPathChanged);
            }
            fs::remove_file(path).map_err(DependencyFetchSocketError::RemoveStaleSocket)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(DependencyFetchSocketError::InspectPath(error)),
    }
    Ok(())
}

struct DependencyFetchSocketCleanupGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for DependencyFetchSocketCleanupGuard {
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

#[derive(Clone)]
pub struct CratesIoHttpFetcherV1 {
    client: reqwest::Client,
    origin: Url,
}

impl CratesIoHttpFetcherV1 {
    pub fn new(request_timeout: Duration) -> Result<Self, DependencyFetchHttpConfigError> {
        if !valid_request_timeout(request_timeout) {
            return Err(DependencyFetchHttpConfigError::InvalidTimeout);
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(PublicDependencyResolver))
            .connect_timeout(Duration::from_secs(5))
            .timeout(request_timeout)
            .user_agent("rdashboard-dependency-fetcher/1")
            .build()
            .map_err(|_| DependencyFetchHttpConfigError::HttpClient)?;
        let origin = Url::parse(CRATES_IO_ORIGIN)
            .map_err(|_| DependencyFetchHttpConfigError::InvalidOrigin)?;
        Ok(Self { client, origin })
    }

    fn package_url(
        &self,
        package: &CargoRegistryPackageV1,
    ) -> Result<Url, DependencyFetchFailureV1> {
        package.validate().map_err(|_| {
            DependencyFetchFailureV1::new(DependencyFetchRejectionCodeV1::InvalidRequest, false)
        })?;
        let mut url = self.origin.clone();
        url.path_segments_mut()
            .map_err(|()| {
                DependencyFetchFailureV1::new(
                    DependencyFetchRejectionCodeV1::CrateUnavailable,
                    false,
                )
            })?
            .pop_if_empty()
            .push(&package.name)
            .push(&package.archive_file_name());
        Ok(url)
    }

    async fn fetch_http(
        &self,
        package: &CargoRegistryPackageV1,
    ) -> Result<Vec<u8>, DependencyFetchFailureV1> {
        let url = self.package_url(package)?;
        let response = self.client.get(url).send().await.map_err(|_| {
            DependencyFetchFailureV1::new(DependencyFetchRejectionCodeV1::CrateUnavailable, true)
        })?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(http_failure(status));
        }
        if response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length == 0 || length > CRATE_ARCHIVE_MAX_BYTES)
        {
            return Err(DependencyFetchFailureV1::new(
                DependencyFetchRejectionCodeV1::ArchiveTooLarge,
                false,
            ));
        }
        let mut archive = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| {
                DependencyFetchFailureV1::new(
                    DependencyFetchRejectionCodeV1::CrateUnavailable,
                    true,
                )
            })?;
            if archive.len().saturating_add(chunk.len()) > CRATE_ARCHIVE_MAX_BYTES {
                return Err(DependencyFetchFailureV1::new(
                    DependencyFetchRejectionCodeV1::ArchiveTooLarge,
                    false,
                ));
            }
            archive.extend_from_slice(&chunk);
        }
        if archive.is_empty() || EvidenceDigest::sha256(&archive) != package.checksum {
            return Err(DependencyFetchFailureV1::new(
                DependencyFetchRejectionCodeV1::IntegrityMismatch,
                false,
            ));
        }
        Ok(archive)
    }
}

impl DependencyFetchHandlerV1 for CratesIoHttpFetcherV1 {
    fn fetch_crate(
        &self,
        package: CargoRegistryPackageV1,
    ) -> BoxFuture<'_, Result<Vec<u8>, DependencyFetchFailureV1>> {
        async move { self.fetch_http(&package).await }.boxed()
    }

    fn fetch_oci_object(
        &self,
        _object: OciRegistryObjectV1,
    ) -> BoxFuture<'_, Result<Vec<u8>, DependencyFetchFailureV1>> {
        std::future::ready(Err(DependencyFetchFailureV1::new(
            DependencyFetchRejectionCodeV1::InvalidRequest,
            false,
        )))
        .boxed()
    }
}

#[derive(Clone)]
pub struct PublicDependencyHttpFetcherV1 {
    crates_io: CratesIoHttpFetcherV1,
    docker_hub: DockerHubHttpFetcherV1,
}

impl PublicDependencyHttpFetcherV1 {
    pub fn new(request_timeout: Duration) -> Result<Self, DependencyFetchHttpConfigError> {
        Ok(Self {
            crates_io: CratesIoHttpFetcherV1::new(request_timeout)?,
            docker_hub: DockerHubHttpFetcherV1::new(request_timeout)?,
        })
    }
}

impl DependencyFetchHandlerV1 for PublicDependencyHttpFetcherV1 {
    fn fetch_crate(
        &self,
        package: CargoRegistryPackageV1,
    ) -> BoxFuture<'_, Result<Vec<u8>, DependencyFetchFailureV1>> {
        self.crates_io.fetch_crate(package)
    }

    fn fetch_oci_object(
        &self,
        object: OciRegistryObjectV1,
    ) -> BoxFuture<'_, Result<Vec<u8>, DependencyFetchFailureV1>> {
        async move { self.docker_hub.fetch_http(&object).await }.boxed()
    }
}

#[derive(Clone)]
struct DockerHubHttpFetcherV1 {
    client: reqwest::Client,
    registry_origin: Url,
    auth_origin: Url,
}

impl DockerHubHttpFetcherV1 {
    fn new(request_timeout: Duration) -> Result<Self, DependencyFetchHttpConfigError> {
        if !valid_request_timeout(request_timeout) {
            return Err(DependencyFetchHttpConfigError::InvalidTimeout);
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(PublicDependencyResolver))
            .connect_timeout(Duration::from_secs(5))
            .timeout(request_timeout)
            .user_agent("rdashboard-dependency-fetcher/2")
            .build()
            .map_err(|_| DependencyFetchHttpConfigError::HttpClient)?;
        Ok(Self {
            client,
            registry_origin: Url::parse(DOCKER_REGISTRY_ORIGIN)
                .map_err(|_| DependencyFetchHttpConfigError::InvalidOrigin)?,
            auth_origin: Url::parse(DOCKER_AUTH_ORIGIN)
                .map_err(|_| DependencyFetchHttpConfigError::InvalidOrigin)?,
        })
    }

    fn object_url(&self, object: &OciRegistryObjectV1) -> Result<Url, DependencyFetchFailureV1> {
        object.validate().map_err(|_| invalid_request())?;
        let mut url = self.registry_origin.clone();
        {
            let mut path = url.path_segments_mut().map_err(|()| unavailable(false))?;
            path.pop_if_empty().push("v2");
            for component in object.repository.split('/') {
                path.push(component);
            }
            path.push(match object.kind {
                OciRegistryObjectKindV1::Manifest => "manifests",
                OciRegistryObjectKindV1::Blob => "blobs",
            });
            path.push(object.digest.as_str());
        }
        Ok(url)
    }

    fn token_url(&self, repository: &str) -> Result<Url, DependencyFetchFailureV1> {
        if repository.is_empty() {
            return Err(invalid_request());
        }
        let mut url = self.auth_origin.clone();
        url.query_pairs_mut()
            .append_pair("service", "registry.docker.io")
            .append_pair("scope", &format!("repository:{repository}:pull"));
        Ok(url)
    }

    async fn token(&self, repository: &str) -> Result<String, DependencyFetchFailureV1> {
        let response = self
            .client
            .get(self.token_url(repository)?)
            .send()
            .await
            .map_err(|_| unavailable(true))?;
        if response.status() != StatusCode::OK {
            return Err(unavailable(response.status().is_server_error()));
        }
        let bytes = read_bounded_response(response, DOCKER_TOKEN_MAX_BYTES as u64).await?;
        let document: DockerTokenResponse =
            serde_json::from_slice(&bytes).map_err(|_| unavailable(false))?;
        let token = document
            .token
            .or(document.access_token)
            .ok_or_else(|| unavailable(false))?;
        if token.is_empty()
            || token.len() > 16 * 1024
            || token.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(unavailable(false));
        }
        Ok(token)
    }

    async fn fetch_http(
        &self,
        object: &OciRegistryObjectV1,
    ) -> Result<Vec<u8>, DependencyFetchFailureV1> {
        let url = self.object_url(object)?;
        let token = self.token(&object.repository).await?;
        let mut request = self
            .client
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {token}"));
        if object.kind == OciRegistryObjectKindV1::Manifest {
            request = request.header(ACCEPT, HeaderValue::from_static(OCI_MANIFEST_ACCEPT));
        }
        let mut response = request.send().await.map_err(|_| unavailable(true))?;
        if object.kind == OciRegistryObjectKindV1::Blob
            && response.status() == StatusCode::TEMPORARY_REDIRECT
        {
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| Url::parse(value).ok())
                .filter(valid_docker_blob_redirect)
                .ok_or_else(|| unavailable(false))?;
            response = self
                .client
                .get(location)
                .send()
                .await
                .map_err(|_| unavailable(true))?;
        }
        let status = response.status();
        if status != StatusCode::OK {
            return Err(oci_http_failure(status));
        }
        if response
            .headers()
            .get("docker-content-digest")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|digest| digest != object.digest.as_str())
        {
            return Err(DependencyFetchFailureV1::new(
                DependencyFetchRejectionCodeV1::IntegrityMismatch,
                false,
            ));
        }
        let bytes = read_bounded_response(response, object.maximum_bytes).await?;
        let length = u64::try_from(bytes.len()).map_err(|_| unavailable(false))?;
        if object
            .expected_bytes
            .is_some_and(|expected| expected != length)
            || EvidenceDigest::sha256(&bytes).as_str() != object.digest.hex()
        {
            return Err(DependencyFetchFailureV1::new(
                DependencyFetchRejectionCodeV1::IntegrityMismatch,
                false,
            ));
        }
        Ok(bytes)
    }
}

fn valid_docker_blob_redirect(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url
            .host_str()
            .is_some_and(|host| host.ends_with(".docker.com"))
        && !url.path().is_empty()
}

#[derive(Deserialize)]
struct DockerTokenResponse {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
}

async fn read_bounded_response(
    response: reqwest::Response,
    maximum_bytes: u64,
) -> Result<Vec<u8>, DependencyFetchFailureV1> {
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length == 0 || length > maximum_bytes)
    {
        return Err(DependencyFetchFailureV1::new(
            DependencyFetchRejectionCodeV1::OciObjectTooLarge,
            false,
        ));
    }
    let maximum = usize::try_from(maximum_bytes).map_err(|_| unavailable(false))?;
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| unavailable(true))?;
        if bytes.len().saturating_add(chunk.len()) > maximum {
            return Err(DependencyFetchFailureV1::new(
                DependencyFetchRejectionCodeV1::OciObjectTooLarge,
                false,
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err(unavailable(false));
    }
    Ok(bytes)
}

fn invalid_request() -> DependencyFetchFailureV1 {
    DependencyFetchFailureV1::new(DependencyFetchRejectionCodeV1::InvalidRequest, false)
}

fn unavailable(retryable: bool) -> DependencyFetchFailureV1 {
    DependencyFetchFailureV1::new(
        DependencyFetchRejectionCodeV1::OciObjectUnavailable,
        retryable,
    )
}

fn oci_http_failure(status: StatusCode) -> DependencyFetchFailureV1 {
    if status == StatusCode::NOT_FOUND {
        DependencyFetchFailureV1::new(DependencyFetchRejectionCodeV1::OciObjectNotFound, false)
    } else {
        unavailable(status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
    }
}

fn http_failure(status: StatusCode) -> DependencyFetchFailureV1 {
    if status == StatusCode::NOT_FOUND {
        DependencyFetchFailureV1::new(DependencyFetchRejectionCodeV1::CrateNotFound, false)
    } else {
        DependencyFetchFailureV1::new(
            DependencyFetchRejectionCodeV1::CrateUnavailable,
            status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
        )
    }
}

struct PublicDependencyResolver;

impl reqwest::dns::Resolve for PublicDependencyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            if host != "static.crates.io"
                && host != "registry-1.docker.io"
                && host != "auth.docker.io"
                && !host.ends_with(".docker.com")
            {
                return Err::<reqwest::dns::Addrs, _>(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "dependency fetch DNS name is not allowlisted",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            let addresses = tokio::net::lookup_host((host.as_str(), 443))
                .await
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?
                .filter(|address| public_ip(address.ip()))
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "dependency fetch DNS returned no public address",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => public_ipv4(address),
        IpAddr::V6(address) => public_ipv6(address),
    }
}

fn public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_unspecified()
        && !address.is_broadcast()
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 192 && b == 0 && c == 0)
        && !(a == 192 && b == 0 && c == 2)
        && !(a == 198 && (b == 18 || b == 19))
        && !(a == 198 && b == 51 && c == 100)
        && !(a == 203 && b == 0 && c == 113)
        && a < 224
        && a != 0
}

fn public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let denied = address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8);
    !denied && address.to_ipv4_mapped().is_none_or(public_ipv4)
}

fn valid_request_timeout(timeout: Duration) -> bool {
    timeout >= Duration::from_millis(MIN_REQUEST_TIMEOUT_MS)
        && timeout <= Duration::from_millis(MAX_REQUEST_TIMEOUT_MS)
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
pub enum DependencyFetchValidationError {
    #[error("unsupported dependency fetch protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("dependency fetch request ID must not be nil")]
    NilRequestId,
    #[error("dependency fetch version set must contain 1-8 entries")]
    InvalidVersionSet,
    #[error("dependency fetch package identity is invalid")]
    InvalidPackage,
    #[error("dependency fetch OCI object identity is invalid")]
    InvalidOciObject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DependencyFetchServerConfigError {
    #[error("dependency fetch server configuration is invalid")]
    InvalidConfiguration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DependencyFetchHttpConfigError {
    #[error("dependency fetch timeout is invalid")]
    InvalidTimeout,
    #[error("dependency fetch HTTP client could not be built")]
    HttpClient,
    #[error("fixed public dependency origin is invalid")]
    InvalidOrigin,
}

#[derive(Debug, thiserror::Error)]
pub enum DependencyFetchClientError {
    #[error("dependency fetch client configuration is invalid")]
    InvalidConfiguration,
    #[error("dependency fetch package identity is invalid")]
    InvalidPackage,
    #[error("dependency fetch OCI object identity is invalid")]
    InvalidOciObject,
    #[error("dependency fetch server uid {received} is not authorized")]
    UnauthorizedServer { received: u32 },
    #[error("dependency fetch request exceeded its deadline")]
    DeadlineExceeded,
    #[error("dependency fetch request was rejected as {code:?}; retryable={retryable}")]
    Rejected {
        code: DependencyFetchRejectionCodeV1,
        retryable: bool,
    },
    #[error("dependency fetch response is invalid")]
    InvalidResponse,
    #[error("dependency fetch peer credentials failed: {0}")]
    PeerCredentials(io::Error),
    #[error("dependency fetch transport failed: {0}")]
    Io(io::Error),
    #[error("dependency fetch frame failed: {0}")]
    Frame(#[from] FrameError),
}

#[derive(Debug, thiserror::Error)]
pub enum DependencyFetchSocketError {
    #[error("dependency fetch socket path is invalid")]
    InvalidBindPath,
    #[error("dependency fetch socket parent could not be inspected: {0}")]
    BindParent(io::Error),
    #[error("dependency fetch socket parent is unsafe")]
    UnsafeBindParent,
    #[error("dependency fetch socket path already exists")]
    SocketPathExists,
    #[error("dependency fetch stale socket could not be inspected: {0}")]
    InspectStaleSocket(io::Error),
    #[error("dependency fetch socket path could not be inspected: {0}")]
    InspectPath(io::Error),
    #[error("dependency fetch socket changed during reconciliation")]
    SocketPathChanged,
    #[error("dependency fetch stale socket could not be removed: {0}")]
    RemoveStaleSocket(io::Error),
    #[error("dependency fetch socket bind failed: {0}")]
    Bind(io::Error),
    #[error("dependency fetch bound path is not the expected socket")]
    BoundPathNotSocket,
    #[error("dependency fetch socket permissions could not be set: {0}")]
    SetPermissions(io::Error),
    #[error("dependency fetch socket accept failed: {0}")]
    Accept(io::Error),
    #[error("dependency fetch peer credentials failed: {0}")]
    PeerCredentials(io::Error),
    #[error("dependency fetch peer uid {received} is not authorized")]
    UnauthorizedPeer { received: u32 },
    #[error("dependency fetch connection exceeded its deadline")]
    DeadlineExceeded,
    #[error("dependency fetch handler returned an invalid archive")]
    InvalidHandlerResponse,
    #[error("dependency fetch response write failed: {0}")]
    Write(io::Error),
    #[error("dependency fetch frame failed: {0}")]
    Frame(#[from] FrameError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr as _;

    #[derive(Clone)]
    struct StaticHandler {
        archive: Vec<u8>,
    }

    impl DependencyFetchHandlerV1 for StaticHandler {
        fn fetch_crate(
            &self,
            _package: CargoRegistryPackageV1,
        ) -> BoxFuture<'_, Result<Vec<u8>, DependencyFetchFailureV1>> {
            std::future::ready(Ok(self.archive.clone())).boxed()
        }

        fn fetch_oci_object(
            &self,
            _object: OciRegistryObjectV1,
        ) -> BoxFuture<'_, Result<Vec<u8>, DependencyFetchFailureV1>> {
            std::future::ready(Ok(self.archive.clone())).boxed()
        }
    }

    fn package(archive: &[u8]) -> CargoRegistryPackageV1 {
        CargoRegistryPackageV1 {
            name: "demo-crate".to_owned(),
            version: "1.2.3".to_owned(),
            checksum: EvidenceDigest::sha256(archive),
        }
    }

    #[tokio::test]
    async fn peer_authenticated_protocol_returns_only_the_exact_archive() {
        let archive = b"exact crate archive".to_vec();
        let package = package(&archive);
        let directory = tempfile::TempDir::new().expect("temporary directory");
        let socket_path = directory.path().join("fetch.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind test socket");
        let server_uid = fs::metadata(directory.path()).expect("metadata").uid();
        let handler = Arc::new(StaticHandler {
            archive: archive.clone(),
        });
        let config = DependencyFetchServerConfigV1::new(server_uid, 1, Duration::from_secs(2))
            .expect("server config");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                serve_dependency_fetch_connection(stream, Arc::clone(&handler), &config)
                    .await
                    .expect("serve request");
            }
        });
        let client = DependencyFetchClientV1::new(socket_path, server_uid, Duration::from_secs(2))
            .expect("client");
        assert_eq!(
            client
                .fetch_crate(&package)
                .await
                .expect("fetch exact crate"),
            archive
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn peer_authenticated_protocol_returns_only_the_exact_oci_object() {
        let bytes = b"exact OCI manifest".to_vec();
        let object = OciRegistryObjectV1 {
            repository: "library/debian".to_owned(),
            digest: format!("sha256:{}", EvidenceDigest::sha256(&bytes))
                .parse()
                .expect("OCI digest"),
            kind: OciRegistryObjectKindV1::Manifest,
            maximum_bytes: crate::oci_base::OCI_MANIFEST_MAX_BYTES,
            expected_bytes: None,
        };
        let directory = tempfile::TempDir::new().expect("temporary directory");
        let socket_path = directory.path().join("fetch.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind test socket");
        let server_uid = fs::metadata(directory.path()).expect("metadata").uid();
        let handler = Arc::new(StaticHandler {
            archive: bytes.clone(),
        });
        let config = DependencyFetchServerConfigV1::new(server_uid, 1, Duration::from_secs(2))
            .expect("server config");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                serve_dependency_fetch_connection(stream, Arc::clone(&handler), &config)
                    .await
                    .expect("serve request");
            }
        });
        let client = DependencyFetchClientV1::new(socket_path, server_uid, Duration::from_secs(2))
            .expect("client");
        assert_eq!(
            client
                .fetch_oci_object(&object)
                .await
                .expect("fetch exact OCI object"),
            bytes
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn server_checks_peer_uid_before_decoding() {
        let (client, server) = UnixStream::pair().expect("socket pair");
        let peer_uid = server.peer_cred().expect("peer credentials").uid();
        let config =
            DependencyFetchServerConfigV1::new(peer_uid.wrapping_add(1), 1, Duration::from_secs(1))
                .expect("server config");
        drop(client);
        assert!(matches!(
            serve_dependency_fetch_connection(
                server,
                Arc::new(StaticHandler { archive: Vec::new() }),
                &config
            )
            .await,
            Err(DependencyFetchSocketError::UnauthorizedPeer { received }) if received == peer_uid
        ));
    }

    #[test]
    fn fixed_url_cannot_be_redirected_by_package_fields() {
        let fetcher = CratesIoHttpFetcherV1::new(Duration::from_secs(5)).expect("fetcher");
        let package = CargoRegistryPackageV1 {
            name: "demo-crate".to_owned(),
            version: "1.2.3".to_owned(),
            checksum: EvidenceDigest::from_str(&"a".repeat(64)).expect("checksum"),
        };
        assert_eq!(
            fetcher.package_url(&package).expect("fixed URL").as_str(),
            "https://static.crates.io/crates/demo-crate/demo-crate-1.2.3.crate"
        );
        let mut invalid = package;
        invalid.name = "../escape".to_owned();
        assert!(fetcher.package_url(&invalid).is_err());
    }

    #[test]
    fn docker_hub_urls_are_derived_only_from_validated_repository_and_digest() {
        let fetcher = DockerHubHttpFetcherV1::new(Duration::from_secs(5)).expect("fetcher");
        let object = OciRegistryObjectV1 {
            repository: "library/debian".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64))
                .parse()
                .expect("OCI digest"),
            kind: OciRegistryObjectKindV1::Manifest,
            maximum_bytes: crate::oci_base::OCI_MANIFEST_MAX_BYTES,
            expected_bytes: None,
        };
        assert_eq!(
            fetcher.object_url(&object).expect("object URL").as_str(),
            format!(
                "https://registry-1.docker.io/v2/library/debian/manifests/sha256:{}",
                "a".repeat(64)
            )
        );
        assert_eq!(
            fetcher
                .token_url("library/debian")
                .expect("token URL")
                .as_str(),
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fdebian%3Apull"
        );
        let mut invalid = object;
        invalid.repository = "../escape".to_owned();
        assert!(fetcher.object_url(&invalid).is_err());
        assert!(valid_docker_blob_redirect(
            &Url::parse("https://production.cloudflare.docker.com/registry-v2/blob?signature=x")
                .expect("Docker CDN URL")
        ));
        for denied in [
            "http://production.cloudflare.docker.com/blob",
            "https://example.com/blob",
            "https://production.cloudflare.docker.com.evil.example/blob",
            "https://user@production.cloudflare.docker.com/blob",
        ] {
            assert!(!valid_docker_blob_redirect(
                &Url::parse(denied).expect("denied redirect URL")
            ));
        }
    }

    #[test]
    fn resolver_rejects_private_loopback_link_local_and_documentation_routes() {
        for denied in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!public_ip(denied.parse().expect("test IP")), "{denied}");
        }
        for allowed in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public_ip(allowed.parse().expect("test IP")), "{allowed}");
        }
    }

    #[tokio::test]
    #[ignore = "requires live anonymous Docker Hub access"]
    async fn live_docker_hub_fetches_the_exact_pinned_manifest_config_and_layer() {
        let fetcher = PublicDependencyHttpFetcherV1::new(Duration::from_secs(30))
            .expect("public dependency fetcher");
        let manifest_object = OciRegistryObjectV1 {
            repository: "library/debian".to_owned(),
            digest: "sha256:9bb8a3626890e084ab54e888fdd7c4b6d2f119071cd4c5dc5fecb4d73062aa5f"
                .parse()
                .expect("manifest digest"),
            kind: OciRegistryObjectKindV1::Manifest,
            maximum_bytes: crate::oci_base::OCI_MANIFEST_MAX_BYTES,
            expected_bytes: None,
        };
        let manifest = fetcher
            .fetch_oci_object(manifest_object)
            .await
            .expect("fetch exact manifest");
        let document: serde_json::Value = serde_json::from_slice(&manifest).expect("manifest JSON");
        assert!(matches!(
            document["mediaType"].as_str(),
            Some(
                "application/vnd.oci.image.manifest.v1+json"
                    | "application/vnd.docker.distribution.manifest.v2+json"
            )
        ));
        let config = &document["config"];
        let config_object = OciRegistryObjectV1 {
            repository: "library/debian".to_owned(),
            digest: config["digest"]
                .as_str()
                .expect("config digest")
                .parse()
                .expect("valid config digest"),
            kind: OciRegistryObjectKindV1::Blob,
            maximum_bytes: config["size"].as_u64().expect("config size"),
            expected_bytes: Some(config["size"].as_u64().expect("config size")),
        };
        let config = fetcher
            .fetch_oci_object(config_object)
            .await
            .expect("fetch exact config blob");
        let config: serde_json::Value = serde_json::from_slice(&config).expect("config JSON");
        assert_eq!(config["architecture"], "amd64");
        assert_eq!(config["os"], "linux");
        let layer = &document["layers"][0];
        let layer_bytes = layer["size"].as_u64().expect("layer size");
        let layer_object = OciRegistryObjectV1 {
            repository: "library/debian".to_owned(),
            digest: layer["digest"]
                .as_str()
                .expect("layer digest")
                .parse()
                .expect("valid layer digest"),
            kind: OciRegistryObjectKindV1::Blob,
            maximum_bytes: layer_bytes,
            expected_bytes: Some(layer_bytes),
        };
        assert_eq!(
            u64::try_from(
                fetcher
                    .fetch_oci_object(layer_object)
                    .await
                    .expect("fetch exact layer blob")
                    .len()
            )
            .expect("layer byte count"),
            layer_bytes
        );
    }
}
