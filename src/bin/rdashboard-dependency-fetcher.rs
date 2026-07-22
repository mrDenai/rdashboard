use std::{
    ffi::OsString,
    future::Future,
    io,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    sync::Arc,
    time::Duration,
};

use rdashboard::dependency_fetch::{
    BoundDependencyFetchSocketV1, DEPENDENCY_FETCH_SOCKET_PATH, DependencyFetchServerConfigV1,
    PublicDependencyHttpFetcherV1, serve_dependency_fetch_until,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

const FETCHER_UID_ENV: &str = "RDASHBOARD_DEPENDENCY_FETCHER_UID";
const FETCH_GROUP_GID_ENV: &str = "RDASHBOARD_DEPENDENCY_FETCH_GID";
const WORKER_UID_ENV: &str = "RDASHBOARD_WORKER_UID";
const MAX_CONNECTIONS: usize = 4;
const SERVER_REQUEST_TIMEOUT: Duration = Duration::from_mins(1);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
type DynError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    if std::env::args_os().len() != 1 {
        return Err(DependencyFetcherServiceError::InvalidInvocation.into());
    }
    init_tracing()?;
    let fetcher_uid = configured_id(FETCHER_UID_ENV, std::env::var_os(FETCHER_UID_ENV))?;
    let fetch_group_gid =
        configured_id(FETCH_GROUP_GID_ENV, std::env::var_os(FETCH_GROUP_GID_ENV))?;
    let worker_uid = configured_id(WORKER_UID_ENV, std::env::var_os(WORKER_UID_ENV))?;
    if fetcher_uid == worker_uid {
        return Err(DependencyFetcherServiceError::IdentityCollision.into());
    }
    let handler = Arc::new(PublicDependencyHttpFetcherV1::new(HTTP_REQUEST_TIMEOUT)?);
    let config =
        DependencyFetchServerConfigV1::new(worker_uid, MAX_CONNECTIONS, SERVER_REQUEST_TIMEOUT)?;
    let socket_path = Path::new(DEPENDENCY_FETCH_SOCKET_PATH);
    let parent = socket_path
        .parent()
        .ok_or(DependencyFetcherServiceError::UnsafeRuntimeDirectory)?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != fetcher_uid
        || metadata.gid() != fetch_group_gid
        || metadata.permissions().mode() & 0o7777 != 0o750
    {
        return Err(DependencyFetcherServiceError::UnsafeRuntimeDirectory.into());
    }
    let mut socket = BoundDependencyFetchSocketV1::bind(socket_path, fetcher_uid, fetch_group_gid)?;
    let listener = socket.take_listener();
    info!(
        socket = %socket.path().display(),
        worker_uid,
        max_connections = MAX_CONNECTIONS,
        "fixed public dependency fetcher listening"
    );
    serve_dependency_fetch_until(listener, handler, config, shutdown_signal()?).await?;
    Ok(())
}

fn configured_id(
    name: &'static str,
    value: Option<OsString>,
) -> Result<u32, DependencyFetcherServiceError> {
    let value = value.ok_or(DependencyFetcherServiceError::MissingEnvironment(name))?;
    let value = value
        .into_string()
        .map_err(|_| DependencyFetcherServiceError::InvalidEnvironment(name))?;
    let parsed = value
        .parse::<u32>()
        .map_err(|_| DependencyFetcherServiceError::InvalidEnvironment(name))?;
    if parsed == 0 || parsed == u32::MAX {
        return Err(DependencyFetcherServiceError::InvalidEnvironment(name));
    }
    Ok(parsed)
}

fn init_tracing() -> Result<(), DynError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()?;
    Ok(())
}

fn shutdown_signal() -> Result<impl Future<Output = ()>, io::Error> {
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
enum DependencyFetcherServiceError {
    #[error("rdashboard-dependency-fetcher accepts no command-line arguments")]
    InvalidInvocation,
    #[error("required environment variable {0} is missing")]
    MissingEnvironment(&'static str),
    #[error("environment variable {0} is invalid")]
    InvalidEnvironment(&'static str),
    #[error("dependency fetcher and worker must use separate Unix identities")]
    IdentityCollision,
    #[error("dependency fetcher runtime directory is unsafe")]
    UnsafeRuntimeDirectory,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_id_configuration_is_strict() {
        assert_eq!(
            configured_id(FETCHER_UID_ENV, Some(OsString::from("991"))),
            Ok(991)
        );
        for invalid in [None, Some(OsString::from("0")), Some(OsString::from("uid"))] {
            assert!(configured_id(FETCHER_UID_ENV, invalid).is_err());
        }
        assert!(
            configured_id(
                FETCH_GROUP_GID_ENV,
                Some(OsString::from(u32::MAX.to_string()))
            )
            .is_err()
        );
    }
}
