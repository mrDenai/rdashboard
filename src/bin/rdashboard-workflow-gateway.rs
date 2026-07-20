use std::{
    collections::BTreeSet,
    ffi::OsString,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    sync::Arc,
    time::Duration,
};

use rdashboard::{
    scheduler::{DurableWorkflowScheduler, WorkflowWorkerRegistrationV1},
    store::ControlStore,
    unix_time_ms,
    worker_socket::{
        BoundWorkflowWorkerSocketV1, SchedulerWorkflowWorkerHandlerV1, WORKER_SOCKET_PATH,
        WorkflowWorkerServerConfigV1, serve_worker_until,
    },
};
use tracing::info;
use tracing_subscriber::EnvFilter;

const CONTROL_STORE_PATH: &str = "/var/lib/rdashboard/control.sqlite";
const WORKER_UID_ENV: &str = "RDASHBOARD_WORKER_UID";
const WORKER_ID_ENV: &str = "RDASHBOARD_WORKER_ID";
const WORKER_HOST_ID_ENV: &str = "RDASHBOARD_WORKER_HOST_ID";
const MAX_CONNECTIONS: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const LEASE_DURATION: Duration = Duration::from_secs(15);
type DynError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    if std::env::args_os().len() != 1 {
        return Err(GatewayError::InvalidInvocation.into());
    }
    init_tracing()?;
    let allowed_uid = configured_worker_uid(std::env::var_os(WORKER_UID_ENV))?;
    let registration = configured_registration(
        std::env::var_os(WORKER_ID_ENV),
        std::env::var_os(WORKER_HOST_ID_ENV),
    )?;
    let scheduler = DurableWorkflowScheduler::new(ControlStore::open(CONTROL_STORE_PATH)?);
    let now_ms = unix_time_ms()?;
    let reconciled = scheduler.reconcile_controller_nodes(now_ms)?;
    let handler = Arc::new(SchedulerWorkflowWorkerHandlerV1::system(
        scheduler,
        registration.clone(),
        LEASE_DURATION,
    )?);
    let server_config =
        WorkflowWorkerServerConfigV1::new(allowed_uid, MAX_CONNECTIONS, REQUEST_TIMEOUT)?;
    let socket_path = Path::new(WORKER_SOCKET_PATH);
    let parent = socket_path
        .parent()
        .ok_or(GatewayError::UnsafeRuntimeDirectory)?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() == 0
        || metadata.gid() == 0
        || metadata.permissions().mode() & 0o777 != 0o750
    {
        return Err(GatewayError::UnsafeRuntimeDirectory.into());
    }
    let mut socket =
        BoundWorkflowWorkerSocketV1::bind(socket_path, metadata.uid(), metadata.gid())?;
    let listener = socket.take_listener();
    info!(
        socket = %socket.path().display(),
        worker_id = %registration.worker_id,
        host_id = %registration.host_id,
        allowed_uid,
        reconciled,
        "workflow worker gateway listening"
    );
    serve_worker_until(listener, handler, server_config, shutdown_signal()).await?;
    Ok(())
}

fn configured_worker_uid(value: Option<OsString>) -> Result<u32, GatewayError> {
    let value = value.ok_or(GatewayError::MissingWorkerUid)?;
    let value = value
        .into_string()
        .map_err(|_| GatewayError::InvalidWorkerUid)?;
    let uid = value
        .parse::<u32>()
        .map_err(|_| GatewayError::InvalidWorkerUid)?;
    if uid == 0 || uid == u32::MAX {
        return Err(GatewayError::InvalidWorkerUid);
    }
    Ok(uid)
}

fn configured_registration(
    worker_id: Option<OsString>,
    host_id: Option<OsString>,
) -> Result<WorkflowWorkerRegistrationV1, GatewayError> {
    let worker_id = configured_identity(worker_id, GatewayError::MissingWorkerId)?;
    let host_id = configured_identity(host_id, GatewayError::MissingWorkerHostId)?;
    let registration = WorkflowWorkerRegistrationV1 {
        worker_id,
        host_id,
        pools: BTreeSet::from([
            rdashboard::domain::WorkflowWorkerPoolV1::VpsRequired,
            rdashboard::domain::WorkflowWorkerPoolV1::BuildCompute,
        ]),
    };
    registration
        .validate_unprivileged()
        .map_err(|_| GatewayError::InvalidWorkerIdentity)?;
    Ok(registration)
}

fn configured_identity(
    value: Option<OsString>,
    missing: GatewayError,
) -> Result<String, GatewayError> {
    value
        .ok_or(missing)?
        .into_string()
        .map_err(|_| GatewayError::InvalidWorkerIdentity)
}

fn init_tracing() -> Result<(), DynError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()?;
    Ok(())
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
}

#[derive(Debug, thiserror::Error)]
enum GatewayError {
    #[error("workflow gateway accepts no command-line arguments")]
    InvalidInvocation,
    #[error("RDASHBOARD_WORKER_UID is required")]
    MissingWorkerUid,
    #[error("RDASHBOARD_WORKER_UID must identify a non-root Unix account")]
    InvalidWorkerUid,
    #[error("RDASHBOARD_WORKER_ID is required")]
    MissingWorkerId,
    #[error("RDASHBOARD_WORKER_HOST_ID is required")]
    MissingWorkerHostId,
    #[error("workflow worker identity is invalid")]
    InvalidWorkerIdentity,
    #[error("workflow gateway runtime directory is not protected")]
    UnsafeRuntimeDirectory,
}

#[cfg(test)]
mod tests {
    use super::{GatewayError, configured_registration, configured_worker_uid};
    use std::ffi::OsString;

    #[test]
    fn installed_worker_identity_is_fixed_non_root_and_repository_agnostic() {
        assert!(matches!(
            configured_worker_uid(Some(OsString::from("0"))),
            Err(GatewayError::InvalidWorkerUid)
        ));
        assert!(matches!(
            configured_worker_uid(None),
            Err(GatewayError::MissingWorkerUid)
        ));
        assert_eq!(
            configured_worker_uid(Some(OsString::from("992")))
                .unwrap_or_else(|error| panic!("worker UID: {error}")),
            992
        );

        let registration = configured_registration(
            Some(OsString::from("vps-worker-1")),
            Some(OsString::from("production-vps")),
        )
        .unwrap_or_else(|error| panic!("worker registration: {error}"));
        assert_eq!(registration.worker_id, "vps-worker-1");
        assert_eq!(registration.host_id, "production-vps");
        assert_eq!(registration.pools.len(), 2);
        assert!(matches!(
            configured_registration(Some(OsString::from("rimg worker")), None),
            Err(GatewayError::MissingWorkerHostId)
        ));
    }
}
