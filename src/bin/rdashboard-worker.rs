use std::{collections::BTreeSet, ffi::OsString, future::Future, io, sync::Arc, time::Duration};

use rdashboard::{
    build_source::{BUILD_SOURCE_EXPORT_ROOT, SourceArchiveReaderV1},
    dependency_fetch::DependencyFetchClientV1,
    domain::WorkflowWorkerPoolV1,
    preparation::{PREPARATION_STORE_ROOT, PreparationStore},
    scheduler::WorkflowWorkerRegistrationV1,
    worker_socket::WorkflowWorkerClientV1,
    workflow_launcher_socket::WorkflowLauncherClientV1,
    workflow_worker::{
        WorkflowHostPreparerV1, WorkflowWorkerRuntimeConfigV1, WorkflowWorkerRuntimeV1,
    },
};
use tracing::info;
use tracing_subscriber::EnvFilter;

const WORKER_UID_ENV: &str = "RDASHBOARD_WORKER_UID";
const WORKER_ID_ENV: &str = "RDASHBOARD_WORKER_ID";
const WORKER_HOST_ID_ENV: &str = "RDASHBOARD_WORKER_HOST_ID";
const WORKER_SLOTS_ENV: &str = "RDASHBOARD_WORKER_SLOTS";
const SOURCE_UID_ENV: &str = "RDASHBOARD_SOURCE_UID";
const BUILD_READER_GID_ENV: &str = "RDASHBOARD_BUILD_READER_GID";
const DEPENDENCY_FETCHER_UID_ENV: &str = "RDASHBOARD_DEPENDENCY_FETCHER_UID";
const GATEWAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const LAUNCHER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEPENDENCY_FETCH_TIMEOUT: Duration = Duration::from_mins(1);
type DynError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    if std::env::args_os().len() != 1 {
        return Err(WorkerServiceError::InvalidInvocation.into());
    }
    init_tracing()?;
    let shutdown = shutdown_signal()?;
    let worker_uid = configured_id(WORKER_UID_ENV, std::env::var_os(WORKER_UID_ENV))?;
    let source_uid = configured_id(SOURCE_UID_ENV, std::env::var_os(SOURCE_UID_ENV))?;
    let build_reader_gid =
        configured_id(BUILD_READER_GID_ENV, std::env::var_os(BUILD_READER_GID_ENV))?;
    let dependency_fetcher_uid = configured_optional_id(
        DEPENDENCY_FETCHER_UID_ENV,
        std::env::var_os(DEPENDENCY_FETCHER_UID_ENV),
    )?;
    let registration = configured_registration(
        std::env::var_os(WORKER_ID_ENV),
        std::env::var_os(WORKER_HOST_ID_ENV),
    )?;
    let slots = configured_slots(std::env::var_os(WORKER_SLOTS_ENV))?;
    let gateway = Arc::new(WorkflowWorkerClientV1::installed(
        GATEWAY_REQUEST_TIMEOUT,
        registration.clone(),
    )?);
    let launcher = Arc::new(WorkflowLauncherClientV1::installed(
        LAUNCHER_REQUEST_TIMEOUT,
    )?);
    let source_reader =
        SourceArchiveReaderV1::open(BUILD_SOURCE_EXPORT_ROOT, source_uid, build_reader_gid)?;
    let preparation_store = PreparationStore::open_for_owner(PREPARATION_STORE_ROOT, worker_uid)?;
    let preparer = Arc::new(WorkflowHostPreparerV1::new(
        preparation_store,
        source_reader,
    ));
    let mut runtime = WorkflowWorkerRuntimeV1::new(
        registration.clone(),
        gateway,
        launcher,
        preparer,
        WorkflowWorkerRuntimeConfigV1::production(slots)?,
    )?;
    if let Some(fetcher_uid) = dependency_fetcher_uid {
        runtime = runtime.with_dependency_fetcher(Arc::new(DependencyFetchClientV1::installed(
            fetcher_uid,
            DEPENDENCY_FETCH_TIMEOUT,
        )?));
    }
    info!(
        worker_id = %registration.worker_id,
        host_id = %registration.host_id,
        worker_uid,
        slots,
        dependency_fetcher_configured = dependency_fetcher_uid.is_some(),
        preparation_root = PREPARATION_STORE_ROOT,
        "generic workflow worker started"
    );
    runtime.run_until(shutdown).await?;
    Ok(())
}

fn configured_registration(
    worker_id: Option<OsString>,
    host_id: Option<OsString>,
) -> Result<WorkflowWorkerRegistrationV1, WorkerServiceError> {
    let registration = WorkflowWorkerRegistrationV1 {
        worker_id: configured_identity(WORKER_ID_ENV, worker_id)?,
        host_id: configured_identity(WORKER_HOST_ID_ENV, host_id)?,
        pools: BTreeSet::from([
            WorkflowWorkerPoolV1::VpsRequired,
            WorkflowWorkerPoolV1::BuildCompute,
        ]),
    };
    registration
        .validate_unprivileged()
        .map_err(|_| WorkerServiceError::InvalidIdentity)?;
    Ok(registration)
}

fn configured_identity(
    name: &'static str,
    value: Option<OsString>,
) -> Result<String, WorkerServiceError> {
    value
        .ok_or(WorkerServiceError::MissingEnvironment(name))?
        .into_string()
        .map_err(|_| WorkerServiceError::InvalidEnvironment(name))
}

fn configured_id(name: &'static str, value: Option<OsString>) -> Result<u32, WorkerServiceError> {
    let parsed = configured_identity(name, value)?
        .parse::<u32>()
        .map_err(|_| WorkerServiceError::InvalidEnvironment(name))?;
    if parsed == 0 || parsed == u32::MAX {
        return Err(WorkerServiceError::InvalidEnvironment(name));
    }
    Ok(parsed)
}

fn configured_optional_id(
    name: &'static str,
    value: Option<OsString>,
) -> Result<Option<u32>, WorkerServiceError> {
    value
        .map(|value| configured_id(name, Some(value)))
        .transpose()
}

fn configured_slots(value: Option<OsString>) -> Result<usize, WorkerServiceError> {
    configured_identity(WORKER_SLOTS_ENV, value)?
        .parse::<usize>()
        .map_err(|_| WorkerServiceError::InvalidEnvironment(WORKER_SLOTS_ENV))
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
enum WorkerServiceError {
    #[error("rdashboard-worker accepts no command-line arguments")]
    InvalidInvocation,
    #[error("required environment variable {0} is missing")]
    MissingEnvironment(&'static str),
    #[error("environment variable {0} is invalid")]
    InvalidEnvironment(&'static str),
    #[error("workflow worker identity is invalid")]
    InvalidIdentity,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_identity_configuration_is_strict() {
        assert_eq!(
            configured_id(WORKER_UID_ENV, Some(OsString::from("992"))),
            Ok(992)
        );
        for invalid in [None, Some(OsString::from("0")), Some(OsString::from("uid"))] {
            assert!(configured_id(WORKER_UID_ENV, invalid).is_err());
        }
        assert!(configured_id(WORKER_UID_ENV, Some(OsString::from(u32::MAX.to_string()))).is_err());
        assert_eq!(
            configured_optional_id(DEPENDENCY_FETCHER_UID_ENV, None),
            Ok(None)
        );
        assert_eq!(
            configured_optional_id(DEPENDENCY_FETCHER_UID_ENV, Some(OsString::from("991"))),
            Ok(Some(991))
        );
    }

    #[test]
    fn registration_is_shared_and_rejects_repository_or_invalid_identities() {
        let registration = configured_registration(
            Some(OsString::from("shared-vps-worker-1")),
            Some(OsString::from("production-vps")),
        )
        .expect("valid shared registration");
        assert_eq!(
            registration.pools,
            BTreeSet::from([
                WorkflowWorkerPoolV1::VpsRequired,
                WorkflowWorkerPoolV1::BuildCompute,
            ])
        );
        assert!(
            configured_registration(
                Some(OsString::from("ralert worker")),
                Some(OsString::from("production-vps")),
            )
            .is_err()
        );
        assert!(
            configured_registration(Some(OsString::from("shared-vps-worker-1")), None).is_err()
        );
    }

    #[test]
    fn slot_configuration_is_required_and_runtime_bounded() {
        assert_eq!(configured_slots(Some(OsString::from("2"))), Ok(2));
        assert!(configured_slots(None).is_err());
        assert!(configured_slots(Some(OsString::from("two"))).is_err());
        assert!(WorkflowWorkerRuntimeConfigV1::production(0).is_err());
        assert!(WorkflowWorkerRuntimeConfigV1::production(17).is_err());
    }
}
