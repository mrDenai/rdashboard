use std::{
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    sync::Arc,
    time::Duration,
};

use rdashboard::{
    operation_state::WorkflowOperationStateStoreV1,
    unix_time_ms,
    workflow_launcher::{
        SystemdWorkflowLaunchRuntimeV1, WORKFLOW_LAUNCHER_JOB_ROOT, WorkflowLaunchJournalV1,
        WorkflowLaunchSupervisorV1, WorkflowLauncherPolicyV1, installed_preparation_reader,
    },
    workflow_launcher_socket::{
        BoundWorkflowLauncherSocketV1, SupervisorWorkflowLauncherHandlerV1,
        WORKFLOW_LAUNCHER_SOCKET_PATH, WorkflowLauncherServerConfigV1, serve_launcher_until,
    },
};
use tracing::info;
use tracing_subscriber::EnvFilter;

const MAX_CONNECTIONS: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
type DynError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    if std::env::args_os().len() != 1 {
        return Err(LauncherServiceError::InvalidInvocation.into());
    }
    init_tracing()?;
    let policy = WorkflowLauncherPolicyV1::load_root_owned()?;
    let preparation_reader = installed_preparation_reader(policy.worker_uid)?;
    let now_ms = unix_time_ms()?;
    let journal = WorkflowLaunchJournalV1::open_root_owned(
        WORKFLOW_LAUNCHER_JOB_ROOT,
        policy.max_journal_records,
        now_ms,
    )?;
    let operation_states = Arc::new(WorkflowOperationStateStoreV1::open_installed(
        policy.build_uid,
        policy.build_gid,
    )?);
    let supervisor = Arc::new(WorkflowLaunchSupervisorV1::new(
        policy.clone(),
        preparation_reader,
        journal,
        operation_states,
        Arc::new(SystemdWorkflowLaunchRuntimeV1),
    )?);
    let handler = Arc::new(SupervisorWorkflowLauncherHandlerV1::system(supervisor));
    let server_config =
        WorkflowLauncherServerConfigV1::new(policy.worker_uid, MAX_CONNECTIONS, REQUEST_TIMEOUT)?;
    let socket_path = Path::new(WORKFLOW_LAUNCHER_SOCKET_PATH);
    let parent = socket_path
        .parent()
        .ok_or(LauncherServiceError::UnsafeRuntimeDirectory)?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.gid() == 0
        || metadata.permissions().mode() & 0o777 != 0o750
    {
        return Err(LauncherServiceError::UnsafeRuntimeDirectory.into());
    }
    let mut socket = BoundWorkflowLauncherSocketV1::bind(socket_path, 0, metadata.gid())?;
    let listener = socket.take_listener();
    info!(
        socket = %socket.path().display(),
        worker_uid = policy.worker_uid,
        worker_id = %policy.worker_id,
        host_id = %policy.host_id,
        max_concurrent_jobs = policy.max_concurrent_jobs,
        "root workflow launcher listening"
    );
    serve_launcher_until(listener, handler, server_config, shutdown_signal()).await?;
    Ok(())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
enum LauncherServiceError {
    #[error("rdashboard-workflow-launcher accepts no command-line arguments")]
    InvalidInvocation,
    #[error("workflow launcher runtime directory is unsafe")]
    UnsafeRuntimeDirectory,
}
