use std::{
    fs::{self, File},
    io::{self, Read as _},
    os::unix::fs::MetadataExt as _,
    path::Path,
    sync::Arc,
    time::Duration,
};

use rdashboard::adapter::AdapterExecutionCancellationV1;
use rdashboard::backup_driver::{
    AcceptedBackupJobDriverV1, BackupJobQueueControlV1, BackupOperationDriverV1,
    InstalledBackupDiskProbeV1, InstalledBackupDriverPolicySourceV1, ROOT_SECURITY_STORE_PATH,
    drive_pending_backup_jobs_until,
};
use rdashboard::deploy_driver::{
    AcceptedDeployJobDriverV1, InstalledDeployOperationDriverV1, drive_pending_deploy_jobs_until,
};
use rdashboard::executor_authority::RootExecutorAuthorityV1;
use rdashboard::executor_socket::{
    BoundExecutorSocket, ROOT_EXECUTOR_CONFIG_PATH, ReadOnlyExecutorHandler, RootExecutorConfigV1,
    serve_until,
};
use rdashboard::installed_clock::InstalledChronyClockSourceV1;
use rdashboard::installed_deploy::InstalledDeployIntentResolverV1;
use rdashboard::installed_effects::{
    InstalledAdapterExternalEffectsV1, RejectNonPrivilegedPhaseEffectsV1,
};
use rdashboard::installed_intent_resolver::InstalledMutationIntentResolverV1;
use rdashboard::mutation_admission::RootMutationAdmissionV1;
use rdashboard::source_socket::SourceBrokerClientV1;
use rdashboard::store::SecurityStore;
use tokio::sync::{Notify, watch};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
type DynError = Box<dyn std::error::Error + Send + Sync>;
type MutationWorkerV1 = (
    SecurityStore,
    Arc<dyn AcceptedBackupJobDriverV1>,
    Arc<dyn AcceptedDeployJobDriverV1>,
    Arc<Notify>,
);

#[tokio::main]
async fn main() -> Result<(), DynError> {
    if std::env::args_os().len() != 1 {
        return Err(invalid_data("rdashboard-executor accepts no arguments").into());
    }
    init_tracing()?;
    let config = load_root_config(Path::new(ROOT_EXECUTOR_CONFIG_PATH))?;
    let server_config = config.server_config()?;
    validate_root_directory(
        config
            .socket_path
            .parent()
            .ok_or_else(|| invalid_data("executor socket has no parent directory"))?,
        "executor runtime directory must be root-owned and not group/other writable",
    )?;
    let disk_metadata = fs::metadata(&config.metrics_disk_path)?;
    if !disk_metadata.is_dir() {
        return Err(invalid_data("configured metrics disk path is not a directory").into());
    }

    let mutation_authority = config
        .mutation_authority
        .as_ref()
        .map(RootExecutorAuthorityV1::load_system_credential)
        .transpose()?;
    let adapter_cancellation = AdapterExecutionCancellationV1::default();
    let (handler, worker) = match mutation_authority {
        Some(authority) => {
            let (handler, worker) =
                configure_mutation_runtime(&config, authority, adapter_cancellation.clone())?;
            (handler, Some(worker))
        }
        None => (
            ReadOnlyExecutorHandler::linux(&config.metrics_disk_path),
            None,
        ),
    };
    let source_client =
        SourceBrokerClientV1::installed(Duration::from_millis(config.request_timeout_ms))?;
    let handler = Arc::new(handler.with_source_client(source_client));
    let mut socket = BoundExecutorSocket::bind(&config.socket_path)?;
    let listener = socket.take_listener();
    info!(
        socket = %socket.path().display(),
        controller_uid = config.controller_uid,
        mutation_authority_loaded = handler.mutation_authority_loaded(),
        "read-only root executor listening"
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let signal_tx = shutdown_tx.clone();
    let signal_cancellation = adapter_cancellation.clone();
    let signal_task = tokio::spawn(async move {
        shutdown_signal().await;
        signal_cancellation.cancel();
        let _ = signal_tx.send(true);
    });
    let worker_task = worker.map(|(security, backup_driver, deploy_driver, wake)| {
        tokio::spawn(run_mutation_worker(
            security,
            backup_driver,
            deploy_driver,
            wake,
            adapter_cancellation.clone(),
            shutdown_rx.clone(),
        ))
    });
    let serve_result = serve_until(
        listener,
        handler,
        server_config,
        wait_for_shutdown(shutdown_rx),
    )
    .await;
    adapter_cancellation.cancel();
    let _ = shutdown_tx.send(true);
    if let Some(task) = worker_task {
        task.await
            .map_err(|_| invalid_data("mutation worker task failed"))?;
    }
    signal_task.abort();
    serve_result?;
    Ok(())
}

fn configure_mutation_runtime(
    config: &RootExecutorConfigV1,
    authority: RootExecutorAuthorityV1,
    cancellation: AdapterExecutionCancellationV1,
) -> Result<(ReadOnlyExecutorHandler, MutationWorkerV1), DynError> {
    let security_path = Path::new(ROOT_SECURITY_STORE_PATH);
    validate_private_root_directory(
        security_path
            .parent()
            .ok_or_else(|| invalid_data("security store has no parent directory"))?,
    )?;
    let security = SecurityStore::open(security_path)?;
    let wake = Arc::new(Notify::new());
    let admission = RootMutationAdmissionV1::new(
        security.clone(),
        authority,
        InstalledMutationIntentResolverV1::installed()?,
    );
    let control = Arc::new(BackupJobQueueControlV1::new(admission, Arc::clone(&wake)));
    let effects = InstalledAdapterExternalEffectsV1::new_with_cancellation(
        security.clone(),
        RejectNonPrivilegedPhaseEffectsV1,
        cancellation,
    );
    let backup_driver: Arc<dyn AcceptedBackupJobDriverV1> = Arc::new(BackupOperationDriverV1::new(
        security.clone(),
        InstalledBackupDriverPolicySourceV1,
        InstalledBackupDiskProbeV1::installed(),
        effects.clone(),
    ));
    let deploy_driver: Arc<dyn AcceptedDeployJobDriverV1> =
        Arc::new(InstalledDeployOperationDriverV1::new(
            security.clone(),
            InstalledDeployIntentResolverV1::installed()?,
            InstalledBackupDiskProbeV1::installed(),
            effects,
            InstalledChronyClockSourceV1::installed(),
        ));
    let handler =
        ReadOnlyExecutorHandler::linux_with_mutation_control(&config.metrics_disk_path, control);
    Ok((handler, (security, backup_driver, deploy_driver, wake)))
}

async fn run_mutation_worker(
    security: SecurityStore,
    backup_driver: Arc<dyn AcceptedBackupJobDriverV1>,
    deploy_driver: Arc<dyn AcceptedDeployJobDriverV1>,
    wake: Arc<Notify>,
    cancellation: AdapterExecutionCancellationV1,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let cycle_security = security.clone();
        let cycle_backup_driver = Arc::clone(&backup_driver);
        let cycle_deploy_driver = Arc::clone(&deploy_driver);
        let cycle_cancellation = cancellation.clone();
        match tokio::task::spawn_blocking(move || {
            let backup_failures = drive_pending_backup_jobs_until(
                &cycle_security,
                cycle_backup_driver.as_ref(),
                || cycle_cancellation.is_cancelled(),
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
            let deploy_failures = drive_pending_deploy_jobs_until(
                &cycle_security,
                cycle_deploy_driver.as_ref(),
                || cycle_cancellation.is_cancelled(),
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
            Ok::<_, io::Error>((backup_failures, deploy_failures))
        })
        .await
        {
            Ok(Ok((backup_failures, deploy_failures))) => {
                for failure in backup_failures {
                    error!(
                        intent_id = %failure.intent_id,
                        attempt_id = %failure.attempt_id,
                        error = %failure.error,
                        "accepted backup job remains pending"
                    );
                }
                for failure in deploy_failures {
                    error!(
                        intent_id = %failure.intent_id,
                        attempt_id = %failure.attempt_id,
                        error = %failure.error,
                        "accepted deploy job remains pending"
                    );
                }
            }
            Ok(Err(error)) => error!(error = %error, "mutation worker scan failed"),
            Err(error) => error!(error = %error, "mutation worker blocking task failed"),
        }
        tokio::select! {
            () = wake.notified() => {}
            () = tokio::time::sleep(Duration::from_secs(30)) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

fn load_root_config(path: &Path) -> Result<RootExecutorConfigV1, DynError> {
    validate_root_directory(
        path.parent()
            .ok_or_else(|| invalid_data("root executor config has no parent directory"))?,
        "root executor config directory must be root-owned and not group/other writable",
    )?;
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(invalid_data("root executor config must be a regular file").into());
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if path_metadata.dev() != opened_metadata.dev() || path_metadata.ino() != opened_metadata.ino()
    {
        return Err(invalid_data("root executor config changed while opening").into());
    }
    if opened_metadata.uid() != 0 || opened_metadata.mode() & 0o022 != 0 {
        return Err(invalid_data(
            "root executor config must be root-owned and not group/other writable",
        )
        .into());
    }
    if opened_metadata.len() > MAX_CONFIG_BYTES {
        return Err(invalid_data("root executor config exceeds 64 KiB").into());
    }

    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len())?);
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(invalid_data("root executor config exceeds 64 KiB").into());
    }
    let config: RootExecutorConfigV1 = serde_json::from_slice(&bytes)?;
    config.validate()?;
    Ok(config)
}

fn validate_root_directory(path: &Path, error_message: &'static str) -> Result<(), DynError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid_data(error_message).into());
    }
    Ok(())
}

fn validate_private_root_directory(path: &Path) -> Result<(), DynError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        return Err(
            invalid_data("security store directory must be root-owned and mode 0700").into(),
        );
    }
    Ok(())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(error = %error, "failed to install Ctrl-C handler");
        }
    };

    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => error!(error = %error, "failed to install SIGTERM handler"),
        }
    };

    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
}
