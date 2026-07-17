use std::{
    fs, io,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
};

use rdashboard::{
    build_source::{SourceArchiveInputV1, SourceArchivePublisherV1},
    installed_source::{
        InstalledSourceConfigV1, load_installed_source_config, load_source_signing_key,
        validate_source_git_ssh_credentials,
    },
    source::{DurableSourceBroker, GitSourceRepository, SourceProjectState, SourceStore},
    source_socket::{
        BoundSourceSocketV1, BrokerSourceRequestHandlerV1, SourceSnapshotReaderV1,
        serve_source_until,
    },
    unix_time_ms,
};
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

type InstalledBroker = DurableSourceBroker<GitSourceRepository>;
type DynError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    if std::env::args_os().len() != 1 {
        return Err(invalid_data("rdashboard-source accepts no arguments").into());
    }
    init_tracing()?;
    let config = load_installed_source_config()?;
    validate_private_directory(&config.state_directory, config.source_uid)?;
    validate_private_directory(&config.repository_root, config.source_uid)?;
    if config.socket_path.parent().is_none() {
        return Err(invalid_data("source socket has no parent").into());
    }

    let signing_key = load_source_signing_key(&config)?;
    validate_source_git_ssh_credentials(&config)?;
    let repository =
        GitSourceRepository::open(&config.repository_root, config.repository_configs())?;
    let export_repository = repository.clone();
    let source_exports = SourceArchivePublisherV1::open(
        &config.build_source_export_root,
        config.source_uid,
        config.build_reader_gid,
    )?;
    let store = SourceStore::open(&config.database_path)?;
    let broker = Arc::new(DurableSourceBroker::new(
        store,
        repository,
        config.attestation_key_id.clone(),
        signing_key,
        config.attestation_ttl_ms()?,
        config.source_policies(),
        unix_time_ms()?,
    )?);
    for project_id in config.project_ids() {
        broker.source_snapshot(&project_id)?;
    }
    let initial_broker = Arc::clone(&broker);
    let initial_projects = config.project_ids();
    let initial_config = config.clone();
    let initial_exports = source_exports.clone();
    let initial_repository = export_repository.clone();
    tokio::task::spawn_blocking(move || {
        reconcile_all(
            &initial_broker,
            &initial_repository,
            &initial_exports,
            &initial_config,
            &initial_projects,
        )
    })
    .await
    .map_err(|_| invalid_data("initial source reconciliation task failed"))??;

    let mut socket = BoundSourceSocketV1::bind(&config.socket_path, config.source_uid)?;
    let listener = socket.take_listener();
    let handler = Arc::new(BrokerSourceRequestHandlerV1::new(ArcBroker(Arc::clone(
        &broker,
    ))));
    let server_config = config.server_config()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let signal_tx = shutdown_tx.clone();
    let signal_task = tokio::spawn(async move {
        shutdown_signal().await;
        let _ = signal_tx.send(true);
    });
    let reconcile_task = tokio::spawn(run_reconciliation_loop(
        Arc::clone(&broker),
        export_repository,
        source_exports,
        config,
        shutdown_rx.clone(),
    ));

    notify_systemd_ready()?;
    info!(socket = %socket.path().display(), "source broker listening");
    let serve_result = serve_source_until(
        listener,
        handler,
        server_config,
        wait_for_shutdown(shutdown_rx),
    )
    .await;
    let _ = shutdown_tx.send(true);
    reconcile_task
        .await
        .map_err(|_| invalid_data("source reconciliation task failed"))?;
    signal_task.abort();
    serve_result?;
    Ok(())
}

#[derive(Clone, Debug)]
struct ArcBroker(Arc<InstalledBroker>);

impl rdashboard::source::LiveSourceGate for ArcBroker {
    fn check_live(
        &self,
        operation: &rdashboard::domain::OperationRecord,
        now_ms: i64,
    ) -> Result<rdashboard::source::SourceGateProof, rdashboard::source::SourceGateError> {
        self.0.check_live(operation, now_ms)
    }

    fn complete_live(
        &self,
        operation: &rdashboard::domain::OperationRecord,
    ) -> Result<(), rdashboard::source::SourceGateError> {
        self.0.complete_live(operation)
    }

    fn abort_live(
        &self,
        operation: &rdashboard::domain::OperationRecord,
    ) -> Result<(), rdashboard::source::SourceGateError> {
        self.0.abort_live(operation)
    }
}

impl SourceSnapshotReaderV1 for ArcBroker {
    fn source_snapshot(
        &self,
        project_id: &rdashboard::domain::ProjectId,
    ) -> Result<rdashboard::source::SourceSnapshot, rdashboard::source::SourceGateError> {
        self.0.source_snapshot(project_id)
    }

    fn source_tree_observation(
        &self,
        project_id: &rdashboard::domain::ProjectId,
    ) -> Result<rdashboard::source::SourceTreeObservationV1, rdashboard::source::SourceGateError>
    {
        self.0
            .source_tree_observation(project_id)
            .map_err(|_| rdashboard::source::SourceGateError::Unavailable)
    }
}

async fn run_reconciliation_loop(
    broker: Arc<InstalledBroker>,
    repository: GitSourceRepository,
    source_exports: SourceArchivePublisherV1,
    config: InstalledSourceConfigV1,
    mut shutdown: watch::Receiver<bool>,
) {
    let reconcile_interval = config.reconcile_interval();
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + reconcile_interval,
        reconcile_interval,
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let cycle_broker = Arc::clone(&broker);
                let cycle_repository = repository.clone();
                let cycle_exports = source_exports.clone();
                let cycle_config = config.clone();
                let projects = config.project_ids();
                let mut cycle = tokio::task::spawn_blocking(move || {
                    reconcile_all(
                        &cycle_broker,
                        &cycle_repository,
                        &cycle_exports,
                        &cycle_config,
                        &projects,
                    )
                });
                tokio::select! {
                    result = &mut cycle => log_reconciliation_result(result),
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            log_reconciliation_result(cycle.await);
                            return;
                        }
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

fn log_reconciliation_result(result: Result<Result<(), io::Error>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => error!(error = %error, "source reconciliation cycle failed"),
        Err(error) => error!(error = %error, "source reconciliation task panicked"),
    }
}

fn reconcile_all(
    broker: &InstalledBroker,
    repository: &GitSourceRepository,
    source_exports: &SourceArchivePublisherV1,
    config: &InstalledSourceConfigV1,
    projects: &[rdashboard::domain::ProjectId],
) -> Result<(), io::Error> {
    for project_id in projects {
        let now_ms = unix_time_ms().map_err(|error| io::Error::other(error.to_string()))?;
        let outcome = broker
            .reconcile_remote_main(project_id, now_ms)
            .map_err(|error| io::Error::other(error.to_string()))?;
        publish_source_export(
            broker,
            repository,
            source_exports,
            config,
            project_id,
            now_ms,
        )?;
        info!(project_id = %project_id, ?outcome, "source reconciliation completed");
    }
    Ok(())
}

fn publish_source_export(
    broker: &InstalledBroker,
    repository: &GitSourceRepository,
    source_exports: &SourceArchivePublisherV1,
    config: &InstalledSourceConfigV1,
    project_id: &rdashboard::domain::ProjectId,
    exported_at_ms: i64,
) -> Result<(), io::Error> {
    let snapshot = broker
        .source_snapshot(project_id)
        .map_err(|error| io::Error::other(error.to_string()))?;
    if snapshot.state != SourceProjectState::Ready {
        return Ok(());
    }
    let head = snapshot
        .head
        .ok_or_else(|| invalid_data("ready source snapshot has no accepted head"))?;
    let source_attestation_digest = snapshot
        .attestation_digest
        .ok_or_else(|| invalid_data("ready source snapshot has no attestation digest"))?;
    let project = config
        .projects
        .iter()
        .find(|project| project.project_id == *project_id)
        .ok_or_else(|| invalid_data("source project is absent from installed config"))?;
    source_exports
        .publish(
            SourceArchiveInputV1 {
                project_id: project_id.clone(),
                head: head.clone(),
                sequence: snapshot.sequence,
                source_attestation_digest,
                installed_policy: project.installed_policy.clone(),
                repository_identity: project.repository_identity.clone(),
                exported_at_ms,
            },
            |output| {
                repository
                    .export_accepted_tree(project_id, &head, output)
                    .map_err(|error| io::Error::other(error.to_string()))
            },
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

fn notify_systemd_ready() -> Result<(), io::Error> {
    if std::env::var_os("NOTIFY_SOCKET").is_none() {
        return Err(invalid_data("systemd notify socket is unavailable"));
    }
    let status = Command::new("/usr/bin/systemd-notify")
        .args(["--ready", "--status=source broker ready"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(invalid_data("systemd readiness notification failed"));
    }
    Ok(())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

fn validate_private_directory(path: &Path, required_uid: u32) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != required_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid_data(
            "source directory is not stable owner-only state",
        ));
    }
    Ok(())
}

fn init_tracing() -> Result<(), DynError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()?;
    Ok(())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
