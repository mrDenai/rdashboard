use std::{
    collections::BTreeMap,
    fs, io,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
};

use rdashboard::{
    build_source::{SourceArchiveInputV1, SourceArchivePublisherV1},
    installed_source::{
        InstalledSourceConfigV1, SourceWebhookSecretsV1, load_installed_source_config,
        load_source_signing_key, load_source_webhook_secrets, validate_source_git_ssh_credentials,
    },
    source::{
        DurableSourceBroker, GitSourceRepository, SOURCE_GITHUB_WEBHOOK_BATCH_MAX,
        SourceProjectState, SourceStore,
    },
    source_delivery_socket::{
        BoundSourceDeliverySocketV1, BrokerSourceDeliveryHandlerV1, SourceOutboxReaderV1,
        serve_source_delivery_until,
    },
    source_ingress_socket::{
        BoundSourceIngressSocketV1, BrokerSourceIngressHandlerV1, GithubWebhookAcceptorV1,
        serve_source_ingress_until,
    },
    source_socket::{
        BoundSourceSocketV1, BrokerSourceRequestHandlerV1, SourceSnapshotReaderV1,
        serve_source_until,
    },
    unix_time_ms,
};
use tokio::sync::{Notify, oneshot, watch};
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
    if config.ingress_socket_path.parent().is_none() {
        return Err(invalid_data("source ingress socket has no parent").into());
    }

    let signing_key = load_source_signing_key(&config)?;
    validate_source_git_ssh_credentials(&config)?;
    let webhook_secrets = Arc::new(load_source_webhook_secrets(&config)?);
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
    let wakeups = SourceWakeups::new(&config.project_ids());
    let initial_broker = Arc::clone(&broker);
    let initial_projects = config.project_ids();
    let initial_config = config.clone();
    let initial_exports = source_exports.clone();
    let initial_repository = export_repository.clone();
    tokio::task::spawn_blocking(move || {
        initialize_all(
            &initial_broker,
            &initial_repository,
            &initial_exports,
            &initial_config,
            &initial_projects,
        )
    })
    .await
    .map_err(|_| invalid_data("initial source reconciliation task failed"))??;
    for project_id in config.project_ids() {
        wakeups.notify(&project_id)?;
    }

    serve_broker(
        config,
        broker,
        export_repository,
        source_exports,
        webhook_secrets,
        wakeups,
    )
    .await
}

async fn serve_broker(
    config: InstalledSourceConfigV1,
    broker: Arc<InstalledBroker>,
    export_repository: GitSourceRepository,
    source_exports: SourceArchivePublisherV1,
    webhook_secrets: Arc<SourceWebhookSecretsV1>,
    wakeups: SourceWakeups,
) -> Result<(), DynError> {
    let mut socket = BoundSourceSocketV1::bind(&config.socket_path, config.source_uid)?;
    let listener = socket.take_listener();
    let handler = Arc::new(BrokerSourceRequestHandlerV1::new(ArcBroker(Arc::clone(
        &broker,
    ))));
    let server_config = config.server_config()?;
    let mut delivery_socket = BoundSourceDeliverySocketV1::bind(
        &config.delivery_socket_path,
        config.source_uid,
        config.controller_gid,
    )?;
    let delivery_listener = delivery_socket.take_listener();
    let delivery_gateway = SourceDeliveryBroker::new(
        Arc::clone(&broker),
        export_repository.clone(),
        source_exports.clone(),
        config.clone(),
    );
    let delivery_handler = Arc::new(BrokerSourceDeliveryHandlerV1::system(delivery_gateway));
    let delivery_server_config = config.delivery_server_config()?;
    let mut ingress_socket = BoundSourceIngressSocketV1::bind(
        &config.ingress_socket_path,
        config.source_uid,
        config.ingress_gid,
    )?;
    let ingress_listener = ingress_socket.take_listener();
    let ingress_handler = Arc::new(BrokerSourceIngressHandlerV1::system(
        IngressBroker {
            broker: Arc::clone(&broker),
            wakeups: wakeups.clone(),
        },
        webhook_secrets,
    ));
    let ingress_server_config = config.ingress_server_config()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let signal_tx = shutdown_tx.clone();
    let signal_task = tokio::spawn(async move {
        shutdown_signal().await;
        let _ = signal_tx.send(true);
    });
    let (reconcile_task, coordinator_result_rx) = spawn_reconciliation_coordinator(
        Arc::clone(&broker),
        export_repository,
        source_exports,
        config,
        wakeups,
        shutdown_rx.clone(),
    );

    notify_systemd_ready()?;
    info!(
        source_socket = %socket.path().display(),
        ingress_socket = %ingress_socket.path().display(),
        delivery_socket = %delivery_socket.path().display(),
        "source broker listening"
    );
    let source_server = serve_source_until(
        listener,
        handler,
        server_config,
        wait_for_shutdown(shutdown_rx.clone()),
    );
    let delivery_server = serve_source_delivery_until(
        delivery_listener,
        delivery_handler,
        delivery_server_config,
        wait_for_shutdown(shutdown_rx.clone()),
    );
    let ingress_server = serve_source_ingress_until(
        ingress_listener,
        ingress_handler,
        ingress_server_config,
        wait_for_shutdown(shutdown_rx),
    );
    let serve_result: Result<((), (), (), ()), DynError> = tokio::try_join!(
        async {
            source_server
                .await
                .map_err(|error| -> DynError { Box::new(error) })
        },
        async {
            delivery_server
                .await
                .map_err(|error| -> DynError { Box::new(error) })
        },
        async {
            ingress_server
                .await
                .map_err(|error| -> DynError { Box::new(error) })
        },
        monitor_reconciliation_coordinator(coordinator_result_rx),
    );
    let _ = shutdown_tx.send(true);
    reconcile_task
        .await
        .map_err(|_| invalid_data("source reconciliation task failed"))?;
    signal_task.abort();
    serve_result?;
    Ok(())
}

fn spawn_reconciliation_coordinator(
    broker: Arc<InstalledBroker>,
    repository: GitSourceRepository,
    source_exports: SourceArchivePublisherV1,
    config: InstalledSourceConfigV1,
    wakeups: SourceWakeups,
    shutdown: watch::Receiver<bool>,
) -> (
    tokio::task::JoinHandle<()>,
    oneshot::Receiver<Result<(), io::Error>>,
) {
    let (result_tx, result_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let result = run_reconciliation_coordinator(
            broker,
            repository,
            source_exports,
            config,
            wakeups,
            shutdown,
        )
        .await;
        let _ = result_tx.send(result);
    });
    (task, result_rx)
}

async fn monitor_reconciliation_coordinator(
    result: oneshot::Receiver<Result<(), io::Error>>,
) -> Result<(), DynError> {
    match result.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(Box::new(error)),
        Err(_) => Err(Box::new(invalid_data(
            "source reconciliation coordinator disappeared",
        ))),
    }
}

#[derive(Clone, Debug)]
struct ArcBroker(Arc<InstalledBroker>);

#[derive(Clone, Debug)]
struct SourceDeliveryBroker {
    broker: Arc<InstalledBroker>,
    repository: GitSourceRepository,
    source_exports: SourceArchivePublisherV1,
    config: InstalledSourceConfigV1,
}

impl SourceDeliveryBroker {
    const fn new(
        broker: Arc<InstalledBroker>,
        repository: GitSourceRepository,
        source_exports: SourceArchivePublisherV1,
        config: InstalledSourceConfigV1,
    ) -> Self {
        Self {
            broker,
            repository,
            source_exports,
            config,
        }
    }
}

#[derive(Clone, Debug)]
struct SourceWakeups(Arc<BTreeMap<String, Arc<Notify>>>);

impl SourceWakeups {
    fn new(projects: &[rdashboard::domain::ProjectId]) -> Self {
        Self(Arc::new(
            projects
                .iter()
                .map(|project_id| (project_id.to_string(), Arc::new(Notify::new())))
                .collect(),
        ))
    }

    fn project(
        &self,
        project_id: &rdashboard::domain::ProjectId,
    ) -> Result<Arc<Notify>, rdashboard::source::SourceError> {
        self.0
            .get(project_id.as_str())
            .cloned()
            .ok_or_else(|| rdashboard::source::SourceError::UnknownProject(project_id.to_string()))
    }

    fn notify(
        &self,
        project_id: &rdashboard::domain::ProjectId,
    ) -> Result<(), rdashboard::source::SourceError> {
        self.project(project_id)?.notify_one();
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct IngressBroker {
    broker: Arc<InstalledBroker>,
    wakeups: SourceWakeups,
}

impl GithubWebhookAcceptorV1 for IngressBroker {
    fn enqueue_github_push(
        &self,
        project_id: &rdashboard::domain::ProjectId,
        delivery_id: &str,
        signature_header: &str,
        webhook_secret: &[u8],
        raw_body: &[u8],
        received_at_ms: i64,
    ) -> Result<rdashboard::source::GithubWebhookAdmissionV1, rdashboard::source::SourceError> {
        let admission = self.broker.enqueue_github_push(
            project_id,
            delivery_id,
            signature_header,
            webhook_secret,
            raw_body,
            received_at_ms,
        )?;
        if matches!(
            admission,
            rdashboard::source::GithubWebhookAdmissionV1::Queued { .. }
                | rdashboard::source::GithubWebhookAdmissionV1::Duplicate {
                    completed: false,
                    ..
                }
        ) {
            self.wakeups.notify(project_id)?;
        }
        Ok(admission)
    }
}

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

impl SourceOutboxReaderV1 for SourceDeliveryBroker {
    fn pending_outbox(
        &self,
        limit: usize,
    ) -> Result<Vec<rdashboard::source::SourceOutboxEntryV1>, rdashboard::source::SourceError> {
        self.broker.pending_outbox(limit)
    }

    fn acknowledge_outbox(
        &self,
        outbox_sequence: u64,
        attestation_digest: &rdashboard::domain::EvidenceDigest,
        acknowledged_at_ms: i64,
    ) -> Result<(), rdashboard::source::SourceError> {
        self.broker
            .acknowledge_outbox(outbox_sequence, attestation_digest, acknowledged_at_ms)
    }

    fn current_shadow_entry(
        &self,
        project_id: &rdashboard::domain::ProjectId,
        observed_at_ms: i64,
    ) -> Result<rdashboard::source::SourceShadowEntryV1, rdashboard::source::SourceError> {
        self.broker
            .refresh_shadow_head(project_id, observed_at_ms)?;
        publish_source_export(
            &self.broker,
            &self.repository,
            &self.source_exports,
            &self.config,
            project_id,
            observed_at_ms,
        )?;
        self.broker.current_shadow_entry(project_id, observed_at_ms)
    }
}

async fn run_reconciliation_coordinator(
    broker: Arc<InstalledBroker>,
    repository: GitSourceRepository,
    source_exports: SourceArchivePublisherV1,
    config: InstalledSourceConfigV1,
    wakeups: SourceWakeups,
    shutdown: watch::Receiver<bool>,
) -> Result<(), io::Error> {
    let config = Arc::new(config);
    let mut tasks = tokio::task::JoinSet::new();
    for project_id in config.project_ids() {
        let project_wakeup = match wakeups.project(&project_id) {
            Ok(wakeup) => wakeup,
            Err(error) => {
                return Err(io::Error::other(format!(
                    "source wake-up registry is incomplete for {project_id}: {error}"
                )));
            }
        };
        tasks.spawn(run_project_source_loop(
            Arc::clone(&broker),
            repository.clone(),
            source_exports.clone(),
            Arc::clone(&config),
            project_id,
            project_wakeup,
            shutdown.clone(),
        ));
    }
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(()) if *shutdown.borrow() => {}
            Ok(()) => {
                return Err(io::Error::other(
                    "source project coordinator stopped before shutdown",
                ));
            }
            Err(error) => {
                return Err(io::Error::other(format!(
                    "source project coordinator task failed: {error}"
                )));
            }
        }
    }
    if *shutdown.borrow() {
        Ok(())
    } else {
        Err(io::Error::other(
            "source reconciliation coordinator has no project tasks",
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_project_source_loop(
    broker: Arc<InstalledBroker>,
    repository: GitSourceRepository,
    source_exports: SourceArchivePublisherV1,
    config: Arc<InstalledSourceConfigV1>,
    project_id: rdashboard::domain::ProjectId,
    wakeup: Arc<Notify>,
    mut shutdown: watch::Receiver<bool>,
) {
    let reconcile_interval = config.reconcile_interval();
    let jitter = project_reconcile_jitter(&project_id);
    let mut reconciliation_deferred = false;
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + reconcile_interval + jitter,
        reconcile_interval,
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            () = wakeup.notified() => {
                if !drain_project_webhooks(
                    Arc::clone(&broker),
                    repository.clone(),
                    source_exports.clone(),
                    Arc::clone(&config),
                    project_id.clone(),
                    Arc::clone(&wakeup),
                    shutdown.clone(),
                ).await {
                    return;
                }
                reconciliation_deferred = false;
            }
            () = async {
                if reconciliation_deferred {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                } else {
                    interval.tick().await;
                }
            } => {
                let cycle_broker = Arc::clone(&broker);
                let cycle_repository = repository.clone();
                let cycle_exports = source_exports.clone();
                let cycle_config = Arc::clone(&config);
                let cycle_project = project_id.clone();
                match tokio::task::spawn_blocking(move || {
                    reconcile_project(
                        &cycle_broker,
                        &cycle_repository,
                        &cycle_exports,
                        &cycle_config,
                        &cycle_project,
                    )
                }).await {
                    Ok(Ok(ReconcileStatus::Complete)) => {
                        reconciliation_deferred = false;
                    }
                    Ok(Ok(ReconcileStatus::Deferred)) => {
                        reconciliation_deferred = true;
                    }
                    Ok(Err(error)) => {
                        reconciliation_deferred = false;
                        error!(project_id = %project_id, error = %error, "source reconciliation failed");
                    }
                    Err(error) => {
                        reconciliation_deferred = false;
                        error!(project_id = %project_id, error = %error, "source reconciliation task panicked");
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drain_project_webhooks(
    broker: Arc<InstalledBroker>,
    repository: GitSourceRepository,
    source_exports: SourceArchivePublisherV1,
    config: Arc<InstalledSourceConfigV1>,
    project_id: rdashboard::domain::ProjectId,
    wakeup: Arc<Notify>,
    mut shutdown: watch::Receiver<bool>,
) -> bool {
    let mut retry_delay = std::time::Duration::from_millis(250);
    loop {
        let cycle_broker = Arc::clone(&broker);
        let cycle_repository = repository.clone();
        let cycle_exports = source_exports.clone();
        let cycle_config = Arc::clone(&config);
        let cycle_project = project_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            drain_project_webhook_batch(
                &cycle_broker,
                &cycle_repository,
                &cycle_exports,
                &cycle_config,
                &cycle_project,
            )
        })
        .await;
        match result {
            Ok(Ok(outcome)) if outcome.deferred_until_remote_catches_up => {
                info!(
                    project_id = %project_id,
                    completed = outcome.completed,
                    "GitHub webhook wake-up is durable while the remote ref catches up"
                );
            }
            Ok(Ok(outcome)) if outcome.completed == SOURCE_GITHUB_WEBHOOK_BATCH_MAX => {
                retry_delay = std::time::Duration::from_millis(250);
                continue;
            }
            Ok(Ok(outcome)) => {
                if outcome.completed > 0 {
                    info!(
                        project_id = %project_id,
                        completed = outcome.completed,
                        "GitHub webhook wake-ups processed"
                    );
                }
                return true;
            }
            Ok(Err(error)) => {
                error!(project_id = %project_id, error = %error, "GitHub webhook wake-up processing failed");
            }
            Err(error) => {
                error!(project_id = %project_id, error = %error, "GitHub webhook processing task panicked");
            }
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return false;
                }
            }
            () = wakeup.notified() => {}
            () = tokio::time::sleep(retry_delay) => {}
        }
        retry_delay = retry_delay
            .saturating_mul(2)
            .min(std::time::Duration::from_secs(5));
    }
}

fn initialize_all(
    broker: &InstalledBroker,
    repository: &GitSourceRepository,
    source_exports: &SourceArchivePublisherV1,
    config: &InstalledSourceConfigV1,
    projects: &[rdashboard::domain::ProjectId],
) -> Result<(), io::Error> {
    for project_id in projects {
        loop {
            let outcome = drain_project_webhook_batch(
                broker,
                repository,
                source_exports,
                config,
                project_id,
            )?;
            if outcome.completed < SOURCE_GITHUB_WEBHOOK_BATCH_MAX
                || outcome.deferred_until_remote_catches_up
            {
                break;
            }
        }
        let _ = reconcile_project(broker, repository, source_exports, config, project_id)?;
    }
    Ok(())
}

fn drain_project_webhook_batch(
    broker: &InstalledBroker,
    repository: &GitSourceRepository,
    source_exports: &SourceArchivePublisherV1,
    config: &InstalledSourceConfigV1,
    project_id: &rdashboard::domain::ProjectId,
) -> Result<rdashboard::source::GithubWebhookDrainOutcomeV1, io::Error> {
    let now_ms = unix_time_ms().map_err(|error| io::Error::other(error.to_string()))?;
    let outcome = broker
        .process_pending_github_pushes(project_id, SOURCE_GITHUB_WEBHOOK_BATCH_MAX, now_ms)
        .map_err(|error| io::Error::other(error.to_string()))?;
    if outcome.completed > 0 {
        publish_source_export(
            broker,
            repository,
            source_exports,
            config,
            project_id,
            now_ms,
        )?;
    }
    Ok(outcome)
}

fn reconcile_project(
    broker: &InstalledBroker,
    repository: &GitSourceRepository,
    source_exports: &SourceArchivePublisherV1,
    config: &InstalledSourceConfigV1,
    project_id: &rdashboard::domain::ProjectId,
) -> Result<ReconcileStatus, io::Error> {
    let now_ms = unix_time_ms().map_err(|error| io::Error::other(error.to_string()))?;
    let outcome = match broker.reconcile_remote_main(project_id, now_ms) {
        Ok(outcome) => outcome,
        Err(rdashboard::source::SourceError::ReconciliationDeferred) => {
            return Ok(ReconcileStatus::Deferred);
        }
        Err(error) => return Err(io::Error::other(error.to_string())),
    };
    publish_source_export(
        broker,
        repository,
        source_exports,
        config,
        project_id,
        now_ms,
    )?;
    info!(project_id = %project_id, ?outcome, "source reconciliation completed");
    Ok(ReconcileStatus::Complete)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconcileStatus {
    Complete,
    Deferred,
}

fn project_reconcile_jitter(project_id: &rdashboard::domain::ProjectId) -> std::time::Duration {
    let value = project_id
        .as_str()
        .bytes()
        .fold(0_u64, |accumulator, byte| {
            accumulator.wrapping_mul(131).wrapping_add(u64::from(byte))
        });
    std::time::Duration::from_millis(value % 5_001)
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
