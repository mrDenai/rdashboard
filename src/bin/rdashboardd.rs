use std::{
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rdashboard::{
    controller::DurableController,
    domain::{
        ControlSummary, DashboardEvent, DashboardSnapshot, HostTelemetry, ObservationStatus,
        ProjectId, PsiMeasurement, truncate_utf8,
    },
    executor_socket::{ROOT_EXECUTOR_SOCKET_PATH, RootExecutorClient},
    integration_collectors::ProjectIntegrationCollectors,
    metrics::HostCollector,
    notifier_socket::{NOTIFIER_SOCKET_PATH, NotifierClientV1},
    projects::{
        HttpHealthCollector, HttpHealthConfigError, ProjectResourceCollector, RimgConfigError,
        RimgHealthCollector,
    },
    store::{
        ControlStore, IntegrationStore, MetricsStore, PROJECT_REPOSITORY_SAMPLE_INTERVAL_MS,
        RepositorySampleWrite,
    },
    unix_time_ms,
    web::{
        CloudflareAccessConfig, CloudflareAccessConfigError, CloudflareAccessVerifier,
        DashboardMutationApiV1, DashboardState, EventHub, router_with_access,
    },
};
use tokio::{net::TcpListener, sync::Mutex};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const DEFAULT_LISTEN: &str = "127.0.0.1:3100";
const DEFAULT_DATA_DIR: &str = "var";
const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
const PROJECT_HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
const PROJECT_RESOURCE_TIMEOUT: Duration = Duration::from_secs(4);
const RIMG_RESOURCE_SOCKET_PATH: &str = "/run/rdashboard-observer/observer.sock";
const EXECUTOR_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const RAW_RETENTION: Duration = Duration::from_hours(24);
const MINUTE_ROLLUP_RETENTION: Duration = Duration::from_hours(720);
const PROJECT_ID_RIMG: &str = "rimg";
const PROJECT_ID_TELEGRAM_GATEWAY: &str = "telegram-gateway";
const TELEGRAM_GATEWAY_DISPLAY_NAME: &str = "Telegram gateway";
const PROJECT_REPOSITORY_ERROR_MAX_BYTES: usize = 512;
const PROJECT_REPOSITORY_FAILURE_RETRY: Duration = Duration::from_mins(5);
const PROJECT_INTEGRATION_INTERVAL: Duration = Duration::from_mins(5);
const PROJECT_INTEGRATION_TIMEOUT: Duration = Duration::from_secs(20);
const NOTIFICATION_HANDOFF_INTERVAL: Duration = Duration::from_secs(5);
const NOTIFICATION_HANDOFF_BATCH: usize = 50;
type DynError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    init_tracing()?;
    let config = Config::from_env()?;
    let access = match config.access.clone() {
        Some(access) => Some(Arc::new(CloudflareAccessVerifier::connect(access).await?)),
        None => None,
    };
    std::fs::create_dir_all(&config.data_dir)?;

    let control_store = ControlStore::open(config.data_dir.join("control.sqlite"))?;
    let metrics_store = MetricsStore::open(config.data_dir.join("metrics.sqlite"))?;
    let integration_store = IntegrationStore::open(config.data_dir.join("integrations.sqlite"))?;
    let integration_collectors = ProjectIntegrationCollectors::from_credential_directory(
        config.credential_directory.as_deref(),
        PROJECT_INTEGRATION_TIMEOUT,
    )?;
    let hub = EventHub::new(control_store.clone());
    let executor_client = config
        .executor_socket
        .as_ref()
        .map(|socket_path| RootExecutorClient::new(socket_path, EXECUTOR_REQUEST_TIMEOUT))
        .transpose()?
        .map(Arc::new);
    let notifier_client = configured_notifier(config.notifier_socket.as_deref())?;
    let durable_controller = DurableController::new(control_store.clone());
    let state = dashboard_state(
        hub.clone(),
        metrics_store.clone(),
        integration_store.clone(),
        durable_controller,
        executor_client.as_ref(),
        notifier_client.as_ref(),
    );
    let host_source = executor_client.clone().map_or_else(
        || {
            HostObservationSource::Local(Arc::new(Mutex::new(HostCollector::linux(
                &config.data_dir,
            ))))
        },
        HostObservationSource::Executor,
    );
    let project_collectors = shared_project_collectors(&config.project_collectors);

    let first_started_at = unix_time_ms()?;
    let recovered = control_store.recover_interrupted_observations(first_started_at)?;
    if recovered > 0 {
        warn!(
            recovered,
            "marked interrupted observation operations as failed"
        );
    }
    let first_operation = control_store.start_observation(first_started_at)?;
    if let Err(collection_error) = Box::pin(collect_and_publish(
        &state,
        &metrics_store,
        &host_source,
        &project_collectors,
        first_operation,
    ))
    .await
    {
        let completed_at = unix_time_ms().unwrap_or(first_started_at);
        if let Err(receipt_error) = control_store.finish_observation(
            first_operation,
            completed_at,
            Some("initial_collection_failed"),
        ) {
            error!(error = %receipt_error, "failed to persist initial collection failure");
        }
        return Err(collection_error);
    }
    control_store.finish_observation(
        first_operation,
        unix_time_ms().unwrap_or(first_started_at),
        None,
    )?;

    spawn_collection_loop(
        state.clone(),
        metrics_store,
        host_source,
        project_collectors,
    );
    spawn_project_repository_collection(state.clone(), executor_client);
    if let Some(client) = notifier_client.as_ref() {
        spawn_notification_handoff_delivery(integration_store.clone(), Arc::clone(client));
    }
    spawn_project_integration_collection(
        integration_store,
        integration_collectors,
        notifier_client.is_some(),
    );

    let listener = TcpListener::bind(config.listen).await?;
    info!(listen = %config.listen, data_dir = %config.data_dir.display(), "rdashboardd listening");
    axum::serve(listener, router_with_access(state, access))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn shared_project_collectors(
    configured: &[MonitoredProjectCollector],
) -> Arc<Vec<Arc<Mutex<MonitoredProjectCollector>>>> {
    Arc::new(
        configured
            .iter()
            .cloned()
            .map(Mutex::new)
            .map(Arc::new)
            .collect(),
    )
}

fn configured_notifier(
    socket_path: Option<&Path>,
) -> Result<Option<Arc<NotifierClientV1>>, rdashboard::notifier_socket::NotifierClientError> {
    socket_path
        .map(|path| NotifierClientV1::new(path, EXECUTOR_REQUEST_TIMEOUT).map(Arc::new))
        .transpose()
}

fn dashboard_state(
    hub: EventHub,
    metrics_store: MetricsStore,
    integration_store: IntegrationStore,
    durable_controller: DurableController,
    executor_client: Option<&Arc<RootExecutorClient>>,
    notifier_client: Option<&Arc<NotifierClientV1>>,
) -> DashboardState {
    let state = DashboardState::new(hub, SAMPLE_INTERVAL);
    let state = if let Some(client) = executor_client {
        state.with_mutation_api(DashboardMutationApiV1::new(
            durable_controller.clone(),
            Arc::clone(client),
        ))
    } else {
        state
    };
    let state = state
        .with_metrics_store(metrics_store)
        .with_integration_store(integration_store)
        .with_operation_history(durable_controller);
    if let Some(client) = notifier_client {
        state.with_notifier_client(Arc::clone(client))
    } else {
        state
    }
}

async fn collect_and_publish(
    state: &DashboardState,
    metrics_store: &MetricsStore,
    host_source: &HostObservationSource,
    project_collectors: &[Arc<Mutex<MonitoredProjectCollector>>],
    observation_operation_id: Uuid,
) -> Result<(), DynError> {
    let now = unix_time_ms()?;
    let (host, projects) = tokio::join!(
        host_source.collect(now),
        collect_projects(project_collectors, now),
    );
    metrics_store.record_collection(&host, &projects)?;
    let snapshot = DashboardSnapshot {
        generated_at_ms: now,
        host,
        projects,
        control: ControlSummary {
            sqlite_version: rusqlite::version().to_owned(),
            observation_operation_id,
            sample_interval_seconds: SAMPLE_INTERVAL.as_secs(),
        },
    };
    state
        .hub
        .publish(now, DashboardEvent::Snapshot(Box::new(snapshot.clone())))?;
    *state.latest_snapshot.write().await = Some(snapshot);
    *state.collection_error.write().await = None;
    Ok(())
}

async fn collect_projects(
    collectors: &[Arc<Mutex<MonitoredProjectCollector>>],
    observed_at_ms: i64,
) -> Vec<rdashboard::domain::ProjectTelemetry> {
    futures_util::future::join_all(
        collectors
            .iter()
            .map(|collector| async move { collector.lock().await.collect(observed_at_ms).await }),
    )
    .await
}

#[derive(Clone, Debug)]
struct MonitoredProjectCollector {
    health: ProjectHealthCollector,
    resources: ProjectResourceCollector,
}

impl MonitoredProjectCollector {
    async fn collect(&mut self, observed_at_ms: i64) -> rdashboard::domain::ProjectTelemetry {
        let (mut project, resources) = tokio::join!(
            self.health.collect(observed_at_ms),
            self.resources.collect(observed_at_ms),
        );
        project.resources = resources;
        project
    }
}

#[derive(Clone, Debug)]
enum ProjectHealthCollector {
    Rimg(RimgHealthCollector),
    Http(HttpHealthCollector),
}

impl ProjectHealthCollector {
    async fn collect(&mut self, observed_at_ms: i64) -> rdashboard::domain::ProjectTelemetry {
        match self {
            Self::Rimg(collector) => collector.collect(observed_at_ms).await,
            Self::Http(collector) => collector.collect(observed_at_ms).await,
        }
    }
}

#[derive(Clone, Debug)]
enum HostObservationSource {
    Local(Arc<Mutex<HostCollector>>),
    Executor(Arc<RootExecutorClient>),
}

impl HostObservationSource {
    async fn collect(&self, observed_at_ms: i64) -> HostTelemetry {
        match self {
            Self::Local(collector) => collector.lock().await.collect(observed_at_ms),
            Self::Executor(client) => match client.observe_host().await {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    warn!(error = %error, "root executor host observation unavailable");
                    HostTelemetry {
                        observed_at_ms,
                        status: ObservationStatus::SignalLost,
                        cpu_percent: None,
                        load_1: None,
                        load_5: None,
                        load_15: None,
                        memory_total_bytes: None,
                        memory_available_bytes: None,
                        swap_total_bytes: None,
                        swap_free_bytes: None,
                        disk_total_bytes: None,
                        disk_available_bytes: None,
                        network_rx_bytes: None,
                        network_tx_bytes: None,
                        network_rx_bytes_per_second: None,
                        network_tx_bytes_per_second: None,
                        psi: PsiMeasurement {
                            cpu_some_avg10: None,
                            memory_some_avg10: None,
                            io_some_avg10: None,
                        },
                        partial_reasons: vec!["root executor observation unavailable".to_owned()],
                    }
                }
            },
        }
    }
}

fn spawn_collection_loop(
    state: DashboardState,
    metrics_store: MetricsStore,
    host_source: HostObservationSource,
    project_collectors: Arc<Vec<Arc<Mutex<MonitoredProjectCollector>>>>,
) {
    tokio::spawn(async move {
        let operation_id = state
            .latest_snapshot
            .read()
            .await
            .as_ref()
            .map(|snapshot| snapshot.control.observation_operation_id);
        let Some(operation_id) = operation_id else {
            error!("collector loop started without an initial snapshot");
            return;
        };
        apply_metric_retention(&state, &metrics_store).await;
        let mut interval = tokio::time::interval(SAMPLE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        let mut cycles = 0_u64;
        loop {
            interval.tick().await;
            match Box::pin(collect_and_publish(
                &state,
                &metrics_store,
                &host_source,
                &project_collectors,
                operation_id,
            ))
            .await
            {
                Ok(()) => {}
                Err(error) => {
                    let detail = error.to_string();
                    error!(error = %detail, "observation collection failed");
                    *state.collection_error.write().await = Some(detail);
                }
            }
            cycles = cycles.saturating_add(1);
            if cycles.is_multiple_of(720) {
                apply_metric_retention(&state, &metrics_store).await;
            }
        }
    });
}

fn spawn_project_repository_collection(
    state: DashboardState,
    executor_client: Option<Arc<RootExecutorClient>>,
) {
    tokio::spawn(async move {
        let project_ids = state
            .latest_snapshot
            .read()
            .await
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .projects
                    .iter()
                    .map(|project| project.project_id.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let Some(metrics_store) = state.metrics_store.clone() else {
            for project_id in &project_ids {
                set_project_repository_error(
                    &state,
                    project_id,
                    "Хранилище истории репозитория не настроено.",
                )
                .await;
            }
            return;
        };
        let Some(executor_client) = executor_client else {
            for project_id in &project_ids {
                set_project_repository_error(
                    &state,
                    project_id,
                    "Источник принятого Git-дерева не настроен.",
                )
                .await;
            }
            return;
        };

        for project_id in project_ids {
            tokio::spawn(collect_project_repository_loop(
                state.clone(),
                metrics_store.clone(),
                Arc::clone(&executor_client),
                project_id,
            ));
        }
    });
}

async fn collect_project_repository_loop(
    state: DashboardState,
    metrics_store: MetricsStore,
    executor_client: Arc<RootExecutorClient>,
    project_id: ProjectId,
) {
    loop {
        let now_ms = match unix_time_ms() {
            Ok(value) => value,
            Err(error) => {
                warn!(error = %error, "repository observation skipped because the host clock is invalid");
                set_project_repository_error(
                    &state,
                    &project_id,
                    "Часы сервера недоступны; почасовой снимок репозитория пропущен.",
                )
                .await;
                tokio::time::sleep(PROJECT_REPOSITORY_FAILURE_RETRY).await;
                continue;
            }
        };
        match metrics_store.next_project_repository_observation_at(&project_id) {
            Ok(Some(next_at_ms)) if next_at_ms > now_ms => {
                tokio::time::sleep(duration_until(now_ms, next_at_ms)).await;
                continue;
            }
            Ok(_) => {}
            Err(error) => {
                warn!(error = %error, "repository observation schedule could not be loaded");
                set_project_repository_error(
                    &state,
                    &project_id,
                    "Расписание почасовых снимков репозитория недоступно.",
                )
                .await;
                tokio::time::sleep(PROJECT_REPOSITORY_FAILURE_RETRY).await;
                continue;
            }
        }

        match executor_client
            .observe_project_source(project_id.clone())
            .await
        {
            Ok(observation) => {
                match metrics_store.record_project_repository_sample(now_ms, &observation) {
                    Ok(RepositorySampleWrite::Recorded) => {
                        state
                            .project_repository_errors
                            .write()
                            .await
                            .remove(project_id.as_str());
                    }
                    Ok(RepositorySampleWrite::NotDue {
                        next_observation_at_ms,
                    }) => {
                        tokio::time::sleep(duration_until(now_ms, next_observation_at_ms)).await;
                        continue;
                    }
                    Err(error) => {
                        warn!(error = %error, "repository observation could not be persisted");
                        set_project_repository_error(
                            &state,
                            &project_id,
                            "Почасовой снимок репозитория не удалось сохранить.",
                        )
                        .await;
                        tokio::time::sleep(PROJECT_REPOSITORY_FAILURE_RETRY).await;
                        continue;
                    }
                }
            }
            Err(error) => {
                warn!(error = %error, "repository observation unavailable");
                set_project_repository_error(&state, &project_id, &error.to_string()).await;
                tokio::time::sleep(PROJECT_REPOSITORY_FAILURE_RETRY).await;
                continue;
            }
        }
        tokio::time::sleep(project_repository_interval()).await;
    }
}

fn spawn_project_integration_collection(
    store: IntegrationStore,
    collectors: ProjectIntegrationCollectors,
    notifications_enabled: bool,
) {
    tokio::spawn(async move {
        let project_id: ProjectId = match PROJECT_ID_RIMG.parse() {
            Ok(project_id) => project_id,
            Err(error) => {
                error!(error = %error, "fixed integration project identifier is invalid");
                return;
            }
        };
        let mut interval = tokio::time::interval(PROJECT_INTEGRATION_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let now_ms = match unix_time_ms() {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, "project integration collection skipped because the host clock is invalid");
                    continue;
                }
            };
            let (errors, updates) = tokio::join!(
                collectors.collect_errors(now_ms),
                collectors.collect_updates(now_ms),
            );
            let cycle_store = store.clone();
            let cycle_project = project_id.clone();
            let persisted = tokio::task::spawn_blocking(move || {
                let errors_result = match errors {
                    Ok(data) if notifications_enabled => {
                        cycle_store.record_errors_success_with_notifications(now_ms, data)
                    }
                    Ok(data) => cycle_store.record_errors_success(now_ms, data),
                    Err(error) if notifications_enabled => cycle_store
                        .record_errors_failure_with_notifications(
                            &cycle_project,
                            now_ms,
                            error.into_failure(),
                        ),
                    Err(error) => cycle_store.record_errors_failure(
                        &cycle_project,
                        now_ms,
                        error.into_failure(),
                    ),
                };
                let updates_result = match updates {
                    Ok(data) if notifications_enabled => {
                        cycle_store.record_updates_success_with_notifications(now_ms, data)
                    }
                    Ok(data) => cycle_store.record_updates_success(now_ms, data),
                    Err(error) if notifications_enabled => cycle_store
                        .record_updates_failure_with_notifications(
                            &cycle_project,
                            now_ms,
                            error.into_failure(),
                        ),
                    Err(error) => cycle_store.record_updates_failure(
                        &cycle_project,
                        now_ms,
                        error.into_failure(),
                    ),
                };
                (errors_result, updates_result)
            })
            .await;
            match persisted {
                Ok((errors_result, updates_result)) => {
                    if let Err(error) = &errors_result {
                        log_integration_persistence_error(error, "errors");
                    }
                    if let Err(error) = &updates_result {
                        log_integration_persistence_error(error, "updates");
                    }
                }
                Err(error) => {
                    error!(error = %error, "project integration persistence task failed");
                }
            }
        }
    });
}

fn log_integration_persistence_error(
    error: &rdashboard::store::IntegrationStoreError,
    integration: &'static str,
) {
    if matches!(
        error,
        rdashboard::store::IntegrationStoreError::NotificationHandoffFull
    ) {
        error!(
            integration,
            "notification handoff capacity blocked the atomic integration commit"
        );
    } else {
        error!(error = %error, integration, "project integration record could not be persisted");
    }
}

fn spawn_notification_handoff_delivery(store: IntegrationStore, notifier: Arc<NotifierClientV1>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(NOTIFICATION_HANDOFF_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let cycle_store = store.clone();
            let cycle_notifier = Arc::clone(&notifier);
            match tokio::task::spawn_blocking(move || {
                deliver_notification_handoff(&cycle_store, &cycle_notifier)
            })
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    warn!(error = %error, "notification handoff remains pending");
                }
                Err(error) => {
                    warn!(error = %error, "notification handoff task failed");
                }
            }
        }
    });
}

fn deliver_notification_handoff(
    store: &IntegrationStore,
    notifier: &NotifierClientV1,
) -> Result<usize, NotificationHandoffError> {
    let events = store.pending_notification_events(NOTIFICATION_HANDOFF_BATCH)?;
    let mut delivered = 0;
    for event in events {
        notifier.enqueue(event.clone())?;
        store.acknowledge_notification_event(&event)?;
        delivered += 1;
    }
    Ok(delivered)
}

fn project_repository_interval() -> Duration {
    Duration::from_millis(u64::try_from(PROJECT_REPOSITORY_SAMPLE_INTERVAL_MS).unwrap_or(u64::MAX))
}

fn duration_until(now_ms: i64, target_ms: i64) -> Duration {
    let delay_ms = target_ms.saturating_sub(now_ms);
    Duration::from_millis(u64::try_from(delay_ms).unwrap_or(u64::MAX))
}

async fn set_project_repository_error(
    state: &DashboardState,
    project_id: &ProjectId,
    detail: &str,
) {
    state.project_repository_errors.write().await.insert(
        project_id.to_string(),
        truncate_utf8(detail, PROJECT_REPOSITORY_ERROR_MAX_BYTES, "…"),
    );
}

async fn apply_metric_retention(state: &DashboardState, metrics_store: &MetricsStore) {
    let now = match unix_time_ms() {
        Ok(now) => now,
        Err(error) => {
            let detail = error.to_string();
            warn!(error = %detail, "metric retention skipped because the host clock is invalid");
            *state.retention_error.write().await = Some(detail);
            return;
        }
    };
    let raw_retention = i64::try_from(RAW_RETENTION.as_millis()).unwrap_or(i64::MAX);
    let rollup_retention = i64::try_from(MINUTE_ROLLUP_RETENTION.as_millis()).unwrap_or(i64::MAX);
    let raw_cutoff = now.saturating_sub(raw_retention);
    let rollup_cutoff = now.saturating_sub(rollup_retention);
    match metrics_store.apply_retention(raw_cutoff, rollup_cutoff) {
        Ok(_) => *state.retention_error.write().await = None,
        Err(error) => {
            let detail = error.to_string();
            warn!(error = %detail, "metric rollup and retention failed");
            *state.retention_error.write().await = Some(detail);
        }
    }
}

#[derive(Debug)]
struct Config {
    listen: SocketAddr,
    data_dir: PathBuf,
    project_collectors: Vec<MonitoredProjectCollector>,
    executor_socket: Option<PathBuf>,
    access: Option<CloudflareAccessConfig>,
    credential_directory: Option<PathBuf>,
    notifier_socket: Option<PathBuf>,
}

impl Config {
    fn from_env() -> Result<Self, ConfigError> {
        let listen = std::env::var("RDASHBOARD_LISTEN")
            .unwrap_or_else(|_| DEFAULT_LISTEN.to_owned())
            .parse::<SocketAddr>()
            .map_err(ConfigError::ListenAddress)?;
        if !listen.ip().is_loopback() {
            return Err(ConfigError::NonLoopbackListen(listen));
        }
        let data_dir = match std::env::var("RDASHBOARD_DATA_DIR") {
            Ok(value) => {
                let path = PathBuf::from(value);
                validate_configured_data_dir(&path)?;
                path
            }
            Err(std::env::VarError::NotPresent) => PathBuf::from(DEFAULT_DATA_DIR),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeDataDirectory);
            }
        };
        let project_collectors = vec![configured_rimg_project()?, configured_telegram_gateway()?];
        let executor_socket = match std::env::var("RDASHBOARD_EXECUTOR_SOCKET") {
            Ok(value) if value == ROOT_EXECUTOR_SOCKET_PATH => Some(PathBuf::from(value)),
            Ok(_) => return Err(ConfigError::InvalidExecutorSocket),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeExecutorSocket);
            }
        };
        let access = CloudflareAccessConfig::from_env()?;
        let credential_directory = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
        if credential_directory
            .as_deref()
            .is_some_and(|path| validate_configured_data_dir(path).is_err())
        {
            return Err(ConfigError::InvalidCredentialDirectory);
        }
        let notifier_socket = match std::env::var("RDASHBOARD_NOTIFIER_SOCKET") {
            Ok(value) if value == NOTIFIER_SOCKET_PATH => Some(PathBuf::from(value)),
            Ok(_) => return Err(ConfigError::InvalidNotifierSocket),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeNotifierSocket);
            }
        };
        Ok(Self {
            listen,
            data_dir,
            project_collectors,
            executor_socket,
            access,
            credential_directory,
            notifier_socket,
        })
    }
}

fn configured_rimg_project() -> Result<MonitoredProjectCollector, ConfigError> {
    let base_url = match std::env::var("RDASHBOARD_RIMG_BASE_URL") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(ConfigError::NonUnicodeRimgBaseUrl);
        }
    };
    let health =
        RimgHealthCollector::from_optional_base_url(base_url.as_deref(), PROJECT_HEALTH_TIMEOUT)
            .map_err(ConfigError::RimgBaseUrl)?;
    let socket = match std::env::var("RDASHBOARD_RIMG_RESOURCE_SOCKET") {
        Ok(value) if value == RIMG_RESOURCE_SOCKET_PATH => Some(PathBuf::from(value)),
        Ok(_) => return Err(ConfigError::InvalidRimgResourceSocket),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(ConfigError::NonUnicodeRimgResourceSocket);
        }
    };
    let resources = ProjectResourceCollector::from_optional_socket_path(
        socket.as_deref(),
        PROJECT_RESOURCE_TIMEOUT,
    )
    .map_err(ConfigError::RimgResourceSocket)?;
    Ok(MonitoredProjectCollector {
        health: ProjectHealthCollector::Rimg(health),
        resources,
    })
}

fn configured_telegram_gateway() -> Result<MonitoredProjectCollector, ConfigError> {
    let base_url = match std::env::var("RDASHBOARD_TELEGRAM_GATEWAY_BASE_URL") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(ConfigError::NonUnicodeTelegramGatewayBaseUrl);
        }
    };
    let project_id: ProjectId = PROJECT_ID_TELEGRAM_GATEWAY
        .parse()
        .map_err(|_| ConfigError::InvalidTelegramGatewayProjectId)?;
    let health = HttpHealthCollector::from_optional_base_url(
        project_id.clone(),
        TELEGRAM_GATEWAY_DISPLAY_NAME,
        base_url.as_deref(),
        PROJECT_HEALTH_TIMEOUT,
    )
    .map_err(ConfigError::TelegramGatewayBaseUrl)?;
    let socket = match std::env::var("RDASHBOARD_TELEGRAM_GATEWAY_RESOURCE_SOCKET") {
        Ok(value) if value == RIMG_RESOURCE_SOCKET_PATH => Some(PathBuf::from(value)),
        Ok(_) => return Err(ConfigError::InvalidTelegramGatewayResourceSocket),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(ConfigError::NonUnicodeTelegramGatewayResourceSocket);
        }
    };
    let resources = ProjectResourceCollector::for_project(
        project_id,
        socket.as_deref(),
        PROJECT_RESOURCE_TIMEOUT,
    )
    .map_err(ConfigError::TelegramGatewayResourceSocket)?;
    Ok(MonitoredProjectCollector {
        health: ProjectHealthCollector::Http(health),
        resources,
    })
}

fn validate_configured_data_dir(path: &Path) -> Result<(), ConfigError> {
    let encoded = path.as_os_str().as_encoded_bytes();
    if encoded.is_empty()
        || encoded.len() > 512
        || encoded.windows(2).any(|pair| pair == b"//")
        || !path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        || path.components().collect::<PathBuf>() != path
    {
        return Err(ConfigError::EmptyDataDirectory);
    }
    Ok(())
}

fn init_tracing() -> Result<(), DynError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).try_init()
}

async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(error = %error, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => error!(error = %error, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
    info!("shutdown requested");
}

#[derive(Debug, thiserror::Error)]
enum NotificationHandoffError {
    #[error("integration notification handoff failed: {0}")]
    Integration(#[from] rdashboard::store::IntegrationStoreError),
    #[error("notifier handoff failed: {0}")]
    Notifier(#[from] rdashboard::notifier_socket::NotifierClientError),
}

#[derive(Debug, thiserror::Error)]
enum ConfigError {
    #[error("RDASHBOARD_LISTEN is invalid: {0}")]
    ListenAddress(std::net::AddrParseError),
    #[error("loopback-only milestone refuses non-loopback listen address {0}")]
    NonLoopbackListen(SocketAddr),
    #[error("RDASHBOARD_DATA_DIR must be absolute, normalized and bounded")]
    EmptyDataDirectory,
    #[error("RDASHBOARD_DATA_DIR must be valid Unicode")]
    NonUnicodeDataDirectory,
    #[error("CREDENTIALS_DIRECTORY must be absolute, normalized and bounded")]
    InvalidCredentialDirectory,
    #[error("RDASHBOARD_RIMG_BASE_URL is invalid: {0}")]
    RimgBaseUrl(RimgConfigError),
    #[error("RDASHBOARD_RIMG_RESOURCE_SOCKET is invalid: {0}")]
    RimgResourceSocket(RimgConfigError),
    #[error("RDASHBOARD_RIMG_BASE_URL must be valid Unicode")]
    NonUnicodeRimgBaseUrl,
    #[error("RDASHBOARD_RIMG_RESOURCE_SOCKET must be {RIMG_RESOURCE_SOCKET_PATH}")]
    InvalidRimgResourceSocket,
    #[error("RDASHBOARD_RIMG_RESOURCE_SOCKET must be valid Unicode")]
    NonUnicodeRimgResourceSocket,
    #[error("the internal telegram-gateway project ID is invalid")]
    InvalidTelegramGatewayProjectId,
    #[error("RDASHBOARD_TELEGRAM_GATEWAY_BASE_URL is invalid: {0}")]
    TelegramGatewayBaseUrl(HttpHealthConfigError),
    #[error("RDASHBOARD_TELEGRAM_GATEWAY_BASE_URL must be valid Unicode")]
    NonUnicodeTelegramGatewayBaseUrl,
    #[error("RDASHBOARD_TELEGRAM_GATEWAY_RESOURCE_SOCKET is invalid: {0}")]
    TelegramGatewayResourceSocket(RimgConfigError),
    #[error("RDASHBOARD_TELEGRAM_GATEWAY_RESOURCE_SOCKET must be {RIMG_RESOURCE_SOCKET_PATH}")]
    InvalidTelegramGatewayResourceSocket,
    #[error("RDASHBOARD_TELEGRAM_GATEWAY_RESOURCE_SOCKET must be valid Unicode")]
    NonUnicodeTelegramGatewayResourceSocket,
    #[error("RDASHBOARD_EXECUTOR_SOCKET must be {ROOT_EXECUTOR_SOCKET_PATH}")]
    InvalidExecutorSocket,
    #[error("RDASHBOARD_EXECUTOR_SOCKET must be valid Unicode")]
    NonUnicodeExecutorSocket,
    #[error("RDASHBOARD_NOTIFIER_SOCKET must be {NOTIFIER_SOCKET_PATH}")]
    InvalidNotifierSocket,
    #[error("RDASHBOARD_NOTIFIER_SOCKET must be valid Unicode")]
    NonUnicodeNotifierSocket,
    #[error(transparent)]
    Access(#[from] CloudflareAccessConfigError),
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigError, HttpHealthCollector, MonitoredProjectCollector, PROJECT_HEALTH_TIMEOUT,
        PROJECT_ID_TELEGRAM_GATEWAY, PROJECT_RESOURCE_TIMEOUT, ProjectHealthCollector,
        ProjectResourceCollector, RimgHealthCollector, TELEGRAM_GATEWAY_DISPLAY_NAME,
        collect_projects, shared_project_collectors, validate_configured_data_dir,
    };
    use rdashboard::domain::ProjectId;
    use std::{path::Path, str::FromStr as _};

    #[test]
    fn configured_data_directory_requires_an_absolute_normalized_path() {
        validate_configured_data_dir(Path::new("/var/lib/rdashboard"))
            .unwrap_or_else(|error| panic!("valid data directory: {error}"));
        for invalid in ["", "var", "/var/../etc", "/var//lib/rdashboard"] {
            assert!(matches!(
                validate_configured_data_dir(Path::new(invalid)),
                Err(ConfigError::EmptyDataDirectory)
            ));
        }
    }

    #[tokio::test]
    async fn configured_collection_keeps_each_project_as_an_independent_row() {
        let rimg = MonitoredProjectCollector {
            health: ProjectHealthCollector::Rimg(
                RimgHealthCollector::from_optional_base_url(None, PROJECT_HEALTH_TIMEOUT)
                    .expect("unconfigured rimg health collector"),
            ),
            resources: ProjectResourceCollector::from_optional_socket_path(
                None,
                PROJECT_RESOURCE_TIMEOUT,
            )
            .expect("unconfigured rimg resource collector"),
        };
        let gateway_id =
            ProjectId::from_str(PROJECT_ID_TELEGRAM_GATEWAY).expect("telegram gateway project ID");
        let gateway = MonitoredProjectCollector {
            health: ProjectHealthCollector::Http(
                HttpHealthCollector::from_optional_base_url(
                    gateway_id.clone(),
                    TELEGRAM_GATEWAY_DISPLAY_NAME,
                    None,
                    PROJECT_HEALTH_TIMEOUT,
                )
                .expect("unconfigured gateway health collector"),
            ),
            resources: ProjectResourceCollector::for_project(
                gateway_id,
                None,
                PROJECT_RESOURCE_TIMEOUT,
            )
            .expect("unconfigured gateway resource collector"),
        };
        let collectors = shared_project_collectors(&[rimg, gateway]);

        let projects = collect_projects(&collectors, 42).await;

        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0].project_id.as_str(), "rimg");
        assert_eq!(projects[1].project_id.as_str(), PROJECT_ID_TELEGRAM_GATEWAY);
        assert_eq!(projects[1].display_name, TELEGRAM_GATEWAY_DISPLAY_NAME);
    }
}
