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
        PsiMeasurement,
    },
    executor_socket::{ROOT_EXECUTOR_SOCKET_PATH, RootExecutorClient},
    metrics::HostCollector,
    projects::{RimgConfigError, RimgHealthCollector},
    store::{ControlStore, MetricsStore},
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
const EXECUTOR_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const RAW_RETENTION: Duration = Duration::from_hours(24);
const MINUTE_ROLLUP_RETENTION: Duration = Duration::from_hours(720);
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
    let hub = EventHub::new(control_store.clone());
    let executor_client = config
        .executor_socket
        .as_ref()
        .map(|socket_path| RootExecutorClient::new(socket_path, EXECUTOR_REQUEST_TIMEOUT))
        .transpose()?
        .map(Arc::new);
    let state = executor_client.as_ref().map_or_else(
        || DashboardState::new(hub.clone(), SAMPLE_INTERVAL),
        |client| {
            DashboardState::new(hub.clone(), SAMPLE_INTERVAL).with_mutation_api(
                DashboardMutationApiV1::new(
                    DurableController::new(control_store.clone()),
                    Arc::clone(client),
                ),
            )
        },
    );
    let host_source = executor_client.map_or_else(
        || {
            HostObservationSource::Local(Arc::new(Mutex::new(HostCollector::linux(
                &config.data_dir,
            ))))
        },
        HostObservationSource::Executor,
    );
    let project_collector = Arc::new(Mutex::new(config.rimg_collector.clone()));

    let first_started_at = unix_time_ms()?;
    let recovered = control_store.recover_interrupted_observations(first_started_at)?;
    if recovered > 0 {
        warn!(
            recovered,
            "marked interrupted observation operations as failed"
        );
    }
    let first_operation = control_store.start_observation(first_started_at)?;
    if let Err(collection_error) = collect_and_publish(
        &state,
        &metrics_store,
        &host_source,
        &project_collector,
        first_operation,
    )
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

    spawn_collection_loop(state.clone(), metrics_store, host_source, project_collector);

    let listener = TcpListener::bind(config.listen).await?;
    info!(listen = %config.listen, data_dir = %config.data_dir.display(), "rdashboardd listening");
    axum::serve(listener, router_with_access(state, access))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn collect_and_publish(
    state: &DashboardState,
    metrics_store: &MetricsStore,
    host_source: &HostObservationSource,
    project_collector: &Mutex<RimgHealthCollector>,
    observation_operation_id: Uuid,
) -> Result<(), DynError> {
    let now = unix_time_ms()?;
    let host = host_source.collect(now).await;
    let project = project_collector.lock().await.collect(now).await;
    metrics_store.record_collection(&host, std::slice::from_ref(&project))?;
    let snapshot = DashboardSnapshot {
        generated_at_ms: now,
        host,
        projects: vec![project],
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
    project_collector: Arc<Mutex<RimgHealthCollector>>,
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
            match collect_and_publish(
                &state,
                &metrics_store,
                &host_source,
                &project_collector,
                operation_id,
            )
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
    rimg_collector: RimgHealthCollector,
    executor_socket: Option<PathBuf>,
    access: Option<CloudflareAccessConfig>,
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
        let rimg_base_url = match std::env::var("RDASHBOARD_RIMG_BASE_URL") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeRimgBaseUrl);
            }
        };
        let rimg_collector = RimgHealthCollector::from_optional_base_url(
            rimg_base_url.as_deref(),
            PROJECT_HEALTH_TIMEOUT,
        )
        .map_err(ConfigError::RimgBaseUrl)?;
        let executor_socket = match std::env::var("RDASHBOARD_EXECUTOR_SOCKET") {
            Ok(value) if value == ROOT_EXECUTOR_SOCKET_PATH => Some(PathBuf::from(value)),
            Ok(_) => return Err(ConfigError::InvalidExecutorSocket),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeExecutorSocket);
            }
        };
        let access = CloudflareAccessConfig::from_env()?;
        Ok(Self {
            listen,
            data_dir,
            rimg_collector,
            executor_socket,
            access,
        })
    }
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
enum ConfigError {
    #[error("RDASHBOARD_LISTEN is invalid: {0}")]
    ListenAddress(std::net::AddrParseError),
    #[error("loopback-only milestone refuses non-loopback listen address {0}")]
    NonLoopbackListen(SocketAddr),
    #[error("RDASHBOARD_DATA_DIR must be absolute, normalized and bounded")]
    EmptyDataDirectory,
    #[error("RDASHBOARD_DATA_DIR must be valid Unicode")]
    NonUnicodeDataDirectory,
    #[error("RDASHBOARD_RIMG_BASE_URL is invalid: {0}")]
    RimgBaseUrl(RimgConfigError),
    #[error("RDASHBOARD_RIMG_BASE_URL must be valid Unicode")]
    NonUnicodeRimgBaseUrl,
    #[error("RDASHBOARD_EXECUTOR_SOCKET must be {ROOT_EXECUTOR_SOCKET_PATH}")]
    InvalidExecutorSocket,
    #[error("RDASHBOARD_EXECUTOR_SOCKET must be valid Unicode")]
    NonUnicodeExecutorSocket,
    #[error(transparent)]
    Access(#[from] CloudflareAccessConfigError),
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, validate_configured_data_dir};
    use std::path::Path;

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
}
