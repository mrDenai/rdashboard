use std::{
    os::unix::fs::MetadataExt as _,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rdashboard::{
    notification_delivery::{NotificationDeliveryWorker, TelegramGatewayClient},
    notifier_socket::{
        BoundNotifierSocketV1, NOTIFIER_SOCKET_PATH, NotifierServerConfigV1,
        StoreNotifierHandlerV1, serve_notifier_until,
    },
    store::NotificationStore,
};
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const DEFAULT_DATA_DIR: &str = "/var/lib/rdashboard-notify";
const WORKER_IDLE_INTERVAL: Duration = Duration::from_secs(1);
const GATEWAY_TIMEOUT: Duration = Duration::from_secs(8);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(2);
type DynError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    init_tracing()?;
    let config = Config::from_env()?;
    let state_metadata = std::fs::symlink_metadata(&config.data_dir)?;
    if !state_metadata.is_dir()
        || state_metadata.file_type().is_symlink()
        || state_metadata.mode() & 0o777 != 0o700
    {
        return Err(ConfigError::UnsafeDataDirectory.into());
    }
    let service_uid = state_metadata.uid();
    let store = NotificationStore::open(config.data_dir.join("notifications.sqlite"))?;
    let gateway = TelegramGatewayClient::from_systemd_credentials(
        &config.credential_directory,
        config.gateway_project_id,
        config.chat_id,
        config.message_thread_id,
        GATEWAY_TIMEOUT,
    )?;
    let worker = NotificationDeliveryWorker::new(store.clone(), gateway);
    let handler = Arc::new(StoreNotifierHandlerV1::new(store));
    let mut bound = BoundNotifierSocketV1::bind(&config.socket_path, service_uid)?;
    let listener = bound.take_listener();
    let server_config = NotifierServerConfigV1::new(config.controller_uid, 8, SOCKET_TIMEOUT)?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let signal_task = tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });
    info!(socket = %config.socket_path.display(), "rdashboard notifier ready");
    let server_shutdown = shutdown_rx.clone();
    let server = async move {
        serve_notifier_until(
            listener,
            handler,
            server_config,
            wait_for_shutdown(server_shutdown),
        )
        .await
        .map_err(|error| -> DynError { Box::new(error) })
    };
    let delivery = async move {
        run_delivery(worker, shutdown_rx)
            .await
            .map_err(|error| -> DynError { Box::new(error) })
    };
    let result = tokio::try_join!(server, delivery);
    signal_task.abort();
    result?;
    Ok(())
}

async fn run_delivery(
    worker: NotificationDeliveryWorker,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), rdashboard::notification_delivery::NotificationDeliveryError> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let processed = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            result = worker.process_once() => result?,
        };
        if processed {
            tokio::task::yield_now().await;
        } else {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
                () = tokio::time::sleep(WORKER_IDLE_INTERVAL) => {}
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

#[derive(Debug)]
struct Config {
    data_dir: PathBuf,
    socket_path: PathBuf,
    credential_directory: PathBuf,
    controller_uid: u32,
    gateway_project_id: String,
    chat_id: i64,
    message_thread_id: i32,
}

impl Config {
    fn from_env() -> Result<Self, ConfigError> {
        let data_dir = path_env("RDASHBOARD_NOTIFY_DATA_DIR", DEFAULT_DATA_DIR)?;
        let socket_path = path_env("RDASHBOARD_NOTIFY_SOCKET", NOTIFIER_SOCKET_PATH)?;
        if socket_path != Path::new(NOTIFIER_SOCKET_PATH) {
            return Err(ConfigError::InvalidSocketPath);
        }
        let credential_directory = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or(ConfigError::MissingCredentialDirectory)?;
        if !is_normalized_absolute_path(&credential_directory) {
            return Err(ConfigError::InvalidCredentialDirectory);
        }
        let controller_uid = required_env("RDASHBOARD_NOTIFY_CONTROLLER_UID")?
            .parse::<u32>()
            .map_err(|_| ConfigError::InvalidControllerUid)?;
        if controller_uid == 0 || controller_uid == u32::MAX {
            return Err(ConfigError::InvalidControllerUid);
        }
        let gateway_project_id = required_env("RDASHBOARD_NOTIFY_GATEWAY_PROJECT")?;
        let chat_id = required_env("RDASHBOARD_NOTIFY_CHAT_ID")?
            .parse::<i64>()
            .map_err(|_| ConfigError::InvalidChatId)?;
        let message_thread_id = std::env::var("RDASHBOARD_NOTIFY_THREAD_ID")
            .unwrap_or_else(|_| "0".to_owned())
            .parse::<i32>()
            .map_err(|_| ConfigError::InvalidThreadId)?;
        Ok(Self {
            data_dir,
            socket_path,
            credential_directory,
            controller_uid,
            gateway_project_id,
            chat_id,
            message_thread_id,
        })
    }
}

fn path_env(name: &'static str, default: &'static str) -> Result<PathBuf, ConfigError> {
    let value = std::env::var_os(name).map_or_else(|| PathBuf::from(default), PathBuf::from);
    if !is_normalized_absolute_path(&value) {
        return Err(ConfigError::InvalidPath(name));
    }
    Ok(value)
}

fn required_env(name: &'static str) -> Result<String, ConfigError> {
    let value = std::env::var(name).map_err(|_| ConfigError::MissingEnvironment(name))?;
    if value.is_empty()
        || value != value.trim()
        || value.len() > 128
        || value.chars().any(char::is_control)
    {
        return Err(ConfigError::InvalidEnvironment(name));
    }
    Ok(value)
}

fn is_normalized_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>() == path
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
            error!(error = %error, "failed to install notifier Ctrl-C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => error!(error = %error, "failed to install notifier terminate handler"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}

#[derive(Debug, thiserror::Error)]
enum ConfigError {
    #[error("notifier path environment {0} is not a normalized absolute path")]
    InvalidPath(&'static str),
    #[error("notifier socket path must remain fixed")]
    InvalidSocketPath,
    #[error("notifier CREDENTIALS_DIRECTORY is required")]
    MissingCredentialDirectory,
    #[error("notifier CREDENTIALS_DIRECTORY is invalid")]
    InvalidCredentialDirectory,
    #[error("notifier environment {0} is required")]
    MissingEnvironment(&'static str),
    #[error("notifier environment {0} is invalid")]
    InvalidEnvironment(&'static str),
    #[error("notifier controller UID is invalid")]
    InvalidControllerUid,
    #[error("notifier chat ID is invalid")]
    InvalidChatId,
    #[error("notifier thread ID is invalid")]
    InvalidThreadId,
    #[error("notifier StateDirectory ownership or mode is unsafe")]
    UnsafeDataDirectory,
}
